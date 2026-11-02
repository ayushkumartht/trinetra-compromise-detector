# SPDX-License-Identifier: GPL-2.0-only
"""Window-level behavioural features + novelty profiles + fleet consensus.

Features are device-agnostic: a router, a firewall and a laptop all produce the
same vector; fields with no telemetry stay 0. Novelty ("never seen on this
device before") is measured against a per-device Profile. Fleet consensus
removes items that are novel on many peers at once (patch rollouts, new SaaS
endpoints): attackers rarely touch a large fraction of the fleet in the same
hour, benign IT change usually does.
"""
from __future__ import annotations

import math
from collections import Counter

import numpy as np

from .schema import is_internal

FEATURES = [
    "n_flows", "bytes_out", "bytes_in", "ext_bytes_out", "out_in_ratio", "n_dst", "n_dport", "dst_entropy",
    "dport_entropy", "new_dst", "new_dport", "new_int_edges", "int_fanout", "ext_frac",
    "failed_conn", "n_dns", "dns_entropy", "dns_new_domains", "dns_max_sub", "n_auth",
    "auth_fail", "auth_new_pairs", "n_proc", "new_proc_pairs", "n_logs", "new_templates",
    "cpu", "mem",
]
CONTEXT = ["hour_sin", "hour_cos", "workhours"]
FIDX = {f: i for i, f in enumerate(FEATURES)}
RAW = {"out_in_ratio", "dst_entropy", "dport_entropy", "ext_frac", "dns_entropy", "cpu", "mem"}  # not log1p counts
NOVELTY_KINDS = ("dst", "dport", "edge", "domain", "authpair", "procpair", "template")

# behavioural feature -> (ATT&CK tactic, technique) for kill-chain attribution
FEATURE_ATTACK = {
    "ext_bytes_out": ("Exfiltration", "T1041 Exfiltration Over C2 Channel"),
    "out_in_ratio": ("Exfiltration", "T1048 Exfiltration Over Alternative Protocol"),
    "new_dst": ("Command and Control", "T1071 Application Layer Protocol"),
    "new_dport": ("Discovery", "T1046 Network Service Discovery"),
    "new_int_edges": ("Lateral Movement", "T1021 Remote Services"),
    "int_fanout": ("Discovery", "T1046 Network Service Discovery"),
    "failed_conn": ("Discovery", "T1046 Network Service Discovery"),
    "dns_entropy": ("Command and Control", "T1071.004 DNS"),
    "dns_new_domains": ("Command and Control", "T1568 Dynamic Resolution"),
    "dns_max_sub": ("Exfiltration", "T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol"),
    "auth_fail": ("Credential Access", "T1110 Brute Force"),
    "auth_new_pairs": ("Lateral Movement", "T1078 Valid Accounts"),
    "new_proc_pairs": ("Execution", "T1059 Command and Scripting Interpreter"),
}
NEGATIVE_ATTACK = {"n_logs": ("Defense Evasion", "T1070 Indicator Removal (log suppression)")}
# z needed to attribute a tactic; never-seen process chains / logins are rare enough to count earlier
ATTRIBUTION_Z = {"new_proc_pairs": 2.0, "auth_new_pairs": 2.0, "dns_max_sub": 2.5}


def _entropy(counter: Counter) -> float:
    n = sum(counter.values())
    if n == 0:
        return 0.0
    return -sum(c / n * math.log2(c / n) for c in counter.values())


def split_domain(q: str) -> tuple:
    parts = q.lower().rstrip(".").split(".")
    return ".".join(parts[-2:]), ".".join(parts[:-2])


class Profile:
    """Everything a device has been seen doing (gated, append-only)."""
    __slots__ = ("seen",)

    def __init__(self):
        self.seen = {k: set() for k in NOVELTY_KINDS}

    def novel(self, items: dict) -> dict:
        return {k: items[k] - self.seen[k] for k in NOVELTY_KINDS}

    def learn(self, items: dict) -> None:
        for k in NOVELTY_KINDS:
            self.seen[k] |= items[k]


def window_items(evs) -> dict:
    items = {k: set() for k in NOVELTY_KINDS}
    for e in evs:
        a, k = e.a, e.kind
        if k == "flow":
            items["dst"].add(a["dst"])
            items["dport"].add(int(a.get("dport", 0)))
            if is_internal(a["dst"]):
                items["edge"].add((a.get("src", ""), a["dst"], int(a.get("dport", 0))))
        elif k == "dns":
            items["domain"].add(split_domain(a["q"])[0])
        elif k == "auth":
            items["authpair"].add((a.get("user", ""), a.get("src", "")))
        elif k == "proc":
            items["procpair"].add((a.get("parent", ""), a.get("name", "")))
        elif k == "log":
            items["template"].add(a.get("t", ""))
    return items


class FleetConsensus:
    """Items novel on >= max(min_count, frac*N) devices of one type within a sliding
    window (span windows back, `look` windows ahead) are fleet-wide benign change."""

    def __init__(self, dtype_of: dict, frac: float = 0.2, min_count: int = 3, span: int = 4):
        self.dtype_of, self.span = dtype_of, span
        n_type = Counter(dtype_of.values())
        self.n_type = dict(n_type)
        self.thr = {t: max(min_count, frac * n) for t, n in n_type.items()}
        self.last_max_frac = 0.0
        self.seen: dict = {}          # (type, kind, item) -> {device: window}
        self.watch: dict = {}       # items once judged fleet-wide -> {"devs": set, "grew": window}

    def touch(self, w: int, items_by_dev: dict) -> None:
        """Record which devices actually touched a fleet-wide item (raw items, not novelty: once an item is
        learned it is no longer novel, but later devices still take part in the same change)."""
        for dev, items in items_by_dev.items():
            t = self.dtype_of[dev]
            for k in NOVELTY_KINDS:
                for x in items[k]:
                    entry = self.watch.get((t, k, x))
                    if entry is not None and dev not in entry["devs"]:
                        entry["devs"].add(dev)
                        entry["grew"] = max(entry["grew"], w)

    def fleet_change(self, w: int, frac: float = 0.5) -> bool:
        """True while a change is still spreading (new devices joined within `span` windows) and has
        reached >= frac of one device class, e.g. a patch rollout. Steady shared use does not count."""
        live = False
        for key, e in list(self.watch.items()):
            if e["grew"] <= w - 4 * self.span:
                del self.watch[key]
            elif e["grew"] > w - self.span and len(e["devs"]) >= frac * self.n_type[key[0]]:
                live = True
        return live

    def add(self, w: int, novel_by_dev: dict) -> None:
        for dev, nov in novel_by_dev.items():
            t = self.dtype_of[dev]
            for k in NOVELTY_KINDS:
                for x in nov[k]:
                    self.seen.setdefault((t, k, x), {})[dev] = w

    def common(self, w: int, look: int = 2) -> dict:
        out = {k: set() for k in NOVELTY_KINDS}
        stale = []
        self.last_max_frac = 0.0
        for (t, k, x), devs in self.seen.items():
            if max(devs.values()) <= w - self.span:
                stale.append((t, k, x))
                continue
            live = sum(1 for lw in devs.values() if w - self.span < lw <= w + look)
            if live >= self.thr[t]:
                out[k].add(x)
                self.last_max_frac = max(self.last_max_frac, live / self.n_type[t])
                entry = self.watch.setdefault((t, k, x), {"devs": set(), "grew": w})
                if not set(devs) <= entry["devs"]:
                    entry["devs"] |= set(devs)
                    entry["grew"] = max(entry["grew"], max(devs.values()))
        for key in stale:
            del self.seen[key]
        return out


def compute(evs, novel: dict, ts: float, tz_offset_h: float = 0.0) -> np.ndarray:
    """Feature vector (log1p for counts) + time context for one device-window."""
    f = np.zeros(len(FEATURES) + len(CONTEXT))
    dsts, ports, int_dsts = Counter(), Counter(), set()
    bout = bin_ = ext_out = ext_in = 0.0
    n_flow = n_ext = n_fail = 0
    n_dns, ent = 0, []
    sub_per_dom: dict = {}
    n_auth = n_fail_auth = n_proc = n_log = 0
    cpu, mem = [], []
    for e in evs:
        a, k = e.a, e.kind
        if k == "flow":
            n_flow += 1
            dsts[a["dst"]] += 1
            ports[int(a.get("dport", 0))] += 1
            bout += a.get("bout", 0)
            bin_ += a.get("bin", 0)
            if is_internal(a["dst"]):
                int_dsts.add(a["dst"])
            else:
                n_ext += 1
                ext_out += a.get("bout", 0)
                ext_in += a.get("bin", 0)
            if a.get("bin", 1) == 0 and a.get("proto") == "tcp":
                n_fail += 1
        elif k == "dns":
            n_dns += 1
            dom, sub = split_domain(a["q"])
            sub_per_dom.setdefault(dom, set()).add(sub)
            ent.append(_entropy(Counter(sub)) * min(1.0, len(sub) / 16))
        elif k == "auth":
            n_auth += 1
            n_fail_auth += not a.get("ok", True)
        elif k == "proc":
            n_proc += 1
        elif k == "log":
            n_log += 1
        elif k == "resource":
            cpu.append(a.get("cpu", 0.0))
            mem.append(a.get("mem", 0.0))
    lg = math.log1p
    v = {
        "n_flows": lg(n_flow), "bytes_out": lg(bout), "bytes_in": lg(bin_), "ext_bytes_out": lg(ext_out),
        "out_in_ratio": lg(ext_out) - lg(ext_in) if n_ext else 0.0,
        "n_dst": lg(len(dsts)), "n_dport": lg(len(ports)), "dst_entropy": _entropy(dsts),
        "dport_entropy": _entropy(ports), "new_dst": lg(len(novel["dst"])),
        "new_dport": lg(len(novel["dport"])), "new_int_edges": lg(len(novel["edge"])),
        "int_fanout": lg(len(int_dsts)), "ext_frac": n_ext / n_flow if n_flow else 0.0,
        "failed_conn": lg(n_fail), "n_dns": lg(n_dns),
        "dns_entropy": float(np.mean(sorted(ent)[-3:])) if ent else 0.0,
        "dns_new_domains": lg(len(novel["domain"])),
        "dns_max_sub": lg(max((len(s) for s in sub_per_dom.values()), default=0)),
        "n_auth": lg(n_auth), "auth_fail": lg(n_fail_auth), "auth_new_pairs": lg(len(novel["authpair"])),
        "n_proc": lg(n_proc), "new_proc_pairs": lg(len(novel["procpair"])),
        "n_logs": lg(n_log), "new_templates": lg(len(novel["template"])),
        "cpu": max(cpu) if cpu else 0.0, "mem": max(mem) if mem else 0.0,
    }
    for name, val in v.items():
        f[FIDX[name]] = val
    hour = ((ts / 3600.0) + tz_offset_h) % 24
    wd = int(((ts / 86400.0) + tz_offset_h / 24 + 3) % 7)   # 1970-01-01 was a Thursday -> Mon=0
    f[len(FEATURES)] = math.sin(2 * math.pi * hour / 24)
    f[len(FEATURES) + 1] = math.cos(2 * math.pi * hour / 24)
    f[len(FEATURES) + 2] = float(wd < 5 and 8 <= hour < 18)
    return f


class Standardizer:
    """Per-device robust scaling (median / MAD with floors) so pooled peer models work."""

    FLOOR = np.array([2.0 if n in ("cpu", "mem") else 0.25 if n in RAW else 0.5 for n in FEATURES])

    def fit(self, X: np.ndarray) -> Standardizer:
        F = X[:, :len(FEATURES)]
        self.med = np.median(F, axis=0)
        mad = 1.4826 * np.median(np.abs(F - self.med), axis=0)
        self.scale = np.maximum.reduce([mad, 0.5 * F.std(axis=0), self.FLOOR])
        return self

    def z(self, X: np.ndarray) -> np.ndarray:
        X = np.atleast_2d(X)
        return np.clip((X[:, :len(FEATURES)] - self.med) / self.scale, -12, 12)

    def full(self, X: np.ndarray) -> np.ndarray:
        X = np.atleast_2d(X)
        return np.hstack([self.z(X), X[:, len(FEATURES):]])
