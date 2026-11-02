# SPDX-License-Identifier: GPL-2.0-only
"""Detector ensemble + statistical calibration.

Each detector turns one device-window into a raw anomaly score. A TailCalibrator
converts it into a conformal p-value (empirical inside the calibration range, a
generalised-Pareto tail beyond it - SPOT-style EVT), so all detectors speak the
same "probability under normal behaviour" language and can be fused with the
Cauchy combination test, which stays valid when detectors are correlated.
"""
from __future__ import annotations

import math
import re
import statistics
from collections import Counter, defaultdict, deque

import numpy as np
from scipy.stats import genpareto
from sklearn.ensemble import IsolationForest
from sklearn.neural_network import MLPRegressor

from .features import FEATURES
from .schema import is_internal

DETECTORS = ["zscore", "iforest", "autoenc", "sequence", "beacon", "graph", "config", "slips"]
DETECTOR_LABEL = {
    "zscore": "Robust deviation from own baseline",
    "iforest": "Isolation Forest (peer-pooled)",
    "autoenc": "Autoencoder reconstruction error",
    "sequence": "Log-grammar surprise (DeepLog-style)",
    "beacon": "Periodic C2 beaconing",
    "graph": "Rare internal communication edges",
    "config": "Configuration semantic drift risk",
    "slips": "Slips IPS behavioural evidence",
}
APPLICABLE = {
    "host": {"zscore", "iforest", "autoenc", "sequence", "beacon", "graph", "slips"},
    "firewall": {"zscore", "iforest", "autoenc", "sequence", "beacon", "graph", "config"},
    "router": {"zscore", "iforest", "autoenc", "sequence", "beacon", "graph", "config"},
    "network": {"zscore", "iforest", "autoenc", "beacon", "graph", "slips"},
}
PRIOR_SCALE = {"zscore": 1.0, "iforest": 0.05, "autoenc": 0.5, "sequence": 1.0, "beacon": 0.2,
               "graph": 1.0, "config": 3.0, "slips": 1.0}
# generic statistical models are never trusted beyond 1e-6; specific semantic detectors beyond 1e-9
MIN_P = {"zscore": 1e-6, "iforest": 1e-6, "autoenc": 1e-6}


# --------------------------------------------------------------------- calibration
class TailCalibrator:
    def __init__(self, prior_scale: float = 1.0, min_p: float = 1e-9):
        self.prior_scale, self.min_p = prior_scale, min_p

    def fit(self, scores) -> TailCalibrator:
        s = np.sort(np.asarray(list(scores) or [0.0], float))
        self.cal, self.n, self.max = s, len(s), float(s[-1])
        self.u = float(np.quantile(s, 0.9))
        exc = s[s > self.u] - self.u
        self.p_u = (1 + len(exc)) / (self.n + 1)
        self.shape, self.scale = 0.0, self.prior_scale
        if len(exc) >= 20:
            try:
                c, _, sc = genpareto.fit(exc, floc=0)
                self.shape, self.scale = float(np.clip(c, 0.0, 0.5)), float(max(sc, 1e-6))
            except Exception:
                self.scale = float(max(exc.mean(), 1e-6))
        elif len(exc) >= 3:
            self.scale = float(max(exc.mean(), 1e-6))
        return self

    def p(self, x: float) -> float:
        if x <= self.max:
            return float((1 + self.n - np.searchsorted(self.cal, x, side="left")) / (self.n + 1))
        tail = self.p_u * genpareto.sf(x - self.u, self.shape, scale=self.scale)
        return float(max(min(tail, 1.0 / (self.n + 1)), self.min_p))


def cauchy_combine(ps) -> float:
    """One-sided Cauchy combination (Liu & Xie, JASA 2020)."""
    ps = np.clip(np.asarray(list(ps), float), 1e-15, 0.5)
    if ps.size == 0:
        return 1.0
    t = float(np.mean(np.tan((0.5 - ps) * np.pi)))
    return 1.0 if t <= 0 else float(np.arctan(1.0 / t) / np.pi)


# ------------------------------------------------------------- vector detectors
class VectorModels:
    """Robust-Z, Isolation Forest and Autoencoder, pooled per device type."""

    def fit(self, Z_by_type: dict) -> VectorModels:
        self.iforest, self.ae, self.fast_if = {}, {}, {}
        for t, Z in Z_by_type.items():
            self.iforest[t] = IsolationForest(n_estimators=150, random_state=0).fit(Z)
            A = self._ae_in(Z)
            self.ae[t] = MLPRegressor(hidden_layer_sizes=(16, 6, 16), alpha=1e-2, max_iter=400,
                                      random_state=0, learning_rate_init=3e-3).fit(A, A)
            # fast scorer for small batches; only used if it reproduces sklearn exactly
            probe = Z[:16]
            try:
                self.fast_if[t] = bool(np.allclose(self._if_fast(t, probe), self.iforest[t].score_samples(probe), atol=1e-9))
            except Exception:
                self.fast_if[t] = False
        return self

    def _if_fast(self, t, Z):
        """Isolation Forest score_samples without joblib's per-tree dispatch (~20x faster for one window)."""
        from sklearn.ensemble._iforest import _average_path_length
        f = self.iforest[t]
        X = np.ascontiguousarray(Z, dtype=np.float32)
        depths = np.zeros(X.shape[0])
        n_feat = X.shape[1]
        for tree, feats, dpl, apl in zip(f.estimators_, f.estimators_features_, f._decision_path_lengths,
                                         f._average_path_length_per_tree):
            Xi = X if len(feats) == n_feat and (feats == np.arange(n_feat)).all() else np.ascontiguousarray(X[:, feats])
            leaves = tree.tree_.apply(Xi)
            depths += dpl[leaves] + apl[leaves] - 1.0
        denom = len(f.estimators_) * _average_path_length([f.max_samples_])
        return -(2.0 ** (-depths / denom))

    @staticmethod
    def _ae_in(Z):
        return np.clip(Z, -9, 9) / 3.0

    def scores(self, t: str, Zfull: np.ndarray) -> dict:
        z = np.abs(Zfull[:, :len(FEATURES)])
        A = self._ae_in(Zfull)
        return {
            "zscore": np.sort(z, axis=1)[:, -3:].mean(axis=1),
            "iforest": -(self._if_fast(t, Zfull) if getattr(self, "fast_if", {}).get(t) else self.iforest[t].score_samples(Zfull)),
            "autoenc": ((self.ae[t].predict(A) - A) ** 2).mean(axis=1),
        }


# ------------------------------------------------------------ sequence (logs)
class SequenceModel:
    """Interpolated trigram over log templates per device type (DeepLog-lite).
    Score = surprise mass: sum of max(0, -log10 P(next | context) - 1)."""

    def __init__(self):
        self.tri, self.bi, self.uni = defaultdict(Counter), defaultdict(Counter), defaultdict(Counter)
        self.n = Counter()          # totals per context key
        self.ctx = {}

    def _p(self, table, key, x, V):
        return (table[key][x] + 0.01) / (self.n[key] + 0.01 * V)

    def _learn(self, dtype, a, b, t):
        for table, key in ((self.tri, (dtype, a, b)), (self.bi, (dtype, b)), (self.uni, dtype)):
            table[key][t] += 1
            self.n[key] += 1

    def score(self, dtype, dev, templates, learn: bool, ignore=frozenset()) -> tuple:
        a, b = self.ctx.get(dev, ("^", "^"))
        surprise, odd = 0.0, []
        for t in templates:
            if t in ignore:                       # fleet-wide new message type (e.g. patch) -> benign
                self._learn(dtype, a, b, t)
            else:
                V = len(self.uni[dtype]) + 1
                p = (0.7 * self._p(self.tri, (dtype, a, b), t, V) + 0.2 * self._p(self.bi, (dtype, b), t, V)
                     + 0.1 * self._p(self.uni, dtype, t, V))
                s = max(0.0, -math.log10(p) - 1.0)
                if s > 0.5 and len(odd) < 6:
                    odd.append(f"{b} -> {t}")
                surprise += s
                if learn:
                    self._learn(dtype, a, b, t)
            a, b = b, t
        self.ctx[dev] = (a, b)
        return surprise, odd


# ---------------------------------------------------------------- beaconing
class BeaconDetector:
    """Jitter-tolerant periodicity of (src -> external dst) contacts over a 3 h horizon
    (RITA / BAYWATCH idea). Benign periodic pairs seen while baselining are learned."""
    HORIZON, MIN_N, MIN_REG = 3 * 3600, 8, 0.5

    def __init__(self):
        self.hist = defaultdict(deque)
        self.known = set()

    def score(self, dev, flows, now, learn: bool) -> tuple:
        touched = set()
        for e in flows:
            dst = e.a["dst"]
            if is_internal(dst):
                continue
            key = (dev, e.a.get("src", ""), dst)
            self.hist[key].append(e.ts)
            touched.add(key)
        best, info = 0.0, None
        for key in touched:
            dq = self.hist[key]
            while dq and dq[0] < now - self.HORIZON:
                dq.popleft()
            if len(dq) < self.MIN_N:
                continue
            # plain-Python median: these arrays are tiny, numpy's per-call overhead dominated the run time
            ts = sorted(dq)
            iat = [b - a for a, b in zip(ts, ts[1:]) if b - a > 2.0]
            if len(iat) < self.MIN_N - 1:
                continue
            med = statistics.median(iat)
            mad = statistics.median([abs(x - med) for x in iat])
            reg = max(0.0, 1.0 - (mad / (med + 1e-9)) / 0.3) * min(1.0, len(iat) / 20)
            if learn:
                if reg > 0.4:
                    self.known.add(key)
                continue
            if key in self.known or reg < self.MIN_REG:
                continue
            if reg > best:
                best, info = reg, {"src": key[1], "dst": key[2], "period_s": round(med, 1),
                                   "jitter_pct": round(100 * mad / (med + 1e-9), 1), "contacts": len(ts)}
        return best, info


# ------------------------------------------------------------------- graph
class GraphDetector:
    """New internal edges weighted by how rare the destination service is network-wide."""

    def __init__(self):
        self.services = set()

    def score(self, novel_edges) -> float:
        return float(sum(1.0 if (d, p) not in self.services else 0.3 for _, d, p in novel_edges))

    def learn(self, edges) -> None:
        self.services |= {(d, p) for _, d, p in edges}


# ------------------------------------------------------------------ config
RISK_RULES = [
    # name, regex, side, weight, tactic, technique
    ("Permissive any-rule added", r"\b(permit|allow|accept)\b.*\bany\b", "add", 4, "Defense Evasion",
     "T1562.004 Disable or Modify System Firewall"),
    ("New privileged account", r"^(username|user)\b", "add", 4, "Persistence", "T1136 Create Account"),
    ("Logging removed", r"^(logging|syslog|log-forwarding|set log)", "del", 5, "Defense Evasion",
     "T1562 Impair Defenses"),
    ("Logging disabled", r"no logging|log-forwarding disable|logging off", "add", 5, "Defense Evasion",
     "T1562 Impair Defenses"),
    ("Tunnel to external peer", r"tunnel|\bgre\b|ipsec.*peer", "add", 4, "Command and Control",
     "T1572 Protocol Tunneling"),
    ("Traffic mirroring", r"monitor session|\bspan\b|mirror|erspan", "add", 4, "Exfiltration",
     "T1020.001 Traffic Duplication"),
    ("Management plane exposed", r"ip http server|\btelnet\b|api-access any|snmp-server community|management.*any",
     "add", 3, "Persistence", "T1133 External Remote Services"),
    ("NAT / port forward", r"\bnat\b.*static|port-forward|\bdnat\b", "add", 3, "Command and Control", "T1090 Proxy"),
    ("Routing change", r"^ip route|^route |static-route", "add", 1.5, "Defense Evasion",
     "T1599 Network Boundary Bridging"),
    ("DNS server change", r"name-server|dns server|dns-server", "add", 3, "Credential Access",
     "T1557 Adversary-in-the-Middle"),
    ("Boot image / firmware change", r"boot system|firmware|boot-image", "add", 4, "Defense Evasion",
     "T1601 Modify System Image"),
    ("AAA / authentication change", r"^aaa |tacacs|radius", "any", 3, "Credential Access",
     "T1556 Modify Authentication Process"),
    ("Deny rule removed", r"\bdeny\b", "del", 1.5, "Defense Evasion", "T1562.004 Disable or Modify System Firewall"),
]
_RULES = [(n, re.compile(rx, re.I), side, w, ta, te) for n, rx, side, w, ta, te in RISK_RULES]


class ConfigDetector:
    """Vendor-neutral semantic risk of a configuration change, scaled by context:
    inside the maintenance window? known admin? -> planned change gets x0.3,
    unknown actor and/or outside the window get x1.5 each."""

    def __init__(self, inventory):
        self.last = {}
        self.admins = set(inventory.admins)
        self.mh = inventory.maintenance_hours
        self.tz = inventory.tz_offset_hours

    def score(self, dev, cfg_events) -> tuple:
        total, findings = 0.0, []
        for e in cfg_events:
            lines = Counter(ln.strip() for ln in e.a.get("text", "").splitlines() if ln.strip())
            prev = self.last.get(dev)
            self.last[dev] = lines
            if prev is None:
                continue
            added, removed = list((lines - prev).elements()), list((prev - lines).elements())
            if not added and not removed:
                continue
            cats, other = {}, 0
            for side, group in (("add", added), ("del", removed)):
                for ln in group:
                    hit = False
                    for n, rx, rs, w, ta, te in _RULES:
                        if rs in (side, "any") and rx.search(ln):
                            cats.setdefault(n, (w, ta, te))
                            hit = True
                    other += not hit
            hour = ((e.ts / 3600.0) + self.tz) % 24
            in_mw = self.mh[0] <= hour < self.mh[1]
            actor = (e.a.get("user", "?"), e.a.get("src", "?"))
            known = actor in self.admins
            mult = (0.3 if (in_mw and known) else 1.0) * (1.0 if in_mw else 1.5) * (1.0 if known else 1.5)
            s = (sum(w for w, _, _ in cats.values()) + 0.3 * other) * mult
            total += s
            findings.append({
                "ts": e.ts, "actor": f"{actor[0]}@{actor[1]}", "known_admin": known, "maintenance_window": in_mw,
                "added": added[:12], "removed": removed[:12], "score": round(s, 2),
                "risks": [{"risk": n, "tactic": ta, "technique": te} for n, (w, ta, te) in cats.items()],
            })
        return total, findings


# ------------------------------------------------------------- Slips evidence
SLIPS_SEVERITY = {"critical": 5.0, "high": 4.0, "medium": 3.0, "low": 1.5, "info": 0.5}


def slips_score(alerts) -> float:
    """Raw score from Slips evidence in this window: sum(severity x confidence)."""
    return float(sum(SLIPS_SEVERITY.get(str(a.a.get("severity", "")).lower(), 0.5) *
                     float(a.a.get("confidence", 0.5)) for a in alerts))
