# SPDX-License-Identifier: GPL-2.0-only
"""Streaming compromise-detection engine.

  baseline (fit)  ->  calibration (conformal + EVT)  ->  detect window by window
      per window:  features + novelty (fleet consensus, 30 min look-ahead)
                   ->  8 detectors  ->  calibrated p-values  ->  Cauchy fusion
                   ->  CUSUM persistence  ->  ATT&CK kill-chain corroboration
                   ->  verdict CLEAN / SUSPICIOUS / COMPROMISED
                   ->  gated online learning (only clean windows update the baseline)
"""
from __future__ import annotations

import math
from collections import defaultdict, deque

import numpy as np

from .detectors import (APPLICABLE, DETECTORS, MIN_P, PRIOR_SCALE, BeaconDetector, ConfigDetector,
                        GraphDetector, SequenceModel, TailCalibrator, VectorModels, cauchy_combine, slips_score)
from .features import (ATTRIBUTION_Z, FEATURE_ATTACK, FEATURES, NEGATIVE_ATTACK, NOVELTY_KINDS, RAW,
                       FleetConsensus, Profile, Standardizer, compute, window_items)
from .schema import WINDOW, is_internal

FEATURE_LABEL = {
    "n_flows": "connections", "bytes_out": "bytes sent", "bytes_in": "bytes received",
    "ext_bytes_out": "bytes sent to Internet", "out_in_ratio": "Internet upload/download ratio (log)",
    "n_dst": "distinct destinations", "n_dport": "distinct ports", "dst_entropy": "destination entropy",
    "dport_entropy": "port entropy", "new_dst": "never-seen destinations", "new_dport": "never-seen ports",
    "new_int_edges": "new internal connections", "int_fanout": "internal hosts contacted",
    "ext_frac": "external traffic share", "failed_conn": "failed connections", "n_dns": "DNS queries",
    "dns_entropy": "DNS name randomness", "dns_new_domains": "never-seen domains",
    "dns_max_sub": "unique sub-domains per domain", "n_auth": "authentications", "auth_fail": "failed logins",
    "auth_new_pairs": "new user@source logins", "n_proc": "processes started",
    "new_proc_pairs": "never-seen process chains", "n_logs": "log messages", "new_templates": "never-seen log types",
    "cpu": "CPU %", "mem": "memory %",
}
LOOK = 2   # consensus look-ahead windows (decision latency 30 min)


def bucket(events) -> dict:
    out = defaultdict(lambda: defaultdict(list))
    for e in events:
        out[int(e.ts // WINDOW)][e.device].append(e)
    return out


def _disp(f, v):
    return round(float(v), 2) if f in RAW else int(round(math.expm1(max(v, 0.0))))


class Engine:
    def __init__(self, inventory, k=2.0, h=4.0, horizon=96, consensus=True, cusum=True, corroboration=True,
                 detectors=None, progress=None):
        self.inv = inventory
        self.devices = list(inventory.devices)
        self.dtype = {d: inventory.devices[d].type for d in self.devices}
        self.ip = {d: inventory.devices[d].ip for d in self.devices}
        self.ip2dev = inventory.by_ip()
        self.k, self.h, self.horizon = k, h, horizon
        self.consensus, self.cusum, self.corroboration = consensus, cusum, corroboration
        self.active = set(detectors or DETECTORS)
        self.progress = progress or (lambda frac, msg: None)
        self.profiles = {d: Profile() for d in self.devices}
        self.seq, self.beacon, self.graph = SequenceModel(), BeaconDetector(), GraphDetector()
        self.config = ConfigDetector(inventory)
        self.fleet = FleetConsensus(self.dtype)
        self._items = {}

    # ------------------------------------------------------------- features
    def _window_items(self, w, by_dev):
        if w not in self._items:
            self._items[w] = {d: window_items(by_dev.get(d, ())) for d in self.devices}
        return self._items[w]

    def _extract(self, w, by_w, learn_seq: bool, learn_beacon: bool) -> dict:
        ts = w * WINDOW
        by_dev = by_w.get(w, {})
        items = self._window_items(w, by_dev)
        self._items.pop(w - 1, None)
        novel = {d: self.profiles[d].novel(items[d]) for d in self.devices}
        common = {kind: set() for kind in NOVELTY_KINDS}
        if self.consensus:
            self.fleet.add(w, novel)
            for w2 in range(w + 1, w + 1 + LOOK):
                it2 = self._window_items(w2, by_w.get(w2, {}))
                self.fleet.add(w2, {d: self.profiles[d].novel(it2[d]) for d in self.devices})
            common = self.fleet.common(w, LOOK)
            # a change touching at least half of a device class (e.g. a patch rollout), look-ahead included
            self.fleet.touch(w, items)
            for w2 in range(w + 1, w + 1 + LOOK):
                self.fleet.touch(w2, self._window_items(w2, by_w.get(w2, {})))
            self._fleet_change = self.fleet.fleet_change(w)
            if any(common.values()):
                for d in self.devices:
                    for kind in NOVELTY_KINDS:
                        novel[d][kind] = novel[d][kind] - common[kind]
                    self.profiles[d].learn(common)
                self.graph.learn(common["edge"])
        rows = {}
        for d in self.devices:
            evs = by_dev.get(d, [])
            t = self.dtype[d]
            seq_s, odd = self.seq.score(t, d, [e.a.get("t", "") for e in evs if e.kind == "log"], learn_seq,
                                        common["template"])
            b_s, b_info = self.beacon.score(d, [e for e in evs if e.kind == "flow"], ts + WINDOW, learn_beacon)
            c_s, findings = self.config.score(d, [e for e in evs if e.kind == "config"])
            alerts = [e for e in evs if e.kind == "alert"]
            rows[d] = {
                "x": compute(evs, novel[d], ts, self.inv.tz_offset_hours),
                "raw": {"sequence": seq_s, "beacon": b_s, "graph": self.graph.score(novel[d]["edge"]),
                        "config": c_s, "slips": slips_score(alerts)},
                "items": items[d], "novel": novel[d], "odd": odd, "beacon": b_info, "findings": findings,
                "slips": [a.a.get("description", "") for a in alerts][:5],
            }
        return rows

    # ------------------------------------------------------------------ fit
    def fit(self, events, train_end: float) -> Engine:
        by_w = bucket(e for e in events if e.ts < train_end)
        w0, w1 = min(by_w), int(train_end // WINDOW)
        burn = w0 + min(96, (w1 - w0) // 4)
        X_fit, cal = defaultdict(list), []
        for i, w in enumerate(range(w0, w1)):
            is_cal = w >= burn and (w // 8) % 3 == 2      # interleaved 2-hour calibration blocks
            rows = self._extract(w, by_w, learn_seq=True, learn_beacon=not is_cal)
            for d, r in rows.items():
                self.profiles[d].learn(r["items"])
                self.graph.learn(r["items"]["edge"])
                if w < burn:
                    continue
                (cal.append((d, r["x"], r["raw"])) if is_cal else X_fit[d].append(r["x"]))
            if i % 24 == 0:
                self.progress(0.1 + 0.5 * i / (w1 - w0), "Learning normal behaviour of every device (baseline)")
        self.progress(0.62, "Training Isolation Forest + Autoencoder per device type")
        self.std = {d: Standardizer().fit(np.array(X_fit[d])) for d in self.devices}
        Zt = defaultdict(list)
        for d in self.devices:
            Zt[self.dtype[d]].append(self.std[d].full(np.array(X_fit[d])))
        self.vec = VectorModels().fit({t: np.vstack(z) for t, z in Zt.items()})
        self.progress(0.7, "Calibrating detectors (conformal p-values + extreme-value tails)")
        raw = defaultdict(lambda: defaultdict(list))
        per_dev = defaultdict(list)
        for d, x, r in cal:
            per_dev[d].append((x, r))
        for d, lst in per_dev.items():
            t = self.dtype[d]
            vs = self.vec.scores(t, self.std[d].full(np.array([x for x, _ in lst])))
            for name, arr in vs.items():
                raw[t][name].extend(arr.tolist())
            for _, r in lst:
                for name, v in r.items():
                    raw[t][name].append(v)
        self.cal = {t: {name: TailCalibrator(PRIOR_SCALE[name], MIN_P.get(name, 1e-9)).fit(raw[t][name])
                        for name in APPLICABLE[t]} for t in set(self.dtype.values())}
        self.n_cal = {t: len(raw[t]["zscore"]) for t in raw}
        self.train_end = train_end
        self._reset()
        return self

    def _reset(self):
        self.state = {d: {"S": 0.0, "verdict": "CLEAN", "first_alarm": None, "compromised_at": None,
                          "last_alarm": None, "tactics": deque(), "max_s": 0.0, "reason": "",
                          "alarm_windows": 0} for d in self.devices}
        self.timeline = {d: [] for d in self.devices}
        self.evidence = {d: [] for d in self.devices}
        self.verdict_events = []
        self.edge_log = deque()

    # --------------------------------------------------------------- detect
    def detect(self, events, start=None, end=None):
        start = self.train_end if start is None else start
        by_w = bucket(e for e in events if e.ts >= start and (end is None or e.ts < end))
        if not by_w:
            return self
        self._items = {}
        w0, w1 = int(start // WINDOW), max(by_w) + 1
        for i, w in enumerate(range(w0, w1)):
            self.detect_window(w, by_w)
            if i % 24 == 0:
                self.progress(0.75 + 0.2 * i / (w1 - w0), "Detecting (streaming 15-minute windows)")
        return self

    def detect_window(self, w, by_w):
        rows = self._extract(w, by_w, learn_seq=False, learn_beacon=False)
        by_dev = by_w.get(w, {})
        Zs = {d: self.std[d].full(r["x"]) for d, r in rows.items()}
        vec = {}
        for t in set(self.dtype.values()):                     # one batched model call per device type
            devs = [d for d in self.devices if self.dtype[d] == t]
            sc = self.vec.scores(t, np.vstack([Zs[d] for d in devs]))
            for i, d in enumerate(devs):
                vec[d] = {name: float(arr[i]) for name, arr in sc.items()}
        for d, r in rows.items():
            t, st = self.dtype[d], self.state[d]
            Z = Zs[d]
            raw = dict(vec[d])
            raw.update(r["raw"])
            ps = {name: self.cal[t][name].p(raw[name]) for name in APPLICABLE[t] if name in self.active}
            if t == "network" and getattr(self, "_fleet_change", False) and self.consensus:
                # a sensor aggregates the whole segment: during a fleet-wide change (patch rollout) its volume
                # shift is explained by that change, so only the non-volumetric detectors speak for it
                for name in ("zscore", "iforest", "autoenc"):
                    ps.pop(name, None)
            s = min(-math.log10(max(cauchy_combine(ps.values()), 1e-300)), 30.0)
            st["S"] = max(0.0, (st["S"] if self.cusum else 0.0) + s - self.k)
            alarm = st["S"] > self.h
            st["max_s"] = max(st["max_s"], s)
            if s >= 3.0 or alarm:
                ev = self._explain(d, w, r, Z[0], ps, s, alarm)
                self.evidence[d].append(ev)
                for ta in ev["tactics"]:
                    st["tactics"].append((w, ta))
            while st["tactics"] and st["tactics"][0][0] < w - self.horizon:
                st["tactics"].popleft()
            self.timeline[d].append((w * WINDOW, round(s, 3), round(st["S"], 3)))
            if alarm:
                st["alarm_windows"] += 1
                st["last_alarm"] = w
                st["first_alarm"] = st["first_alarm"] or w * WINDOW
            self._verdict(d, w, alarm)
            # successful new internal connections (not scans) for lateral-movement propagation
            if t != "network" and len({dst for _, dst, _ in r["novel"]["edge"]}) < 10:
                ok = {(e.a.get("src"), e.a["dst"]) for e in by_dev.get(d, ())
                      if e.kind == "flow" and e.a.get("bin", 0) > 0}
                for src, dst, _ in r["novel"]["edge"]:
                    if (src, dst) in ok:
                        self.edge_log.append((w, src, dst))
            if s < 1.3 and not alarm and st["verdict"] == "CLEAN":     # gated online learning
                self.profiles[d].learn(r["items"])
                self.graph.learn(r["items"]["edge"])
        self._propagate(w)

    def _set(self, d, w, verdict, reason):
        st = self.state[d]
        self.verdict_events.append({"ts": w * WINDOW, "device": d, "from": st["verdict"], "to": verdict,
                                    "reason": reason})
        st["verdict"], st["reason"] = verdict, reason
        if verdict == "COMPROMISED":
            st["compromised_at"] = w * WINDOW

    def _verdict(self, d, w, alarm):
        st = self.state[d]
        if st["verdict"] == "COMPROMISED":
            return
        tactics = sorted({ta for _, ta in st["tactics"]})
        if alarm and (not self.corroboration or len(tactics) >= 2):
            self._set(d, w, "COMPROMISED", ("Persistent anomaly corroborated by multiple attack stages: "
                                            + ", ".join(tactics)) if tactics else "Persistent anomaly")
        elif alarm and st["verdict"] == "CLEAN":
            self._set(d, w, "SUSPICIOUS", "Persistent behavioural anomaly" +
                      (f" ({tactics[0]})" if tactics else "") + " - awaiting corroboration")
        elif not alarm and st["verdict"] == "SUSPICIOUS" and w - st["last_alarm"] > self.horizon:
            self._set(d, w, "CLEAN", "No anomaly for 24 h")

    def _propagate(self, w):
        while self.edge_log and self.edge_log[0][0] < w - self.horizon:
            self.edge_log.popleft()
        bad = {self.ip[d] for d, st in self.state.items() if st["verdict"] == "COMPROMISED"}
        if not bad:
            return
        for d, st in self.state.items():
            if st["verdict"] != "SUSPICIOUS" or self.dtype[d] == "network" or not st["tactics"]:
                continue
            for _, src, dst in self.edge_log:
                if dst == self.ip[d] and src in bad:
                    self._set(d, w, "COMPROMISED", f"Anomalous and received a new connection from compromised "
                              f"{self.ip2dev.get(src, src)} (lateral movement)")
                    break

    def mark_benign(self, d, w):
        """Analyst feedback: resolve a device as benign and reset its evidence accumulator."""
        st = self.state[d]
        st["S"], st["tactics"] = 0.0, deque()
        self._set(d, w, "CLEAN", "Marked benign by analyst")

    # -------------------------------------------------------------- explain
    def _explain(self, d, w, r, z, ps, s, alarm) -> dict:
        tactics = defaultdict(set)
        sd = self.std[d]
        top = []
        for i in np.argsort(-np.abs(z[:len(FEATURES)]))[:6]:
            if abs(z[i]) < 3:
                break
            f = FEATURES[i]
            top.append({"feature": FEATURE_LABEL[f], "key": f, "value": _disp(f, r["x"][i]),
                        "normal": _disp(f, sd.med[i]), "z": round(float(z[i]), 1)})
        if min(ps.get(x, 1.0) for x in ("zscore", "iforest", "autoenc")) < 0.01:
            for i, f in enumerate(FEATURES):
                if f in FEATURE_ATTACK and z[i] > ATTRIBUTION_Z.get(f, 4.0):
                    tactics[FEATURE_ATTACK[f][0]].add(FEATURE_ATTACK[f][1])
                if f in NEGATIVE_ATTACK and z[i] < -4:
                    tactics[NEGATIVE_ATTACK[f][0]].add(NEGATIVE_ATTACK[f][1])
        if ps.get("beacon", 1) < 0.01:
            tactics["Command and Control"].add("T1071 Application Layer Protocol (periodic beaconing)")
        if ps.get("graph", 1) < 0.01 and r["raw"]["graph"] >= 1.0:     # >= 1 edge to a never-used service
            tactics["Lateral Movement"].add("T1021 Remote Services")
            if len({dst for _, dst, _ in r["novel"]["edge"]}) >= 10:
                tactics["Discovery"].add("T1046 Network Service Discovery")
        for fnd in r["findings"]:
            for risk in fnd["risks"]:
                tactics[risk["tactic"]].add(risk["technique"])
        nov = r["novel"]
        related = sorted({dst for _, dst, _ in nov["edge"]} | {src for _, src in nov["authpair"]}
                         | ({r["beacon"]["dst"]} if r["beacon"] else set())
                         | {f["actor"].split("@")[-1] for f in r["findings"]})
        name = lambda ip: self.ip2dev.get(ip, ip)
        return {
            "ts": w * WINDOW, "score": round(s, 2), "alarm": alarm,
            "detectors": {k: round(-math.log10(max(v, 1e-300)), 2) for k, v in ps.items()},
            "top_features": top,
            "tactics": {k: sorted(v) for k, v in tactics.items()},
            "beacon": r["beacon"], "config": r["findings"], "odd_logs": r["odd"], "slips": r["slips"],
            "new_internal": [f"{name(a)} -> {name(b)}:{p}" for a, b, p in sorted(nov["edge"])[:8]],
            "n_new_internal": len(nov["edge"]),
            "new_external": sorted(x for x in nov["dst"] if not is_internal(x))[:8],
            "new_processes": [f"{a} -> {b}" for a, b in sorted(nov["procpair"])[:6]],
            "new_logins": [f"{u}@{name(s_)}" for u, s_ in sorted(nov["authpair"])[:6]],
            "new_domains": sorted(nov["domain"])[:6],
            "related_ips": related[:60],
        }

    # -------------------------------------------------------------- results
    def incidents(self) -> list:
        """Compromised hosts/appliances linked by direct relations (new connections, logins, shared external
        attacker IPs) form one incident; network sensors join every incident they observed; suspicious
        devices are reported as separate 'watch' items."""
        flagged = [d for d, st in self.state.items()
                   if st["verdict"] == "COMPROMISED" and self.dtype[d] != "network"]
        parent = {d: d for d in flagged}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        ips_of = {d: set() for d in flagged}
        for d in flagged:
            for ev in self.evidence[d]:
                if ev["n_new_internal"] < 10:          # a scan touches everything; it is not a relation
                    ips_of[d] |= set(ev["related_ips"])
        for a in flagged:
            for b in flagged:
                if a < b and (self.ip[a] in ips_of[b] or self.ip[b] in ips_of[a] or
                              any(not is_internal(x) for x in ips_of[a] & ips_of[b])):
                    parent[find(a)] = find(b)
        groups = defaultdict(list)
        for d in flagged:
            groups[find(d)].append(d)
        groups = list(groups.values())
        for n in (d for d, st in self.state.items() if self.dtype[d] == "network" and st["verdict"] != "CLEAN"):
            seen_ips = {ip for ev in self.evidence[n] for ip in ev["related_ips"]} | {
                ip for ev in self.evidence[n] for x in ev["new_internal"] for ip in [x.split(" -> ")[0]]}
            for g in groups:
                if any(self.ip[d] in seen_ips or d in seen_ips for d in g):
                    g.append(n)
        groups += [[d] for d, st in self.state.items() if st["verdict"] == "SUSPICIOUS"]
        out = []
        for devs in groups:
            chain = []
            for d in devs:
                seen = set()
                for ev in self.evidence[d]:
                    for ta, techs in ev["tactics"].items():
                        if (ta, techs[0]) not in seen:
                            seen.add((ta, techs[0]))
                            chain.append({"ts": ev["ts"], "device": d, "tactic": ta, "technique": techs[0]})
            chain.sort(key=lambda c: c["ts"])
            starts = [self.state[d]["first_alarm"] for d in devs if self.state[d]["first_alarm"]]
            sev = "critical" if any(self.state[d]["verdict"] == "COMPROMISED" for d in devs) else "warning"
            out.append({"devices": sorted(devs), "severity": sev,
                        "start": min(starts) if starts else (chain[0]["ts"] if chain else 0),
                        "kill_chain": chain[:80], "tactics": sorted({c["tactic"] for c in chain})})
        out.sort(key=lambda x: (x["severity"] != "critical", x["start"]))
        for i, inc in enumerate(out):
            inc["id"] = f"INC-{i + 1:03d}"
        return out

    def results(self) -> dict:
        devs = []
        for d in self.devices:
            st, dev = self.state[d], self.inv.devices[d]
            devs.append({
                "id": d, "type": dev.type, "ip": dev.ip, "role": dev.role, "verdict": st["verdict"],
                "reason": st["reason"], "compromised_at": st["compromised_at"], "first_alarm": st["first_alarm"],
                "max_score": round(st["max_s"], 2), "alarm_windows": st["alarm_windows"],
                "tactics": sorted({ta for ev in self.evidence[d] for ta in ev["tactics"]}),
                "coverage": sorted(x for x in APPLICABLE[dev.type] if x in self.active),
            })
        ev = {d: sorted(sorted(self.evidence[d], key=lambda e: -e["score"])[:40], key=lambda e: e["ts"])
              for d in self.devices}
        return {"devices": devs, "timeline": self.timeline, "evidence": ev,
                "verdict_events": self.verdict_events, "incidents": self.incidents(),
                "params": {"k": self.k, "h": self.h, "horizon_h": self.horizon * WINDOW / 3600,
                           "window_min": WINDOW // 60, "calibration_windows": self.n_cal,
                           "consensus_latency_min": LOOK * WINDOW // 60}}
