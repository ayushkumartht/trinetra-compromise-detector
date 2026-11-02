# SPDX-License-Identifier: GPL-2.0-only
"""End-to-end runs: simulate -> fit -> detect -> evaluate (+ ablation study)."""
from __future__ import annotations

import copy
import time

from .detectors import DETECTORS, DETECTOR_LABEL
from .engine import Engine
from .schema import WINDOW
from .simulate import simulate

RECOMMENDED_ACTIONS = {
    "host": [
        "Isolate the host from the network (keep it powered on to preserve memory)",
        "Capture memory and triage artefacts (e.g. Velociraptor / KAPE)",
        "Review the never-seen process chains and persistence (services, scheduled tasks, run keys)",
        "Reset credentials of every account that logged on to this host",
        "Block the beacon / exfiltration destinations listed in the evidence at the perimeter",
    ],
    "firewall": [
        "Restrict the management interface to the admin network immediately",
        "Export the running policy and admin audit log; diff against the last known-good backup",
        "Remove rogue rules/accounts only after evidence is preserved",
        "Verify the firmware image hash against the vendor's published value",
        "Rotate all admin credentials and API keys",
    ],
    "router": [
        "Collect running + startup config, 'show tech-support' and a core dump before any reboot",
        "Verify the OS/firmware image hash against the vendor's known-good value",
        "Check for tunnels, mirror/ERSPAN sessions, new local users and removed logging hosts",
        "Re-enable remote logging and AAA; rotate local and TACACS credentials",
        "Inspect neighbour NetFlow for traffic the router no longer reports itself",
    ],
    "network": [
        "Identify the internal hosts behind the anomalous flows (see related devices)",
        "Increase capture (full PCAP via Slips/Zeek) on the affected segment",
        "Apply temporary egress filtering for the beacon / exfiltration destinations",
        "Hunt for the same behaviour on peer segments",
    ],
}


def evaluate(engine: Engine, truth: dict) -> dict:
    comp = truth["compromised"]
    rows = []
    tp = fp = fn = tn = touched = 0
    ttd = []
    last = max(t for tl in engine.timeline.values() for t, _, _ in tl)
    days = (last + WINDOW - engine.train_end) / 86400
    fa_windows = 0
    for d, st in engine.state.items():
        positive, detected = d in comp, st["verdict"] == "COMPROMISED"
        if positive and detected:
            tp += 1
            ttd.append((st["compromised_at"] - comp[d]) / 60)
        elif positive:
            fn += 1
        elif detected:
            fp += 1
        else:
            tn += 1
        if not positive:
            fa_windows += st["alarm_windows"]
            touched += st["alarm_windows"] > 0
        rows.append({"device": d, "truth": "attacked" if positive else "clean", "verdict": st["verdict"],
                     "alarm_windows": st["alarm_windows"],
                     "ttd_min": round((st["compromised_at"] - comp[d]) / 60) if positive and detected else None})
    clean = len(engine.devices) - len(comp)
    return {
        "devices": rows, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(tp / (tp + fp), 3) if tp + fp else 1.0,
        "recall": round(tp / (tp + fn), 3) if tp + fn else 1.0,
        "f1": round(2 * tp / (2 * tp + fp + fn), 3) if tp else 0.0,
        "median_ttd_min": round(sorted(ttd)[len(ttd) // 2]) if ttd else None,
        "clean_devices_with_any_alarm": touched,
        "false_alarm_windows_per_device_day": round(fa_windows / max(clean, 1) / days, 3),
        "n_attacked": len(comp), "n_clean": clean, "test_days": round(days, 1),
    }


def _short(ev: dict) -> dict:
    return {k: ev[k] for k in ("tp", "fp", "fn", "precision", "recall", "f1", "median_ttd_min",
                               "clean_devices_with_any_alarm", "false_alarm_windows_per_device_day")}


def run_demo(seed: int = 7, ablations: bool = True, progress=None) -> dict:
    progress = progress or (lambda f, m: None)
    t0 = time.time()
    progress(0.02, "Simulating 7-day enterprise: 22 devices, 4 attack campaigns, 6 benign traps")
    events, inv, truth = simulate(seed)
    eng = Engine(inv, progress=progress).fit(events, truth["train_end"])
    fitted = copy.deepcopy(eng) if ablations else None
    eng.detect(events)
    out = eng.results()
    out["evaluation"] = evaluate(eng, truth)
    if ablations:
        rows = [{"variant": "Full system (all layers)", **_short(out["evaluation"])}]
        variants = [("Without fleet consensus", {"consensus": False}),
                    ("Without kill-chain corroboration", {"corroboration": False}),
                    ("Without CUSUM persistence", {"cusum": False})]
        variants += [(f"Single detector: {DETECTOR_LABEL[n]}", {"active": {n}, "corroboration": False})
                     for n in DETECTORS if n != "slips"]
        for i, (name, kw) in enumerate(variants):
            progress(0.95 + 0.04 * i / len(variants), f"Ablation study: {name}")
            e = copy.deepcopy(fitted)
            for key, val in kw.items():
                setattr(e, key, val)
            e.detect(events)
            rows.append({"variant": name, **_short(evaluate(e, truth))})
        out["ablation"] = rows
    out["truth"] = {"compromised": truth["compromised"], "scenarios": truth["scenarios"]}
    out["meta"] = {"source": "simulation", "t_train_start": truth["t0"], "t_train_end": truth["train_end"],
                   "t_end": max(e.ts for e in events), "n_events": len(events), "seed": seed,
                   "runtime_s": round(time.time() - t0, 1), "window_s": WINDOW,
                   "detectors": {k: DETECTOR_LABEL[k] for k in DETECTORS}}
    out["actions"] = RECOMMENDED_ACTIONS
    progress(1.0, "Done")
    return out


def run_real(events, inventory, train_end: float, progress=None) -> dict:
    """Analyse real telemetry (e.g. exported by the Slips module) - no ground truth."""
    progress = progress or (lambda f, m: None)
    t0 = time.time()
    eng = Engine(inventory, progress=progress).fit(events, train_end)
    eng.detect(events)
    out = eng.results()
    out["meta"] = {"source": "real", "t_train_start": events[0].ts, "t_train_end": train_end,
                   "t_end": events[-1].ts, "n_events": len(events), "runtime_s": round(time.time() - t0, 1),
                   "window_s": WINDOW, "detectors": {k: DETECTOR_LABEL[k] for k in DETECTORS}}
    out["actions"] = RECOMMENDED_ACTIONS
    return out
