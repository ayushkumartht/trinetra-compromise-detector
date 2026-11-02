# SPDX-License-Identifier: GPL-2.0-only
"""Interactive labs for the console.

  POST /api/whatif          re-run detection on the benchmark week with other parameters / layers
  POST /api/live/start      {"scenario": "A2"} stream a fresh week with one attack injected, window by window
  GET  /api/live/state      latest live snapshot (same schema as /api/results)
  POST /api/live/stop
  POST /api/upload          analyse uploaded telemetry (UBT jsonl, inventory.json, Zeek logs, syslog, configs, Slips alerts)
  GET  /api/sample          sample UBT dataset (zip) to try the upload
  POST /api/restore_demo    switch back to the simulated benchmark after an upload
  GET  /report              printable executive report
"""
from __future__ import annotations

import copy
import io
import json
import os
import shutil
import tempfile
import threading
import time
import zipfile

from flask import Blueprint, Response, jsonify, request, send_from_directory

from modules.compromise_detector.core.detectors import DETECTORS, DETECTOR_LABEL
from modules.compromise_detector.core.engine import Engine, bucket
from modules.compromise_detector.core.pipeline import RECOMMENDED_ACTIONS, evaluate, run_real
from modules.compromise_detector.core.schema import WINDOW, Event, Inventory, is_internal, read_events
from modules.compromise_detector.core.simulate import SCENARIOS, simulate

labs = Blueprint("labs", __name__)
HERE = os.path.dirname(os.path.abspath(__file__))

# ------------------------------------------------------------------ what-if
_fitted = {"seed": None, "engine": None, "events": None, "truth": None}
_fit_lock = threading.Lock()
_whatif_cache: dict = {}


def fitted_engine(seed: int):
    """Fit once per seed and keep it in memory; what-if runs reuse a deep copy."""
    with _fit_lock:
        if _fitted["seed"] != seed:
            events, inv, truth = simulate(seed)
            eng = Engine(inv).fit(events, truth["train_end"])
            _fitted.update(seed=seed, engine=eng, events=events, truth=truth)
            _whatif_cache.clear()
    return _fitted["engine"], _fitted["events"], _fitted["truth"]


def current_seed() -> int:
    from .server import load_results
    data = load_results() or {}
    return int((data.get("meta") or {}).get("seed") or 7)


def prewarm():
    threading.Thread(target=lambda: fitted_engine(current_seed()), daemon=True).start()


@labs.post("/api/whatif")
def api_whatif():
    b = request.get_json(silent=True) or {}
    dets = [d for d in (b.get("detectors") or DETECTORS) if d in DETECTORS] or list(DETECTORS)
    params = {"k": float(b.get("k", 2.0)), "h": float(b.get("h", 4.0)), "consensus": bool(b.get("consensus", True)),
              "corroboration": bool(b.get("corroboration", True)), "cusum": bool(b.get("cusum", True)),
              "detectors": sorted(dets)}
    seed = current_seed()
    key = json.dumps([seed, params], sort_keys=True)
    if key not in _whatif_cache:
        eng, events, truth = fitted_engine(seed)
        e = copy.deepcopy(eng)
        e.k, e.h = params["k"], params["h"]
        e.consensus, e.corroboration, e.cusum = params["consensus"], params["corroboration"], params["cusum"]
        e.active = set(params["detectors"])
        t0 = time.time()
        e.detect(events)
        ev = evaluate(e, truth)
        _whatif_cache[key] = {"params": params, "seed": seed, "runtime_s": round(time.time() - t0, 1),
                              "evaluation": {k: v for k, v in ev.items() if k != "devices"}, "devices": ev["devices"]}
    return jsonify(_whatif_cache[key])


@labs.get("/api/whatif/ready")
def api_whatif_ready():
    return jsonify({"ready": _fitted["seed"] == current_seed()})


# ------------------------------------------------------------------ live attack lab
live = {"running": False, "phase": "", "progress": 0.0, "data": None, "error": None, "scenario": None, "stop": False, "seq": 0}


def _snapshot(eng, events, truth, scenario, t_now, done):
    out = eng.results()
    out["meta"] = {"source": "live", "scenario": scenario, "t_train_start": truth["t0"], "t_train_end": truth["train_end"],
                   "t_end": t_now, "n_events": len(events), "seed": None, "runtime_s": 0, "window_s": WINDOW,
                   "detectors": {k: DETECTOR_LABEL[k] for k in DETECTORS}, "done": done}
    out["actions"] = RECOMMENDED_ACTIONS
    out["truth"] = {"compromised": truth["compromised"], "scenarios": truth["scenarios"]}
    if done:
        out["evaluation"] = evaluate(eng, truth)
    return out


def _live_worker(scenario: str, seed: int, delay: float):
    try:
        live.update(phase="Generating a fresh enterprise week", progress=0.02)
        events, inv, truth = simulate(seed, attacks={scenario})
        prog = lambda f, m: live.update(progress=round(0.05 + 0.45 * f, 3), phase=m)
        eng = Engine(inv, progress=prog).fit(events, truth["train_end"])
        by_w = bucket(e for e in events if e.ts >= eng.train_end)
        eng._items = {}
        w0, w1 = int(eng.train_end // WINDOW), max(by_w) + 1
        for i, w in enumerate(range(w0, w1)):
            if live["stop"]:
                break
            eng.detect_window(w, by_w)
            last = w == w1 - 1
            if i % 2 == 0 or last:
                live["data"] = _snapshot(eng, events, truth, scenario, (w + 1) * WINDOW, last)
                live["seq"] += 1
            live.update(progress=round(0.5 + 0.5 * (i + 1) / (w1 - w0), 3), phase="Streaming detection, live")
            time.sleep(delay)
        if live["stop"] and live["data"]:
            live["data"]["meta"]["done"] = True
        live.update(phase="Finished", progress=1.0)
    except Exception as exc:  # surfaced to the UI
        live["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        live["running"] = False


@labs.post("/api/live/start")
def api_live_start():
    b = request.get_json(silent=True) or {}
    scenario = b.get("scenario", "A2")
    if scenario not in {"A1", "A2", "A3", "A4"}:
        return jsonify({"error": "unknown scenario"}), 400
    if live["running"]:
        return jsonify({"error": "a live run is already in progress"}), 409
    live.update(running=True, phase="Starting", progress=0.0, data=None, error=None, scenario=scenario, stop=False, seq=0)
    seed = int(b.get("seed") or (int(time.time()) % 900 + 11))
    threading.Thread(target=_live_worker, args=(scenario, seed, float(b.get("delay", 0.04))), daemon=True).start()
    return jsonify({"started": True, "seed": seed}), 202


@labs.get("/api/live/state")
def api_live_state():
    since = int(request.args.get("since", -1))
    body = {k: live[k] for k in ("running", "phase", "progress", "error", "scenario", "seq")}
    if live["data"] is not None and live["seq"] != since:
        body["data"] = live["data"]
    return jsonify(body)


@labs.post("/api/live/stop")
def api_live_stop():
    live["stop"] = True
    return jsonify({"ok": True})


@labs.get("/api/scenarios")
def api_scenarios():
    return jsonify([s for s in SCENARIOS if s["kind"] == "attack"])


# ------------------------------------------------------------------ upload
def _guess_kind(name: str) -> str:
    n = name.lower()
    if n == "inventory.json":
        return "inventory"
    if n.endswith(".jsonl"):
        return "ubt"
    if "alerts" in n and n.endswith(".json"):
        return "slips"
    if ("conn" in n or "dns" in n) and n.endswith((".log", ".json")):
        return "zeek"
    if n.endswith((".cfg", ".conf", ".config")) or "config" in n:
        return "config"
    return "syslog"


@labs.post("/api/upload")
def api_upload():
    from .server import start_job
    from modules.compromise_detector.core.adapters import read_config_snapshots, read_slips_alerts, read_syslog, read_zeek

    meta = json.loads(request.form.get("meta", "[]"))
    frac = min(0.9, max(0.3, float(request.form.get("train_frac", 0.6))))
    tmp = tempfile.mkdtemp(prefix="trinetra_upload_")
    entries = []
    for i, m in enumerate(meta):
        f = request.files.get(f"file{i}")
        if not f:
            continue
        safe = f"{i}_" + "".join(c for c in os.path.basename(f.filename or "file") if c.isalnum() or c in "._-")
        path = os.path.join(tmp, safe)
        f.save(path)
        entries.append({**m, "path": path, "name": f.filename})
    if not entries:
        shutil.rmtree(tmp, ignore_errors=True)
        return jsonify({"error": "no files received"}), 400

    def fn(progress=None):
        progress(0.03, "Reading uploaded files")
        events, inv, declared = [], None, {}
        for e in entries:
            kind = e.get("kind") or _guess_kind(e["name"])
            dev, dtype = (e.get("device") or "").strip(), e.get("dtype") or "router"
            if kind == "inventory":
                with open(e["path"], encoding="utf-8") as fh:
                    inv = Inventory.from_dict(json.load(fh))
            elif kind == "ubt":
                events += read_events(e["path"])
            elif kind == "zeek":
                evs = read_zeek(e["path"], "ZEEK-SENSOR")
                events += evs
                events += [Event(x.ts, f"HOST-{x.a['src']}", x.kind, x.a) for x in evs
                           if x.kind == "flow" and is_internal(x.a.get("src", ""))]
            elif kind == "slips":
                events += read_slips_alerts(e["path"], {}, "ZEEK-SENSOR")
            elif kind in ("syslog", "config"):
                if not dev:
                    raise ValueError(f"{e['name']}: please give the device name for syslog/config files")
                declared[dev] = dtype
                if kind == "syslog":
                    events += read_syslog(e["path"], dev)
                else:
                    d = os.path.join(tmp, f"cfg_{len(declared)}_{os.path.basename(e['path'])}")
                    os.makedirs(d, exist_ok=True)
                    shutil.copy(e["path"], d)
                    events += read_config_snapshots(d, dev)
        if not events:
            raise ValueError("no events could be read from the uploaded files")
        events.sort(key=lambda x: x.ts)
        inv = inv or Inventory({})
        from modules.compromise_detector.core.schema import Device
        for x in events:
            if x.device not in inv.devices:
                t = declared.get(x.device) or ("network" if x.device.endswith("SENSOR") else "host")
                ip = x.device[5:] if x.device.startswith("HOST-") else ""
                inv.devices[x.device] = Device(x.device, t, ip, "uploaded")
        span = events[-1].ts - events[0].ts
        if span < 4 * WINDOW:
            raise ValueError("the uploaded data covers less than one hour; at least a few hours are needed")
        progress(0.08, f"{len(events):,} events from {len(inv.devices)} devices")
        out = run_real(events, inv, events[0].ts + frac * span, progress)
        out["meta"]["uploaded"] = [e["name"] for e in entries]
        _backup_demo()
        shutil.rmtree(tmp, ignore_errors=True)
        return out

    if not start_job(fn):
        return jsonify({"error": "an analysis is already running"}), 409
    return jsonify({"started": True, "files": [e["name"] for e in entries]}), 202


def _backup_demo():
    from .server import RESULTS, load_results
    data = load_results()
    if data and (data.get("meta") or {}).get("source") == "simulation":
        shutil.copy(RESULTS, os.path.join(os.path.dirname(RESULTS), "results_demo.json"))


@labs.post("/api/restore_demo")
def api_restore_demo():
    from .server import RESULTS
    demo = os.path.join(os.path.dirname(RESULTS), "results_demo.json")
    if not os.path.exists(demo):
        return jsonify({"error": "no saved benchmark"}), 404
    shutil.copy(demo, RESULTS)
    return jsonify({"ok": True})


@labs.get("/api/sample")
def api_sample():
    seed = current_seed()
    events, inv, _ = simulate(seed)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("ubt_events.jsonl", "".join(json.dumps(e.to_dict(), separators=(",", ":")) + "\n" for e in events))
        z.writestr("inventory.json", json.dumps(inv.to_dict(), indent=1))
        z.writestr("README.txt", "TRINETRA sample dataset (simulated 22-device enterprise, 7 days).\n"
                                 "Upload both files in the console: Upload data -> ubt_events.jsonl + inventory.json.\n")
    return Response(buf.getvalue(), mimetype="application/zip",
                    headers={"Content-Disposition": f"attachment; filename=trinetra_sample_seed{seed}.zip"})


# ------------------------------------------------------------------ report page
@labs.get("/report")
def report_page():
    return send_from_directory(os.path.join(HERE, "static"), "report.html")
