# SPDX-License-Identifier: GPL-2.0-only
"""TRINETRA dashboard backend (Flask).

  GET  /                     landing page
  GET  /console              analyst console
  GET  /docs                 documentation site (renders trinetra_docs/*.md)
  GET  /api/docs             documentation index
  GET  /docs/raw/<slug>      one markdown page
  GET  /api/results          latest analysis (verdicts, timelines, evidence, incidents, evaluation)
  GET  /api/status           background job progress
  POST /api/run              {"seed": 7} re-run the simulated enterprise demo
  POST /api/mark_benign      {"device": "WS-07"} analyst feedback
  GET  /api/export/cef       verdicts as CEF lines for any SIEM
  GET  /api/export/json      full report download
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import threading
import time

from flask import Flask, Response, jsonify, request, send_from_directory

from modules.compromise_detector.core.pipeline import run_demo, run_real

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
DOCS = os.path.join(os.path.dirname(HERE), "trinetra_docs")
RESULTS = os.path.join(DATA, "results.json")

app = Flask(__name__, static_folder=os.path.join(HERE, "static"), static_url_path="/static")
job = {"running": False, "progress": 0.0, "message": "", "error": None}
lock = threading.Lock()
_cache = {"mtime": None, "data": None}


def load_results():
    if not os.path.exists(RESULTS):
        return None
    m = os.path.getmtime(RESULTS)
    if _cache["mtime"] != m:
        with open(RESULTS, encoding="utf-8") as f:
            _cache["data"], _cache["mtime"] = json.load(f), m
    return _cache["data"]


def save_results(data):
    os.makedirs(DATA, exist_ok=True)
    tmp = RESULTS + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, separators=(",", ":"))
    os.replace(tmp, RESULTS)


def _progress(frac, msg):
    job["progress"], job["message"] = round(float(frac), 3), msg


def start_job(fn, *args):
    with lock:
        if job["running"]:
            return False
        job.update(running=True, progress=0.0, message="Starting", error=None)

    def work():
        try:
            data = fn(*args, progress=_progress)
            data["meta"]["generated"] = time.time()
            save_results(data)
            _progress(1.0, "Done")
        except Exception as exc:  # surfaced to the UI
            job["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            job["running"] = False

    threading.Thread(target=work, daemon=True).start()
    return True


def analyse_slips_output(directory):
    from modules.compromise_detector.core.adapters import load_slips_export

    def fn(progress=None):
        events, inv = load_slips_export(directory)
        span = events[-1].ts - events[0].ts
        return run_real(events, inv, events[0].ts + 0.6 * span, progress)
    return fn


@app.get("/")
def landing():
    return send_from_directory(app.static_folder, "landing.html")


@app.get("/console")
def console():
    return send_from_directory(app.static_folder, "console.html")


@app.get("/docs")
def docs():
    return send_from_directory(app.static_folder, "docs.html")


def _doc_pages():
    pages = []
    for name in sorted(os.listdir(DOCS)):
        if not name.endswith(".md"):
            continue
        with open(os.path.join(DOCS, name), encoding="utf-8") as f:
            text = f.read()
        group = re.search(r"<!--\s*group:\s*(.+?)\s*-->", text)
        title = re.search(r"^# (.+)$", text, re.M)
        slug = name[:-3]
        pages.append({"slug": slug, "n": slug.split("-")[0], "group": group[1] if group else "Docs",
                      "title": title[1].strip() if title else slug, "text": text.lower()[:20000]})
    return pages


@app.get("/api/docs")
def api_docs():
    return jsonify(_doc_pages())


@app.get("/docs/raw/<slug>")
def doc_raw(slug):
    if not re.fullmatch(r"[\w-]+", slug) or not os.path.exists(os.path.join(DOCS, slug + ".md")):
        return Response("# Not found", status=404, mimetype="text/markdown")
    return send_from_directory(DOCS, slug + ".md", mimetype="text/markdown")


@app.get("/api/results")
def api_results():
    data = load_results()
    return (jsonify(data), 200) if data else (jsonify({"error": "no results yet"}), 404)


@app.get("/api/status")
def api_status():
    return jsonify({**job, "has_results": os.path.exists(RESULTS)})


@app.post("/api/run")
def api_run():
    body = request.get_json(silent=True) or {}
    ok = start_job(run_demo, int(body.get("seed", 7)), bool(body.get("ablations", True)))
    return jsonify({"started": ok}), (202 if ok else 409)


@app.post("/api/mark_benign")
def api_mark_benign():
    body = request.get_json(silent=True) or {}
    data = load_results()
    dev = next((d for d in (data or {}).get("devices", []) if d["id"] == body.get("device")), None)
    if not dev:
        return jsonify({"error": "unknown device"}), 404
    ts = data["meta"]["t_end"]
    data["verdict_events"].append({"ts": ts, "device": dev["id"], "from": dev["verdict"], "to": "CLEAN",
                                   "reason": "Marked benign by analyst (baseline updated)"})
    data.setdefault("feedback", []).append({"device": dev["id"], "previous": dev["verdict"], "at": time.time()})
    dev["verdict"], dev["reason"] = "CLEAN", "Marked benign by analyst (baseline updated)"
    data["incidents"] = [i for i in data["incidents"] if i["devices"] != [dev["id"]]]
    save_results(data)
    return jsonify({"ok": True})


@app.get("/api/export/cef")
def api_cef():
    data = load_results() or {"devices": []}
    sev = {"COMPROMISED": 10, "SUSPICIOUS": 6, "CLEAN": 1}
    lines = []
    for d in data["devices"]:
        t = d.get("compromised_at") or d.get("first_alarm") or data["meta"]["t_end"]
        tactics = ", ".join(d["tactics"]).replace("=", "\\=")
        reason = d["reason"].replace("|", "/").replace("=", "\\=")
        lines.append(f"CEF:0|TRINETRA|Compromise Detector|0.1|verdict-{d['verdict'].lower()}|"
                     f"Device {d['id']} {d['verdict']}|{sev[d['verdict']]}|rt={int(t * 1000)} dvchost={d['id']} "
                     f"dvc={d['ip']} cs1Label=deviceType cs1={d['type']} cs2Label=tactics cs2={tactics} "
                     f"cs3Label=reason cs3={reason} cn1Label=maxEvidence cn1={d['max_score']}")
    return Response("\n".join(lines) + "\n", mimetype="text/plain",
                    headers={"Content-Disposition": "attachment; filename=trinetra_verdicts.cef"})


@app.get("/api/export/json")
def api_json():
    data = load_results() or {}
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M")
    return Response(json.dumps(data, indent=1), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=trinetra_report_{stamp}.json"})


# interactive labs (what-if, live attack lab, upload, sample data, executive report)
from .labs import labs  # noqa: E402

app.register_blueprint(labs)
