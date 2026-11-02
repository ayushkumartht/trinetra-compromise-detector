# SPDX-License-Identifier: GPL-2.0-only
"""Run the TRINETRA dashboard.

  python -m compromise_dashboard                      demo (simulated 22-device enterprise)
  python -m compromise_dashboard --rebuild --seed 11  force a fresh demo analysis
  python -m compromise_dashboard --slips-output output/<run>   analyse telemetry exported by Slips
"""
import argparse
import os

from .labs import prewarm
from .server import RESULTS, analyse_slips_output, app, start_job
from modules.compromise_detector.core.pipeline import run_demo


def main():
    ap = argparse.ArgumentParser(description="TRINETRA compromise-detection dashboard")
    ap.add_argument("--port", type=int, default=5050)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--rebuild", action="store_true", help="re-run the demo analysis on start")
    ap.add_argument("--slips-output", help="Slips output dir containing compromise_detector/ubt_events.jsonl")
    args = ap.parse_args()
    if args.slips_output:
        start_job(analyse_slips_output(os.path.join(args.slips_output, "compromise_detector")))
    elif args.rebuild or not os.path.exists(RESULTS):
        start_job(run_demo, args.seed, True)
    else:
        prewarm()          # fit the what-if engine in the background so the first slider move is quick
    print(f"\n  TRINETRA dashboard -> http://{args.host}:{args.port}\n")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
