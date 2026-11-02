# SPDX-License-Identifier: GPL-2.0-only
"""Extract the real-log excerpts shown on the landing page from the captures shipped with Slips.

Every log line comes verbatim from a real capture in `dataset/` (Stratosphere Lab, CTU Prague);
nothing is generated. For the flow captures the script also runs TRINETRA's own feature code
(features.compute) on the busiest 15-minute window, so the page shows what the engine actually
measures on real traffic.

    python -m compromise_dashboard.build_real_logs      -> static/data/real_logs.json
"""
import json
import math
import os
import statistics
from collections import Counter, defaultdict

from modules.compromise_detector.core.features import FEATURE_ATTACK, FIDX, Profile, compute, window_items
from modules.compromise_detector.core.schema import Event

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DS = os.path.join(ROOT, "dataset")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "data", "real_logs.json")
WINDOW = 900
SHOW = [("n_flows", "connections"), ("n_dst", "destinations"), ("n_dport", "destination ports"),
        ("new_dst", "never-seen destinations"), ("failed_conn", "failed connections"),
        ("dport_entropy", "port entropy (bits)"), ("ext_frac", "share to Internet")]
COUNTS = {"n_flows", "n_dst", "n_dport", "new_dst", "failed_conn"}


def zeek_tsv(path):
    fields = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line and not line.startswith("#") and fields:
                yield dict(zip(fields, line.split("\t"))), line


def zeek_json(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.strip():
                yield json.loads(line), line.rstrip("\n")


def clip(s, n=420):
    return s if len(s) <= n else s[:n] + " …"


def num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def flow_event(r):
    return Event(num(r["ts"]), r["id.orig_h"], "flow",
                 {"src": r["id.orig_h"], "dst": r["id.resp_h"], "dport": int(num(r["id.resp_p"])),
                  "proto": r["proto"], "bout": num(r.get("orig_bytes")), "bin": num(r.get("resp_bytes"))})


def engine_features(events):
    """TRINETRA's feature vector for the busiest (host, 15-min window) of a real capture."""
    by = defaultdict(list)
    for e in events:
        by[(e.device, int(e.ts // WINDOW))].append(e)
    (host, w), evs = max(by.items(), key=lambda kv: len(kv[1]))
    f = compute(evs, Profile().novel(window_items(evs)), w * WINDOW)
    out = []
    for name, label in SHOW:
        v = float(f[FIDX[name]])
        v = round(math.expm1(v)) if name in COUNTS else round(v, 2)
        tactic = FEATURE_ATTACK.get(name)
        out.append({"feature": name, "label": label, "value": v, "tactic": tactic[0] if tactic else None,
                    "technique": tactic[1] if tactic else None})
    return {"host": host, "window_flows": len(evs), "features": out}


def pulses(ts, n=80):
    ts = sorted(ts)[:n]
    return [round(t - ts[0], 3) for t in ts]


# ------------------------------------------------------------------- feeds
def remcos():
    """CTU-SME-11 (expert-labelled Windows 7 capture): Remcos RAT C2 traffic + benign traffic."""
    path = os.path.join(DS, "test18-malicious-ctu-sme-11-win", "zeek-labeled", "conn.log.labeled")
    rows, labels, c2, c2_state, events = [], Counter(), defaultdict(list), [], []
    seen_benign = 0
    for r, raw in zeek_tsv(path):
        labels[r["label"]] += 1
        events.append(flow_event(r))
        bad = r["label"].lower().startswith("malicious")
        if bad:
            c2[(r["id.orig_h"], r["id.resp_h"], r["id.resp_p"])].append(num(r["ts"]))
            c2_state.append(r["conn_state"])
        if len(rows) < 16 and (bad and len(rows) < 8 or not bad and seen_benign < 8):
            seen_benign += not bad
            rows.append({"ts": num(r["ts"]), "bad": bad, "raw": clip(raw),
                         "text": f'{r["id.orig_h"]}:{r["id.orig_p"]} → {r["id.resp_h"]}:{r["id.resp_p"]}  '
                                 f'{r["proto"]} {r["conn_state"]}  label={r["label"]} '
                                 f'({r["detailedlabel"].rsplit("-", 1)[-1]})'})
    rows.sort(key=lambda x: x["ts"])
    (src, dst, port), ts = max(c2.items(), key=lambda kv: len(kv[1]))
    ts.sort()
    iat = [b - a for a, b in zip(ts, ts[1:])]
    med = statistics.median(iat)
    mad = statistics.median([abs(x - med) for x in iat])
    failed = sum(1 for s in c2_state if s in ("REJ", "S0"))
    return {
        "lines": rows, "labels": dict(labels), "pulses": pulses(ts), "engine": engine_features(events),
        "signals": [["C2 contacts", f"{len(ts)}"], ["time span", f"{round(ts[-1] - ts[0])} s"],
                    ["period (median)", f"{med:.2f} s"], ["jitter (MAD / median)", f"{100 * mad / med:.1f} %"],
                    ["rejected by server", f"{round(100 * failed / len(c2_state))} %"],
                    ["expert labels", ", ".join(f"{k} {v}" for k, v in labels.most_common())]],
        "c2": {"src": src, "dst": dst, "port": port},
    }


def mozi():
    """Mozi IoT botnet: the infected device fetches the Mozi payload and a shell script over HTTP."""
    rows, last, hosts, total, payloads = [], None, set(), 0, 0
    for r, raw in zeek_json(os.path.join(DS, "test14-malicious-zeek-dir", "http.log")):
        uri = r.get("uri", "")
        bad = uri.endswith((".m", ".sh")) or "Mozi" in uri
        total += 1
        hosts.add(r.get("host", ""))
        payloads += bad
        if len(rows) >= 14 or (uri == last and not bad):      # skip runs of identical requests (/wpad.dat)
            continue
        last = uri
        rows.append({"ts": r["ts"], "bad": bad, "raw": clip(raw),
                     "text": f'{r["id.orig_h"]}:{r["id.orig_p"]} → {r["id.resp_h"]}:{r["id.resp_p"]}  '
                             f'{r.get("method", "-")} {r.get("host", "-")}{uri[:70]}  '
                             f'{r.get("status_code", "-")} {",".join(r.get("resp_mime_types") or ["-"])}'})
    return {"lines": rows, "signals": [["HTTP requests", str(total)], ["distinct Host headers", str(len(hosts))],
                                       ["payload fetches (/Mozi.m, /bin.sh)", str(payloads)],
                                       ["Host header", "raw IP address"]]}


def telnet_scan():
    rows, ports, srcs, total = [], Counter(), set(), 0
    for r, raw in zeek_tsv(os.path.join(DS, "test10-mixed-zeek-dir", "notice.log")):
        total += 1
        if r.get("p", "").isdigit():
            ports[r["p"]] += 1
        srcs.add(r.get("src", ""))
        if len(rows) < 14:
            rows.append({"ts": num(r["ts"]), "bad": True, "raw": clip(raw), "text": f'{r["note"]}  {r["msg"]}'})
    return {"lines": rows, "signals": [["Zeek notices", str(total)], ["scanners", str(len(srcs))],
                                       ["ports targeted", ", ".join(sorted(ports, key=int))],
                                       ["typical target", "routers / IoT (telnet 23, 2323, 8080)"]]}


def suricata():
    rows, sigs, total, rep = [], Counter(), 0, 0
    with open(os.path.join(DS, "test6-malicious.suricata.json"), encoding="utf-8") as f:
        for line in f:
            if '"event_type":"alert"' not in line:
                continue
            r = json.loads(line)
            a = r["alert"]
            total += 1
            sigs[a["signature"]] += 1
            rep += any(k in a["signature"] for k in ("CINS", "Dshield", "DROP", "Reputation", "Block Listed", "Spamhaus"))
            if len(rows) < 14:
                rows.append({"ts": r["timestamp"], "bad": True, "raw": clip(line.strip()),
                             "text": f'{r["src_ip"]}:{r["src_port"]} → {r["dest_ip"]}:{r["dest_port"]}  '
                                     f'[{a["category"]}] {a["signature"]}'})
    return {"lines": rows, "signals": [["signature alerts", str(total)], ["distinct signatures", str(len(sigs))],
                                       ["based on IP reputation lists", f"{round(100 * rep / max(1, total))} %"],
                                       ["new attacker, new IP", "no list entry, no alert"]]}


def port_scan():
    rows, events, states = [], [], Counter()
    for r, raw in zeek_json(os.path.join(DS, "port-scans", "vertical", "conn.log")):
        r = {k: (str(v) if k in ("id.resp_p",) else v) for k, v in r.items()}
        events.append(flow_event(r))
        states[r["conn_state"]] += 1
        if len(rows) < 14:
            rows.append({"ts": r["ts"], "bad": r["conn_state"] in ("REJ", "S0"), "raw": clip(raw),
                         "text": f'{r["id.orig_h"]}:{r["id.orig_p"]} → {r["id.resp_h"]}:{r["id.resp_p"]}  '
                                 f'{r["proto"]} {r["conn_state"]} hist={r["history"]} '
                                 f'pkts={r["orig_pkts"]}/{r["resp_pkts"]}'})
    n = sum(states.values())
    return {"lines": rows, "engine": engine_features(events), "pulses": pulses([e.ts for e in events]),
            "signals": [["connections", str(n)], ["distinct ports", str(len({e.a["dport"] for e in events}))],
                        ["rejected / no answer", f"{round(100 * (states['REJ'] + states['S0']) / max(1, n))} %"],
                        ["scanner", events[0].a["src"] if events else "-"]]}


META = [
    ("remcos", remcos, "Remcos RAT · Windows 7", "Zeek conn.log (expert-labelled)", "system",
     "dataset/test18-malicious-ctu-sme-11-win", "CTU-SME-11, Stratosphere Lab (zenodo.org/records/7958259)"),
    ("mozi", mozi, "Mozi IoT botnet", "Zeek http.log", "router",
     "dataset/test14-malicious-zeek-dir/http.log", "Stratosphere Lab malware capture"),
    ("portscan", port_scan, "Vertical port scan", "Zeek conn.log", "network",
     "dataset/port-scans/vertical/conn.log", "Slips test capture (nmap against scanme.nmap.org)"),
    ("telnet", telnet_scan, "Telnet / IoT scanning", "Zeek notice.log", "network",
     "dataset/test10-mixed-zeek-dir/notice.log", "CTU university network capture"),
    ("suricata", suricata, "Signature alerts at the perimeter", "Suricata eve.json", "firewall",
     "dataset/test6-malicious.suricata.json", "Stratosphere Lab honeypot capture"),
]


def main():
    feeds = []
    for fid, fn, title, kind, device, source, origin in META:
        feeds.append({"id": fid, "title": title, "kind": kind, "device": device, "source": source,
                      "origin": origin, **fn()})
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"feeds": feeds}, f, ensure_ascii=False)
    for fd in feeds:
        print(f'{fd["id"]:<9} {len(fd["lines"]):>2} lines  {sum(x["bad"] for x in fd["lines"]):>2} flagged')
    print(f"-> {os.path.relpath(OUT, ROOT)}")


if __name__ == "__main__":
    main()
