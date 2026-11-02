# SPDX-License-Identifier: GPL-2.0-only
"""Adapters: real telemetry -> UBT events.

  load_slips_export(dir)        ubt_events.jsonl + inventory.json written by the Slips module
  read_slips_alerts(path)       Slips alerts.json (IDEA format) -> "alert" events
  read_zeek(path, device)       Zeek conn.log / dns.log (JSON or TSV) -> "flow" / "dns" events
  read_syslog(path, device)     router / firewall / Linux syslog -> "log" (+ "auth") events
  read_config_snapshots(dir, device)   one file per config backup (e.g. Oxidized git checkout)
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re

from .schema import Event, Inventory, read_events

_MASKS = [
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<IP>"),
    (re.compile(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", re.I), "<MAC>"),
    (re.compile(r"\b0x[0-9a-f]+\b|\b[0-9a-f]{12,}\b", re.I), "<HEX>"),
    (re.compile(r"\"[^\"]*\"|'[^']*'"), "<STR>"),
    (re.compile(r"\b\d+(?:\.\d+)?\b"), "<NUM>"),
]
_SYSLOG = re.compile(r"^(?P<ts>\w{3}\s+\d+\s[\d:]+|\d{4}-\d\d-\d\dT[\d:.]+(?:Z|[+-][\d:]+)?)\s+(?P<host>\S+)\s+(?P<msg>.*)$")
# OpenSSH style ("Accepted password for admin from 1.2.3.4") and key=value style
# (Cisco "LOGIN_SUCCESS: [user: admin] [Source: 1.2.3.4]", FortiOS "user=admin srcip=1.2.3.4 ... status=failed")
_AUTH_OK = re.compile(r"(?:Accepted \w+ for(?: invalid user)? (?P<u1>\S+) from (?P<s1>[\d.]+))|"
                      r"(?:(?:LOGIN_SUCCESS|Login Success|login success|logged in).*?user[:=\s]+(?P<u2>[\w.-]+)"
                      r".*?(?:source|from|srcip)[:=\s]+(?P<s2>[\d.]+))", re.I)
_AUTH_FAIL = re.compile(r"(?:Failed password for(?: invalid user)? (?P<u1>\S+) from (?P<s1>[\d.]+))|"
                        r"(?:(?:LOGIN_FAILED|Login failed|login failure|authentication failure|status=failed).*?"
                        r"user[:=\s]+(?P<u2>[\w.-]+).*?(?:source|from|srcip|rhost)[:=\s]+(?P<s2>[\d.]+))", re.I)


class TemplateMiner:
    """Drain-lite: mask variable tokens so 'same message type' maps to one template id."""

    def __init__(self):
        self.ids = {}

    def __call__(self, msg: str) -> str:
        t = msg.strip()
        for rx, rep in _MASKS:
            t = rx.sub(rep, t)
        t = " ".join(t.split()[:12])
        return self.ids.setdefault(t, f"T{len(self.ids):04d}:{t[:60]}")


def load_slips_export(directory: str):
    events = read_events(os.path.join(directory, "ubt_events.jsonl"))
    with open(os.path.join(directory, "inventory.json"), encoding="utf-8") as f:
        inv = Inventory.from_dict(json.load(f))
    return events, inv


def read_slips_alerts(path: str, ip2dev: dict, default_device: str):
    out = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            src = (o.get("Source") or [{}])[0].get("IP", "")
            ts = o.get("StartTime") or o.get("CreateTime")
            try:
                t = dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
            except ValueError:
                continue
            out.append(Event(t, ip2dev.get(src, default_device), "alert",
                             {"severity": str(o.get("Severity", "info")).lower(),
                              "confidence": float(o.get("Confidence", 0.5) or 0.5),
                              "description": str(o.get("Description", ""))[:300]}))
    return out


def read_zeek(path: str, device: str):
    """Zeek conn.log or dns.log, JSON-lines or classic TSV with #fields header."""

    def _int(rec, k):     # Zeek writes "-" for unset fields
        v = rec.get(k, 0)
        return int(float(v)) if v not in ("-", "", None) else 0

    out, fields = [], None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                continue
            if not line.strip() or line.startswith("#"):
                continue
            rec = json.loads(line) if line.lstrip().startswith("{") else dict(zip(fields or [], line.rstrip("\n").split("\t")))
            ts = float(rec.get("ts", 0))
            if "query" in rec:
                if rec["query"] not in ("-", ""):
                    out.append(Event(ts, device, "dns", {"q": rec["query"]}))
                continue
            out.append(Event(ts, device, "flow", {
                "src": rec.get("id.orig_h", ""), "dst": rec.get("id.resp_h", ""), "dport": _int(rec, "id.resp_p"),
                "proto": str(rec.get("proto", "tcp")).lower(), "bout": _int(rec, "orig_bytes"), "bin": _int(rec, "resp_bytes"),
                "dur": float(rec.get("duration") or 0) if rec.get("duration") not in ("-", None) else 0.0}))
    return out


def read_syslog(path: str, device: str, year: int | None = None):
    miner, out = TemplateMiner(), []
    year = year or dt.datetime.now().year
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = _SYSLOG.match(line.strip())
            if not m:
                continue
            raw = m["ts"]
            try:
                t = (dt.datetime.fromisoformat(raw.replace("Z", "+00:00")) if "T" in raw else
                     dt.datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S").replace(tzinfo=dt.timezone.utc))
            except ValueError:
                continue
            ts, msg = t.timestamp(), m["msg"]
            out.append(Event(ts, device, "log", {"t": miner(msg)}))
            for rx, ok in ((_AUTH_OK, True), (_AUTH_FAIL, False)):
                a = rx.search(msg)
                if a:
                    out.append(Event(ts, device, "auth", {"user": a["u1"] or a["u2"] or "?",
                                                          "src": a["s1"] or a["s2"], "ok": ok}))
                    break
    return out


def read_config_snapshots(directory: str, device: str, user: str = "?", src: str = "?"):
    """Each file is one full config backup; its modification time is the change time."""
    out = []
    for name in sorted(os.listdir(directory)):
        p = os.path.join(directory, name)
        if os.path.isfile(p):
            with open(p, encoding="utf-8", errors="replace") as f:
                out.append(Event(os.path.getmtime(p), device, "config", {"text": f.read(), "user": user, "src": src}))
    return sorted(out, key=lambda e: e.ts)
