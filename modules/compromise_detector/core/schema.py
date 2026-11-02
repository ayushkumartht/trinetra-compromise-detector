# SPDX-License-Identifier: GPL-2.0-only
"""Unified Behavioural Telemetry (UBT).

Every device type -- endpoint/server ("host"), "firewall", "router" and passive
"network" sensor -- is reduced to the same event kinds, so one detection
pipeline serves all of them. Adapters (see adapters.py) translate Slips flows
and evidence, Zeek logs, syslog and config snapshots into UBT JSON lines.

    kind      attributes
    flow      src, dst, dport, proto, bout, bin, dur
    dns       q
    auth      user, src, ok
    proc      name, parent, user
    log       t (template id; mined from raw text by adapters.TemplateMiner)
    config    text (full running config), user, src
    resource  cpu, mem
    alert     severity, confidence, description (external sensors, e.g. Slips evidence)
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from functools import lru_cache

DEVICE_TYPES = ("host", "firewall", "router", "network")
KINDS = ("flow", "dns", "auth", "proc", "log", "config", "resource", "alert")
WINDOW = 900  # seconds per analysis window (15 min)


@dataclass(slots=True)
class Event:
    ts: float
    device: str
    kind: str
    a: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"ts": self.ts, "device": self.device, "kind": self.kind, **self.a}

    @staticmethod
    def from_dict(d: dict) -> Event:
        d = dict(d)
        return Event(float(d.pop("ts")), str(d.pop("device")), str(d.pop("kind")), d)


@dataclass(slots=True)
class Device:
    id: str
    type: str
    ip: str
    role: str = ""


@dataclass
class Inventory:
    devices: dict
    maintenance_hours: tuple = (1, 3)       # [start, end) local hour for planned changes
    admins: set = field(default_factory=set)  # {(user, src_ip)} known network admins
    tz_offset_hours: float = 0.0

    def by_ip(self) -> dict:
        return {d.ip: d.id for d in self.devices.values()}

    def to_dict(self) -> dict:
        return {
            "devices": [{"id": d.id, "type": d.type, "ip": d.ip, "role": d.role}
                        for d in self.devices.values()],
            "maintenance_hours": list(self.maintenance_hours),
            "admins": [list(x) for x in sorted(self.admins)],
            "tz_offset_hours": self.tz_offset_hours,
        }

    @staticmethod
    def from_dict(d: dict) -> Inventory:
        devs = {x["id"]: Device(x["id"], x["type"], x.get("ip", ""), x.get("role", ""))
                for x in d["devices"]}
        for dev in devs.values():
            if dev.type not in DEVICE_TYPES:
                raise ValueError(f"{dev.id}: unknown device type {dev.type!r}")
        return Inventory(devs, tuple(d.get("maintenance_hours", (1, 3))),
                         {tuple(x) for x in d.get("admins", [])},
                         float(d.get("tz_offset_hours", 0.0)))


@lru_cache(maxsize=65536)
def is_internal(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def read_events(path: str) -> list:
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(Event.from_dict(json.loads(line)))
    out.sort(key=lambda e: e.ts)
    return out


def write_events(path: str, events) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e.to_dict(), separators=(",", ":")) + "\n")
