# SPDX-License-Identifier: GPL-2.0-only
"""Slips module: TRINETRA compromise detector bridge.

Slips analyses network traffic. TRINETRA extends it to answer the question
"is this device compromised?" for systems, firewalls, routers and the network,
without relying on IoCs. This module streams what Slips sees into TRINETRA's
Unified Behavioural Telemetry (UBT) format:

  * every flow  -> UBT "flow" event for the source host and for the sensor
  * every DNS   -> UBT "dns" event
  * every Slips evidence -> UBT "alert" event (one of TRINETRA's 8 detectors)

Output (inside the Slips output dir):
  compromise_detector/ubt_events.jsonl   streamed telemetry
  compromise_detector/inventory.json     auto-discovered local hosts + sensor

Router / firewall syslog and config snapshots are merged by the TRINETRA
adapters, then everything is analysed and shown by the dashboard:
  python -m compromise_dashboard --slips-output <output_dir>
"""
import json
import os

from slips_files.common.abstracts.imodule import IModule
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.slips_utils import utils

from modules.compromise_detector.core.schema import is_internal

SENSOR = "SLIPS-SENSOR"


class CompromiseDetector(IModule):
    name = "compromise_detector"
    description = ("TRINETRA: exports Slips flows/DNS/evidence as unified behavioural telemetry for "
                   "IoC-free compromise verdicts on systems, firewalls, routers and networks")
    authors = ["TRINETRA team"]

    def init(self):
        self.classifier = FlowClassifier()
        self.ubt_path = self.get_module_specific_output_path("ubt_events.jsonl")
        self.inv_path = self.get_module_specific_output_path("inventory.json")
        self.out = open(self.ubt_path, "a", encoding="utf-8")
        self.hosts = set()
        self.batch = 50

    def subscribe_to_channels(self):
        self.c_flow = self.db.subscribe("new_flow")
        self.c_dns = self.db.subscribe("new_dns")
        self.c_evidence = self.db.subscribe("evidence_added")
        self.channels = {
            "new_flow": self.c_flow,
            "new_dns": self.c_dns,
            "evidence_added": self.c_evidence,
        }

    @staticmethod
    def _ts(value) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return float(utils.convert_ts_format(value, "unixtimestamp"))

    def _write(self, ts, device, kind, **attrs):
        self.out.write(json.dumps({"ts": ts, "device": device, "kind": kind, **attrs},
                                  separators=(",", ":")) + "\n")

    def _host(self, ip: str) -> str:
        if is_internal(ip):
            self.hosts.add(ip)
            return f"HOST-{ip}"
        return SENSOR

    def handle_flow(self, flow):
        ts = self._ts(flow.starttime)
        sbytes = flow.sbytes if isinstance(flow.sbytes, int) else 0
        dbytes = flow.dbytes if isinstance(flow.dbytes, int) else 0
        attrs = {"src": flow.saddr, "dst": flow.daddr, "dport": int(flow.dport or 0)
                 if str(flow.dport).isdigit() else 0, "proto": str(flow.proto).lower(),
                 "bout": sbytes, "bin": dbytes, "dur": float(flow.dur or 0)}
        self._write(ts, SENSOR, "flow", **attrs)
        if is_internal(flow.saddr):
            self._write(ts, self._host(flow.saddr), "flow", **attrs)

    def handle_dns(self, flow):
        if getattr(flow, "query", None):
            self._write(self._ts(flow.starttime), self._host(flow.saddr), "dns", q=flow.query)

    def handle_evidence(self, evidence: dict):
        profile = evidence.get("profile") or {}
        ip = profile.get("ip", "") if isinstance(profile, dict) else str(profile)
        ts = evidence.get("timestamp")
        self._write(self._ts(ts) if ts else 0.0, self._host(ip) if ip else SENSOR, "alert",
                    severity=str(evidence.get("threat_level", "info")).lower(),
                    confidence=float(evidence.get("confidence", 0.5) or 0.5),
                    description=str(evidence.get("description", ""))[:300])

    def write_inventory(self):
        devices = [{"id": SENSOR, "type": "network", "ip": "", "role": "Slips sensor"}]
        devices += [{"id": f"HOST-{ip}", "type": "host", "ip": ip, "role": "discovered by Slips"}
                    for ip in sorted(self.hosts)]
        with open(self.inv_path, "w", encoding="utf-8") as f:
            json.dump({"devices": devices, "maintenance_hours": [1, 3], "admins": []}, f, indent=1)

    def pre_main(self):
        utils.drop_root_privs_permanently()

    def main(self):
        for _ in range(self.batch):
            if msg := self.get_msg("new_flow"):
                msg = json.loads(msg["data"])
                self.handle_flow(self.classifier.convert_to_flow_obj(msg["flow"]))
            else:
                break
        if msg := self.get_msg("new_dns"):
            msg = json.loads(msg["data"])
            self.handle_dns(self.classifier.convert_to_flow_obj(msg["flow"]))
        if msg := self.get_msg("evidence_added"):
            try:
                self.handle_evidence(json.loads(msg["data"]))
            except (ValueError, TypeError):
                self.print_traceback()

    def shutdown_gracefully(self):
        self.out.flush()
        self.out.close()
        self.write_inventory()
        self.print(f"UBT telemetry written to {os.path.dirname(self.ubt_path)}", 2, 0)
