# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic multi-device enterprise testbed with ground truth.

Public IDS datasets (CIC-IDS2017, UNSW-NB15, Slips' own pcaps) are flow-only and
contain no router/firewall configs, auth or process telemetry, so they cannot
exercise a cross-device detector. This generator produces a realistic 7-day,
22-device enterprise (12 workstations, 4 servers, 3 routers, 2 firewalls, 1 core
network sensor) with diurnal/weekly rhythms, benign novelty and benign periodic
traffic, then injects IoC-free attack campaigns (fresh random IPs/domains,
living-off-the-land tooling) and benign look-alike events designed to trigger
false alarms.

Attacks (test period):
  A1  Workstation LOTL intrusion -> C2 beacon -> discovery -> credential spraying
      -> lateral movement (WinRM) to file server -> night exfiltration.
  A2  Edge-router implant: night brute force, rogue admin, GRE tunnel + traffic
      mirroring to attacker, syslog host removed.
  A3  Firewall backdoor: admin brute force, any->RDP rule, rogue superuser, API
      exposed, firewall-originated C2, follow-on DB server access.
  A4  Low-and-slow DNS tunnelling exfiltration from a workstation.
Benign traps (test period):
  B1 fleet patch rollout, B2 new legit DB usage, B3 planned router change,
  B4 late-night work, B5 browsing many new sites, B6 backup surge via firewall.
"""
from __future__ import annotations

import datetime as dt
from collections import defaultdict

import numpy as np

from .schema import WINDOW, Device, Event, Inventory

DAY = 86400
T0 = dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc).timestamp()  # a Thursday

DNS, SYSLOG, TACACS, NMS = "10.0.3.53", "10.0.3.5", "10.0.3.6", "10.0.3.20"
TELEMETRY, NTP, VENDOR = "52.96.14.20", "162.159.200.1", "64.233.177.10"
ISP_PEER = "151.101.1.1"
WORDS = ["news", "mail", "cloud", "shop", "video", "docs", "maps", "learn", "bank",
         "travel", "food", "sport", "tech", "music", "health", "jobs", "photo", "wiki"]

HOST_CHAIN = {
    "policy_refresh": [("update_check", 3), ("svc_start", 2), ("policy_refresh", 1)],
    "update_check": [("update_none", 8), ("svc_start", 1)],
    "update_none": [("policy_refresh", 3), ("svc_start", 2), ("logon", 1), ("logoff", 1)],
    "svc_start": [("svc_stop", 3), ("policy_refresh", 2), ("net_change", 1), ("svc_start", 1)],
    "svc_stop": [("svc_start", 3), ("policy_refresh", 2)],
    "logon": [("svc_start", 3), ("policy_refresh", 2)],
    "logoff": [("svc_stop", 2), ("policy_refresh", 2)],
    "net_change": [("svc_start", 2), ("policy_refresh", 1)],
}
ROUTER_CHAIN = {
    "snmp_poll": [("snmp_poll", 3), ("if_counter", 3), ("ntp_sync", 1), ("ospf_hello", 3)],
    "if_counter": [("snmp_poll", 3), ("ospf_hello", 2)],
    "ntp_sync": [("ospf_hello", 2), ("snmp_poll", 2)],
    "ospf_hello": [("ospf_hello", 2), ("snmp_poll", 3), ("if_counter", 1), ("cdp_nbr", 1)],
    "cdp_nbr": [("snmp_poll", 2), ("ospf_hello", 1)],
}
FW_CHAIN = {
    "sess_allow_out": [("sess_allow_out", 6), ("sess_deny_in", 2), ("sess_allow_in_web", 2),
                       ("ha_heartbeat", 1)],
    "sess_deny_in": [("sess_allow_out", 3), ("sess_deny_in", 2), ("ips_match_low", 1)],
    "sess_allow_in_web": [("sess_allow_out", 3), ("sess_allow_in_web", 1)],
    "ha_heartbeat": [("sess_allow_out", 3)],
    "ips_match_low": [("sess_deny_in", 1), ("sess_allow_out", 2)],
}
WS_PROCS = [(("explorer", "browser"), 6), (("explorer", "office"), 4), (("explorer", "mail"), 3),
            (("services", "svchost"), 3), (("svchost", "updater"), 1), (("svchost", "taskhost"), 2),
            (("browser", "browser_renderer"), 5)]
ADMIN_PROCS = [(("explorer", "shell"), 2), (("shell", "ping"), 1), (("shell", "ipconfig"), 1)]
SRV_PROCS = {"SRV-FILE": "smbsvc", "SRV-WEB": "httpd", "SRV-DB": "sqlserver", "SRV-DC": "lsass"}

ROUTER_CFG = """hostname {name}
aaa new-model
tacacs-server host 10.0.3.6
username netadmin privilege 15 secret 5 $1$kQ9$hX0
logging host 10.0.3.5
logging trap informational
ntp server 162.159.200.1
snmp-server group NMS v3 priv
interface Gi0/0
 ip address {ip} 255.255.255.0
interface Gi0/1
 description uplink
router ospf 1
 network 10.0.0.0 0.255.255.255 area 0
access-list 101 permit tcp 10.0.0.0 0.255.255.255 any eq 443
access-list 101 deny ip any any log
line vty 0 4
 transport input ssh"""
FW_CFG = """set hostname {name}
user admin role superuser
set system api-access 10.0.3.0/24
logging host 10.0.3.5
rule 10 permit tcp any host 10.0.2.11 eq 443
rule 20 permit udp 10.0.0.0/8 any eq 53
rule 30 permit tcp 10.0.0.0/8 any eq 443
rule 99 deny ip any any log"""

SCENARIOS = [
    {"id": "A1", "kind": "attack", "devices": ["WS-03", "SRV-FILE", "NET-CORE"],
     "title": "Workstation living-off-the-land intrusion",
     "story": "Malicious document -> script host -> shell; C2 beacon; internal scan; credential spraying; "
              "WinRM lateral movement to the file server; night-time exfiltration."},
    {"id": "A2", "kind": "attack", "devices": ["RTR-EDGE"], "title": "Edge router implant",
     "story": "Night brute force from the Internet; rogue privileged user; GRE tunnel and ERSPAN traffic "
              "mirroring to the attacker; syslog host removed to hide activity."},
    {"id": "A3", "kind": "attack", "devices": ["FW-PERIM", "SRV-DB"], "title": "Perimeter firewall backdoor",
     "story": "Admin brute force; any->RDP rule to the DB server; rogue superuser; management API opened to "
              "any; firewall-originated C2; attacker logs in to the DB server and dumps data."},
    {"id": "A4", "kind": "attack", "devices": ["WS-09"], "title": "Low-and-slow DNS tunnelling",
     "story": "Six hours of long random sub-domain queries to a never-seen domain (data hidden in DNS)."},
    {"id": "B1", "kind": "benign", "devices": ["all hosts"], "title": "Fleet-wide patch rollout",
     "story": "Every host contacts new update servers, runs a new installer and logs a new message type."},
    {"id": "B2", "kind": "benign", "devices": ["WS-07"], "title": "User starts using DB application",
     "story": "Legitimate new internal connection WS-07 -> SRV-DB:1433 every working day."},
    {"id": "B3", "kind": "benign", "devices": ["RTR-CORE"], "title": "Planned router change",
     "story": "Known admin adds a static route inside the 01:00-03:00 maintenance window."},
    {"id": "B4", "kind": "benign", "devices": ["WS-11"], "title": "Late-night work",
     "story": "User works from 22:00 to 01:00 at daytime intensity."},
    {"id": "B5", "kind": "benign", "devices": ["WS-05"], "title": "Research browsing spree",
     "story": "User visits dozens of never-seen websites for two hours."},
    {"id": "B6", "kind": "benign", "devices": ["FW-DC"], "title": "Backup surge",
     "story": "Large nightly backup through the data-centre firewall with triple log volume."},
]


class Simulator:
    def __init__(self, seed: int = 7, days: int = 7, train_days: int = 4, attacks=None):
        self.rng = np.random.default_rng(seed)
        self.days, self.train_days = days, train_days
        # which attack campaigns to inject; skipped campaigns still consume the same random numbers,
        # so benign traffic is identical whatever subset is chosen
        self.attacks = set(attacks) if attacks else {"A1", "A2", "A3", "A4"}
        self._cur = None
        self.t0, self.td = T0, T0 + train_days * DAY
        self.events: list = []
        self.labels: dict = defaultdict(set)
        self.suppress = []
        self.state = {}
        self.cfg = {}
        self._build_inventory()
        self.ext_pool = [self._ext_ip() for _ in range(150)]
        self.domain_of = {ip: f"{WORDS[i % len(WORDS)]}{i}.com" for i, ip in enumerate(self.ext_pool)}

    # ------------------------------------------------------------------ setup
    def _build_inventory(self):
        devs = {}
        for i in range(1, 13):
            devs[f"WS-{i:02d}"] = Device(f"WS-{i:02d}", "host", f"10.0.1.{10 + i}", "workstation")
        for j, n in enumerate(["SRV-FILE", "SRV-WEB", "SRV-DB", "SRV-DC"]):
            devs[n] = Device(n, "host", f"10.0.2.{10 + j}", "server")
        for j, n in enumerate(["RTR-CORE", "RTR-EDGE", "RTR-BRANCH"]):
            devs[n] = Device(n, "router", f"10.0.0.{1 + j}", ["core router", "edge router", "branch router"][j])
        devs["FW-PERIM"] = Device("FW-PERIM", "firewall", "10.0.0.254", "perimeter firewall")
        devs["FW-DC"] = Device("FW-DC", "firewall", "10.0.2.254", "datacentre firewall")
        devs["NET-CORE"] = Device("NET-CORE", "network", "10.0.0.250", "core SPAN sensor (Slips/Zeek)")
        self.inv = Inventory(devs, (1, 3), {("netadmin", NMS)})
        self.ip = {d.id: d.ip for d in devs.values()}
        self.ws = [d for d in devs if d.startswith("WS-")]
        self.srv = [d for d in devs if d.startswith("SRV-")]
        r = self.rng
        self.prof = {}
        for k, d in enumerate(self.ws):
            fav = r.choice(100, 25, replace=False)
            w = 1.0 / np.arange(1, 26) ** 1.1
            self.prof[d] = {"fav": fav, "fw": w / w.sum(), "user": f"user{k + 1:02d}",
                            "admin": d in ("WS-01", "WS-02"), "logged": -1,
                            "tel_phase": r.uniform(0, 300), "ntp_phase": r.uniform(0, 1024)}
        for d in self.srv:
            self.prof[d] = {"tel_phase": r.uniform(0, 300), "ntp_phase": r.uniform(0, 1024)}

    def _ext_ip(self) -> str:
        r = self.rng
        first = int(r.choice([23, 31, 45, 52, 64, 81, 91, 104, 142, 151, 185, 193, 212]))
        return f"{first}.{r.integers(1, 255)}.{r.integers(1, 255)}.{r.integers(1, 255)}"

    def _rand_label(self, n: int, alphabet="abcdefghijklmnopqrstuvwxyz234567") -> str:
        return "".join(self.rng.choice(list(alphabet), n))

    # ---------------------------------------------------------------- emitters
    def ev(self, _ts, dev, kind, attack=False, label=True, **a):
        """label=False: attacker activity that does not compromise `dev` (e.g. a failed login attempt)."""
        if attack and self._cur and self._cur not in self.attacks:
            return
        self.events.append(Event(float(_ts), dev, kind, a))
        if attack and label:
            self.labels[dev].add(int((_ts - self.t0) // WINDOW))

    def flow(self, t, dev, dst, dport, bout, bin_, proto="tcp", attack=False):
        a = dict(src=self.ip[dev], dst=dst, dport=int(dport), proto=proto,
                 bout=int(bout), bin=int(bin_), dur=round(float(self.rng.exponential(2.0)), 2))
        self.ev(t, dev, "flow", attack, **a)
        if self.inv.devices[dev].type == "host":        # SPAN sensor sees host traffic
            self.ev(t, "NET-CORE", "flow", attack, **a)

    def logs(self, dev, t0, n, chain, attack=False):
        st = self.state.get(dev, next(iter(chain)))
        for i in range(n):
            nxt, w = zip(*chain[st])
            w = np.asarray(w, float)
            st = nxt[self.rng.choice(len(nxt), p=w / w.sum())]
            self.ev(t0 + (i + self.rng.random()) * WINDOW / max(n, 1), dev, "log", attack, t=st)
        self.state[dev] = st

    def seq(self, dev, t, templates, attack=False, gap=5.0):
        for i, tpl in enumerate(templates):
            self.ev(t + i * gap, dev, "log", attack, t=tpl)

    def periodic(self, dev, ws, period, phase, dst, dport, size, proto="tcp", jitter=2.0):
        k = int(np.ceil((ws - self.t0 - phase) / period))
        while True:
            t = self.t0 + phase + k * period
            if t >= ws + WINDOW:
                break
            self.flow(t + self.rng.normal(0, jitter), dev, dst, dport,
                      size * self.rng.uniform(0.9, 1.1), size * self.rng.uniform(1.0, 1.6), proto)
            k += 1

    # ---------------------------------------------------------------- behaviour
    def activity(self, t, dev=None):
        d, h = int((t - self.t0) // DAY), ((t - self.t0) % DAY) / 3600
        if dev == "WS-11" and self.td + 22 * 3600 <= t < self.td + 25 * 3600:   # B4 late work
            return 0.9
        if (3 + d) % 7 >= 5:                                                     # weekend
            return 0.08 + 0.1 * (10 <= h < 17)
        if 8 <= h < 18:
            return 0.6 if 12 <= h < 13 else 1.0
        if 7 <= h < 8 or 18 <= h < 20:
            return 0.35
        return 0.05

    def _workstation(self, dev, ws):
        r, p = self.rng, self.prof[dev]
        act = self.activity(ws + WINDOW / 2, dev)
        p_new = 0.5 if (dev == "WS-05" and self.td + 2 * DAY + 13 * 3600 <= ws < self.td + 2 * DAY + 15 * 3600) \
            else 0.025                                                            # B5
        for _ in range(r.poisson(20 * act + 0.5)):
            t = ws + r.uniform(0, WINDOW)
            if r.random() < 0.28:
                srv, port = [("SRV-FILE", 445), ("SRV-WEB", 443), ("SRV-DC", 389), ("SRV-DC", 88)][
                    r.choice(4, p=[0.45, 0.3, 0.15, 0.1])]
                self.flow(t, dev, self.ip[srv], port, r.lognormal(8, 1), r.lognormal(10, 1.3))
                if srv == "SRV-FILE" and r.random() < 0.15:
                    self.ev(t, "SRV-FILE", "auth", user=p["user"], src=self.ip[dev], ok=True)
            else:
                if r.random() < p_new:
                    ip, dom = self._ext_ip(), f"{WORDS[r.integers(len(WORDS))]}{r.integers(10**5)}.com"
                else:
                    ip = self.ext_pool[p["fav"][r.choice(25, p=p["fw"])]]
                    dom = self.domain_of[ip]
                if r.random() < 0.5:
                    self.ev(t - 0.05, dev, "dns", q=f"www.{dom}")
                self.flow(t, dev, ip, 443 if r.random() < 0.85 else 80, r.lognormal(7.5, 1), r.lognormal(10, 1.5))
        if dev == "WS-07" and ws >= self.td + 9 * 3600 and act >= 0.6 and r.random() < 0.6:   # B2
            for _ in range(r.integers(1, 4)):
                self.flow(ws + r.uniform(0, WINDOW), dev, self.ip["SRV-DB"], 1433, r.lognormal(7, 1), r.lognormal(9, 1))
        self.periodic(dev, ws, 300, p["tel_phase"], TELEMETRY, 443, 900)
        self.periodic(dev, ws, 1024, p["ntp_phase"], NTP, 123, 90, "udp")
        if r.random() < 0.3 * act + 0.02:   # benign high-entropy CDN names
            self.ev(ws + r.uniform(0, WINDOW), dev, "dns",
                    q=f"{self._rand_label(8, '0123456789abcdef')}.cdn{r.integers(3)}.net")
        day = int((ws - self.t0) // DAY)
        if act >= 0.35 and p["logged"] != day:
            p["logged"] = day
            t = ws + r.uniform(0, 300)
            if r.random() < 0.05:
                self.ev(t - 20, dev, "auth", user=p["user"], src=self.ip[dev], ok=False)
            self.ev(t, dev, "auth", user=p["user"], src=self.ip[dev], ok=True)
            self.ev(t + 1, "SRV-DC", "auth", user=p["user"], src=self.ip[dev], ok=True)
        procs = WS_PROCS + (ADMIN_PROCS if p["admin"] else [])
        pw = np.array([w for _, w in procs], float)
        for _ in range(r.poisson(3 * act + 0.2)):
            par, name = procs[r.choice(len(procs), p=pw / pw.sum())][0]
            self.ev(ws + r.uniform(0, WINDOW), dev, "proc", parent=par, name=name, user=p["user"])
        if r.random() < 0.004:   # rare benign new application
            self.ev(ws + r.uniform(0, WINDOW), dev, "proc", parent="explorer", name=f"app_{r.integers(10**4)}",
                    user=p["user"])
        self.logs(dev, ws, r.poisson(4 * act + 1), HOST_CHAIN)
        self.ev(ws + 450, dev, "resource", cpu=round(10 + 40 * act + r.normal(0, 5), 1),
                mem=round(40 + 20 * act + r.normal(0, 3), 1))

    def _server(self, dev, ws):
        r, p = self.rng, self.prof[dev]
        act = self.activity(ws + WINDOW / 2)
        for _ in range(r.poisson(3 + 3 * act)):
            t = ws + r.uniform(0, WINDOW)
            c = r.random()
            if c < 0.4 and dev != "SRV-DC":
                self.flow(t, dev, self.ip["SRV-DC"], [389, 88][r.integers(2)], r.lognormal(7, 1), r.lognormal(8, 1))
            elif c < 0.7:
                self.flow(t, dev, DNS, 53, 80, 160, "udp")
            elif c < 0.85 and dev == "SRV-WEB":
                self.flow(t, dev, self.ext_pool[100 + r.integers(5)], 443, r.lognormal(8, 1), r.lognormal(9, 1))
            else:
                self.flow(t, dev, VENDOR, 443, r.lognormal(7, 0.5), r.lognormal(11, 1))
        if dev == "SRV-FILE" and 2 <= ((ws - self.t0) % DAY) / 3600 < 3:   # nightly backup job
            self.ev(ws + 60, dev, "proc", parent="scheduler", name="backup_agent", user="svc_backup")
            self.flow(ws + 120, dev, self.ip["SRV-DC"], 445, r.lognormal(14, 0.3), r.lognormal(8, 1))
        self.periodic(dev, ws, 300, p["tel_phase"], TELEMETRY, 443, 900)
        self.periodic(dev, ws, 1024, p["ntp_phase"], NTP, 123, 90, "udp")
        for _ in range(r.poisson(1.5 + 2 * act)):
            par, name = [("services", "svchost"), ("services", SRV_PROCS[dev]), ("svchost", "taskhost")][r.integers(3)]
            self.ev(ws + r.uniform(0, WINDOW), dev, "proc", parent=par, name=name, user="system")
        self.logs(dev, ws, r.poisson(3 + 3 * act), HOST_CHAIN)
        self.ev(ws + 450, dev, "resource", cpu=round(20 + 25 * act + r.normal(0, 4), 1),
                mem=round(55 + 10 * act + r.normal(0, 2), 1))

    def _netdev(self, dev, ws):
        r = self.rng
        typ = self.inv.devices[dev].type
        act = self.activity(ws + WINDOW / 2)
        hod = ((ws - self.t0) % DAY) / 3600
        if typ == "router":
            n = r.poisson(9)
            self.logs(dev, ws, n, ROUTER_CHAIN)
            for peer in ("RTR-CORE", "RTR-EDGE", "RTR-BRANCH"):
                if peer != dev:
                    self.flow(ws + r.uniform(0, WINDOW), dev, self.ip[peer], 0, 120, 120, "ospf")
            if dev == "RTR-EDGE":
                self.periodic(dev, ws, 60, 7.0, ISP_PEER, 179, 80, jitter=0.5)
        else:
            surge = 3 if (dev == "FW-DC" and self.td + 2 * DAY <= ws < self.td + 2 * DAY + 7200) else 1  # B6
            n = r.poisson((25 * act + 8) * surge)
            self.logs(dev, ws, n, FW_CHAIN)
            peer = "FW-DC" if dev == "FW-PERIM" else "FW-PERIM"
            self.periodic(dev, ws, 60, 13.0 if dev == "FW-PERIM" else 41.0, self.ip[peer], 8009, 300, jitter=0.5)
            if int(ws) % (4 * 3600) == 0:
                self.flow(ws + 30, dev, VENDOR, 443, 2000, 80000)
            if r.random() < 0.2:
                self.flow(ws + r.uniform(0, WINDOW), dev, self.ip["SRV-DC"], 389, 600, 1500)
            if surge > 1:
                for _ in range(10):
                    self.flow(ws + r.uniform(0, WINDOW), dev, self.ip["SRV-FILE"], 445, r.lognormal(15, 0.4), 4000)
        self.flow(ws + 899, dev, SYSLOG, 514, 180 * max(n, 1), 0, "udp")
        if ws % 1024 < WINDOW:
            self.flow(ws + 1, dev, NTP, 123, 90, 90, "udp")
        if 2.0 <= hod < 2.25:   # daily admin "show" session by the network team
            t = ws + r.uniform(0, 300)
            self.ev(t, dev, "auth", user="netadmin", src=NMS, ok=True)
            self.flow(t, dev, TACACS, 49, 300, 300)
            self.seq(dev, t, ["aaa_login_ok"] + ["exec_cmd"] * int(r.integers(2, 6)) + ["aaa_logout"])
        self.ev(ws + 450, dev, "resource", cpu=round(15 + 5 * act + r.normal(0, 3), 1),
                mem=round(45 + r.normal(0, 2), 1))

    def config_change(self, t, dev, add=(), remove=(), user="netadmin", src=NMS, attack=False, failures=0):
        for i in range(failures):
            self.ev(t - 60 - 5 * (failures - i), dev, "auth", attack, user=user, src=src, ok=False)
            self.ev(t - 60 - 5 * (failures - i), dev, "log", attack, t="aaa_login_fail")
        self.ev(t - 50, dev, "auth", attack, user=user, src=src, ok=True)
        self.seq(dev, t - 45, ["aaa_login_ok", "config_enter"] + ["config_line"] * max(1, len(add) + len(remove)),
                 attack)
        rm = {x.strip() for x in remove}
        self.cfg[dev] = [ln for ln in self.cfg[dev] if ln.strip() not in rm] + list(add)
        self.ev(t, dev, "config", attack, text="\n".join(self.cfg[dev]), user=user, src=src)
        tail = ["config_exit"] + (["logging_host_removed"] if any("logging" in x for x in remove) else []) + \
               ["config_save", "aaa_logout"]
        self.seq(dev, t + 5, tail, attack)

    # ----------------------------------------------------------------- attacks
    def _attacks(self):
        r, td, end = self.rng, self.td, self.t0 + self.days * DAY
        H = 3600
        # ---- A1: workstation intrusion -> lateral movement -> exfiltration
        self._cur = "A1"
        s = td + 10 * H + 20 * 60
        for i, (par, name) in enumerate([("mail", "doc_viewer"), ("doc_viewer", "script_host"),
                                         ("script_host", "shell"), ("shell", "netcfg")]):
            self.ev(s + 20 * i, "WS-03", "proc", True, parent=par, name=name, user="user03")
        stage = self._ext_ip()
        self.ev(s + 90, "WS-03", "dns", True, q=f"{self._rand_label(10)}.{WORDS[r.integers(18)]}-sync.net")
        self.flow(s + 91, "WS-03", stage, 443, 900, 2_400_000, attack=True)
        self.ev(s + 300, "WS-03", "log", True, t="svc_install")
        self.ev(s + 310, "WS-03", "proc", True, parent="services", name="svc_helper", user="system")
        c2 = self._ext_ip()
        t = s + 400
        while t < end:
            self.flow(t, "WS-03", c2, 443, r.lognormal(6.2, 0.3), r.lognormal(6.8, 0.5), attack=True)
            t += 75 * r.uniform(0.85, 1.15)
        s2 = td + 15 * H
        hosts = {v for v in self.ip.values() if v.startswith(("10.0.1.", "10.0.2."))}
        for k in range(60):
            tgt = f"10.0.{1 + k % 2}.{10 + k // 2}"
            for port in (445, 3389, 22, 5985, 135):
                ok = tgt in hosts and port in (445, 135)
                self.flow(s2 + r.uniform(0, 2700), "WS-03", tgt, port, 60, 300 if ok else 0, attack=True)
        s3 = td + 15 * H + 50 * 60
        for k in range(25):
            tgt = ["SRV-FILE", "SRV-DB"][k % 2]
            self.ev(s3 + 40 * k, tgt, "auth", True, user=["administrator", "svc_backup", "admin", "backup"][k % 4],
                    src=self.ip["WS-03"], ok=False, label=False)
        self.ev(td + 16 * H + 10 * 60, "SRV-FILE", "auth", True, user="svc_backup", src=self.ip["WS-03"], ok=True)
        s4 = td + 16 * H + 15 * 60
        for k in range(6):
            self.flow(s4 + 100 * k, "WS-03", self.ip["SRV-FILE"], 5985, r.lognormal(9, 0.5), r.lognormal(8, 0.5),
                      attack=True)
        self.ev(s4 + 30, "SRV-FILE", "proc", True, parent="wsmprovhost", name="shell", user="svc_backup")
        self.ev(s4 + 60, "SRV-FILE", "proc", True, parent="shell", name="archiver", user="svc_backup")
        self.ev(s4 + 90, "SRV-FILE", "log", True, t="svc_install")
        c2b = self._ext_ip()
        t = td + 16 * H + 30 * 60
        while t < end:
            self.flow(t, "SRV-FILE", c2b, 443, r.lognormal(6.2, 0.3), r.lognormal(6.8, 0.5), attack=True)
            t += 120 * r.uniform(0.8, 1.2)
        exf = self._ext_ip()
        t = td + DAY + 1 * H
        while t < td + DAY + 3 * H:
            self.flow(t, "SRV-FILE", exf, 443, r.lognormal(15.5, 0.5), r.lognormal(7, 0.5), attack=True)
            t += r.exponential(110)

        # ---- A2: edge router implant

        self._cur = "A2"
        s = td + 23 * H + 40 * 60
        atk, tun = self._ext_ip(), self._ext_ip()
        self.config_change(s, "RTR-EDGE", user="admin", src=atk, attack=True, failures=6,
                           add=["username maint privilege 15 secret 5 $1$Zx$9q", "interface Tunnel99",
                                " tunnel source Gi0/1", f" tunnel destination {tun}",
                                "monitor session 1 source interface Gi0/1 both",
                                "monitor session 1 destination remote erspan"],
                           remove=["logging host 10.0.3.5"])
        if "A2" in self.attacks:
            self.suppress.append(("RTR-EDGE", s + 60, lambda e: e.kind == "log" or
                                  (e.kind == "flow" and e.a.get("dst") == SYSLOG), 0.08))
        for w in range(int((s + 300 - self.t0) // WINDOW), int((end - self.t0) // WINDOW)):
            ws = self.t0 + w * WINDOW
            for _ in range(r.integers(12, 26)):
                self.flow(ws + r.uniform(0, WINDOW), "RTR-EDGE", tun, 0, r.lognormal(12.5, 0.6), 0, "gre",
                          attack=True)
            self.ev(ws + 451, "RTR-EDGE", "resource", True, cpu=round(32 + r.normal(0, 3), 1),
                    mem=round(52 + r.normal(0, 2), 1))

        # ---- A3: perimeter firewall backdoor + DB server

        self._cur = "A3"
        s = td + DAY + 13 * H + 35 * 60
        atk, c2f = self._ext_ip(), self._ext_ip()
        self.config_change(s, "FW-PERIM", user="admin", src=atk, attack=True, failures=40,
                           add=["rule 5 permit tcp any host 10.0.2.12 eq 3389",
                                "user add fwsupport role superuser", "set system api-access any"])
        for w in range(int((s - self.t0) // WINDOW) + 1, int((s + 6 * H - self.t0) // WINDOW)):
            self.seq("FW-PERIM", self.t0 + w * WINDOW + r.uniform(0, 600),
                     ["sess_allow_in_rdp"] * int(r.integers(2, 7)), True, gap=20)
        t = s + 600
        while t < end:
            self.flow(t, "FW-PERIM", c2f, 8443, r.lognormal(6.5, 0.3), r.lognormal(7, 0.4), attack=True)
            t += 300 * r.uniform(0.9, 1.1)
        s5 = s + 15 * 60
        self.ev(s5, "SRV-DB", "auth", True, user="administrator", src=atk, ok=True)
        self.ev(s5 + 30, "SRV-DB", "proc", True, parent="rdp_session", name="shell", user="administrator")
        self.ev(s5 + 90, "SRV-DB", "proc", True, parent="shell", name="sql_dump", user="administrator")
        t = s5 + 300
        while t < s5 + 2 * H:
            self.flow(t, "SRV-DB", atk, 443, r.lognormal(14.5, 0.5), r.lognormal(7, 0.5), attack=True)
            t += r.exponential(240)

        # ---- A4: low-and-slow DNS tunnelling

        self._cur = "A4"
        s = td + 2 * DAY + 9 * H
        base = f"{self._rand_label(6, 'abcdefghijklmnopqrstuvwxyz')}-cdn.org"
        for w in range(int((s - self.t0) // WINDOW), int((s + 6 * H - self.t0) // WINDOW)):
            for _ in range(r.integers(4, 9)):
                t = self.t0 + w * WINDOW + r.uniform(0, WINDOW)
                self.ev(t, "WS-09", "dns", True, q=f"{self._rand_label(int(r.integers(30, 42)))}.t.{base}")
                self.flow(t, "WS-09", DNS, 53, 140, 120, "udp", attack=True)

    def _benign_changes(self):
        r, td = self.rng, self.td
        self.config_change(self.t0 + DAY + 1.6 * 3600, "RTR-BRANCH",
                           add=["access-list 101 deny ip host 91.12.4.8 any", "interface Gi0/2",
                                " description new-branch-link"])
        self.config_change(self.t0 + 2 * DAY + 1.5 * 3600, "FW-DC",
                           add=["rule 40 permit tcp 10.0.1.0/24 host 10.0.2.12 eq 1433"])
        self.config_change(td + DAY + 1.5 * 3600, "RTR-CORE",                                     # B3
                           add=["ip route 10.9.0.0 255.255.0.0 10.0.0.9", "access-list 101 deny ip host 31.7.7.7 any"])
        patch = [self._ext_ip() for _ in range(3)]                                                 # B1
        s = td + DAY + 10 * 3600
        for dev in self.ws + self.srv:
            t = s + r.uniform(0, 3000)
            self.ev(t, dev, "dns", q="dl.patchcdn-global.com")
            for ip in patch:
                self.flow(t + r.uniform(1, 30), dev, ip, 443, r.lognormal(8, 0.5), r.lognormal(16, 0.5))
            self.ev(t + 40, dev, "proc", parent="updater", name="patch_installer", user="system")
            self.ev(t + 60, dev, "log", t="update_installed")
            self.ev(t + 61, dev, "resource", cpu=85.0, mem=70.0)

    # ---------------------------------------------------------------------- run
    def run(self):
        n_win = self.days * DAY // WINDOW
        for d in ("RTR-CORE", "RTR-EDGE", "RTR-BRANCH"):
            self.cfg[d] = ROUTER_CFG.format(name=d, ip=self.ip[d]).splitlines()
        for d in ("FW-PERIM", "FW-DC"):
            self.cfg[d] = FW_CFG.format(name=d).splitlines()
        for d, lines in self.cfg.items():
            self.ev(self.t0 + 1, d, "config", text="\n".join(lines), user="netadmin", src=NMS)
        for w in range(n_win):
            ws = self.t0 + w * WINDOW
            for d in self.ws:
                self._workstation(d, ws)
            for d in self.srv:
                self._server(d, ws)
            for d in ("RTR-CORE", "RTR-EDGE", "RTR-BRANCH", "FW-PERIM", "FW-DC"):
                self._netdev(d, ws)
        self._benign_changes()
        self._attacks()
        self._cur = None
        keep = []
        for e in self.events:
            drop = False
            for dev, t_from, pred, kp in self.suppress:
                if e.device == dev and e.ts >= t_from and pred(e) and self.rng.random() > kp:
                    drop = True
                    break
            if not drop:
                keep.append(e)
        keep.sort(key=lambda e: e.ts)
        self.events = keep
        truth = {
            "t0": self.t0, "train_end": self.td, "window": WINDOW,
            "compromised": {d: self.t0 + min(w) * WINDOW for d, w in sorted(self.labels.items())},
            "attack_windows": {d: sorted(w) for d, w in self.labels.items()},
            "scenarios": [s for s in SCENARIOS if s["kind"] == "benign" or s["id"] in self.attacks],
        }
        return self.events, self.inv, truth


def simulate(seed: int = 7, days: int = 7, train_days: int = 4, attacks=None):
    return Simulator(seed, days, train_days, attacks).run()
