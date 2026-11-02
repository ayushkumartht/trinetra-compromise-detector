<!-- group: Reference -->
# Glossary

| Term | Meaning in TRINETRA |
|---|---|
| **Ablation study** | Re-running the same evaluation with one component removed (or one detector alone) to measure its contribution |
| **Alarm** | CUSUM statistic S above threshold h = 4 for a device |
| **ATT&CK** | MITRE's knowledge base of adversary tactics (goals, e.g. *Persistence*) and techniques (methods, e.g. *T1136 Create Account*) |
| **Autoencoder** | Neural network trained to reproduce its input through a bottleneck; abnormal inputs reconstruct badly |
| **Baseline** | The learned normal behaviour of a device (profiles, scaling, models, calibration) |
| **Beaconing** | Periodic "check-in" connections from an implant to its command-and-control server |
| **Burn-in** | First baseline day; profiles learn but no model is fitted, because everything looks new at first |
| **Calibration** | Converting a raw detector score into a p-value using held-out normal windows |
| **Cauchy combination** | Method to merge p-values that stays valid when they are correlated (Liu & Xie 2020) |
| **CEF** | Common Event Format, a one-line text format understood by most SIEMs |
| **COMPROMISED** | Verdict: persistent anomaly corroborated by ≥ 2 ATT&CK tactics within 24 h, or lateral movement from a compromised device |
| **Config semantic drift** | Risk-scored meaning of a configuration change (new admin, tunnel, any-rule…) × context (who / when / where) |
| **Conformal p-value** | (1 + number of calibration scores ≥ x) / (n + 1); uniform under normal behaviour |
| **Corroboration** | Requiring independent evidence (different attack stages) before conviction |
| **CUSUM** | Cumulative-sum change detector: S = max(0, S + s − k) |
| **Device type** | `host`, `firewall`, `router` or `network` |
| **EVT / GPD** | Extreme-value theory / generalised Pareto distribution, used to model the far tail of scores |
| **Evidence (s)** | Fused −log₁₀ p of one device-window; 2 ≈ 1-in-100, 6 ≈ 1-in-a-million |
| **Evidence matrix** | Console view: devices × 15-minute windows, brightness = evidence |
| **Fleet consensus** | Treating items novel on many peers at once as benign organisation-wide change |
| **Gated learning** | Only clean, unsuspicious windows update the baseline (anti-poisoning) |
| **Incident** | Group of compromised devices linked by connections, logins or shared attacker infrastructure |
| **IoC** | Indicator of Compromise: hash, IP, domain, URL, YARA rule… of a *known* attack |
| **Isolation Forest** | Ensemble of random trees; anomalies are isolated in fewer splits |
| **Kill chain** | Ordered stages of an intrusion; here mapped to ATT&CK tactics |
| **Lateral movement** | Attacker moving from one internal device to another |
| **LOTL** | Living off the land: attacks that use built-in tools and valid accounts, leaving no malware |
| **MAD** | Median absolute deviation, a robust measure of spread |
| **Novelty** | Something never seen on this device before (destination, process chain, login, log type…) |
| **Peer pooling** | Training one model per device type on all devices of that type, each in its own robust units |
| **Profile** | Per-device sets of everything seen (destinations, ports, edges, domains, logins, process chains, templates) |
| **Slips** | Stratosphere Linux IPS, the behavioural network IPS that TRINETRA extends |
| **SUSPICIOUS** | Verdict: persistent anomaly without corroboration; for analyst review |
| **Template (log)** | Log message with variable parts masked, e.g. `Failed password for admin from <IP>` |
| **TTD** | Time to detect: conviction window minus first attacker action |
| **UBT** | Unified Behavioural Telemetry: the 8-kind event model shared by all device types |
| **Window** | 15-minute analysis interval |
| **Zeek** | Network monitor that turns packets into connection, DNS, HTTP… logs |
