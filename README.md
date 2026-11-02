# TRINETRA: detect the breach, not the signature

*IoC-free compromise detection for systems, firewalls, routers and networks. An extension of [Stratosphere Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) (GPL-2.0).*

TRINETRA learns how every device normally behaves, measures deviation with **8 independent detectors**, turns every score into a calibrated probability, and declares a device **COMPROMISED** only when evidence persists *and* spans at least two MITRE ATT&CK stages.

## Run it

```bash
cd slips
pip install -r compromise_dashboard/requirements.txt
python -m compromise_dashboard          # → http://127.0.0.1:5050
```

On Windows you can also double-click `run_trinetra.bat`.

| URL | What you get |
|---|---|
| `/` | Landing page: the problem, real device photos, **real malware log captures** analysed by TRINETRA's feature code, live replay of a detected intrusion, console screenshots, engine, false-alarm layers, results |
| `/console` | Analyst console: replay timeline, interactive network map (drag, zoom, minimap, filters), evidence matrix, MITRE ATT&CK map, attack timeline, incidents, per-device forensic reports with a plain-language "why", **story mode**, **live attack lab**, **what-if lab**, data upload, toasts, Ctrl+K palette, dark/light, English/हिंदी, presenter mode |
| `/report` | Printable executive compromise-assessment report (Save as PDF) |
| `/docs` | Full documentation: 19 pages with architecture, sequence, state and timeline diagrams, a Hinglish beginner's guide and the worldwide research survey (offline) |

The first start analyses a simulated 7-day, 22-device enterprise (≈ 1 min including the ablation study). Later starts load the cached result instantly.

## Results (benchmark, seed 7)

| | |
|---|---|
| Attacked devices caught | **7 / 7** (workstation, file server, DB server, edge router, perimeter firewall, DNS-tunnelling host, network sensor) |
| Clean devices wrongly convicted | **0 / 15** |
| Benign traps (patch rollout, planned change, late work, browsing spree, new app, backup surge) | none convicted; 2 shown as SUSPICIOUS for review |
| Median time to detect | 30 min |
| Other seeds (11, 42, 99, 201, 303) | every attack caught, 0 clean devices convicted |

Ablation: without fleet consensus, 13 clean devices alarm; without corroboration, 2 are wrongly convicted; without CUSUM, 2 attacks are missed. No single detector matches the fused system. Details: `trinetra_docs/12-evaluation.md`.

> **Limitations:** the benchmark is a simulation we built (no public dataset combines router/firewall configs, syslog, host telemetry and flows). The Slips module follows the v1.1.24 module API but has not yet been run inside a live Slips/Redis instance. See the docs for the validation roadmap.

## What was added to Slips

| Path | Purpose |
|---|---|
| `modules/compromise_detector/compromise_detector.py` | New Slips module: streams flows, DNS and Slips evidence as Unified Behavioural Telemetry |
| `modules/compromise_detector/core/` | Detection engine: schema, features, 8 detectors, calibration and fusion, verdicts, adapters, testbed, pipeline |
| `modules/supported_module_names.py` | Registers `compromise_detector` (the only modified Slips source file) |
| `SLIPS_README.md` | The original Slips README, renamed so this file is the repository front page |
| `compromise_dashboard/` | Flask API + landing page, console and docs (vanilla JS, works offline) |
| `compromise_dashboard/build_real_logs.py` | Extracts the real log excerpts shown on the landing page from `dataset/` and runs TRINETRA's feature code on them |
| `compromise_dashboard/static/img/photos/` | Real photographs from Wikimedia Commons (CC0 / CC BY / CC BY-SA), credits in `credits.json` |
| `compromise_dashboard/requirements.txt` | The four Python packages TRINETRA needs |
| `tests/unit/modules/compromise_detector/` | Engine unit tests (`python -m unittest tests.unit.modules.compromise_detector.test_compromise_detector`) |
| `trinetra_docs/` | Documentation in Markdown + Mermaid (renders on GitHub and in `/docs`) |
| `run_trinetra.bat` | Windows launcher |

## Documentation map

| Page | |
|---|---|
| `00-overview` · `01-problem` · `02-quickstart` | what, why, how to run |
| `03-architecture` · `04-repository` · `05-slips-integration` | system design, file-by-file tour, Slips module |
| `06-telemetry` · `07-features` · `08-detectors` · `09-fusion-and-verdict` · `10-false-alarms` | the engine and its maths |
| `11-console-and-api` | every screen, REST API, CEF format |
| `12-evaluation` · `13-deployment` · `14-research` | results, deployment, literature |
| `15-presentation-guide` · `16-glossary` | demo script and judge Q&A, terms |
| `17-basics-se-samjho` · `18-research-survey` | Hinglish guide from zero, full worldwide research survey |
