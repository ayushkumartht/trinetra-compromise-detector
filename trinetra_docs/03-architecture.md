<!-- group: Architecture -->
# System architecture

TRINETRA has four layers: **collection**, **normalisation**, **detection engine** and **presentation**. Each layer talks to the next through one stable contract.

## Context

```mermaid
flowchart TB
  analyst(["SOC analyst / forensic investigator"])
  siem(["SIEM: Splunk · QRadar · Wazuh · Elastic"])
  subgraph ENT["Monitored enterprise"]
    hosts["Systems"]
    fws["Firewalls"]
    rts["Routers"]
    span["SPAN / TAP"]
  end
  slips["Stratosphere Slips<br/>+ compromise_detector module"]
  tri["TRINETRA engine"]
  ui["Console · API · Docs"]
  span -->|"pcap / Zeek"| slips
  slips -->|"UBT: flows, DNS, evidence"| tri
  fws -->|"syslog · config backups"| tri
  rts -->|"syslog · NetFlow · config backups"| tri
  hosts -->|"auth · process · resource"| tri
  tri --> ui
  ui -->|"CEF / JSON"| siem
  analyst --> ui
```

## Components

```mermaid
flowchart LR
  subgraph COLLECT["1 · Collection"]
    M["Slips module<br/>compromise_detector.py"]
    AD["Adapters<br/>adapters.py"]
    SIM["Testbed<br/>simulate.py"]
  end
  subgraph NORM["2 · Normalisation"]
    SCH["UBT schema<br/>schema.py"]
    INV["Inventory<br/>devices · admins · windows"]
  end
  subgraph ENGINE["3 · Engine"]
    FEAT["features.py<br/>Profile · FleetConsensus<br/>compute · Standardizer"]
    DETS["detectors.py<br/>VectorModels · SequenceModel<br/>BeaconDetector · GraphDetector<br/>ConfigDetector · TailCalibrator"]
    ENG["engine.py<br/>fit · detect_window · verdict<br/>propagate · incidents"]
    PIPE["pipeline.py<br/>run_demo · run_real · evaluate"]
  end
  subgraph PRES["4 · Presentation"]
    API["server.py<br/>Flask REST"]
    WEB["landing · console · docs<br/>vanilla JS, offline"]
  end
  M --> SCH
  AD --> SCH
  SIM --> SCH
  INV --> ENG
  SCH --> FEAT --> DETS --> ENG --> PIPE --> API --> WEB
```

| Layer | Contract it produces | Why it matters |
|---|---|---|
| Collection | UBT JSON lines `{ts, device, kind, ...attrs}` | Any new data source only needs a small adapter |
| Normalisation | `Event` objects + `Inventory` | The engine never sees vendor formats |
| Engine | `results` dict: devices, timeline, evidence, verdict events, incidents | One object drives UI, CEF and JSON export |
| Presentation | REST + static pages | Works offline, no build step, no CDN |

## Life of one 15-minute window

```mermaid
sequenceDiagram
  autonumber
  participant B as Event buckets
  participant F as Feature engine
  participant FC as Fleet consensus
  participant D as 8 detectors
  participant C as Calibrators
  participant E as Engine state
  participant UI as Results / UI
  B->>F: events of window w (all devices)
  F->>FC: novel items (w) + look-ahead (w+1, w+2)
  FC-->>F: items novel on ≥20% of peers → treated as benign change
  F->>D: 28-feature vector + raw events per device
  D->>C: 8 raw scores per device
  C-->>E: 8 calibrated p-values per device
  E->>E: Cauchy fusion → s = −log10 p
  E->>E: CUSUM S = max(0, S + s − k), alarm if S > h
  E->>E: map evidence to ATT&CK tactics (24 h memory)
  E->>E: verdict state machine + lateral-movement propagation
  E->>F: if clean (s < 1.3): learn window into baseline (gated)
  E-->>UI: timeline point, evidence, verdict events
```

## Training vs detection

```mermaid
flowchart LR
  subgraph FIT["fit(): baseline period"]
    direction TB
    f1["Day 1: burn-in<br/>profiles learn, no fitting"] --> f2["Days 2–4: fit windows<br/>(2 of every 3 two-hour blocks)"]
    f2 --> f3["Per-device robust scaling<br/>IForest + Autoencoder per device type"]
    f1 --> f4["Days 2–4: calibration windows<br/>(every 3rd two-hour block)"]
    f4 --> f5["Raw scores of held-out windows<br/>→ TailCalibrator per type × detector"]
  end
  subgraph DETECT["detect(): streaming"]
    direction TB
    d1["window w"] --> d2["score · fuse · CUSUM · verdict"] --> d3["gated learning"] --> d1
  end
  FIT --> DETECT
```

Calibration windows are **interleaved** with fitting windows across weekdays, weekends, days and nights. That way the calibrated p-values reflect every normal regime, not a single quiet day.

## Deployment view

```mermaid
flowchart TB
  subgraph SENSOR["Sensor host · Linux / Docker"]
    z["Zeek"] --> s["Slips + compromise_detector"]
    s --> o[("output/run/compromise_detector<br/>ubt_events.jsonl · inventory.json")]
  end
  subgraph COLL["Collector · any OS"]
    sy["syslog receiver<br/>routers · firewalls"] --> a["adapters.py"]
    ox["Oxidized / config backups"] --> a
    o --> a
  end
  subgraph APP["TRINETRA server · any OS"]
    a --> e["engine"] --> r[("results.json")] --> f["Flask :5050"]
  end
  f --> b(["Analyst browser"])
  f --> siem(["SIEM · CEF"])
```

## Design principles

1. **Device-agnostic core.** All four device classes share the same feature vector; missing telemetry is simply zero, and the coverage is shown per device.
2. **Calibrate everything.** No detector is trusted with a hand-picked threshold; each one gets a data-driven p-value.
3. **Convict on corroboration.** Statistics raise SUSPICIOUS; independent attack stages are required for COMPROMISED.
4. **Explain every verdict.** Evidence records what changed, by how much versus normal, and which detector saw it.
5. **Ship anywhere.** Pure Python + numpy/scipy/scikit-learn; front-end is vanilla JS with vendored libraries; no GPU, no cloud.
