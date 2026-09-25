# CanaryMesh — Industrial IoT Security Operations

CanaryMesh is a defensive industrial-security prototype aligned to the supplied architecture: detect anomalous or honeypot activity, quarantine the affected device, sanitize it, verify health, and require operator approval before reconnection. The architecture document explicitly calls for Low/Medium/High/Critical threat evaluation, MQTT-level blocking/quarantine, SQLite audit logging, a device sanitization state machine, and a live SOC dashboard. See the supplied architecture flow: `fileciteturn14file0L56-L62` `fileciteturn14file0L63-L82` `fileciteturn14file0L83-L98`.

## What changed in this integrated version

The original project used randomly generated telemetry and UI values in several places. This version changes the runtime source of truth to a **SQLite-backed replay of labeled UNSW ToN-IoT IoT/IIoT benchmark CSV rows**.

```text
UNSW ToN-IoT CSV
      ↓
SQLite telemetry table
      ↓
per-device feature extraction
      ↓
Isolation Forest + temporal persistence
      ↓
risk fusion (0–100) → Low / Medium / High / Critical
      ↓
real dataset row wrapped as MQTT JSON
      ↓
real MQTT broker publish (if Mosquitto is running)
      ↓
SQLite MQTT log + WebSocket
      ↓
React SOC dashboard
```

The benchmark is used as a **controlled replay/evaluation source**, not as a claim that these rows came from the user's physical factory. Device IDs such as `D1` and names such as `PLC-01` are project-side mappings to the benchmark telemetry.

## Data and risk model

The loader supports the ToN-IoT IoT/IIoT telemetry subsets used by the project: Modbus, Weather, Garage Door, Thermostat, Fridge, Motion Light, and GPS Tracker. Missing CSVs are downloaded automatically on backend startup from the configured mirror. The rows are imported into SQLite and then read back from SQLite before replay, so the runtime model does not generate its own telemetry values.

Ground-truth labels are stored for evaluation and displayed as evidence, but **the runtime risk score does not use the ground-truth label**. Risk is an operational policy score derived from the model and observed behavior:

```text
riskScore = 100 × (
    0.40 × anomalyScore
  + 0.15 × persistenceScore
  + 0.10 × featureDeviationScore
  + 0.35 × IsolationForestOutlier
)
```

Classification:

```text
LOW       < 25
MEDIUM    25–49.99
HIGH      50–74.99
CRITICAL  ≥ 75
```

These are **policy thresholds**, not probabilities of compromise.

## Controlled attack demonstration

The dashboard's **Replay labeled attack** action selects an actual attack-labeled row already loaded into SQLite and queues it for the next telemetry cycles. The frontend shows the dataset, attack type, source timestamp, feature values, model evidence, and resulting risk score.

This is intentionally a safe benchmark replay rather than a live exploitation routine. The project does not include instructions or code for attacking a real HTTP/HTTPS target.

## MQTT behavior

When Mosquitto or another MQTT broker is available at the configured host/port, CanaryMesh publishes the exact JSON payload produced from the benchmark row to:

```text
factory/<device-name>/telemetry
```

The MQTT log records the exact topic, payload, dataset, label, message type, and transport status. When a broker is unavailable, the event remains truthfully recorded in SQLite as `recorded_only` instead of pretending that a network publish occurred.

## Sanitization flow

The backend follows the supplied four-phase design: source blocking, queue purge, FL model reset, a 10-second health observation window, then operator-approved reconnection. The architecture document specifies this lifecycle and the UI transitions from quarantined to sanitizing, health-check, ready-to-reconnect, and normal. `fileciteturn14file0L63-L98`

Isolation is represented here as a defensive control action. In a real OT deployment, the equivalent enforcement would be done by the site's approved firewall, ACL, NAC, segmentation, or industrial security gateway rather than by retaliating against an attacker.

## Federated learning note

The current implementation performs a **compact, measured parameter aggregation** of local Isolation Forest offset values and evaluates the resulting threshold against held-out labeled ToN-IoT rows. The UI calls the per-device quantity an **update norm**, not a neural-network gradient. Raw telemetry is not shared.

It does **not** currently implement a full Flower server/client deployment. Do not describe this codebase as a production Flower cluster until that layer has been added.

## Project structure

```text
canarymesh/
├── backend/
│   ├── main.py                 FastAPI + WebSocket + orchestration
│   ├── database.py             SQLite telemetry, MQTT, alert and audit storage
│   ├── dataset_loader.py       ToN-IoT download/import/replay
│   ├── mqtt_service.py         real broker publisher
│   ├── sanitizer.py            defensive sanitization/recovery flow
│   └── requirements.txt
├── data/
│   └── README.md               dataset acquisition notes
├── ml_federated/
│   ├── node_manager.py         per-device Isolation Forest + risk engine
│   └── fl_engine.py            compact federated parameter aggregation
├── iot_cybersecurity/
│   ├── honeypot.py             controlled honeypot probe event
│   └── mqtt_broker.py          legacy compatibility wrapper
└── frontend/
    └── src/
        ├── App.jsx
        ├── useWebSocket.js
        └── components/
```

## Quick start on Windows PowerShell

### 1. Backend

```powershell
cd C:\Users\Admin\canarymesh\backend
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```

On first startup, the backend downloads the configured ToN-IoT CSV files if they are not already present in `data/`, imports them into `backend/canarymesh.db`, trains the local models, and starts the WebSocket loop.

### 2. MQTT broker

For an actual MQTT transport log, run Mosquitto locally on port `1883`.

If Mosquitto is not running, the dashboard will still work and the MQTT log will explicitly show `SQLite only / recorded_only`.

### 3. Frontend

Open a second PowerShell window:

```powershell
cd C:\Users\Admin\canarymesh\frontend
npm.cmd install
npm.cmd run dev
```

Open `http://localhost:5173`.

### 4. Verify the data path

Backend state:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/state
```

Dataset status:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/dataset/status
```

MQTT log:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/mqtt/recent?limit=10"
```

Risk policy:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/risk/thresholds
```

In Chrome DevTools, the frontend should now show `/api/state`, `/api/mqtt/recent`, and `/api/dataset/attack-types` during initial load, followed by the `/ws` WebSocket for live updates.

## Demo sequence for judges

1. Open **Devices** and show live risk/anomaly/persistence values and the source dataset.
2. Open **MQTT Log** and show exact benchmark-backed JSON payloads.
3. Select a device and choose **Replay labeled attack**.
4. Watch the next telemetry cycles change the model evidence and risk score.
5. Show the resulting alert and automatic quarantine for High/Critical policy events.
6. Start sanitization and show source block → queue purge → FL model reset → health check.
7. Use **Approve Reconnection** after the health check passes.
8. Open **Audit** and show the lifecycle entries stored in SQLite.

## Important implementation boundaries

- The benchmark is real external data, but the demo is still a replay environment.
- The displayed device identities are project-defined aliases, not claims about specific physical equipment.
- A benchmark label is stored for evaluation and explanation; it is not fed into the runtime risk formula.
- MQTT is genuinely published only when a broker is reachable.
- The current FL layer is measured compact aggregation, not full Flower infrastructure.
- “100% accurate” detection is not claimed. The dashboard reports measured evaluation results from the held-out benchmark rows.

## Architecture alignment

The supplied architecture calls for: detection/isolation, automated sanitization/eradication, a health-check handshake, operator-approved reconnection, SQLite audit logging, the sanitization state machine, the honeypot layer, MQTT handling, and a six-tab SOC dashboard. `fileciteturn14file0L100-L133`

