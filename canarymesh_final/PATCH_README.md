# CanaryMesh Frontend/Backend Integration Fix

Replace the matching files in the existing CanaryMesh repository. Do not delete any other project files.

## Files in this patch

- `backend/main.py`
- `backend/dataset_loader.py`
- `frontend/.env`
- `frontend/src/useWebSocket.js`
- `frontend/src/App.jsx`
- `frontend/src/components/AlertsTab.jsx`

## What this fixes

1. Frontend REST URLs use `127.0.0.1:8000` for the local backend.
2. Frontend polls `/api/state`, `/api/mqtt/recent`, and `/api/dataset/attack-types` every 3 seconds, so the dashboard can populate even while the WebSocket reconnects.
3. WebSocket remains the live channel when available.
4. App now passes `alerts`, `approveAlert`, and `clearAlerts` into `AlertsTab`.
5. AlertsTab has safe defaults and no longer crashes when props are temporarily unavailable.
6. Backend exposes `/api/health` for a quick connection test.
7. Dataset loading first uses local CSVs and can reuse already-imported SQLite benchmark telemetry when a temporary download/DNS failure occurs.
8. Backend startup now reports dataset download warnings instead of immediately treating every failed download as the cause of a dead API. If SQLite has no imported telemetry either, the startup error explicitly tells you what is missing.

## Run order

Terminal 1:

```powershell
cd <project>\backend
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```

Terminal 2:

```powershell
cd <project>\frontend
npm.cmd install
npm.cmd run dev
```

Then open `http://localhost:5173/`.

## Verify backend before opening the UI

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/health
```

A healthy backend should return JSON with `"backend": true`.

If `datasetLoaded` is false, the project still needs the real ToN-IoT CSV files or an existing imported SQLite telemetry database. Do not replace those with invented/random values.
