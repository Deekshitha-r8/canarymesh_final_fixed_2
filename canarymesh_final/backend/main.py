"""CanaryMesh FastAPI backend.

Startup is resilient: real ToN-IoT data is preferred, but the service can fall
back to a clearly labelled deterministic offline demo dataset for local testing.
WebSocket is an enhancement, not a prerequisite for REST/API functionality.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "ml_federated"))
sys.path.insert(0, str(ROOT / "iot_cybersecurity"))

from database import (
    init_db,
    get_recent_alerts,
    get_decisions,
    get_recent_mqtt,
    get_recent_telemetry,
    log_alert,
    log_decision,
    log_mqtt,
    log_replay_event,
)
from dataset_loader import DatasetReplayStore
from fl_engine import FederatedEngine
from honeypot import HoneypotServer
from mqtt_service import MQTTPublisher, now_iso
from node_manager import NodeManager, SEVERITY_THRESHOLDS, IoTDevice
from sanitizer import NodeSanitizer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("canarymesh")

store: DatasetReplayStore | None = None
node_manager: NodeManager | None = None
fl_engine: FederatedEngine | None = None
honeypot: HoneypotServer | None = None
sanitizer: NodeSanitizer | None = None
mqtt_publisher = MQTTPublisher()
ws_clients: list[WebSocket] = []
loop_task: asyncio.Task | None = None
startup_error = ""


async def broadcast(data: dict) -> None:
    dead: list[WebSocket] = []

    for ws in list(ws_clients):
        try:
            await ws.send_json(data)
        except Exception:
            dead.append(ws)

    for ws in dead:
        if ws in ws_clients:
            ws_clients.remove(ws)


async def current_state(
    *,
    mqtt: list | None = None,
    fl: dict | None = None,
) -> dict:
    if not node_manager or not fl_engine or not store:
        return {
            "type": "state_update",
            "devices": [],
            "nodes": [],
            "alerts": [],
            "mqtt": mqtt or [],
            "fl": fl or None,
            "dataset": None,
            "mqttBroker": mqtt_publisher.status(),
            "timestamp": now_iso(),
            "startupError": startup_error or "Backend is still starting",
        }

    return {
        "type": "state_update",
        "devices": node_manager.get_all_nodes(),
        "nodes": node_manager.get_all_nodes(),
        "alerts": node_manager.get_active_alerts(),
        "mqtt": mqtt if mqtt is not None else await get_recent_mqtt(40),
        "fl": fl if fl is not None else fl_engine.get_status(),
        "dataset": store.status(),
        "mqttBroker": mqtt_publisher.status(),
        "timestamp": now_iso(),
    }


async def persist_and_publish_updates(
    updated_ids: list[str],
) -> list[dict]:
    assert node_manager

    emitted: list[dict] = []

    for device_id in updated_ids:
        device = node_manager.nodes.get(device_id)

        if not device or not device.last_mqtt:
            continue

        sample = device.last_mqtt

        transport = mqtt_publisher.publish(
            topic=sample["topic"],
            payload=sample["payload"],
        )

        payload_text = json.dumps(
            sample["payload"],
            ensure_ascii=False,
            separators=(",", ":"),
        )

        row_id = await log_mqtt(
            {
                "timestamp": now_iso(),
                "topic": sample["topic"],
                "payload": payload_text,
                "source_id": device.id,
                "source_name": device.name,
                "destination": "broker" if transport == "mqtt" else "SQLite",
                "command": (
                    "ATTACK_TELEMETRY"
                    if sample["type"] == "ATTACK"
                    else "TELEMETRY"
                ),
                "message_type": sample["type"],
                "dataset": device.dataset,
                "label": sample["label"],
                "transport": transport,
            }
        )

        emitted.append(
            {
                "id": row_id,
                "timestamp": now_iso(),
                "topic": sample["topic"],
                "payload": payload_text,
                "source_id": device.id,
                "source_name": device.name,
                "destination": "broker" if transport == "mqtt" else "SQLite",
                "message_type": sample["type"],
                "dataset": device.dataset,
                "label": sample["label"],
                "transport": transport,
            }
        )

        if sample["type"] == "ATTACK":
            await log_replay_event(
                {
                    "id": f"replay_{row_id}",
                    "timestamp": now_iso(),
                    "device_id": device.id,
                    "dataset": device.dataset,
                    "attack_type": (
                        sample["payload"].get("attackType")
                        or sample["label"]
                        or "attack"
                    ),
                    "source_row_ts": sample["sourceTimestamp"],
                    "model_score": device.anomaly_score,
                    "risk_score": device.risk_score,
                    "severity": device.severity,
                }
            )

    return emitted


async def simulation_loop() -> None:
    tick_no = 0

    try:
        interval = max(
            0.5,
            float(os.getenv("CANARYMESH_TICK_SECONDS", "2")),
        )
    except ValueError:
        interval = 2.0

    while True:
        await asyncio.sleep(interval)

        try:
            if not node_manager or not fl_engine:
                continue

            tick_no += 1

            active_ids = [
                device.id
                for device in node_manager.nodes.values()
                if not device.is_isolated
            ]

            node_manager.tick()

            emitted = await persist_and_publish_updates(active_ids)

            new_alerts = node_manager.check_alerts()

            for alert in new_alerts:
                await log_alert(alert)

                if alert["severity"] in {"HIGH", "CRITICAL"}:
                    result = node_manager.isolate_node(alert["nodeId"])

                    if result:
                        isolation_event = {
                            "id": f"iso_{uuid.uuid4().hex[:8]}",
                            "nodeId": alert["nodeId"],
                            "node": result["name"],
                            "node_name": result["name"],
                            "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                            "timestamp": now_iso(),
                            "severity": "CRITICAL",
                            "riskScore": alert.get("riskScore"),
                            "anomalyScore": alert.get("anomalyScore"),
                            "reason": (
                                f"Automatic quarantine triggered by measured "
                                f"{alert['severity']} risk."
                            ),
                        }

                        await log_alert(isolation_event)
                        node_manager.add_alert(isolation_event)

                        await log_decision(
                            {
                                "node_id": alert["nodeId"],
                                "action": "auto_isolate",
                                "operator": "system",
                                "reason": isolation_event["reason"],
                                "timestamp": now_iso(),
                            }
                        )

            fl_update = None

            if tick_no % 5 == 0:
                fl_update = await fl_engine.run_round()

            await broadcast(
                await current_state(
                    mqtt=emitted,
                    fl=fl_update,
                )
            )

        except asyncio.CancelledError:
            raise

        except Exception:
            logger.exception("CanaryMesh loop error")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global store
    global node_manager
    global fl_engine
    global honeypot
    global sanitizer
    global loop_task
    global startup_error

    await init_db()

    try:
        store = DatasetReplayStore(
            auto_download=(
                os.getenv(
                    "CANARYMESH_AUTO_DOWNLOAD",
                    "false",
                ).lower()
                == "true"
            )
        )

        await store.import_into_db()

        node_manager = NodeManager(store)
        fl_engine = FederatedEngine(node_manager)
        sanitizer = NodeSanitizer(node_manager, fl_engine)
        honeypot = HoneypotServer(node_manager)

        honeypot.start()
        mqtt_publisher.start()

        loop_task = asyncio.create_task(simulation_loop())

        startup_error = ""

        logger.info("CanaryMesh backend started successfully")
        logger.info(
            "Dataset mode: %s",
            store.status().get("mode"),
        )

    except Exception as exc:
        startup_error = str(exc)

        logger.exception("CanaryMesh startup error")

        store = None
        node_manager = None
        fl_engine = None
        honeypot = None
        sanitizer = None

        mqtt_publisher.start()

    try:
        yield

    finally:
        if loop_task:
            loop_task.cancel()

            try:
                await loop_task
            except asyncio.CancelledError:
                pass

        mqtt_publisher.stop()

        if honeypot:
            honeypot.stop()


app = FastAPI(
    title="CanaryMesh API",
    version="5.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class AddDeviceReq(BaseModel):
    name: str
    node_type: str
    dataset: str = "modbus"


class ReplayAttackReq(BaseModel):
    device_id: str
    attack_type: str | None = None


def require_runtime() -> None:
    if not node_manager or not fl_engine or not store:
        raise RuntimeError(
            startup_error or "CanaryMesh runtime is not initialized"
        )


@app.get("/")
async def root():
    return {
        "status": "ok" if not startup_error else "degraded",
        "version": "5.1.0",
        "dataMode": store.status()["mode"] if store else None,
        "startupError": startup_error or None,
    }


@app.get("/api/health")
async def health():
    return {
        "status": "ok" if not startup_error else "degraded",
        "backend": True,
        "datasetLoaded": bool(
            store and store.status().get("totalRows", 0) > 0
        ),
        "deviceCount": len(node_manager.nodes) if node_manager else 0,
        "websocketClients": len(ws_clients),
        "mqtt": mqtt_publisher.status(),
        "startupError": startup_error or None,
        "dataset": store.status() if store else None,
    }


@app.get("/api/state")
async def api_state():
    return await current_state()


@app.get("/api/devices")
def get_devices():
    if not node_manager:
        return {
            "devices": [],
            "error": startup_error or "Backend starting",
        }

    return {
        "devices": node_manager.get_all_nodes()
    }


@app.get("/api/nodes")
def get_nodes_legacy():
    if not node_manager:
        return {
            "nodes": [],
            "error": startup_error or "Backend starting",
        }

    return {
        "nodes": node_manager.get_all_nodes()
    }


@app.get("/api/telemetry/recent")
async def telemetry_recent(
    dataset: str | None = None,
    limit: int = 50,
):
    return {
        "rows": await get_recent_telemetry(
            dataset,
            min(max(limit, 1), 500),
        )
    }


@app.post("/api/devices")
async def add_device(req: AddDeviceReq):
    require_runtime()

    assert store
    assert node_manager

    if req.dataset not in store.dataset_names:
        return {
            "success": False,
            "error": f"Dataset {req.dataset} is not loaded",
        }

    device_id = f"U{uuid.uuid4().hex[:4].upper()}"

    index = len(node_manager.nodes)

    position = {
        "x": 18 + (index * 13) % 65,
        "y": 16 + (index * 19) % 62,
    }

    device = IoTDevice(
        device_id,
        req.name,
        req.node_type,
        req.dataset,
        position,
        store,
    )

    node_manager.nodes[device_id] = device

    result = device.to_dict()

    await broadcast(
        {
            "type": "device_added",
            "device": result,
        }
    )

    return {
        "success": True,
        "device": result,
    }


@app.post("/api/devices/{device_id}/replay-attack")
async def replay_attack(
    device_id: str,
    req: ReplayAttackReq | None = None,
):
    require_runtime()

    assert node_manager
    assert store

    try:
        replay = node_manager.replay_attack(
            device_id,
            req.attack_type if req else None,
        )

    except (KeyError, RuntimeError) as exc:
        return {
            "success": False,
            "error": str(exc),
        }

    await log_replay_event(
        {
            "id": f"queued_{uuid.uuid4().hex[:8]}",
            "timestamp": now_iso(),
            "device_id": device_id,
            "dataset": replay["dataset"],
            "attack_type": replay["attackType"],
            "source_row_ts": replay["sourceTimestamp"],
        }
    )

    await broadcast(
        {
            "type": "dataset_attack_replay",
            "device_id": device_id,
            **replay,
        }
    )

    return {
        "success": True,
        "replay": replay,
        "message": "Attack row queued for the next telemetry cycle",
    }


async def isolate_impl(
    device_id: str,
    operator: str,
):
    require_runtime()

    assert node_manager

    result = node_manager.isolate_node(device_id)

    if not result:
        return {
            "success": False,
            "error": "Device not found",
        }

    event = {
        "id": f"iso_{uuid.uuid4().hex[:8]}",
        "nodeId": device_id,
        "node": result["name"],
        "node_name": result["name"],
        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "timestamp": now_iso(),
        "severity": "HIGH",
        "reason": f"Device manually isolated by {operator}.",
    }

    await log_alert(event)
    node_manager.add_alert(event)

    await log_decision(
        {
            "node_id": device_id,
            "action": "isolate",
            "operator": operator,
            "reason": event["reason"],
            "timestamp": now_iso(),
        }
    )

    await broadcast(await current_state())

    return {
        "success": True
    }


@app.post("/api/devices/{device_id}/isolate")
async def isolate_device(
    device_id: str,
    operator: str = "operator",
):
    return await isolate_impl(
        device_id,
        operator,
    )


@app.post("/api/nodes/{node_id}/isolate")
async def isolate_node_legacy(
    node_id: str,
    operator: str = "operator",
):
    return await isolate_impl(
        node_id,
        operator,
    )


@app.post("/api/nodes/{node_id}/sanitize")
async def sanitize_node(
    node_id: str,
    operator: str = "operator",
):
    require_runtime()

    assert node_manager

    device = node_manager.nodes.get(node_id)

    if not device:
        return {
            "success": False,
            "error": "Device not found",
        }

    node_manager.set_sanitizing(node_id)

    await broadcast(
        {
            "type": "sanitization_started",
            "node_id": node_id,
            "node_name": device.name,
            "timestamp": now_iso(),
        }
    )

    asyncio.create_task(
        _run_sanitization(
            node_id,
            device.name,
            operator,
        )
    )

    return {
        "success": True
    }


async def _run_sanitization(
    node_id: str,
    node_name: str,
    operator: str,
):
    assert node_manager
    assert sanitizer

    await asyncio.sleep(0.4)

    source = sanitizer.block_attacker_source(node_id)

    message = (
        f"[Source Blocked] {node_name} - "
        f"{source} added to the demo gateway/broker deny list"
    )

    await log_decision(
        {
            "node_id": node_id,
            "action": "block_source",
            "operator": "system",
            "reason": message,
            "timestamp": now_iso(),
        }
    )

    await broadcast(
        {
            "type": "sanitization_progress",
            "node_id": node_id,
            "phase": "block_source",
            "message": message,
            "step": 1,
            "total_steps": 4,
        }
    )

    await asyncio.sleep(0.4)

    sanitizer.purge_command_queue(node_id)

    message = (
        f"[Buffer Purged] {node_name} - "
        "queued replay commands cleared"
    )

    await log_decision(
        {
            "node_id": node_id,
            "action": "purge_queue",
            "operator": "system",
            "reason": message,
            "timestamp": now_iso(),
        }
    )

    await broadcast(
        {
            "type": "sanitization_progress",
            "node_id": node_id,
            "phase": "purge_queue",
            "message": message,
            "step": 2,
            "total_steps": 4,
        }
    )

    await asyncio.sleep(0.4)

    fl_round = sanitizer.restore_fl_model(node_id)

    message = (
        f"[FL Model Reset] {node_name} - "
        f"restored global parameters from Round #{fl_round}"
    )

    await log_decision(
        {
            "node_id": node_id,
            "action": "fl_model_reset",
            "operator": "system",
            "reason": message,
            "timestamp": now_iso(),
        }
    )

    await broadcast(
        {
            "type": "sanitization_progress",
            "node_id": node_id,
            "phase": "fl_model_reset",
            "message": message,
            "step": 3,
            "total_steps": 4,
            "fl_round": fl_round,
        }
    )

    node_manager.set_health_checking(node_id)

    window = max(
        1.0,
        float(
            os.getenv(
                "CANARYMESH_HEALTH_WINDOW_SECONDS",
                "10",
            )
        ),
    )

    message = (
        f"[Health Check] {node_name} - "
        f"observing normal telemetry for {window:.0f} seconds"
    )

    await broadcast(
        {
            "type": "sanitization_progress",
            "node_id": node_id,
            "phase": "health_check",
            "message": message,
            "step": 4,
            "total_steps": 4,
        }
    )

    await asyncio.sleep(window)

    passed = sanitizer.verify_health(node_id)

    if passed:
        message = (
            f"[Health Check Passed] {node_name} - "
            "live replay remains below LOW risk policy"
        )
    else:
        message = (
            f"[Health Check Failed] {node_name} - "
            "measured telemetry is still above LOW risk policy"
        )

    await log_decision(
        {
            "node_id": node_id,
            "action": (
                "health_check_passed"
                if passed
                else "health_check_failed"
            ),
            "operator": "system",
            "reason": message,
            "timestamp": now_iso(),
        }
    )

    if passed:
        node_manager.set_ready_for_reconnect(node_id)

    await broadcast(
        {
            "type": "sanitization_complete",
            "node_id": node_id,
            "node_name": node_name,
            "passed": passed,
            "message": message,
        }
    )


@app.post("/api/nodes/{node_id}/reconnect")
async def reconnect(
    node_id: str,
    operator: str = "operator",
):
    require_runtime()

    assert node_manager

    result = node_manager.reconnect_node(node_id)

    if not result:
        return {
            "success": False,
            "error": "Device is not ready for reconnection",
        }

    await log_decision(
        {
            "node_id": node_id,
            "action": "reconnect",
            "operator": operator,
            "reason": "Operator approved re-integration",
            "timestamp": now_iso(),
        }
    )

    await broadcast(
        {
            "type": "node_reconnected",
            "node_id": node_id,
            "node_name": result["name"],
            "message": "Operator approved re-integration",
            "timestamp": now_iso(),
        }
    )

    return {
        "success": True
    }


@app.post("/api/nodes/{node_id}/restore")
async def restore(node_id: str):
    require_runtime()

    assert node_manager

    ok = node_manager.restore_node(node_id)

    if ok:
        await log_decision(
            {
                "node_id": node_id,
                "action": "restore",
                "operator": "operator",
                "reason": "Manual restore",
                "timestamp": now_iso(),
            }
        )

        await broadcast(await current_state())

    return {
        "success": ok
    }


@app.get("/api/alerts")
async def alerts(limit: int = 50):
    return {
        "alerts": await get_recent_alerts(
            min(max(limit, 1), 200)
        )
    }


@app.post("/api/alerts/{alert_id}/approve")
async def approve_alert(
    alert_id: str,
    operator: str = "operator",
):
    require_runtime()

    assert node_manager

    target = next(
        (
            a
            for a in node_manager.get_active_alerts()
            if a.get("id") == alert_id
        ),
        None,
    )

    if not target:
        all_alerts = await get_recent_alerts(200)

        target = next(
            (
                a
                for a in all_alerts
                if a.get("id") == alert_id
            ),
            None,
        )

    if not target:
        return {
            "success": False,
            "error": "Alert not found",
        }

    target_node_id = (
        target.get("node_id")
        or target.get("nodeId")
    )

    result = node_manager.isolate_node(
        target_node_id
    )

    if not result:
        return {
            "success": False,
            "error": "Device not found",
        }

    # Remove the pending MEDIUM alert from the live feed now that it has
    # been actioned, and replace it with a clear confirmation event so the
    # operator sees something actually change when they click the button.
    node_manager.resolve_alert(alert_id)

    confirmation = {
        "id": f"appr_{uuid.uuid4().hex[:8]}",
        "nodeId": target_node_id,
        "node": result["name"],
        "node_name": result["name"],
        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "timestamp": now_iso(),
        "severity": "HIGH",
        "reason": f"Isolation approved by {operator} from the alert queue.",
    }
    await log_alert(confirmation)
    node_manager.add_alert(confirmation)

    await log_decision(
        {
            "node_id": target_node_id,
            "action": "approve_isolation",
            "operator": operator,
            "reason": "Operator approved isolation from alert queue",
            "timestamp": now_iso(),
        }
    )

    await broadcast(await current_state())

    return {
        "success": True
    }


@app.post("/api/alerts/clear")
async def clear_alerts_rest():
    require_runtime()

    assert node_manager

    node_manager.clear_alerts()

    await broadcast(await current_state())

    return {
        "success": True
    }


@app.get("/api/audit")
async def audit(limit: int = 100):
    return {
        "decisions": await get_decisions(
            min(max(limit, 1), 300)
        )
    }


@app.get("/api/mqtt/recent")
async def mqtt_recent(limit: int = 50):
    return {
        "messages": await get_recent_mqtt(
            min(max(limit, 1), 200)
        )
    }


@app.get("/api/dataset/status")
async def dataset_status():
    if not store:
        return {
            "source": None,
            "mode": "unavailable",
            "error": startup_error,
        }

    return store.status()


@app.get("/api/dataset/attack-types")
def dataset_attack_types():
    if not node_manager:
        return {}

    return node_manager.attack_types()


@app.get("/api/mqtt/status")
def mqtt_status():
    return mqtt_publisher.status()


@app.get("/api/fl/status")
def fl_status():
    if not fl_engine:
        return {
            "round": 0,
            "accuracy": 0,
            "measured": False,
            "error": startup_error,
        }

    return fl_engine.get_status()


@app.get("/api/risk/thresholds")
def risk_thresholds():
    return {
        "LOW": f"< {SEVERITY_THRESHOLDS['LOW']}",
        "MEDIUM": (
            f"{SEVERITY_THRESHOLDS['LOW']}–"
            f"{SEVERITY_THRESHOLDS['MEDIUM'] - 0.01:.2f}"
        ),
        "HIGH": (
            f"{SEVERITY_THRESHOLDS['MEDIUM']}–"
            f"{SEVERITY_THRESHOLDS['HIGH'] - 0.01:.2f}"
        ),
        "CRITICAL": f">= {SEVERITY_THRESHOLDS['HIGH']}",
        "basis": (
            "Measured Isolation Forest anomaly + temporal persistence "
            "+ feature deviation; no ground-truth label is used in "
            "runtime risk scoring"
        ),
    }


@app.post("/api/simulate/honeypot_probe")
async def honeypot_probe():
    require_runtime()

    assert honeypot

    event = honeypot.manual_probe()

    alert = {
        "id": f"hp_{uuid.uuid4().hex[:8]}",
        "nodeId": event["honeypot_id"],
        "node": event["honeypot_name"],
        "node_name": event["honeypot_name"],
        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "timestamp": now_iso(),
        "severity": "HIGH",
        "reason": f"Controlled honeypot probe from {event['source_id']}.",
    }

    await log_alert(alert)
    node_manager.add_alert(alert)

    await log_decision(
        {
            "node_id": event["honeypot_id"],
            "action": "honeypot_probe",
            "operator": "demo",
            "reason": alert["reason"],
            "timestamp": now_iso(),
        }
    )

    await broadcast(await current_state())

    return {
        "success": True,
        "alert": alert,
    }


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    ws_clients.append(ws)

    try:
        await ws.send_json(
            {
                **(await current_state()),
                "type": "init",
            }
        )

        while True:
            message = await ws.receive_json()

            action = message.get("action")
            device_id = (
                message.get("node_id")
                or message.get("device_id")
            )

            if action == "isolate" and node_manager:
                if device_id:
                    await isolate_impl(
                        device_id,
                        "operator",
                    )
                else:
                    await ws.send_json(
                        {
                            "type": "error",
                            "message": "Device ID is required",
                        }
                    )

            elif action == "restore" and node_manager:
                if device_id:
                    ok = node_manager.restore_node(
                        device_id
                    )

                    if ok:
                        await broadcast(
                            await current_state()
                        )
                    else:
                        await ws.send_json(
                            {
                                "type": "error",
                                "message": (
                                    "Device not found "
                                    "or could not be restored"
                                ),
                            }
                        )
                else:
                    await ws.send_json(
                        {
                            "type": "error",
                            "message": "Device ID is required",
                        }
                    )

            elif action == "sanitize" and node_manager:
                if not device_id:
                    await ws.send_json(
                        {
                            "type": "error",
                            "message": "Device ID is required",
                        }
                    )
                    continue

                device = node_manager.nodes.get(
                    device_id
                )

                if device:
                    node_manager.set_sanitizing(
                        device_id
                    )

                    asyncio.create_task(
                        _run_sanitization(
                            device_id,
                            device.name,
                            "operator",
                        )
                    )

                    await broadcast(
                        {
                            "type": "sanitization_started",
                            "node_id": device_id,
                            "node_name": device.name,
                            "timestamp": now_iso(),
                        }
                    )
                else:
                    await ws.send_json(
                        {
                            "type": "error",
                            "message": (
                                f"Device {device_id} not found"
                            ),
                        }
                    )

            elif action == "reconnect" and node_manager:
                if not device_id:
                    await ws.send_json(
                        {
                            "type": "error",
                            "message": "Device ID is required",
                        }
                    )
                    continue

                result = node_manager.reconnect_node(
                    device_id
                )

                if result:
                    await broadcast(
                        {
                            "type": "node_reconnected",
                            "node_id": device_id,
                            "node_name": result["name"],
                            "message": (
                                "Operator approved re-integration"
                            ),
                            "timestamp": now_iso(),
                        }
                    )
                else:
                    await ws.send_json(
                        {
                            "type": "error",
                            "message": (
                                "Device is not ready "
                                "for reconnection"
                            ),
                        }
                    )

            elif action == "replay_attack" and node_manager:
                if not device_id:
                    await ws.send_json(
                        {
                            "type": "error",
                            "message": "Device ID is required",
                        }
                    )
                    continue

                try:
                    result = node_manager.replay_attack(
                        device_id,
                        message.get("attack_type"),
                    )

                    await broadcast(
                        {
                            "type": "dataset_attack_replay",
                            "device_id": device_id,
                            **result,
                        }
                    )

                except Exception as exc:
                    await ws.send_json(
                        {
                            "type": "error",
                            "message": str(exc),
                        }
                    )

            elif action == "approve_isolation" and node_manager:
                if not device_id:
                    await ws.send_json(
                        {
                            "type": "error",
                            "message": "Device ID is required",
                        }
                    )
                    continue

                device = node_manager.nodes.get(
                    device_id
                )

                if device:
                    result = node_manager.isolate_node(
                        device_id
                    )

                    if result:
                        # Resolve whichever pending MEDIUM alert triggered
                        # this approval and add a confirmation event, same
                        # as the REST /api/alerts/{id}/approve path, so the
                        # live feed actually reflects the operator's click.
                        pending = next(
                            (
                                a
                                for a in node_manager.get_active_alerts()
                                if (a.get("nodeId") or a.get("node_id")) == device_id
                                and a.get("severity") == "MEDIUM"
                            ),
                            None,
                        )
                        if pending:
                            node_manager.resolve_alert(pending["id"])

                        confirmation = {
                            "id": f"appr_{uuid.uuid4().hex[:8]}",
                            "nodeId": device_id,
                            "node": result["name"],
                            "node_name": result["name"],
                            "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                            "timestamp": now_iso(),
                            "severity": "HIGH",
                            "reason": "Isolation approved by operator from the alert queue.",
                        }
                        await log_alert(confirmation)
                        node_manager.add_alert(confirmation)

                        await log_decision(
                            {
                                "node_id": device_id,
                                "action": "approve_isolation",
                                "operator": "operator",
                                "reason": (
                                    "Operator approved medium-risk "
                                    "isolation from alert queue"
                                ),
                                "timestamp": now_iso(),
                            }
                        )

                        await broadcast(
                            await current_state()
                        )
                    else:
                        await ws.send_json(
                            {
                                "type": "error",
                                "message": (
                                    f"Unable to isolate device "
                                    f"{device_id}"
                                ),
                            }
                        )
                else:
                    await ws.send_json(
                        {
                            "type": "error",
                            "message": (
                                f"Device {device_id} not found"
                            ),
                        }
                    )

            elif action == "clear_alerts" and node_manager:
                node_manager.clear_alerts()
                await broadcast(
                    await current_state()
                )

            else:
                await ws.send_json(
                    {
                        "type": "error",
                        "message": f"Unknown action: {action}",
                    }
                )

    except WebSocketDisconnect:
        pass

    except Exception:
        logger.exception("WebSocket error")

    finally:
        if ws in ws_clients:
            ws_clients.remove(ws)