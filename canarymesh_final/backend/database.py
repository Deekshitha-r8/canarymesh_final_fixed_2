"""SQLite persistence for CanaryMesh benchmark telemetry and security events."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_PATH = str(Path(__file__).resolve().parent / "canarymesh.db")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def _add_column_if_missing(db: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    names = {row[1] for row in db.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in names:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


async def init_db() -> None:
    with _connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                node_id TEXT,
                node_name TEXT,
                severity TEXT,
                reason TEXT,
                timestamp TEXT,
                risk_score REAL,
                anomaly_score REAL,
                ground_truth TEXT,
                attack_type TEXT
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id TEXT,
                action TEXT,
                operator TEXT,
                reason TEXT,
                timestamp TEXT
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS dataset_meta (
                dataset TEXT PRIMARY KEY,
                source_name TEXT NOT NULL,
                source_url TEXT NOT NULL,
                local_file TEXT NOT NULL,
                row_count INTEGER NOT NULL DEFAULT 0,
                imported_at TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dataset TEXT NOT NULL,
                device_type TEXT NOT NULL,
                source_ts TEXT NOT NULL,
                label TEXT NOT NULL,
                attack_type TEXT,
                raw_json TEXT NOT NULL,
                feature_json TEXT NOT NULL
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_dataset_id ON telemetry(dataset,id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_label ON telemetry(label)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS mqtt_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                topic TEXT NOT NULL,
                payload TEXT NOT NULL,
                source_id TEXT,
                source_name TEXT,
                destination TEXT,
                command TEXT,
                message_type TEXT,
                dataset TEXT,
                label TEXT,
                transport TEXT NOT NULL
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_mqtt_id ON mqtt_messages(id)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS replay_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                device_id TEXT NOT NULL,
                dataset TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                source_row_ts TEXT,
                model_score REAL,
                risk_score REAL,
                severity TEXT
            )
        """)
        for column, definition in [("risk_score", "REAL"), ("anomaly_score", "REAL"), ("ground_truth", "TEXT"), ("attack_type", "TEXT")]:
            _add_column_if_missing(db, "alerts", column, definition)
        db.commit()


async def clear_dataset(dataset: str) -> None:
    with _connect() as db:
        db.execute("DELETE FROM telemetry WHERE dataset = ?", (dataset,))
        db.execute("DELETE FROM dataset_meta WHERE dataset = ?", (dataset,))
        db.commit()


async def set_dataset_meta(dataset: str, source_name: str, source_url: str, local_file: str, row_count: int) -> None:
    with _connect() as db:
        db.execute("""
            INSERT INTO dataset_meta(dataset,source_name,source_url,local_file,row_count,imported_at)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(dataset) DO UPDATE SET
              source_name=excluded.source_name,
              source_url=excluded.source_url,
              local_file=excluded.local_file,
              row_count=excluded.row_count,
              imported_at=excluded.imported_at
        """, (dataset, source_name, source_url, local_file, row_count, utc_now()))
        db.commit()


async def insert_telemetry_rows(dataset: str, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    values = [(
        dataset, row.get("device_type", "IoT"), row.get("source_ts", "unknown"),
        row.get("label", "normal"), row.get("attack_type"),
        json.dumps(row.get("raw", {}), ensure_ascii=False, separators=(",", ":")),
        json.dumps(row.get("features", {}), ensure_ascii=False, separators=(",", ":")),
    ) for row in rows]
    with _connect() as db:
        db.executemany("""
            INSERT INTO telemetry(dataset,device_type,source_ts,label,attack_type,raw_json,feature_json)
            VALUES(?,?,?,?,?,?,?)
        """, values)
        db.commit()


async def get_dataset_rows(dataset: str) -> list[dict[str, Any]]:
    with _connect() as db:
        rows = db.execute("""
            SELECT source_ts, device_type, label, attack_type, raw_json, feature_json
            FROM telemetry WHERE dataset = ? ORDER BY id ASC
        """, (dataset,)).fetchall()
        return [{
            "source_ts": row["source_ts"], "device_type": row["device_type"], "label": row["label"],
            "attack_type": row["attack_type"], "raw": json.loads(row["raw_json"] or "{}"),
            "features": json.loads(row["feature_json"] or "{}"),
        } for row in rows]


async def log_alert(alert: dict) -> None:
    with _connect() as db:
        db.execute("""
            INSERT OR REPLACE INTO alerts(
                id,node_id,node_name,severity,reason,timestamp,risk_score,anomaly_score,ground_truth,attack_type
            ) VALUES(?,?,?,?,?,?,?,?,?,?)
        """, (
            alert.get("id", ""), alert.get("nodeId", alert.get("node_id", "")),
            alert.get("node", alert.get("node_name", "")), alert.get("severity", ""), alert.get("reason", ""),
            alert.get("timestamp", alert.get("time", utc_now())), alert.get("riskScore"), alert.get("anomalyScore"),
            alert.get("groundTruth"), alert.get("attackType"),
        ))
        db.commit()


async def log_decision(decision: dict) -> None:
    with _connect() as db:
        db.execute("""
            INSERT INTO decisions(node_id,action,operator,reason,timestamp) VALUES(?,?,?,?,?)
        """, (
            decision.get("node_id", ""), decision.get("action", ""), decision.get("operator", "operator"),
            decision.get("reason", ""), decision.get("timestamp", utc_now()),
        ))
        db.commit()


async def log_mqtt(message: dict) -> int:
    with _connect() as db:
        cur = db.execute("""
            INSERT INTO mqtt_messages(
              timestamp,topic,payload,source_id,source_name,destination,command,message_type,dataset,label,transport
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
        """, (
            message.get("timestamp", utc_now()), message.get("topic", ""), message.get("payload", ""),
            message.get("source_id", ""), message.get("source_name", ""), message.get("destination", "broker"),
            message.get("command", "TELEMETRY"), message.get("message_type", "TELEMETRY"), message.get("dataset", ""),
            message.get("label", "normal"), message.get("transport", "recorded_only"),
        ))
        row_id = int(cur.lastrowid)
        db.commit()
        return row_id


async def log_replay_event(event: dict) -> None:
    with _connect() as db:
        db.execute("""
            INSERT OR REPLACE INTO replay_events(
              id,timestamp,device_id,dataset,attack_type,source_row_ts,model_score,risk_score,severity
            ) VALUES(?,?,?,?,?,?,?,?,?)
        """, (
            event.get("id"), event.get("timestamp", utc_now()), event.get("device_id"), event.get("dataset"),
            event.get("attack_type"), event.get("source_row_ts"), event.get("model_score"),
            event.get("risk_score"), event.get("severity"),
        ))
        db.commit()


async def get_recent_alerts(limit: int = 50) -> list[dict]:
    with _connect() as db:
        return [dict(row) for row in db.execute("SELECT * FROM alerts ORDER BY timestamp DESC, rowid DESC LIMIT ?", (limit,)).fetchall()]


async def get_decisions(limit: int = 100) -> list[dict]:
    with _connect() as db:
        return [dict(row) for row in db.execute("SELECT * FROM decisions ORDER BY timestamp DESC, id DESC LIMIT ?", (limit,)).fetchall()]


async def get_recent_mqtt(limit: int = 50) -> list[dict]:
    with _connect() as db:
        return [dict(row) for row in db.execute("SELECT * FROM mqtt_messages ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]


async def get_dataset_meta() -> list[dict]:
    with _connect() as db:
        return [dict(row) for row in db.execute("SELECT * FROM dataset_meta ORDER BY dataset").fetchall()]


async def get_recent_telemetry(dataset: str | None = None, limit: int = 50) -> list[dict]:
    with _connect() as db:
        if dataset:
            rows = db.execute("SELECT * FROM telemetry WHERE dataset = ? ORDER BY id DESC LIMIT ?", (dataset, limit)).fetchall()
        else:
            rows = db.execute("SELECT * FROM telemetry ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["raw"] = json.loads(item.pop("raw_json") or "{}")
            item["features"] = json.loads(item.pop("feature_json") or "{}")
            out.append(item)
        return out
