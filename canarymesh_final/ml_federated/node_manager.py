"""Device-level anomaly detection using database-backed UNSW ToN-IoT replay rows."""
from __future__ import annotations

import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from dataset_loader import DatasetReplayStore, DatasetRow

FIXED_POSITIONS = {
    "D1": {"x": 15, "y": 22}, "D2": {"x": 40, "y": 14}, "D3": {"x": 68, "y": 20},
    "D4": {"x": 28, "y": 52}, "D5": {"x": 55, "y": 48}, "D6": {"x": 80, "y": 55},
}
SEVERITY_THRESHOLDS = {"LOW": 25.0, "MEDIUM": 50.0, "HIGH": 75.0}
DEVICE_PROFILES = [
    ("D1", "PLC-01", "PLC", "modbus", FIXED_POSITIONS["D1"]),
    ("D2", "Weather-02", "Sensor", "weather", FIXED_POSITIONS["D2"]),
    ("D3", "GarageDoor-03", "Actuator", "garage_door", FIXED_POSITIONS["D3"]),
    ("D4", "Thermostat-04", "Sensor", "thermostat", FIXED_POSITIONS["D4"]),
    ("D5", "PLC-05", "PLC", "modbus", FIXED_POSITIONS["D5"]),
    ("D6", "Weather-06", "Sensor", "weather", FIXED_POSITIONS["D6"]),
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def get_model_offset(model) -> float:
    """Return IsolationForest offset_ safely as a Python float."""
    return float(np.asarray(model.offset_).reshape(-1)[0])

class IoTDevice:
    def __init__(self, device_id: str, name: str, device_type: str, dataset: str, position: dict, store: DatasetReplayStore):
        self.id, self.name, self.type, self.dataset, self.position, self.store = device_id, name, device_type, dataset, position, store
        self.is_isolated = False
        self.status = "normal"
        self.persistence_score = 0.0
        self.anomaly_score = 0.0
        self.feature_deviation = 0.0
        self.risk_score = 0.0
        self.severity = "LOW"
        self.last_evidence: dict = {}
        self.last_row: DatasetRow | None = None
        self.last_mqtt: dict | None = None
        self.gradient: Optional[np.ndarray] = None
        self.history = deque(maxlen=20)
        self._attack_rows: deque[DatasetRow] = deque()

        normal_rows = store.normal_rows[dataset]
        if not normal_rows:
            raise RuntimeError(f"No normal data available for {dataset}")
        train_rows = normal_rows[: min(5000, len(normal_rows))]
        self.feature_names = list(train_rows[0].feature_names)
        matrix = np.array([[row.features[name] for name in self.feature_names] for row in train_rows], dtype=float)
        self.scaler = StandardScaler()
        scaled = self.scaler.fit_transform(matrix)
        self.model = IsolationForest(n_estimators=150, contamination=0.05, random_state=42)
        self.model.fit(scaled)
        normal_scores = self.model.decision_function(scaled)
        self.normal_decision_p01 = float(np.percentile(normal_scores, 1))
        self.normal_score_p01 = float(np.percentile(self.model.score_samples(scaled), 1))
        self.normal_score_p05 = float(np.percentile(self.model.score_samples(scaled), 5))
        self.normal_score_median = float(np.median(self.model.score_samples(scaled)))
        self.normal_feature_mean = np.mean(matrix, axis=0)
        self.normal_feature_std = np.std(matrix, axis=0)
        self.normal_feature_std = np.where(self.normal_feature_std < 1e-9, 1.0, self.normal_feature_std)
        self.activity = 0.0
        self.expected_activity = float(np.median(np.sum(np.abs(matrix), axis=1)))

    def queue_attack(self, row: DatasetRow, repeats: int = 3) -> dict:
        self._attack_rows.clear()
        for _ in range(max(1, repeats)):
            self._attack_rows.append(row)
        return {"dataset": self.dataset, "attackType": row.attack_type, "sourceTimestamp": row.source_ts, "deviceId": self.id}

    def _next_row(self) -> DatasetRow:
        return self._attack_rows.popleft() if self._attack_rows else self.store.next_normal(self.dataset)

    def _model_anomaly(self, features: dict[str, float]) -> tuple[float, float]:
        vector = np.array([[features[name] for name in self.feature_names]], dtype=float)
        decision = float(self.model.decision_function(self.scaler.transform(vector))[0])
        # sklearn's Isolation Forest prediction is positive for an inlier and
        # negative for an outlier. The anomaly strength is therefore zero for
        # positive decisions and grows as the observed row moves into the
        # lower tail of the normal decision distribution.
        reference = max(0.01, abs(self.normal_decision_p01))
        anomaly = float(np.clip((-decision) / reference, 0.0, 1.0))
        return anomaly, decision

    def _feature_deviation_score(self, features: dict[str, float]) -> float:
        values = np.array([features[name] for name in self.feature_names], dtype=float)
        z = np.abs((values - self.normal_feature_mean) / self.normal_feature_std)
        return float(np.clip(np.mean(z) / 4.0, 0.0, 1.0))

    def _risk(self, anomaly: float, feature_deviation: float, model_outlier: bool) -> tuple[float, str]:
        self.persistence_score = 0.70 * self.persistence_score + 0.30 * anomaly
        outlier_evidence = 1.0 if model_outlier else 0.0
        # Model-derived evidence is part of the operational risk fusion. The
        # benchmark ground-truth label is deliberately not used here.
        risk = float(np.clip(100.0 * (
            0.40 * anomaly + 0.15 * self.persistence_score +
            0.10 * feature_deviation + 0.35 * outlier_evidence
        ), 0.0, 100.0))
        if risk >= SEVERITY_THRESHOLDS["HIGH"]:
            severity = "CRITICAL"
        elif risk >= SEVERITY_THRESHOLDS["MEDIUM"]:
            severity = "HIGH"
        elif risk >= SEVERITY_THRESHOLDS["LOW"]:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        return risk, severity

    def tick(self) -> dict:
        if self.is_isolated:
            return self.to_dict()
        row = self._next_row()
        anomaly, decision = self._model_anomaly(row.features)
        feature_deviation = self._feature_deviation_score(row.features)
        vector = np.array([[row.features[name] for name in self.feature_names]], dtype=float)
        model_outlier = int(self.model.predict(self.scaler.transform(vector))[0]) == -1
        risk, severity = self._risk(anomaly, feature_deviation, model_outlier)
        self.last_row = row
        self.anomaly_score = anomaly
        self.feature_deviation = feature_deviation
        self.risk_score = risk
        self.severity = severity
        self.status = "compromised" if severity in {"HIGH", "CRITICAL"} else "suspicious" if severity == "MEDIUM" else "normal"
        self.activity = float(sum(abs(float(v)) for v in row.features.values()))
        self.gradient = np.array([get_model_offset(self.model), anomaly, self.persistence_score], dtype=float)
        self.last_evidence = {
            "dataset": self.dataset,
            "sourceTimestamp": row.source_ts,
            "label": row.label,
            "attackType": row.attack_type,
            "features": row.features,
            "featureNames": self.feature_names,
            "isolationDecision": round(decision, 6),
            "modelOutlier": model_outlier,
         "modelOffset": round(get_model_offset(self.model), 6),  
            "normalP01": round(self.normal_score_p01, 6),
            "normalMedian": round(self.normal_score_median, 6),
            "anomalyScore": round(anomaly, 4),
            "featureDeviationScore": round(feature_deviation, 4),
            "persistenceScore": round(self.persistence_score, 4),
            "riskScore": round(risk, 2),
            "groundTruthUsedForRisk": False,
            "riskFormula": "0.40*anomaly + 0.15*persistence + 0.10*featureDeviation + 0.35*IsolationForestOutlier",
        }
        self.history.append({
            "timestamp": utc_now(), "sourceTimestamp": row.source_ts, "anomalyScore": round(anomaly, 4),
            "riskScore": round(risk, 2), "severity": severity, "attackType": row.attack_type,
        })
        payload = {
            "deviceId": self.id, "deviceName": self.name, "dataset": self.dataset,
            "sourceTimestamp": row.source_ts, "label": row.label, "attackType": row.attack_type,
            "features": row.features,
        }
        self.last_mqtt = {
            "topic": f"factory/{self.name}/telemetry", "payload": payload,
            "type": "ATTACK" if row.attack_type else "NORMAL", "dataset": self.dataset,
            "label": row.label, "sourceTimestamp": row.source_ts,
        }
        return self.to_dict()

    def threat_reason(self) -> str:
        if not self.last_evidence:
            return "Waiting for benchmark telemetry."
        e = self.last_evidence
        observed = ", ".join(f"{k}={float(v):.3f}" for k, v in e["features"].items())
        is_demo = bool(getattr(self.store, "demo_datasets", set()))
        label_name = "Demo label" if is_demo else "Benchmark label"
        gt = f"{label_name}: {e['attackType']}. " if e.get("attackType") else f"{label_name}: normal. "
        return (
            f"{gt}Isolation Forest anomaly={e['anomalyScore'] * 100:.1f}%, "
            f"persistence={e['persistenceScore'] * 100:.1f}%, feature deviation={e['featureDeviationScore'] * 100:.1f}%. "
            f"Policy risk={e['riskScore']:.1f}/100. Observed telemetry: {observed}."
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id, "deviceId": self.id, "name": self.name, "deviceName": self.name,
            "type": self.type, "status": "isolated" if self.is_isolated else self.status,
            "severity": self.severity, "anomalyScore": round(self.anomaly_score, 4),
            "riskScore": round(self.risk_score, 2), "persistenceScore": round(self.persistence_score, 4),
            "featureDeviationScore": round(self.feature_deviation, 4), "activity": round(self.activity, 3),
            "expectedActivity": round(self.expected_activity, 3), "activityUnit": "sum(abs(feature values))",
            "dataset": self.dataset, "sourceTimestamp": self.last_row.source_ts if self.last_row else None,
            "groundTruth": self.last_row.label if self.last_row else "unknown",
            "attackType": self.last_row.attack_type if self.last_row else None,
            "threatReason": self.threat_reason(), "lastEvidence": self.last_evidence,
            "mqttSample": self.last_mqtt, "position": self.position, "isIsolated": self.is_isolated,
            "history": list(self.history)[-10:],
        }

    def apply_global_model(self, global_offset: float) -> None:
     self.model.offset_ = np.array([float(global_offset)], dtype=float)


class NodeManager:
    def __init__(self, store: DatasetReplayStore):
        self.store = store
        self._active_alerts = {}
        self.nodes = {}
        self.honeypots = [
            {"id": "HP1", "deviceId": "HP1", "name": "PLC-99 (Honeypot)", "deviceName": "PLC-99 (Honeypot)", "type": "Honeypot", "status": "honeypot", "severity": "HIGH", "anomalyScore": 1.0, "riskScore": 100, "position": {"x": 15, "y": 78}, "threatReason": "Decoy PLC. Unauthorized interaction is a detection signal."},
            {"id": "HP2", "deviceId": "HP2", "name": "Sensor-98 (Honeypot)", "deviceName": "Sensor-98 (Honeypot)", "type": "Honeypot", "status": "honeypot", "severity": "HIGH", "anomalyScore": 1.0, "riskScore": 100, "position": {"x": 72, "y": 80}, "threatReason": "Decoy sensor. Unauthorized interaction is a detection signal."},
        ]
        for profile in DEVICE_PROFILES:
            device_id, name, kind, dataset, position = profile
            if dataset in store.dataset_names:
                self.nodes[device_id] = IoTDevice(device_id, name, kind, dataset, position, store)

    def tick(self) -> list[dict]:
        return [device.tick() for device in self.nodes.values()]

    def check_alerts(self) -> list[dict]:
        new_alerts = []
        for device in self.nodes.values():
            if device.is_isolated or device.severity == "LOW":
                continue
            source_ts = device.last_row.source_ts if device.last_row else ""
            key = f"{device.id}:{device.severity}:{source_ts}"
            if key in self._active_alerts:
                continue
            alert = {
                "id": f"al_{uuid.uuid4().hex[:8]}", "nodeId": device.id, "node": device.name, "node_name": device.name,
                "time": datetime.now(timezone.utc).strftime("%H:%M:%S"), "timestamp": utc_now(),
                "severity": device.severity, "riskScore": device.risk_score, "anomalyScore": device.anomaly_score,
                "groundTruth": device.last_row.label if device.last_row else None,
                "attackType": device.last_row.attack_type if device.last_row else None,
                "reason": device.threat_reason(),
            }
            self._active_alerts[key] = alert
            new_alerts.append(alert)
        return new_alerts

    def replay_attack(self, device_id: str, attack_type: str | None = None) -> dict:
        device = self.nodes.get(device_id)
        if not device:
            raise KeyError(f"Unknown device: {device_id}")
        return device.queue_attack(self.store.next_attack(device.dataset, attack_type), repeats=3)

    def isolate_node(self, node_id: str) -> Optional[dict]:
        device = self.nodes.get(node_id)
        if not device:
            return None
        device.is_isolated = True
        device.status = "isolated"
        return {"id": device.id, "name": device.name}

    def restore_node(self, node_id: str) -> bool:
        device = self.nodes.get(node_id)
        if not device or not device.is_isolated:
            return False
        device.is_isolated = False
        device.status = "normal"
        device.severity = "LOW"
        device.persistence_score = 0.0
        device.risk_score = 0.0
        return True

    def clear_alerts(self) -> None:
        self._active_alerts.clear()

    def add_alert(self, alert: dict) -> None:
        """Insert a manually-created alert (isolate/honeypot/approve) into the
        live in-memory feed so it actually shows up in the dashboard/alerts
        tab instead of only being written to the audit database."""
        key = alert.get("id") or f"manual_{uuid.uuid4().hex[:8]}"
        self._active_alerts[key] = alert

    def resolve_alert(self, alert_id: str) -> Optional[dict]:
        """Remove an alert from the live feed (e.g. once an operator has
        approved/actioned it) and return it, or None if not found."""
        key = next(
            (k for k, a in self._active_alerts.items() if a.get("id") == alert_id),
            None,
        )
        if key is None:
            return None
        return self._active_alerts.pop(key)

    def get_all_nodes(self) -> list[dict]:
        return [device.to_dict() for device in self.nodes.values()] + self.honeypots

    def get_active_alerts(self) -> list[dict]:
        return list(self._active_alerts.values())

    def get_gradients(self) -> dict[str, np.ndarray]:
        return {nid: device.gradient for nid, device in self.nodes.items() if device.gradient is not None and not device.is_isolated}

    def set_sanitizing(self, node_id: str) -> None:
        if node_id in self.nodes: self.nodes[node_id].status = "sanitizing"
    def set_health_checking(self, node_id: str) -> None:
        if node_id in self.nodes: self.nodes[node_id].status = "health_check"
    def set_ready_for_reconnect(self, node_id: str) -> None:
        if node_id in self.nodes: self.nodes[node_id].status = "ready_reconnect"
    def reconnect_node(self, node_id: str):
        device = self.nodes.get(node_id)
        if not device or device.status != "ready_reconnect": return None
        device.is_isolated = False
        device.status, device.severity = "normal", "LOW"
        device.anomaly_score = device.risk_score = device.persistence_score = 0.0
        return {"id": device.id, "name": device.name}
    def attack_types(self):
        return self.store.attack_types()
