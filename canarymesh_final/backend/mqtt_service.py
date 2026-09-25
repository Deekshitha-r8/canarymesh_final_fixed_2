"""MQTT publisher used by the live replay pipeline."""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import Any

try:
    import paho.mqtt.client as mqtt
except Exception:  # pragma: no cover
    mqtt = None


class MQTTPublisher:
    def __init__(self):
        self.host = os.getenv("MQTT_BROKER_HOST", "127.0.0.1")
        self.port = int(os.getenv("MQTT_BROKER_PORT", "1883"))
        self.enabled = os.getenv("MQTT_ENABLED", "true").lower() == "true"
        self.connected = False
        self.last_error = ""
        self._client = None
        self._lock = threading.Lock()

    def start(self) -> None:
        if not self.enabled or mqtt is None:
            self.last_error = "MQTT publisher disabled or paho-mqtt unavailable"
            return
        try:
            self._client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="canarymesh-soc")
            self._client.on_connect = self._on_connect
            self._client.on_disconnect = self._on_disconnect
            self._client.connect(self.host, self.port, keepalive=30)
            self._client.loop_start()
        except Exception as exc:
            self.last_error = str(exc)
            self.connected = False

    def stop(self) -> None:
        with self._lock:
            client = self._client
            self._client = None
            self.connected = False
        if client is not None:
            try:
                client.loop_stop()
                client.disconnect()
            except Exception:
                pass

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        self.connected = int(reason_code) == 0
        if not self.connected:
            self.last_error = f"broker refused connection: {reason_code}"

    def _on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties=None):
        self.connected = False
        if reason_code:
            self.last_error = str(reason_code)

    def publish(self, *, topic: str, payload: dict[str, Any]) -> str:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        if not self.enabled or self._client is None or not self.connected:
            return "recorded_only"
        try:
            info = self._client.publish(topic, body, qos=0, retain=False)
            return "mqtt" if info.rc == mqtt.MQTT_ERR_SUCCESS else "recorded_only"
        except Exception as exc:
            self.last_error = str(exc)
            self.connected = False
            return "recorded_only"

    def status(self) -> dict:
        return {
            "connected": self.connected,
            "host": self.host,
            "port": self.port,
            "enabled": self.enabled,
            "error": self.last_error,
        }


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
