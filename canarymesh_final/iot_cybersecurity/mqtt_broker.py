"""Compatibility wrapper for the real MQTT publisher used by CanaryMesh.

The original project generated random in-process MQTT messages. The final runtime
instead publishes the exact database-backed telemetry payload through paho-mqtt.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class MQTTMessage:
    topic: str
    payload: str
    source_id: str
    source_name: str
    destination: str = "broker"
    command: str = "TELEMETRY"
    msg_type: str = "NORMAL"
    timestamp: str = ""
    is_attack: bool = False


class MQTTBrokerSimulator:
    """Legacy name retained so older imports do not break. No random data is generated."""
    def __init__(self):
        self._subscribers: dict[str, list[Callable[[MQTTMessage], Any]]] = {}

    def subscribe(self, topic_pattern: str, callback: Callable[[MQTTMessage], Any]):
        self._subscribers.setdefault(topic_pattern, []).append(callback)

    def publish(self, msg: MQTTMessage):
        for pattern, callbacks in self._subscribers.items():
            if pattern == "#" or pattern == msg.topic or (pattern.endswith("/#") and msg.topic.startswith(pattern[:-2])):
                for callback in callbacks:
                    callback(msg)
