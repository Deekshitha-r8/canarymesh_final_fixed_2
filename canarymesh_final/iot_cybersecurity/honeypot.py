"""Controlled defensive honeypot events. No random background probes are generated."""
from __future__ import annotations

import threading
from datetime import datetime, timezone

HONEYPOTS = [
    {"id": "HP1", "name": "PLC-99 (Honeypot)", "port": 1884},
    {"id": "HP2", "name": "Sensor-98 (Honeypot)", "port": 1885},
]


class HoneypotServer:
    def __init__(self, node_manager=None):
        self.node_manager = node_manager
        self._running = False
        self._queue: list[dict] = []
        self._lock = threading.Lock()
        self._counter = 0

    def start(self):
        self._running = True

    def stop(self):
        self._running = False

    def manual_probe(self) -> dict:
        self._counter += 1
        hp = HONEYPOTS[(self._counter - 1) % len(HONEYPOTS)]
        event = {
            "honeypot_id": hp["id"],
            "honeypot_name": hp["name"],
            "source_id": f"controlled-demo-client-{self._counter}",
            "port": hp["port"],
            "attack_pattern": "unauthorized honeypot interaction",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            self._queue.append(event)
        return event

    def check_probes(self) -> list[dict]:
        with self._lock:
            events = list(self._queue)
            self._queue.clear()
        return events
