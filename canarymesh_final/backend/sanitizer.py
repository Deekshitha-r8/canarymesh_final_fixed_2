"""Defensive sanitization stages matching the supplied four-phase architecture."""
from __future__ import annotations

BLOCKLIST: list[str] = []


class NodeSanitizer:
    def __init__(self, node_manager, fl_engine):
        self.node_manager = node_manager
        self.fl_engine = fl_engine

    def block_attacker_source(self, node_id: str) -> str:
        node = self.node_manager.nodes.get(node_id)
        if not node:
            return "unknown-source"
        attack_type = node.last_row.attack_type if node.last_row else "unknown"
        # The benchmark does not contain a verified source IP for the replay row.
        # Never invent one and call it real; identify the replay event instead.
        source = f"dataset-replay:{node.dataset}:{attack_type or 'normal'}"
        if source not in BLOCKLIST:
            BLOCKLIST.append(source)
        return source

    def purge_command_queue(self, node_id: str) -> bool:
        node = self.node_manager.nodes.get(node_id)
        if not node:
            return False
        node._attack_rows.clear()
        node.persistence_score = 0.0
        node.anomaly_score = 0.0
        node.feature_deviation = 0.0
        node.risk_score = 0.0
        node.severity = "LOW"
        node.status = "sanitizing"
        return True

    def restore_fl_model(self, node_id: str) -> int:
        node = self.node_manager.nodes.get(node_id)
        if not node:
            return self.fl_engine.round
        if self.fl_engine.global_params is not None:
            node.apply_global_model(float(self.fl_engine.global_params[0]))
        else:
            rows = self.node_manager.store.normal_rows[node.dataset][:5000]
            import numpy as np
            matrix = np.array([[r.features[name] for name in node.feature_names] for r in rows], dtype=float)
            scaled = node.scaler.fit_transform(matrix)
            node.model.fit(scaled)
            scores = node.model.score_samples(scaled)
            decision = node.model.decision_function(scaled)
            node.normal_decision_p01 = float(np.percentile(decision, 1))
            node.normal_score_p01 = float(np.percentile(scores, 1))
            node.normal_score_p05 = float(np.percentile(scores, 5))
            node.normal_score_median = float(np.median(scores))
            node.normal_feature_mean = np.mean(matrix, axis=0)
            node.normal_feature_std = np.where(np.std(matrix, axis=0) < 1e-9, 1.0, np.std(matrix, axis=0))
        node.persistence_score = node.anomaly_score = node.feature_deviation = node.risk_score = 0.0
        node.severity = "LOW"
        return self.fl_engine.round

    def verify_health(self, node_id: str) -> bool:
        node = self.node_manager.nodes.get(node_id)
        if not node:
            return False
        return node.severity == "LOW" and node.risk_score < 25.0

    def get_blocklist(self) -> list[str]:
        return list(BLOCKLIST)
