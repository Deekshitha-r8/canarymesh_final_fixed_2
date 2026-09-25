"""Compact federated parameter aggregation with measured ToN-IoT evaluation."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import numpy as np

def get_model_offset(model) -> float:
    """Return IsolationForest offset_ safely as a Python float."""
    return float(np.asarray(model.offset_).reshape(-1)[0])

class FederatedEngine:
    def __init__(self, node_manager):
        self.node_manager = node_manager
        self.round = 0
        self.max_rounds = 100
        self.global_accuracy: Optional[float] = None
        self.global_params: Optional[np.ndarray] = None
        self.round_history: list[dict] = []

    def _evaluate_global_model(self, global_offset: float | None) -> float:
        scores = []
        for node in self.node_manager.nodes.values():
            normal = self.node_manager.store.normal_rows[node.dataset]
            attacks = self.node_manager.store.attack_rows[node.dataset]
            if not normal or not attacks:
                continue
            normal_eval = normal[min(5000, max(0, len(normal) - 50)):][:50]
            attack_eval = []
            for attack_type in sorted(attacks):
                attack_eval.extend(attacks[attack_type][:10])
                if len(attack_eval) >= 50:
                    break
            eval_rows = normal_eval + attack_eval[:50]
            if not eval_rows:
                continue
            old_offset = get_model_offset(node.model)
            if global_offset is not None:
                node.model.offset_ = float(global_offset)
            correct = 0
            for row in eval_rows:
                vec = np.array([[row.features[name] for name in node.feature_names]], dtype=float)
                predicted_attack = int(node.model.predict(node.scaler.transform(vec))[0]) == -1
                correct += int(predicted_attack == bool(row.attack_type))
            node.model.offset_ = np.array([old_offset])
            scores.append(correct / len(eval_rows))
        return float(np.mean(scores) * 100.0) if scores else 0.0

    async def run_round(self) -> dict:
        self.round += 1
        active = [node for node in self.node_manager.nodes.values() if not node.is_isolated]
        offsets, weights, contributions = [], [], {}
        for node in active:
            offsets.append(get_model_offset(node.model))
            weights.append(max(node.activity, 1.0))
            contributions[node.id] = {
                "name": node.name,
                "contributed": True,
                "update_norm": round(float(np.linalg.norm(node.gradient)), 4) if node.gradient is not None else 0.0,
                "param_offset": round(get_model_offset(node.model), 6),
            }
        for node in self.node_manager.nodes.values():
            if node.is_isolated:
                contributions[node.id] = {"name": node.name, "contributed": False, "update_norm": 0.0,"param_offset": get_model_offset(node.model)}
        if offsets:
            self.global_params = np.array([float(np.average(np.array(offsets), weights=np.array(weights)))])
            for node in active:
                node.apply_global_model(self.global_params[0])
            self.global_accuracy = self._evaluate_global_model(float(self.global_params[0]))
        record = {
            "round": self.round, "participants": len(active), "accuracy": round(float(self.global_accuracy or 0.0), 2),
            "raw_data_shared": 0, "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.round_history.append(record)
        self.round_history = self.round_history[-100:]
        return self.get_status(contributions)

    def get_status(self, contributions: dict | None = None) -> dict:
        if contributions is None:
            contributions = {
                nid: {"name": node.name, "contributed": not node.is_isolated,
                      "update_norm": round(float(np.linalg.norm(node.gradient)), 4) if node.gradient is not None else 0.0,
                      "param_offset": round(get_model_offset(node.model), 6)}
                for nid, node in self.node_manager.nodes.items()
            }
        return {
            "round": self.round,
            "maxRounds": self.max_rounds,
            "accuracy": round(float(self.global_accuracy or 0.0), 2),
            "rawDataShared": 0,
            "participants": sum(1 for node in self.node_manager.nodes.values() if not node.is_isolated),
            "contributions": contributions,
            "history": self.round_history[-10:],
            "aggregationMethod": "Traffic-weighted aggregation of local Isolation Forest offset parameters",
            "evaluationSource": "Held-out labeled ToN-IoT database rows",
            "measured": self.global_accuracy is not None,
        }
