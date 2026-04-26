from __future__ import annotations

from typing import Dict, List, Mapping, Sequence, Tuple

import numpy as np
import pandas as pd

from risk_system.domain import ThreatType


class BayesianEngine:
    def __init__(
        self,
        dependencies: Mapping[str, Sequence[Tuple[str, float]]] | None = None,
        group_key: str = "node_id",
    ) -> None:
        self.group_key = group_key
        self.dependencies: Dict[str, List[Tuple[str, float]]] = {}
        self.set_dependencies(dependencies or self._default_dependencies())

    def set_dependencies(
        self,
        dependencies: Mapping[str, Sequence[Tuple[str, float]]],
    ) -> None:
        normalized: Dict[str, List[Tuple[str, float]]] = {}

        for target, parents in dependencies.items():
            target_key = str(target)
            normalized[target_key] = []

            for parent, weight in parents:
                normalized[target_key].append((str(parent), float(np.clip(weight, 0.0, 1.0))))

        self.dependencies = normalized

    def update_probabilities(self, probabilities: pd.DataFrame) -> pd.DataFrame:
        required_columns = {"event_id", "node_id", "asset_id", "threat_type"}
        self._check_columns(probabilities, required_columns, "probabilities")

        probability_column = self._resolve_probability_column(probabilities)

        result = probabilities.copy()
        result["threat_type"] = result["threat_type"].astype(str)
        result["base_probability"] = result[probability_column].astype(float).clip(0.0, 1.0)

        if self.group_key not in result.columns:
            raise ValueError(
                f"Для байесовского уточнения в probabilities должна быть колонка '{self.group_key}'."
            )

        adjusted_values: List[float] = []

        for _, group_df in result.groupby(self.group_key, sort=False):
            adjusted_group = self._update_group(group_df)
            adjusted_values.extend(adjusted_group["bayesian_probability"].tolist())

        result["bayesian_probability"] = np.asarray(adjusted_values, dtype=float)
        result["bayesian_probability"] = result["bayesian_probability"].clip(0.0, 1.0)

        if "calibrated_probability" in result.columns:
            result["calibrated_probability"] = result["bayesian_probability"]
        else:
            result["probability"] = result["bayesian_probability"]

        return result

    def _update_group(self, group_df: pd.DataFrame) -> pd.DataFrame:
        group = group_df.copy().reset_index(drop=True)

        threat_base_map = (
            group.groupby("threat_type", as_index=False)["base_probability"]
            .max()
            .set_index("threat_type")["base_probability"]
            .to_dict()
        )

        threat_adjusted_map: Dict[str, float] = {}

        for threat_name, base_probability in threat_base_map.items():
            adjusted_probability = self._apply_dependencies(
                target_threat=threat_name,
                base_probability=float(base_probability),
                current_probabilities=threat_base_map,
            )
            threat_adjusted_map[threat_name] = adjusted_probability

        group["bayesian_probability"] = group["threat_type"].map(threat_adjusted_map).astype(float)
        return group

    def _apply_dependencies(
        self,
        target_threat: str,
        base_probability: float,
        current_probabilities: Dict[str, float],
    ) -> float:
        parents = self.dependencies.get(target_threat, [])
        if not parents:
            return float(np.clip(base_probability, 0.0, 1.0))

        complement = 1.0 - float(np.clip(base_probability, 0.0, 1.0))

        for parent_name, weight in parents:
            parent_probability = float(np.clip(current_probabilities.get(parent_name, 0.0), 0.0, 1.0))
            complement *= 1.0 - float(np.clip(weight, 0.0, 1.0)) * parent_probability

        adjusted = 1.0 - complement
        return float(np.clip(adjusted, 0.0, 1.0))

    @staticmethod
    def _resolve_probability_column(probabilities: pd.DataFrame) -> str:
        if "calibrated_probability" in probabilities.columns:
            return "calibrated_probability"
        if "raw_probability" in probabilities.columns:
            return "raw_probability"
        if "probability" in probabilities.columns:
            return "probability"
        raise ValueError(
            "В таблице probabilities должна быть одна из колонок: "
            "'calibrated_probability', 'raw_probability' или 'probability'."
        )

    @staticmethod
    def _check_columns(frame: pd.DataFrame, required: set[str], frame_name: str) -> None:
        missing = required - set(frame.columns)
        if missing:
            raise ValueError(
                f"В таблице '{frame_name}' отсутствуют обязательные колонки: {sorted(missing)}"
            )

    @staticmethod
    def _default_dependencies() -> Dict[str, List[Tuple[str, float]]]:
        return {
            ThreatType.MALWARE.value: [
                (ThreatType.PHISHING.value, 0.25),
                (ThreatType.MISCONFIGURATION.value, 0.15),
            ],
            ThreatType.PRIVILEGE_ESCALATION.value: [
                (ThreatType.UNAUTHORIZED_ACCESS.value, 0.35),
                (ThreatType.MISCONFIGURATION.value, 0.25),
            ],
            ThreatType.DATA_LEAK.value: [
                (ThreatType.UNAUTHORIZED_ACCESS.value, 0.40),
                (ThreatType.INSIDER.value, 0.35),
                (ThreatType.MALWARE.value, 0.20),
            ],
            ThreatType.UNAUTHORIZED_ACCESS.value: [
                (ThreatType.PHISHING.value, 0.20),
                (ThreatType.MISCONFIGURATION.value, 0.20),
            ],
        }