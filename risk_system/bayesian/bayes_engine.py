from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional, Sequence

import numpy as np
import pandas as pd

from risk_system.domain import ThreatType


@dataclass
class ThreatDependency:
    parent: str
    weight: float
    dependency_type: str = "direct"


class BayesianEngine:
    def __init__(
        self,
        dependencies: Mapping[str, Sequence[dict | tuple | ThreatDependency]] | None = None,
        group_key: str = "node_id",
        min_probability: float = 0.0,
        max_probability: float = 1.0,
    ) -> None:
        self.group_key = group_key
        self.min_probability = float(np.clip(min_probability, 0.0, 1.0))
        self.max_probability = float(np.clip(max_probability, 0.0, 1.0))
        self.dependencies: Dict[str, List[ThreatDependency]] = {}
        self.set_dependencies(dependencies or self._default_dependencies())

    def set_dependencies(
        self,
        dependencies: Mapping[str, Sequence[dict | tuple | ThreatDependency]],
    ) -> None:
        normalized: Dict[str, List[ThreatDependency]] = {}

        for target, parents in dependencies.items():
            target_key = str(target)
            normalized[target_key] = []

            for item in parents:
                if isinstance(item, ThreatDependency):
                    dep = ThreatDependency(
                        parent=str(item.parent),
                        weight=float(np.clip(item.weight, 0.0, 1.0)),
                        dependency_type=str(item.dependency_type),
                    )
                elif isinstance(item, dict):
                    dep = ThreatDependency(
                        parent=str(item["parent"]),
                        weight=float(np.clip(item["weight"], 0.0, 1.0)),
                        dependency_type=str(item.get("dependency_type", "direct")),
                    )
                else:
                    parent, weight = item
                    dep = ThreatDependency(
                        parent=str(parent),
                        weight=float(np.clip(weight, 0.0, 1.0)),
                        dependency_type="direct",
                    )

                normalized[target_key].append(dep)

        self.dependencies = normalized

    def set_group_key(self, group_key: str) -> None:
        self.group_key = group_key

    def update_probabilities(self, probabilities: pd.DataFrame) -> pd.DataFrame:
        required_columns = {"event_id", "node_id", "asset_id", "threat_type"}
        self._check_columns(probabilities, required_columns, "probabilities")

        probability_column = self._resolve_probability_column(probabilities)

        result = probabilities.copy()
        result["threat_type"] = result["threat_type"].astype(str)
        result["base_probability"] = pd.to_numeric(
            result[probability_column], errors="coerce"
        ).fillna(0.0).clip(self.min_probability, self.max_probability)

        if self.group_key not in result.columns:
            raise ValueError(
                f"Для байесовского уточнения в probabilities должна быть колонка '{self.group_key}'."
            )

        all_groups: List[pd.DataFrame] = []

        for _, group_df in result.groupby(self.group_key, sort=False):
            adjusted_group = self._update_group(group_df)
            all_groups.append(adjusted_group)

        final_df = pd.concat(all_groups, axis=0).reset_index(drop=True)
        final_df["bayesian_probability"] = final_df["bayesian_probability"].clip(
            self.min_probability,
            self.max_probability,
        )

        if "calibrated_probability" in final_df.columns:
            final_df["calibrated_probability"] = final_df["bayesian_probability"]
        else:
            final_df["probability"] = final_df["bayesian_probability"]

        return final_df

    def _update_group(self, group_df: pd.DataFrame) -> pd.DataFrame:
        group = group_df.copy().reset_index(drop=True)

        threat_base_map = (
            group.groupby("threat_type", as_index=False)["base_probability"]
            .max()
            .set_index("threat_type")["base_probability"]
            .to_dict()
        )

        adjusted_map: Dict[str, float] = {}

        for threat_name, base_probability in threat_base_map.items():
            adjusted_probability = self._apply_dependencies(
                target_threat=threat_name,
                base_probability=float(base_probability),
                current_probabilities=threat_base_map,
            )
            adjusted_map[threat_name] = adjusted_probability

        group["bayesian_probability"] = group["threat_type"].map(adjusted_map).astype(float)
        return group

    def _apply_dependencies(
        self,
        target_threat: str,
        base_probability: float,
        current_probabilities: Dict[str, float],
    ) -> float:
        parents = self.dependencies.get(target_threat, [])
        if not parents:
            return float(np.clip(base_probability, self.min_probability, self.max_probability))

        complement = 1.0 - float(np.clip(base_probability, self.min_probability, self.max_probability))

        for parent_dep in parents:
            parent_probability = float(
                np.clip(
                    current_probabilities.get(parent_dep.parent, 0.0),
                    self.min_probability,
                    self.max_probability,
                )
            )

            effective_weight = self._dependency_weight(parent_dep)
            complement *= 1.0 - effective_weight * parent_probability

        adjusted = 1.0 - complement
        return float(np.clip(adjusted, self.min_probability, self.max_probability))

    @staticmethod
    def _dependency_weight(dependency: ThreatDependency) -> float:
        dep_type = dependency.dependency_type.lower()

        type_factor = {
            "direct": 1.00,
            "prerequisite": 0.90,
            "escalation": 1.10,
            "supporting": 0.75,
        }.get(dep_type, 1.00)

        return float(np.clip(dependency.weight * type_factor, 0.0, 1.0))

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
    def _default_dependencies() -> Dict[str, List[dict]]:
        return {
            ThreatType.UNAUTHORIZED_ACCESS.value: [
                {
                    "parent": ThreatType.PHISHING.value,
                    "weight": 0.28,
                    "dependency_type": "prerequisite",
                },
                {
                    "parent": ThreatType.MISCONFIGURATION.value,
                    "weight": 0.22,
                    "dependency_type": "supporting",
                },
            ],
            ThreatType.PRIVILEGE_ESCALATION.value: [
                {
                    "parent": ThreatType.UNAUTHORIZED_ACCESS.value,
                    "weight": 0.38,
                    "dependency_type": "escalation",
                },
                {
                    "parent": ThreatType.MISCONFIGURATION.value,
                    "weight": 0.20,
                    "dependency_type": "supporting",
                },
            ],
            ThreatType.DATA_LEAK.value: [
                {
                    "parent": ThreatType.PRIVILEGE_ESCALATION.value,
                    "weight": 0.34,
                    "dependency_type": "escalation",
                },
                {
                    "parent": ThreatType.UNAUTHORIZED_ACCESS.value,
                    "weight": 0.20,
                    "dependency_type": "direct",
                },
                {
                    "parent": ThreatType.INSIDER.value,
                    "weight": 0.30,
                    "dependency_type": "direct",
                },
            ],
            ThreatType.MALWARE.value: [
                {
                    "parent": ThreatType.PHISHING.value,
                    "weight": 0.24,
                    "dependency_type": "prerequisite",
                }
            ],
        }