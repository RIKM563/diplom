from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence

import numpy as np
import pandas as pd

from risk_system.domain import Asset, Node, SecurityEvent


@dataclass
class ImpactResult:
    event_id: str
    node_id: str
    asset_id: str
    impact: float
    node_criticality: float
    asset_criticality: float
    final_criticality: float


class ImpactModel:
    def __init__(
        self,
        severity_weight: float = 0.30,
        frequency_weight: float = 0.15,
        anomaly_weight: float = 0.20,
        vulnerability_weight: float = 0.15,
        privilege_weight: float = 0.10,
        exposure_weight: float = 0.10,
        node_criticality_weight: float = 0.40,
        asset_criticality_weight: float = 0.60,
        frequency_scale: float = 100.0,
        asset_cost_scale: float = 1_000_000.0,
    ) -> None:
        self.severity_weight = severity_weight
        self.frequency_weight = frequency_weight
        self.anomaly_weight = anomaly_weight
        self.vulnerability_weight = vulnerability_weight
        self.privilege_weight = privilege_weight
        self.exposure_weight = exposure_weight
        self.node_criticality_weight = node_criticality_weight
        self.asset_criticality_weight = asset_criticality_weight
        self.frequency_scale = frequency_scale
        self.asset_cost_scale = asset_cost_scale

        self._validate_weights()

    def estimate_impact(
        self,
        event: SecurityEvent,
        node: Node,
        asset: Asset,
    ) -> float:
        severity_component = self._clip_01(event.severity)
        frequency_component = self._normalize_frequency(event.frequency)
        anomaly_component = self._clip_01(event.anomaly_score)
        vulnerability_component = 1.0 if event.has_vulnerability else 0.0
        privilege_component = self._normalize_privilege(event.privilege_level)
        exposure_component = self._clip_01(node.exposure)

        impact = (
            self.severity_weight * severity_component
            + self.frequency_weight * frequency_component
            + self.anomaly_weight * anomaly_component
            + self.vulnerability_weight * vulnerability_component
            + self.privilege_weight * privilege_component
            + self.exposure_weight * exposure_component
        )

        cost_factor = self._normalize_cost(asset.cost)
        impact = 0.85 * impact + 0.15 * cost_factor

        return float(self._clip_01(impact))

    def get_node_criticality(self, node: Node) -> float:
        return float(max(node.criticality, 0.0))

    def get_asset_criticality(self, asset: Asset) -> float:
        return float(max(asset.criticality, 0.0))

    def get_final_criticality(self, node: Node, asset: Asset) -> float:
        node_criticality = self.get_node_criticality(node)
        asset_criticality = self.get_asset_criticality(asset)

        final_criticality = (
            self.node_criticality_weight * node_criticality
            + self.asset_criticality_weight * asset_criticality
        )
        return float(max(final_criticality, 0.0))

    def evaluate(
        self,
        event: SecurityEvent,
        node: Node,
        asset: Asset,
    ) -> ImpactResult:
        impact = self.estimate_impact(event, node, asset)
        node_criticality = self.get_node_criticality(node)
        asset_criticality = self.get_asset_criticality(asset)
        final_criticality = self.get_final_criticality(node, asset)

        return ImpactResult(
            event_id=event.event_id,
            node_id=node.node_id,
            asset_id=asset.asset_id,
            impact=impact,
            node_criticality=node_criticality,
            asset_criticality=asset_criticality,
            final_criticality=final_criticality,
        )

    def build_impact_table(
        self,
        events: Sequence[SecurityEvent],
        nodes: Sequence[Node],
        assets: Sequence[Asset],
    ) -> pd.DataFrame:
        node_map: Dict[str, Node] = {node.node_id: node for node in nodes}
        asset_map: Dict[str, Asset] = {asset.asset_id: asset for asset in assets}

        rows: List[Dict[str, float | str]] = []

        for event in events:
            node = node_map.get(event.node_id)
            asset = asset_map.get(event.asset_id)

            if node is None:
                raise ValueError(f"Для события {event.event_id} не найден узел {event.node_id}.")
            if asset is None:
                raise ValueError(f"Для события {event.event_id} не найден актив {event.asset_id}.")

            result = self.evaluate(event, node, asset)
            rows.append(
                {
                    "event_id": result.event_id,
                    "node_id": result.node_id,
                    "asset_id": result.asset_id,
                    "impact": result.impact,
                    "node_criticality": result.node_criticality,
                    "asset_criticality": result.asset_criticality,
                    "final_criticality": result.final_criticality,
                }
            )

        return pd.DataFrame(rows)

    def evaluate_from_feature_table(self, feature_table: pd.DataFrame) -> pd.DataFrame:
        required_columns = {
            "event_id",
            "node_id",
            "asset_id",
            "severity",
            "frequency",
            "anomaly_score",
            "has_vulnerability",
            "privilege_level",
            "exposure",
            "criticality",
            "criticality_asset",
            "cost",
        }

        missing = required_columns - set(feature_table.columns)
        if missing:
            raise ValueError(
                f"В feature_table отсутствуют обязательные колонки для расчета ущерба: {sorted(missing)}"
            )

        df = feature_table.copy()

        severity_component = df["severity"].clip(0.0, 1.0)
        frequency_component = self._normalize_frequency_series(df["frequency"])
        anomaly_component = df["anomaly_score"].clip(0.0, 1.0)
        vulnerability_component = df["has_vulnerability"].astype(int).clip(0, 1)
        privilege_component = self._normalize_privilege_series(df["privilege_level"])
        exposure_component = df["exposure"].clip(lower=0.0, upper=1.0)
        cost_component = self._normalize_cost_series(df["cost"])

        impact = (
            self.severity_weight * severity_component
            + self.frequency_weight * frequency_component
            + self.anomaly_weight * anomaly_component
            + self.vulnerability_weight * vulnerability_component
            + self.privilege_weight * privilege_component
            + self.exposure_weight * exposure_component
        )
        impact = 0.85 * impact + 0.15 * cost_component
        impact = impact.clip(lower=0.0, upper=1.0)

        node_criticality = df["criticality"].clip(lower=0.0)
        asset_criticality = df["criticality_asset"].clip(lower=0.0)
        final_criticality = (
            self.node_criticality_weight * node_criticality
            + self.asset_criticality_weight * asset_criticality
        ).clip(lower=0.0)

        result = pd.DataFrame(
            {
                "event_id": df["event_id"].astype(str),
                "node_id": df["node_id"].astype(str),
                "asset_id": df["asset_id"].astype(str),
                "impact": impact.astype(float),
                "node_criticality": node_criticality.astype(float),
                "asset_criticality": asset_criticality.astype(float),
                "final_criticality": final_criticality.astype(float),
            }
        )

        return result.reset_index(drop=True)

    def _validate_weights(self) -> None:
        event_weight_sum = (
            self.severity_weight
            + self.frequency_weight
            + self.anomaly_weight
            + self.vulnerability_weight
            + self.privilege_weight
            + self.exposure_weight
        )
        if not np.isclose(event_weight_sum, 1.0):
            raise ValueError("Сумма весов компонентов ущерба должна быть равна 1.0.")

        criticality_weight_sum = self.node_criticality_weight + self.asset_criticality_weight
        if not np.isclose(criticality_weight_sum, 1.0):
            raise ValueError("Сумма весов критичности узла и актива должна быть равна 1.0.")

    @staticmethod
    def _clip_01(value: float) -> float:
        return float(np.clip(value, 0.0, 1.0))

    def _normalize_frequency(self, value: float) -> float:
        value = max(float(value), 0.0)
        return float(np.clip(np.log1p(value) / np.log1p(self.frequency_scale), 0.0, 1.0))

    def _normalize_frequency_series(self, values: pd.Series) -> pd.Series:
        series = values.astype(float).clip(lower=0.0)
        normalized = np.log1p(series) / np.log1p(self.frequency_scale)
        return normalized.clip(lower=0.0, upper=1.0)

    @staticmethod
    def _normalize_privilege(value: int) -> float:
        value = min(max(int(value), 0), 10)
        return float(value / 10.0)

    @staticmethod
    def _normalize_privilege_series(values: pd.Series) -> pd.Series:
        series = values.astype(float).clip(lower=0.0, upper=10.0)
        return (series / 10.0).clip(lower=0.0, upper=1.0)

    def _normalize_cost(self, value: float) -> float:
        value = max(float(value), 0.0)
        return float(np.clip(np.log1p(value) / np.log1p(self.asset_cost_scale), 0.0, 1.0))

    def _normalize_cost_series(self, values: pd.Series) -> pd.Series:
        series = values.astype(float).clip(lower=0.0)
        normalized = np.log1p(series) / np.log1p(self.asset_cost_scale)
        return normalized.clip(lower=0.0, upper=1.0)