from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Mapping, Sequence

import numpy as np
import pandas as pd

from risk_system.domain import Asset, Node, SecurityEvent, ThreatType


@dataclass
class ImpactResult:
    event_id: str
    node_id: str
    asset_id: str
    event_component: float
    asset_component: float
    business_context: float
    threat_multiplier: float
    impact: float
    node_criticality: float
    asset_criticality: float
    final_criticality: float


class ImpactModel:
    def __init__(
        self,
        event_component_weight: float = 0.55,
        asset_component_weight: float = 0.45,
        severity_weight: float = 0.25,
        frequency_weight: float = 0.12,
        anomaly_weight: float = 0.18,
        vulnerability_weight: float = 0.12,
        privilege_weight: float = 0.10,
        exposure_weight: float = 0.13,
        event_context_weight: float = 0.10,

        cost_weight: float = 0.15,
        data_sensitivity_weight: float = 0.25,
        regulatory_weight: float = 0.15,
        client_exposure_weight: float = 0.15,
        business_criticality_weight: float = 0.20,
        tier_weight: float = 0.10,

        node_criticality_weight: float = 0.35,
        asset_criticality_weight: float = 0.45,
        business_context_weight: float = 0.20,
        frequency_scale: float = 100.0,
        asset_cost_scale: float = 1_000_000.0,
        tier_scale: float = 4.0,
        failed_logins_scale: float = 10.0,
        suspicious_processes_scale: float = 10.0,
        open_ports_scale: float = 20.0,
        large_transfer_scale: float = 1500.0,
        threat_multipliers: Mapping[str, float] | None = None,
    ) -> None:
        self.event_component_weight = event_component_weight
        self.asset_component_weight = asset_component_weight

        self.severity_weight = severity_weight
        self.frequency_weight = frequency_weight
        self.anomaly_weight = anomaly_weight
        self.vulnerability_weight = vulnerability_weight
        self.privilege_weight = privilege_weight
        self.exposure_weight = exposure_weight
        self.event_context_weight = event_context_weight

        self.cost_weight = cost_weight
        self.data_sensitivity_weight = data_sensitivity_weight
        self.regulatory_weight = regulatory_weight
        self.client_exposure_weight = client_exposure_weight
        self.business_criticality_weight = business_criticality_weight
        self.tier_weight = tier_weight

        self.node_criticality_weight = node_criticality_weight
        self.asset_criticality_weight = asset_criticality_weight
        self.business_context_weight = business_context_weight

        self.frequency_scale = frequency_scale
        self.asset_cost_scale = asset_cost_scale
        self.tier_scale = tier_scale
        self.failed_logins_scale = failed_logins_scale
        self.suspicious_processes_scale = suspicious_processes_scale
        self.open_ports_scale = open_ports_scale
        self.large_transfer_scale = large_transfer_scale

        self.threat_multipliers = dict(threat_multipliers or self._default_threat_multipliers())

        self._validate_weights()

    def estimate_event_component(
        self,
        event: SecurityEvent,
        node: Node,
    ) -> float:
        severity_component = self._clip_01(event.severity)
        frequency_component = self._normalize_log(event.frequency, self.frequency_scale)
        anomaly_component = self._clip_01(event.anomaly_score)
        vulnerability_component = 1.0 if event.has_vulnerability else 0.0
        privilege_component = self._normalize_privilege(event.privilege_level)
        exposure_component = self._clip_01(node.exposure)
        event_context_component = self._estimate_event_context_from_entities(event)

        value = (
            self.severity_weight * severity_component
            + self.frequency_weight * frequency_component
            + self.anomaly_weight * anomaly_component
            + self.vulnerability_weight * vulnerability_component
            + self.privilege_weight * privilege_component
            + self.exposure_weight * exposure_component
            + self.event_context_weight * event_context_component
        )

        return float(self._clip_01(value))

    def estimate_asset_component(
        self,
        node: Node,
        asset: Asset,
    ) -> float:
        cost_component = self._normalize_log(asset.cost, self.asset_cost_scale)
        data_sensitivity_component = self._extract_meta_value(asset.metadata, "data_sensitivity", 0.0)
        regulatory_component = self._extract_meta_value(asset.metadata, "regulatory_significance", 0.0)
        client_exposure_component = self._extract_meta_value(asset.metadata, "client_exposure", 0.0)
        business_criticality_component = self._extract_meta_value(asset.metadata, "business_criticality", 0.0)
        tier_component = self._normalize_linear(
            self._extract_meta_value(asset.metadata, "tier", 0.0),
            self.tier_scale,
        )

        value = (
            self.cost_weight * cost_component
            + self.data_sensitivity_weight * data_sensitivity_component
            + self.regulatory_weight * regulatory_component
            + self.client_exposure_weight * client_exposure_component
            + self.business_criticality_weight * business_criticality_component
            + self.tier_weight * tier_component
        )

        return float(self._clip_01(value))

    def get_business_context(self, node: Node, asset: Asset) -> float:
        asset_business = self._extract_meta_value(asset.metadata, "business_criticality", 0.0)
        asset_regulatory = self._extract_meta_value(asset.metadata, "regulatory_significance", 0.0)
        asset_client_exposure = self._extract_meta_value(asset.metadata, "client_exposure", 0.0)
        node_internet_facing = self._extract_meta_value(node.metadata, "internet_facing", 0.0)
        node_cross_segment = self._extract_meta_value(node.metadata, "cross_segment_access", 0.0)
        node_shared_service = self._extract_meta_value(node.metadata, "service_shared", 0.0)
        node_privileged_zone = self._extract_meta_value(node.metadata, "privileged_zone", 0.0)

        value = (
            0.24 * asset_business
            + 0.20 * asset_regulatory
            + 0.18 * asset_client_exposure
            + 0.14 * node_internet_facing
            + 0.10 * node_cross_segment
            + 0.07 * node_shared_service
            + 0.07 * node_privileged_zone
        )

        return float(self._clip_01(value))

    def get_node_criticality(self, node: Node) -> float:
        return float(self._clip_01(node.criticality))

    def get_asset_criticality(self, asset: Asset) -> float:
        return float(self._clip_01(asset.criticality))

    def get_final_criticality(self, node: Node, asset: Asset) -> float:
        node_criticality = self.get_node_criticality(node)
        asset_criticality = self.get_asset_criticality(asset)
        business_context = self.get_business_context(node, asset)

        final_criticality = (
            self.node_criticality_weight * node_criticality
            + self.asset_criticality_weight * asset_criticality
            + self.business_context_weight * business_context
        )

        return float(self._clip_01(final_criticality))

    def get_threat_multiplier(self, threat_type: ThreatType | str) -> float:
        key = threat_type.value if isinstance(threat_type, ThreatType) else str(threat_type)
        return float(self.threat_multipliers.get(key, 1.0))

    def estimate_impact(
        self,
        event: SecurityEvent,
        node: Node,
        asset: Asset,
    ) -> float:
        event_component = self.estimate_event_component(event, node)
        asset_component = self.estimate_asset_component(node, asset)
        threat_multiplier = self.get_threat_multiplier(event.threat_type)

        base_impact = (
            self.event_component_weight * event_component
            + self.asset_component_weight * asset_component
        )

        impact = base_impact * threat_multiplier
        return float(self._clip_01(impact))

    def evaluate(
        self,
        event: SecurityEvent,
        node: Node,
        asset: Asset,
    ) -> ImpactResult:
        event_component = self.estimate_event_component(event, node)
        asset_component = self.estimate_asset_component(node, asset)
        business_context = self.get_business_context(node, asset)
        threat_multiplier = self.get_threat_multiplier(event.threat_type)

        base_impact = (
            self.event_component_weight * event_component
            + self.asset_component_weight * asset_component
        )
        impact = self._clip_01(base_impact * threat_multiplier)

        node_criticality = self.get_node_criticality(node)
        asset_criticality = self.get_asset_criticality(asset)
        final_criticality = self.get_final_criticality(node, asset)

        return ImpactResult(
            event_id=event.event_id,
            node_id=node.node_id,
            asset_id=asset.asset_id,
            event_component=event_component,
            asset_component=asset_component,
            business_context=business_context,
            threat_multiplier=threat_multiplier,
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

        rows: list[dict[str, float | str]] = []

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
                    "event_component": result.event_component,
                    "asset_component": result.asset_component,
                    "business_context": result.business_context,
                    "threat_multiplier": result.threat_multiplier,
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
            "threat_type",
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

        severity_component = self._series(df, "severity", 0.0).clip(0.0, 1.0)
        frequency_component = self._normalize_log_series(self._series(df, "frequency", 0.0), self.frequency_scale)
        anomaly_component = self._series(df, "anomaly_score", 0.0).clip(0.0, 1.0)
        vulnerability_component = self._series(df, "has_vulnerability", 0.0).clip(0.0, 1.0)
        privilege_component = self._normalize_privilege_series(self._series(df, "privilege_level", 0.0))
        exposure_component = self._series(df, "exposure", 0.0).clip(0.0, 1.0)

        event_context_component = self._estimate_event_context_from_frame(df)

        event_component = (
            self.severity_weight * severity_component
            + self.frequency_weight * frequency_component
            + self.anomaly_weight * anomaly_component
            + self.vulnerability_weight * vulnerability_component
            + self.privilege_weight * privilege_component
            + self.exposure_weight * exposure_component
            + self.event_context_weight * event_context_component
        ).clip(0.0, 1.0)

        cost_component = self._normalize_log_series(self._series(df, "cost", 0.0), self.asset_cost_scale)
        data_sensitivity_component = self._series(df, "asset_meta_data_sensitivity", 0.0).clip(0.0, 1.0)
        regulatory_component = self._series(df, "asset_meta_regulatory_significance", 0.0).clip(0.0, 1.0)
        client_exposure_component = self._series(df, "asset_meta_client_exposure", 0.0).clip(0.0, 1.0)
        business_criticality_component = self._series(df, "asset_meta_business_criticality", 0.0).clip(0.0, 1.0)
        tier_component = self._normalize_linear_series(self._series(df, "asset_meta_tier", 0.0), self.tier_scale)

        asset_component = (
            self.cost_weight * cost_component
            + self.data_sensitivity_weight * data_sensitivity_component
            + self.regulatory_weight * regulatory_component
            + self.client_exposure_weight * client_exposure_component
            + self.business_criticality_weight * business_criticality_component
            + self.tier_weight * tier_component
        ).clip(0.0, 1.0)

        business_context = (
            0.24 * self._series(df, "asset_meta_business_criticality", 0.0).clip(0.0, 1.0)
            + 0.20 * self._series(df, "asset_meta_regulatory_significance", 0.0).clip(0.0, 1.0)
            + 0.18 * self._series(df, "asset_meta_client_exposure", 0.0).clip(0.0, 1.0)
            + 0.14 * self._series(df, "node_meta_internet_facing", 0.0).clip(0.0, 1.0)
            + 0.10 * self._series(df, "node_meta_cross_segment_access", 0.0).clip(0.0, 1.0)
            + 0.07 * self._series(df, "node_meta_service_shared", 0.0).clip(0.0, 1.0)
            + 0.07 * self._series(df, "node_meta_privileged_zone", 0.0).clip(0.0, 1.0)
        ).clip(0.0, 1.0)

        threat_multiplier = df["threat_type"].astype(str).map(self.threat_multipliers).fillna(1.0).astype(float)

        impact = (
            (self.event_component_weight * event_component + self.asset_component_weight * asset_component)
            * threat_multiplier
        ).clip(0.0, 1.0)

        node_criticality = self._series(df, "criticality", 0.0).clip(0.0, 1.0)
        asset_criticality = self._series(df, "criticality_asset", 0.0).clip(0.0, 1.0)
        final_criticality = (
            self.node_criticality_weight * node_criticality
            + self.asset_criticality_weight * asset_criticality
            + self.business_context_weight * business_context
        ).clip(0.0, 1.0)

        result = pd.DataFrame(
            {
                "event_id": df["event_id"].astype(str),
                "node_id": df["node_id"].astype(str),
                "asset_id": df["asset_id"].astype(str),
                "event_component": event_component.astype(float),
                "asset_component": asset_component.astype(float),
                "business_context": business_context.astype(float),
                "threat_multiplier": threat_multiplier.astype(float),
                "impact": impact.astype(float),
                "node_criticality": node_criticality.astype(float),
                "asset_criticality": asset_criticality.astype(float),
                "final_criticality": final_criticality.astype(float),
            }
        )

        return result.reset_index(drop=True)

    def _estimate_event_context_from_entities(self, event: SecurityEvent) -> float:
        meta = event.metadata or {}

        external_ip = self._extract_meta_value(meta, "external_ip", 0.0)
        after_hours_activity = self._extract_meta_value(meta, "after_hours_activity", 0.0)
        failed_logins = self._normalize_linear(
            self._extract_meta_value(meta, "failed_logins", 0.0),
            self.failed_logins_scale,
        )
        suspicious_processes = self._normalize_linear(
            self._extract_meta_value(meta, "suspicious_processes", 0.0),
            self.suspicious_processes_scale,
        )
        open_ports = self._normalize_linear(
            self._extract_meta_value(meta, "open_ports", 0.0),
            self.open_ports_scale,
        )
        large_transfer = self._normalize_linear(
            self._extract_meta_value(meta, "large_transfer_mb", 0.0),
            self.large_transfer_scale,
        )

        value = (
            0.20 * external_ip
            + 0.18 * after_hours_activity
            + 0.18 * failed_logins
            + 0.16 * suspicious_processes
            + 0.12 * open_ports
            + 0.16 * large_transfer
        )

        return float(self._clip_01(value))

    def _estimate_event_context_from_frame(self, df: pd.DataFrame) -> pd.Series:
        external_ip = self._series(df, "event_meta_external_ip", 0.0).clip(0.0, 1.0)
        after_hours_activity = self._series(df, "event_meta_after_hours_activity", 0.0).clip(0.0, 1.0)
        failed_logins = self._normalize_linear_series(self._series(df, "event_meta_failed_logins", 0.0), self.failed_logins_scale)
        suspicious_processes = self._normalize_linear_series(
            self._series(df, "event_meta_suspicious_processes", 0.0),
            self.suspicious_processes_scale,
        )
        open_ports = self._normalize_linear_series(self._series(df, "event_meta_open_ports", 0.0), self.open_ports_scale)
        large_transfer = self._normalize_linear_series(
            self._series(df, "event_meta_large_transfer_mb", 0.0),
            self.large_transfer_scale,
        )

        value = (
            0.20 * external_ip
            + 0.18 * after_hours_activity
            + 0.18 * failed_logins
            + 0.16 * suspicious_processes
            + 0.12 * open_ports
            + 0.16 * large_transfer
        )

        return value.clip(0.0, 1.0)

    def _validate_weights(self) -> None:
        if not np.isclose(self.event_component_weight + self.asset_component_weight, 1.0):
            raise ValueError("Сумма весов event_component_weight и asset_component_weight должна быть равна 1.0.")

        event_sum = (
            self.severity_weight
            + self.frequency_weight
            + self.anomaly_weight
            + self.vulnerability_weight
            + self.privilege_weight
            + self.exposure_weight
            + self.event_context_weight
        )
        if not np.isclose(event_sum, 1.0):
            raise ValueError("Сумма весов компонент события должна быть равна 1.0.")

        asset_sum = (
            self.cost_weight
            + self.data_sensitivity_weight
            + self.regulatory_weight
            + self.client_exposure_weight
            + self.business_criticality_weight
            + self.tier_weight
        )
        if not np.isclose(asset_sum, 1.0):
            raise ValueError("Сумма весов компонент актива должна быть равна 1.0.")

        criticality_sum = (
            self.node_criticality_weight
            + self.asset_criticality_weight
            + self.business_context_weight
        )
        if not np.isclose(criticality_sum, 1.0):
            raise ValueError("Сумма весов критичности должна быть равна 1.0.")

    @staticmethod
    def _default_threat_multipliers() -> Dict[str, float]:
        return {
            ThreatType.MALWARE.value: 1.05,
            ThreatType.PHISHING.value: 1.00,
            ThreatType.PRIVILEGE_ESCALATION.value: 1.12,
            ThreatType.DATA_LEAK.value: 1.20,
            ThreatType.DDOS.value: 1.08,
            ThreatType.UNAUTHORIZED_ACCESS.value: 1.10,
            ThreatType.MISCONFIGURATION.value: 0.92,
            ThreatType.INSIDER.value: 1.18,
            ThreatType.OTHER.value: 1.00,
        }

    @staticmethod
    def _extract_meta_value(metadata: Mapping[str, object], key: str, default: float = 0.0) -> float:
        if key not in metadata:
            return default

        value = metadata.get(key, default)

        if isinstance(value, bool):
            return float(int(value))

        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _clip_01(value: float) -> float:
        return float(np.clip(value, 0.0, 1.0))

    def _normalize_log(self, value: float, scale: float) -> float:
        value = max(float(value), 0.0)
        return float(np.clip(np.log1p(value) / np.log1p(scale), 0.0, 1.0))

    def _normalize_log_series(self, values: pd.Series, scale: float) -> pd.Series:
        series = pd.to_numeric(values, errors="coerce").fillna(0.0).clip(lower=0.0)
        normalized = np.log1p(series) / np.log1p(scale)
        return normalized.clip(lower=0.0, upper=1.0)

    @staticmethod
    def _normalize_linear(value: float, scale: float) -> float:
        if scale <= 0:
            return 0.0
        return float(np.clip(float(value) / float(scale), 0.0, 1.0))

    @staticmethod
    def _normalize_linear_series(values: pd.Series, scale: float) -> pd.Series:
        if scale <= 0:
            return pd.Series(np.zeros(len(values)), index=values.index, dtype=float)
        series = pd.to_numeric(values, errors="coerce").fillna(0.0)
        return (series / float(scale)).clip(lower=0.0, upper=1.0)

    @staticmethod
    def _normalize_privilege(value: int | float) -> float:
        value = min(max(float(value), 0.0), 10.0)
        return float(value / 10.0)

    @staticmethod
    def _normalize_privilege_series(values: pd.Series) -> pd.Series:
        series = pd.to_numeric(values, errors="coerce").fillna(0.0).clip(lower=0.0, upper=10.0)
        return (series / 10.0).clip(lower=0.0, upper=1.0)

    @staticmethod
    def _series(frame: pd.DataFrame, column: str, default: float = 0.0) -> pd.Series:
        if column not in frame.columns:
            return pd.Series(np.full(len(frame), default, dtype=float), index=frame.index)

        series = frame[column]

        if pd.api.types.is_bool_dtype(series):
            return series.astype(int).astype(float)

        return pd.to_numeric(series, errors="coerce").fillna(default).astype(float)