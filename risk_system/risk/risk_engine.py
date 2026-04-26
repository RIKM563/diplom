from __future__ import annotations

from typing import Dict, Iterable, List, Optional

import numpy as np
import pandas as pd

from risk_system.domain import (
    AssetRiskResult,
    ExplanationItem,
    NodeRiskResult,
    RiskAssessmentResponse,
    RiskClass,
    RiskScore,
    ThreatType,
)


class RiskEngine:
    def __init__(
        self,
        low_threshold: float = 0.20,
        medium_threshold: float = 0.50,
        high_threshold: float = 0.80,
        propagation_blend: float = 0.50,
    ) -> None:
        self.low_threshold = low_threshold
        self.medium_threshold = medium_threshold
        self.high_threshold = high_threshold
        self.propagation_blend = propagation_blend

        self._validate_thresholds()

    def compute_base_risk(
        self,
        probability: float,
        impact: float,
        criticality: float,
    ) -> float:
        probability = self._clip_01(probability)
        impact = self._clip_01(impact)
        criticality = max(float(criticality), 0.0)

        base_risk = probability * impact * criticality
        return float(max(base_risk, 0.0))

    def assign_risk_class(self, score: float) -> RiskClass:
        score = max(float(score), 0.0)

        if score < self.low_threshold:
            return RiskClass.LOW
        if score < self.medium_threshold:
            return RiskClass.MEDIUM
        if score < self.high_threshold:
            return RiskClass.HIGH
        return RiskClass.CRITICAL

    def build_event_risk_table(
        self,
        probabilities: pd.DataFrame,
        impact_table: pd.DataFrame,
    ) -> pd.DataFrame:
        required_prob_columns = {
            "event_id",
            "node_id",
            "asset_id",
            "threat_type",
        }
        required_impact_columns = {
            "event_id",
            "node_id",
            "asset_id",
            "impact",
            "final_criticality",
        }

        self._check_columns(probabilities, required_prob_columns, "probabilities")
        self._check_columns(impact_table, required_impact_columns, "impact_table")

        probability_column = self._resolve_probability_column(probabilities)

        merged = probabilities.merge(
            impact_table,
            on=["event_id", "node_id", "asset_id"],
            how="inner",
        )

        if merged.empty:
            raise ValueError("После объединения таблиц probabilities и impact_table не осталось строк.")

        merged["probability"] = merged[probability_column].astype(float).clip(0.0, 1.0)
        merged["impact"] = merged["impact"].astype(float).clip(lower=0.0, upper=1.0)
        merged["criticality"] = merged["final_criticality"].astype(float).clip(lower=0.0)

        merged["base_risk"] = merged.apply(
            lambda row: self.compute_base_risk(
                probability=row["probability"],
                impact=row["impact"],
                criticality=row["criticality"],
            ),
            axis=1,
        )

        merged["propagated_risk"] = np.nan
        merged["final_risk"] = merged["base_risk"]
        merged["risk_class"] = merged["final_risk"].apply(lambda x: self.assign_risk_class(x).value)

        columns = [
            "event_id",
            "node_id",
            "asset_id",
            "threat_type",
            "probability",
            "impact",
            "criticality",
            "base_risk",
            "propagated_risk",
            "final_risk",
            "risk_class",
        ]
        return merged[columns].reset_index(drop=True)

    def apply_propagated_node_risks(
        self,
        event_risk_table: pd.DataFrame,
        propagated_node_risks: pd.DataFrame,
    ) -> pd.DataFrame:
        required_event_columns = {
            "event_id",
            "node_id",
            "asset_id",
            "threat_type",
            "probability",
            "impact",
            "criticality",
            "base_risk",
            "final_risk",
        }
        required_node_columns = {"node_id", "propagated_risk"}

        self._check_columns(event_risk_table, required_event_columns, "event_risk_table")
        self._check_columns(propagated_node_risks, required_node_columns, "propagated_node_risks")

        result = event_risk_table.copy()
        node_map = (
            propagated_node_risks[["node_id", "propagated_risk"]]
            .drop_duplicates(subset=["node_id"])
            .set_index("node_id")["propagated_risk"]
            .to_dict()
        )

        result["propagated_risk"] = result["node_id"].map(node_map)
        result["propagated_risk"] = result["propagated_risk"].astype(float)

        result["final_risk"] = result.apply(
            lambda row: self._combine_base_and_propagated(
                base_risk=row["base_risk"],
                propagated_risk=row["propagated_risk"],
            ),
            axis=1,
        )
        result["risk_class"] = result["final_risk"].apply(lambda x: self.assign_risk_class(x).value)

        return result.reset_index(drop=True)

    def aggregate_node_risks(self, event_risk_table: pd.DataFrame) -> pd.DataFrame:
        required_columns = {"node_id", "asset_id", "final_risk"}
        self._check_columns(event_risk_table, required_columns, "event_risk_table")

        grouped = (
            event_risk_table.groupby(["node_id", "asset_id"], as_index=False)["final_risk"]
            .apply(self._aggregate_risk_values)
            .rename(columns={"final_risk": "aggregated_dummy"})
        )

        if "aggregated_dummy" not in grouped.columns:
            grouped = grouped.rename(columns={grouped.columns[-1]: "aggregated_dummy"})

        grouped["final_risk"] = grouped["aggregated_dummy"].astype(float)
        grouped = grouped.drop(columns=["aggregated_dummy"])
        grouped["risk_class"] = grouped["final_risk"].apply(lambda x: self.assign_risk_class(x).value)

        return grouped.reset_index(drop=True)

    def aggregate_asset_risks(self, node_risk_table: pd.DataFrame) -> pd.DataFrame:
        required_columns = {"asset_id", "final_risk"}
        self._check_columns(node_risk_table, required_columns, "node_risk_table")

        grouped = (
            node_risk_table.groupby(["asset_id"], as_index=False)["final_risk"]
            .apply(self._aggregate_risk_values)
            .rename(columns={"final_risk": "aggregated_dummy"})
        )

        if "aggregated_dummy" not in grouped.columns:
            grouped = grouped.rename(columns={grouped.columns[-1]: "aggregated_dummy"})

        grouped["final_risk"] = grouped["aggregated_dummy"].astype(float)
        grouped = grouped.drop(columns=["aggregated_dummy"])
        grouped["risk_class"] = grouped["final_risk"].apply(lambda x: self.assign_risk_class(x).value)

        return grouped.reset_index(drop=True)

    def build_event_scores(self, event_risk_table: pd.DataFrame) -> List[RiskScore]:
        required_columns = {
            "event_id",
            "node_id",
            "asset_id",
            "threat_type",
            "probability",
            "impact",
            "criticality",
            "base_risk",
            "final_risk",
            "risk_class",
        }
        self._check_columns(event_risk_table, required_columns, "event_risk_table")

        results: List[RiskScore] = []

        for _, row in event_risk_table.iterrows():
            propagated_value = row.get("propagated_risk")
            propagated_risk = (
                None if pd.isna(propagated_value) else float(propagated_value)
            )

            results.append(
                RiskScore(
                    event_id=str(row["event_id"]),
                    node_id=str(row["node_id"]),
                    asset_id=str(row["asset_id"]),
                    threat_type=ThreatType(str(row["threat_type"])),
                    probability=float(row["probability"]),
                    impact=float(row["impact"]),
                    criticality=float(row["criticality"]),
                    base_risk=float(row["base_risk"]),
                    propagated_risk=propagated_risk,
                    final_risk=float(row["final_risk"]),
                    risk_class=RiskClass(str(row["risk_class"])),
                )
            )

        return results

    def build_node_results(
        self,
        node_risk_table: pd.DataFrame,
        explanations: Optional[Dict[str, List[ExplanationItem]]] = None,
    ) -> List[NodeRiskResult]:
        required_columns = {"node_id", "asset_id", "final_risk", "risk_class"}
        self._check_columns(node_risk_table, required_columns, "node_risk_table")

        results: List[NodeRiskResult] = []

        for _, row in node_risk_table.iterrows():
            node_id = str(row["node_id"])
            results.append(
                NodeRiskResult(
                    node_id=node_id,
                    asset_id=str(row["asset_id"]),
                    final_risk=float(row["final_risk"]),
                    risk_class=RiskClass(str(row["risk_class"])),
                    explanations=(explanations or {}).get(node_id, []),
                )
            )

        return results

    def build_asset_results(
        self,
        asset_risk_table: pd.DataFrame,
        node_results: List[NodeRiskResult],
    ) -> List[AssetRiskResult]:
        required_columns = {"asset_id", "final_risk", "risk_class"}
        self._check_columns(asset_risk_table, required_columns, "asset_risk_table")

        node_map: Dict[str, List[NodeRiskResult]] = {}
        for node_result in node_results:
            node_map.setdefault(node_result.asset_id, []).append(node_result)

        results: List[AssetRiskResult] = []

        for _, row in asset_risk_table.iterrows():
            asset_id = str(row["asset_id"])
            results.append(
                AssetRiskResult(
                    asset_id=asset_id,
                    final_risk=float(row["final_risk"]),
                    risk_class=RiskClass(str(row["risk_class"])),
                    node_results=node_map.get(asset_id, []),
                )
            )

        return results

    def build_risk_response(
        self,
        event_risk_table: pd.DataFrame,
        explanations: Optional[Dict[str, List[ExplanationItem]]] = None,
    ) -> RiskAssessmentResponse:
        node_risk_table = self.aggregate_node_risks(event_risk_table)
        asset_risk_table = self.aggregate_asset_risks(node_risk_table)

        event_scores = self.build_event_scores(event_risk_table)
        node_results = self.build_node_results(node_risk_table, explanations=explanations)
        asset_results = self.build_asset_results(asset_risk_table, node_results)

        return RiskAssessmentResponse(
            event_risks=event_scores,
            node_risks=node_results,
            asset_risks=asset_results,
        )

    def build_explanations_from_importance(
        self,
        importance_table: pd.DataFrame,
        top_k: int = 5,
    ) -> List[ExplanationItem]:
        required_columns = {"feature_name", "importance"}
        self._check_columns(importance_table, required_columns, "importance_table")

        top = importance_table.sort_values("importance", ascending=False).head(top_k)

        explanations: List[ExplanationItem] = []
        for _, row in top.iterrows():
            explanations.append(
                ExplanationItem(
                    feature_name=str(row["feature_name"]),
                    contribution=float(row["importance"]),
                    direction="positive",
                )
            )
        return explanations

    def _combine_base_and_propagated(
        self,
        base_risk: float,
        propagated_risk: float | None,
    ) -> float:
        base = max(float(base_risk), 0.0)

        if propagated_risk is None or pd.isna(propagated_risk):
            return base

        propagated = max(float(propagated_risk), 0.0)
        combined = (1.0 - self.propagation_blend) * base + self.propagation_blend * propagated

        return float(max(base, combined))

    @staticmethod
    def _aggregate_risk_values(values: Iterable[float]) -> float:
        array = np.asarray(list(values), dtype=float)
        if array.size == 0:
            return 0.0

        clipped = np.clip(array, 0.0, 1.0)
        aggregated = 1.0 - np.prod(1.0 - clipped)
        return float(np.clip(aggregated, 0.0, 1.0))

    @staticmethod
    def _clip_01(value: float) -> float:
        return float(np.clip(value, 0.0, 1.0))

    @staticmethod
    def _check_columns(frame: pd.DataFrame, required: set[str], frame_name: str) -> None:
        missing = required - set(frame.columns)
        if missing:
            raise ValueError(
                f"В таблице '{frame_name}' отсутствуют обязательные колонки: {sorted(missing)}"
            )

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

    def _validate_thresholds(self) -> None:
        thresholds = [self.low_threshold, self.medium_threshold, self.high_threshold]
        if any(value <= 0 for value in thresholds):
            raise ValueError("Пороги классов риска должны быть положительными.")
        if not (self.low_threshold < self.medium_threshold < self.high_threshold):
            raise ValueError(
                "Пороги классов риска должны удовлетворять условию: "
                "low < medium < high."
            )
        if not (0.0 <= self.propagation_blend <= 1.0):
            raise ValueError("Параметр propagation_blend должен лежать в диапазоне [0, 1].")