from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from .schemas import InfrastructureLink, RiskAssessmentRecord, RiskClass


class GraphRiskAdjustmentEngine:
    def __init__(
        self,
        low_threshold: float = 0.20,
        medium_threshold: float = 0.50,
        high_threshold: float = 0.80,
        max_inherited_risk: float = 0.35,
    ) -> None:
        self.low_threshold = low_threshold
        self.medium_threshold = medium_threshold
        self.high_threshold = high_threshold
        self.max_inherited_risk = max_inherited_risk
        self._validate_thresholds()

    def adjust_many(
        self,
        assessments: List[RiskAssessmentRecord],
        infrastructure_links: List[InfrastructureLink],
    ) -> List[RiskAssessmentRecord]:
        if not assessments:
            return []

        local_risk_by_node = self._build_local_risk_by_node(assessments)
        incoming_links_by_target = self._group_links_by_target(infrastructure_links)

        adjusted_assessments: List[RiskAssessmentRecord] = []

        for assessment in assessments:
            adjusted_assessments.append(
                self.adjust_one(
                    assessment=assessment,
                    local_risk_by_node=local_risk_by_node,
                    incoming_links=incoming_links_by_target.get(assessment.node_id or "", []),
                )
            )

        return adjusted_assessments

    def adjust_one(
        self,
        assessment: RiskAssessmentRecord,
        local_risk_by_node: Dict[str, float],
        incoming_links: List[InfrastructureLink],
    ) -> RiskAssessmentRecord:
        local_risk = assessment.initial_risk_estimate

        if not assessment.node_id or not incoming_links:
            return self._copy_with_graph_values(
                assessment=assessment,
                graph_adjusted_risk=local_risk,
                final_risk=local_risk,
                inherited_risk=0.0,
                incoming_links_count=0,
                explanation=[
                    "Графовое уточнение не изменило оценку: для объекта не переданы входящие инфраструктурные связи.",
                ],
            )

        inherited_risk = 0.0
        used_links = 0

        for link in incoming_links:
            source_risk = local_risk_by_node.get(link.source_node_id, 0.0)

            if source_risk <= 0:
                continue

            inherited_risk += source_risk * link.influence_weight
            used_links += 1

        inherited_risk = min(inherited_risk, self.max_inherited_risk)

        graph_adjusted_risk = self._clip_01(
            local_risk + inherited_risk * (1.0 - local_risk)
        )

        final_risk = graph_adjusted_risk

        explanation = [
            "Выполнено графовое уточнение расчетной оценки риска с учетом инфраструктурных связей между объектами защиты.",
            f"Локальная расчетная оценка риска: {local_risk:.4f}.",
            f"Учитываемое влияние связанных объектов: {inherited_risk:.4f}.",
            f"Оценка после графового уточнения: {graph_adjusted_risk:.4f}.",
        ]

        return self._copy_with_graph_values(
            assessment=assessment,
            graph_adjusted_risk=graph_adjusted_risk,
            final_risk=final_risk,
            inherited_risk=inherited_risk,
            incoming_links_count=used_links,
            explanation=explanation,
        )

    def _copy_with_graph_values(
        self,
        assessment: RiskAssessmentRecord,
        graph_adjusted_risk: float,
        final_risk: float,
        inherited_risk: float,
        incoming_links_count: int,
        explanation: List[str],
    ) -> RiskAssessmentRecord:
        risk_class = self.assign_risk_class(final_risk)

        metadata = {
            **assessment.metadata,
            "graph_adjustment_applied": incoming_links_count > 0,
            "incoming_links_count": incoming_links_count,
            "inherited_risk_component": inherited_risk,
            "normative_stage": "graph_adjusted_risk_assessment",
        }

        return assessment.model_copy(
            update={
                "graph_adjusted_risk_estimate": graph_adjusted_risk,
                "final_risk_estimate": final_risk,
                "risk_class": risk_class,
                "priority": self._priority_from_class(risk_class),
                "explanation": [
                    *assessment.explanation,
                    *explanation,
                ],
                "metadata": metadata,
            }
        )

    def _build_local_risk_by_node(
        self,
        assessments: List[RiskAssessmentRecord],
    ) -> Dict[str, float]:
        local_risk_by_node: Dict[str, float] = defaultdict(float)

        for assessment in assessments:
            if not assessment.node_id:
                continue

            local_risk_by_node[assessment.node_id] = max(
                local_risk_by_node[assessment.node_id],
                assessment.initial_risk_estimate,
            )

        return dict(local_risk_by_node)

    def _group_links_by_target(
        self,
        infrastructure_links: List[InfrastructureLink],
    ) -> Dict[str, List[InfrastructureLink]]:
        result: Dict[str, List[InfrastructureLink]] = defaultdict(list)

        for link in infrastructure_links:
            result[link.target_node_id].append(link)

        return dict(result)

    def assign_risk_class(self, risk_value: float) -> RiskClass:
        value = self._clip_01(risk_value)

        if value < self.low_threshold:
            return RiskClass.LOW

        if value < self.medium_threshold:
            return RiskClass.MEDIUM

        if value < self.high_threshold:
            return RiskClass.HIGH

        return RiskClass.CRITICAL

    def _priority_from_class(self, risk_class: RiskClass) -> int:
        if risk_class == RiskClass.CRITICAL:
            return 1

        if risk_class == RiskClass.HIGH:
            return 2

        if risk_class == RiskClass.MEDIUM:
            return 3

        return 4

    def _validate_thresholds(self) -> None:
        if not (0.0 < self.low_threshold < self.medium_threshold < self.high_threshold <= 1.0):
            raise ValueError(
                "Пороги классов риска должны удовлетворять условию: "
                "0 < low < medium < high <= 1."
            )

        if not (0.0 <= self.max_inherited_risk <= 1.0):
            raise ValueError("max_inherited_risk должен находиться в диапазоне [0; 1].")

    def _clip_01(self, value: float) -> float:
        return max(0.0, min(1.0, float(value)))