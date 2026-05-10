from __future__ import annotations

import hashlib
from typing import List

from .schemas import (
    RiskAssessmentRecord,
    RiskClass,
    RiskEventRecord,
)


class RiskEventAssessmentEngine:
    def __init__(
        self,
        low_threshold: float = 0.20,
        medium_threshold: float = 0.50,
        high_threshold: float = 0.80,
    ) -> None:
        self.low_threshold = low_threshold
        self.medium_threshold = medium_threshold
        self.high_threshold = high_threshold
        self._validate_thresholds()

    def assess_many(self, risk_events: List[RiskEventRecord]) -> List[RiskAssessmentRecord]:
        return [self.assess_one(risk_event) for risk_event in risk_events]

    def assess_one(self, risk_event: RiskEventRecord) -> RiskAssessmentRecord:
        probability = self._clip_01(risk_event.probability_estimate)
        impact = self._clip_01(risk_event.impact_estimate)

        initial_risk = self.compute_initial_risk(
            probability_estimate=probability,
            impact_estimate=impact,
        )

        final_risk = initial_risk
        risk_class = self.assign_risk_class(final_risk)

        return RiskAssessmentRecord(
            assessment_id=self._make_assessment_id(risk_event),
            risk_event_id=risk_event.risk_event_id,
            incident_id=risk_event.incident_id,
            node_id=risk_event.node_id,
            asset_id=risk_event.asset_id,
            threat_scenario=risk_event.threat_scenario,
            probability_estimate=probability,
            impact_estimate=impact,
            initial_risk_estimate=initial_risk,
            graph_adjusted_risk_estimate=None,
            final_risk_estimate=final_risk,
            risk_class=risk_class,
            priority=self._priority_from_class(risk_class),
            explanation=[
                "Расчетная оценка риска выполнена по событиям риска реализации информационных угроз.",
                "Использована формула r_ij^0 = p_ij^* · I_ij.",
                "Значимость актива учитывается в оценке последствий I_ij, а не применяется как отдельный множитель.",
                *risk_event.rationale,
            ],
            metadata={
                **risk_event.metadata,
                "event_type": risk_event.event_type.value,
                "threat_scenario": risk_event.threat_scenario.value,
                "has_actual_loss": risk_event.has_actual_loss,
                "estimated_loss": risk_event.estimated_loss,
                "potential_loss": risk_event.potential_loss,
                "registration_threshold_reached": risk_event.registration_threshold_reached,
                "normative_stage": "risk_event_assessment",
            },
        )

    def compute_initial_risk(
        self,
        probability_estimate: float,
        impact_estimate: float,
    ) -> float:
        probability = self._clip_01(probability_estimate)
        impact = self._clip_01(impact_estimate)
        return self._clip_01(probability * impact)

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

    def _make_assessment_id(self, risk_event: RiskEventRecord) -> str:
        raw = (
            f"{risk_event.risk_event_id}|"
            f"{risk_event.incident_id}|"
            f"{risk_event.node_id}|"
            f"{risk_event.asset_id}|"
            f"{risk_event.threat_scenario.value}"
        )
        digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
        return f"risk_assess_{digest}"

    def _validate_thresholds(self) -> None:
        if not (0.0 < self.low_threshold < self.medium_threshold < self.high_threshold <= 1.0):
            raise ValueError(
                "Пороги классов риска должны удовлетворять условию: "
                "0 < low < medium < high <= 1."
            )

    def _clip_01(self, value: float) -> float:
        return max(0.0, min(1.0, float(value)))