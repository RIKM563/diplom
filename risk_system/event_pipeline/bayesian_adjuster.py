from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Mapping, Sequence

from risk_system.config import settings

from .schemas import RiskEventRecord


@dataclass(frozen=True)
class RiskEventDependency:
    parent: str
    weight: float
    dependency_type: str = "direct"


class BayesianRiskEventAdjuster:
    def __init__(
        self,
        dependencies: Mapping[str, Sequence[dict | tuple | RiskEventDependency]] | None = None,
        group_key: str | None = None,
        min_probability: float | None = None,
        max_probability: float | None = None,
    ) -> None:
        self.group_key = group_key or settings.bayesian.group_key
        self.min_probability = self._clip_01(
            settings.bayesian.min_probability if min_probability is None else min_probability
        )
        self.max_probability = self._clip_01(
            settings.bayesian.max_probability if max_probability is None else max_probability
        )
        self.dependencies: Dict[str, List[RiskEventDependency]] = {}
        self.set_dependencies(dependencies or settings.bayesian.dependencies)

    def set_dependencies(
        self,
        dependencies: Mapping[str, Sequence[dict | tuple | RiskEventDependency]],
    ) -> None:
        self.dependencies = {
            str(target): [self._normalize_dependency(item) for item in parents]
            for target, parents in dependencies.items()
        }

    def adjust_many(self, risk_events: List[RiskEventRecord]) -> List[RiskEventRecord]:
        if not risk_events:
            return []

        grouped_events: Dict[str, List[RiskEventRecord]] = {}
        for event in risk_events:
            grouped_events.setdefault(self._group_value(event), []).append(event)

        adjusted_events: List[RiskEventRecord] = []
        for group_events in grouped_events.values():
            adjusted_events.extend(self._adjust_group(group_events))

        return adjusted_events

    def _adjust_group(self, risk_events: List[RiskEventRecord]) -> List[RiskEventRecord]:
        scenario_probabilities = self._scenario_probability_map(risk_events)
        adjusted_events: List[RiskEventRecord] = []

        for event in risk_events:
            base_probability = self._clip(event.probability_estimate)
            adjusted_probability, evidence = self._adjust_probability(
                scenario=event.threat_scenario.value,
                base_probability=base_probability,
                scenario_probabilities=scenario_probabilities,
            )

            adjusted_events.append(
                self._copy_event(
                    event=event,
                    probability=max(base_probability, adjusted_probability),
                    evidence=evidence,
                    adjusted=adjusted_probability > base_probability,
                )
            )

        return adjusted_events

    def _adjust_probability(
        self,
        scenario: str,
        base_probability: float,
        scenario_probabilities: Dict[str, float],
    ) -> tuple[float, List[str]]:
        probability = self._clip(base_probability)
        evidence: List[str] = []

        for dependency in self.dependencies.get(scenario, []):
            parent_probability = self._clip(scenario_probabilities.get(dependency.parent, 0.0))
            if parent_probability <= 0.0:
                continue

            weight = self._dependency_weight(dependency)
            previous_probability = probability
            probability = probability + parent_probability * weight * (1.0 - probability)
            probability = self._clip(probability)

            if probability > previous_probability:
                evidence.append(
                    "Bayesian adjustment: "
                    f"{dependency.parent} -> {scenario}, "
                    f"parent_probability={parent_probability:.4f}, "
                    f"weight={weight:.4f}, "
                    f"probability={previous_probability:.4f}->{probability:.4f}."
                )

        return probability, evidence

    def _copy_event(
        self,
        event: RiskEventRecord,
        probability: float,
        evidence: List[str],
        adjusted: bool,
    ) -> RiskEventRecord:
        metadata = {
            **event.metadata,
            "bayesian_adjusted": adjusted,
            "probability_before_bayesian": event.probability_estimate,
            "probability_after_bayesian": probability,
            "bayesian_group_key": self.group_key,
            "bayesian_evidence": evidence,
        }

        rationale = list(event.rationale)
        if adjusted:
            rationale.extend(
                [
                    (
                        "Вероятностная составляющая уточнена байесовским модулем "
                        "с учетом зависимостей между сценариями реализации информационных угроз."
                    ),
                    *evidence,
                ]
            )

        return event.model_copy(
            update={
                "probability_estimate": probability,
                "classifier_confidence": probability,
                "rationale": rationale,
                "metadata": metadata,
            },
            deep=True,
        )

    def _scenario_probability_map(self, risk_events: List[RiskEventRecord]) -> Dict[str, float]:
        result: Dict[str, float] = {}

        for event in risk_events:
            scenario = event.threat_scenario.value
            probability = self._clip(event.probability_estimate)
            result[scenario] = max(result.get(scenario, 0.0), probability)

        return result

    def _group_value(self, event: RiskEventRecord) -> str:
        if self.group_key == "asset_id":
            return event.asset_id or "unknown_asset"
        if self.group_key == "affected_process":
            return event.affected_process or "unknown_process"
        return event.node_id or "unknown_node"

    def _normalize_dependency(
        self,
        item: dict | tuple | RiskEventDependency,
    ) -> RiskEventDependency:
        if isinstance(item, RiskEventDependency):
            return RiskEventDependency(
                parent=str(item.parent),
                weight=self._clip_01(item.weight),
                dependency_type=str(item.dependency_type),
            )

        if isinstance(item, dict):
            return RiskEventDependency(
                parent=str(item["parent"]),
                weight=self._clip_01(float(item["weight"])),
                dependency_type=str(item.get("dependency_type", "direct")),
            )

        parent, weight = item
        return RiskEventDependency(
            parent=str(parent),
            weight=self._clip_01(float(weight)),
            dependency_type="direct",
        )

    def _dependency_weight(self, dependency: RiskEventDependency) -> float:
        type_factor = {
            "direct": 1.00,
            "prerequisite": 0.90,
            "escalation": 1.10,
            "supporting": 0.75,
        }.get(dependency.dependency_type.lower(), 1.00)

        return self._clip_01(dependency.weight * type_factor)

    def _clip(self, value: float) -> float:
        return min(self.max_probability, max(self.min_probability, float(value)))

    @staticmethod
    def _clip_01(value: float) -> float:
        return min(1.0, max(0.0, float(value)))
