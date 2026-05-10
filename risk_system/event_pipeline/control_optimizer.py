from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence, Set

from .schemas import (
    ControlMeasureCandidate,
    ControlMeasureType,
    ControlOptimizationConstraints,
    ControlOptimizationResult,
    RecommendedControlMeasure,
    RiskAssessmentRecord,
    RiskClass,
    RiskEventType,
    ThreatScenario,
)


@dataclass
class _MeasureCandidate:
    measure: ControlMeasureCandidate
    expected_risk_reduction: float
    covered_assessment_ids: List[str]
    covered_risk_event_ids: List[str]
    covered_node_ids: List[str]
    rationale: List[str]

    @property
    def efficiency_score(self) -> float:
        denominator = (
            self.measure.cost
            + self.measure.labor * 1_000.0
        )

        if denominator <= 0:
            return self.expected_risk_reduction

        return self.expected_risk_reduction / denominator


@dataclass
class _SearchState:
    selected_indices: List[int]
    selected_measure_ids: Set[str]
    total_risk_reduction: float
    total_cost: float
    total_labor: float


class EventRiskControlOptimizer:
    def optimize(
        self,
        assessments: List[RiskAssessmentRecord],
        measures: List[ControlMeasureCandidate] | None = None,
        constraints: ControlOptimizationConstraints | None = None,
    ) -> ControlOptimizationResult:
        constraints = constraints or ControlOptimizationConstraints()

        if not assessments:
            return ControlOptimizationResult(
                constraints=constraints,
                explanation=[
                    "Подбор мер защиты не выполнен: отсутствуют расчетные оценки риска."
                ],
            )

        measures = measures or self.default_measures()

        total_initial_risk = sum(item.final_risk_estimate for item in assessments)

        candidates = self._build_candidates(
            assessments=assessments,
            measures=measures,
            constraints=constraints,
        )

        if not candidates:
            return ControlOptimizationResult(
                total_initial_risk=total_initial_risk,
                expected_total_residual_risk=total_initial_risk,
                constraints=constraints,
                explanation=[
                    "Не найдено применимых мер защиты с положительным ожидаемым эффектом.",
                    "Проверьте перечень мер, применимость к сценариям угроз и ограничения по ресурсам.",
                ],
            )

        selected = self._solve_branch_and_bound(
            candidates=candidates,
            constraints=constraints,
        )

        selected_measures = [
            self._to_recommended_measure(candidate, total_initial_risk)
            for candidate in selected
        ]

        total_reduction = sum(item.expected_risk_reduction for item in selected)
        total_cost = sum(item.measure.cost for item in selected)
        total_labor = sum(item.measure.labor for item in selected)
        total_time = sum(item.measure.implementation_time for item in selected)

        return ControlOptimizationResult(
            selected_measures=selected_measures,
            total_initial_risk=total_initial_risk,
            expected_total_risk_reduction=total_reduction,
            expected_total_residual_risk=max(0.0, total_initial_risk - total_reduction),
            total_cost=total_cost,
            total_labor=total_labor,
            total_implementation_time=total_time,
            constraints=constraints,
            explanation=[
                "Подбор мер защиты выполнен после расчета и графового уточнения риска.",
                "Цель подбора — максимизировать ожидаемое снижение расчетной оценки риска при ограничениях на бюджет, трудоемкость и количество мер.",
                "Ожидаемый эффект меры рассчитывается для связанных событий риска реализации информационных угроз и не использует критичность объекта как отдельный множитель риска.",
            ],
        )

    def _build_candidates(
        self,
        assessments: List[RiskAssessmentRecord],
        measures: List[ControlMeasureCandidate],
        constraints: ControlOptimizationConstraints,
    ) -> List[_MeasureCandidate]:
        candidates: List[_MeasureCandidate] = []

        for measure in measures:
            if not self._measure_can_fit_constraints(measure, constraints):
                continue

            reduction = 0.0
            covered_assessment_ids: List[str] = []
            covered_risk_event_ids: List[str] = []
            covered_node_ids: List[str] = []
            rationale: List[str] = []

            for assessment in assessments:
                applicability = self._measure_applicability(measure, assessment)

                if applicability <= 0:
                    continue

                effectiveness = self._measure_effectiveness(measure, assessment)
                effective_reduction = assessment.final_risk_estimate * effectiveness * applicability

                if effective_reduction <= 0:
                    continue

                reduction += effective_reduction
                covered_assessment_ids.append(assessment.assessment_id)
                covered_risk_event_ids.append(assessment.risk_event_id)

                if assessment.node_id and assessment.node_id not in covered_node_ids:
                    covered_node_ids.append(assessment.node_id)

                rationale.append(
                    f"Мера применима к событию риска {assessment.risk_event_id}: "
                    f"сценарий {assessment.threat_scenario.value}, "
                    f"ожидаемая эффективность {effectiveness:.2f}."
                )

            if reduction < constraints.min_effectiveness:
                continue

            candidates.append(
                _MeasureCandidate(
                    measure=measure,
                    expected_risk_reduction=reduction,
                    covered_assessment_ids=covered_assessment_ids,
                    covered_risk_event_ids=covered_risk_event_ids,
                    covered_node_ids=covered_node_ids,
                    rationale=rationale,
                )
            )

        return sorted(candidates, key=lambda item: item.efficiency_score, reverse=True)

    def _solve_branch_and_bound(
        self,
        candidates: Sequence[_MeasureCandidate],
        constraints: ControlOptimizationConstraints,
    ) -> List[_MeasureCandidate]:
        best = _SearchState(
            selected_indices=[],
            selected_measure_ids=set(),
            total_risk_reduction=0.0,
            total_cost=0.0,
            total_labor=0.0,
        )

        initial = _SearchState(
            selected_indices=[],
            selected_measure_ids=set(),
            total_risk_reduction=0.0,
            total_cost=0.0,
            total_labor=0.0,
        )

        suffix_bound = self._build_suffix_bound(candidates)

        def search(index: int, state: _SearchState) -> None:
            nonlocal best

            if state.total_risk_reduction > best.total_risk_reduction:
                best = state

            if index >= len(candidates):
                return

            optimistic = state.total_risk_reduction + suffix_bound[index]
            if optimistic <= best.total_risk_reduction:
                return

            candidate = candidates[index]

            if self._can_add(candidate, state, constraints):
                next_state = _SearchState(
                    selected_indices=[*state.selected_indices, index],
                    selected_measure_ids={
                        *state.selected_measure_ids,
                        candidate.measure.measure_id,
                    },
                    total_risk_reduction=state.total_risk_reduction
                    + candidate.expected_risk_reduction,
                    total_cost=state.total_cost + candidate.measure.cost,
                    total_labor=state.total_labor + candidate.measure.labor,
                )
                search(index + 1, next_state)

            search(index + 1, state)

        search(0, initial)

        return [candidates[index] for index in best.selected_indices]

    def _build_suffix_bound(self, candidates: Sequence[_MeasureCandidate]) -> List[float]:
        result = [0.0 for _ in range(len(candidates) + 1)]

        for index in range(len(candidates) - 1, -1, -1):
            result[index] = result[index + 1] + candidates[index].expected_risk_reduction

        return result

    def _can_add(
        self,
        candidate: _MeasureCandidate,
        state: _SearchState,
        constraints: ControlOptimizationConstraints,
    ) -> bool:
        measure = candidate.measure

        if len(state.selected_indices) + 1 > constraints.max_measures:
            return False

        if state.total_cost + measure.cost > constraints.max_budget:
            return False

        if state.total_labor + measure.labor > constraints.max_labor:
            return False

        if any(item in state.selected_measure_ids for item in measure.incompatible_with):
            return False

        if any(required not in state.selected_measure_ids for required in measure.requires):
            return False

        return True

    def _measure_can_fit_constraints(
        self,
        measure: ControlMeasureCandidate,
        constraints: ControlOptimizationConstraints,
    ) -> bool:
        if measure.cost > constraints.max_budget:
            return False

        if measure.labor > constraints.max_labor:
            return False

        return True

    def _measure_applicability(
        self,
        measure: ControlMeasureCandidate,
        assessment: RiskAssessmentRecord,
    ) -> float:
        metadata = assessment.metadata or {}

        event_type = str(metadata.get("event_type", ""))
        threat_scenario = assessment.threat_scenario.value
        node_type = str(metadata.get("node_type", "unknown"))
        asset_type = str(metadata.get("asset_type", "unknown"))
        affected_process = str(metadata.get("affected_process", assessment.metadata.get("affected_process", "unknown")))

        if measure.applicable_threat_scenarios:
            allowed = [item.value for item in measure.applicable_threat_scenarios]
            if threat_scenario not in allowed:
                return 0.0

        if measure.applicable_event_types:
            allowed = [item.value for item in measure.applicable_event_types]
            if event_type not in allowed:
                return 0.0

        if measure.applicable_node_types and node_type not in measure.applicable_node_types:
            return 0.0

        if measure.applicable_asset_types and asset_type not in measure.applicable_asset_types:
            return 0.0

        if measure.applicable_processes and affected_process not in measure.applicable_processes:
            return 0.0

        multiplier = 1.0

        if assessment.risk_class == RiskClass.CRITICAL:
            multiplier += 0.20
        elif assessment.risk_class == RiskClass.HIGH:
            multiplier += 0.10

        if bool(metadata.get("has_critical_asset", False)):
            multiplier += 0.10

        return min(multiplier, 1.30)

    def _measure_effectiveness(
        self,
        measure: ControlMeasureCandidate,
        assessment: RiskAssessmentRecord,
    ) -> float:
        metadata = assessment.metadata or {}

        threat_scenario = assessment.threat_scenario.value
        event_type = str(metadata.get("event_type", ""))

        if threat_scenario in measure.effectiveness_by_threat_scenario:
            return self._clip_01(measure.effectiveness_by_threat_scenario[threat_scenario])

        if event_type in measure.effectiveness_by_event_type:
            return self._clip_01(measure.effectiveness_by_event_type[event_type])

        return self._clip_01(measure.default_effectiveness)

    def _to_recommended_measure(
        self,
        candidate: _MeasureCandidate,
        total_initial_risk: float,
    ) -> RecommendedControlMeasure:
        return RecommendedControlMeasure(
            measure_id=candidate.measure.measure_id,
            name=candidate.measure.name,
            measure_type=candidate.measure.measure_type,
            description=candidate.measure.description,
            cost=candidate.measure.cost,
            labor=candidate.measure.labor,
            implementation_time=candidate.measure.implementation_time,
            expected_risk_reduction=candidate.expected_risk_reduction,
            expected_residual_risk=max(0.0, total_initial_risk - candidate.expected_risk_reduction),
            covered_risk_event_ids=candidate.covered_risk_event_ids,
            covered_assessment_ids=candidate.covered_assessment_ids,
            covered_node_ids=candidate.covered_node_ids,
            rationale=candidate.rationale,
            metadata={
                **candidate.measure.metadata,
                "efficiency_score": candidate.efficiency_score,
                "covered_events_count": len(candidate.covered_risk_event_ids),
            },
        )

    def default_measures(self) -> List[ControlMeasureCandidate]:
        return [
            ControlMeasureCandidate(
                measure_id="CTRL-EDR-HARDENING",
                name="Усиление контроля работоспособности EDR",
                measure_type=ControlMeasureType.TECHNICAL,
                description="Настройка контроля отключения EDR, автоматического восстановления агента и уведомлений SOC.",
                cost=180_000,
                labor=32,
                implementation_time=7,
                default_effectiveness=0.18,
                effectiveness_by_threat_scenario={
                    ThreatScenario.MALWARE.value: 0.32,
                    ThreatScenario.MISCONFIGURATION.value: 0.22,
                },
                applicable_threat_scenarios=[
                    ThreatScenario.MALWARE,
                    ThreatScenario.MISCONFIGURATION,
                ],
                applicable_node_types=[
                    "application_server",
                    "database_server",
                    "workstation",
                    "server",
                ],
            ),
            ControlMeasureCandidate(
                measure_id="CTRL-PATCH-CONTROL",
                name="Регламент контроля защитных обновлений",
                measure_type=ControlMeasureType.PROCESS,
                description="Автоматизация контроля установки критических обновлений и эскалация ошибок обновления.",
                cost=120_000,
                labor=28,
                implementation_time=10,
                default_effectiveness=0.20,
                effectiveness_by_threat_scenario={
                    ThreatScenario.MISCONFIGURATION.value: 0.30,
                },
                applicable_threat_scenarios=[
                    ThreatScenario.MISCONFIGURATION,
                ],
            ),
            ControlMeasureCandidate(
                measure_id="CTRL-MFA-ADMIN",
                name="Усиление многофакторной аутентификации для привилегированного доступа",
                measure_type=ControlMeasureType.TECHNICAL,
                description="Включение MFA и дополнительных правил контроля для административных учетных записей.",
                cost=300_000,
                labor=48,
                implementation_time=14,
                default_effectiveness=0.22,
                effectiveness_by_threat_scenario={
                    ThreatScenario.PHISHING.value: 0.35,
                    ThreatScenario.UNAUTHORIZED_ACCESS.value: 0.30,
                    ThreatScenario.PRIVILEGE_ESCALATION.value: 0.25,
                },
                applicable_threat_scenarios=[
                    ThreatScenario.PHISHING,
                    ThreatScenario.UNAUTHORIZED_ACCESS,
                    ThreatScenario.PRIVILEGE_ESCALATION,
                ],
            ),
            ControlMeasureCandidate(
                measure_id="CTRL-DLP-EXPORT",
                name="Контроль выгрузки данных и DLP-правила",
                measure_type=ControlMeasureType.SOFTWARE,
                description="Настройка правил контроля массовой выгрузки данных и операций во внерабочее время.",
                cost=420_000,
                labor=56,
                implementation_time=21,
                default_effectiveness=0.24,
                effectiveness_by_threat_scenario={
                    ThreatScenario.DATA_LEAK.value: 0.40,
                    ThreatScenario.INSIDER.value: 0.32,
                },
                applicable_threat_scenarios=[
                    ThreatScenario.DATA_LEAK,
                    ThreatScenario.INSIDER,
                ],
            ),
            ControlMeasureCandidate(
                measure_id="CTRL-NETWORK-SEGMENTATION",
                name="Уточнение сетевой сегментации",
                measure_type=ControlMeasureType.TECHNICAL,
                description="Ограничение сетевого взаимодействия между критичными объектами инфраструктуры.",
                cost=500_000,
                labor=72,
                implementation_time=30,
                default_effectiveness=0.20,
                effectiveness_by_threat_scenario={
                    ThreatScenario.MALWARE.value: 0.26,
                    ThreatScenario.UNAUTHORIZED_ACCESS.value: 0.24,
                    ThreatScenario.DDOS.value: 0.18,
                },
            ),
            ControlMeasureCandidate(
                measure_id="CTRL-BACKUP-RECOVERY",
                name="Проверка резервного копирования и восстановления",
                measure_type=ControlMeasureType.PROCESS,
                description="Проверка актуальности резервных копий и сценариев восстановления критичных сервисов.",
                cost=220_000,
                labor=40,
                implementation_time=12,
                default_effectiveness=0.18,
                effectiveness_by_threat_scenario={
                    ThreatScenario.MALWARE.value: 0.24,
                    ThreatScenario.DDOS.value: 0.22,
                },
                applicable_event_types=[
                    RiskEventType.AVAILABILITY_VIOLATION,
                    RiskEventType.INTEGRITY_VIOLATION,
                ],
            ),
        ]

    def _clip_01(self, value: float) -> float:
        return max(0.0, min(1.0, float(value)))
