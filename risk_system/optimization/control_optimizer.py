from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

import numpy as np

from risk_system.domain import (
    ControlMeasure,
    OptimizationConstraints,
    OptimizationRequest,
    OptimizationResponse,
    RiskScore,
    SelectedMeasure,
)


@dataclass
class MeasureCandidate:
    measure: ControlMeasure
    expected_risk_reduction: float
    cost: float
    labor: float
    implementation_time: float

    @property
    def efficiency_score(self) -> float:
        denominator = self.cost + self.labor + self.implementation_time
        if denominator <= 0:
            return self.expected_risk_reduction
        return self.expected_risk_reduction / denominator


@dataclass
class _SearchState:
    selected_indices: List[int]
    total_benefit: float
    total_cost: float
    total_labor: float
    total_time: float


class ControlOptimizer:
    def __init__(self, min_effectiveness: float = 0.0) -> None:
        self.min_effectiveness = float(np.clip(min_effectiveness, 0.0, 1.0))

    def optimize(self, request: OptimizationRequest) -> OptimizationResponse:
        candidates = self._build_candidates(
            current_risks=request.current_risks,
            measures=request.measures,
        )

        if not candidates:
            return OptimizationResponse()

        selected_candidates = self.solve(
            candidates=candidates,
            constraints=request.constraints,
        )

        selected_measures: List[SelectedMeasure] = []
        total_cost = 0.0
        total_labor = 0.0
        total_time = 0.0
        total_reduction = 0.0

        for candidate in selected_candidates:
            selected_measures.append(
                SelectedMeasure(
                    measure_id=candidate.measure.measure_id,
                    name=candidate.measure.name,
                    cost=float(candidate.cost),
                    labor=float(candidate.labor),
                    implementation_time=float(candidate.implementation_time),
                    expected_risk_reduction=float(candidate.expected_risk_reduction),
                )
            )
            total_cost += candidate.cost
            total_labor += candidate.labor
            total_time += candidate.implementation_time
            total_reduction += candidate.expected_risk_reduction

        return OptimizationResponse(
            selected_measures=selected_measures,
            total_cost=float(total_cost),
            total_labor=float(total_labor),
            total_time=float(total_time),
            expected_total_risk_reduction=float(total_reduction),
        )

    def solve(
        self,
        candidates: Sequence[MeasureCandidate],
        constraints: OptimizationConstraints,
    ) -> List[MeasureCandidate]:
        ordered = sorted(
            [candidate for candidate in candidates if candidate.expected_risk_reduction > 0.0],
            key=lambda item: item.efficiency_score,
            reverse=True,
        )

        if not ordered:
            return []

        best_state = _SearchState(
            selected_indices=[],
            total_benefit=0.0,
            total_cost=0.0,
            total_labor=0.0,
            total_time=0.0,
        )

        initial_state = _SearchState(
            selected_indices=[],
            total_benefit=0.0,
            total_cost=0.0,
            total_labor=0.0,
            total_time=0.0,
        )

        best_state = self._branch_and_bound(
            candidates=ordered,
            constraints=constraints,
            index=0,
            state=initial_state,
            best_state=best_state,
        )

        return [ordered[idx] for idx in best_state.selected_indices]

    def _branch_and_bound(
        self,
        candidates: Sequence[MeasureCandidate],
        constraints: OptimizationConstraints,
        index: int,
        state: _SearchState,
        best_state: _SearchState,
    ) -> _SearchState:
        if not self._is_feasible(state, constraints):
            return best_state

        upper_bound = self._compute_upper_bound(
            candidates=candidates,
            constraints=constraints,
            index=index,
            state=state,
        )

        if upper_bound <= best_state.total_benefit:
            return best_state

        if index >= len(candidates):
            if state.total_benefit > best_state.total_benefit:
                return _SearchState(
                    selected_indices=list(state.selected_indices),
                    total_benefit=state.total_benefit,
                    total_cost=state.total_cost,
                    total_labor=state.total_labor,
                    total_time=state.total_time,
                )
            return best_state

        candidate = candidates[index]

        include_state = _SearchState(
            selected_indices=state.selected_indices + [index],
            total_benefit=state.total_benefit + candidate.expected_risk_reduction,
            total_cost=state.total_cost + candidate.cost,
            total_labor=state.total_labor + candidate.labor,
            total_time=state.total_time + candidate.implementation_time,
        )

        best_state = self._branch_and_bound(
            candidates=candidates,
            constraints=constraints,
            index=index + 1,
            state=include_state,
            best_state=best_state,
        )

        exclude_state = _SearchState(
            selected_indices=list(state.selected_indices),
            total_benefit=state.total_benefit,
            total_cost=state.total_cost,
            total_labor=state.total_labor,
            total_time=state.total_time,
        )

        best_state = self._branch_and_bound(
            candidates=candidates,
            constraints=constraints,
            index=index + 1,
            state=exclude_state,
            best_state=best_state,
        )

        return best_state

    def _compute_upper_bound(
        self,
        candidates: Sequence[MeasureCandidate],
        constraints: OptimizationConstraints,
        index: int,
        state: _SearchState,
    ) -> float:
        remaining_budget = constraints.max_budget - state.total_cost
        remaining_labor = None if constraints.max_labor is None else constraints.max_labor - state.total_labor
        remaining_time = None if constraints.max_time is None else constraints.max_time - state.total_time

        if remaining_budget < 0:
            return -1.0
        if remaining_labor is not None and remaining_labor < 0:
            return -1.0
        if remaining_time is not None and remaining_time < 0:
            return -1.0

        bound = state.total_benefit

        for candidate in candidates[index:]:
            if candidate.cost > remaining_budget:
                continue
            if remaining_labor is not None and candidate.labor > remaining_labor:
                continue
            if remaining_time is not None and candidate.implementation_time > remaining_time:
                continue

            bound += candidate.expected_risk_reduction

        return float(bound)

    def _is_feasible(self, state: _SearchState, constraints: OptimizationConstraints) -> bool:
        if state.total_cost > constraints.max_budget:
            return False
        if constraints.max_labor is not None and state.total_labor > constraints.max_labor:
            return False
        if constraints.max_time is not None and state.total_time > constraints.max_time:
            return False
        return True

    def _build_candidates(
        self,
        current_risks: Sequence[RiskScore],
        measures: Sequence[ControlMeasure],
    ) -> List[MeasureCandidate]:
        candidates: List[MeasureCandidate] = []

        for measure in measures:
            reduction = self._estimate_measure_reduction(
                measure=measure,
                current_risks=current_risks,
            )

            candidate = MeasureCandidate(
                measure=measure,
                expected_risk_reduction=float(max(reduction, 0.0)),
                cost=float(measure.cost),
                labor=float(measure.labor),
                implementation_time=float(measure.implementation_time),
            )
            candidates.append(candidate)

        return candidates

    def _estimate_measure_reduction(
        self,
        measure: ControlMeasure,
        current_risks: Sequence[RiskScore],
    ) -> float:
        total_reduction = 0.0

        for risk in current_risks:
            threat_key = risk.threat_type.value if hasattr(risk.threat_type, "value") else str(risk.threat_type)
            effectiveness = float(measure.effectiveness.get(threat_key, 0.0))
            effectiveness = float(np.clip(effectiveness, 0.0, 1.0))

            if effectiveness < self.min_effectiveness:
                continue

            total_reduction += float(risk.final_risk) * effectiveness

        return float(total_reduction)