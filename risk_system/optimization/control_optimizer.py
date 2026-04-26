from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence, Set

import numpy as np

from risk_system.domain import (
    ControlMeasure,
    Node,
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
    expected_weighted_risk_reduction: float
    covered_node_ids: List[str]
    cost: float
    labor: float
    implementation_time: float

    @property
    def efficiency_score(self) -> float:
        denominator = self.cost + self.labor + self.implementation_time
        if denominator <= 0:
            return self.expected_weighted_risk_reduction
        return self.expected_weighted_risk_reduction / denominator


@dataclass
class _SearchState:
    selected_indices: List[int]
    selected_measure_ids: Set[str]
    total_benefit: float
    total_raw_benefit: float
    total_cost: float
    total_labor: float
    total_time: float
    measure_count: int


class ControlOptimizer:
    def __init__(
        self,
        min_effectiveness: float = 0.0,
        require_applicability: bool = True,
        class_weights: Dict[str, float] | None = None,
    ) -> None:
        self.min_effectiveness = float(np.clip(min_effectiveness, 0.0, 1.0))
        self.require_applicability = require_applicability
        self.class_weights = dict(class_weights or self._default_class_weights())

    def optimize(self, request: OptimizationRequest) -> OptimizationResponse:
        total_current_risk = float(sum(r.final_risk for r in request.current_risks))
        total_current_weighted_risk = float(
            sum(self._weighted_risk_value(r) for r in request.current_risks)
        )

        candidates = self._build_candidates(
            current_risks=request.current_risks,
            measures=request.measures,
            nodes=request.nodes,
        )

        if not candidates:
            return OptimizationResponse(
                expected_total_residual_risk=total_current_risk,
                expected_weighted_residual_risk=total_current_weighted_risk,
            )

        selected_candidates = self.solve(
            candidates=candidates,
            constraints=request.constraints,
        )

        selected_measures: List[SelectedMeasure] = []
        total_cost = 0.0
        total_labor = 0.0
        total_time = 0.0
        total_reduction = 0.0
        total_weighted_reduction = 0.0

        for candidate in selected_candidates:
            selected_measures.append(
                SelectedMeasure(
                    measure_id=candidate.measure.measure_id,
                    name=candidate.measure.name,
                    cost=float(candidate.cost),
                    labor=float(candidate.labor),
                    implementation_time=float(candidate.implementation_time),
                    expected_risk_reduction=float(candidate.expected_risk_reduction),
                    expected_weighted_risk_reduction=float(candidate.expected_weighted_risk_reduction),
                    covered_node_ids=list(candidate.covered_node_ids),
                )
            )
            total_cost += candidate.cost
            total_labor += candidate.labor
            total_time += candidate.implementation_time
            total_reduction += candidate.expected_risk_reduction
            total_weighted_reduction += candidate.expected_weighted_risk_reduction

        residual_risk = max(0.0, total_current_risk - total_reduction)
        weighted_residual_risk = max(0.0, total_current_weighted_risk - total_weighted_reduction)

        return OptimizationResponse(
            selected_measures=selected_measures,
            total_cost=float(total_cost),
            total_labor=float(total_labor),
            total_time=float(total_time),
            expected_total_risk_reduction=float(total_reduction),
            expected_weighted_risk_reduction=float(total_weighted_reduction),
            expected_total_residual_risk=float(residual_risk),
            expected_weighted_residual_risk=float(weighted_residual_risk),
        )

    def solve(
        self,
        candidates: Sequence[MeasureCandidate],
        constraints: OptimizationConstraints,
    ) -> List[MeasureCandidate]:
        ordered = sorted(
            [candidate for candidate in candidates if candidate.expected_weighted_risk_reduction > 0.0],
            key=lambda item: item.efficiency_score,
            reverse=True,
        )

        if not ordered:
            return []

        best_state = _SearchState(
            selected_indices=[],
            selected_measure_ids=set(),
            total_benefit=0.0,
            total_raw_benefit=0.0,
            total_cost=0.0,
            total_labor=0.0,
            total_time=0.0,
            measure_count=0,
        )

        initial_state = _SearchState(
            selected_indices=[],
            selected_measure_ids=set(),
            total_benefit=0.0,
            total_raw_benefit=0.0,
            total_cost=0.0,
            total_labor=0.0,
            total_time=0.0,
            measure_count=0,
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
            if self._is_final_valid(state, candidates):
                if state.total_benefit > best_state.total_benefit:
                    return _SearchState(
                        selected_indices=list(state.selected_indices),
                        selected_measure_ids=set(state.selected_measure_ids),
                        total_benefit=state.total_benefit,
                        total_raw_benefit=state.total_raw_benefit,
                        total_cost=state.total_cost,
                        total_labor=state.total_labor,
                        total_time=state.total_time,
                        measure_count=state.measure_count,
                    )
            return best_state

        candidate = candidates[index]

        if self._is_pairwise_compatible(candidate.measure, state.selected_measure_ids, candidates):
            include_state = _SearchState(
                selected_indices=state.selected_indices + [index],
                selected_measure_ids=state.selected_measure_ids | {candidate.measure.measure_id},
                total_benefit=state.total_benefit + candidate.expected_weighted_risk_reduction,
                total_raw_benefit=state.total_raw_benefit + candidate.expected_risk_reduction,
                total_cost=state.total_cost + candidate.cost,
                total_labor=state.total_labor + candidate.labor,
                total_time=state.total_time + candidate.implementation_time,
                measure_count=state.measure_count + 1,
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
            selected_measure_ids=set(state.selected_measure_ids),
            total_benefit=state.total_benefit,
            total_raw_benefit=state.total_raw_benefit,
            total_cost=state.total_cost,
            total_labor=state.total_labor,
            total_time=state.total_time,
            measure_count=state.measure_count,
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
        remaining_count = None if constraints.max_measures is None else constraints.max_measures - state.measure_count

        if remaining_budget < 0:
            return -1.0
        if remaining_labor is not None and remaining_labor < 0:
            return -1.0
        if remaining_time is not None and remaining_time < 0:
            return -1.0
        if remaining_count is not None and remaining_count < 0:
            return -1.0

        bound = state.total_benefit
        temp_count = 0

        for candidate in candidates[index:]:
            if candidate.cost > remaining_budget:
                continue
            if remaining_labor is not None and candidate.labor > remaining_labor:
                continue
            if remaining_time is not None and candidate.implementation_time > remaining_time:
                continue
            if remaining_count is not None and temp_count >= remaining_count:
                break

            bound += candidate.expected_weighted_risk_reduction
            temp_count += 1

        return float(bound)

    def _is_feasible(self, state: _SearchState, constraints: OptimizationConstraints) -> bool:
        if state.total_cost > constraints.max_budget:
            return False
        if constraints.max_labor is not None and state.total_labor > constraints.max_labor:
            return False
        if constraints.max_time is not None and state.total_time > constraints.max_time:
            return False
        if constraints.max_measures is not None and state.measure_count > constraints.max_measures:
            return False
        return True

    def _is_pairwise_compatible(
        self,
        measure: ControlMeasure,
        selected_ids: Set[str],
        candidates: Sequence[MeasureCandidate],
    ) -> bool:
        incompatible = set(measure.incompatible_with)

        if incompatible & selected_ids:
            return False

        for candidate in candidates:
            if candidate.measure.measure_id in selected_ids:
                if measure.measure_id in set(candidate.measure.incompatible_with):
                    return False

        return True

    def _is_final_valid(
        self,
        state: _SearchState,
        candidates: Sequence[MeasureCandidate],
    ) -> bool:
        selected_ids = set(state.selected_measure_ids)

        for idx in state.selected_indices:
            measure = candidates[idx].measure
            required_ids = set(measure.requires)
            if not required_ids.issubset(selected_ids):
                return False

        return True

    def _build_candidates(
        self,
        current_risks: Sequence[RiskScore],
        measures: Sequence[ControlMeasure],
        nodes: Sequence[Node],
    ) -> List[MeasureCandidate]:
        node_type_by_node_id = {
            node.node_id: node.node_type.value if hasattr(node.node_type, "value") else str(node.node_type)
            for node in nodes
        }

        candidates: List[MeasureCandidate] = []

        for measure in measures:
            raw_reduction = 0.0
            weighted_reduction = 0.0
            covered_nodes: Set[str] = set()

            for risk in current_risks:
                if not self._is_measure_applicable(measure, risk.node_id, node_type_by_node_id):
                    continue

                threat_key = risk.threat_type.value if hasattr(risk.threat_type, "value") else str(risk.threat_type)
                effectiveness = float(measure.effectiveness.get(threat_key, 0.0))
                effectiveness = float(np.clip(effectiveness, 0.0, 1.0))

                if effectiveness < self.min_effectiveness:
                    continue

                reduction = float(risk.final_risk) * effectiveness
                weighted = self._weighted_risk_value(risk) * effectiveness

                raw_reduction += reduction
                weighted_reduction += weighted
                covered_nodes.add(risk.node_id)

            candidates.append(
                MeasureCandidate(
                    measure=measure,
                    expected_risk_reduction=float(max(raw_reduction, 0.0)),
                    expected_weighted_risk_reduction=float(max(weighted_reduction, 0.0)),
                    covered_node_ids=sorted(covered_nodes),
                    cost=float(measure.cost),
                    labor=float(measure.labor),
                    implementation_time=float(measure.implementation_time),
                )
            )

        return candidates

    def _is_measure_applicable(
        self,
        measure: ControlMeasure,
        node_id: str,
        node_type_by_node_id: Dict[str, str],
    ) -> bool:
        if not measure.applicable_node_types:
            return True

        node_type = node_type_by_node_id.get(node_id)
        if node_type is None:
            return not self.require_applicability

        allowed = {
            item.value if hasattr(item, "value") else str(item)
            for item in measure.applicable_node_types
        }
        return node_type in allowed

    def _weighted_risk_value(self, risk: RiskScore) -> float:
        risk_class_value = risk.risk_class.value if hasattr(risk.risk_class, "value") else str(risk.risk_class)
        weight = float(self.class_weights.get(risk_class_value, 1.0))
        return float(risk.final_risk) * weight

    @staticmethod
    def _default_class_weights() -> Dict[str, float]:
        return {
            "low": 1.0,
            "medium": 1.4,
            "high": 1.9,
            "critical": 2.8,
        }