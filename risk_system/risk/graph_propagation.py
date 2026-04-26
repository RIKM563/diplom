from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

import numpy as np
import pandas as pd

from risk_system.risk.influence_matrix import InfluenceMatrixResult


@dataclass
class PropagationResult:
    node_risks: pd.DataFrame
    propagated_vector: np.ndarray


class GraphPropagator:
    def __init__(
        self,
        alpha: float = 0.70,
        max_iter: int = 20,
        tol: float = 1e-4,
        clip_to_unit: bool = True,
    ) -> None:
        self.alpha = alpha
        self.max_iter = max_iter
        self.tol = tol
        self.clip_to_unit = clip_to_unit
        self._validate_params()

    def propagate(
        self,
        node_risk_table: pd.DataFrame,
        influence_result: InfluenceMatrixResult,
        iterative: bool = True,
    ) -> PropagationResult:
        required_columns = {"node_id", "final_risk"}
        self._check_columns(node_risk_table, required_columns, "node_risk_table")

        aligned = self._align_node_risks(node_risk_table, influence_result.node_ids)
        base_vector = aligned["final_risk"].to_numpy(dtype=float)
        base_vector = np.clip(base_vector, 0.0, 1.0)

        if iterative:
            propagated_vector = self.iterative_propagation(
                base_vector=base_vector,
                influence_matrix=influence_result.matrix,
            )
        else:
            propagated_vector = self.single_step(
                base_vector=base_vector,
                influence_matrix=influence_result.matrix,
            )

        result_table = aligned.copy()
        result_table["base_risk"] = base_vector
        result_table["propagated_risk"] = propagated_vector
        result_table["final_risk"] = propagated_vector

        return PropagationResult(
            node_risks=result_table.reset_index(drop=True),
            propagated_vector=propagated_vector,
        )

    def single_step(
        self,
        base_vector: np.ndarray,
        influence_matrix: np.ndarray,
    ) -> np.ndarray:
        self._validate_inputs(base_vector, influence_matrix)

        propagated = self.alpha * base_vector + (1.0 - self.alpha) * (influence_matrix.T @ base_vector)
        return self._postprocess_vector(propagated)

    def iterative_propagation(
        self,
        base_vector: np.ndarray,
        influence_matrix: np.ndarray,
    ) -> np.ndarray:
        self._validate_inputs(base_vector, influence_matrix)

        current = base_vector.copy()

        for _ in range(self.max_iter):
            next_vector = self.alpha * base_vector + (1.0 - self.alpha) * (influence_matrix.T @ current)
            next_vector = self._postprocess_vector(next_vector)

            if np.linalg.norm(next_vector - current, ord=1) < self.tol:
                current = next_vector
                break

            current = next_vector

        return self._postprocess_vector(current)

    def build_node_risk_table_from_events(self, event_risk_table: pd.DataFrame) -> pd.DataFrame:
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

        return grouped.reset_index(drop=True)

    def _align_node_risks(
        self,
        node_risk_table: pd.DataFrame,
        ordered_node_ids: List[str],
    ) -> pd.DataFrame:
        node_map = (
            node_risk_table[["node_id", "asset_id", "final_risk"]]
            .drop_duplicates(subset=["node_id"])
            .set_index("node_id")
        )

        rows: List[Dict[str, object]] = []
        for node_id in ordered_node_ids:
            if node_id in node_map.index:
                row = node_map.loc[node_id]
                asset_id = str(row["asset_id"])
                risk_value = float(row["final_risk"])
            else:
                asset_id = "unknown"
                risk_value = 0.0

            rows.append(
                {
                    "node_id": node_id,
                    "asset_id": asset_id,
                    "final_risk": risk_value,
                }
            )

        return pd.DataFrame(rows)

    def _postprocess_vector(self, vector: np.ndarray) -> np.ndarray:
        result = np.asarray(vector, dtype=float).reshape(-1)
        if self.clip_to_unit:
            result = np.clip(result, 0.0, 1.0)
        else:
            result = np.clip(result, 0.0, None)
        return result

    def _validate_inputs(self, base_vector: np.ndarray, influence_matrix: np.ndarray) -> None:
        vector = np.asarray(base_vector, dtype=float).reshape(-1)
        matrix = np.asarray(influence_matrix, dtype=float)

        if matrix.ndim != 2 or matrix.shape[0] != matrix.shape[1]:
            raise ValueError("Матрица влияния должна быть квадратной.")
        if matrix.shape[0] != vector.shape[0]:
            raise ValueError(
                "Размер вектора узловых рисков должен совпадать с размерностью матрицы влияния."
            )
        if np.any(matrix < 0):
            raise ValueError("Матрица влияния не должна содержать отрицательных значений.")

    def _validate_params(self) -> None:
        if not (0.0 <= self.alpha <= 1.0):
            raise ValueError("Параметр alpha должен лежать в диапазоне [0, 1].")
        if self.max_iter <= 0:
            raise ValueError("Параметр max_iter должен быть положительным.")
        if self.tol <= 0:
            raise ValueError("Параметр tol должен быть положительным.")

    @staticmethod
    def _aggregate_risk_values(values) -> float:
        array = np.asarray(list(values), dtype=float)
        if array.size == 0:
            return 0.0
        clipped = np.clip(array, 0.0, 1.0)
        aggregated = 1.0 - np.prod(1.0 - clipped)
        return float(np.clip(aggregated, 0.0, 1.0))

    @staticmethod
    def _check_columns(frame: pd.DataFrame, required: set[str], frame_name: str) -> None:
        missing = required - set(frame.columns)
        if missing:
            raise ValueError(
                f"В таблице '{frame_name}' отсутствуют обязательные колонки: {sorted(missing)}"
            )