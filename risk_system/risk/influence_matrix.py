from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence

import numpy as np
import pandas as pd

from risk_system.domain import InfluenceEdge, Node


@dataclass
class InfluenceMatrixResult:
    matrix: np.ndarray
    node_ids: List[str]


class InfluenceMatrixBuilder:
    def __init__(
        self,
        self_weight: float = 1.0,
        normalize_rows: bool = True,
        min_weight: float = 0.0,
    ) -> None:
        self.self_weight = self_weight
        self.normalize_rows = normalize_rows
        self.min_weight = min_weight

    def build_from_edges(
        self,
        nodes: Sequence[Node],
        edges: Sequence[InfluenceEdge],
    ) -> InfluenceMatrixResult:
        node_ids = [node.node_id for node in nodes]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("Идентификаторы узлов должны быть уникальными.")

        node_index = {node_id: idx for idx, node_id in enumerate(node_ids)}
        n = len(node_ids)

        matrix = np.zeros((n, n), dtype=float)

        for i in range(n):
            matrix[i, i] = max(self.self_weight, 0.0)

        for edge in edges:
            if edge.source_node_id not in node_index or edge.target_node_id not in node_index:
                continue

            src = node_index[edge.source_node_id]
            dst = node_index[edge.target_node_id]
            weight = max(float(edge.weight), self.min_weight)

            matrix[src, dst] += weight

            if edge.bidirectional:
                matrix[dst, src] += weight

        matrix = self._normalize(matrix) if self.normalize_rows else matrix
        self.validate_matrix(matrix)

        return InfluenceMatrixResult(matrix=matrix, node_ids=node_ids)

    def build_from_dataframe(
        self,
        nodes_df: pd.DataFrame,
        edges_df: pd.DataFrame,
    ) -> InfluenceMatrixResult:
        required_node_columns = {"node_id"}
        required_edge_columns = {"source_node_id", "target_node_id", "weight"}

        self._check_columns(nodes_df, required_node_columns, "nodes_df")
        self._check_columns(edges_df, required_edge_columns, "edges_df")

        nodes = [
            Node(
                node_id=str(row["node_id"]),
                asset_id=str(row.get("asset_id", row["node_id"])),
                node_type=row.get("node_type", "other"),
                segment=str(row.get("segment", "unknown")),
                business_service=row.get("business_service"),
                criticality=float(row.get("criticality", 0.0)),
                exposure=float(row.get("exposure", 0.0)),
                trust_level=float(row.get("trust_level", 0.0)),
                metadata={},
            )
            for _, row in nodes_df.iterrows()
        ]

        edges = [
            InfluenceEdge(
                source_node_id=str(row["source_node_id"]),
                target_node_id=str(row["target_node_id"]),
                weight=float(row["weight"]),
                relation_type=str(row.get("relation_type", "network")),
                bidirectional=bool(row.get("bidirectional", False)),
            )
            for _, row in edges_df.iterrows()
        ]

        return self.build_from_edges(nodes, edges)

    def build_from_risk_table(
        self,
        risk_table: pd.DataFrame,
        edges: Sequence[InfluenceEdge],
    ) -> InfluenceMatrixResult:
        if "node_id" not in risk_table.columns:
            raise ValueError("В risk_table должна присутствовать колонка 'node_id'.")

        unique_nodes = (
            risk_table[["node_id", "asset_id"]]
            .drop_duplicates()
            .reset_index(drop=True)
        )

        nodes = [
            Node(
                node_id=str(row["node_id"]),
                asset_id=str(row.get("asset_id", row["node_id"])),
                node_type="other",
                segment="unknown",
                business_service=None,
                criticality=0.0,
                exposure=0.0,
                trust_level=0.0,
                metadata={},
            )
            for _, row in unique_nodes.iterrows()
        ]

        return self.build_from_edges(nodes, edges)

    def to_dataframe(self, result: InfluenceMatrixResult) -> pd.DataFrame:
        return pd.DataFrame(
            result.matrix,
            index=result.node_ids,
            columns=result.node_ids,
        )

    def validate_matrix(self, matrix: np.ndarray) -> None:
        if matrix.ndim != 2:
            raise ValueError("Матрица влияния должна быть двумерной.")
        if matrix.shape[0] != matrix.shape[1]:
            raise ValueError("Матрица влияния должна быть квадратной.")
        if np.any(matrix < 0):
            raise ValueError("Матрица влияния не должна содержать отрицательных значений.")

    def _normalize(self, matrix: np.ndarray) -> np.ndarray:
        result = matrix.copy()
        row_sums = result.sum(axis=1, keepdims=True)
        non_zero_rows = row_sums.squeeze() > 0

        result[non_zero_rows] = result[non_zero_rows] / row_sums[non_zero_rows]
        return result

    @staticmethod
    def _check_columns(frame: pd.DataFrame, required: set[str], frame_name: str) -> None:
        missing = required - set(frame.columns)
        if missing:
            raise ValueError(
                f"В таблице '{frame_name}' отсутствуют обязательные колонки: {sorted(missing)}"
            )