from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Mapping, Sequence

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
        max_weight: float = 1.0,
        trust_weight: float = 0.25,
        same_segment_bonus: float = 0.15,
        cross_segment_penalty: float = 0.10,
        same_service_bonus: float = 0.20,
        node_type_matrix: Mapping[str, Mapping[str, float]] | None = None,
    ) -> None:
        self.self_weight = self_weight
        self.normalize_rows = normalize_rows
        self.min_weight = min_weight
        self.max_weight = max_weight
        self.trust_weight = trust_weight
        self.same_segment_bonus = same_segment_bonus
        self.cross_segment_penalty = cross_segment_penalty
        self.same_service_bonus = same_service_bonus
        self.node_type_matrix = dict(node_type_matrix or self._default_node_type_matrix())

        self._validate_params()

    def build_from_edges(
        self,
        nodes: Sequence[Node],
        edges: Sequence[InfluenceEdge],
    ) -> InfluenceMatrixResult:
        node_ids = [node.node_id for node in nodes]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("Идентификаторы узлов должны быть уникальными.")

        node_index = {node_id: idx for idx, node_id in enumerate(node_ids)}
        node_map = {node.node_id: node for node in nodes}

        n = len(node_ids)
        matrix = np.zeros((n, n), dtype=float)

        for i in range(n):
            matrix[i, i] = max(self.self_weight, 0.0)

        for edge in edges:
            if edge.source_node_id not in node_index or edge.target_node_id not in node_index:
                continue

            src_idx = node_index[edge.source_node_id]
            dst_idx = node_index[edge.target_node_id]

            src_node = node_map[edge.source_node_id]
            dst_node = node_map[edge.target_node_id]

            effective_weight = self._compute_effective_weight(
                edge=edge,
                src_node=src_node,
                dst_node=dst_node,
            )
            matrix[src_idx, dst_idx] += effective_weight

            if edge.bidirectional:
                reverse_weight = self._compute_effective_weight(
                    edge=edge,
                    src_node=dst_node,
                    dst_node=src_node,
                )
                matrix[dst_idx, src_idx] += reverse_weight

        if self.normalize_rows:
            matrix = self._normalize(matrix)

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

        unique_nodes = risk_table[["node_id", "asset_id"]].drop_duplicates().reset_index(drop=True)

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
        return pd.DataFrame(result.matrix, index=result.node_ids, columns=result.node_ids)

    def validate_matrix(self, matrix: np.ndarray) -> None:
        if matrix.ndim != 2:
            raise ValueError("Матрица влияния должна быть двумерной.")
        if matrix.shape[0] != matrix.shape[1]:
            raise ValueError("Матрица влияния должна быть квадратной.")
        if np.any(matrix < 0):
            raise ValueError("Матрица влияния не должна содержать отрицательных значений.")

    def _compute_effective_weight(
        self,
        edge: InfluenceEdge,
        src_node: Node,
        dst_node: Node,
    ) -> float:
        base_weight = float(np.clip(edge.weight, self.min_weight, self.max_weight))

        avg_trust = (float(src_node.trust_level) + float(dst_node.trust_level)) / 2.0
        trust_factor = 1.0 + self.trust_weight * float(np.clip(avg_trust, 0.0, 1.0))

        if src_node.segment == dst_node.segment:
            segment_factor = 1.0 + self.same_segment_bonus
        else:
            segment_factor = max(0.0, 1.0 - self.cross_segment_penalty)

        same_service = (
            src_node.business_service is not None
            and dst_node.business_service is not None
            and src_node.business_service == dst_node.business_service
        )
        service_factor = 1.0 + self.same_service_bonus if same_service else 1.0

        src_type = str(src_node.node_type)
        dst_type = str(dst_node.node_type)
        type_factor = self.node_type_matrix.get(src_type, {}).get(dst_type, 1.0)

        effective = base_weight * trust_factor * segment_factor * service_factor * type_factor
        return float(np.clip(effective, self.min_weight, self.max_weight))

    def _normalize(self, matrix: np.ndarray) -> np.ndarray:
        result = matrix.copy()
        row_sums = result.sum(axis=1, keepdims=True)
        non_zero_rows = row_sums.squeeze() > 0
        result[non_zero_rows] = result[non_zero_rows] / row_sums[non_zero_rows]
        return result

    @staticmethod
    def _default_node_type_matrix() -> Dict[str, Dict[str, float]]:
        return {
            "gateway": {
                "server": 1.15,
                "application": 1.10,
                "database": 0.95,
            },
            "application": {
                "server": 1.08,
                "database": 1.10,
                "gateway": 0.95,
            },
            "server": {
                "database": 1.12,
                "application": 1.05,
                "server": 1.00,
            },
            "database": {
                "database": 1.00,
                "server": 0.95,
                "application": 0.90,
            },
        }

    def _validate_params(self) -> None:
        if self.self_weight < 0:
            raise ValueError("self_weight должен быть неотрицательным.")
        if self.min_weight < 0:
            raise ValueError("min_weight должен быть неотрицательным.")
        if self.max_weight <= 0:
            raise ValueError("max_weight должен быть положительным.")
        if self.min_weight > self.max_weight:
            raise ValueError("min_weight не может быть больше max_weight.")

    @staticmethod
    def _check_columns(frame: pd.DataFrame, required: set[str], frame_name: str) -> None:
        missing = required - set(frame.columns)
        if missing:
            raise ValueError(
                f"В таблице '{frame_name}' отсутствуют обязательные колонки: {sorted(missing)}"
            )