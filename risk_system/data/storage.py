from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from risk_system.domain import (
    Asset,
    ControlMeasure,
    InfluenceEdge,
    MeasureType,
    Node,
    NodeType,
    OptimizationRequest,
    OptimizationResponse,
    RiskAssessmentRequest,
    RiskAssessmentResponse,
    SecurityEvent,
    ThreatType,
)


class Storage:
    def __init__(self) -> None:
        self._latest_request: Optional[RiskAssessmentRequest] = None
        self._latest_response: Optional[RiskAssessmentResponse] = None
        self._latest_optimization_request: Optional[OptimizationRequest] = None
        self._latest_optimization_response: Optional[OptimizationResponse] = None

    def store_request(self, request: RiskAssessmentRequest) -> None:
        self._latest_request = request

    def get_request(self) -> Optional[RiskAssessmentRequest]:
        return self._latest_request

    def store_response(self, response: RiskAssessmentResponse) -> None:
        self._latest_response = response

    def get_response(self) -> Optional[RiskAssessmentResponse]:
        return self._latest_response

    def store_optimization_request(self, request: OptimizationRequest) -> None:
        self._latest_optimization_request = request

    def get_optimization_request(self) -> Optional[OptimizationRequest]:
        return self._latest_optimization_request

    def store_optimization_response(self, response: OptimizationResponse) -> None:
        self._latest_optimization_response = response

    def get_optimization_response(self) -> Optional[OptimizationResponse]:
        return self._latest_optimization_response

    def build_request(
        self,
        events: List[SecurityEvent],
        nodes: List[Node],
        assets: List[Asset],
        edges: Optional[List[InfluenceEdge]] = None,
    ) -> RiskAssessmentRequest:
        request = RiskAssessmentRequest(
            events=events,
            nodes=nodes,
            assets=assets,
            edges=edges or [],
        )
        self.store_request(request)
        return request

    def save_request_to_json(self, request: RiskAssessmentRequest, path: str | Path) -> None:
        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(
            json.dumps(request.model_dump(mode="json"), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def load_request_from_json(self, path: str | Path) -> RiskAssessmentRequest:
        file_path = Path(path)
        payload = json.loads(file_path.read_text(encoding="utf-8"))
        request = RiskAssessmentRequest.model_validate(payload)
        self.store_request(request)
        return request

    def save_response_to_json(self, response: RiskAssessmentResponse, path: str | Path) -> None:
        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(
            json.dumps(response.model_dump(mode="json"), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def load_events_from_csv(self, path: str | Path) -> List[SecurityEvent]:
        rows = self._read_csv(path)
        events: List[SecurityEvent] = []

        for row in rows:
            event = SecurityEvent(
                event_id=self._get_required_str(row, "event_id"),
                node_id=self._get_required_str(row, "node_id"),
                asset_id=self._get_required_str(row, "asset_id"),
                threat_type=ThreatType(self._get_required_str(row, "threat_type")),
                source=self._get_required_str(row, "source"),
                timestamp=self._get_optional_str(row, "timestamp"),
                severity=self._get_float(row, "severity", 0.0),
                frequency=self._get_float(row, "frequency", 0.0),
                anomaly_score=self._get_float(row, "anomaly_score", 0.0),
                has_vulnerability=self._get_bool(row, "has_vulnerability", False),
                privilege_level=self._get_int(row, "privilege_level", 0),
                has_controls=self._get_bool(row, "has_controls", False),
                metadata=self._get_dict(row, "metadata"),
            )
            events.append(event)

        return events

    def load_nodes_from_csv(self, path: str | Path) -> List[Node]:
        rows = self._read_csv(path)
        nodes: List[Node] = []

        for row in rows:
            node = Node(
                node_id=self._get_required_str(row, "node_id"),
                asset_id=self._get_required_str(row, "asset_id"),
                node_type=NodeType(self._get_required_str(row, "node_type")),
                segment=self._get_required_str(row, "segment"),
                business_service=self._get_optional_str(row, "business_service"),
                criticality=self._get_float(row, "criticality", 0.0),
                exposure=self._get_float(row, "exposure", 0.0),
                trust_level=self._get_float(row, "trust_level", 0.0),
                metadata=self._get_dict(row, "metadata"),
            )
            nodes.append(node)

        return nodes

    def load_assets_from_csv(self, path: str | Path) -> List[Asset]:
        rows = self._read_csv(path)
        assets: List[Asset] = []

        for row in rows:
            asset = Asset(
                asset_id=self._get_required_str(row, "asset_id"),
                name=self._get_required_str(row, "name"),
                owner=self._get_optional_str(row, "owner"),
                business_process=self._get_optional_str(row, "business_process"),
                criticality=self._get_float(row, "criticality", 0.0),
                cost=self._get_float(row, "cost", 0.0),
                metadata=self._get_dict(row, "metadata"),
            )
            assets.append(asset)

        return assets

    def load_edges_from_csv(self, path: str | Path) -> List[InfluenceEdge]:
        rows = self._read_csv(path)
        edges: List[InfluenceEdge] = []

        for row in rows:
            edge = InfluenceEdge(
                source_node_id=self._get_required_str(row, "source_node_id"),
                target_node_id=self._get_required_str(row, "target_node_id"),
                weight=self._get_float(row, "weight", 0.0),
                relation_type=self._get_optional_str(row, "relation_type") or "network",
                bidirectional=self._get_bool(row, "bidirectional", False),
            )
            edges.append(edge)

        return edges

    def load_measures_from_csv(self, path: str | Path) -> List[ControlMeasure]:
        rows = self._read_csv(path)
        measures: List[ControlMeasure] = []

        for row in rows:
            applicable_node_types = [
                NodeType(value)
                for value in self._get_list(row, "applicable_node_types")
                if value
            ]

            measure = ControlMeasure(
                measure_id=self._get_required_str(row, "measure_id"),
                name=self._get_required_str(row, "name"),
                measure_type=MeasureType(self._get_required_str(row, "measure_type")),
                cost=self._get_float(row, "cost", 0.0),
                labor=self._get_float(row, "labor", 0.0),
                implementation_time=self._get_float(row, "implementation_time", 0.0),
                effectiveness=self._get_float_dict(row, "effectiveness"),
                applicable_node_types=applicable_node_types,
                metadata=self._get_dict(row, "metadata"),
            )
            measures.append(measure)

        return measures

    @staticmethod
    def _read_csv(path: str | Path) -> List[Dict[str, str]]:
        file_path = Path(path)
        with file_path.open("r", encoding="utf-8-sig", newline="") as file:
            reader = csv.DictReader(file)
            return [dict(row) for row in reader]

    @staticmethod
    def _get_required_str(row: Dict[str, Any], key: str) -> str:
        value = row.get(key)
        if value is None or str(value).strip() == "":
            raise ValueError(f"Поле '{key}' обязательно для заполнения.")
        return str(value).strip()

    @staticmethod
    def _get_optional_str(row: Dict[str, Any], key: str) -> Optional[str]:
        value = row.get(key)
        if value is None:
            return None
        value_str = str(value).strip()
        return value_str if value_str != "" else None

    @staticmethod
    def _get_float(row: Dict[str, Any], key: str, default: float = 0.0) -> float:
        value = row.get(key)
        if value is None or str(value).strip() == "":
            return default
        return float(str(value).replace(",", ".").strip())

    @staticmethod
    def _get_int(row: Dict[str, Any], key: str, default: int = 0) -> int:
        value = row.get(key)
        if value is None or str(value).strip() == "":
            return default
        return int(float(str(value).replace(",", ".").strip()))

    @staticmethod
    def _get_bool(row: Dict[str, Any], key: str, default: bool = False) -> bool:
        value = row.get(key)
        if value is None or str(value).strip() == "":
            return default

        normalized = str(value).strip().lower()
        if normalized in {"1", "true", "yes", "y", "да"}:
            return True
        if normalized in {"0", "false", "no", "n", "нет"}:
            return False

        return default

    @staticmethod
    def _get_dict(row: Dict[str, Any], key: str) -> Dict[str, Any]:
        value = row.get(key)
        if value is None or str(value).strip() == "":
            return {}
        parsed = json.loads(str(value))
        if not isinstance(parsed, dict):
            raise ValueError(f"Поле '{key}' должно содержать JSON-объект.")
        return parsed

    @staticmethod
    def _get_float_dict(row: Dict[str, Any], key: str) -> Dict[str, float]:
        value = row.get(key)
        if value is None or str(value).strip() == "":
            return {}
        parsed = json.loads(str(value))
        if not isinstance(parsed, dict):
            raise ValueError(f"Поле '{key}' должно содержать JSON-объект.")
        return {str(k): float(v) for k, v in parsed.items()}

    @staticmethod
    def _get_list(row: Dict[str, Any], key: str) -> List[str]:
        value = row.get(key)
        if value is None or str(value).strip() == "":
            return []

        raw = str(value).strip()

        if raw.startswith("["):
            parsed = json.loads(raw)
            if not isinstance(parsed, list):
                raise ValueError(f"Поле '{key}' должно содержать JSON-массив.")
            return [str(item).strip() for item in parsed]

        return [item.strip() for item in raw.split(",") if item.strip()]