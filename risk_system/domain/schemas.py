from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class ThreatType(str, Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_LEAK = "data_leak"
    DDOS = "ddos"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    MISCONFIGURATION = "misconfiguration"
    INSIDER = "insider"
    OTHER = "other"


class NodeType(str, Enum):
    SERVER = "server"
    WORKSTATION = "workstation"
    DATABASE = "database"
    NETWORK_DEVICE = "network_device"
    APPLICATION = "application"
    GATEWAY = "gateway"
    ATM = "atm"
    PAYMENT_NODE = "payment_node"
    OTHER = "other"


class MeasureType(str, Enum):
    ORGANIZATIONAL = "organizational"
    TECHNICAL = "technical"
    SOFTWARE = "software"
    HARDWARE = "hardware"
    OTHER = "other"


class RiskClass(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEvent(BaseModel):
    event_id: str = Field(..., description="Уникальный идентификатор события")
    node_id: str = Field(..., description="Идентификатор узла, к которому относится событие")
    asset_id: str = Field(..., description="Идентификатор актива")
    threat_type: ThreatType = Field(..., description="Тип угрозы")
    source: str = Field(..., description="Источник события")
    timestamp: Optional[str] = Field(default=None, description="Временная метка события")
    severity: float = Field(default=0.0, ge=0.0, le=1.0, description="Нормированная серьезность события")
    frequency: float = Field(default=0.0, ge=0.0, description="Частота или интенсивность события")
    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Оценка аномальности")
    has_vulnerability: bool = Field(default=False, description="Наличие связанной уязвимости")
    privilege_level: int = Field(default=0, ge=0, le=10, description="Уровень привилегий")
    has_controls: bool = Field(default=False, description="Есть ли уже защитные меры")
    metadata: Dict[str, float | int | str | bool] = Field(default_factory=dict)


class Node(BaseModel):
    node_id: str = Field(..., description="Уникальный идентификатор узла")
    asset_id: str = Field(..., description="Идентификатор актива, к которому относится узел")
    node_type: NodeType = Field(..., description="Тип узла")
    segment: str = Field(..., description="Сегмент сети или инфраструктуры")
    business_service: Optional[str] = Field(default=None, description="Связанный бизнес-сервис")
    criticality: float = Field(..., ge=0.0, description="Коэффициент критичности узла")
    exposure: float = Field(default=0.0, ge=0.0, description="Оценка экспонированности узла")
    trust_level: float = Field(default=0.0, ge=0.0, description="Уровень доверия к узлу")
    metadata: Dict[str, float | int | str | bool] = Field(default_factory=dict)


class Asset(BaseModel):
    asset_id: str = Field(..., description="Уникальный идентификатор актива")
    name: str = Field(..., description="Название актива")
    owner: Optional[str] = Field(default=None, description="Владелец актива")
    business_process: Optional[str] = Field(default=None, description="Бизнес-процесс")
    criticality: float = Field(..., ge=0.0, description="Коэффициент критичности актива")
    cost: float = Field(default=0.0, ge=0.0, description="Условная стоимость актива")
    metadata: Dict[str, float | int | str | bool] = Field(default_factory=dict)


class InfluenceEdge(BaseModel):
    source_node_id: str = Field(..., description="Узел-источник влияния")
    target_node_id: str = Field(..., description="Узел-приемник влияния")
    weight: float = Field(..., ge=0.0, description="Вес влияния")
    relation_type: str = Field(default="network", description="Тип связи")
    bidirectional: bool = Field(default=False, description="Двунаправленная ли связь")


class ControlMeasure(BaseModel):
    measure_id: str = Field(..., description="Идентификатор меры защиты")
    name: str = Field(..., description="Название меры защиты")
    measure_type: MeasureType = Field(..., description="Тип меры защиты")
    cost: float = Field(..., ge=0.0, description="Стоимость реализации меры")
    labor: float = Field(default=0.0, ge=0.0, description="Трудоемкость реализации")
    implementation_time: float = Field(default=0.0, ge=0.0, description="Время внедрения")
    effectiveness: Dict[str, float] = Field(
        default_factory=dict,
        description="Эффективность меры по типам угроз, ключ = threat_type, значение от 0 до 1",
    )
    applicable_node_types: List[NodeType] = Field(default_factory=list)
    metadata: Dict[str, float | int | str | bool] = Field(default_factory=dict)


class ThreatProbability(BaseModel):
    event_id: str
    node_id: str
    asset_id: str
    threat_type: ThreatType
    raw_probability: float = Field(..., ge=0.0, le=1.0)
    calibrated_probability: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class RiskScore(BaseModel):
    event_id: Optional[str] = None
    node_id: Optional[str] = None
    asset_id: Optional[str] = None
    threat_type: Optional[ThreatType] = None
    probability: float = Field(..., ge=0.0, le=1.0)
    impact: float = Field(..., ge=0.0)
    criticality: float = Field(..., ge=0.0)
    base_risk: float = Field(..., ge=0.0)
    propagated_risk: Optional[float] = Field(default=None, ge=0.0)
    final_risk: float = Field(..., ge=0.0)
    risk_class: RiskClass


class ExplanationItem(BaseModel):
    feature_name: str
    contribution: float
    direction: str = Field(..., description="positive или negative")


class NodeRiskResult(BaseModel):
    node_id: str
    asset_id: str
    final_risk: float = Field(..., ge=0.0)
    risk_class: RiskClass
    explanations: List[ExplanationItem] = Field(default_factory=list)


class AssetRiskResult(BaseModel):
    asset_id: str
    final_risk: float = Field(..., ge=0.0)
    risk_class: RiskClass
    node_results: List[NodeRiskResult] = Field(default_factory=list)


class RiskAssessmentRequest(BaseModel):
    events: List[SecurityEvent]
    nodes: List[Node]
    assets: List[Asset]
    edges: List[InfluenceEdge] = Field(default_factory=list)


class RiskAssessmentResponse(BaseModel):
    event_risks: List[RiskScore] = Field(default_factory=list)
    node_risks: List[NodeRiskResult] = Field(default_factory=list)
    asset_risks: List[AssetRiskResult] = Field(default_factory=list)


class OptimizationConstraints(BaseModel):
    max_budget: float = Field(..., ge=0.0)
    max_labor: Optional[float] = Field(default=None, ge=0.0)
    max_time: Optional[float] = Field(default=None, ge=0.0)


class OptimizationRequest(BaseModel):
    current_risks: List[RiskScore]
    measures: List[ControlMeasure]
    constraints: OptimizationConstraints


class SelectedMeasure(BaseModel):
    measure_id: str
    name: str
    cost: float = Field(..., ge=0.0)
    labor: float = Field(..., ge=0.0)
    implementation_time: float = Field(..., ge=0.0)
    expected_risk_reduction: float = Field(..., ge=0.0)


class OptimizationResponse(BaseModel):
    selected_measures: List[SelectedMeasure] = Field(default_factory=list)
    total_cost: float = Field(default=0.0, ge=0.0)
    total_labor: float = Field(default=0.0, ge=0.0)
    total_time: float = Field(default=0.0, ge=0.0)
    expected_total_risk_reduction: float = Field(default=0.0, ge=0.0)