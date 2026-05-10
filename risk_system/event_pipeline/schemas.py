from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class LogSourceType(str, Enum):
    SIEM = "siem"
    EDR = "edr"
    DLP = "dlp"
    IDS = "ids"
    FIREWALL = "firewall"
    OS = "os"
    APPLICATION = "application"
    DATABASE = "database"
    OTHER = "other"


class SecurityEventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    ACCESS_CONTROL = "access_control"
    NETWORK = "network"
    MALWARE_PROTECTION = "malware_protection"
    DATA_OPERATION = "data_operation"
    CONFIGURATION_CHANGE = "configuration_change"
    SOFTWARE_UPDATE = "software_update"
    SYSTEM_ERROR = "system_error"
    VULNERABILITY = "vulnerability"
    OTHER = "other"


class EventResult(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    ERROR = "error"
    UNKNOWN = "unknown"


class IncidentType(str, Enum):
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    MALWARE_ACTIVITY = "malware_activity"
    DATA_LEAK_SIGNS = "data_leak_signs"
    SERVICE_UNAVAILABILITY = "service_unavailability"
    SECURITY_UPDATE_FAILURE = "security_update_failure"
    CONFIGURATION_VIOLATION = "configuration_violation"
    PRIVILEGE_ESCALATION_SIGNS = "privilege_escalation_signs"
    ACCOUNT_COMPROMISE_SIGNS = "account_compromise_signs"
    OTHER = "other"


class IncidentSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class RiskEventType(str, Enum):
    CONFIDENTIALITY_VIOLATION = "confidentiality_violation"
    INTEGRITY_VIOLATION = "integrity_violation"
    AVAILABILITY_VIOLATION = "availability_violation"
    FRAUD_OPERATION_SIGNS = "fraud_operation_signs"
    TECH_PROCESS_DISRUPTION = "tech_process_disruption"
    REGULATORY_REQUIREMENT_VIOLATION = "regulatory_requirement_violation"
    OTHER = "other"


class ThreatScenario(str, Enum):
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    MALWARE = "malware"
    PHISHING = "phishing"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_LEAK = "data_leak"
    DDOS = "ddos"
    MISCONFIGURATION = "misconfiguration"
    INSIDER = "insider"
    OTHER = "other"


class RawLogRecord(BaseModel):
    log_id: str = Field(..., description="Уникальный идентификатор записи журнала")
    timestamp: Optional[str] = Field(default=None, description="Время формирования записи")
    source_system: str = Field(..., description="Источник записи: SIEM, EDR, ОС, приложение и т.д.")
    source_type: LogSourceType = Field(default=LogSourceType.OTHER)
    raw_message: str = Field(..., description="Исходное сообщение журнала")
    event_code: Optional[str] = Field(default=None)
    host: Optional[str] = Field(default=None)
    src_ip: Optional[str] = Field(default=None)
    dst_ip: Optional[str] = Field(default=None)
    user_id: Optional[str] = Field(default=None)
    object_id: Optional[str] = Field(default=None)
    node_id: Optional[str] = Field(default=None)
    asset_id: Optional[str] = Field(default=None)
    action: Optional[str] = Field(default=None)
    result: EventResult = Field(default=EventResult.UNKNOWN)
    severity_from_source: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class NormalizedSecurityEvent(BaseModel):
    event_id: str = Field(..., description="Идентификатор нормализованного события защиты информации")
    source_log_id: str = Field(..., description="Идентификатор исходной записи журнала")
    timestamp: Optional[str] = None
    source_system: str
    source_type: LogSourceType
    event_category: SecurityEventCategory
    event_name: str
    action: Optional[str] = None
    result: EventResult = EventResult.UNKNOWN
    node_id: Optional[str] = None
    asset_id: Optional[str] = None
    subject_id: Optional[str] = None
    object_id: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    normalized_severity: float = Field(default=0.0, ge=0.0, le=1.0)
    is_security_relevant: bool = Field(default=True)
    correlation_key: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IncidentRecord(BaseModel):
    incident_id: str = Field(..., description="Идентификатор инцидента защиты информации")
    created_from_event_ids: List[str] = Field(default_factory=list)
    detected_at: Optional[str] = None
    incident_type: IncidentType
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.NEW
    node_id: Optional[str] = None
    asset_id: Optional[str] = None
    affected_process: Optional[str] = None
    description: str = ""
    classifier_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RiskEventRecord(BaseModel):
    risk_event_id: str = Field(..., description="Идентификатор события риска ИБ")
    incident_id: str
    event_type: RiskEventType
    threat_scenario: ThreatScenario
    node_id: Optional[str] = None
    asset_id: Optional[str] = None
    affected_process: Optional[str] = None
    has_actual_loss: bool = Field(default=False)
    estimated_loss: float = Field(default=0.0, ge=0.0)
    potential_loss: float = Field(default=0.0, ge=0.0)
    probability_estimate: float = Field(default=0.0, ge=0.0, le=1.0)
    impact_estimate: float = Field(default=0.0, ge=0.0)
    registration_threshold_reached: bool = Field(default=True)
    classifier_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    rationale: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RiskEventClassifierTrainingSample(BaseModel):
    incident: IncidentRecord
    target: int = Field(
        ...,
        ge=0,
        le=1,
        description="1 — инцидент отнесён к событию риска реализации информационных угроз, 0 — не отнесён",
    )
    expected_event_type: Optional[RiskEventType] = None
    expected_threat_scenario: Optional[ThreatScenario] = None


class RiskEventClassifierTrainingRequest(BaseModel):
    samples: List[RiskEventClassifierTrainingSample]
    model_type: str = Field(
        default="random_forest",
        description="Тип ML-модели: random_forest, gradient_boosting или logistic_regression",
    )
    save_model: bool = True

class RiskEventClassifierFlatTrainingSample(BaseModel):
    target: int = Field(
        ...,
        ge=0,
        le=1,
        description="1 — инцидент отнесён к событию риска реализации информационных угроз, 0 — не отнесён",
    )

    incident_id: Optional[str] = None
    incident_type: IncidentType
    severity: IncidentSeverity
    classifier_confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    node_id: Optional[str] = None
    asset_id: Optional[str] = None
    affected_process: Optional[str] = None

    events_count: int = Field(default=1, ge=0)
    failed_auth_count: int = Field(default=0, ge=0)
    blocked_or_failed_count: int = Field(default=0, ge=0)
    malware_event_count: int = Field(default=0, ge=0)
    update_error_count: int = Field(default=0, ge=0)
    access_denied_count: int = Field(default=0, ge=0)
    data_operation_count: int = Field(default=0, ge=0)
    system_error_count: int = Field(default=0, ge=0)
    max_severity: float = Field(default=0.0, ge=0.0, le=1.0)

    has_after_hours_activity: bool = False
    has_admin_action: bool = False
    has_edr_disabled: bool = False
    has_malware_detected: bool = False
    has_large_data_export: bool = False
    has_critical_asset: bool = False
    has_service_unavailable: bool = False
    has_actual_loss: bool = False

    potential_loss: float = Field(default=0.0, ge=0.0)
    estimated_loss: float = Field(default=0.0, ge=0.0)

    node_type: str = "unknown"
    asset_type: str = "unknown"
    network_segment: str = "unknown"
    process_criticality: str = "unknown"
    confidentiality_impact: str = "unknown"
    integrity_impact: str = "unknown"
    availability_impact: str = "unknown"
    rule_id: str = "unknown"

    expected_event_type: Optional[RiskEventType] = None
    expected_threat_scenario: Optional[ThreatScenario] = None


class RiskEventClassifierFlatTrainingRequest(BaseModel):
    samples: List[RiskEventClassifierFlatTrainingSample]
    model_type: str = Field(
        default="random_forest",
        description="Тип ML-модели: random_forest, gradient_boosting или logistic_regression",
    )
    save_model: bool = True

class RiskEventClassifierTrainingResponse(BaseModel):
    model_type: str
    samples_count: int
    positive_count: int
    negative_count: int
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1: Optional[float] = None
    roc_auc: Optional[float] = None
    model_path: Optional[str] = None
    feature_columns: List[str] = Field(default_factory=list)


class RiskClass(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskAssessmentRecord(BaseModel):
    assessment_id: str = Field(..., description="Идентификатор расчетной оценки риска")
    risk_event_id: str = Field(..., description="Идентификатор события риска ИБ")
    incident_id: str = Field(..., description="Идентификатор связанного инцидента защиты информации")
    node_id: Optional[str] = None
    asset_id: Optional[str] = None
    threat_scenario: ThreatScenario
    probability_estimate: float = Field(default=0.0, ge=0.0, le=1.0)
    impact_estimate: float = Field(default=0.0, ge=0.0, le=1.0)
    initial_risk_estimate: float = Field(default=0.0, ge=0.0, le=1.0)
    graph_adjusted_risk_estimate: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    final_risk_estimate: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_class: RiskClass
    priority: int = Field(default=0, ge=0)
    explanation: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ControlMeasureType(str, Enum):
    ORGANIZATIONAL = "organizational"
    TECHNICAL = "technical"
    SOFTWARE = "software"
    HARDWARE = "hardware"
    PROCESS = "process"
    OTHER = "other"


class ControlMeasureCandidate(BaseModel):
    measure_id: str = Field(..., description="Идентификатор меры защиты")
    name: str = Field(..., description="Наименование меры защиты")
    measure_type: ControlMeasureType = Field(default=ControlMeasureType.TECHNICAL)

    description: str = Field(default="")
    cost: float = Field(default=0.0, ge=0.0)
    labor: float = Field(default=0.0, ge=0.0)
    implementation_time: float = Field(default=0.0, ge=0.0)

    default_effectiveness: float = Field(
        default=0.10,
        ge=0.0,
        le=1.0,
        description="Базовая ожидаемая эффективность меры"
    )

    effectiveness_by_threat_scenario: Dict[str, float] = Field(default_factory=dict)
    effectiveness_by_event_type: Dict[str, float] = Field(default_factory=dict)

    applicable_threat_scenarios: List[ThreatScenario] = Field(default_factory=list)
    applicable_event_types: List[RiskEventType] = Field(default_factory=list)
    applicable_node_types: List[str] = Field(default_factory=list)
    applicable_asset_types: List[str] = Field(default_factory=list)
    applicable_processes: List[str] = Field(default_factory=list)

    incompatible_with: List[str] = Field(default_factory=list)
    requires: List[str] = Field(default_factory=list)

    metadata: Dict[str, Any] = Field(default_factory=dict)


class ControlOptimizationConstraints(BaseModel):
    max_budget: float = Field(default=1_000_000.0, ge=0.0)
    max_labor: float = Field(default=200.0, ge=0.0)
    max_implementation_time: float = Field(default=60.0, ge=0.0)
    max_measures: int = Field(default=5, ge=1)
    min_effectiveness: float = Field(default=0.03, ge=0.0, le=1.0)


class RecommendedControlMeasure(BaseModel):
    measure_id: str
    name: str
    measure_type: ControlMeasureType
    description: str = ""

    cost: float = Field(default=0.0, ge=0.0)
    labor: float = Field(default=0.0, ge=0.0)
    implementation_time: float = Field(default=0.0, ge=0.0)

    expected_risk_reduction: float = Field(default=0.0, ge=0.0)
    expected_residual_risk: float = Field(default=0.0, ge=0.0)
    covered_risk_event_ids: List[str] = Field(default_factory=list)
    covered_assessment_ids: List[str] = Field(default_factory=list)
    covered_node_ids: List[str] = Field(default_factory=list)
    rationale: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ControlOptimizationResult(BaseModel):
    selected_measures: List[RecommendedControlMeasure] = Field(default_factory=list)

    total_initial_risk: float = Field(default=0.0, ge=0.0)
    expected_total_risk_reduction: float = Field(default=0.0, ge=0.0)
    expected_total_residual_risk: float = Field(default=0.0, ge=0.0)

    total_cost: float = Field(default=0.0, ge=0.0)
    total_labor: float = Field(default=0.0, ge=0.0)
    total_implementation_time: float = Field(default=0.0, ge=0.0)

    constraints: ControlOptimizationConstraints
    explanation: List[str] = Field(default_factory=list)


class FullPipelineResponse(BaseModel):
    pipeline: EventPipelineResponse
    risk_assessments: List[RiskAssessmentRecord] = Field(default_factory=list)
    control_optimization: Optional[ControlOptimizationResult] = None

class PipelineSummary(BaseModel):
    logs_received: int = 0
    normalized_events_count: int = 0
    incident_candidates_count: int = 0
    risk_events_count: int = 0
    pipeline_stages: Dict[str, str] = Field(default_factory=dict)


class RuleEvidence(BaseModel):
    rule_id: str
    rule_name: str
    rule_source: str
    normative_basis: str
    technical_basis: str
    description: str


class InfrastructureLink(BaseModel):
    source_node_id: str = Field(..., description="Идентификатор исходного объекта инфраструктуры")
    target_node_id: str = Field(..., description="Идентификатор связанного объекта инфраструктуры")
    influence_weight: float = Field(
        default=0.10,
        ge=0.0,
        le=1.0,
        description="Вес влияния риска исходного объекта на связанный объект"
    )
    relation_type: str = Field(
        default="infrastructure_dependency",
        description="Тип инфраструктурной связи"
    )
    description: Optional[str] = Field(default=None)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EventPipelineRequest(BaseModel):
    logs: List[RawLogRecord]
    incident_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    risk_event_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    infrastructure_links: List[InfrastructureLink] = Field(default_factory=list)

    control_measures: List[ControlMeasureCandidate] = Field(default_factory=list)
    optimization_constraints: ControlOptimizationConstraints = Field(
        default_factory=ControlOptimizationConstraints
    )

class EventPipelineResponse(BaseModel):
    summary: PipelineSummary
    normalized_events: List[NormalizedSecurityEvent] = Field(default_factory=list)
    incidents: List[IncidentRecord] = Field(default_factory=list)
    risk_events: List[RiskEventRecord] = Field(default_factory=list)