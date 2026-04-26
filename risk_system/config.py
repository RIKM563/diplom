from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ApiSettings:
    title: str = "Risk System API"
    version: str = "1.0.0"
    description: str = (
        "API для автоматизации анализа и оценки рисков ИБ "
        "корпоративных систем банка."
    )
    host: str = "127.0.0.1"
    port: int = 8000
    reload: bool = True


@dataclass
class ModelSettings:
    default_model_type: str = "random_forest"
    random_state: int = 42


@dataclass
class CalibrationSettings:
    method: str = "isotonic"


@dataclass
class RiskThresholdSettings:
    # mode: str = "fixed"
    mode: str = "empirical"
    low_threshold: float = 0.20
    medium_threshold: float = 0.50
    high_threshold: float = 0.80

    empirical_low_quantile: float = 0.50
    empirical_medium_quantile: float = 0.75
    empirical_high_quantile: float = 0.90

    min_threshold_gap: float = 0.02


@dataclass
@dataclass
class PropagationSettings:
    alpha: float = 0.70
    decay: float = 0.85
    max_iter: int = 20
    tol: float = 1e-4
    clip_to_unit: bool = True
    blend: float = 0.50
    max_growth_factor: float = 1.35
    growth_margin: float = 0.20


@dataclass
class InfluenceSettings:
    self_weight: float = 1.0
    normalize_rows: bool = True
    min_weight: float = 0.0
    max_weight: float = 1.0
    trust_weight: float = 0.25
    same_segment_bonus: float = 0.15
    cross_segment_penalty: float = 0.10
    same_service_bonus: float = 0.20
    node_type_matrix: dict[str, dict[str, float]] = field(default_factory=lambda: {
        "gateway": {"server": 1.15, "application": 1.10, "database": 0.95},
        "application": {"server": 1.08, "database": 1.10, "gateway": 0.95},
        "server": {"database": 1.12, "application": 1.05, "server": 1.00},
        "database": {"database": 1.00, "server": 0.95, "application": 0.90},
    })


@dataclass
class ImpactSettings:
    event_component_weight: float = 0.55
    asset_component_weight: float = 0.45

    severity_weight: float = 0.25
    frequency_weight: float = 0.12
    anomaly_weight: float = 0.18
    vulnerability_weight: float = 0.12
    privilege_weight: float = 0.10
    exposure_weight: float = 0.13
    event_context_weight: float = 0.10

    cost_weight: float = 0.15
    data_sensitivity_weight: float = 0.25
    regulatory_weight: float = 0.15
    client_exposure_weight: float = 0.15
    business_criticality_weight: float = 0.20
    tier_weight: float = 0.10

    node_criticality_weight: float = 0.35
    asset_criticality_weight: float = 0.45
    business_context_weight: float = 0.20

    frequency_scale: float = 100.0
    asset_cost_scale: float = 1_000_000.0
    tier_scale: float = 4.0
    failed_logins_scale: float = 10.0
    suspicious_processes_scale: float = 10.0
    open_ports_scale: float = 20.0
    large_transfer_scale: float = 1500.0

    threat_multipliers: dict[str, float] = field(default_factory=lambda: {
        "malware": 1.05,
        "phishing": 1.00,
        "privilege_escalation": 1.12,
        "data_leak": 1.20,
        "ddos": 1.08,
        "unauthorized_access": 1.10,
        "misconfiguration": 0.92,
        "insider": 1.18,
        "other": 1.00,
    })


@dataclass
class OptimizationSettings:
    min_effectiveness: float = 0.0
    require_applicability: bool = True
    class_weights: dict[str, float] = field(default_factory=lambda: {
        "low": 1.0,
        "medium": 1.4,
        "high": 1.9,
        "critical": 2.8,
    })


@dataclass
class PathSettings:
    project_root: Path = field(default_factory=lambda: Path(__file__).resolve().parent)
    artifacts_dir: Path = field(init=False)
    models_dir: Path = field(init=False)
    data_dir: Path = field(init=False)
    templates_dir: Path = field(init=False)
    static_dir: Path = field(init=False)

    def __post_init__(self) -> None:
        self.artifacts_dir = self.project_root / "artifacts"
        self.models_dir = self.artifacts_dir / "models"
        self.data_dir = self.project_root / "data_files"
        self.templates_dir = self.project_root / "templates"
        self.static_dir = self.project_root / "static"

        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self.static_dir.mkdir(parents=True, exist_ok=True)


@dataclass
class BayesianSettings:
    group_key: str = "node_id"
    min_probability: float = 0.0
    max_probability: float = 1.0
    dependencies: dict[str, list[dict[str, float | str]]] = field(default_factory=lambda: {
        "unauthorized_access": [
            {"parent": "phishing", "weight": 0.28, "dependency_type": "prerequisite"},
            {"parent": "misconfiguration", "weight": 0.22, "dependency_type": "supporting"},
        ],
        "privilege_escalation": [
            {"parent": "unauthorized_access", "weight": 0.38, "dependency_type": "escalation"},
            {"parent": "misconfiguration", "weight": 0.20, "dependency_type": "supporting"},
        ],
        "data_leak": [
            {"parent": "privilege_escalation", "weight": 0.34, "dependency_type": "escalation"},
            {"parent": "unauthorized_access", "weight": 0.20, "dependency_type": "direct"},
            {"parent": "insider", "weight": 0.30, "dependency_type": "direct"},
        ],
        "malware": [
            {"parent": "phishing", "weight": 0.24, "dependency_type": "prerequisite"},
        ],
    })

@dataclass
class Settings:
    api: ApiSettings = field(default_factory=ApiSettings)
    model: ModelSettings = field(default_factory=ModelSettings)
    calibration: CalibrationSettings = field(default_factory=CalibrationSettings)
    risk_thresholds: RiskThresholdSettings = field(default_factory=RiskThresholdSettings)
    propagation: PropagationSettings = field(default_factory=PropagationSettings)
    influence: InfluenceSettings = field(default_factory=InfluenceSettings)
    impact: ImpactSettings = field(default_factory=ImpactSettings)
    optimization: OptimizationSettings = field(default_factory=OptimizationSettings)
    paths: PathSettings = field(default_factory=PathSettings)
    bayesian: BayesianSettings = field(default_factory=BayesianSettings)


settings = Settings()