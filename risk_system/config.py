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
    low_threshold: float = 0.20
    medium_threshold: float = 0.50
    high_threshold: float = 0.80


@dataclass
class PropagationSettings:
    alpha: float = 0.70
    max_iter: int = 20
    tol: float = 1e-4
    clip_to_unit: bool = True
    blend: float = 0.50


@dataclass
class InfluenceSettings:
    self_weight: float = 1.0
    normalize_rows: bool = True
    min_weight: float = 0.0


@dataclass
class ImpactSettings:
    severity_weight: float = 0.30
    frequency_weight: float = 0.15
    anomaly_weight: float = 0.20
    vulnerability_weight: float = 0.15
    privilege_weight: float = 0.10
    exposure_weight: float = 0.10
    node_criticality_weight: float = 0.40
    asset_criticality_weight: float = 0.60
    frequency_scale: float = 100.0
    asset_cost_scale: float = 1_000_000.0


@dataclass
class OptimizationSettings:
    min_effectiveness: float = 0.0


@dataclass
class PathSettings:
    project_root: Path = field(default_factory=lambda: Path(__file__).resolve().parent)
    artifacts_dir: Path = field(init=False)
    models_dir: Path = field(init=False)
    data_dir: Path = field(init=False)

    def __post_init__(self) -> None:
        self.artifacts_dir = self.project_root / "artifacts"
        self.models_dir = self.artifacts_dir / "models"
        self.data_dir = self.project_root / "data_files"

        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)


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


settings = Settings()