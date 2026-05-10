from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from .schemas import (
    IncidentRecord,
    IncidentSeverity,
    IncidentStatus,
    IncidentType,
    RiskEventClassifierTrainingResponse,
    RiskEventClassifierTrainingSample,
    RiskEventClassifierFlatTrainingSample,
)


class IncidentMLFeatureBuilder:
    numeric_columns = [
        "classifier_confidence",
        "severity_level",
        "events_count",
        "failed_auth_count",
        "blocked_or_failed_count",
        "malware_event_count",
        "update_error_count",
        "access_denied_count",
        "data_operation_count",
        "system_error_count",
        "max_severity",
        "has_after_hours_activity",
        "has_admin_action",
        "has_edr_disabled",
        "has_malware_detected",
        "has_large_data_export",
        "has_critical_asset",
        "has_service_unavailable",
        "has_actual_loss",
        "potential_loss",
        "estimated_loss",
        "has_node",
        "has_asset",
        "has_affected_process",
    ]

    categorical_columns = [
        "incident_type",
        "severity",
        "node_type",
        "asset_type",
        "network_segment",
        "affected_process",
        "process_criticality",
        "confidentiality_impact",
        "integrity_impact",
        "availability_impact",
        "rule_id",
    ]

    def build_frame(self, incidents: List[IncidentRecord]) -> pd.DataFrame:
        rows = [self._incident_to_row(incident) for incident in incidents]
        return pd.DataFrame(rows)

    def feature_columns(self) -> List[str]:
        return [*self.numeric_columns, *self.categorical_columns]

    def _incident_to_row(self, incident: IncidentRecord) -> Dict[str, Any]:
        metadata = incident.metadata or {}

        return {
            "classifier_confidence": float(incident.classifier_confidence),
            "severity_level": self._severity_level(incident.severity),
            "events_count": self._as_float(metadata.get("events_count")),
            "failed_auth_count": self._as_float(metadata.get("failed_auth_count")),
            "blocked_or_failed_count": self._as_float(metadata.get("blocked_or_failed_count")),
            "malware_event_count": self._as_float(metadata.get("malware_event_count")),
            "update_error_count": self._as_float(metadata.get("update_error_count")),
            "access_denied_count": self._as_float(metadata.get("access_denied_count")),
            "data_operation_count": self._as_float(metadata.get("data_operation_count")),
            "system_error_count": self._as_float(metadata.get("system_error_count")),
            "max_severity": self._as_float(metadata.get("max_severity")),
            "has_after_hours_activity": self._as_int_bool(metadata.get("has_after_hours_activity")),
            "has_admin_action": self._as_int_bool(metadata.get("has_admin_action")),
            "has_edr_disabled": self._as_int_bool(metadata.get("has_edr_disabled")),
            "has_malware_detected": self._as_int_bool(metadata.get("has_malware_detected")),
            "has_large_data_export": self._as_int_bool(metadata.get("has_large_data_export")),
            "has_critical_asset": self._as_int_bool(metadata.get("has_critical_asset")),
            "has_service_unavailable": self._as_int_bool(metadata.get("has_service_unavailable")),
            "has_actual_loss": self._as_int_bool(metadata.get("has_actual_loss")),
            "potential_loss": self._as_float(metadata.get("potential_loss")),
            "estimated_loss": self._as_float(metadata.get("estimated_loss")),
            "has_node": int(bool(incident.node_id)),
            "has_asset": int(bool(incident.asset_id)),
            "has_affected_process": int(bool(incident.affected_process)),
            "incident_type": incident.incident_type.value,
            "severity": incident.severity.value,
            "node_type": self._as_text(metadata.get("node_type")),
            "asset_type": self._as_text(metadata.get("asset_type")),
            "network_segment": self._as_text(metadata.get("network_segment")),
            "affected_process": incident.affected_process or self._as_text(
                metadata.get("affected_process")
            ),
            "process_criticality": self._as_text(metadata.get("process_criticality")),
            "confidentiality_impact": self._as_text(metadata.get("confidentiality_impact")),
            "integrity_impact": self._as_text(metadata.get("integrity_impact")),
            "availability_impact": self._as_text(metadata.get("availability_impact")),
            "rule_id": self._as_text(metadata.get("rule_id")),
        }

    def _severity_level(self, severity: IncidentSeverity) -> int:
        mapping = {
            IncidentSeverity.LOW: 1,
            IncidentSeverity.MEDIUM: 2,
            IncidentSeverity.HIGH: 3,
            IncidentSeverity.CRITICAL: 4,
        }
        return mapping.get(severity, 0)

    def _as_float(self, value: object) -> float:
        try:
            if value is None:
                return 0.0
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    def _as_int_bool(self, value: object) -> int:
        if isinstance(value, bool):
            return int(value)

        if isinstance(value, int):
            return int(value != 0)

        if isinstance(value, str):
            return int(value.strip().lower() in {"true", "1", "yes", "да"})

        return 0

    def _as_text(self, value: object) -> str:
        if value is None:
            return "unknown"

        text = str(value).strip()
        if not text:
            return "unknown"

        return text


class RiskEventMLClassifier:
    def __init__(
        self,
        model_path: str | Path | None = None,
        model_type: str = "random_forest",
        random_state: int = 42,
    ) -> None:
        if model_path is None:
            project_root = Path(__file__).resolve().parents[2]
            model_path = project_root / "runtime" / "models" / "risk_event_classifier.joblib"

        self.model_path = Path(model_path)
        self.model_type = model_type
        self.random_state = random_state
        self.feature_builder = IncidentMLFeatureBuilder()
        self.pipeline: Optional[Pipeline] = None
        self.is_fitted = False

    def ensure_model(self) -> None:
        if self.is_fitted:
            return

        if self.model_path.exists():
            self.load(self.model_path)
            return

        bootstrap_samples = self.build_bootstrap_samples()
        self.fit(
            samples=bootstrap_samples,
            model_type=self.model_type,
            save_model=True,
        )

    def fit(
        self,
        samples: List[RiskEventClassifierTrainingSample],
        model_type: str = "random_forest",
        save_model: bool = True,
    ) -> RiskEventClassifierTrainingResponse:
        if not samples:
            raise ValueError("Для обучения классификатора событий риска передан пустой набор данных.")

        incidents = [sample.incident for sample in samples]
        target = np.asarray([sample.target for sample in samples], dtype=int)

        if len(np.unique(target)) < 2:
            raise ValueError(
                "В обучающей выборке должны быть представлены оба класса: 0 и 1."
            )

        x_frame = self.feature_builder.build_frame(incidents)
        self.pipeline = self._build_pipeline(model_type=model_type)
        self.model_type = model_type

        metrics: Dict[str, Optional[float]] = {
            "accuracy": None,
            "precision": None,
            "recall": None,
            "f1": None,
            "roc_auc": None,
        }

        can_split = self._can_use_train_test_split(target)

        if can_split:
            x_train, x_test, y_train, y_test = train_test_split(
                x_frame,
                target,
                test_size=0.25,
                random_state=self.random_state,
                stratify=target,
            )

            self.pipeline.fit(x_train, y_train)
            metrics = self._evaluate(x_test, y_test)
        else:
            self.pipeline.fit(x_frame, target)
            metrics = self._evaluate(x_frame, target)

        self.is_fitted = True

        if save_model:
            self.save(self.model_path)

        return RiskEventClassifierTrainingResponse(
            model_type=self.model_type,
            samples_count=len(samples),
            positive_count=int(target.sum()),
            negative_count=int(len(target) - target.sum()),
            accuracy=metrics["accuracy"],
            precision=metrics["precision"],
            recall=metrics["recall"],
            f1=metrics["f1"],
            roc_auc=metrics["roc_auc"],
            model_path=str(self.model_path) if save_model else None,
            feature_columns=self.feature_builder.feature_columns(),
        )

    def predict_proba(self, incidents: List[IncidentRecord]) -> np.ndarray:
        self.ensure_model()

        if self.pipeline is None:
            raise RuntimeError("ML-классификатор событий риска не обучен.")

        x_frame = self.feature_builder.build_frame(incidents)
        probabilities = self.pipeline.predict_proba(x_frame)

        model = self.pipeline.named_steps["model"]
        classes = list(model.classes_)

        if 1 not in classes:
            raise RuntimeError("Обученная модель не содержит положительный класс 1.")

        positive_index = classes.index(1)
        return probabilities[:, positive_index]

    def save(self, path: str | Path) -> None:
        if self.pipeline is None or not self.is_fitted:
            raise RuntimeError("Невозможно сохранить необученную модель.")

        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "model_type": self.model_type,
            "random_state": self.random_state,
            "pipeline": self.pipeline,
            "feature_columns": self.feature_builder.feature_columns(),
        }

        joblib.dump(payload, file_path)

    def load(self, path: str | Path) -> None:
        file_path = Path(path)
        payload = joblib.load(file_path)

        self.model_type = payload["model_type"]
        self.random_state = payload["random_state"]
        self.pipeline = payload["pipeline"]
        self.is_fitted = True

    def build_samples_from_flat(
        self,
        flat_samples: List[RiskEventClassifierFlatTrainingSample],
    ) -> List[RiskEventClassifierTrainingSample]:
        result: List[RiskEventClassifierTrainingSample] = []

        for index, sample in enumerate(flat_samples, start=1):
            incident_id = sample.incident_id or f"train_inc_{index:05d}"

            metadata = {
                "events_count": sample.events_count,
                "failed_auth_count": sample.failed_auth_count,
                "blocked_or_failed_count": sample.blocked_or_failed_count,
                "malware_event_count": sample.malware_event_count,
                "update_error_count": sample.update_error_count,
                "access_denied_count": sample.access_denied_count,
                "data_operation_count": sample.data_operation_count,
                "system_error_count": sample.system_error_count,
                "max_severity": sample.max_severity,
                "has_after_hours_activity": sample.has_after_hours_activity,
                "has_admin_action": sample.has_admin_action,
                "has_edr_disabled": sample.has_edr_disabled,
                "has_malware_detected": sample.has_malware_detected,
                "has_large_data_export": sample.has_large_data_export,
                "has_critical_asset": sample.has_critical_asset,
                "has_service_unavailable": sample.has_service_unavailable,
                "has_actual_loss": sample.has_actual_loss,
                "potential_loss": sample.potential_loss,
                "estimated_loss": sample.estimated_loss,
                "node_type": sample.node_type,
                "asset_type": sample.asset_type,
                "network_segment": sample.network_segment,
                "affected_process": sample.affected_process or "unknown",
                "process_criticality": sample.process_criticality,
                "confidentiality_impact": sample.confidentiality_impact,
                "integrity_impact": sample.integrity_impact,
                "availability_impact": sample.availability_impact,
                "rule_id": sample.rule_id,
                "training_source": "flat_training_sample",
            }

            incident = IncidentRecord(
                incident_id=incident_id,
                created_from_event_ids=[],
                detected_at=None,
                incident_type=sample.incident_type,
                severity=sample.severity,
                status=IncidentStatus.CONFIRMED,
                node_id=sample.node_id,
                asset_id=sample.asset_id,
                affected_process=sample.affected_process,
                description="Размеченный пример для обучения ML-классификатора событий риска.",
                classifier_confidence=sample.classifier_confidence,
                evidence=[],
                metadata=metadata,
            )

            result.append(
                RiskEventClassifierTrainingSample(
                    incident=incident,
                    target=sample.target,
                    expected_event_type=sample.expected_event_type,
                    expected_threat_scenario=sample.expected_threat_scenario,
                )
            )

        return result

    def build_bootstrap_samples(self) -> List[RiskEventClassifierTrainingSample]:
        incidents = [
            self._make_incident(
                incident_id="boot_inc_001",
                incident_type=IncidentType.SECURITY_UPDATE_FAILURE,
                severity=IncidentSeverity.HIGH,
                confidence=0.90,
                node_id="node_app_01",
                asset_id="asset_payments",
                affected_process="payment_processing",
                metadata={
                    "events_count": 2,
                    "update_error_count": 2,
                    "has_edr_disabled": True,
                    "has_critical_asset": True,
                    "potential_loss": 750000,
                    "node_type": "application_server",
                    "asset_type": "payment_system",
                    "network_segment": "payment_processing",
                    "process_criticality": "critical",
                    "availability_impact": "high",
                    "integrity_impact": "high",
                    "rule_id": "IR-001",
                },
            ),
            self._make_incident(
                incident_id="boot_inc_002",
                incident_type=IncidentType.MALWARE_ACTIVITY,
                severity=IncidentSeverity.CRITICAL,
                confidence=0.95,
                node_id="node_db_01",
                asset_id="asset_clients_db",
                affected_process="client_data_processing",
                metadata={
                    "events_count": 1,
                    "malware_event_count": 1,
                    "has_malware_detected": True,
                    "has_critical_asset": True,
                    "potential_loss": 1500000,
                    "node_type": "database_server",
                    "asset_type": "client_database",
                    "network_segment": "data_processing",
                    "process_criticality": "critical",
                    "confidentiality_impact": "critical",
                    "integrity_impact": "high",
                    "rule_id": "IR-002",
                },
            ),
            self._make_incident(
                incident_id="boot_inc_003",
                incident_type=IncidentType.DATA_LEAK_SIGNS,
                severity=IncidentSeverity.HIGH,
                confidence=0.88,
                node_id="node_file_01",
                asset_id="asset_reports",
                affected_process="reporting",
                metadata={
                    "events_count": 3,
                    "data_operation_count": 3,
                    "has_large_data_export": True,
                    "has_after_hours_activity": True,
                    "has_critical_asset": True,
                    "potential_loss": 900000,
                    "node_type": "file_server",
                    "asset_type": "confidential_documents",
                    "network_segment": "office",
                    "process_criticality": "high",
                    "confidentiality_impact": "critical",
                    "rule_id": "IR-005",
                },
            ),
            self._make_incident(
                incident_id="boot_inc_004",
                incident_type=IncidentType.ACCOUNT_COMPROMISE_SIGNS,
                severity=IncidentSeverity.HIGH,
                confidence=0.82,
                node_id="node_vpn_01",
                asset_id="asset_remote_access",
                affected_process="remote_access",
                metadata={
                    "events_count": 8,
                    "failed_auth_count": 8,
                    "has_after_hours_activity": True,
                    "has_admin_action": True,
                    "potential_loss": 600000,
                    "node_type": "vpn_gateway",
                    "asset_type": "access_service",
                    "network_segment": "perimeter",
                    "process_criticality": "high",
                    "confidentiality_impact": "high",
                    "rule_id": "IR-003",
                },
            ),
            self._make_incident(
                incident_id="boot_inc_005",
                incident_type=IncidentType.UNAUTHORIZED_ACCESS,
                severity=IncidentSeverity.HIGH,
                confidence=0.80,
                node_id="node_admin_01",
                asset_id="asset_admin_console",
                affected_process="administration",
                metadata={
                    "events_count": 2,
                    "access_denied_count": 2,
                    "has_admin_action": True,
                    "has_critical_asset": True,
                    "potential_loss": 800000,
                    "node_type": "admin_console",
                    "asset_type": "privileged_access",
                    "network_segment": "management",
                    "process_criticality": "critical",
                    "integrity_impact": "high",
                    "rule_id": "IR-004",
                },
            ),
            self._make_incident(
                incident_id="boot_inc_006",
                incident_type=IncidentType.SERVICE_UNAVAILABILITY,
                severity=IncidentSeverity.CRITICAL,
                confidence=0.92,
                node_id="node_core_01",
                asset_id="asset_core_banking",
                affected_process="core_banking",
                metadata={
                    "events_count": 4,
                    "system_error_count": 4,
                    "has_service_unavailable": True,
                    "has_critical_asset": True,
                    "potential_loss": 1500000,
                    "node_type": "application_server",
                    "asset_type": "core_banking_system",
                    "network_segment": "core",
                    "process_criticality": "critical",
                    "availability_impact": "critical",
                    "rule_id": "IR-SERVICE",
                },
            ),
            self._make_incident(
                incident_id="boot_inc_007",
                incident_type=IncidentType.SECURITY_UPDATE_FAILURE,
                severity=IncidentSeverity.LOW,
                confidence=0.45,
                node_id="node_test_01",
                asset_id="asset_test",
                affected_process=None,
                metadata={
                    "events_count": 1,
                    "update_error_count": 1,
                    "has_edr_disabled": False,
                    "has_critical_asset": False,
                    "potential_loss": 20000,
                    "node_type": "test_host",
                    "asset_type": "test_environment",
                    "network_segment": "test",
                    "process_criticality": "low",
                    "availability_impact": "low",
                    "rule_id": "IR-001",
                },
            ),
            self._make_incident(
                incident_id="boot_inc_008",
                incident_type=IncidentType.CONFIGURATION_VIOLATION,
                severity=IncidentSeverity.LOW,
                confidence=0.40,
                node_id="node_user_01",
                asset_id="asset_workstation",
                affected_process=None,
                metadata={
                    "events_count": 1,
                    "has_critical_asset": False,
                    "potential_loss": 10000,
                    "node_type": "workstation",
                    "asset_type": "user_device",
                    "network_segment": "office",
                    "process_criticality": "low",
                    "rule_id": "IR-CONFIG",
                },
            ),
            self._make_incident(
                incident_id="boot_inc_009",
                incident_type=IncidentType.ACCOUNT_COMPROMISE_SIGNS,
                severity=IncidentSeverity.MEDIUM,
                confidence=0.55,
                node_id="node_auth_01",
                asset_id="asset_auth",
                affected_process=None,
                metadata={
                    "events_count": 5,
                    "failed_auth_count": 5,
                    "has_after_hours_activity": False,
                    "has_admin_action": False,
                    "has_critical_asset": False,
                    "potential_loss": 50000,
                    "node_type": "auth_server",
                    "asset_type": "authentication_service",
                    "network_segment": "internal",
                    "process_criticality": "medium",
                    "rule_id": "IR-003",
                },
            ),
            self._make_incident(
                incident_id="boot_inc_010",
                incident_type=IncidentType.OTHER,
                severity=IncidentSeverity.LOW,
                confidence=0.30,
                node_id="node_misc_01",
                asset_id="asset_misc",
                affected_process=None,
                metadata={
                    "events_count": 1,
                    "has_critical_asset": False,
                    "potential_loss": 0,
                    "node_type": "workstation",
                    "asset_type": "misc",
                    "network_segment": "office",
                    "process_criticality": "low",
                    "rule_id": "IR-OTHER",
                },
            ),
        ]

        labels = [1, 1, 1, 1, 1, 1, 0, 0, 0, 0]

        return [
            RiskEventClassifierTrainingSample(incident=incident, target=target)
            for incident, target in zip(incidents, labels)
        ]

    def _build_pipeline(self, model_type: str) -> Pipeline:
        preprocessor = ColumnTransformer(
            transformers=[
                (
                    "num",
                    StandardScaler(),
                    self.feature_builder.numeric_columns,
                ),
                (
                    "cat",
                    self._build_one_hot_encoder(),
                    self.feature_builder.categorical_columns,
                ),
            ],
            remainder="drop",
        )

        model = self._build_model(model_type)

        return Pipeline(
            steps=[
                ("preprocessor", preprocessor),
                ("model", model),
            ]
        )

    def _build_model(self, model_type: str):
        if model_type == "random_forest":
            return RandomForestClassifier(
                n_estimators=250,
                max_depth=8,
                min_samples_split=4,
                min_samples_leaf=2,
                class_weight="balanced",
                random_state=self.random_state,
            )

        if model_type == "gradient_boosting":
            return GradientBoostingClassifier(
                n_estimators=120,
                learning_rate=0.05,
                max_depth=3,
                random_state=self.random_state,
            )

        if model_type == "logistic_regression":
            return LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=self.random_state,
            )

        raise ValueError(
            "Неизвестный тип модели. Поддерживаются: "
            "random_forest, gradient_boosting, logistic_regression."
        )

    def _evaluate(self, x_frame: pd.DataFrame, y_true: np.ndarray) -> Dict[str, Optional[float]]:
        if self.pipeline is None:
            raise RuntimeError("ML-конвейер не инициализирован.")

        y_proba = self.predict_proba_from_frame(x_frame)
        y_pred = (y_proba >= 0.5).astype(int)

        metrics: Dict[str, Optional[float]] = {
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, zero_division=0)),
            "f1": float(f1_score(y_true, y_pred, zero_division=0)),
            "roc_auc": None,
        }

        if len(np.unique(y_true)) > 1:
            metrics["roc_auc"] = float(roc_auc_score(y_true, y_proba))

        return metrics

    def predict_proba_from_frame(self, x_frame: pd.DataFrame) -> np.ndarray:
        if self.pipeline is None:
            raise RuntimeError("ML-конвейер не инициализирован.")

        probabilities = self.pipeline.predict_proba(x_frame)
        model = self.pipeline.named_steps["model"]
        classes = list(model.classes_)

        if 1 not in classes:
            raise RuntimeError("Обученная модель не содержит положительный класс 1.")

        return probabilities[:, classes.index(1)]

    def _can_use_train_test_split(self, target: np.ndarray) -> bool:
        if len(target) < 8:
            return False

        values, counts = np.unique(target, return_counts=True)
        if len(values) < 2:
            return False

        return bool(np.min(counts) >= 2)

    def _make_incident(
        self,
        incident_id: str,
        incident_type: IncidentType,
        severity: IncidentSeverity,
        confidence: float,
        node_id: Optional[str],
        asset_id: Optional[str],
        affected_process: Optional[str],
        metadata: Dict[str, Any],
    ) -> IncidentRecord:
        return IncidentRecord(
            incident_id=incident_id,
            created_from_event_ids=[],
            detected_at=None,
            incident_type=incident_type,
            severity=severity,
            status=IncidentStatus.CONFIRMED,
            node_id=node_id,
            asset_id=asset_id,
            affected_process=affected_process,
            description="Экспертно размеченный пример для начального обучения ML-классификатора.",
            classifier_confidence=confidence,
            evidence=[],
            metadata=metadata,
        )

    @staticmethod
    def _build_one_hot_encoder() -> OneHotEncoder:
        try:
            return OneHotEncoder(handle_unknown="ignore", sparse_output=False)
        except TypeError:
            return OneHotEncoder(handle_unknown="ignore", sparse=False)