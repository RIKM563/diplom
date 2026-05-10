from __future__ import annotations

import hashlib
from typing import List

from .risk_event_ml import RiskEventMLClassifier
from .schemas import (
    IncidentRecord,
    IncidentSeverity,
    IncidentType,
    RiskEventClassifierTrainingResponse,
    RiskEventClassifierTrainingSample,
    RiskEventClassifierFlatTrainingSample,
    RiskEventRecord,
    RiskEventType,
    ThreatScenario,
)


class RiskEventClassifier:
    def __init__(self) -> None:
        self.ml_classifier = RiskEventMLClassifier()
        self.ml_classifier.ensure_model()

    def classify_many(
        self,
        incidents: List[IncidentRecord],
        threshold: float = 0.5,
    ) -> List[RiskEventRecord]:
        if not incidents:
            return []

        probabilities = self.ml_classifier.predict_proba(incidents)
        risk_events: List[RiskEventRecord] = []

        for incident, probability in zip(incidents, probabilities):
            score = float(probability)

            if score < threshold:
                continue

            event_type, scenario = self._map_incident_to_risk_event(incident)

            risk_events.append(
                RiskEventRecord(
                    risk_event_id=self._make_risk_event_id(incident),
                    incident_id=incident.incident_id,
                    event_type=event_type,
                    threat_scenario=scenario,
                    node_id=incident.node_id,
                    asset_id=incident.asset_id,
                    affected_process=incident.affected_process,
                    has_actual_loss=self._as_bool(incident.metadata.get("has_actual_loss")),
                    estimated_loss=self._as_float(incident.metadata.get("estimated_loss")),
                    potential_loss=self._estimate_potential_loss(incident),
                    probability_estimate=score,
                    impact_estimate=self._estimate_impact(incident),
                    registration_threshold_reached=True,
                    classifier_confidence=score,
                    rationale=[
                        "Инцидент защиты информации отнесен к событию риска реализации информационных угроз ML-классификатором.",
                        f"Расчетная вероятность отнесения к событию риска: {score:.4f}.",
                        f"Тип инцидента: {incident.incident_type.value}.",
                        f"Уровень инцидента: {incident.severity.value}.",
                    ],
                    metadata={
                        **incident.metadata,
                        "risk_event_classifier": "ml",
                        "ml_model_type": self.ml_classifier.model_type,
                        "risk_event_threshold": threshold,
                        "normative_stage": "incident_to_risk_event",
                    },
                )
            )

        return risk_events

    def train(
        self,
        samples: List[RiskEventClassifierTrainingSample],
        model_type: str = "random_forest",
        save_model: bool = True,
    ) -> RiskEventClassifierTrainingResponse:
        return self.ml_classifier.fit(
            samples=samples,
            model_type=model_type,
            save_model=save_model,
        )

    def train_flat(
        self,
        samples: List[RiskEventClassifierFlatTrainingSample],
        model_type: str = "random_forest",
        save_model: bool = True,
    ) -> RiskEventClassifierTrainingResponse:
        training_samples = self.ml_classifier.build_samples_from_flat(samples)

        return self.ml_classifier.fit(
            samples=training_samples,
            model_type=model_type,
            save_model=save_model,
        )

    def _map_incident_to_risk_event(
        self,
        incident: IncidentRecord,
    ) -> tuple[RiskEventType, ThreatScenario]:
        if incident.incident_type == IncidentType.UNAUTHORIZED_ACCESS:
            return RiskEventType.CONFIDENTIALITY_VIOLATION, ThreatScenario.UNAUTHORIZED_ACCESS

        if incident.incident_type == IncidentType.ACCOUNT_COMPROMISE_SIGNS:
            return RiskEventType.CONFIDENTIALITY_VIOLATION, ThreatScenario.PHISHING

        if incident.incident_type == IncidentType.MALWARE_ACTIVITY:
            return RiskEventType.INTEGRITY_VIOLATION, ThreatScenario.MALWARE

        if incident.incident_type == IncidentType.DATA_LEAK_SIGNS:
            return RiskEventType.CONFIDENTIALITY_VIOLATION, ThreatScenario.DATA_LEAK

        if incident.incident_type == IncidentType.SERVICE_UNAVAILABILITY:
            return RiskEventType.AVAILABILITY_VIOLATION, ThreatScenario.DDOS

        if incident.incident_type == IncidentType.SECURITY_UPDATE_FAILURE:
            return RiskEventType.REGULATORY_REQUIREMENT_VIOLATION, ThreatScenario.MISCONFIGURATION

        if incident.incident_type == IncidentType.CONFIGURATION_VIOLATION:
            return RiskEventType.REGULATORY_REQUIREMENT_VIOLATION, ThreatScenario.MISCONFIGURATION

        if incident.incident_type == IncidentType.PRIVILEGE_ESCALATION_SIGNS:
            return RiskEventType.INTEGRITY_VIOLATION, ThreatScenario.PRIVILEGE_ESCALATION

        return RiskEventType.OTHER, ThreatScenario.OTHER

    def _estimate_potential_loss(self, incident: IncidentRecord) -> float:
        explicit_loss = self._as_float(incident.metadata.get("potential_loss"))
        if explicit_loss > 0:
            return explicit_loss

        base = {
            IncidentSeverity.LOW: 50_000.0,
            IncidentSeverity.MEDIUM: 250_000.0,
            IncidentSeverity.HIGH: 750_000.0,
            IncidentSeverity.CRITICAL: 1_500_000.0,
        }[incident.severity]

        if self._as_bool(incident.metadata.get("has_critical_asset")):
            base *= 1.25

        return base

    def _estimate_impact(self, incident: IncidentRecord) -> float:
        potential_loss = self._estimate_potential_loss(incident)
        impact = min(1.0, potential_loss / 1_500_000.0)

        if self._as_bool(incident.metadata.get("has_service_unavailable")):
            impact += 0.10

        if self._as_bool(incident.metadata.get("has_large_data_export")):
            impact += 0.10

        if self._as_bool(incident.metadata.get("has_edr_disabled")):
            impact += 0.05

        return max(0.0, min(1.0, impact))

    def _make_risk_event_id(self, incident: IncidentRecord) -> str:
        raw = (
            f"{incident.incident_id}|"
            f"{incident.incident_type.value}|"
            f"{incident.node_id}|"
            f"{incident.asset_id}|"
            f"ml"
        )
        digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
        return f"risk_evt_{digest}"

    def _as_float(self, value: object) -> float:
        try:
            if value is None:
                return 0.0
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    def _as_bool(self, value: object) -> bool:
        if isinstance(value, bool):
            return value

        if isinstance(value, int):
            return value != 0

        if isinstance(value, str):
            return value.strip().lower() in {"true", "1", "yes", "да"}

        return False