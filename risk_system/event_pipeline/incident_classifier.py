from __future__ import annotations

import hashlib
from typing import List

from .correlator import EventCorrelator, EventGroup
from .rules import IncidentRuleEngine, IncidentRuleResult
from .schemas import IncidentRecord, IncidentStatus, NormalizedSecurityEvent


class IncidentClassifier:
    def __init__(self) -> None:
        self.correlator = EventCorrelator()
        self.rule_engine = IncidentRuleEngine()

    def classify_many(
        self,
        events: List[NormalizedSecurityEvent],
        threshold: float = 0.5,
    ) -> List[IncidentRecord]:
        groups = self.correlator.correlate(events)
        incidents: List[IncidentRecord] = []

        for group in groups:
            rule_result = self.rule_engine.apply(group)

            if rule_result is None:
                continue

            if rule_result.score < threshold:
                continue

            incidents.append(self._build_incident(group, rule_result))

        return incidents

    def _build_incident(
        self,
        group: EventGroup,
        rule_result: IncidentRuleResult,
    ) -> IncidentRecord:
        return IncidentRecord(
            incident_id=self._make_incident_id(group, rule_result),
            created_from_event_ids=group.event_ids,
            detected_at=self._detect_time(group),
            incident_type=rule_result.incident_type,
            severity=rule_result.severity,
            status=IncidentStatus.NEW,
            node_id=group.node_id,
            asset_id=group.asset_id,
            affected_process=self._optional_text(group.features.get("affected_process")),
            description=rule_result.description,
            classifier_confidence=rule_result.score,
            evidence=[
                f"{rule_result.rule_id}: {rule_result.rule_name}",
                *rule_result.evidence,
            ],
            metadata={
                "correlation_group_id": group.group_id,
                "correlation_key": group.correlation_key,
                "events_count": len(group.events),
                "rule_id": rule_result.rule_id,
                "rule_name": rule_result.rule_name,
                "rule_source": "formalized_expert_rule",
                "normative_basis": rule_result.normative_basis,
                "technical_basis": rule_result.technical_basis,
                "normative_stage": "security_event_to_information_security_incident",
                **group.features,
            },
        )

    def _make_incident_id(
        self,
        group: EventGroup,
        rule_result: IncidentRuleResult,
    ) -> str:
        raw = f"{group.group_id}|{rule_result.rule_id}|{rule_result.incident_type.value}"
        digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
        return f"inc_{digest}"

    def _detect_time(self, group: EventGroup) -> str | None:
        timestamps = [event.timestamp for event in group.events if event.timestamp]
        if not timestamps:
            return None
        return sorted(timestamps)[0]

    def _optional_text(self, value: object) -> str | None:
        if value is None:
            return None

        text = str(value).strip()
        if not text or text == "unknown":
            return None

        return text