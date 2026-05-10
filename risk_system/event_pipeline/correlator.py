from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .schemas import EventResult, NormalizedSecurityEvent, SecurityEventCategory


@dataclass
class EventGroup:
    group_id: str
    events: List[NormalizedSecurityEvent]
    correlation_key: str
    node_id: Optional[str] = None
    asset_id: Optional[str] = None
    subject_id: Optional[str] = None
    src_ip: Optional[str] = None
    features: Dict[str, float | int | str | bool] = field(default_factory=dict)

    @property
    def event_ids(self) -> List[str]:
        return [event.event_id for event in self.events]


class EventCorrelator:
    def correlate(self, events: List[NormalizedSecurityEvent]) -> List[EventGroup]:
        buckets: Dict[str, List[NormalizedSecurityEvent]] = {}

        for event in events:
            key = self._build_group_key(event)
            buckets.setdefault(key, []).append(event)

        groups: List[EventGroup] = []

        for key, grouped_events in buckets.items():
            groups.append(
                EventGroup(
                    group_id=self._make_group_id(key, grouped_events),
                    events=grouped_events,
                    correlation_key=key,
                    node_id=self._first_not_empty([event.node_id for event in grouped_events]),
                    asset_id=self._first_not_empty([event.asset_id for event in grouped_events]),
                    subject_id=self._first_not_empty([event.subject_id for event in grouped_events]),
                    src_ip=self._first_not_empty([event.src_ip for event in grouped_events]),
                    features=self._build_group_features(grouped_events),
                )
            )

        return groups

    def _build_group_key(self, event: NormalizedSecurityEvent) -> str:
        parts = [
            event.node_id or "",
            event.asset_id or "",
            event.subject_id or "",
            event.src_ip or "",
            event.correlation_key or "",
        ]

        key = "|".join(part for part in parts if part)

        if key:
            return key

        return event.event_id

    def _build_group_features(
            self,
            events: List[NormalizedSecurityEvent],
    ) -> Dict[str, float | int | str | bool]:
        failed_auth_count = 0
        blocked_or_failed_count = 0
        malware_event_count = 0
        update_error_count = 0
        access_denied_count = 0
        data_operation_count = 0
        system_error_count = 0
        max_severity = 0.0

        has_after_hours_activity = False
        has_admin_action = False
        has_edr_disabled = False
        has_malware_detected = False
        has_large_data_export = False
        has_critical_asset = False
        has_service_unavailable = False
        has_actual_loss = False

        potential_loss_values: List[float] = []
        estimated_loss_values: List[float] = []

        affected_process = "unknown"
        node_type = "unknown"
        asset_type = "unknown"
        network_segment = "unknown"
        process_criticality = "unknown"
        confidentiality_impact = "unknown"
        integrity_impact = "unknown"
        availability_impact = "unknown"

        for event in events:
            max_severity = max(max_severity, event.normalized_severity)

            if event.result in {EventResult.FAILURE, EventResult.ERROR, EventResult.BLOCKED}:
                blocked_or_failed_count += 1

            if (
                    event.event_category == SecurityEventCategory.AUTHENTICATION
                    and event.result in {EventResult.FAILURE, EventResult.ERROR, EventResult.BLOCKED}
            ):
                failed_auth_count += 1

            if event.event_category == SecurityEventCategory.MALWARE_PROTECTION:
                malware_event_count += 1

            if (
                    event.event_category == SecurityEventCategory.SOFTWARE_UPDATE
                    and event.result in {EventResult.FAILURE, EventResult.ERROR}
            ):
                update_error_count += 1

            if (
                    event.event_category == SecurityEventCategory.ACCESS_CONTROL
                    and event.result in {EventResult.FAILURE, EventResult.ERROR, EventResult.BLOCKED}
            ):
                access_denied_count += 1

            if event.event_category == SecurityEventCategory.DATA_OPERATION:
                data_operation_count += 1

            if event.event_category == SecurityEventCategory.SYSTEM_ERROR:
                system_error_count += 1

            metadata = event.metadata or {}

            has_after_hours_activity = has_after_hours_activity or self._as_bool(
                metadata.get("after_hours_activity")
            )
            has_admin_action = has_admin_action or self._as_bool(metadata.get("admin_action"))
            has_edr_disabled = has_edr_disabled or self._as_bool(metadata.get("edr_disabled"))
            has_malware_detected = has_malware_detected or self._as_bool(
                metadata.get("malware_detected")
            )
            has_large_data_export = has_large_data_export or self._as_bool(
                metadata.get("large_data_export")
            )
            has_critical_asset = has_critical_asset or self._as_bool(
                metadata.get("critical_asset")
            )
            has_service_unavailable = has_service_unavailable or self._as_bool(
                metadata.get("service_unavailable")
            )
            has_actual_loss = has_actual_loss or self._as_bool(
                metadata.get("has_actual_loss")
            )

            potential_loss_values.append(self._as_float(metadata.get("potential_loss")))
            estimated_loss_values.append(self._as_float(metadata.get("estimated_loss")))

            affected_process = self._first_known(
                affected_process,
                metadata.get("affected_process"),
            )
            node_type = self._first_known(node_type, metadata.get("node_type"))
            asset_type = self._first_known(asset_type, metadata.get("asset_type"))
            network_segment = self._first_known(
                network_segment,
                metadata.get("network_segment"),
            )
            process_criticality = self._first_known(
                process_criticality,
                metadata.get("process_criticality"),
            )
            confidentiality_impact = self._first_known(
                confidentiality_impact,
                metadata.get("confidentiality_impact"),
            )
            integrity_impact = self._first_known(
                integrity_impact,
                metadata.get("integrity_impact"),
            )
            availability_impact = self._first_known(
                availability_impact,
                metadata.get("availability_impact"),
            )

        return {
            "events_count": len(events),
            "failed_auth_count": failed_auth_count,
            "blocked_or_failed_count": blocked_or_failed_count,
            "malware_event_count": malware_event_count,
            "update_error_count": update_error_count,
            "access_denied_count": access_denied_count,
            "data_operation_count": data_operation_count,
            "system_error_count": system_error_count,
            "max_severity": max_severity,
            "has_after_hours_activity": has_after_hours_activity,
            "has_admin_action": has_admin_action,
            "has_edr_disabled": has_edr_disabled,
            "has_malware_detected": has_malware_detected,
            "has_large_data_export": has_large_data_export,
            "has_critical_asset": has_critical_asset,
            "has_service_unavailable": has_service_unavailable,
            "has_actual_loss": has_actual_loss,
            "potential_loss": max(potential_loss_values) if potential_loss_values else 0.0,
            "estimated_loss": max(estimated_loss_values) if estimated_loss_values else 0.0,
            "affected_process": affected_process,
            "node_type": node_type,
            "asset_type": asset_type,
            "network_segment": network_segment,
            "process_criticality": process_criticality,
            "confidentiality_impact": confidentiality_impact,
            "integrity_impact": integrity_impact,
            "availability_impact": availability_impact,
        }

    def _make_group_id(self, key: str, events: List[NormalizedSecurityEvent]) -> str:
        event_ids = "|".join(sorted(event.event_id for event in events))
        raw = f"{key}|{event_ids}"
        digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
        return f"grp_{digest}"

    def _first_not_empty(self, values: List[Optional[str]]) -> Optional[str]:
        for value in values:
            if value:
                return value
        return None

    def _as_bool(self, value: object) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"true", "1", "yes", "да"}
        if isinstance(value, int):
            return value != 0
        return False

    def _as_float(self, value: object) -> float:
        try:
            if value is None:
                return 0.0
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    def _first_known(self, current: str, candidate: object) -> str:
        if current != "unknown":
            return current

        if candidate is None:
            return current

        value = str(candidate).strip()
        if not value:
            return current

        return value