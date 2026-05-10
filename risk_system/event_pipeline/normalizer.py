from __future__ import annotations

import hashlib
from typing import List

from .schemas import (
    EventResult,
    NormalizedSecurityEvent,
    RawLogRecord,
    SecurityEventCategory,
)


class EventNormalizer:
    def normalize_many(self, logs: List[RawLogRecord]) -> List[NormalizedSecurityEvent]:
        return [self.normalize(log) for log in logs]

    def normalize(self, log: RawLogRecord) -> NormalizedSecurityEvent:
        message = log.raw_message.lower()
        category = self._detect_category(log, message)
        event_name = self._build_event_name(log, category)

        return NormalizedSecurityEvent(
            event_id=self._make_event_id(log),
            source_log_id=log.log_id,
            timestamp=log.timestamp,
            source_system=log.source_system,
            source_type=log.source_type,
            event_category=category,
            event_name=event_name,
            action=log.action,
            result=log.result,
            node_id=log.node_id or log.host,
            asset_id=log.asset_id,
            subject_id=log.user_id,
            object_id=log.object_id,
            src_ip=log.src_ip,
            dst_ip=log.dst_ip,
            normalized_severity=self._normalize_severity(log),
            is_security_relevant=self._is_security_relevant(category, log.result),
            correlation_key=self._build_correlation_key(log),
            metadata=log.metadata,
        )

    def _detect_category(self, log: RawLogRecord, message: str) -> SecurityEventCategory:
        text = f"{log.event_code or ''} {log.action or ''} {message}".lower()

        if any(token in text for token in ["login", "logon", "auth", "password", "учетн", "парол"]):
            return SecurityEventCategory.AUTHENTICATION

        if any(token in text for token in ["access", "permission", "denied", "acl", "доступ"]):
            return SecurityEventCategory.ACCESS_CONTROL

        if any(token in text for token in ["malware", "virus", "trojan", "edr", "antivirus", "вирус"]):
            return SecurityEventCategory.MALWARE_PROTECTION

        if any(token in text for token in ["update", "patch", "обновлен", "патч"]):
            return SecurityEventCategory.SOFTWARE_UPDATE

        if any(token in text for token in ["config", "policy", "setting", "конфигурац", "настрой"]):
            return SecurityEventCategory.CONFIGURATION_CHANGE

        if any(token in text for token in ["network", "firewall", "ids", "scan", "port", "сет"]):
            return SecurityEventCategory.NETWORK

        if any(token in text for token in ["database", "select", "insert", "delete", "dump", "export"]):
            return SecurityEventCategory.DATA_OPERATION

        if any(token in text for token in ["error", "failed", "failure", "ошибка", "сбой"]):
            return SecurityEventCategory.SYSTEM_ERROR

        if any(token in text for token in ["cve", "vulnerability", "уязвим"]):
            return SecurityEventCategory.VULNERABILITY

        return SecurityEventCategory.OTHER

    def _build_event_name(self, log: RawLogRecord, category: SecurityEventCategory) -> str:
        if log.event_code:
            return f"{category.value}:{log.event_code}"
        if log.action:
            return f"{category.value}:{log.action}"
        return category.value

    def _normalize_severity(self, log: RawLogRecord) -> float:
        if log.severity_from_source is not None:
            return max(0.0, min(1.0, float(log.severity_from_source)))

        if log.result in {EventResult.FAILURE, EventResult.ERROR, EventResult.BLOCKED}:
            return 0.55

        return 0.15

    def _is_security_relevant(self, category: SecurityEventCategory, result: EventResult) -> bool:
        if category in {
            SecurityEventCategory.AUTHENTICATION,
            SecurityEventCategory.ACCESS_CONTROL,
            SecurityEventCategory.MALWARE_PROTECTION,
            SecurityEventCategory.VULNERABILITY,
        }:
            return True

        if result in {EventResult.FAILURE, EventResult.ERROR, EventResult.BLOCKED}:
            return True

        return category != SecurityEventCategory.OTHER

    def _build_correlation_key(self, log: RawLogRecord) -> str:
        parts = [
            log.host or "",
            log.node_id or "",
            log.asset_id or "",
            log.user_id or "",
            log.src_ip or "",
            log.dst_ip or "",
        ]
        return "|".join([part for part in parts if part])

    def _make_event_id(self, log: RawLogRecord) -> str:
        base = f"{log.log_id}|{log.timestamp}|{log.source_system}|{log.raw_message}"
        digest = hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]
        return f"evt_{digest}"