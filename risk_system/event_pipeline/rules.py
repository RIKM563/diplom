from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .correlator import EventGroup
from .schemas import IncidentSeverity, IncidentType


@dataclass
class IncidentRuleResult:
    rule_id: str
    rule_name: str
    matched: bool
    score: float
    incident_type: IncidentType
    severity: IncidentSeverity
    description: str
    normative_basis: str
    technical_basis: str
    evidence: List[str]


class IncidentRule:
    rule_id: str
    rule_name: str
    incident_type: IncidentType
    normative_basis: str
    technical_basis: str
    description: str

    def apply(self, group: EventGroup) -> IncidentRuleResult:
        raise NotImplementedError


class SecurityUpdateFailureRule(IncidentRule):
    rule_id = "IR-001"
    rule_name = "Ошибка защитного обновления"
    incident_type = IncidentType.SECURITY_UPDATE_FAILURE
    normative_basis = (
        "ГОСТ Р 57580.1-2017: регистрация и анализ событий защиты информации, "
        "потенциально связанных с инцидентами защиты информации."
    )
    technical_basis = (
        "Корреляционный признак SIEM: ошибка установки обновления безопасности, "
        "сбой обновления средства защиты или невозможность применения исправления."
    )
    description = (
        "События ошибки защитного обновления рассматриваются как кандидаты "
        "в инцидент защиты информации, если они могут привести к сохранению "
        "уязвимости или нарушению работы средства защиты."
    )

    def apply(self, group: EventGroup) -> IncidentRuleResult:
        update_errors = int(group.features.get("update_error_count", 0))
        edr_disabled = bool(group.features.get("has_edr_disabled", False))
        max_severity = float(group.features.get("max_severity", 0.0))

        matched = update_errors > 0
        score = 0.0
        evidence: List[str] = []

        if update_errors > 0:
            score += 0.45
            evidence.append("Зафиксирована ошибка обновления программного обеспечения или средства защиты")

        if edr_disabled:
            score += 0.30
            evidence.append("В метаданных события указан признак отключения EDR/средства защиты")

        if max_severity >= 0.7:
            score += 0.15
            evidence.append("Источник события указал высокий уровень серьезности")

        return self._result(group, matched, min(score, 1.0), evidence)

    def _result(
        self,
        group: EventGroup,
        matched: bool,
        score: float,
        evidence: List[str],
    ) -> IncidentRuleResult:
        return IncidentRuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=matched,
            score=score,
            incident_type=self.incident_type,
            severity=self._severity(score),
            description=self.description,
            normative_basis=self.normative_basis,
            technical_basis=self.technical_basis,
            evidence=evidence,
        )

    def _severity(self, score: float) -> IncidentSeverity:
        if score >= 0.85:
            return IncidentSeverity.CRITICAL
        if score >= 0.70:
            return IncidentSeverity.HIGH
        if score >= 0.50:
            return IncidentSeverity.MEDIUM
        return IncidentSeverity.LOW


class MalwareActivityRule(IncidentRule):
    rule_id = "IR-002"
    rule_name = "Признаки вредоносной активности"
    incident_type = IncidentType.MALWARE_ACTIVITY
    normative_basis = (
        "ГОСТ Р 57580.1-2017: выявление и анализ событий защиты информации, "
        "потенциально связанных с инцидентами защиты информации."
    )
    technical_basis = (
        "Типовая SIEM-логика: срабатывание EDR, антивируса, IDS/IPS "
        "или другого средства обнаружения вредоносной активности."
    )
    description = (
        "События обнаружения вредоносной активности рассматриваются как кандидаты "
        "в инцидент защиты информации."
    )

    def apply(self, group: EventGroup) -> IncidentRuleResult:
        malware_count = int(group.features.get("malware_event_count", 0))
        malware_detected = bool(group.features.get("has_malware_detected", False))
        max_severity = float(group.features.get("max_severity", 0.0))

        matched = malware_count > 0 or malware_detected
        score = 0.0
        evidence: List[str] = []

        if malware_count > 0:
            score += 0.45
            evidence.append("В группе есть событие категории malware_protection")

        if malware_detected:
            score += 0.35
            evidence.append("В метаданных указан признак обнаружения вредоносной активности")

        if max_severity >= 0.7:
            score += 0.15
            evidence.append("Источник события указал высокий уровень серьезности")

        return self._result(matched, min(score, 1.0), evidence)

    def _result(
        self,
        matched: bool,
        score: float,
        evidence: List[str],
    ) -> IncidentRuleResult:
        return IncidentRuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=matched,
            score=score,
            incident_type=self.incident_type,
            severity=self._severity(score),
            description=self.description,
            normative_basis=self.normative_basis,
            technical_basis=self.technical_basis,
            evidence=evidence,
        )

    def _severity(self, score: float) -> IncidentSeverity:
        if score >= 0.85:
            return IncidentSeverity.CRITICAL
        if score >= 0.70:
            return IncidentSeverity.HIGH
        if score >= 0.50:
            return IncidentSeverity.MEDIUM
        return IncidentSeverity.LOW


class MultipleFailedAuthenticationRule(IncidentRule):
    rule_id = "IR-003"
    rule_name = "Множественные неуспешные попытки аутентификации"
    incident_type = IncidentType.ACCOUNT_COMPROMISE_SIGNS
    normative_basis = (
        "ГОСТ Р 57580.1-2017: регистрация событий защиты информации, "
        "потенциально связанных с инцидентами защиты информации, в том числе "
        "событий несанкционированного доступа."
    )
    technical_basis = (
        "Корреляционная логика SIEM: несколько неуспешных попыток аутентификации "
        "по одному субъекту, адресу или объекту за ограниченный период наблюдения."
    )
    description = (
        "Группа неуспешных попыток аутентификации рассматривается как кандидат "
        "в инцидент, связанный с признаками компрометации учетной записи."
    )

    def __init__(self, failed_attempts_threshold: int = 5) -> None:
        self.failed_attempts_threshold = failed_attempts_threshold

    def apply(self, group: EventGroup) -> IncidentRuleResult:
        failed_auth_count = int(group.features.get("failed_auth_count", 0))
        after_hours = bool(group.features.get("has_after_hours_activity", False))
        admin_action = bool(group.features.get("has_admin_action", False))

        matched = failed_auth_count >= self.failed_attempts_threshold
        score = 0.0
        evidence: List[str] = []

        if matched:
            score += 0.50
            evidence.append(
                f"Количество неуспешных попыток аутентификации: {failed_auth_count}"
            )

        if after_hours:
            score += 0.15
            evidence.append("Активность выполнялась во внерабочее время")

        if admin_action:
            score += 0.15
            evidence.append("События связаны с административными действиями или привилегированной учетной записью")

        return IncidentRuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=matched,
            score=min(score, 1.0),
            incident_type=self.incident_type,
            severity=self._severity(score),
            description=self.description,
            normative_basis=self.normative_basis,
            technical_basis=self.technical_basis,
            evidence=evidence,
        )

    def _severity(self, score: float) -> IncidentSeverity:
        if score >= 0.85:
            return IncidentSeverity.CRITICAL
        if score >= 0.70:
            return IncidentSeverity.HIGH
        if score >= 0.50:
            return IncidentSeverity.MEDIUM
        return IncidentSeverity.LOW


class AccessDeniedToCriticalAssetRule(IncidentRule):
    rule_id = "IR-004"
    rule_name = "Отказ доступа к значимому объекту или активу"
    incident_type = IncidentType.UNAUTHORIZED_ACCESS
    normative_basis = (
        "ГОСТ Р 57580.1-2017: регистрация событий защиты информации, "
        "потенциально связанных с инцидентами защиты информации, включая события НСД."
    )
    technical_basis = (
        "SIEM-корреляция: отказ доступа, блокировка действия или нарушение политики "
        "доступа на объекте, связанном со значимым активом."
    )
    description = (
        "События отказа доступа к значимому активу рассматриваются как кандидаты "
        "в инцидент защиты информации."
    )

    def apply(self, group: EventGroup) -> IncidentRuleResult:
        access_denied_count = int(group.features.get("access_denied_count", 0))
        critical_asset = bool(group.features.get("has_critical_asset", False))
        max_severity = float(group.features.get("max_severity", 0.0))

        matched = access_denied_count > 0 and (critical_asset or max_severity >= 0.6)
        score = 0.0
        evidence: List[str] = []

        if access_denied_count > 0:
            score += 0.35
            evidence.append("Есть события отказа или блокировки доступа")

        if critical_asset:
            score += 0.30
            evidence.append("События связаны со значимым активом")

        if max_severity >= 0.6:
            score += 0.15
            evidence.append("Источник события указал повышенную серьезность")

        return IncidentRuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=matched,
            score=min(score, 1.0),
            incident_type=self.incident_type,
            severity=self._severity(score),
            description=self.description,
            normative_basis=self.normative_basis,
            technical_basis=self.technical_basis,
            evidence=evidence,
        )

    def _severity(self, score: float) -> IncidentSeverity:
        if score >= 0.85:
            return IncidentSeverity.CRITICAL
        if score >= 0.70:
            return IncidentSeverity.HIGH
        if score >= 0.50:
            return IncidentSeverity.MEDIUM
        return IncidentSeverity.LOW


class DataExportAfterHoursRule(IncidentRule):
    rule_id = "IR-005"
    rule_name = "Выгрузка данных во внерабочее время"
    incident_type = IncidentType.DATA_LEAK_SIGNS
    normative_basis = (
        "ГОСТ Р 57580.1-2017: мониторинг и анализ событий защиты информации, "
        "потенциально связанных с инцидентами защиты информации."
    )
    technical_basis = (
        "SIEM/DLP-корреляция: операция с данными, повышенный объем выгрузки "
        "или активность во внерабочее время."
    )
    description = (
        "События операций с данными при наличии признаков повышенного объема "
        "или внерабочей активности рассматриваются как кандидаты в инцидент."
    )

    def apply(self, group: EventGroup) -> IncidentRuleResult:
        data_operation_count = int(group.features.get("data_operation_count", 0))
        after_hours = bool(group.features.get("has_after_hours_activity", False))
        large_export = bool(group.features.get("has_large_data_export", False))
        critical_asset = bool(group.features.get("has_critical_asset", False))

        matched = data_operation_count > 0 and (after_hours or large_export)
        score = 0.0
        evidence: List[str] = []

        if data_operation_count > 0:
            score += 0.25
            evidence.append("В группе есть операции с данными")

        if after_hours:
            score += 0.20
            evidence.append("Операция выполнялась во внерабочее время")

        if large_export:
            score += 0.30
            evidence.append("Указан признак повышенного объема выгрузки данных")

        if critical_asset:
            score += 0.15
            evidence.append("Событие связано со значимым активом")

        return IncidentRuleResult(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=matched,
            score=min(score, 1.0),
            incident_type=self.incident_type,
            severity=self._severity(score),
            description=self.description,
            normative_basis=self.normative_basis,
            technical_basis=self.technical_basis,
            evidence=evidence,
        )

    def _severity(self, score: float) -> IncidentSeverity:
        if score >= 0.85:
            return IncidentSeverity.CRITICAL
        if score >= 0.70:
            return IncidentSeverity.HIGH
        if score >= 0.50:
            return IncidentSeverity.MEDIUM
        return IncidentSeverity.LOW


class IncidentRuleEngine:
    def __init__(self) -> None:
        self.rules: List[IncidentRule] = [
            SecurityUpdateFailureRule(),
            MalwareActivityRule(),
            MultipleFailedAuthenticationRule(failed_attempts_threshold=5),
            AccessDeniedToCriticalAssetRule(),
            DataExportAfterHoursRule(),
        ]

    def apply(self, group: EventGroup) -> Optional[IncidentRuleResult]:
        matched_results = [rule.apply(group) for rule in self.rules]
        matched_results = [result for result in matched_results if result.matched]

        if not matched_results:
            return None

        return max(matched_results, key=lambda result: result.score)