from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Tuple


THREAT_TYPES = [
    "malware",
    "phishing",
    "privilege_escalation",
    "data_leak",
    "ddos",
    "unauthorized_access",
    "misconfiguration",
    "insider",
    "other",
]

NODE_TYPES = [
    "server",
    "workstation",
    "database",
    "network_device",
    "application",
    "gateway",
    "atm",
    "payment_node",
    "other",
]

MEASURE_TYPES = [
    "organizational",
    "technical",
    "software",
    "hardware",
    "other",
]

SEGMENTS = [
    "dmz",
    "office",
    "admin",
    "core_banking",
    "payment_processing",
    "client_data",
    "atm_network",
    "monitoring",
    "test",
]

BUSINESS_SERVICES = [
    "remote_banking",
    "payment_processing",
    "client_data_storage",
    "authentication",
    "internal_reporting",
    "anti_fraud",
    "atm_service",
    "monitoring",
    "test_environment",
]

EVENT_SOURCES = [
    "siem",
    "edr",
    "network_sensor",
    "iam",
    "db_audit",
    "waf",
    "vulnerability_scanner",
    "manual_review",
]

RELATION_TYPES = [
    "network",
    "admin",
    "database_dependency",
    "service_dependency",
    "same_service",
    "authentication",
    "monitoring",
]


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def weighted_choice(items: List[Tuple[str, float]]) -> str:
    values = [item for item, _ in items]
    weights = [weight for _, weight in items]
    return random.choices(values, weights=weights, k=1)[0]


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def make_asset(index: int) -> Dict[str, Any]:
    templates = [
        ("client_db", "База данных клиентов", "client_data_storage", 0.95, 25_000_000),
        ("payments", "Платёжный сервис", "payment_processing", 0.98, 30_000_000),
        ("remote_banking", "Система дистанционного банковского обслуживания", "remote_banking", 0.92, 22_000_000),
        ("auth", "Сервис аутентификации", "authentication", 0.90, 18_000_000),
        ("anti_fraud", "Антифрод-контур", "anti_fraud", 0.86, 15_000_000),
        ("atm", "Сеть банкоматов", "atm_service", 0.82, 12_000_000),
        ("reporting", "Внутренняя аналитическая система", "internal_reporting", 0.65, 8_000_000),
        ("monitoring", "Система мониторинга", "monitoring", 0.70, 7_000_000),
        ("files", "Файловое хранилище", "internal_reporting", 0.55, 5_500_000),
        ("test", "Тестовая среда", "test_environment", 0.30, 1_500_000),
    ]

    code, name, process, criticality, cost = templates[index % len(templates)]
    asset_id = f"asset_{index + 1:03d}_{code}"

    return {
        "asset_id": asset_id,
        "name": name,
        "owner": random.choice(["ИБ", "ИТ", "Операционный блок", "Розничный бизнес", "Платёжный блок"]),
        "business_process": process,
        "criticality": round(clamp(random.gauss(criticality, 0.05), 0.1, 1.0), 3),
        "cost": float(round(random.gauss(cost, cost * 0.08), -3)),
        "metadata": {
            "contains_personal_data": process in {"client_data_storage", "remote_banking", "payment_processing"},
            "contains_bank_secret": process in {"client_data_storage", "payment_processing", "remote_banking", "anti_fraud"},
            "regulatory_significance": round(clamp(criticality + random.uniform(-0.08, 0.08), 0.0, 1.0), 3),
            "rto_hours": random.choice([1, 2, 4, 8, 24]),
            "rpo_minutes": random.choice([5, 15, 30, 60, 240]),
        },
    }


def make_node(index: int, assets: List[Dict[str, Any]]) -> Dict[str, Any]:
    node_type = weighted_choice(
        [
            ("server", 0.18),
            ("workstation", 0.20),
            ("database", 0.10),
            ("network_device", 0.10),
            ("application", 0.18),
            ("gateway", 0.08),
            ("atm", 0.08),
            ("payment_node", 0.06),
            ("other", 0.02),
        ]
    )

    if node_type == "database":
        asset = random.choice([a for a in assets if a["business_process"] in {"client_data_storage", "payment_processing", "anti_fraud"}] or assets)
        segment = random.choice(["client_data", "core_banking", "payment_processing"])
    elif node_type == "payment_node":
        asset = random.choice([a for a in assets if a["business_process"] == "payment_processing"] or assets)
        segment = "payment_processing"
    elif node_type == "gateway":
        asset = random.choice(assets)
        segment = "dmz"
    elif node_type == "atm":
        asset = random.choice([a for a in assets if a["business_process"] == "atm_service"] or assets)
        segment = "atm_network"
    elif node_type == "workstation":
        asset = random.choice(assets)
        segment = random.choice(["office", "admin"])
    else:
        asset = random.choice(assets)
        segment = random.choice(SEGMENTS)

    criticality = clamp(
        0.55 * float(asset["criticality"]) + random.uniform(0.05, 0.35),
        0.05,
        1.0,
    )

    exposure_base = {
        "gateway": 0.75,
        "application": 0.55,
        "payment_node": 0.45,
        "database": 0.25,
        "server": 0.35,
        "network_device": 0.40,
        "workstation": 0.50,
        "atm": 0.65,
        "other": 0.30,
    }[node_type]

    trust_base = {
        "admin": 0.35,
        "core_banking": 0.80,
        "payment_processing": 0.75,
        "client_data": 0.78,
        "dmz": 0.30,
        "office": 0.55,
        "atm_network": 0.45,
        "monitoring": 0.70,
        "test": 0.25,
    }[segment]

    node_id = f"node_{index + 1:04d}_{node_type}"

    return {
        "node_id": node_id,
        "asset_id": asset["asset_id"],
        "node_type": node_type,
        "segment": segment,
        "business_service": asset["business_process"],
        "criticality": round(criticality, 3),
        "exposure": round(clamp(random.gauss(exposure_base, 0.12), 0.0, 1.0), 3),
        "trust_level": round(clamp(random.gauss(trust_base, 0.10), 0.0, 1.0), 3),
        "metadata": {
            "os_family": random.choice(["windows", "linux", "network_os", "database_appliance"]),
            "patch_age_days": random.randint(1, 180),
            "open_ports": random.randint(1, 35),
            "internet_exposed": segment == "dmz" or node_type in {"gateway", "atm"},
            "has_edr": random.random() < 0.78,
            "has_mfa": random.random() < (0.85 if segment in {"admin", "core_banking"} else 0.55),
            "admin_access": node_type in {"server", "database", "network_device", "payment_node"} or segment == "admin",
            "service_tier": random.choice([1, 2, 3]),
        },
    }


def make_edges(nodes: List[Dict[str, Any]], target_count: int) -> List[Dict[str, Any]]:
    edges: List[Dict[str, Any]] = []

    by_service: Dict[str, List[Dict[str, Any]]] = {}
    for node in nodes:
        by_service.setdefault(node["business_service"] or "unknown", []).append(node)

    def add_edge(source: Dict[str, Any], target: Dict[str, Any], relation_type: str, weight: float, bidirectional: bool = False) -> None:
        if source["node_id"] == target["node_id"]:
            return
        edges.append(
            {
                "source_node_id": source["node_id"],
                "target_node_id": target["node_id"],
                "weight": round(clamp(weight, 0.05, 1.0), 3),
                "relation_type": relation_type,
                "bidirectional": bidirectional,
            }
        )

    for service_nodes in by_service.values():
        if len(service_nodes) < 2:
            continue
        service_nodes = service_nodes[:]
        random.shuffle(service_nodes)
        for source, target in zip(service_nodes, service_nodes[1:]):
            add_edge(
                source,
                target,
                "same_service",
                0.45 + 0.35 * min(float(source["criticality"]), float(target["criticality"])),
                bidirectional=True,
            )

    admin_nodes = [n for n in nodes if n["segment"] == "admin" or n["metadata"].get("admin_access")]
    critical_nodes = [n for n in nodes if float(n["criticality"]) >= 0.75]

    for _ in range(max(3, len(nodes) // 8)):
        if admin_nodes and critical_nodes:
            add_edge(
                random.choice(admin_nodes),
                random.choice(critical_nodes),
                "admin",
                random.uniform(0.65, 0.95),
                bidirectional=False,
            )

    while len(edges) < target_count:
        source, target = random.sample(nodes, 2)
        relation_type = random.choice(RELATION_TYPES)
        base = {
            "network": 0.25,
            "admin": 0.75,
            "database_dependency": 0.70,
            "service_dependency": 0.60,
            "same_service": 0.50,
            "authentication": 0.65,
            "monitoring": 0.30,
        }[relation_type]
        add_edge(source, target, relation_type, random.gauss(base, 0.12), bidirectional=random.random() < 0.18)

    unique: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for edge in edges:
        key = (edge["source_node_id"], edge["target_node_id"], edge["relation_type"])
        unique[key] = edge

    return list(unique.values())


def threat_distribution_for_node(node: Dict[str, Any]) -> List[Tuple[str, float]]:
    node_type = node["node_type"]
    segment = node["segment"]

    weights = {
        "malware": 0.11,
        "phishing": 0.12,
        "privilege_escalation": 0.11,
        "data_leak": 0.12,
        "ddos": 0.08,
        "unauthorized_access": 0.16,
        "misconfiguration": 0.14,
        "insider": 0.08,
        "other": 0.08,
    }

    if node_type == "database":
        weights["data_leak"] += 0.20
        weights["unauthorized_access"] += 0.10
        weights["ddos"] -= 0.04
    elif node_type == "workstation":
        weights["phishing"] += 0.20
        weights["malware"] += 0.10
        weights["data_leak"] -= 0.03
    elif node_type == "gateway":
        weights["ddos"] += 0.22
        weights["unauthorized_access"] += 0.08
    elif node_type == "payment_node":
        weights["data_leak"] += 0.10
        weights["ddos"] += 0.08
        weights["unauthorized_access"] += 0.10

    if segment == "dmz":
        weights["ddos"] += 0.10
        weights["unauthorized_access"] += 0.08
    if segment == "admin":
        weights["privilege_escalation"] += 0.18
        weights["insider"] += 0.07

    return [(threat, max(weight, 0.01)) for threat, weight in weights.items()]


def make_event(index: int, nodes: List[Dict[str, Any]], start_time: datetime) -> Tuple[Dict[str, Any], int]:
    node = random.choice(nodes)
    threat_type = weighted_choice(threat_distribution_for_node(node))
    asset_id = node["asset_id"]
    timestamp = start_time + timedelta(minutes=random.randint(0, 60 * 24 * 30))

    node_criticality = float(node["criticality"])
    exposure = float(node["exposure"])
    trust = float(node["trust_level"])
    patch_age = int(node["metadata"]["patch_age_days"])
    open_ports = int(node["metadata"]["open_ports"])

    failed_logins = 0
    data_volume_mb = random.randint(1, 300)
    after_hours = timestamp.hour < 7 or timestamp.hour > 21
    external_connection = bool(node["metadata"].get("internet_exposed")) or random.random() < 0.18
    sensitive_data_access = node["business_service"] in {"client_data_storage", "payment_processing", "remote_banking"}
    geo_anomaly = random.random() < 0.08
    new_admin_session = random.random() < 0.08
    rare_process = random.random() < 0.10
    edr_alerts = random.randint(0, 2)
    siem_correlation_score = random.random() * 0.35

    severity = random.uniform(0.05, 0.45)
    frequency = random.uniform(1.0, 15.0)
    anomaly_score = random.uniform(0.05, 0.40)
    has_vulnerability = patch_age > 90 or random.random() < 0.18
    privilege_level = random.randint(0, 4)
    has_controls = bool(node["metadata"].get("has_edr")) and bool(node["metadata"].get("has_mfa"))

    if threat_type == "phishing":
        failed_logins = random.randint(2, 18)
        after_hours = after_hours or random.random() < 0.35
        external_connection = True
        geo_anomaly = random.random() < 0.30
        anomaly_score += random.uniform(0.15, 0.35)
        severity += random.uniform(0.10, 0.30)
        siem_correlation_score += random.uniform(0.20, 0.45)

    elif threat_type == "unauthorized_access":
        failed_logins = random.randint(8, 60)
        external_connection = True
        geo_anomaly = random.random() < 0.45
        new_admin_session = random.random() < 0.25
        anomaly_score += random.uniform(0.20, 0.45)
        severity += random.uniform(0.15, 0.40)
        privilege_level = random.randint(2, 7)
        siem_correlation_score += random.uniform(0.25, 0.50)

    elif threat_type == "privilege_escalation":
        failed_logins = random.randint(1, 20)
        new_admin_session = True
        rare_process = random.random() < 0.45
        privilege_level = random.randint(6, 10)
        anomaly_score += random.uniform(0.25, 0.50)
        severity += random.uniform(0.25, 0.45)
        siem_correlation_score += random.uniform(0.30, 0.55)

    elif threat_type == "data_leak":
        data_volume_mb = random.randint(800, 15_000)
        sensitive_data_access = True
        after_hours = after_hours or random.random() < 0.40
        external_connection = external_connection or random.random() < 0.35
        anomaly_score += random.uniform(0.25, 0.50)
        severity += random.uniform(0.25, 0.50)
        privilege_level = random.randint(3, 9)
        siem_correlation_score += random.uniform(0.35, 0.55)

    elif threat_type == "ddos":
        frequency = random.uniform(150.0, 3_000.0)
        external_connection = True
        anomaly_score += random.uniform(0.30, 0.50)
        severity += random.uniform(0.20, 0.45)
        siem_correlation_score += random.uniform(0.30, 0.55)

    elif threat_type == "misconfiguration":
        open_ports += random.randint(10, 40)
        has_vulnerability = True
        anomaly_score += random.uniform(0.10, 0.30)
        severity += random.uniform(0.10, 0.30)
        siem_correlation_score += random.uniform(0.10, 0.30)

    elif threat_type == "malware":
        rare_process = True
        edr_alerts = random.randint(2, 8)
        anomaly_score += random.uniform(0.25, 0.55)
        severity += random.uniform(0.20, 0.45)
        siem_correlation_score += random.uniform(0.25, 0.50)

    elif threat_type == "insider":
        sensitive_data_access = True
        after_hours = after_hours or random.random() < 0.40
        privilege_level = random.randint(4, 10)
        anomaly_score += random.uniform(0.20, 0.45)
        severity += random.uniform(0.15, 0.40)
        siem_correlation_score += random.uniform(0.20, 0.50)

    severity = clamp(severity, 0.0, 1.0)
    anomaly_score = clamp(anomaly_score, 0.0, 1.0)
    siem_correlation_score = clamp(siem_correlation_score, 0.0, 1.0)

    risk_signal = (
        0.22 * severity
        + 0.20 * anomaly_score
        + 0.16 * node_criticality
        + 0.12 * exposure
        + 0.08 * (1.0 - trust)
        + 0.07 * min(open_ports / 50.0, 1.0)
        + 0.08 * float(has_vulnerability)
        + 0.07 * siem_correlation_score
    )

    if threat_type in {"data_leak", "privilege_escalation", "unauthorized_access"}:
        risk_signal += 0.07
    if sensitive_data_access:
        risk_signal += 0.06
    if after_hours:
        risk_signal += 0.04
    if external_connection:
        risk_signal += 0.04
    if failed_logins > 20:
        risk_signal += 0.06
    if data_volume_mb > 2_000:
        risk_signal += 0.08
    if edr_alerts >= 3:
        risk_signal += 0.06
    if has_controls:
        risk_signal -= 0.10

    noise = random.gauss(0.0, 0.08)
    probability_like = clamp(risk_signal + noise, 0.0, 1.0)

    label = int(probability_like >= 0.55)

    event = {
        "event_id": f"event_{index + 1:06d}",
        "node_id": node["node_id"],
        "asset_id": asset_id,
        "threat_type": threat_type,
        "source": random.choice(EVENT_SOURCES),
        "timestamp": timestamp.isoformat(timespec="seconds"),
        "severity": round(severity, 3),
        "frequency": round(frequency, 3),
        "anomaly_score": round(anomaly_score, 3),
        "has_vulnerability": bool(has_vulnerability),
        "privilege_level": int(privilege_level),
        "has_controls": bool(has_controls),
        "metadata": {
            "open_ports": int(open_ports),
            "failed_logins": int(failed_logins),
            "after_hours_activity": bool(after_hours),
            "external_connection": bool(external_connection),
            "sensitive_data_access": bool(sensitive_data_access),
            "data_volume_mb": int(data_volume_mb),
            "patch_age_days": int(patch_age),
            "cve_cvss": round(random.uniform(0.0, 9.8) if has_vulnerability else 0.0, 1),
            "geo_anomaly": bool(geo_anomaly),
            "new_admin_session": bool(new_admin_session),
            "rare_process": bool(rare_process),
            "edr_alerts": int(edr_alerts),
            "siem_correlation_score": round(siem_correlation_score, 3),
            "synthetic_risk_signal": round(probability_like, 3),
        },
    }

    return event, label


def make_measures() -> List[Dict[str, Any]]:
    return [
        {
            "measure_id": "measure_mfa_admin",
            "name": "Усиление многофакторной аутентификации для административного доступа",
            "measure_type": "technical",
            "cost": 180_000,
            "labor": 80,
            "implementation_time": 14,
            "effectiveness": {
                "unauthorized_access": 0.35,
                "privilege_escalation": 0.25,
                "insider": 0.15,
            },
            "applicable_node_types": ["server", "database", "network_device", "payment_node", "application"],
            "incompatible_with": [],
            "requires": [],
            "metadata": {"priority": "high", "control_family": "access_control"},
        },
        {
            "measure_id": "measure_close_unused_ports",
            "name": "Закрытие неиспользуемых сетевых портов",
            "measure_type": "technical",
            "cost": 90_000,
            "labor": 45,
            "implementation_time": 7,
            "effectiveness": {
                "misconfiguration": 0.40,
                "unauthorized_access": 0.25,
                "malware": 0.10,
            },
            "applicable_node_types": ["server", "database", "network_device", "gateway", "application", "payment_node"],
            "incompatible_with": [],
            "requires": [],
            "metadata": {"priority": "medium", "control_family": "hardening"},
        },
        {
            "measure_id": "measure_patch_vulnerabilities",
            "name": "Устранение критичных уязвимостей",
            "measure_type": "software",
            "cost": 240_000,
            "labor": 110,
            "implementation_time": 21,
            "effectiveness": {
                "misconfiguration": 0.20,
                "malware": 0.25,
                "unauthorized_access": 0.30,
                "privilege_escalation": 0.25,
            },
            "applicable_node_types": ["server", "database", "application", "gateway", "payment_node", "workstation"],
            "incompatible_with": [],
            "requires": [],
            "metadata": {"priority": "high", "control_family": "vulnerability_management"},
        },
        {
            "measure_id": "measure_network_segmentation",
            "name": "Уточнение сетевой сегментации критичных контуров",
            "measure_type": "technical",
            "cost": 320_000,
            "labor": 130,
            "implementation_time": 30,
            "effectiveness": {
                "unauthorized_access": 0.30,
                "data_leak": 0.25,
                "privilege_escalation": 0.20,
                "ddos": 0.15,
            },
            "applicable_node_types": ["server", "database", "network_device", "gateway", "application", "payment_node"],
            "incompatible_with": ["measure_flat_network_exception"],
            "requires": [],
            "metadata": {"priority": "high", "control_family": "network_security"},
        },
        {
            "measure_id": "measure_siem_rules",
            "name": "Настройка корреляционных правил SIEM",
            "measure_type": "software",
            "cost": 130_000,
            "labor": 70,
            "implementation_time": 10,
            "effectiveness": {
                "phishing": 0.20,
                "unauthorized_access": 0.20,
                "privilege_escalation": 0.20,
                "data_leak": 0.25,
                "malware": 0.15,
            },
            "applicable_node_types": NODE_TYPES,
            "incompatible_with": [],
            "requires": [],
            "metadata": {"priority": "medium", "control_family": "monitoring"},
        },
        {
            "measure_id": "measure_edr_policy",
            "name": "Усиление политики EDR для серверов и рабочих станций",
            "measure_type": "software",
            "cost": 210_000,
            "labor": 90,
            "implementation_time": 14,
            "effectiveness": {
                "malware": 0.35,
                "privilege_escalation": 0.18,
                "unauthorized_access": 0.15,
            },
            "applicable_node_types": ["server", "workstation", "application", "payment_node"],
            "incompatible_with": [],
            "requires": [],
            "metadata": {"priority": "medium", "control_family": "endpoint_security"},
        },
        {
            "measure_id": "measure_db_access_review",
            "name": "Пересмотр прав доступа к критичным базам данных",
            "measure_type": "organizational",
            "cost": 160_000,
            "labor": 100,
            "implementation_time": 20,
            "effectiveness": {
                "data_leak": 0.35,
                "insider": 0.25,
                "unauthorized_access": 0.20,
            },
            "applicable_node_types": ["database"],
            "incompatible_with": [],
            "requires": ["measure_siem_rules"],
            "metadata": {"priority": "high", "control_family": "access_review"},
        },
        {
            "measure_id": "measure_antiphishing_training",
            "name": "Антифишинговое обучение сотрудников",
            "measure_type": "organizational",
            "cost": 110_000,
            "labor": 60,
            "implementation_time": 14,
            "effectiveness": {
                "phishing": 0.35,
                "unauthorized_access": 0.10,
            },
            "applicable_node_types": ["workstation"],
            "incompatible_with": [],
            "requires": [],
            "metadata": {"priority": "medium", "control_family": "awareness"},
        },
        {
            "measure_id": "measure_ddos_protection",
            "name": "Усиление защиты от DDoS для внешних сервисов",
            "measure_type": "technical",
            "cost": 280_000,
            "labor": 75,
            "implementation_time": 12,
            "effectiveness": {
                "ddos": 0.45,
                "unauthorized_access": 0.08,
            },
            "applicable_node_types": ["gateway", "application", "payment_node"],
            "incompatible_with": [],
            "requires": [],
            "metadata": {"priority": "high", "control_family": "availability"},
        },
        {
            "measure_id": "measure_flat_network_exception",
            "name": "Временное исключение для плоского сетевого взаимодействия",
            "measure_type": "other",
            "cost": 30_000,
            "labor": 15,
            "implementation_time": 3,
            "effectiveness": {
                "other": 0.05,
            },
            "applicable_node_types": ["server", "application"],
            "incompatible_with": ["measure_network_segmentation"],
            "requires": [],
            "metadata": {"priority": "low", "control_family": "exception"},
        },
    ]


def make_synthetic_risk_scores(events: List[Dict[str, Any]], nodes: List[Dict[str, Any]], limit: int = 80) -> List[Dict[str, Any]]:
    node_by_id = {node["node_id"]: node for node in nodes}
    selected_events = sorted(
        events,
        key=lambda event: float(event["metadata"].get("synthetic_risk_signal", 0.0)),
        reverse=True,
    )[:limit]

    scores: List[Dict[str, Any]] = []

    for event in selected_events:
        node = node_by_id[event["node_id"]]
        probability = clamp(float(event["metadata"]["synthetic_risk_signal"]))
        impact = round(
            0.30
            + 0.35 * float(event["severity"])
            + 0.25 * float(node["criticality"])
            + 0.10 * float(event["metadata"].get("sensitive_data_access", False)),
            3,
        )
        criticality = float(node["criticality"])
        base_risk = round(probability * impact * criticality, 4)
        propagated_risk = round(clamp(base_risk + random.uniform(0.0, 0.18) * criticality, 0.0, 1.0), 4)
        final_risk = max(base_risk, propagated_risk)

        if final_risk >= 0.65:
            risk_class = "critical"
        elif final_risk >= 0.40:
            risk_class = "high"
        elif final_risk >= 0.20:
            risk_class = "medium"
        else:
            risk_class = "low"

        scores.append(
            {
                "event_id": event["event_id"],
                "node_id": event["node_id"],
                "asset_id": event["asset_id"],
                "threat_type": event["threat_type"],
                "probability": round(probability, 4),
                "impact": impact,
                "criticality": round(criticality, 3),
                "base_risk": base_risk,
                "propagated_risk": propagated_risk,
                "final_risk": round(final_risk, 4),
                "risk_class": risk_class,
            }
        )

    return scores


def generate_dataset(
    asset_count: int,
    node_count: int,
    event_count: int,
    edge_count: int,
    seed: int,
) -> Dict[str, Any]:
    random.seed(seed)

    assets = [make_asset(i) for i in range(asset_count)]
    nodes = [make_node(i, assets) for i in range(node_count)]
    edges = make_edges(nodes, edge_count)
    start_time = datetime(2026, 2, 1, 0, 0, 0)

    events: List[Dict[str, Any]] = []
    labels: Dict[str, int] = {}

    for index in range(event_count):
        event, label = make_event(index, nodes, start_time)
        events.append(event)
        labels[event["event_id"]] = label

    measures = make_measures()
    risks = make_synthetic_risk_scores(events, nodes)

    return {
        "events": events,
        "nodes": nodes,
        "assets": assets,
        "edges": edges,
        "labels": labels,
        "measures": measures,
        "current_risks": risks,
    }


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def write_readme(output_dir: Path) -> None:
    readme = """# Синтетические данные для дипломного проекта

Данные сформированы искусственно и предназначены для тестирования прототипа системы анализа и оценки рисков информационной безопасности корпоративных систем банка.

Реальные банковские журналы событий, сведения о клиентах, инфраструктуре или внутренних сервисах не использовались. Структура данных приближена к типовым объектам банковской инфраструктуры: события ИБ, узлы, активы, связи между узлами и меры защиты.

Состав файлов:

- `train_dataset.json` — набор для обучения модели через endpoint `/train`;
- `demo_assess.json` — демонстрационный набор для оценки риска через `/assess`;
- `scenario_data_leak.json` — сценарий повышенного риска утечки данных;
- `scenario_ddos_payment.json` — сценарий DDoS-воздействия на платёжный контур;
- `scenario_privilege_escalation.json` — сценарий повышения привилегий;
- `scenario_graph_propagation.json` — сценарий, в котором важно графовое распространение риска;
- `optimization_request.json` — пример входных данных для `/optimize`.

Целевые метки в `train_dataset.json` являются синтетическими и сформированы на основе скрытого риск-сигнала, учитывающего критичность узла, тип угрозы, аномальность события, признаки уязвимости, привилегированную активность и наличие защитных мер.
"""
    (output_dir / "README.md").write_text(readme, encoding="utf-8")


def make_train_request(dataset: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "events": dataset["events"],
        "nodes": dataset["nodes"],
        "assets": dataset["assets"],
        "labels": dataset["labels"],
        "model_type": "gradient_boosting",
        "model_params": {},
        "use_calibration": True,
        "validation_size": 0.30,
        "calibration_size": 0.50,
        "threshold": 0.50,
        "tune_hyperparameters": False,
        "tuning_scoring": "f1",
        "cv_folds": 3,
        "compute_permutation_importance": True,
        "permutation_scoring": "f1",
        "permutation_n_repeats": 10,
        "importance_top_k": 15,
    }


def make_assess_request(dataset: Dict[str, Any], event_limit: int) -> Dict[str, Any]:
    return {
        "events": dataset["events"][:event_limit],
        "nodes": dataset["nodes"],
        "assets": dataset["assets"],
        "edges": dataset["edges"],
    }


def filter_events_by_threat(dataset: Dict[str, Any], threat_type: str, limit: int) -> Dict[str, Any]:
    events = [event for event in dataset["events"] if event["threat_type"] == threat_type]
    if len(events) < limit:
        events = dataset["events"][:limit]

    used_node_ids = {event["node_id"] for event in events[:limit]}
    nodes = [node for node in dataset["nodes"] if node["node_id"] in used_node_ids]
    used_asset_ids = {node["asset_id"] for node in nodes}
    assets = [asset for asset in dataset["assets"] if asset["asset_id"] in used_asset_ids]
    edges = [
        edge
        for edge in dataset["edges"]
        if edge["source_node_id"] in used_node_ids or edge["target_node_id"] in used_node_ids
    ]

    return {
        "events": events[:limit],
        "nodes": nodes,
        "assets": assets,
        "edges": edges,
    }


def make_graph_scenario(dataset: Dict[str, Any], limit: int) -> Dict[str, Any]:
    critical_nodes = [node for node in dataset["nodes"] if float(node["criticality"]) >= 0.75]
    if not critical_nodes:
        return make_assess_request(dataset, limit)

    related_ids = {node["node_id"] for node in critical_nodes[:8]}
    for edge in dataset["edges"]:
        if edge["source_node_id"] in related_ids or edge["target_node_id"] in related_ids:
            related_ids.add(edge["source_node_id"])
            related_ids.add(edge["target_node_id"])

    events = [event for event in dataset["events"] if event["node_id"] in related_ids][:limit]
    nodes = [node for node in dataset["nodes"] if node["node_id"] in related_ids]
    used_asset_ids = {node["asset_id"] for node in nodes}
    assets = [asset for asset in dataset["assets"] if asset["asset_id"] in used_asset_ids]
    edges = [
        edge
        for edge in dataset["edges"]
        if edge["source_node_id"] in related_ids and edge["target_node_id"] in related_ids
    ]

    return {
        "events": events,
        "nodes": nodes,
        "assets": assets,
        "edges": edges,
    }


def make_optimization_request(dataset: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "current_risks": dataset["current_risks"],
        "measures": dataset["measures"],
        "constraints": {
            "max_budget": 650_000,
            "max_labor": 280,
            "max_time": 45,
            "max_measures": 4,
        },
        "nodes": dataset["nodes"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Генерация синтетических данных для системы оценки рисков ИБ банка."
    )
    parser.add_argument("--assets", type=int, default=24)
    parser.add_argument("--nodes", type=int, default=120)
    parser.add_argument("--events", type=int, default=5000)
    parser.add_argument("--edges", type=int, default=220)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=project_root() / "data" / "generated",
    )

    args = parser.parse_args()

    dataset = generate_dataset(
        asset_count=args.assets,
        node_count=args.nodes,
        event_count=args.events,
        edge_count=args.edges,
        seed=args.seed,
    )

    output_dir: Path = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    write_json(output_dir / "train_dataset.json", make_train_request(dataset))
    write_json(output_dir / "demo_assess.json", make_assess_request(dataset, event_limit=160))

    write_json(output_dir / "scenario_data_leak.json", filter_events_by_threat(dataset, "data_leak", limit=120))
    write_json(output_dir / "scenario_ddos_payment.json", filter_events_by_threat(dataset, "ddos", limit=120))
    write_json(output_dir / "scenario_privilege_escalation.json", filter_events_by_threat(dataset, "privilege_escalation", limit=120))
    write_json(output_dir / "scenario_graph_propagation.json", make_graph_scenario(dataset, limit=180))
    write_json(output_dir / "optimization_request.json", make_optimization_request(dataset))

    write_readme(output_dir)

    positive = sum(dataset["labels"].values())
    total = len(dataset["labels"])
    negative = total - positive

    print(f"Синтетические данные сохранены в: {output_dir}")
    print(f"Активы: {len(dataset['assets'])}")
    print(f"Узлы: {len(dataset['nodes'])}")
    print(f"События: {len(dataset['events'])}")
    print(f"Связи: {len(dataset['edges'])}")
    print(f"Метки: positive={positive}, negative={negative}, positive_share={positive / total:.3f}")


if __name__ == "__main__":
    main()