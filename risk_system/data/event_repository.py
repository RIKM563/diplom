from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from risk_system.event_pipeline import (
    EventPipelineResponse,
    FullPipelineResponse,
    IncidentRecord,
    NormalizedSecurityEvent,
    RiskAssessmentRecord,
    RiskEventRecord,
    ControlOptimizationResult,
    RecommendedControlMeasure,
)


class EventPipelineRepository:
    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is None:
            project_root = Path(__file__).resolve().parents[2]
            db_path = project_root / "runtime" / "risk_system.sqlite3"

        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def init_db(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA foreign_keys = ON;")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    source_log_id TEXT NOT NULL,
                    timestamp TEXT,
                    source_system TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    event_category TEXT NOT NULL,
                    event_name TEXT NOT NULL,
                    action TEXT,
                    result TEXT NOT NULL,
                    node_id TEXT,
                    asset_id TEXT,
                    subject_id TEXT,
                    object_id TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    normalized_severity REAL NOT NULL,
                    is_security_relevant INTEGER NOT NULL,
                    correlation_key TEXT,
                    metadata_json TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    detected_at TEXT,
                    incident_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    node_id TEXT,
                    asset_id TEXT,
                    affected_process TEXT,
                    description TEXT,
                    classifier_confidence REAL NOT NULL,
                    evidence_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS incident_events (
                    incident_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    relation_type TEXT NOT NULL DEFAULT 'created_from',
                    PRIMARY KEY (incident_id, event_id),
                    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
                    FOREIGN KEY (event_id) REFERENCES security_events(event_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS risk_events (
                    risk_event_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    threat_scenario TEXT NOT NULL,
                    node_id TEXT,
                    asset_id TEXT,
                    affected_process TEXT,
                    has_actual_loss INTEGER NOT NULL,
                    estimated_loss REAL NOT NULL,
                    potential_loss REAL NOT NULL,
                    probability_estimate REAL NOT NULL,
                    impact_estimate REAL NOT NULL,
                    registration_threshold_reached INTEGER NOT NULL,
                    classifier_confidence REAL NOT NULL,
                    rationale_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
                );
                
                CREATE TABLE IF NOT EXISTS risk_assessments (
                    assessment_id TEXT PRIMARY KEY,
                    risk_event_id TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    node_id TEXT,
                    asset_id TEXT,
                    threat_scenario TEXT NOT NULL,
                    probability_estimate REAL NOT NULL,
                    impact_estimate REAL NOT NULL,
                    initial_risk_estimate REAL NOT NULL,
                    graph_adjusted_risk_estimate REAL,
                    final_risk_estimate REAL NOT NULL,
                    risk_class TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    explanation_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (risk_event_id) REFERENCES risk_events(risk_event_id) ON DELETE CASCADE,
                    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
                );
                
                CREATE TABLE IF NOT EXISTS control_recommendations (
                    measure_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    measure_type TEXT NOT NULL,
                    description TEXT,
                    cost REAL NOT NULL,
                    labor REAL NOT NULL,
                    implementation_time REAL NOT NULL,
                    expected_risk_reduction REAL NOT NULL,
                    expected_residual_risk REAL NOT NULL,
                    covered_risk_event_ids_json TEXT NOT NULL,
                    covered_assessment_ids_json TEXT NOT NULL,
                    covered_node_ids_json TEXT NOT NULL,
                    rationale_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE INDEX IF NOT EXISTS idx_control_recommendations_effect
                    ON control_recommendations(expected_risk_reduction DESC);

                CREATE INDEX IF NOT EXISTS idx_risk_assessments_class_priority
                    ON risk_assessments(risk_class, priority);
                
                CREATE INDEX IF NOT EXISTS idx_risk_assessments_node_asset
                    ON risk_assessments(node_id, asset_id);

                CREATE INDEX IF NOT EXISTS idx_security_events_timestamp
                    ON security_events(timestamp);

                CREATE INDEX IF NOT EXISTS idx_security_events_node_asset
                    ON security_events(node_id, asset_id);

                CREATE INDEX IF NOT EXISTS idx_incidents_type_severity
                    ON incidents(incident_type, severity);

                CREATE INDEX IF NOT EXISTS idx_incidents_node_asset
                    ON incidents(node_id, asset_id);

                CREATE INDEX IF NOT EXISTS idx_risk_events_type_scenario
                    ON risk_events(event_type, threat_scenario);

                CREATE INDEX IF NOT EXISTS idx_risk_events_node_asset
                    ON risk_events(node_id, asset_id);
                """
            )
            connection.commit()

    def save_pipeline_response(self, response: EventPipelineResponse) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA foreign_keys = ON;")

            for event in response.normalized_events:
                self._upsert_security_event(connection, event)

            for incident in response.incidents:
                self._upsert_incident(connection, incident)
                self._upsert_incident_event_links(connection, incident)

            for risk_event in response.risk_events:
                self._upsert_risk_event(connection, risk_event)

            connection.commit()

    def save_full_pipeline_response(self, response: FullPipelineResponse) -> None:
        self.save_pipeline_response(response.pipeline)

        with self._connect() as connection:
            connection.execute("PRAGMA foreign_keys = ON;")

            for assessment in response.risk_assessments:
                self._upsert_risk_assessment(connection, assessment)

            if response.control_optimization is not None:
                for measure in response.control_optimization.selected_measures:
                    self._upsert_control_recommendation(connection, measure)

            connection.commit()

    def list_security_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._fetch_all(
            """
            SELECT
                event_id,
                source_log_id,
                timestamp,
                source_system,
                source_type,
                event_category,
                event_name,
                action,
                result,
                node_id,
                asset_id,
                subject_id,
                object_id,
                src_ip,
                dst_ip,
                normalized_severity,
                is_security_relevant,
                correlation_key,
                metadata_json,
                created_at
            FROM security_events
            ORDER BY created_at DESC
            LIMIT ?;
            """,
            (limit,),
        )

    def list_incidents(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._fetch_all(
            """
            SELECT
                incident_id,
                detected_at,
                incident_type,
                severity,
                status,
                node_id,
                asset_id,
                affected_process,
                description,
                classifier_confidence,
                evidence_json,
                metadata_json,
                created_at
            FROM incidents
            ORDER BY created_at DESC
            LIMIT ?;
            """,
            (limit,),
        )

    def list_risk_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._fetch_all(
            """
            SELECT
                risk_event_id,
                incident_id,
                event_type,
                threat_scenario,
                node_id,
                asset_id,
                affected_process,
                has_actual_loss,
                estimated_loss,
                potential_loss,
                probability_estimate,
                impact_estimate,
                registration_threshold_reached,
                classifier_confidence,
                rationale_json,
                metadata_json,
                created_at
            FROM risk_events
            ORDER BY created_at DESC
            LIMIT ?;
            """,
            (limit,),
        )

    def list_risk_assessments(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._fetch_all(
            """
            SELECT
                assessment_id,
                risk_event_id,
                incident_id,
                node_id,
                asset_id,
                threat_scenario,
                probability_estimate,
                impact_estimate,
                initial_risk_estimate,
                graph_adjusted_risk_estimate,
                final_risk_estimate,
                risk_class,
                priority,
                explanation_json,
                metadata_json,
                created_at
            FROM risk_assessments
            ORDER BY priority ASC, final_risk_estimate DESC, created_at DESC
            LIMIT ?;
            """,
            (limit,),
        )

    def list_control_recommendations(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._fetch_all(
            """
            SELECT
                measure_id,
                name,
                measure_type,
                description,
                cost,
                labor,
                implementation_time,
                expected_risk_reduction,
                expected_residual_risk,
                covered_risk_event_ids_json,
                covered_assessment_ids_json,
                covered_node_ids_json,
                rationale_json,
                metadata_json,
                created_at
            FROM control_recommendations
            ORDER BY expected_risk_reduction DESC, created_at DESC
            LIMIT ?;
            """,
            (limit,),
        )

    def get_summary(self) -> Dict[str, int | str]:
        with self._connect() as connection:
            return {
                "db_path": str(self.db_path),
                "security_events_count": self._count(connection, "security_events"),
                "incidents_count": self._count(connection, "incidents"),
                "incident_event_links_count": self._count(connection, "incident_events"),
                "risk_events_count": self._count(connection, "risk_events"),
                "risk_assessments_count": self._count(connection, "risk_assessments"),
                "control_recommendations_count": self._count(connection, "control_recommendations"),
            }

    def _upsert_security_event(
        self,
        connection: sqlite3.Connection,
        event: NormalizedSecurityEvent,
    ) -> None:
        payload = event.model_dump(mode="json")

        connection.execute(
            """
            INSERT OR REPLACE INTO security_events (
                event_id,
                source_log_id,
                timestamp,
                source_system,
                source_type,
                event_category,
                event_name,
                action,
                result,
                node_id,
                asset_id,
                subject_id,
                object_id,
                src_ip,
                dst_ip,
                normalized_severity,
                is_security_relevant,
                correlation_key,
                metadata_json,
                raw_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                event.event_id,
                event.source_log_id,
                event.timestamp,
                event.source_system,
                event.source_type.value,
                event.event_category.value,
                event.event_name,
                event.action,
                event.result.value,
                event.node_id,
                event.asset_id,
                event.subject_id,
                event.object_id,
                event.src_ip,
                event.dst_ip,
                event.normalized_severity,
                self._bool_to_int(event.is_security_relevant),
                event.correlation_key,
                self._to_json(event.metadata),
                self._to_json(payload),
            ),
        )

    def _upsert_incident(
        self,
        connection: sqlite3.Connection,
        incident: IncidentRecord,
    ) -> None:
        payload = incident.model_dump(mode="json")

        connection.execute(
            """
            INSERT OR REPLACE INTO incidents (
                incident_id,
                detected_at,
                incident_type,
                severity,
                status,
                node_id,
                asset_id,
                affected_process,
                description,
                classifier_confidence,
                evidence_json,
                metadata_json,
                raw_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                incident.incident_id,
                incident.detected_at,
                incident.incident_type.value,
                incident.severity.value,
                incident.status.value,
                incident.node_id,
                incident.asset_id,
                incident.affected_process,
                incident.description,
                incident.classifier_confidence,
                self._to_json(incident.evidence),
                self._to_json(incident.metadata),
                self._to_json(payload),
            ),
        )

    def _upsert_incident_event_links(
        self,
        connection: sqlite3.Connection,
        incident: IncidentRecord,
    ) -> None:
        for event_id in incident.created_from_event_ids:
            connection.execute(
                """
                INSERT OR REPLACE INTO incident_events (
                    incident_id,
                    event_id,
                    relation_type
                )
                VALUES (?, ?, ?);
                """,
                (
                    incident.incident_id,
                    event_id,
                    "created_from",
                ),
            )

    def _upsert_risk_event(
        self,
        connection: sqlite3.Connection,
        risk_event: RiskEventRecord,
    ) -> None:
        payload = risk_event.model_dump(mode="json")

        connection.execute(
            """
            INSERT OR REPLACE INTO risk_events (
                risk_event_id,
                incident_id,
                event_type,
                threat_scenario,
                node_id,
                asset_id,
                affected_process,
                has_actual_loss,
                estimated_loss,
                potential_loss,
                probability_estimate,
                impact_estimate,
                registration_threshold_reached,
                classifier_confidence,
                rationale_json,
                metadata_json,
                raw_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                risk_event.risk_event_id,
                risk_event.incident_id,
                risk_event.event_type.value,
                risk_event.threat_scenario.value,
                risk_event.node_id,
                risk_event.asset_id,
                risk_event.affected_process,
                self._bool_to_int(risk_event.has_actual_loss),
                risk_event.estimated_loss,
                risk_event.potential_loss,
                risk_event.probability_estimate,
                risk_event.impact_estimate,
                self._bool_to_int(risk_event.registration_threshold_reached),
                risk_event.classifier_confidence,
                self._to_json(risk_event.rationale),
                self._to_json(risk_event.metadata),
                self._to_json(payload),
            ),
        )

    def _upsert_risk_assessment(
        self,
        connection: sqlite3.Connection,
        assessment: RiskAssessmentRecord,
    ) -> None:
        payload = assessment.model_dump(mode="json")

        connection.execute(
            """
            INSERT OR REPLACE INTO risk_assessments (
                assessment_id,
                risk_event_id,
                incident_id,
                node_id,
                asset_id,
                threat_scenario,
                probability_estimate,
                impact_estimate,
                initial_risk_estimate,
                graph_adjusted_risk_estimate,
                final_risk_estimate,
                risk_class,
                priority,
                explanation_json,
                metadata_json,
                raw_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                assessment.assessment_id,
                assessment.risk_event_id,
                assessment.incident_id,
                assessment.node_id,
                assessment.asset_id,
                assessment.threat_scenario.value,
                assessment.probability_estimate,
                assessment.impact_estimate,
                assessment.initial_risk_estimate,
                assessment.graph_adjusted_risk_estimate,
                assessment.final_risk_estimate,
                assessment.risk_class.value,
                assessment.priority,
                self._to_json(assessment.explanation),
                self._to_json(assessment.metadata),
                self._to_json(payload),
            ),
        )

    def _upsert_control_recommendation(
            self,
            connection: sqlite3.Connection,
            measure: RecommendedControlMeasure,
    ) -> None:
        payload = measure.model_dump(mode="json")

        connection.execute(
            """
            INSERT OR REPLACE INTO control_recommendations (
                measure_id,
                name,
                measure_type,
                description,
                cost,
                labor,
                implementation_time,
                expected_risk_reduction,
                expected_residual_risk,
                covered_risk_event_ids_json,
                covered_assessment_ids_json,
                covered_node_ids_json,
                rationale_json,
                metadata_json,
                raw_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                measure.measure_id,
                measure.name,
                measure.measure_type.value,
                measure.description,
                measure.cost,
                measure.labor,
                measure.implementation_time,
                measure.expected_risk_reduction,
                measure.expected_residual_risk,
                self._to_json(measure.covered_risk_event_ids),
                self._to_json(measure.covered_assessment_ids),
                self._to_json(measure.covered_node_ids),
                self._to_json(measure.rationale),
                self._to_json(measure.metadata),
                self._to_json(payload),
            ),
        )

    def _fetch_all(
        self,
        query: str,
        params: tuple[Any, ...] = (),
    ) -> List[Dict[str, Any]]:
        with self._connect() as connection:
            cursor = connection.execute(query, params)
            rows = cursor.fetchall()
            return [self._row_to_dict(row) for row in rows]

    def _count(self, connection: sqlite3.Connection, table_name: str) -> int:
        cursor = connection.execute(f"SELECT COUNT(*) AS count_value FROM {table_name};")
        row = cursor.fetchone()
        return int(row["count_value"])

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        result = dict(row)

        for key in [
            "metadata_json",
            "raw_json",
            "evidence_json",
            "rationale_json",
            "explanation_json",
            "covered_risk_event_ids_json",
            "covered_assessment_ids_json",
            "covered_node_ids_json",
        ]:
            if key in result:
                result[key.replace("_json", "")] = self._from_json(result.pop(key))
        for key in [
            "is_security_relevant",
            "has_actual_loss",
            "registration_threshold_reached",
        ]:
            if key in result and result[key] is not None:
                result[key] = bool(result[key])

        return result

    def _to_json(self, value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)

    def _from_json(self, value: Optional[str]) -> Any:
        if value is None or value == "":
            return None
        return json.loads(value)

    def _bool_to_int(self, value: bool) -> int:
        return 1 if value else 0