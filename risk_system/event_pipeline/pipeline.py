from __future__ import annotations

from .bayesian_adjuster import BayesianRiskEventAdjuster
from .graph_adjustment import GraphRiskAdjustmentEngine
from .incident_classifier import IncidentClassifier
from .normalizer import EventNormalizer
from .risk_assessment import RiskEventAssessmentEngine
from .risk_event_classifier import RiskEventClassifier
from .schemas import (
    EventPipelineRequest,
    EventPipelineResponse,
    FullPipelineResponse,
    PipelineSummary,
)
from .control_optimizer import EventRiskControlOptimizer


class EventRiskPipeline:
    def __init__(self) -> None:
        self.normalizer = EventNormalizer()
        self.incident_classifier = IncidentClassifier()
        self.risk_event_classifier = RiskEventClassifier()
        self.bayesian_adjuster = BayesianRiskEventAdjuster()
        self.risk_assessment_engine = RiskEventAssessmentEngine()
        self.graph_adjustment_engine = GraphRiskAdjustmentEngine()
        self.control_optimizer = EventRiskControlOptimizer()

    def process(self, request: EventPipelineRequest) -> EventPipelineResponse:
        normalized_events = self.normalizer.normalize_many(request.logs)

        incidents = self.incident_classifier.classify_many(
            events=normalized_events,
            threshold=request.incident_threshold,
        )

        risk_events = self.risk_event_classifier.classify_many(
            incidents=incidents,
            threshold=request.risk_event_threshold,
        )
        risk_events = self.bayesian_adjuster.adjust_many(risk_events)

        summary = PipelineSummary(
            logs_received=len(request.logs),
            normalized_events_count=len(normalized_events),
            incident_candidates_count=len(incidents),
            risk_events_count=len(risk_events),
            pipeline_stages={
                "stage_1": "Прием записей журналов от SIEM, средств защиты, ОС или приложений",
                "stage_2": "Нормализация записей журналов в события защиты информации",
                "stage_3": "Корреляция событий защиты информации по объекту, активу, субъекту и источнику",
                "stage_4": "Выявление инцидентов защиты информации на основе формализованных экспертных правил",
                "stage_5": "Отнесение инцидентов защиты информации к событиям риска реализации информационных угроз",
                "stage_6": "Байесовское уточнение вероятностной составляющей с учетом зависимостей сценариев",
            },
        )

        return EventPipelineResponse(
            summary=summary,
            normalized_events=normalized_events,
            incidents=incidents,
            risk_events=risk_events,
        )

    def process_full(self, request: EventPipelineRequest) -> FullPipelineResponse:
        pipeline_response = self.process(request)

        local_risk_assessments = self.risk_assessment_engine.assess_many(
            pipeline_response.risk_events
        )

        graph_adjusted_assessments = self.graph_adjustment_engine.adjust_many(
            assessments=local_risk_assessments,
            infrastructure_links=request.infrastructure_links,
        )

        control_optimization = self.control_optimizer.optimize(
            assessments=graph_adjusted_assessments,
            measures=request.control_measures,
            constraints=request.optimization_constraints,
        )

        pipeline_response.summary.pipeline_stages[
            "stage_7"
        ] = "Расчетная оценка риска и графовое уточнение результата с учетом инфраструктурных связей"

        pipeline_response.summary.pipeline_stages[
            "stage_8"
        ] = "Подбор мер обработки риска при ограничениях на бюджет и трудоемкость"

        return FullPipelineResponse(
            pipeline=pipeline_response,
            risk_assessments=graph_adjusted_assessments,
            control_optimization=control_optimization,
        )
