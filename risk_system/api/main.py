from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from fastapi.staticfiles import StaticFiles
from risk_system.ui import router as ui_router

from risk_system.bayesian import BayesianEngine
from risk_system.config import settings
from risk_system.data import Storage
from risk_system.domain import (
    Asset,
    ExplanationItem,
    Node,
    OptimizationRequest,
    OptimizationResponse,
    RiskAssessmentRequest,
    RiskAssessmentResponse,
    SecurityEvent,
)
from risk_system.features import FeatureEngine
from risk_system.models import Calibrator, RiskModel
from risk_system.optimization import ControlOptimizer
from risk_system.risk import GraphPropagator, ImpactModel, InfluenceMatrixBuilder, RiskEngine


class TrainingRequest(BaseModel):
    events: List[SecurityEvent]
    nodes: List[Node]
    assets: List[Asset]
    labels: Dict[str, int] = Field(..., description="Отображение event_id -> целевая метка 0/1")
    model_type: Optional[str] = Field(default=None)
    model_params: Dict[str, Any] = Field(default_factory=dict)
    use_calibration: bool = Field(default=True)


class TrainingResponse(BaseModel):
    status: str
    model_info: Dict[str, Any]
    metrics: Dict[str, float | None]
    samples: int


class AppContainer:
    def __init__(self) -> None:
        self.storage = Storage()

        self.feature_engine = FeatureEngine()
        self.risk_model: Optional[RiskModel] = None
        self.calibrator: Optional[Calibrator] = None

        self.impact_model = ImpactModel(
            event_component_weight=settings.impact.event_component_weight,
            asset_component_weight=settings.impact.asset_component_weight,
            severity_weight=settings.impact.severity_weight,
            frequency_weight=settings.impact.frequency_weight,
            anomaly_weight=settings.impact.anomaly_weight,
            vulnerability_weight=settings.impact.vulnerability_weight,
            privilege_weight=settings.impact.privilege_weight,
            exposure_weight=settings.impact.exposure_weight,
            event_context_weight=settings.impact.event_context_weight,
            cost_weight=settings.impact.cost_weight,
            data_sensitivity_weight=settings.impact.data_sensitivity_weight,
            regulatory_weight=settings.impact.regulatory_weight,
            client_exposure_weight=settings.impact.client_exposure_weight,
            business_criticality_weight=settings.impact.business_criticality_weight,
            tier_weight=settings.impact.tier_weight,
            node_criticality_weight=settings.impact.node_criticality_weight,
            asset_criticality_weight=settings.impact.asset_criticality_weight,
            business_context_weight=settings.impact.business_context_weight,
            frequency_scale=settings.impact.frequency_scale,
            asset_cost_scale=settings.impact.asset_cost_scale,
            tier_scale=settings.impact.tier_scale,
            failed_logins_scale=settings.impact.failed_logins_scale,
            suspicious_processes_scale=settings.impact.suspicious_processes_scale,
            open_ports_scale=settings.impact.open_ports_scale,
            large_transfer_scale=settings.impact.large_transfer_scale,
            threat_multipliers=settings.impact.threat_multipliers,
        )

        self.risk_engine = RiskEngine(
            low_threshold=settings.risk_thresholds.low_threshold,
            medium_threshold=settings.risk_thresholds.medium_threshold,
            high_threshold=settings.risk_thresholds.high_threshold,
            propagation_blend=settings.propagation.blend,
            threshold_mode=settings.risk_thresholds.mode,
            empirical_low_quantile=settings.risk_thresholds.empirical_low_quantile,
            empirical_medium_quantile=settings.risk_thresholds.empirical_medium_quantile,
            empirical_high_quantile=settings.risk_thresholds.empirical_high_quantile,
            min_threshold_gap=settings.risk_thresholds.min_threshold_gap,
        )

        self.influence_builder = InfluenceMatrixBuilder(
            self_weight=settings.influence.self_weight,
            normalize_rows=settings.influence.normalize_rows,
            min_weight=settings.influence.min_weight,
            max_weight=settings.influence.max_weight,
            trust_weight=settings.influence.trust_weight,
            same_segment_bonus=settings.influence.same_segment_bonus,
            cross_segment_penalty=settings.influence.cross_segment_penalty,
            same_service_bonus=settings.influence.same_service_bonus,
            node_type_matrix=settings.influence.node_type_matrix,
        )

        self.graph_propagator = GraphPropagator(
            alpha=settings.propagation.alpha,
            decay=settings.propagation.decay,
            max_iter=settings.propagation.max_iter,
            tol=settings.propagation.tol,
            clip_to_unit=settings.propagation.clip_to_unit,
            max_growth_factor=settings.propagation.max_growth_factor,
            growth_margin=settings.propagation.growth_margin,
        )

        self.bayesian_engine = BayesianEngine(
            dependencies=settings.bayesian.dependencies,
            group_key=settings.bayesian.group_key,
            min_probability=settings.bayesian.min_probability,
            max_probability=settings.bayesian.max_probability,
        )

        self.control_optimizer = ControlOptimizer(
            min_effectiveness=settings.optimization.min_effectiveness,
            require_applicability=settings.optimization.require_applicability,
            class_weights=settings.optimization.class_weights,
        )

        self.is_trained: bool = False

    def train(self, request: TrainingRequest) -> TrainingResponse:
        x_train, y_train, _, _ = self.feature_engine.fit_transform(
            events=request.events,
            nodes=request.nodes,
            assets=request.assets,
            target=request.labels,
        )

        if y_train is None:
            raise ValueError("Не удалось сформировать целевую переменную для обучения.")

        self.risk_model = RiskModel(
            model_type=request.model_type or settings.model.default_model_type,
            random_state=settings.model.random_state,
            **request.model_params,
        )
        self.risk_model.fit(x_train, y_train)

        raw_proba = self.risk_model.predict_proba(x_train)
        metrics = self.risk_model.evaluate(x_train, y_train)

        if request.use_calibration:
            self.calibrator = Calibrator(method=settings.calibration.method)
            self.calibrator.fit(raw_proba, y_train.to_numpy())
        else:
            self.calibrator = None

        self.is_trained = True

        return TrainingResponse(
            status="trained",
            model_info=self.risk_model.get_model_info(),
            metrics={
                "accuracy": metrics.accuracy,
                "precision": metrics.precision,
                "recall": metrics.recall,
                "f1": metrics.f1,
                "roc_auc": metrics.roc_auc,
            },
            samples=len(x_train),
        )

    def assess(self, request: RiskAssessmentRequest) -> RiskAssessmentResponse:
        if not self.is_trained or self.risk_model is None:
            raise RuntimeError("Модель еще не обучена. Сначала вызови endpoint /train.")

        self.storage.store_request(request)

        x_infer, _, feature_table = self.feature_engine.transform_from_entities(
            events=request.events,
            nodes=request.nodes,
            assets=request.assets,
        )

        raw_proba = self.risk_model.predict_proba(x_infer)

        probabilities = feature_table[["event_id", "node_id", "asset_id", "threat_type"]].copy()
        probabilities["raw_probability"] = raw_proba

        if self.calibrator is not None:
            probabilities["calibrated_probability"] = self.calibrator.transform(raw_proba)

        probabilities = self.bayesian_engine.update_probabilities(probabilities)

        impact_table = self.impact_model.evaluate_from_feature_table(feature_table)

        event_risk_table = self.risk_engine.build_event_risk_table(
            probabilities=probabilities,
            impact_table=impact_table,
        )

        if request.edges:
            node_risk_table = self.risk_engine.aggregate_node_risks(event_risk_table)

            influence_result = self.influence_builder.build_from_edges(
                nodes=request.nodes,
                edges=request.edges,
            )

            propagation_result = self.graph_propagator.propagate(
                node_risk_table=node_risk_table,
                influence_result=influence_result,
                iterative=True,
            )

            event_risk_table = self.risk_engine.apply_propagated_node_risks(
                event_risk_table=event_risk_table,
                propagated_node_risks=propagation_result.node_risks[["node_id", "propagated_risk"]],
            )

        explanations = self._build_explanations_map(request.nodes)

        response = self.risk_engine.build_risk_response(
            event_risk_table=event_risk_table,
            explanations=explanations,
        )

        self.storage.store_response(response)
        return response

    def optimize(self, request: OptimizationRequest) -> OptimizationResponse:
        self.storage.store_optimization_request(request)
        response = self.control_optimizer.optimize(request)
        self.storage.store_optimization_response(response)
        return response

    def get_latest_response(self) -> Optional[RiskAssessmentResponse]:
        return self.storage.get_response()

    def get_thresholds(self) -> Dict[str, float | str]:
        return self.risk_engine.get_thresholds()

    def _build_explanations_map(self, nodes: List[Node]) -> Dict[str, List[ExplanationItem]]:
        if self.risk_model is None:
            return {}

        feature_names = self.feature_engine.get_feature_names()
        if not feature_names:
            return {}

        try:
            importance_table = self.risk_model.get_feature_importance(feature_names)
            explanation_items = self.risk_engine.build_explanations_from_importance(
                importance_table=importance_table,
                top_k=5,
            )
        except Exception:
            explanation_items = []

        return {node.node_id: explanation_items for node in nodes}


container = AppContainer()

app = FastAPI(
    title=settings.api.title,
    version=settings.api.version,
    description=settings.api.description,
)

app.include_router(ui_router)
app.mount("/static", StaticFiles(directory=str(settings.paths.static_dir)), name="static")


@app.get("/health")
def healthcheck() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/train", response_model=TrainingResponse)
def train_model(request: TrainingRequest) -> TrainingResponse:
    try:
        return container.train(request)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/assess", response_model=RiskAssessmentResponse)
def assess_risk(request: RiskAssessmentRequest) -> RiskAssessmentResponse:
    try:
        return container.assess(request)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/optimize", response_model=OptimizationResponse)
def optimize_controls(request: OptimizationRequest) -> OptimizationResponse:
    try:
        return container.optimize(request)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/latest", response_model=RiskAssessmentResponse)
def get_latest_result() -> RiskAssessmentResponse:
    latest = container.get_latest_response()
    if latest is None:
        raise HTTPException(status_code=404, detail="Результаты оценки пока отсутствуют.")
    return latest


@app.get("/thresholds")
def get_thresholds() -> Dict[str, float | str]:
    return container.get_thresholds()