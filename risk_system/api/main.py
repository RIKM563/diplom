from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field
from fastapi.staticfiles import StaticFiles
from risk_system.ui import router as ui_router

from risk_system.bayesian import BayesianEngine
from risk_system.config import settings
from risk_system.data import EventPipelineRepository, Storage
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
from risk_system.event_pipeline import (
    EventPipelineRequest,
    EventPipelineResponse,
    EventRiskPipeline,
    FullPipelineResponse,
    RiskEventClassifierFlatTrainingRequest,
    RiskEventClassifierTrainingRequest,
    RiskEventClassifierTrainingResponse,
    RiskEventTrainingSampleImporter,
)


class TrainingRequest(BaseModel):
    events: List[SecurityEvent]
    nodes: List[Node]
    assets: List[Asset]

    labels: Dict[str, int] = Field(
        ...,
        description="Отображение event_id -> целевая метка 0/1",
    )

    model_type: Optional[str] = Field(default=None)
    model_params: Dict[str, Any] = Field(default_factory=dict)

    use_calibration: bool = Field(default=True)

    validation_size: float = Field(
        default=0.30,
        ge=0.10,
        le=0.50,
        description="Доля данных, выделяемая на валидацию и калибровку",
    )

    calibration_size: float = Field(
        default=0.50,
        ge=0.20,
        le=0.80,
        description="Доля holdout-части, выделяемая на обучение калибратора",
    )

    threshold: float = Field(
        default=0.50,
        ge=0.0,
        le=1.0,
        description="Порог вероятности для расчета классификационных метрик",
    )

    tune_hyperparameters: bool = Field(
        default=False,
        description="Выполнять ли подбор гиперпараметров модели",
    )

    tuning_scoring: str = Field(
        default="f1",
        description="Метрика для подбора гиперпараметров",
    )

    cv_folds: int = Field(
        default=3,
        ge=2,
        le=10,
        description="Число фолдов кросс-валидации при подборе гиперпараметров",
    )

    compute_permutation_importance: bool = Field(
        default=True,
        description="Вычислять ли permutation importance на validation-части",
    )

    permutation_scoring: str = Field(
        default="f1",
        description="Метрика для permutation importance",
    )

    permutation_n_repeats: int = Field(
        default=10,
        ge=3,
        le=50,
        description="Число перестановок каждого признака",
    )

    importance_top_k: int = Field(
        default=15,
        ge=1,
        le=100,
        description="Количество признаков, возвращаемых в ответе обучения",
    )


class TrainingResponse(BaseModel):
    status: str
    model_info: Dict[str, Any]

    metrics: Dict[str, float | None]
    train_metrics: Dict[str, float | None] = Field(default_factory=dict)
    validation_metrics: Dict[str, float | None] = Field(default_factory=dict)
    calibration_metrics: Dict[str, float | None] = Field(default_factory=dict)
    feature_importance: List[Dict[str, Any]] = Field(default_factory=list)
    permutation_importance: List[Dict[str, Any]] = Field(default_factory=list)

    samples: int
    train_samples: int = 0
    validation_samples: int = 0
    calibration_samples: int = 0

    tuning_result: Dict[str, Any] = Field(default_factory=dict)
    notes: List[str] = Field(default_factory=list)


class AppContainer:
    def __init__(self) -> None:
        self.storage = Storage()
        self.event_repository = EventPipelineRepository()
        self.event_risk_pipeline = EventRiskPipeline()
        self.risk_event_training_importer = RiskEventTrainingSampleImporter()
        self.feature_engine = FeatureEngine()
        self.risk_model: Optional[RiskModel] = None
        self.calibrator: Optional[Calibrator] = None
        self.feature_importance_table: Optional[pd.DataFrame] = None
        self.permutation_importance_table: Optional[pd.DataFrame] = None

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

    def process_logs(self, request: EventPipelineRequest) -> EventPipelineResponse:
        response = self.event_risk_pipeline.process(request)
        self.event_repository.save_pipeline_response(response)
        return response

    def list_security_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.event_repository.list_security_events(limit=limit)

    def list_incidents(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.event_repository.list_incidents(limit=limit)

    def list_risk_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.event_repository.list_risk_events(limit=limit)

    def list_risk_assessments(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.event_repository.list_risk_assessments(limit=limit)

    def get_event_storage_summary(self) -> Dict[str, int | str]:
        return self.event_repository.get_summary()

    def process_full_pipeline(self, request: EventPipelineRequest) -> FullPipelineResponse:
        response = self.event_risk_pipeline.process_full(request)
        self.event_repository.save_full_pipeline_response(response)
        return response

    def train(self, request: TrainingRequest) -> TrainingResponse:
        notes: List[str] = []

        y_all = self._labels_for_events(request.events, request.labels)

        if len(request.events) < 5 or len(np.unique(y_all)) < 2:
            notes.append(
                "Данных недостаточно для корректного разбиения на train/validation/calibration. "
                "Модель обучена и оценена на полном наборе; такие метрики следует считать техническими."
            )

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

            tuning_result: Dict[str, Any] = {}
            if request.tune_hyperparameters:
                tuning_result = self.risk_model.tune(
                    x_train=x_train,
                    y_train=y_train,
                    scoring=request.tuning_scoring,
                    cv=request.cv_folds,
                )
            else:
                self.risk_model.fit(x_train, y_train)

            train_eval = self.risk_model.evaluate(
                x_train,
                y_train,
                threshold=request.threshold,
            )
            train_metrics = self._metrics_to_dict(train_eval)

            self._update_importance_tables(
                x_reference=x_train,
                y_reference=y_train,
                compute_permutation=request.compute_permutation_importance,
                permutation_scoring=request.permutation_scoring,
                permutation_n_repeats=request.permutation_n_repeats,
            )

            feature_importance = self._importance_to_records(
                self.feature_importance_table,
                top_k=request.importance_top_k,
            )

            permutation_importance_records = self._importance_to_records(
                self.permutation_importance_table,
                top_k=request.importance_top_k,
            )

            calibration_metrics: Dict[str, float | None] = {}
            if request.use_calibration:
                raw_train = self.risk_model.predict_proba(x_train)
                self.calibrator = Calibrator(method=settings.calibration.method)
                self.calibrator.fit(raw_train, y_train.to_numpy())
                calibrated_train = self.calibrator.transform(raw_train)
                calibration_eval = self.calibrator.evaluate(
                    raw_train,
                    calibrated_train,
                    y_train.to_numpy(),
                )
                calibration_metrics = self._calibration_metrics_to_dict(calibration_eval)
                notes.append(
                    "Калибратор обучен на полном наборе из-за малого объема данных. "
                    "Для итогового эксперимента рекомендуется использовать отдельную калибровочную часть."
                )
            else:
                self.calibrator = None

            self.is_trained = True

            return TrainingResponse(
                status="trained",
                model_info=self.risk_model.get_model_info(),
                metrics=train_metrics,
                train_metrics=train_metrics,
                validation_metrics=train_metrics,
                calibration_metrics=calibration_metrics,
                samples=len(request.events),
                train_samples=len(request.events),
                validation_samples=0,
                calibration_samples=0,
                tuning_result=tuning_result,
                notes=notes,
                feature_importance=feature_importance,
                permutation_importance=permutation_importance_records,
            )

        train_events, holdout_events, y_train_raw, y_holdout_raw = train_test_split(
            list(request.events),
            y_all,
            test_size=request.validation_size,
            random_state=settings.model.random_state,
            stratify=self._stratify_or_none(y_all),
        )

        validation_events = holdout_events
        y_validation_raw = y_holdout_raw
        calibration_events: List[SecurityEvent] = []
        y_calibration_raw = np.array([], dtype=int)

        if request.use_calibration and len(holdout_events) >= 4:
            try:
                validation_events, calibration_events, y_validation_raw, y_calibration_raw = train_test_split(
                    list(holdout_events),
                    y_holdout_raw,
                    test_size=request.calibration_size,
                    random_state=settings.model.random_state,
                    stratify=self._stratify_or_none(y_holdout_raw),
                )
            except ValueError:
                calibration_events = list(holdout_events)
                y_calibration_raw = y_holdout_raw
                validation_events = list(holdout_events)
                y_validation_raw = y_holdout_raw
                notes.append(
                    "Holdout-часть не удалось разделить на независимые validation/calibration. "
                    "Для калибровки и проверки использована одна holdout-часть."
                )
        elif request.use_calibration:
            calibration_events = list(holdout_events)
            y_calibration_raw = y_holdout_raw
            notes.append(
                "Holdout-часть слишком мала для отдельной калибровочной выборки. "
                "Для калибровки использована вся holdout-часть."
            )

        train_labels = {
            event.event_id: int(label)
            for event, label in zip(train_events, y_train_raw)
        }

        x_train, y_train, _, _ = self.feature_engine.fit_transform(
            events=train_events,
            nodes=request.nodes,
            assets=request.assets,
            target=train_labels,
        )

        if y_train is None:
            raise ValueError("Не удалось сформировать целевую переменную для обучения.")

        x_validation, _, _ = self.feature_engine.transform_from_entities(
            events=validation_events,
            nodes=request.nodes,
            assets=request.assets,
        )
        y_validation = pd.Series(y_validation_raw, name="target").astype(int)

        self.risk_model = RiskModel(
            model_type=request.model_type or settings.model.default_model_type,
            random_state=settings.model.random_state,
            **request.model_params,
        )

        tuning_result = {}
        if request.tune_hyperparameters:
            tuning_result = self.risk_model.tune(
                x_train=x_train,
                y_train=y_train,
                scoring=request.tuning_scoring,
                cv=request.cv_folds,
            )
        else:
            self.risk_model.fit(x_train, y_train)

        train_eval = self.risk_model.evaluate(
            x_train,
            y_train,
            threshold=request.threshold,
        )
        validation_eval = self.risk_model.evaluate(
            x_validation,
            y_validation,
            threshold=request.threshold,
        )

        train_metrics = self._metrics_to_dict(train_eval)
        validation_metrics = self._metrics_to_dict(validation_eval)
        self._update_importance_tables(
            x_reference=x_validation,
            y_reference=y_validation,
            compute_permutation=request.compute_permutation_importance,
            permutation_scoring=request.permutation_scoring,
            permutation_n_repeats=request.permutation_n_repeats,
        )

        feature_importance = self._importance_to_records(
            self.feature_importance_table,
            top_k=request.importance_top_k,
        )

        permutation_importance_records = self._importance_to_records(
            self.permutation_importance_table,
            top_k=request.importance_top_k,
        )

        calibration_metrics: Dict[str, float | None] = {}

        if request.use_calibration:
            if not calibration_events:
                calibration_events = list(validation_events)
                y_calibration_raw = y_validation_raw

            x_calibration, _, _ = self.feature_engine.transform_from_entities(
                events=calibration_events,
                nodes=request.nodes,
                assets=request.assets,
            )
            y_calibration = pd.Series(y_calibration_raw, name="target").astype(int)

            raw_calibration = self.risk_model.predict_proba(x_calibration)

            self.calibrator = Calibrator(method=settings.calibration.method)
            self.calibrator.fit(raw_calibration, y_calibration.to_numpy())

            raw_validation = self.risk_model.predict_proba(x_validation)
            calibrated_validation = self.calibrator.transform(raw_validation)

            calibration_eval = self.calibrator.evaluate(
                raw_validation,
                calibrated_validation,
                y_validation.to_numpy(),
            )
            calibration_metrics = self._calibration_metrics_to_dict(calibration_eval)
        else:
            self.calibrator = None

        self.is_trained = True

        return TrainingResponse(
            status="trained",
            model_info=self.risk_model.get_model_info(),
            metrics=validation_metrics,
            train_metrics=train_metrics,
            validation_metrics=validation_metrics,
            calibration_metrics=calibration_metrics,
            samples=len(request.events),
            train_samples=len(train_events),
            validation_samples=len(validation_events),
            calibration_samples=len(calibration_events),
            tuning_result=tuning_result,
            notes=notes,
            feature_importance=feature_importance,
            permutation_importance=permutation_importance_records,
        )

    def train_risk_event_classifier(
        self,
        request: RiskEventClassifierTrainingRequest,
    ) -> RiskEventClassifierTrainingResponse:
        return self.event_risk_pipeline.risk_event_classifier.train(
            samples=request.samples,
            model_type=request.model_type,
            save_model=request.save_model,
        )

    def train_risk_event_classifier_flat(
        self,
        request: RiskEventClassifierFlatTrainingRequest,
    ) -> RiskEventClassifierTrainingResponse:
        return self.event_risk_pipeline.risk_event_classifier.train_flat(
            samples=request.samples,
            model_type=request.model_type,
            save_model=request.save_model,
        )

    def train_risk_event_classifier_from_file(
        self,
        filename: str,
        content: bytes,
        model_type: str = "random_forest",
        save_model: bool = True,
    ) -> RiskEventClassifierTrainingResponse:
        samples = self.risk_event_training_importer.parse_file(
            filename=filename,
            content=content,
        )

        return self.event_risk_pipeline.risk_event_classifier.train_flat(
            samples=samples,
            model_type=model_type,
            save_model=save_model,
        )

    @staticmethod
    def _labels_for_events(
            events: Sequence[SecurityEvent],
            labels: Dict[str, int],
    ) -> np.ndarray:
        missing = [event.event_id for event in events if event.event_id not in labels]
        if missing:
            raise ValueError(
                f"Для части событий отсутствуют целевые метки. "
                f"Примеры event_id: {missing[:5]}"
            )

        values = np.asarray(
            [labels[event.event_id] for event in events],
            dtype=int,
        )

        unique_values = set(np.unique(values).tolist())
        if not unique_values.issubset({0, 1}):
            raise ValueError("Целевые метки должны быть бинарными: 0 или 1.")

        return values

    @staticmethod
    def _stratify_or_none(labels: Sequence[int] | np.ndarray) -> Optional[np.ndarray]:
        values = np.asarray(labels, dtype=int)
        unique, counts = np.unique(values, return_counts=True)

        if len(unique) < 2:
            return None

        if int(counts.min()) < 2:
            return None

        return values

    @staticmethod
    def _metrics_to_dict(metrics: Any) -> Dict[str, float | None]:
        return {
            "accuracy": metrics.accuracy,
            "precision": metrics.precision,
            "recall": metrics.recall,
            "f1": metrics.f1,
            "roc_auc": metrics.roc_auc,
        }

    @staticmethod
    def _calibration_metrics_to_dict(metrics: Any) -> Dict[str, float | None]:
        return {
            "brier_before": metrics.brier_before,
            "brier_after": metrics.brier_after,
            "logloss_before": metrics.logloss_before,
            "logloss_after": metrics.logloss_after,
        }

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

    def _update_importance_tables(
            self,
            x_reference: pd.DataFrame | np.ndarray,
            y_reference: pd.Series | np.ndarray,
            compute_permutation: bool = True,
            permutation_scoring: str = "f1",
            permutation_n_repeats: int = 10,
    ) -> None:
        if self.risk_model is None:
            self.feature_importance_table = None
            self.permutation_importance_table = None
            return

        feature_names = self.feature_engine.get_feature_names()
        if not feature_names:
            self.feature_importance_table = None
            self.permutation_importance_table = None
            return

        try:
            self.feature_importance_table = self.risk_model.get_feature_importance(
                feature_names=feature_names,
            )
        except Exception:
            self.feature_importance_table = None

        if not compute_permutation:
            self.permutation_importance_table = None
            return

        try:
            self.permutation_importance_table = self.risk_model.get_permutation_importance(
                x=x_reference,
                y=y_reference,
                feature_names=feature_names,
                scoring=permutation_scoring,
                n_repeats=permutation_n_repeats,
            )
        except Exception:
            self.permutation_importance_table = None

    @staticmethod
    def _importance_to_records(
            importance_table: Optional[pd.DataFrame],
            top_k: int = 15,
    ) -> List[Dict[str, Any]]:
        if importance_table is None or importance_table.empty:
            return []

        safe_table = importance_table.head(top_k).copy()

        records: List[Dict[str, Any]] = []
        for row in safe_table.to_dict(orient="records"):
            records.append(
                {
                    key: (
                        None
                        if pd.isna(value)
                        else float(value)
                        if isinstance(value, (int, float, np.integer, np.floating))
                        else value
                    )
                    for key, value in row.items()
                }
            )

        return records

    def get_importance_response(self) -> Dict[str, Any]:
        return {
            "feature_importance": self._importance_to_records(
                self.feature_importance_table,
                top_k=50,
            ),
            "permutation_importance": self._importance_to_records(
                self.permutation_importance_table,
                top_k=50,
            ),
        }

    def _build_explanations_map(self, nodes: List[Node]) -> Dict[str, List[ExplanationItem]]:
        if self.risk_model is None:
            return {}

        importance_table = None

        if self.permutation_importance_table is not None and not self.permutation_importance_table.empty:
            importance_table = self.permutation_importance_table
        elif self.feature_importance_table is not None and not self.feature_importance_table.empty:
            importance_table = self.feature_importance_table
        else:
            feature_names = self.feature_engine.get_feature_names()
            if not feature_names:
                return {}

            try:
                importance_table = self.risk_model.get_feature_importance(feature_names)
            except Exception:
                return {}

        try:
            explanation_items = self.risk_engine.build_explanations_from_importance(
                importance_table=importance_table,
                top_k=5,
            )
        except Exception:
            explanation_items = []

        return {node.node_id: explanation_items for node in nodes}

    def list_control_recommendations(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.event_repository.list_control_recommendations(limit=limit)

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


@app.post("/process-logs", response_model=EventPipelineResponse)
def process_logs(request: EventPipelineRequest) -> EventPipelineResponse:
    try:
        return container.process_logs(request)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/security-events")
def list_security_events(limit: int = 100) -> List[Dict[str, Any]]:
    try:
        return container.list_security_events(limit=limit)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/incidents")
def list_incidents(limit: int = 100) -> List[Dict[str, Any]]:
    try:
        return container.list_incidents(limit=limit)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/risk-events")
def list_risk_events(limit: int = 100) -> List[Dict[str, Any]]:
    try:
        return container.list_risk_events(limit=limit)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/event-storage-summary")
def get_event_storage_summary() -> Dict[str, int | str]:
    try:
        return container.get_event_storage_summary()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


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


@app.get("/model/importance")
def get_model_importance() -> Dict[str, Any]:
    return container.get_importance_response()


@app.post("/pipeline/full", response_model=FullPipelineResponse)
def process_full_pipeline(request: EventPipelineRequest) -> FullPipelineResponse:
    try:
        return container.process_full_pipeline(request)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/risk-assessments")
def list_risk_assessments(limit: int = 100) -> List[Dict[str, Any]]:
    try:
        return container.list_risk_assessments(limit=limit)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/risk-event-classifier/train", response_model=RiskEventClassifierTrainingResponse)
def train_risk_event_classifier(
    request: RiskEventClassifierTrainingRequest,
) -> RiskEventClassifierTrainingResponse:
    try:
        return container.train_risk_event_classifier(request)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/risk-event-classifier/train-flat", response_model=RiskEventClassifierTrainingResponse)
def train_risk_event_classifier_flat(
    request: RiskEventClassifierFlatTrainingRequest,
) -> RiskEventClassifierTrainingResponse:
    try:
        return container.train_risk_event_classifier_flat(request)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/risk-event-classifier/train-file", response_model=RiskEventClassifierTrainingResponse)
async def train_risk_event_classifier_from_file(
    file: UploadFile = File(...),
    model_type: str = Form("random_forest"),
    save_model: bool = Form(True),
) -> RiskEventClassifierTrainingResponse:
    try:
        content = await file.read()

        return container.train_risk_event_classifier_from_file(
            filename=file.filename or "training_dataset",
            content=content,
            model_type=model_type,
            save_model=save_model,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

@app.get("/control-recommendations")
def list_control_recommendations(limit: int = 100) -> List[Dict[str, Any]]:
    try:
        return container.list_control_recommendations(limit=limit)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc