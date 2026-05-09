from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np
import pandas as pd
from joblib import dump, load
from sklearn.inspection import permutation_importance
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GridSearchCV, StratifiedKFold, train_test_split


@dataclass
class ModelEvaluationResult:
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: Optional[float] = None


class RiskModel:
    def __init__(
        self,
        model_type: str = "random_forest",
        random_state: int = 42,
        **model_params: Any,
    ) -> None:
        self.model_type = model_type
        self.random_state = random_state
        self.model_params = model_params
        self.model = self._build_model(model_type, random_state, **model_params)
        self.is_fitted_: bool = False
        self.classes_: Optional[np.ndarray] = None

    def fit(self, x_train: pd.DataFrame | np.ndarray, y_train: pd.Series | np.ndarray) -> "RiskModel":
        x_values = self._to_matrix(x_train)
        y_values = self._to_vector(y_train)

        self.model.fit(x_values, y_values)
        self.is_fitted_ = True
        self.classes_ = getattr(self.model, "classes_", None)
        return self

    def predict_proba(self, x: pd.DataFrame | np.ndarray) -> np.ndarray:
        self._ensure_fitted()
        x_values = self._to_matrix(x)

        if not hasattr(self.model, "predict_proba"):
            raise RuntimeError("Текущая модель не поддерживает predict_proba.")

        probabilities = self.model.predict_proba(x_values)
        if probabilities.ndim != 2 or probabilities.shape[1] < 2:
            raise RuntimeError("Некорректный формат вероятностей, возвращенный моделью.")

        return probabilities[:, 1]

    def predict(self, x: pd.DataFrame | np.ndarray, threshold: float = 0.5) -> np.ndarray:
        probabilities = self.predict_proba(x)
        return (probabilities >= threshold).astype(int)

    def evaluate(
        self,
        x_test: pd.DataFrame | np.ndarray,
        y_test: pd.Series | np.ndarray,
        threshold: float = 0.5,
    ) -> ModelEvaluationResult:
        self._ensure_fitted()

        y_true = self._to_vector(y_test)
        y_proba = self.predict_proba(x_test)
        y_pred = (y_proba >= threshold).astype(int)

        accuracy = float(accuracy_score(y_true, y_pred))
        precision = float(precision_score(y_true, y_pred, zero_division=0))
        recall = float(recall_score(y_true, y_pred, zero_division=0))
        f1 = float(f1_score(y_true, y_pred, zero_division=0))

        roc_auc: Optional[float]
        if len(np.unique(y_true)) > 1:
            roc_auc = float(roc_auc_score(y_true, y_proba))
        else:
            roc_auc = None

        return ModelEvaluationResult(
            model_name=self.model_type,
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1=f1,
            roc_auc=roc_auc,
        )

    def fit_and_evaluate(
        self,
        x: pd.DataFrame | np.ndarray,
        y: pd.Series | np.ndarray,
        test_size: float = 0.2,
        threshold: float = 0.5,
    ) -> ModelEvaluationResult:
        x_values = self._to_matrix(x)
        y_values = self._to_vector(y)

        x_train, x_test, y_train, y_test = train_test_split(
            x_values,
            y_values,
            test_size=test_size,
            random_state=self.random_state,
            stratify=y_values if len(np.unique(y_values)) > 1 else None,
        )

        self.fit(x_train, y_train)
        return self.evaluate(x_test, y_test, threshold=threshold)

    def tune(
        self,
        x_train: pd.DataFrame | np.ndarray,
        y_train: pd.Series | np.ndarray,
        scoring: str = "f1",
        cv: int = 3,
        param_grid: Optional[Dict[str, list[Any]]] = None,
    ) -> Dict[str, Any]:
        x_values = self._to_matrix(x_train)
        y_values = self._to_vector(y_train)

        unique, counts = np.unique(y_values, return_counts=True)
        if len(unique) < 2:
            self.fit(x_values, y_values)
            return {
                "used": False,
                "reason": "Подбор гиперпараметров невозможен: в обучающей выборке только один класс.",
            }

        min_class_count = int(counts.min())
        effective_cv = min(cv, min_class_count)

        if effective_cv < 2:
            self.fit(x_values, y_values)
            return {
                "used": False,
                "reason": "Подбор гиперпараметров невозможен: недостаточно объектов в одном из классов.",
            }

        grid = param_grid or self._default_param_grid(self.model_type)

        if not grid:
            self.fit(x_values, y_values)
            return {
                "used": False,
                "reason": f"Для модели {self.model_type} не задана сетка гиперпараметров.",
            }

        cv_strategy = StratifiedKFold(
            n_splits=effective_cv,
            shuffle=True,
            random_state=self.random_state,
        )

        search = GridSearchCV(
            estimator=self.model,
            param_grid=grid,
            scoring=scoring,
            cv=cv_strategy,
            n_jobs=None,
        )

        search.fit(x_values, y_values)

        self.model = search.best_estimator_
        self.model_params.update(search.best_params_)
        self.is_fitted_ = True
        self.classes_ = getattr(self.model, "classes_", None)

        return {
            "used": True,
            "model_type": self.model_type,
            "scoring": scoring,
            "cv": effective_cv,
            "best_score": float(search.best_score_),
            "best_params": dict(search.best_params_),
        }

    def _default_param_grid(self, model_type: str) -> Dict[str, list[Any]]:
        if model_type == "logistic_regression":
            return {
                "C": [0.1, 1.0, 3.0],
                "class_weight": ["balanced"],
            }

        if model_type == "random_forest":
            return {
                "n_estimators": [200, 300],
                "max_depth": [6, 8, 12],
                "min_samples_split": [6, 10],
                "min_samples_leaf": [2, 4],
                "class_weight": ["balanced"],
            }

        if model_type == "gradient_boosting":
            return {
                "n_estimators": [100, 150, 200],
                "learning_rate": [0.03, 0.05, 0.1],
                "max_depth": [2, 3],
            }

        return {}

    def save(self, path: str | Path) -> None:
        self._ensure_fitted()
        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "model_type": self.model_type,
            "random_state": self.random_state,
            "model_params": self.model_params,
            "model": self.model,
            "is_fitted_": self.is_fitted_,
            "classes_": self.classes_,
        }
        dump(payload, file_path)

    @classmethod
    def load(cls, path: str | Path) -> "RiskModel":
        file_path = Path(path)
        payload = load(file_path)

        instance = cls(
            model_type=payload["model_type"],
            random_state=payload["random_state"],
            **payload["model_params"],
        )
        instance.model = payload["model"]
        instance.is_fitted_ = payload["is_fitted_"]
        instance.classes_ = payload["classes_"]
        return instance

    def get_feature_importance(
        self,
        feature_names: list[str],
    ) -> pd.DataFrame:
        self._ensure_fitted()

        if hasattr(self.model, "feature_importances_"):
            importances = np.asarray(self.model.feature_importances_, dtype=float)
        elif hasattr(self.model, "coef_"):
            coef = np.asarray(self.model.coef_, dtype=float)
            if coef.ndim == 2:
                importances = np.abs(coef[0])
            else:
                importances = np.abs(coef)
        else:
            raise RuntimeError("Для текущей модели важности признаков недоступны.")

        if len(importances) != len(feature_names):
            raise ValueError("Количество важностей признаков не совпадает с длиной feature_names.")

        result = pd.DataFrame(
            {
                "feature_name": feature_names,
                "importance": importances,
            }
        )
        result = result.sort_values("importance", ascending=False).reset_index(drop=True)
        return result

    def get_permutation_importance(
        self,
        x: pd.DataFrame | np.ndarray,
        y: pd.Series | np.ndarray,
        feature_names: list[str],
        scoring: str = "f1",
        n_repeats: int = 10,
    ) -> pd.DataFrame:
        self._ensure_fitted()

        x_values = self._to_matrix(x)
        y_values = self._to_vector(y)

        if len(feature_names) != x_values.shape[1]:
            raise ValueError(
                "Количество имен признаков не совпадает с числом столбцов в x."
            )

        if len(np.unique(y_values)) < 2 and scoring in {"roc_auc", "average_precision"}:
            raise ValueError(
                f"Permutation importance с метрикой {scoring} невозможна: "
                "в выборке присутствует только один класс."
            )

        result = permutation_importance(
            estimator=self.model,
            X=x_values,
            y=y_values,
            scoring=scoring,
            n_repeats=n_repeats,
            random_state=self.random_state,
            n_jobs=None,
        )

        importance_table = pd.DataFrame(
            {
                "feature_name": feature_names,
                "importance": result.importances_mean,
                "importance_mean": result.importances_mean,
                "importance_std": result.importances_std,
            }
        )

        importance_table["importance_abs"] = importance_table["importance_mean"].abs()
        importance_table["scoring"] = scoring
        importance_table["n_repeats"] = n_repeats

        importance_table = importance_table.sort_values(
            "importance_mean",
            ascending=False,
        ).reset_index(drop=True)

        return importance_table


    def get_model_info(self) -> Dict[str, Any]:
        return {
            "model_type": self.model_type,
            "random_state": self.random_state,
            "model_params": self.model_params,
            "is_fitted": self.is_fitted_,
            "classes": None if self.classes_ is None else self.classes_.tolist(),
        }

    def _build_model(
        self,
        model_type: str,
        random_state: int,
        **model_params: Any,
    ) -> Any:
        if model_type == "logistic_regression":
            default_params = {
                "random_state": random_state,
                "max_iter": 1000,
                "class_weight": "balanced",
            }
            default_params.update(model_params)
            return LogisticRegression(**default_params)

        if model_type == "random_forest":
            default_params = {
                "random_state": random_state,
                "n_estimators": 300,
                "max_depth": 8,
                "min_samples_split": 10,
                "min_samples_leaf": 4,
                "class_weight": "balanced",
            }
            default_params.update(model_params)
            return RandomForestClassifier(**default_params)

        if model_type == "gradient_boosting":
            default_params = {
                "random_state": random_state,
                "n_estimators": 150,
                "learning_rate": 0.05,
                "max_depth": 3,
            }
            default_params.update(model_params)
            return GradientBoostingClassifier(**default_params)

        raise ValueError(
            "Неизвестный тип модели. Поддерживаются: "
            "'logistic_regression', 'random_forest', 'gradient_boosting'."
        )

    @staticmethod
    def _to_matrix(x: pd.DataFrame | np.ndarray) -> np.ndarray:
        if isinstance(x, pd.DataFrame):
            return x.to_numpy()
        return np.asarray(x)

    @staticmethod
    def _to_vector(y: pd.Series | np.ndarray) -> np.ndarray:
        if isinstance(y, pd.Series):
            return y.to_numpy().astype(int)
        return np.asarray(y).astype(int)

    def _ensure_fitted(self) -> None:
        if not self.is_fitted_:
            raise RuntimeError("Модель еще не обучена.")