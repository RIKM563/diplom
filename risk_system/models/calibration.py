from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional

import numpy as np
from joblib import dump, load
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import brier_score_loss, log_loss


@dataclass
class CalibrationEvaluationResult:
    method: str
    brier_before: float
    brier_after: float
    logloss_before: Optional[float]
    logloss_after: Optional[float]


class Calibrator:
    def __init__(self, method: Literal["isotonic"] = "isotonic") -> None:
        self.method = method
        self.calibrator = self._build_calibrator(method)
        self.is_fitted_: bool = False

    def fit(self, raw_proba: np.ndarray, y_true: np.ndarray) -> "Calibrator":
        raw = self._to_probability_vector(raw_proba)
        target = self._to_binary_vector(y_true)

        if self.method == "isotonic":
            self.calibrator.fit(raw, target)
        else:
            raise ValueError(f"Неподдерживаемый метод калибровки: {self.method}")

        self.is_fitted_ = True
        return self

    def transform(self, raw_proba: np.ndarray) -> np.ndarray:
        self._ensure_fitted()
        raw = self._to_probability_vector(raw_proba)

        if self.method == "isotonic":
            calibrated = self.calibrator.predict(raw)
        else:
            raise ValueError(f"Неподдерживаемый метод калибровки: {self.method}")

        calibrated = np.clip(calibrated, 0.0, 1.0)
        return calibrated.astype(float)

    def fit_transform(self, raw_proba: np.ndarray, y_true: np.ndarray) -> np.ndarray:
        self.fit(raw_proba, y_true)
        return self.transform(raw_proba)

    def evaluate(
        self,
        raw_proba: np.ndarray,
        calibrated_proba: np.ndarray,
        y_true: np.ndarray,
    ) -> CalibrationEvaluationResult:
        raw = self._to_probability_vector(raw_proba)
        calibrated = self._to_probability_vector(calibrated_proba)
        target = self._to_binary_vector(y_true)

        brier_before = float(brier_score_loss(target, raw))
        brier_after = float(brier_score_loss(target, calibrated))

        logloss_before: Optional[float]
        logloss_after: Optional[float]

        try:
            logloss_before = float(log_loss(target, raw, labels=[0, 1]))
        except ValueError:
            logloss_before = None

        try:
            logloss_after = float(log_loss(target, calibrated, labels=[0, 1]))
        except ValueError:
            logloss_after = None

        return CalibrationEvaluationResult(
            method=self.method,
            brier_before=brier_before,
            brier_after=brier_after,
            logloss_before=logloss_before,
            logloss_after=logloss_after,
        )

    def save(self, path: str | Path) -> None:
        self._ensure_fitted()
        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "method": self.method,
            "calibrator": self.calibrator,
            "is_fitted_": self.is_fitted_,
        }
        dump(payload, file_path)

    @classmethod
    def load(cls, path: str | Path) -> "Calibrator":
        file_path = Path(path)
        payload = load(file_path)

        instance = cls(method=payload["method"])
        instance.calibrator = payload["calibrator"]
        instance.is_fitted_ = payload["is_fitted_"]
        return instance

    @staticmethod
    def _build_calibrator(method: str) -> IsotonicRegression:
        if method == "isotonic":
            return IsotonicRegression(out_of_bounds="clip")
        raise ValueError(f"Неподдерживаемый метод калибровки: {method}")

    @staticmethod
    def _to_probability_vector(values: np.ndarray) -> np.ndarray:
        array = np.asarray(values, dtype=float).reshape(-1)
        return np.clip(array, 0.0, 1.0)

    @staticmethod
    def _to_binary_vector(values: np.ndarray) -> np.ndarray:
        array = np.asarray(values, dtype=int).reshape(-1)
        unique_values = set(np.unique(array).tolist())
        if not unique_values.issubset({0, 1}):
            raise ValueError("Целевые значения для калибровки должны быть бинарными: 0 или 1.")
        return array

    def _ensure_fitted(self) -> None:
        if not self.is_fitted_:
            raise RuntimeError("Калибратор еще не обучен.")