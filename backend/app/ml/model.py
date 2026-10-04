"""Isolation Forest anomaly model (docs/ml/ml-pipeline.md §2, §6).

A real trained model, not a wrapper around an LLM call: this module trains
an actual sklearn IsolationForest on feature vectors from app.ml.features,
and persists it with joblib alongside enough metadata (feature schema,
training score range, hyperparameters, version) to make every future score
traceable back to exactly what produced it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from app.ml.features import FEATURE_NAMES, features_to_vector


class FeatureSchemaMismatch(ValueError):
    """Raised when scoring data whose feature columns don't match the
    schema the model was trained on — silently scoring against the wrong
    columns would produce a number that looks valid but means nothing."""


@dataclass
class TrainedModelMetadata:
    model_version: str
    model_type: str = "isolation_forest"
    trained_at: str = field(default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())
    feature_names: list[str] = field(default_factory=lambda: list(FEATURE_NAMES))
    hyperparameters: dict[str, Any] = field(default_factory=dict)
    training_sample_count: int = 0
    # Min/max of the *training set's* raw decision_function output — used
    # to min-max normalize inference-time scores into [0, 1]. Stored at
    # train time so inference never needs the training set again.
    train_score_min: float = 0.0
    train_score_max: float = 1.0


class AnomalyModel:
    """Wraps sklearn's IsolationForest with the input/output contract
    docs/ml/ml-pipeline.md §5 requires: fit on a feature matrix, score
    returns a normalized anomaly_score in [0, 1] (never a bare "malicious"
    label), and the model is always saved/loaded with its feature schema
    and version attached.
    """

    def __init__(
        self,
        model_version: str,
        *,
        n_estimators: int = 200,
        contamination: float = 0.05,
        random_state: int = 42,
    ) -> None:
        self.metadata = TrainedModelMetadata(
            model_version=model_version,
            hyperparameters={
                "n_estimators": n_estimators,
                "contamination": contamination,
                "random_state": random_state,
            },
        )
        self._model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
        )
        self._fitted = False

    def fit(self, X: list[list[float]] | np.ndarray) -> "AnomalyModel":
        X_arr = np.asarray(X, dtype=float)
        self._model.fit(X_arr)
        self._fitted = True
        self.metadata.training_sample_count = X_arr.shape[0]

        # decision_function: higher = more normal. We negate later at
        # score() time so "higher = more anomalous", and store the raw
        # (unnegated) training range here to keep this method's contract
        # simple — score() does the sign flip consistently in one place.
        raw_scores = self._model.decision_function(X_arr)
        self.metadata.train_score_min = float(raw_scores.min())
        self.metadata.train_score_max = float(raw_scores.max())
        return self

    def score(self, X: list[list[float]] | np.ndarray) -> np.ndarray:
        """Returns anomaly scores in [0, 1] — 0 = perfectly typical of the
        training distribution, 1 = maximally anomalous. Values outside the
        training score range are clipped, not extrapolated past [0, 1]."""
        if not self._fitted:
            raise RuntimeError("AnomalyModel.score() called before fit() or load()")

        X_arr = np.asarray(X, dtype=float)
        if X_arr.shape[1] != len(self.metadata.feature_names):
            raise FeatureSchemaMismatch(
                f"Expected {len(self.metadata.feature_names)} features "
                f"({self.metadata.feature_names}), got {X_arr.shape[1]} columns."
            )

        raw = self._model.decision_function(X_arr)  # higher = more normal
        inverted = -raw  # higher = more anomalous

        train_min, train_max = -self.metadata.train_score_max, -self.metadata.train_score_min
        span = train_max - train_min
        if span <= 0:  # degenerate training set (all identical scores) — avoid divide-by-zero
            return np.zeros_like(inverted)

        normalized = (inverted - train_min) / span
        return np.clip(normalized, 0.0, 1.0)

    def score_one(self, features: dict[str, float]) -> float:
        """Convenience wrapper for scoring a single entity's feature dict
        (as produced by app.ml.features.extract_entity_features) rather
        than a raw vector — this is what the inference path in
        app/services/ml_scoring_service.py calls."""
        vector = features_to_vector(features)
        return float(self.score([vector])[0])

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self._model, "metadata": self.metadata, "fitted": self._fitted}, path)

    @classmethod
    def load(cls, path: str | Path) -> "AnomalyModel":
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"No model artifact at {path}")
        payload = joblib.load(path)

        instance = cls.__new__(cls)
        instance._model = payload["model"]
        instance.metadata = payload["metadata"]
        instance._fitted = payload["fitted"]
        return instance
