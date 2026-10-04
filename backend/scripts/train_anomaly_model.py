#!/usr/bin/env python3
"""Trains the Isolation Forest anomaly model, evaluates it against a
labeled synthetic holdout set, and persists the artifact + a ModelRun
record. Prints real precision/recall/PR-AUC — never hand-waved numbers
(docs/evaluation.md's rule for every metric in this project).

IsolationForest is trained unsupervised, on BENIGN data only (matching how
it'd be deployed — you don't have labeled attacks in production, you have
"this is what normal looks like"). The labeled anomalous rows exist only
for evaluation, never for fitting the model.

Usage:
    python scripts/train_anomaly_model.py [--model-version if-2026.01]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    average_precision_score,
    precision_score,
    recall_score,
)

from app.ml.model import AnomalyModel  # noqa: E402
from app.ml.synthetic import generate_benign_rows, generate_labeled_dataset  # noqa: E402


def train_and_evaluate(model_version: str, *, contamination: float = 0.05) -> tuple[AnomalyModel, dict]:
    rng = np.random.default_rng(42)

    # Train on benign-only data.
    X_train = generate_benign_rows(1000, rng=rng)
    model = AnomalyModel(model_version, contamination=contamination)
    model.fit(X_train)

    # Evaluate on a held-out labeled set (different seed so it's not the
    # same rows the model trained on).
    X_eval, y_eval = generate_labeled_dataset(n_benign=900, n_anomalous=100, seed=1337)
    scores = model.score(X_eval)

    # Threshold at the training contamination rate's implied percentile —
    # i.e. "flag the top `contamination` fraction as anomalous", which is
    # what `contamination` actually configures in IsolationForest.
    threshold = float(np.quantile(scores, 1 - contamination))
    predictions = (scores >= threshold).astype(int)

    precision = float(precision_score(y_eval, predictions, zero_division=0))
    recall = float(recall_score(y_eval, predictions, zero_division=0))
    pr_auc = float(average_precision_score(y_eval, scores))

    metrics = {
        "precision": precision,
        "recall": recall,
        "pr_auc": pr_auc,
        "threshold": threshold,
        "eval_sample_count": len(y_eval),
        "eval_anomaly_count": int(y_eval.sum()),
    }
    return model, metrics


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-version", default=None, help="Defaults to if-<today's date>")
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Defaults to app.core.config's ml_models_path setting ('ml/models') if available, "
        "else 'ml/models' directly — this fallback lets the script run in minimal "
        "environments that have sklearn/numpy but not the full app config stack.",
    )
    args = parser.parse_args()

    from datetime import date

    model_version = args.model_version or f"if-{date.today().isoformat()}"

    model, metrics = train_and_evaluate(model_version, contamination=args.contamination)

    output_dir = args.output_dir
    if output_dir is None:
        try:
            from app.core.config import get_settings

            output_dir = get_settings().ml_models_path
        except ModuleNotFoundError:
            output_dir = "ml/models"

    artifact_path = Path(output_dir) / f"anomaly_{model_version}.joblib"
    model.save(artifact_path)

    print(f"\nModel version: {model_version}")
    print(f"Training samples: {model.metadata.training_sample_count}")
    print(f"Hyperparameters: {model.metadata.hyperparameters}")
    print(f"\nEvaluation (on {metrics['eval_sample_count']} held-out samples, "
          f"{metrics['eval_anomaly_count']} true anomalies):")
    print(f"  Precision: {metrics['precision']:.3f}")
    print(f"  Recall:    {metrics['recall']:.3f}")
    print(f"  PR-AUC:    {metrics['pr_auc']:.3f}")
    print(f"  Threshold: {metrics['threshold']:.3f}")
    print(f"\nSaved to: {artifact_path}")

    try:
        from app.core.logging import configure_logging, get_logger

        configure_logging()
        get_logger(__name__).info(
            "anomaly_model_trained",
            model_version=model_version,
            precision=metrics["precision"],
            recall=metrics["recall"],
            pr_auc=metrics["pr_auc"],
        )
    except ModuleNotFoundError:
        pass  # structured logging stack not available in this environment — the print()s above already reported everything

    # Note: the corresponding ModelRun DB row (app/models/model_run.py) is
    # written by app/repositories when this script is run against a live
    # DB via `make train-ml` inside the backend container — kept separate
    # from train_and_evaluate() so that function stays pure/testable
    # without needing a database, same pattern as detection/correlation.
    return 0


if __name__ == "__main__":
    sys.exit(main())
