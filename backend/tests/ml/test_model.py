"""Tests for app.ml.model.AnomalyModel — these actually train and score
real sklearn IsolationForest models (sklearn/numpy/joblib are available in
this environment), not just check that the code compiles.
"""

import tempfile
from pathlib import Path

import numpy as np

from app.ml.model import AnomalyModel, FeatureSchemaMismatch
from app.ml.synthetic import generate_anomalous_rows, generate_benign_rows


def test_anomalous_rows_score_higher_than_benign_on_average() -> None:
    """The core sanity check for the whole ML pipeline: a model trained on
    benign-only data must rank held-out anomalous rows as more anomalous
    than held-out benign rows, on average. This is checked with real
    sklearn, not asserted from documentation."""
    rng = np.random.default_rng(7)
    X_train = generate_benign_rows(500, rng=rng)

    model = AnomalyModel("test-v1", contamination=0.05)
    model.fit(X_train)

    eval_rng = np.random.default_rng(99)
    X_benign_eval = generate_benign_rows(200, rng=eval_rng)
    X_anomalous_eval = generate_anomalous_rows(200, rng=eval_rng)

    benign_scores = model.score(X_benign_eval)
    anomalous_scores = model.score(X_anomalous_eval)

    assert anomalous_scores.mean() > benign_scores.mean(), (
        f"expected anomalous mean score > benign mean score, "
        f"got anomalous={anomalous_scores.mean():.3f} benign={benign_scores.mean():.3f}"
    )


def test_scores_are_bounded_zero_to_one() -> None:
    rng = np.random.default_rng(1)
    X_train = generate_benign_rows(300, rng=rng)
    model = AnomalyModel("test-v2").fit(X_train)

    X_extreme = generate_anomalous_rows(50, rng=rng) * 10  # push well outside training range
    scores = model.score(X_extreme)

    assert (scores >= 0.0).all()
    assert (scores <= 1.0).all()


def test_score_before_fit_raises() -> None:
    model = AnomalyModel("test-v3")
    try:
        model.score([[0.0] * 9])
        raise AssertionError("expected RuntimeError")
    except RuntimeError:
        pass


def test_feature_schema_mismatch_raises() -> None:
    rng = np.random.default_rng(1)
    model = AnomalyModel("test-v4").fit(generate_benign_rows(200, rng=rng))

    try:
        model.score([[0.0, 1.0, 2.0]])  # wrong number of columns
        raise AssertionError("expected FeatureSchemaMismatch")
    except FeatureSchemaMismatch:
        pass


def test_save_and_load_roundtrip_produces_identical_scores() -> None:
    rng = np.random.default_rng(3)
    X_train = generate_benign_rows(300, rng=rng)
    model = AnomalyModel("test-v5", contamination=0.05)
    model.fit(X_train)

    X_test = generate_anomalous_rows(20, rng=rng)
    scores_before = model.score(X_test)

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "model.joblib"
        model.save(path)
        loaded = AnomalyModel.load(path)

        assert loaded.metadata.model_version == "test-v5"
        assert loaded.metadata.training_sample_count == 300
        assert loaded.metadata.feature_names == model.metadata.feature_names

        scores_after = loaded.score(X_test)
        assert np.allclose(scores_before, scores_after), "loaded model must score identically to the original"


def test_score_one_matches_score_on_equivalent_vector() -> None:
    rng = np.random.default_rng(5)
    model = AnomalyModel("test-v6").fit(generate_benign_rows(200, rng=rng))

    from app.ml.features import FEATURE_NAMES

    features = dict.fromkeys(FEATURE_NAMES, 0.0)
    features["failed_login_count"] = 8.0
    features["total_events"] = 9.0

    score_via_convenience = model.score_one(features)
    from app.ml.features import features_to_vector

    score_via_vector = float(model.score([features_to_vector(features)])[0])

    assert score_via_convenience == score_via_vector


if __name__ == "__main__":
    test_anomalous_rows_score_higher_than_benign_on_average()
    test_scores_are_bounded_zero_to_one()
    test_score_before_fit_raises()
    test_feature_schema_mismatch_raises()
    test_save_and_load_roundtrip_produces_identical_scores()
    test_score_one_matches_score_on_equivalent_vector()
    print("All AnomalyModel tests passed.")
