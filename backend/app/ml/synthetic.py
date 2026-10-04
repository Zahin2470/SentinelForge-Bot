"""Synthetic entity-behavior feature data for training and evaluating the
anomaly model (docs/evaluation.md §2 — "Isolation Forest is unsupervised at
training time but our synthetic scenarios carry ground-truth anomaly labels
for evaluation purposes"). No real user data anywhere — every row is drawn
from a documented random distribution, not sampled from any real system.

This operates at the feature-vector level (one row per synthetic
"entity-window"), which is a deliberately different generator from
simulator/scenarios.py (which produces raw per-event logs for the
ingestion pipeline). Training a model needs hundreds-to-thousands of
entity-windows; generating that many *raw events* and running them through
normalize()+feature extraction would be needlessly slow and wouldn't test
anything this module doesn't already cover on its own — the ingestion path
is tested separately in tests/test_scenario_pipeline.py.
"""

from __future__ import annotations

import numpy as np

from app.ml.features import FEATURE_NAMES

# Training data assumes a fixed canonical window size, matching how
# app.services.detection_service and the ML scoring path both use a fixed
# lookback (1 hour) in practice. event_rate_per_minute below is always
# DERIVED from total_events at this window size — sampling it
# independently would let training rows imply a different window per row,
# which would silently mismatch the deterministic total_events/window_minutes
# relationship extract_entity_features computes at inference time (real
# train/serve skew, not just noise). If the scoring window size ever
# becomes genuinely variable, this generator needs to change to match.
CANONICAL_WINDOW_MINUTES = 60.0


def generate_benign_rows(n: int, *, rng: np.random.Generator) -> np.ndarray:
    """Ordinary, unremarkable entity-window behavior: mostly successful
    logins, occasional single failed attempt (typo), one source IP, no
    privilege changes, activity during normal hours."""
    failed_login_count = rng.poisson(0.3, n).astype(float)
    successful_login_count = rng.poisson(2.0, n).astype(float) + 1
    total_events = successful_login_count + failed_login_count + rng.poisson(1.0, n)
    unique_source_ips = np.clip(rng.poisson(1.0, n) + 1, 1, 3).astype(float)
    unique_countries = np.ones(n)
    distinct_hostnames = np.clip(rng.poisson(0.5, n) + 1, 1, 3).astype(float)
    privilege_change_count = (rng.random(n) < 0.02).astype(float)  # rare legitimate admin activity
    night_time_event_ratio = np.clip(rng.normal(0.08, 0.05, n), 0.0, 1.0)
    event_rate_per_minute = total_events / CANONICAL_WINDOW_MINUTES

    return np.column_stack([
        failed_login_count,
        successful_login_count,
        total_events,
        unique_source_ips,
        unique_countries,
        distinct_hostnames,
        privilege_change_count,
        night_time_event_ratio,
        event_rate_per_minute,
    ])


def generate_anomalous_rows(n: int, *, rng: np.random.Generator) -> np.ndarray:
    """A mix of distinct anomalous patterns — brute force, impossible
    travel / credential sharing, off-hours privileged activity — so the
    model has to learn "unusual" broadly, not one specific attack shape."""
    third = max(n // 3, 1)
    remainder = n - 2 * third

    # Pattern A: brute force — many failed logins, one attacker IP, then a success.
    a_failed = rng.poisson(9, third).astype(float) + 4
    a_success = (rng.random(third) < 0.6).astype(float)
    a_total = a_failed + a_success + rng.poisson(0.5, third)
    a_ips = np.ones(third)
    a_countries = np.ones(third)
    a_hosts = np.ones(third)
    a_priv = np.zeros(third)
    a_night = np.clip(rng.normal(0.2, 0.15, third), 0.0, 1.0)
    a_rate = a_total / CANONICAL_WINDOW_MINUTES

    # Pattern B: credential sharing / impossible travel — many source IPs
    # and countries for one account in a short window.
    b_failed = rng.poisson(1.0, third).astype(float)
    b_success = rng.poisson(3.0, third).astype(float) + 2
    b_total = b_failed + b_success
    b_ips = rng.poisson(4, third).astype(float) + 3
    b_countries = rng.poisson(2, third).astype(float) + 2
    b_hosts = np.clip(rng.poisson(1, third) + 1, 1, 4).astype(float)
    b_priv = np.zeros(third)
    b_night = np.clip(rng.normal(0.15, 0.1, third), 0.0, 1.0)
    b_rate = b_total / CANONICAL_WINDOW_MINUTES

    # Pattern C: off-hours privileged activity — few events, but privilege
    # changes, deep in the night.
    c_failed = rng.poisson(0.2, remainder).astype(float)
    c_success = rng.poisson(1.5, remainder).astype(float) + 1
    c_total = c_success + c_failed + rng.poisson(1, remainder)
    c_ips = np.ones(remainder)
    c_countries = np.ones(remainder)
    c_hosts = np.clip(rng.poisson(1, remainder) + 1, 1, 3).astype(float)
    c_priv = rng.poisson(2, remainder).astype(float) + 1
    c_night = np.clip(rng.normal(0.85, 0.1, remainder), 0.3, 1.0)
    c_rate = c_total / CANONICAL_WINDOW_MINUTES

    failed = np.concatenate([a_failed, b_failed, c_failed])
    success = np.concatenate([a_success, b_success, c_success])
    total = np.concatenate([a_total, b_total, c_total])
    ips = np.concatenate([a_ips, b_ips, c_ips])
    countries = np.concatenate([a_countries, b_countries, c_countries])
    hosts = np.concatenate([a_hosts, b_hosts, c_hosts])
    priv = np.concatenate([a_priv, b_priv, c_priv])
    night = np.concatenate([a_night, b_night, c_night])
    rate = np.concatenate([a_rate, b_rate, c_rate])

    return np.column_stack([failed, success, total, ips, countries, hosts, priv, night, rate])


def generate_labeled_dataset(
    n_benign: int = 900, n_anomalous: int = 100, *, seed: int = 42
) -> tuple[np.ndarray, np.ndarray]:
    """Returns (X, y) where y is 1 for anomalous, 0 for benign — the
    ground-truth labels used ONLY for evaluation (docs/evaluation.md §2),
    never for training (IsolationForest trains unsupervised, on benign
    data only, matching how it'd be deployed: you don't have labeled
    attacks in production, you have "this is what normal looks like").
    """
    rng = np.random.default_rng(seed)
    benign = generate_benign_rows(n_benign, rng=rng)
    anomalous = generate_anomalous_rows(n_anomalous, rng=rng)

    X = np.vstack([benign, anomalous])
    y = np.concatenate([np.zeros(n_benign), np.ones(n_anomalous)])

    # Shuffle so evaluation code can't accidentally cheat by assuming order.
    shuffle_idx = rng.permutation(len(X))
    return X[shuffle_idx], y[shuffle_idx]


assert len(FEATURE_NAMES) == 9, "generate_benign_rows/generate_anomalous_rows column order must match FEATURE_NAMES"
