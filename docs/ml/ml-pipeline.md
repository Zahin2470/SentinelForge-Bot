# ML Pipeline — Anomaly Detection

## 1. Purpose

The ML component's job is narrow and specific: flag statistically unusual
behavior that a fixed rule wouldn't catch, and produce an **anomaly score**
with supporting evidence — never a final "malicious" verdict. That judgment
is left to the risk-scoring system (which combines this with rule matches,
correlation, and threat intel) and ultimately the human analyst.

This is a real, trained model, not a wrapper around an LLM call.

## 2. Model choice

**MVP model: Isolation Forest** (`sklearn.ensemble.IsolationForest`)

Chosen because:
- unsupervised — we don't need labeled attack data to start
- works well on tabular, mixed-scale features
- fast to train and score, easy to explain (path length → anomaly score)
- easy to demonstrate and evaluate honestly at portfolio scale

Documented upgrade path (not required for MVP): One-Class SVM, Local Outlier
Factor, an autoencoder, or a supervised XGBoost/Random Forest classifier once
labeled incident outcomes exist to train against.

## 3. Feature engineering

Features are computed per-entity (user, host, or session) over a rolling
window, from normalized `security_events`:

| Feature | Description |
|---|---|
| `failed_login_count` | failed auth events in window |
| `successful_login_count` | successful auth events in window |
| `unique_source_ips` | distinct source IPs for the entity |
| `unique_country_count` | distinct source countries (geo-IP derived) |
| `requests_per_minute` | event rate |
| `bytes_transferred` | sum of outbound/inbound bytes, where available |
| `privilege_changes` | count of privilege-modification events |
| `unusual_hour` | binary/continuous deviation from the entity's normal login-hour baseline |
| `new_device` | binary — device/user-agent not seen before for this entity |
| `new_ip` | binary — source IP not seen before for this entity |
| `process_frequency` | how often this process runs for this host, vs. baseline |
| `event_frequency` | overall event rate vs. baseline |
| `destination_port_frequency` | how common this destination port is for this entity |
| `user_behavior_baseline` | distance from the user's rolling behavioral baseline |
| `host_behavior_baseline` | distance from the host's rolling behavioral baseline |

Feature extraction is implemented in `backend/app/ml/features.py` (pure
functions, unit-testable without a running model) and is shared by both the
training pipeline and the real-time scoring path — the same code computes
features at train time and inference time to avoid train/serve skew.

## 4. Pipeline stages

```
security_events (normalized)
      │
      ▼
Feature extraction (windowed, per-entity)
      │
      ▼
Training pipeline (offline, scheduled/manual)
      │  → IsolationForest.fit()
      │  → persist model + scaler + feature schema + model_version
      ▼
model artifact (models/anomaly_{model_version}.joblib)
      │
      ▼
Inference (online, per new event/window)
      │  → same feature extraction
      │  → model.decision_function() → raw score
      │  → min-max normalize using stored training-score range → anomaly_score ∈ [0,1]
      ▼
{
  "anomaly_score": 0.91,
  "risk_score": null,        // combined later, not here
  "model_version": "if-2026.01",
  "model_explanation": {
    "top_contributing_features": [...],
    "entity": "user:admin",
    "window": "2026-09-17T10:10:00Z/2026-09-17T10:20:00Z"
  }
}
```

## 5. Output contract

The model **never** outputs a label like `"malicious"`. It outputs:

```json
{
  "anomaly_score": 0.91,
  "supporting_features": {
    "failed_login_count": 17,
    "unique_source_ips": 3,
    "new_ip": true
  },
  "model_confidence": "moderate",
  "model_limitations": "Baseline built from 7 days of history; new entities have low-confidence baselines.",
  "model_version": "if-2026.01"
}
```

This is combined with rule matches, correlation results, and threat-intel
context by the risk-scoring service (`backend/app/services/risk_scoring.py`)
— see `docs/architecture/architecture.md` §7. The ML score is one input
among several, always shown to the analyst broken out individually, never
buried inside a single opaque number.

## 6. Model persistence & versioning

- Trained models are saved with `joblib`, named with a `model_version`.
- Every anomaly score record stores the `model_version` that produced it, so
  scores remain interpretable after a model is retrained.
- Retraining is a scripted, repeatable step (`make train-ml` /
  `backend/scripts/train_anomaly_model.py`), not a manual notebook-only
  process — though exploratory work lives in `ml/notebooks/`.

## 7. Evaluation

See `docs/evaluation.md` for the full methodology. For the anomaly model
specifically we track precision, recall, and PR-AUC against a labeled
evaluation set built from the scenario library (`scenarios/`), since
Isolation Forest is unsupervised at training time but we do have
ground-truth labels for our synthetic scenarios to evaluate against.

## 8. Explicit limitations (documented, not hidden)

- Isolation Forest is unsupervised: it flags statistical rarity, not
  intent. A legitimate but rare action (e.g., a first-time night-shift
  login) can score as anomalous.
- Baselines need history to be meaningful; new users/hosts start with wide
  uncertainty.
- The model is retrained on a schedule, not continuously online-learned, so
  very recent behavioral drift may not yet be reflected.

These limitations are surfaced to the analyst via `model_limitations` in the
output, not left implicit.
