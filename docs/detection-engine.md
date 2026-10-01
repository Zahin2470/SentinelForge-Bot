# Detection Engine

## 1. Purpose

Deterministic, testable, explainable detections. The LLM is never the
mechanism that decides "this is an alert" — that's this engine's job.

## 2. Rule format (Sigma-style)

Rules live under `detection-rules/<category>/` as YAML, following Sigma's
philosophy (portable, declarative, backend-agnostic) rather than an
arbitrary proprietary format, so they could plausibly be translated to other
query backends later.

```
detection-rules/
├── authentication/
├── endpoint/
├── network/
├── cloud/
├── application/
└── correlation/
```

Each rule file contains:

```yaml
id: AUTH-BRUTEFORCE-001
title: Repeated Failed Authentication Followed by Success
status: enabled
description: >
  Detects a burst of failed authentication attempts from the same source
  followed by a successful authentication for the same account.
severity: high
tags:
  - authentication
  - brute-force
references:
  - https://attack.mitre.org/techniques/T1110/
attack:
  technique_id: T1110
  technique_name: Brute Force
false_positive_notes: >
  Shared NAT/VPN egress IPs can produce bursts of failed logins from
  multiple legitimate users; correlate with user identity, not IP alone.
logsource:
  category: authentication
detection:
  failed_login:
    event_type: authentication
    status: failure
  successful_login:
    event_type: authentication
    status: success
  timeframe: 10m
  condition: failed_login | count() by username, source_ip >= 5 followed_by successful_login
```

## 3. Rule engine components

| Component | Responsibility | Status |
|---|---|---|
| Parser (`app/detection/parser.py`) | Load YAML, check required keys are present | ✅ implemented |
| Validator (`backend/scripts/validate_detection_rules.py`) | Full JSON-Schema validation, run in CI on every push | ✅ implemented |
| Executor (`app/detection/executor.py`) | Evaluate a rule's condition against a window of normalized events | ✅ implemented for the condition shapes below |
| Result generator | `DetectionResult`: rule ID, matched event IDs, severity, group key | ✅ implemented |

### Executor scope (honest, not aspirational)

The executor is a **rule-type-based engine**, not a general expression
parser: it recognizes four specific, documented condition shapes and
compiles each into a direct evaluation over a list of event dicts.

Supported today:

| Shape | Example |
|---|---|
| `count(<sub>) >= N followed_by <sub2>` | AUTH-BRUTEFORCE-001 |
| `count(<sub>) >= N` | APP-ACCESSDENIED-001 |
| `<sub>.<field> matches any <patterns_key>` | ENDPOINT-POWERSHELL-001 |
| `<sub>` (bare existence match) | CLOUD-SECCONTROL-001 |

Explicitly **not yet implemented** — these rules load and run, but the
executor returns a `status="unsupported"` result with a clear reason rather
than silently returning zero matches (which would be indistinguishable from
"evaluated, found nothing") or guessing:

- `"... not in baseline"` / `"frequency(baseline) < ..."` conditions
  (AUTH-NEWLOGINIP-002, NETWORK-OUTBOUND-001) — depend on the
  behavioral-baseline service, a separate component that hasn't been built
  yet.
- `rule_ref`-based conditions (AUTH-PRIVCHANGE-003) — rule chaining belongs
  to the correlation engine, not the per-rule executor.
- Meta-rules like CORRELATION-MULTIHOST-001 are never run by this module at
  all; they're consumed by the correlation engine once it exists, which
  operates on alert output, not raw events.

Every one of these is covered by a test that asserts the honest
`unsupported` result — see `backend/tests/detection/test_unsupported_conditions.py`.

Detection results feed both **alerts** and the **risk-scoring** system
(`rule_score` component) — they are never shown to the analyst without the
matched event IDs attached, so every alert is explainable back to raw
evidence.

## 4. Initial rule library (~20 rules, MVP)

Representative categories (full set implemented incrementally, tracked in
`detection-rules/README.md`):

- Repeated failed authentication / brute-force pattern
- Successful login after repeated failures
- Impossible travel (auth from geographically implausible locations in a
  short window)
- Unusual login time for the account's baseline
- Suspicious privilege escalation / unusual administrator activity
- Account creation anomaly
- Suspicious PowerShell / suspicious command execution
- Abnormal process or file execution
- Unusual outbound network connection
- Suspicious DNS behavior
- Suspicious API access / repeated access denial
- Disabled security control event
- Abnormal data transfer volume
- Suspicious user-agent pattern
- Multiple anomalies associated with a single host (meta-rule, feeds
  correlation)

Every rule ships with: rule ID, title, description, severity, tags,
false-positive notes, references, detection logic, ATT&CK mapping, and an
enabled/disabled flag.

## 5. Testing

Every implemented rule has at least one **positive** test (a synthetic
event sequence that must trigger it) and one **negative** test (a
close-but-not-matching sequence that must *not* trigger it), under
`backend/tests/detection/`. These are runnable right now:

```bash
cd backend && PYTHONPATH=. python3 -m pytest tests/detection/ -v
# or, without pytest installed, each file is directly executable:
PYTHONPATH=backend python3 backend/tests/detection/test_auth_bruteforce.py
```

CI runs the full rule library against the fixture set on every change
(`.github/workflows/ci.yml`, job `backend`) so a rule edit that silently
breaks another rule's expectations is caught immediately.

## 6. Relationship to correlation and ML

The detection engine produces individual rule matches. It does **not** try
to decide on its own whether five separate matches are "one attack" — that's
the correlation engine's job (`docs/architecture/architecture.md` §3–5). The
detection engine's contract to the rest of the system is simple and stable:
*given a window of normalized events, return the set of rules that matched
and exactly which events matched them.*
