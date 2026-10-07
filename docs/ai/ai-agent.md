# AI SOC Analyst — Agent Design

> ✅ **Implementation status**: every mechanism described in this document
> is implemented in `backend/app/agents/` and covered by 42 passing tests
> (`backend/tests/agents/`, plus the capstone
> `tests/test_agent_investigation.py`) — state machine transitions, hard
> resource limits, the tool registry with per-call authorization, evidence
> grounding, and the retry-then-fail-cleanly output validation path are
> all real, executed code, not just this design doc. What's *not*
> executable in this offline dev environment: the real `AnthropicProvider`
> / `OpenAIProvider` / `LocalProvider` implementations (§2) need network
> access and are honest stubs that raise `ProviderUnavailable`, and
> `build_default_registry`'s DB-wired tools (vs. the in-memory
> `build_test_registry` the tests use) are written and reviewed but
> unexecuted, same caveat as every other DB-touching layer in this repo.
> The capstone test proves the *entire* orchestration loop — including
> every tool call actually going through `app.rag`'s real TF-IDF
> retrieval, `app.threat_intel`'s real IOC matcher, and the real detection
> pipeline's output — end to end, with a scripted `MockLLMProvider`
> standing in only for the model call itself.

## 1. Role

The AI SOC Analyst is a tool-using assistant that investigates an incident
*after* it has already been created by deterministic detection + ML +
correlation. It does not decide whether something is an incident — it helps
explain and evidence one that already exists. It never receives a bare
"analyze this alert" prompt with no structure; it operates through an
explicit state machine and a fixed tool registry.

## 2. Model abstraction

The agent is never hard-coded to one LLM provider.

```
LLMProvider (interface)
 ├── AnthropicProvider
 ├── OpenAIProvider
 ├── LocalProvider
 └── MockProvider   ← used in tests / offline dev, no API key required
```

Configured via environment variables (`LLM_PROVIDER`, `LLM_MODEL`,
`LLM_API_KEY`), never committed to source control. `MockProvider` returns
deterministic canned responses so the full pipeline — including agent state
transitions, tool authorization, and report schema validation — is testable
without any paid API access. The same abstraction pattern applies to
embeddings (`EmbeddingProvider`) for the RAG layer.

## 3. State machine

```
RECEIVED
  → UNDERSTANDING
  → COLLECTING_EVIDENCE
  → CORRELATING
  → THREAT_INTELLIGENCE_LOOKUP
  → HYPOTHESIS_GENERATION
  → HYPOTHESIS_VALIDATION
  → RISK_ASSESSMENT
  → REPORT_GENERATION
  → HUMAN_REVIEW
  → COMPLETED
  (or → FAILED at any step, with reason)
```

Each transition is persisted (`agent_runs` / `agent_steps` tables):

```
run_id, incident_id, step, tool_call, tool_result_summary,
model, latency, tokens/cost (where available), errors, timestamp
```

Prompts are not stored verbatim when unnecessary — summaries are stored
instead, and secrets are never logged.

## 4. Tool registry

```
search_security_events()      get_asset_context()
get_event_by_id()              get_user_context()
get_alert_context()            list_detection_rules()
get_incident_history()         get_detection_rule()
search_related_events()        run_detection_rule()
calculate_anomaly_score()      generate_incident_summary()
lookup_ioc()                   generate_report()
search_threat_intelligence()
search_security_knowledge()
lookup_attack_technique()
```

Every tool:
- has a typed input schema and typed output schema (Pydantic)
- validates its input before doing anything
- re-checks the acting user's authorization server-side (the model's
  "intent" is never itself authorization)
- returns structured errors on failure, not free text
- writes an audit log entry (tool name, input summary, result summary,
  actor, incident, timestamp)

Architecture (the LLM never touches the database directly):

```
LLM → Agent tool → Authorized service → Database / intelligence source
```

Almost all tools are **read-only**. The only "write" tools are simulated
response actions (§7), and even those only ever write to simulation state
pending human approval.

## 5. Prompt structure and injection defense

The prompt sent to the model always keeps these sections explicitly
separated and labeled — never concatenated into one blob:

```
SYSTEM INSTRUCTIONS
USER REQUEST
SECURITY EVENT DATA      ← untrusted, explicitly labeled as data
RETRIEVED DOCUMENTS      ← untrusted, explicitly labeled as data
TOOL RESULTS             ← untrusted, explicitly labeled as data
```

The system instructions state directly that content inside the data
sections must never be treated as an instruction, no matter how it's
phrased (e.g. a `command_line` field containing "ignore previous
instructions"). This is covered by adversarial tests in
`backend/tests/security/test_prompt_injection.py` — see
`docs/evaluation.md`.

## 6. Loop limits (hard, not advisory)

```
MAX_AGENT_STEPS = 12
MAX_TOOL_CALLS = 20
MAX_RETRIES = 2
MAX_CONTEXT_SIZE = <configured>
MAX_INVESTIGATION_TIME = <configured>
```

If any limit is hit, the run transitions to `FAILED` with a clear reason
surfaced to the analyst: *"Investigation incomplete due to safety/resource
limits."* There is no path to an unbounded autonomous loop.

## 7. Human-in-the-loop boundary

| Category | Who can do it | Example |
|---|---|---|
| Analysis | Automated | Evidence gathering, correlation, ATT&CK mapping |
| Recommendations | Automated | "Recommend reviewing source IP reputation" |
| Destructive / operational actions | **Human only** | Disabling an account, isolating a host, blocking an IP |

Destructive actions never execute for real. The agent can only propose
simulated actions:

```
SIMULATE_DISABLE_ACCOUNT
SIMULATE_ISOLATE_HOST
SIMULATE_BLOCK_IP
```

These modify simulation state only, and remain in status
`AWAITING_HUMAN_APPROVAL` until an analyst with sufficient permission
confirms them. Every report ends with an explicit statement: *"No automatic
containment action was executed. Human analyst approval is required for
operational response."*

## 8. Output contract

The final investigation output is validated against a Pydantic schema
before being persisted or shown — not accepted as free text. Structure
(abbreviated):

```json
{
  "classification": "string",
  "severity": "low|medium|high|critical",
  "confidence": 0.0,
  "summary": "string",
  "evidence": ["EVT-...", "..."],
  "detection_contributions": ["RULE-ID", "..."],
  "ml_signal": {"anomaly_score": 0.0},
  "attack_mapping": [{"technique_id": "T1110", "name": "Brute Force"}],
  "alternative_explanations": ["string", "..."],
  "unknowns": ["string", "..."],
  "recommended_next_steps": ["string", "..."],
  "evidence_sources": ["Internal SOC Playbook — ...", "Event EVT-19483"]
}
```

Every claim must trace back to a real event ID, rule ID, or retrieved
document ID that was actually returned by a tool call in that run — the
model cannot cite a source it wasn't given. Malformed output is retried up
to `MAX_RETRIES`, then the run fails cleanly rather than showing invalid or
partially-fabricated content.

## 9. Degraded mode

If no `LLM_PROVIDER` is configured, or the provider errors, the API returns
a clear `AI analysis unavailable` response rather than failing silently or
falling back to fabricated text. Detection, correlation, ML scoring, and
manual incident workflows are entirely independent of the LLM and continue
to work.
