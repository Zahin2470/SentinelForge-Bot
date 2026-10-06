# Detection Rule Format Reference (Sigma-Style)

**Category:** detection documentation
**See also:** `docs/detection-engine.md` for the authoritative, current
spec — this document is the RAG-facing explainer version, written for an
analyst or the AI SOC Analyst to understand a rule's structure quickly
without reading the source engine code.

SentinelForge's detection rules follow the philosophy of
[Sigma](https://github.com/SigmaHQ/sigma) — a backend-agnostic,
declarative detection rule format used widely in the SOC community —
rather than an arbitrary proprietary format. This means a rule's *logic*
is meant to be portable and human-readable, separate from however it's
actually executed.

## Anatomy of a rule

Every rule has: a unique `id` (`CATEGORY-SHORTNAME-NNN`), a `title`,
`status` (enabled/disabled/experimental), `description`, `severity`
(low/medium/high/critical), `tags`, an `attack` block mapping it to a
MITRE ATT&CK technique, `false_positive_notes` (written for a human
analyst — always read these before dismissing or escalating an alert),
`logsource.category` (which telemetry type the rule applies to), and a
`detection` block containing the actual matching logic.

## The condition grammar SentinelForge currently executes

The detection engine (`app/detection/executor.py`) recognizes four
condition shapes:

- **`count(<sub>) >= N followed_by <sub2>`** — N or more events matching
  one filter, followed within the rule's `timeframe` by an event matching
  a second filter. Example: AUTH-BRUTEFORCE-001 (5+ failures followed by a
  success).
- **`count(<sub>) >= N`** — a plain threshold within a timeframe. Example:
  APP-ACCESSDENIED-001 (10+ denied responses in 5 minutes).
- **`<sub>.<field> matches any <patterns>`** — a field on a matching event
  contains any of a list of patterns. Example: ENDPOINT-POWERSHELL-001
  (command line contains an evasive flag).
- **`<sub>`** (bare) — any event matching a filter, no threshold. Example:
  CLOUD-SECCONTROL-001 (any security-control-disable action).

Rules using a baseline comparison (`... not in baseline`,
`frequency(baseline) < ...`) or referencing another rule (`rule_ref`) are
honestly reported as **unsupported** by the current executor rather than
silently mis-evaluated — the behavioral-baseline service and rule-chaining
support are documented as not-yet-built (`docs/detection-engine.md` §3).
If you see an "unsupported" status on a rule evaluation, that means "this
rule's logic depends on infrastructure that doesn't exist yet," not "this
rule found nothing."

## Reading `false_positive_notes`

Every rule's false-positive notes are written from real operational
experience with that detection pattern (or a documented, reasoned
prediction of where they'd come from) and should be the first thing
checked when triaging a new alert — they often point directly at the
distinguishing question that separates a true from a false positive (e.g.
"check whether failures span multiple usernames at one IP" for a
brute-force rule fed by shared NAT).
