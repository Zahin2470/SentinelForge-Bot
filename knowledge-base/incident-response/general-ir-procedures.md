# Incident Response Procedures — General Guidelines

**Category:** incident response

These are the cross-cutting IR procedures that apply regardless of which
specific detection triggered an incident — the playbooks
(brute-force-response.md, defense-evasion-response.md) cover
pattern-specific steps; this document covers what's common to all of them.

## The incident lifecycle

```
OPEN → TRIAGED → INVESTIGATING → CONTAINMENT_RECOMMENDED
     → AWAITING_REVIEW → RESOLVED | FALSE_POSITIVE → CLOSED
```

An incident can also be reopened if new evidence surfaces after closure.

## Triage priorities

When multiple incidents are open simultaneously, prioritize by:

1. **Final risk score** (`docs/architecture/risk-scoring.md`) — this
   already combines rule severity, correlation strength, threat-intel
   matches, and asset criticality into one comparable number.
2. **Asset criticality** independent of risk score — an incident touching
   a domain controller or a production database deserves a faster look
   even at a moderate risk score than a low-criticality test VM at a
   slightly higher one.
3. **Whether containment is already recommended** — an incident that has
   reached `CONTAINMENT_RECOMMENDED` status has already been assessed as
   needing action; it shouldn't sit behind lower-urgency triage work.

## What "evidence-grounded" means in an investigation report

Every factual claim in an AI-generated or human-written investigation
report must be traceable to one of:

- a specific security event ID
- a detection rule ID that matched
- a retrieved knowledge-base document (this corpus)
- a threat-intelligence indicator that matched

A sentence like "this is likely a coordinated campaign" with no evidence
citation is an opinion, not a finding, and should be clearly labeled as
such (e.g. under "alternative explanations" or "analyst assessment"),
never presented as an established fact.

## Human approval requirements

No operational containment action (disabling an account, isolating a
host, blocking an IP, revoking a session) executes automatically,
regardless of confidence or severity. The system can only propose a
`SIMULATE_*` action, which remains in `AWAITING_HUMAN_APPROVAL` status
until an analyst with sufficient permission confirms it
(`docs/ai/ai-agent.md` §7). This is a hard boundary, not a configurable
setting — it exists so a false positive (or a compromised or manipulated
AI reasoning chain) can never take a destructive action unsupervised.

## Closing an incident

Every closed incident needs:

1. A final classification: `RESOLVED` (confirmed true positive, handled)
   or `FALSE_POSITIVE`.
2. A one-paragraph resolution summary — what happened, what was done,
   and why. This isn't bureaucracy; it's what makes the detection rules'
   tracked false-positive rate (`docs/evaluation.md` §1) and the AI
   agent's evaluation metrics (`docs/evaluation.md` §3) meaningful instead
   of just numbers nobody can explain six months later.
3. If false positive: a note on *why* it fired, so the underlying rule or
   model can potentially be tuned to avoid repeating the same
   false-positive pattern.

## Escalation

Escalate to a Security Manager when: a privileged account is involved,
a defense-evasion technique is confirmed, the incident's final risk score
is critical, or the analyst is uncertain about the correct classification
after following the relevant playbook. Escalating because you're unsure is
always the right call — it is never treated as a failure to have escalated
something that turned out to be benign.
