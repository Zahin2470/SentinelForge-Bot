# Security Terminology Reference

**Category:** terminology

Short definitions of terms used throughout SentinelForge alerts, incident
reports, and playbooks — written for an analyst who knows security
fundamentals but wants a quick, consistent reference rather than a full
textbook definition. Each term below is its own section so it can be
retrieved precisely rather than bundled in with a dozen unrelated
definitions.

## Alert

The output of a single detection rule match or a single ML anomaly score
crossing its threshold. An alert always has evidence attached (the
specific event IDs that produced it). One alert is not automatically one
incident — correlation decides that.

## Incident

One or more correlated alerts grouped together because they share an
entity (user or host) and fall within a correlation time window. An
incident is the unit an analyst actually triages and resolves.

## True positive and false positive

**True positive (TP)** — an alert or incident that correctly identified
genuinely malicious or policy-violating activity. **False positive (FP)**
— an alert or incident that fired on legitimate, benign activity. Every
closed incident should be labeled TP or FP; this is what detection rules'
precision/recall are measured against (`docs/evaluation.md`).

## Risk score

A 0–1 transparent, weighted combination of independent signals (rule
match severity, ML anomaly score, correlation strength, threat-intel
match, asset criticality, identity context). Never a number an AI model
invents — see `docs/architecture/risk-scoring.md` for the exact formula
and worked examples.

## IOC (Indicator of Compromise)

A specific observable value (IP, domain, URL, file hash) known or
suspected to be associated with malicious activity. An IOC match is
evidence, not proof — a known-bad IP appearing in a log doesn't by itself
confirm compromise, but it substantially raises prior probability and
should always be cross-referenced with other signals.

## TTP (Tactics, Techniques, and Procedures)

The behavioral patterns an adversary uses, as cataloged by the MITRE
ATT&CK framework. A "technique" (e.g. T1110, Brute Force) is a specific
method; a "tactic" (e.g. TA0006, Credential Access) is the higher-level
goal the technique serves.

## Baseline

The established normal behavior pattern for a given entity (user, host)
over time — typical login hours, typical source IPs, typical data-access
volume. Anomaly detection is fundamentally about deviation from baseline,
which is why new entities (with no history yet) produce lower-confidence
anomaly scores (`docs/ml/ml-pipeline.md` §8).

## Correlation

The process of grouping separate alerts into a single incident because
they likely represent the same underlying event or campaign, based on
shared entity and temporal proximity (`docs/architecture/architecture.md`
§3-5).

## Containment

An operational action that stops or limits an ongoing compromise
(disabling an account, isolating a host, blocking an IP). SentinelForge's
AI never performs containment autonomously; it can only recommend a
`SIMULATE_*` action pending human approval (`docs/ai/ai-agent.md` §7).

## Evidence grounding

The requirement that every factual claim in an AI-generated investigation
report trace back to a specific event ID, rule ID, or retrieved
knowledge-base document that was actually returned by a tool call during
that investigation. A claim with no traceable source is a hallucination,
not a finding.

## Defense evasion

An ATT&CK tactic (TA0005) covering techniques an adversary uses to avoid
detection during a compromise — disabling logging, clearing event logs,
obfuscating payloads. See the defense-evasion-response playbook for the
SOC response procedure.

## Privilege escalation

An ATT&CK tactic (TA0004) covering techniques that gain an adversary
higher-level permissions than they started with — exploiting a
misconfiguration, abusing a legitimate elevation mechanism, or
manipulating account/group membership.
