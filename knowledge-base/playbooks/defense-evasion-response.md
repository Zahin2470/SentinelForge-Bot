# Internal SOC Playbook — Disabled Security Control Incident

**Category:** playbook
**Applies to:** CLOUD-SECCONTROL-001, T1562 (Impair Defenses)

## When this playbook applies

A cloud audit event shows a security control being weakened or disabled:
logging turned off, an MFA requirement removed, or an administrative port
opened to the public internet. This is a classic **defense evasion**
technique — attackers disable logging or monitoring specifically so their
subsequent actions go unrecorded.

## Why this is treated as high/critical severity by default

Unlike many detections, this one has very few benign explanations that
don't involve *some* legitimate human intentionally making the change.
The question is never really "is this suspicious" — it's "was this
planned and approved, or not."

## Step 1 — Check for a change ticket

Before anything else: does this action correlate with an approved,
scheduled infrastructure change (planned maintenance window, IaC deploy,
migration)? If there's a matching ticket and the actor matches the
ticket's assignee, this is very likely a legitimate false positive —
document it and close.

If there is **no** matching change ticket, treat as a confirmed
high-priority incident and proceed.

## Step 2 — Establish the blast radius

- What exactly was disabled? (CloudTrail logging, an MFA policy, a
  security group rule, a WAF rule, etc.)
- What does that control normally protect, and what's now unmonitored or
  exposed as a result?
- Was logging re-enabled at any point, or is it still off right now?

## Step 3 — Look for what happened *during* the gap

If logging was disabled and later re-enabled, the gap between disable and
re-enable is the highest-priority window to investigate — it's exactly
when an attacker would want to act unobserved. Pull whatever
cross-referencing signal exists for that window: network flow logs (if a
separate system captured them), billing/resource-creation events (new
compute instances, new IAM users, new access keys), and any endpoint
telemetry from hosts in the affected environment.

## Step 4 — Identity review

- Does the acting identity's normal behavior include making security
  configuration changes? (An analyst account making an infrastructure
  change is itself an anomaly worth investigating regardless of the
  specific action taken.)
- Was this identity's session established through a suspicious login
  (check for a correlated AUTH-* alert on the same identity shortly
  before this event — this is exactly the kind of chain
  AUTH-PRIVCHANGE-003 is designed to eventually auto-correlate once
  rule-chaining support lands, per `docs/detection-engine.md` §3).

## Step 5 — Recommended response actions

1. Recommend re-enabling the disabled control immediately if it's still
   off.
2. Recommend rotating credentials for the acting identity if the change
   was not authorized.
3. Recommend a focused audit of all actions taken by that identity across
   the full session, not just this one event.
4. Escalate to Security Manager — this category of incident should never
   be resolved by a single analyst without a second reviewer, given how
   directly it can mask further compromise.
