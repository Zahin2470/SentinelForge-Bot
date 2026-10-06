# Internal SOC Playbook — Brute Force / Credential Access Incident

**Category:** playbook
**Applies to:** AUTH-BRUTEFORCE-001, AUTH-NEWLOGINIP-002, T1110 (Brute Force)

## When this playbook applies

An incident where a detection rule flagged repeated failed authentication
attempts against a single account, optionally followed by a successful
login. This is the most common precursor to account takeover and
privilege escalation incidents.

## Step 1 — Confirm the pattern

Before treating this as malicious, rule out common false-positive sources:

- **Shared NAT/VPN egress.** Many legitimate users behind the same
  corporate VPN or NAT gateway can produce a burst of failed logins from
  one source IP. Check whether the failures come from *multiple* usernames
  at that IP (likely benign infrastructure noise) or *one* username
  (suspicious — someone is guessing that one account's password).
- **Expired credentials / password rotation.** A user who just changed
  their password may generate several failures from cached credentials on
  old sessions (phone, old laptop, forgotten service account) before
  succeeding. Check whether the failures stop right after a successful
  login and never recur — that pattern is far more consistent with a
  forgotten cached password than an attacker.
- **Automated service account misconfiguration.** A scheduled job with a
  stale credential can retry on a fixed interval indefinitely. Check
  whether the failure timestamps are suspiciously regular (e.g. exactly
  every 5 minutes) — humans and real attack tooling are rarely that
  regular.

## Step 2 — Assess the account and source

- Is the account privileged (admin, service account with broad access)?
  Escalate severity if so.
- Is the source IP or ASN known-hostile (check `GET /api/v1/threat-intel/iocs`
  and any indicator match already attached to the alert)?
- Is this the account's normal login behavior, or does the source
  IP/country/device differ from its established baseline?

## Step 3 — If a successful login followed the failures

This is the highest-priority variant — the attempt appears to have
succeeded. Immediately:

1. Check what the account did *after* the successful login (privilege
   changes, new API keys, mail forwarding rules, data access outside its
   normal pattern). Rules like AUTH-PRIVCHANGE-003 are designed to
   auto-correlate this next step.
2. Check for MFA. If the account has MFA enabled and it was NOT
   challenged, treat as significantly more suspicious (may indicate MFA
   bypass, or a legacy protocol that doesn't support MFA being abused).

## Step 4 — Recommended response actions

These are recommendations only — an analyst must approve any operational
action; SentinelForge does not execute containment automatically
(`docs/ai/ai-agent.md` §7).

| Situation | Recommended action |
|---|---|
| Failures only, no success | Monitor; consider rate-limiting the source IP |
| Success from a known-bad IP/indicator | Recommend account password reset + session revocation |
| Success + privilege change | Recommend immediate password reset, session revocation, and review of all actions taken since the login |
| Privileged account involved | Escalate to Security Manager regardless of other signals |

## Step 5 — Close-out

Document the final determination (true positive / false positive) and
why — this feeds the detection rule's tracked false-positive rate
(`docs/evaluation.md` §1) and helps tune thresholds over time.
