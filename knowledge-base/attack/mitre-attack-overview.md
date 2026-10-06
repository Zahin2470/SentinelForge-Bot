# MITRE ATT&CK Technique Reference

**Category:** attack
**Source:** curated from `app/attack/reference_data.py` (ATT&CK v16.1
subset covering the techniques SentinelForge's detection rules currently
cite — see `docs/threat-intelligence.md` §1 for the full scope note on why
this is a curated subset rather than the complete framework).

MITRE ATT&CK organizes adversary behavior into **tactics** (the "why" — the
adversary's tactical goal) and **techniques** (the "how" — the specific
method used to achieve that goal). A technique can have **sub-techniques**
that describe a more specific variant.

## Techniques SentinelForge currently detects for

### T1110 — Brute Force (tactic: TA0006, Credential Access)

Adversaries attempt to gain account access by systematically guessing
credentials — trying many passwords against one account, one password
against many accounts (password spraying), or using previously breached
credential lists. Detected by AUTH-BRUTEFORCE-001 (repeated failures
followed by a success).

### T1078 — Valid Accounts (tactic: TA0001, Initial Access)

Adversaries obtain and abuse legitimate credentials to gain access,
maintain persistence, or escalate privileges — rather than exploiting a
technical vulnerability, they simply log in as someone else. Detected by
AUTH-NEWLOGINIP-002 (login from a source IP never seen before for that
account), though full confidence requires the behavioral baseline service
(not yet implemented — see `docs/detection-engine.md` §3).

### T1098 — Account Manipulation (tactic: TA0004, Privilege Escalation)

Adversaries modify account permissions, group membership, or credentials
to maintain or expand their access. Detected by AUTH-PRIVCHANGE-003
(privilege modification shortly after a login from a new IP).

### T1059.001 — PowerShell (sub-technique of T1059, tactic: TA0002, Execution)

Adversaries abuse PowerShell for execution — it's a powerful,
built-in-on-Windows scripting environment that can download payloads,
execute in memory, and interact with almost every part of the OS. Detected
by ENDPOINT-POWERSHELL-001 (encoded commands, hidden window style, or
execution-policy bypass flags).

### T1071 — Application Layer Protocol (tactic: TA0011, Command and Control)

Adversaries communicate with compromised hosts using standard application
protocols (HTTP, HTTPS, DNS) to blend malicious traffic in with legitimate
traffic. Detected heuristically by NETWORK-OUTBOUND-001 (connections to a
destination port the host rarely uses) — full confidence again requires
the behavioral baseline service.

### T1562 — Impair Defenses (tactic: TA0005, Defense Evasion)

Adversaries disable or weaken security controls — logging, monitoring,
antivirus, firewall rules — specifically to operate undetected. Detected
by CLOUD-SECCONTROL-001. See the defense-evasion-response playbook for the
full SOC procedure; this technique deserves unusually high default
severity because it has few benign explanations.

### T1595 — Active Scanning (tactic: TA0007, Discovery)

Adversaries probe a target's infrastructure to map what's exposed before
attempting further action — port scans, vulnerability scans, or repeated
requests against many endpoints looking for one that responds
unexpectedly. Detected by APP-ACCESSDENIED-001 (a burst of 401/403
responses from one client).

### T1499 — Endpoint Denial of Service (tactic: TA0040, Impact)

Adversaries degrade or block the availability of a service or host. Used
here as the technique tag for CORRELATION-MULTIHOST-001, the meta-rule that
flags when many distinct detections cluster on one host in a short window
— that pattern is consistent with (though not exclusive to) an
availability-impacting event.

## Reading a technique ID

`T1110` — a top-level technique. `T1059.001` — technique `T1059`
(Command and Scripting Interpreter), sub-technique `.001` (PowerShell
specifically, as opposed to `.003` Windows Command Shell, `.006` Python,
etc.). When SentinelForge cites a sub-technique, the parent technique's
broader description still applies — the sub-technique just narrows down
the specific method.
