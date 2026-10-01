# Detection Rules

Sigma-style YAML detection rules, organized by category. See
`docs/detection-engine.md` for the full rule format and engine design.

## Status

8 example rules implemented so far, covering the rule schema and every
category directory. Target for MVP is ~20 rules per
`docs/architecture/architecture.md`'s Phase 3. Tracked here as they're added:

| ID | Category | Title | Status |
|---|---|---|---|
| AUTH-BRUTEFORCE-001 | authentication | Repeated failed auth → success | ✅ implemented |
| AUTH-NEWLOGINIP-002 | authentication | Login from unseen source IP | ✅ implemented |
| AUTH-PRIVCHANGE-003 | authentication | Privilege change after new-IP login | ✅ implemented |
| ENDPOINT-POWERSHELL-001 | endpoint | Suspicious encoded PowerShell | ✅ implemented |
| NETWORK-OUTBOUND-001 | network | Unusual outbound destination port | ✅ implemented |
| CLOUD-SECCONTROL-001 | cloud | Security control disabled | ✅ implemented |
| APP-ACCESSDENIED-001 | application | Repeated 401/403 from one client | ✅ implemented |
| CORRELATION-MULTIHOST-001 | correlation | ≥3 distinct rules, one host | ✅ implemented |
| — impossible travel | authentication | | planned |
| — unusual login time | authentication | | planned |
| — account creation anomaly | authentication | | planned |
| — abnormal process execution | endpoint | | planned |
| — abnormal file execution | endpoint | | planned |
| — suspicious DNS behavior | network | | planned |
| — abnormal data transfer volume | network | | planned |
| — suspicious user-agent pattern | application | | planned |
| — suspicious API access pattern | application | | planned |
| — disabled security control (endpoint variant) | endpoint | | planned |
| — unusual administrator activity | authentication | | planned |
| — account creation anomaly (cloud) | cloud | | planned |

## Validating rules

```bash
python backend/scripts/validate_detection_rules.py detection-rules/
```

Runs automatically in CI (`.github/workflows/ci.yml`, job
`detection-rules-validate`) on every push and PR.

## Adding a new rule

1. Pick the right category directory.
2. Copy the closest existing rule as a starting point.
3. Fill in `id` (`CATEGORY-SHORTNAME-NNN`), `attack.technique_id` /
   `technique_name` from MITRE ATT&CK, and honest `false_positive_notes` —
   these are read by analysts and by the AI agent's context, so they should
   be accurate, not boilerplate.
4. Add a positive and negative fixture test under
   `backend/tests/detection/` (see `docs/detection-engine.md` §5).
5. Run the validator locally before opening a PR.
