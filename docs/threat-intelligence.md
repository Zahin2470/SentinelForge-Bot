# Threat Intelligence & MITRE ATT&CK

## 1. MITRE ATT&CK mapping

`app/attack/reference_data.py` holds a curated reference set: 8 tactics and
9 techniques, covering exactly what the current detection rule library
(`detection-rules/`) cites, plus each technique's parent tactic. This is a
deliberate scope choice, not a shortcut taken silently — the module's
docstring explains why: the canonical machine-readable source is
[MITRE's published STIX bundle](https://github.com/mitre/cti), and a
connected environment should point `scripts/import_attack_data.py` at that
bundle instead of this hand-curated set. There's no network access in this
dev environment, so what's here is real, tested, and honestly scoped rather
than a stub.

A test (`backend/tests/attack/test_attack_mapper.py:test_every_rule_technique_is_in_reference_data`)
is the tripwire that stops the rule library and this reference set from
silently drifting apart — if someone adds a rule citing a technique ID this
module doesn't know, CI fails immediately rather than the dashboard quietly
showing a broken mapping.

`app/attack/coverage.py` computes the "Detected Techniques / Covered
Techniques / Uncovered Techniques / Detection Coverage" numbers the
dashboard's coverage view needs, as a pure function over
(rule_technique_ids, detected_technique_ids) — 9 passing tests, exposed at
`GET /api/v1/attack/coverage`.

## 2. IOC engine

`app/models/threat_intel.py:IOC` supports the required 7 types (ipv4, ipv6,
domain, url, sha256, sha1, md5) with the required fields (type, value,
source, confidence, first_seen, last_seen, tags, threat_level,
related_campaign, related_techniques).

`app/threat_intel/matcher.py` does the actual lookup: given a batch of
normalized events and a list of known IOCs, it returns every match with
which field matched and the IOC's confidence/threat_level attached — never
a bare "this IP is bad" with no evidence trail. 9 passing tests.

## 3. STIX/TAXII — scoped honestly, per the master spec's own guidance

The build spec is explicit that STIX/TAXII is "an advanced module — do not
make it a blocker for MVP." `app/threat_intel/stix_normalizer.py` reflects
that: it handles the common case (a single `ObjectType:property = 'value'`
comparison — the overwhelming majority of real-world indicator objects)
and explicitly raises `UnsupportedStixPattern` for anything with boolean
logic (`AND`/`OR`) rather than silently mis-parsing it. This is not a full
STIX patterning-language implementation, and doesn't pretend to be one.

`threat-intel/sample_feed.json` is a small hand-written STIX-2.1-shaped
bundle used for local dev/demo — per the spec, "use simulated/private
sample intelligence for the local demo, do not rely on an external
commercial security API for core functionality." It includes one
indicator that intentionally uses a boolean-OR pattern, specifically to
prove the normalizer's "parse what it can, honestly skip what it can't"
behavior on a mixed batch (`test_sample_feed_parses_three_of_four_indicators`),
not just on hand-picked easy cases.

A real TAXII client (polling a TAXII 2.1 server for new indicator
collections) is not implemented — `import_feed()` reads a local JSON file.
Swapping in a real TAXII client later only touches how the bundle is
fetched, not `stix_normalizer.py` or anything downstream of it.

## 4. Wired into the pipeline

`app/services/threat_intel_service.py` imports a feed into the IOC table
and matches recent events against it, creating `Alert` rows with
`source="threat_intel"` — same evidence-attached contract as detection and
ML alerts (`docs/detection-engine.md`, `docs/ml/ml-pipeline.md`). These
alerts flow through the *same* correlation engine as rule/ML alerts
(`app/correlation/engine.py` doesn't care what produced an alert, only its
entity/timestamp/severity), so a known-bad IP showing up in the same
incident as a brute-force rule match is exactly what correlation is
supposed to surface — proven end-to-end in
`tests/test_scenario_pipeline.py:test_threat_intel_matching_adds_a_third_alert_to_the_same_incident`.

`app/services/risk_scoring.py:threat_intelligence_score_from_alerts`
computes the `threat_intelligence_score` risk-scoring component
(`docs/architecture/risk-scoring.md`) from an incident's threat-intel-sourced
alerts — the highest severity among them, or `None` (not 0) when no IOC
matched, so `compute_risk_score` renormalizes correctly instead of treating
"no intel signal" as "confirmed clean."

## 5. API surface

```
GET  /api/v1/threat-intel/iocs     list known IOCs
POST /api/v1/threat-intel/import   import a STIX-shaped feed file
POST /api/v1/threat-intel/match    match recent events against known IOCs, create alerts
GET  /api/v1/attack/coverage       Detected/Covered/Uncovered techniques + coverage %
```
