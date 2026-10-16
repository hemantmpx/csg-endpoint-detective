# Scenario package format

Each case is a frozen package generated from the canonical definitions in `backend/app/catalog.py`. For incident cases, one incident definition is replayed at every boundary to produce inventories, independently sourced CSG transitions, adjacent-pair Snapshot Deltas, and separately configured Wazuh coverage. CSG transitions are never inferred from generated Wazuh events. Each Snapshot Delta names its before and after captures; three captures therefore produce separate A→B and B→C differences.

```text
scenarios/<slug>/
  manifest.json
  briefing.md
  snapshots.json
  deltas.json
  transitions.json
  events.jsonl.gz
  answer-key.private.json
```

The private answer key is backend-only and is not returned by student routes. `events.jsonl.gz` is the deterministic Variant A corpus used for reference and packaging; runtime seeding generates all five variants from the same definitions.

## CSG transition record

A transition is structurally separate from a snapshot, a durable delta, and a Wazuh event:

```json
{
  "id": "t-service-auto",
  "source": "csg",
  "host": "WIN-LAB-01",
  "observed_at": "2026-09-26T09:37:12+00:00",
  "category": "service",
  "object_key": "service:remoteassistservice",
  "transition": "MODIFY",
  "before": {"start_mode": "manual"},
  "after": {"start_mode": "automatic"}
}
```

Records include source, host, timestamp, category, stable object identity, operation, and before/after attributes where applicable. Internal operations remain generic in the schema. The student UI translates them into object-specific labels, including Process Create/Process Terminated, Listener Opened/Listener Closed, Scheduled Task Registered, and Registry Value Set. A service start-type change is not displayed as a runtime start or stop. Process START/EXIT and listener OPEN/CLOSE records can exist while captures show the object absent. A service can change and revert while adjacent captures agree.

## Canonical incident definition

Incident cases declare an explicit initial state, ordered transitions, two or more snapshot boundaries, a telemetry coverage entry for every transition, and durable delta ID mappings. A transition can be configured as `recorded` or `missing` in the Wazuh plane. Replaying the CSG transitions derives state at every capture and the adjacent-pair delta list. Wazuh records are generated independently, with designed correlation points such as a shared executable path, process ancestry, exact service command, task action, or registry value. This preserves source independence while giving students grounds to connect a threat to observed CSG state.

Variants change hosts, object names, PIDs, paths, ports, and stable event IDs while retaining the same logical timeline. `tools/build_scenarios.py` writes all package files and materializes private per-variant answer keys.

## Snapshots, deltas, events, and answers

Snapshots contain stable IDs, host IDs, UTC observation times, counts, collector health, and inventories. A durable delta references its adjacent before/after snapshots and contains category, object key, `ADD|REMOVE|MODIFY`, before/after attributes, and the observation window. The runtime API returns snapshot headers and paginated inventory separately.

Wazuh events contain event ID, timestamp, host, provider, Windows event code, normalized type, stable object key, normalized searchable fields, raw Wazuh-shaped JSON, and provenance. One Sysmon 13 record is marked `redacted_research_structure` and preserves the sanitized Wazuh envelope/field shape; all host, user, process, ID, and target values are fictional substitutions. The UI labels each record's provenance in its details. Each case also adds a correlated `synthetic_attack_context` trail: a lab-specific level 12 rule (`110901`) over PowerShell 4104, Defender 5007, Sysmon file-creation 11, and Sysmon outbound-network 3 records. The simulated 4104 script names case service or persistence objects where applicable; process ancestry and shared paths tie activity to CSG-observed processes. The synthetic alert and reserved TEST-NET destinations make hostile intent explicit while keeping transfer success unverified. These events do not generate or mutate CSG state. Private answer mappings can require direct state evidence together with a contextual script record; the script links intent but does not independently prove command success.

Private answers identify the expected classification, required/acceptable evidence IDs, prohibited distractor IDs, whether all matching evidence is required, explanation, and learning notes for each variant and investigation item.

## Validation

`tools/validate_scenario.py` checks package identity, ordered snapshots and transitions, the CSG source marker, durable deltas from canonical replay, explicit telemetry coverage, generated event presence/absence, event IDs, per-variant answer references, noise volume, and sensitive/personal data patterns. It also ensures the scenario directories match the active catalog.
