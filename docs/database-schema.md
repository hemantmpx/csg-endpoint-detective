# Database schema

PostgreSQL 16 stores learner activity, instructor controls, scenario seed versions, and the indexed frozen Wazuh event corpus. Canonical scenario definitions and generated snapshots, deltas, CSG transitions, briefings, and private answer keys remain in `scenarios/` and backend code.

| Table | Important columns | Purpose |
|---|---|---|
| `lab_control` | `id`, `active`, `mode`, `enabled_cases JSON` | Classroom state, guided/challenge mode, enabled cases. |
| `student_sessions` | `id UUID`, `display_name`, `variant`, `created_at`, `last_seen_at` | Opaque cookie-backed learner identity and stable variant. |
| `events` | `id`, `scenario_slug`, `variant`, `timestamp`, `host_name`, `event_code`, `event_type`, `provider`, `object_key`, normalized/raw JSON, `search_text`, `provenance` | Archived Wazuh/Windows telemetry; indexed by scenario, variant, time, code/type, host, object, service, process, and registry fields. |
| `scenario_seeds` | `id`, `version`, `event_count`, `seeded_at` | Records the generated event-corpus version for each case/variant so revised Case 1 and 2 event rows can be refreshed in place while preserving learner evidence selections and submissions. |
| `evidence_selections` | `student_id`, `scenario_slug`, `delta_id`, `event_id`, `selected_at` | Event selections linked to the currently active investigation item. The existing `delta_id` column stores the item ID for compatibility. |
| `submissions` | `id UUID`, `student_id`, `scenario_slug`, `delta_id`, `classification`, `explanation`, `submitted_at`, `score`, `correct`, `evidence_ids JSONB` | Persisted item-level reconciliation and score. |
| `search_history` | `id`, `student_id`, `scenario_slug`, `query`, `result_count`, `created_at` | Instructor review of classroom search strategy. |

CSG transition records are separate immutable scenario records, not rows in the Wazuh `events` table. The timeline API returns those CSG records alongside, but clearly distinguished from, snapshot headers and Snapshot Delta data. Snapshot inventory is deterministically materialized from canonical state for the selected variant. Each variant's 15,000+ Wazuh events are generated at seed time, not per student request.

All event queries are constrained by scenario and assigned variant before user filters. The query parser accepts only allow-listed fields and compiles terms to bound SQL expressions. Pagination defaults to 100 rows and caps at 500.
