# API route map

FastAPI is served under `/api` through the same-origin Caddy proxy. Student identity is read from an opaque HttpOnly cookie; no route trusts a student ID supplied by the browser. Instructor routes require the signed instructor cookie.

| Method / route | Access | Purpose |
|---|---|---|
| `GET /api/health` | public | Database readiness and service version. |
| `GET /api/lab` | public | Classroom title and active/mode state. |
| `POST /api/sessions` | public | Validate class code, create session, assign a variant, set cookie. |
| `GET /api/sessions/me` | student | Display name, variant, progress, completed cases. |
| `GET /api/cases` | student | Public case list, item counts, completion, guided-mode locks. |
| `GET /api/cases/{slug}` | student | Briefing and public metadata; no answer key. |
| `GET /api/cases/{slug}/timeline` | student | Snapshot headers, Snapshot Delta data, separate CSG State Change Timeline records, item list, and submitted statuses. |
| `GET /api/cases/{slug}/snapshots/{snapshot_id}` | student | Full searchable, paginated inventory for one snapshot. |
| `GET /api/events?slug=...` | student | Allow-listed query, time/type/host filters, bounded page, count, histogram. |
| `GET /api/events/{event_id}` | student | Normalized details and raw JSON for the assigned variant. |
| `GET /api/cases/{slug}/evidence?delta_id=...` | student | Evidence tray for one investigation item. The compatibility parameter stores an item ID. |
| `PUT /api/cases/{slug}/evidence/{delta_id}/{event_id}` | student | Add an archived Wazuh event to the active item. |
| `DELETE /api/cases/{slug}/evidence/{delta_id}/{event_id}` | student | Remove a selected Wazuh event. |
| `POST /api/cases/{slug}/submissions` | student | Submit item ID, classification, and explanation; receive result and evidence review. |
| `GET /api/cases/{slug}/submissions/{delta_id}` | student | Return a prior result only after that student submitted the item. |
| `POST /api/instructor/session` | public | Authenticate and set instructor cookie. |
| `GET /api/instructor/summary` | instructor | Roster, completion, case response distributions, and progress. |
| `GET /api/instructor/search-history` | instructor | Recent classroom search strategies. |
| `GET /api/instructor/export.csv` | instructor | Export item ID, classification, correctness, score, evidence count, submitted explanation, and timestamps for instructor review. |
| `PATCH /api/instructor/lab` | instructor | Start/pause, guided/challenge mode, enabled cases. |
| `POST /api/instructor/students/{id}/reset` | instructor | Reset a learner's selections, submissions, and searches. |

The query parser supports field/value terms, quoted values, `AND`, `OR`, and free text. Search fields are allow-listed. Expected classifications and private answer explanations are returned only after a valid submission.
