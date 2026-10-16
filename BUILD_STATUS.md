# Build status

## Current implementation

- Case 1, **The Expected Service**, links a new service to its exact installation record and malicious process chain.
- Case 2, **The Overnight Change**, gives students a CSG service identity and executable path to pivot into Wazuh process and PowerShell records; the briefing leaves the incident sequence for students to discover.
- Case 3, **Between the Snapshots**, combines a persistent scheduled task with a reverted service cycle and short-lived process.
- Case 4, **The Relay Takes Hold**, links A→B service/process changes to B→C task and listener additions across three snapshots.
- Case 5, **Final Investigation**, links a temporary service change, process, listener, scheduled task, and registry Run value. The task and Run value persist; the service reverts and process/listener end. Task registration is missing and listener close is not recorded.
- CSG transitions are separate records with `source: csg`; they are not derived from Wazuh rows. Canonical state replay generates captures, adjacent Snapshot Delta records, and CSG transitions. Telemetry coverage separately generates recorded or missing Wazuh evidence.
- Case 1 includes five out-of-window, same-service 7045 records with a benign-context binary path at distinct times, so students compare time and image path rather than treating the service name or `agent.exe` filename as proof.
- Scenario packages contain five variants each. Variant A currently has 15,019, 15,017, 15,020, 15,027, and 15,025 Wazuh records in Cases 1–5 respectively.
- Keeps the research repository read-only. One Sysmon 13 record preserves the sanitized event envelope and field names with fictional classroom values.

## Previously recorded baseline checks

- These checks predate the current five-case scenario revision and are retained as a record of the earlier baseline.
- `tools/build_scenarios.py` regenerated all four active case packages, including the structured briefing sections. Variant A packages contain 15,008, 15,008, 15,015, and 15,020 Wazuh events respectively; each case has five seeded variants.
- `tools/validate_scenario.py` passed for all four active cases.
- Backend unit tests passed: 16 tests, including progressive briefing structure, combined event filters, bounded time ranges, listener-close mapping, and cleanup for transitions declared missing.
- `npm run typecheck` passed.
- Playwright end-to-end tests passed: 2 tests cover student reconciliation, CSG terminology, live search, structured filters, combined custom time ranges, reset behavior, chart click/drag synchronization, and the zero-result message.
- `docker compose up --build -d backend frontend` rebuilt and started the production frontend/API images; the API health check returned `ok`. The existing PostgreSQL volume was retained.
- Docker Compose backend and frontend images were previously rebuilt. API health returned `ok`, `/lab` returned HTTP 200, and PostgreSQL reported 300,255 events across the four active cases.

## Local classroom

`http://localhost:8080`
