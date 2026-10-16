# CSG Endpoint Detective

CSG Endpoint Detective is a standalone classroom investigation simulator for learning how endpoint state and event telemetry are reconciled. Students compare CSG snapshots, review Snapshot Delta, inspect the separate CSG State Change Timeline, search archived Wazuh-style events, collect evidence, and submit a reasoned classification.

A nearby event is only a search lead. Students must compare host, object identity, operation, transition values, and observation interval. `UNEXPLAINED` means the available event telemetry does not explain a CSG observation; it does not by itself mean malicious activity.

## Evidence model

- **Snapshots A and B** (and Snapshot C in the three-capture case) show endpoint state at successive points in the observation window. **Snapshot Delta** compares one adjacent pair and shows the difference that remains at the later capture.
- **CSG State Change Timeline** preserves selected state activity CSG observed between those snapshot boundaries, including service changes that reverted and short-lived processes or listeners.
- **Wazuh events** are a separate evidence plane that can corroborate, partially explain, contradict, or fail to explain a CSG observation.

CSG transition records are never generated from Wazuh rows. Incident scenarios use one canonical state timeline to generate snapshots, Snapshot Delta data, CSG observations, and separately configured telemetry coverage.

The CSG research repository is used only as a read-only reference for terminology, visual structure, state/delta schemas, and sanitized Wazuh examples. One Sysmon 13 record preserves the sanitized Wazuh event envelope and field names; its host, user, process, IDs, and target values are classroom substitutions. No research source code, credentials, live API, database, endpoint VM, or sibling path is imported at runtime. The classroom corpus is fictional and deterministic.

## Case sequence

1. **The Expected Service:** a new service persists into Snapshot B; students test it against independent event evidence.
2. **The Overnight Change:** students use a service change and its identifying attributes to investigate related process activity in the event archive.
3. **Between the Snapshots:** a scheduled task persists while CSG separately records service and process activity that reverts or ends before Snapshot B.
4. **The Relay Takes Hold:** follow a two-stage intrusion from a service change in A→B to a startup task and network listener in B→C.
5. **Final Investigation — Transient Compromise with Persistent Foothold:** linked service, process, listener, task, and registry activity; persistent state, temporary activity, mixed event coverage, and deliberate noise.

For a short plain-language explanation of the research idea behind each case, see [What each case teaches](docs/case-research-concepts.md).

Each case has five deterministic variants and at least 15,000 Wazuh events per case/variant.

## Architecture

- Next.js 16.3.8 + React + TypeScript classroom UI
- FastAPI + SQLAlchemy API
- PostgreSQL 16 for sessions, evidence, submissions, instructor controls, and indexed event data
- Caddy same-origin proxy and Docker Compose deployment

See [architecture](docs/architecture.md), [database schema](docs/database-schema.md), [route map](docs/route-map.md), [scenario schema](docs/scenario-schema.md), [scenario authoring](docs/scenario-authoring.md), and [UX wireframe](docs/ux-wireframe.md).

## Quick start

1. Copy `.env.example` to `.env` and set unique `POSTGRES_PASSWORD`, `CLASS_CODE`, and `INSTRUCTOR_PASSWORD` values.
   `CLASS_CODE` remains the primary join code; optional comma-separated `ADDITIONAL_CLASS_CODES` are alternate ways into the same class and roster.
2. Run `docker compose up --build -d`.
3. Wait for the API to finish seeding the event variants.
4. Open `http://localhost:8080` and join with the class code.
5. Open `http://localhost:8080/instructor` to manage the class.

The browser reaches the API through Caddy. Student requests receive paginated archived events; the app makes no live Wazuh connection.

## Classroom flow

1. Read the case briefing.
2. Compare the snapshots in order and expand each adjacent Snapshot Delta.
3. Read the CSG State Change Timeline for selected activity that reverted or ended between the observations.
4. Search archived Wazuh events. Search updates automatically; text, object filters, and archive-relative time controls combine, and the chart selects the same time range.
5. Inspect candidate details and reconcile each investigation item using host, identity, operation, values, and time—not proximity alone.

The [student guide](docs/student-guide.md), instructor [guide](docs/instructor-guide.md), [professor-led lab walkthrough](docs/professor-lab-walkthrough.docx), and instructor-only [teacher’s manual and answer key](docs/teacher-manual.md) cover the classroom workflow and answers.

For the research presentation, see the [slide-by-slide speaker notes](docs/presentation-speaker-notes.md).

## Development

```sh
python3 -m venv .venv
./.venv/bin/pip install -r backend/requirements.txt
cd frontend && npm install && npx playwright install chromium && cd ..
python3 tools/build_scenarios.py
python3 tools/validate_scenario.py
make test
```

Frontend builds in `frontend/` with `npm install && npm run build`; `npm run typecheck` checks TypeScript. `make up`, `make down`, `make logs`, `make seed`, `make validate-scenarios`, `make load-test`, and `make reset-lab` are available.

Private answer material stays in scenario packages mounted into the backend and is omitted from student-facing case and event responses. See [deployment](docs/deployment.md) and [load testing](docs/load-testing.md) for operations and capacity notes.
