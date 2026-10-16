# Architecture

## Boundary

CSG Endpoint Detective is an independent classroom application. The neighboring CSG research repository is used only as read-only reference material for terminology, visual structure, state/delta schemas, and sanitized Wazuh evidence examples. Runtime reads only files and services in this repository. There is no live Wazuh connection, research API/database, endpoint agent, VM, credential, or sibling-path dependency.

## Runtime components

```text
Student / instructor browser
          │ HTTPS
          ▼
       Caddy
       ├── Next.js classroom UI
       └── FastAPI API ───── PostgreSQL 16
                             ├── sessions, evidence, searches, submissions
                             ├── indexed archived Wazuh events
                             └── scenario seed versions
```

The case catalog is the canonical scenario source. For incident cases, state replay produces each configured snapshot, independent CSG transition records, and a Snapshot Delta for every adjacent pair. A separate telemetry declaration controls which Wazuh records are generated or missing. Search requests never create or alter CSG state evidence. Frozen scenario files contain snapshots, deltas, transitions, events, and backend-only answer keys.

## CSG and Wazuh evidence model

Snapshots show what persisted at collection time. **Snapshot Delta** compares an adjacent pair (A→B, then B→C where a case has three captures). The CSG State Change Timeline preserves selected activity between snapshots, including changes that reverted or ended. Wazuh events remain an independent source that can corroborate, partially explain, contradict, or fail to explain a CSG observation.

The student classifications are `CONSISTENT`, `PARTIALLY_EXPLAINED`, `UNEXPLAINED`, `CONTRADICTED`, and `INSUFFICIENT_EVIDENCE`. A nearby event is only a search candidate; reconciliation checks host, stable object identity, operation, transition values, and observation interval. `UNEXPLAINED` is an evidence gap, not a maliciousness verdict.

## Capacity and isolation

The deployment uses stateless API workers and PostgreSQL as shared storage. Each student has a random opaque session cookie and a stable scenario variant. Evidence selections, searches, and submissions are session-scoped. Event retrieval is paginated (100 default, 500 maximum) and constrained by scenario and variant. Answer keys are read only by backend scoring code and never included in student case or timeline responses.

## Visual language

The CSG workspace uses a light analyst-console palette, restrained teal accents, snapshot inventory, expandable Snapshot Delta cards, a separate CSG State Change Timeline, and an evidence tray. The Wazuh-style console uses a dark surface, automatically updating text and structured filters, archive-relative time-range controls, a synchronized event-volume chart, timestamp-first results, event details, and raw JSON. It is labeled archived lab evidence and disconnected from live Wazuh.

## Evidence provenance

Terminology and field shapes are informed by the read-only reference. Any real Wazuh evidence example is sanitized. The classroom event corpus uses deterministic fictional data with explicit source/provenance and realistic Windows event envelopes. Scenario variants preserve the same logical incident while changing identifiers.
