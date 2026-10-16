# Scenario authoring

Scenario definitions live in `backend/app/catalog.py`; deterministic Wazuh event creation lives in `backend/app/generator.py`. Preserve Cases 1 and 2 when changing later scenarios.

For a new incident case, declare one canonical CSG incident with an explicit initial state, ordered state transitions, snapshot boundaries, and explicit Wazuh coverage for every transition. Replay the state at every boundary and derive a Snapshot Delta for each adjacent pair; three captures therefore produce A→B and B→C deltas. Do not create CSG transition records from Wazuh rows. Put noise and distractors in separate telemetry generation declarations so a missing-event answer cannot acquire an accidental exact match.

A transition needs a stable ID, timestamp/offset, category, object template, operation, and before/after values. Use stable identity fields to connect related objects: service binary path, process image/parent/PID, listener PID/path/port, task action, and registry value data. Include same-time lookalikes that differ on meaningful fields, but keep the correct classification unambiguous.

Variants share one logical timeline and may change host, names, path, PID, port, and event IDs. Keep all answer evidence and distractor IDs variant-specific. Public scenario files must contain no expected classifications or private answer logic.

After changing a scenario, run `python3 tools/build_scenarios.py` to regenerate package files and private answers. Run `python3 tools/validate_scenario.py` to check package consistency and references across variants.

## Student-facing terminology and telemetry

The canonical scenario may keep generic internal operations such as `MODIFY`, `START`, `EXIT`, `OPEN`, `CLOSE`, and `CREATE`. The UI translates those operations using object category and fields: service start-type changes, Process Create/Process Terminated, Listener Opened/Listener Closed, Scheduled Task Registered, and Registry Value Set. Do not rename an independent Windows/Wazuh event to imitate the CSG label; for example, Windows Event 5154 retains its native listen-permitted meaning.

Listener transitions marked `missing` in Wazuh coverage must not produce a Wazuh row. The current generator has an explicit listen-permitted mapping for listener OPEN only; it rejects attempts to map CLOSE through that builder. If a future case models close telemetry, define and test a separate event representation with its own native semantics.
