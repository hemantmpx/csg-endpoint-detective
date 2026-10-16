# Final Investigation — Transient Compromise with Persistent Foothold

## Research perspective

CyberStateGuardian (CSG) records endpoint state and changes between snapshots. Wazuh is an open-source SIEM that collects Windows, PowerShell, Defender, and Sysmon events. The sources are independent, but analysts correlate them by host, object name, executable path, process ancestry, command, and time to assess which activity is linked to an observed state change.

## Scenario

On WIN-LAB-01, RemoteAssistSvc temporarily changed startup mode while TelemetryStage.exe ran and opened a network listener. The process ended and the service configuration reverted, but a scheduled task and registry Run value remained. Trace their executable paths and process identifiers to reconstruct the activity and assess what the logs support.

## What CSG observed

CSG recorded changes to several related objects. Some remain in Snapshot B; others appear only in the timeline.

## What this case teaches

Link objects by executable path, PID, parent process, task action, and registry data. A close timestamp is a lead to inspect, not proof of a link.

## Technical context

A listener is a process waiting for connections on a local address and port. A scheduled task stores a program to run. A registry Run value starts a program at sign-in. Match their paths and process IDs where available.

## Evidence available to you

- **Snapshot A / Snapshot B:** Endpoint inventories at the beginning and end of the interval.
- **Snapshot Delta:** Differences that remain when Snapshot A is compared with Snapshot B.
- **CSG State Change Timeline:** Changes recorded by CSG between snapshots, including activity that later ended or reverted.
- **Wazuh / Windows telemetry:** Separate event logs. Compare the host, object, operation, values, and time with CSG.

## Your task

Reconstruct the sequence from service to parent process, child PowerShell, listener, task, and Run value. Match exact object names and executable data across CSG and Wazuh; identify the malicious intent and state where telemetry is missing.
