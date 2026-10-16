# The Relay Takes Hold

## Research perspective

CyberStateGuardian (CSG) records endpoint state at collection boundaries and selected changes between them. Wazuh is an open-source SIEM configured here for Windows, PowerShell, Defender, and Sysmon telemetry. Compare each adjacent snapshot pair, then follow host, service image, process ID, parent process, task action, and listener ownership across the independent sources.

## Scenario

Three captures on WIN-LAB-01 show a staged intrusion. Between Snapshot A and B, DeviceCacheSvc changes from Manual to Automatic and its CacheHost.exe image appears in the running process inventory. Between B and C, the same image is registered in \Microsoft\Windows\Diagnostics\CacheHealth and begins listening on TCP 8448. The sequence resembles a quiet maintenance relay. Trace the service-to-process relationship and then decide whether the later task and listener are routine support activity or a foothold being established.

## What CSG observed

CSG captured three endpoint states. Compare A→B and B→C separately: the first interval changes service configuration and process inventory; the second adds a task and a listener.

## What this case teaches

A sequence across adjacent snapshot deltas can reveal more than an isolated before/after pair. Establish the first link, then carry its exact image path and PID forward to test whether later persistence and network exposure belong to the same activity.

## Technical context

A service start type controls startup behavior. A scheduled task stores a later execution action. A listener accepts inbound connections on a local address and port. Process telemetry, PowerShell script blocks, task registration, and Windows Filtering Platform records describe different parts of the sequence; correlate their identities rather than treating any one timestamp as proof.

## Evidence available to you

- **Snapshots A, B, and C:** Three endpoint inventories. Each adjacent pair represents a separate observation interval.
- **Snapshot Delta:** The durable differences for A→B and B→C; check the interval named on each record.
- **CSG State Change Timeline:** Selected state transitions CSG observed across the full capture window.
- **Wazuh / Windows telemetry:** Independent events for service configuration, process ancestry, script content, task registration, and listener permission.

## Your task

Investigate both intervals in order. First match the service start-type change and process image. Then test whether the task action and listener PID/path continue that chain. Inspect PowerShell 4104 for the attacker’s purpose, and reject records that only share a name, port, or nearby time.
