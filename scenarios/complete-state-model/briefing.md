# Between the Snapshots

## Research perspective

CyberStateGuardian (CSG) records endpoint state and changes between snapshots. Wazuh is an open-source SIEM that collects Windows, PowerShell, Defender, and Sysmon events. The sources are independent, but analysts correlate them by host, object name, executable path, process ancestry, command, and time to assess which activity is linked to an observed state change.

## Scenario

On WIN-LAB-01, DeviceHealthSvc briefly changed from Manual to Automatic and back. In the same interval, DeviceHealthCheck.exe started and exited, while a new task, \Microsoft\Windows\DeviceHealth\CacheRefresh, remained configured. The service returned to its original state before Snapshot B. Follow the shared executable and process identifiers to investigate what happened between captures.

## What CSG observed

CSG recorded changes inside the interval, including activity that may no longer appear in Snapshot B.

## What this case teaches

A process may start and exit, or a service may change and change back, between snapshots. Read the CSG timeline as well as the inventories.

## Technical context

A process can start and exit before the next snapshot. A service can return to its earlier configuration. A scheduled task can remain configured after the activity that created it ends.

## Evidence available to you

- **Snapshot A / Snapshot B:** Endpoint inventories at the beginning and end of the interval.
- **Snapshot Delta:** Differences that remain when Snapshot A is compared with Snapshot B.
- **CSG State Change Timeline:** Changes recorded by CSG between snapshots, including activity that later ended or reverted.
- **Wazuh / Windows telemetry:** Separate event logs. Compare the host, object, operation, values, and time with CSG.

## Your task

Identify what persisted and what ended. Trace the child process, its security-setting and data-staging commands, and the task it requested. Match the task and action across the script, CSG timeline, and Wazuh registration event.
