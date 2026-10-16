# The Overnight Change

## Research perspective

CyberStateGuardian (CSG) captures endpoint state and records changes between snapshots. Wazuh is an open-source SIEM; this lab models a deployment configured to collect Windows, Defender, PowerShell, and Sysmon events. Correlate the sources by host, object, executable path, PID, command, and time. One source can reveal a change while another reveals the process and intent behind it.

## Scenario

An overnight maintenance window on WIN-LAB-01 is followed by activity that needs review. Reconstruct the sequence from endpoint state and event logs, then assess whether the activity is consistent with expected administration.

## What CSG observed

CSG provides endpoint snapshots and a separate record of changes observed between captures. Begin with the object and attributes recorded in the state evidence.

## What this case teaches

Use endpoint state to form a testable lead, then compare it with independent event records. Explain where the sources agree, where they differ, and what the evidence cannot establish.

## Technical context

Services have separate configuration and runtime state. Windows events, process records, and script content describe different parts of activity; compare the exact object, relevant fields, process relationships, and time before inferring cause.

## Evidence available to you

- **Snapshot A and Snapshot B:** Endpoint inventories at the beginning and end of the interval.
- **Snapshot Delta:** Differences that remain when Snapshot A is compared with Snapshot B.
- **Wazuh / Windows telemetry:** Separate event logs. Compare the host, object, operation, values, and time with CSG.

## Your task

Compare the snapshots. Expand the relevant Snapshot Delta and note the host, exact object identity, changed values, and any other identifying attributes. Use those CSG details as pivots into Wazuh, reconstruct the surrounding activity, and explain what each source can and cannot confirm.
