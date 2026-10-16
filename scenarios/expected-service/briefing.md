# The Expected Service

## Research perspective

CyberStateGuardian (CSG) records endpoint state and changes between snapshots. Wazuh is an open-source SIEM that collects Windows, PowerShell, Defender, and Sysmon events. The sources are independent, but analysts correlate them by host, object name, executable path, process ancestry, command, and time to assess which activity is linked to an observed state change.

## Scenario

During a maintenance window on WIN-LAB-01, the BackupAgent service appeared in the endpoint inventory. Snapshot A has no entry for it; Snapshot B shows it running as LocalSystem with Automatic startup. Its name suggests routine software. Investigate the executable and its activity before accepting that explanation.

## What CSG observed

CSG captured the service inventory before and after the maintenance window.

## What this case teaches

Find the state change first. Then check whether a Windows event describes the same host, service, and operation.

## Technical context

Start type controls when a service can start: Manual, Automatic, or Disabled. Runtime status tells you whether it is Running or Stopped. Check which field the event actually describes.

## Evidence available to you

- **Snapshot A:** Endpoint inventory at the beginning of the interval.
- **Snapshot B:** Endpoint inventory at the end of the interval.
- **Snapshot Delta:** Differences that remain when Snapshot A is compared with Snapshot B.
- **Wazuh / Windows telemetry:** Separate event logs. Compare the host, object, operation, values, and time with CSG.

## Your task

Match the service installation record, then follow its executable into the process and PowerShell events. Use the command, parent PID, and shared path to explain why the service is part of the threat.
