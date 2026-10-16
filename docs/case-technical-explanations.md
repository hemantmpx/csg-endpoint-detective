<!-- Instructor reference: five case sheets; each sheet is one page in the Word document. -->

> These case sheets use Version A examples. For the exact CSG clues, identifiers, Wazuh searches, classifications, and reasoning for **all five versions**, see the [Variant Answer Key](variant-answer-key.md).

# Case 1 — The Expected Service

**Instructor-only · Variant A example · WIN-LAB-01 · 26 September 2026 · all times UTC · 15,019 events**

Snapshot A 09:30; Snapshot B 10:00. Wazuh archive 09:00–12:00; the UI displays browser-local time.

## What happened

BackupAgent is absent from Snapshot A and present in Snapshot B, configured as Automatic and Running under LocalSystem. Its binary is C:\Program Files\BackupAgent\agent.exe. CSG establishes a service addition during the interval; the matching Windows log supplies the installation time.

## Answer and matching evidence

| Finding | Collect | Decisive match |
| --- | --- | --- |
| Consistent | SCM 7045 + PowerShell 4104 | 7045 names BackupAgent and its path; 4104 names the same service in its persistence command and reveals malicious intent. |

## Clues and search

Compare inventories first. A newly present service needs installation evidence. Event 7045 represents installation; a 7040 start-type change or 7036 runtime-state record does not establish creation. Check the full service name, host, executable path, and snapshot interval.

```text
host.name:WIN-LAB-01 AND event.id:7045
host.name:WIN-LAB-01 AND service.name:"BackupAgent" AND event.id:7045
event.id:4104 AND BackupAgent
```

## Noise and distractors

- 15,000 routine records, 12 deliberate distractor rows, and six incident-context records. Full credit requires the in-window 7045 and its correlated 4104.
- 09:49–09:54: 7040 records for update services and BackupAgentSvc. AdobeUpdateService changes at the exact installation timestamp, but it is a different service and operation.
- 09:52:17.432: a BackupAgent 7040 event on WIN-OPS-07. The name matches, but the endpoint and operation do not. Name searches may also return similarly named services.
- Five benign-context 7045 records for the same service occur at five distinct times after Snapshot B. Their path is `C:\Program Files\BackupAgent\BackupAgent.exe`, while CSG records `agent.exe`. The exact-service query returns six rows; compare each image path and timestamp with CSG.

## How the evidence maps together

CSG shows BackupAgent absent in A and present in B. The same-host 7045 inside that interval records the CSG `agent.exe` path; Sysmon 1 records that image starting. Its process launches PowerShell; 4104 names BackupAgent in a startup command and records Defender disablement and SAM staging. Events 5007, Sysmon 11, and 3 corroborate defense evasion, archive creation, and an outbound attempt. Five benign-context 7045 records name the same service at distinct times after Snapshot B, using a different routine-looking binary path. They do not match the observed delta. The process/script chain establishes the malicious link; outbound traffic does not prove receipt.

## Expected explanation

“BackupAgent appears between the snapshots. Six same-host 7045 rows name BackupAgent, but five duplicate rows are after Snapshot B and record a different binary path. The in-window event records the `agent.exe` path shown by CSG. I do not classify `agent.exe` by its name alone: Sysmon shows that image starting and launching PowerShell, and 4104 records the persistence command, Defender change, and data staging. The CSG addition is directly supported and linked to malicious activity.”

## Full-credit selection

Choose Consistent and collect both the matching 7045 installation record and the correlated 4104 script block. Explain that 7045 directly supports the service addition; the matching image path, service name, and child-process chain connect its malicious purpose.

*Instructor answer reference • For A–E identifiers and exact CSG-to-Wazuh searches, see variant-answer-key.md.*


<div style="page-break-before: always;"></div>


# Case 2 — The Overnight Change

**Instructor-only · Variant A example · WIN-LAB-01 · 26 September 2026 · all times UTC · 15,017 events**

Snapshot A is 09:30 and Snapshot B is 10:00. Wazuh’s archive covers 09:00–12:00; the UI displays browser-local time.

## CSG clue and answer

CSG records `UpdateHelper` changing from Manual to Automatic while its runtime status remains Running. Expand Snapshot Delta to read the stable executable path: `C:\Program Files\UpdateHelper\agent.exe`. The same path identifies a Wazuh service-process start. Classification: **PARTIALLY_EXPLAINED**.

## Work from state to events

First search the assigned host, exact service, and event 7040 for the CSG start-type change. There is no matching record. Then pivot from the CSG executable path to Sysmon event 1, note service PID 4160, find its PowerShell child (PID 4180), and open that PID’s event 4104:

```text
host.name:WIN-LAB-01 AND service.name:"UpdateHelper" AND event.id:7040
host.name:WIN-LAB-01 AND process.executable_path:"C:\Program Files\UpdateHelper\agent.exe" AND event.id:1
host.name:WIN-LAB-01 AND process.parent_pid:"4160" AND event.id:1
host.name:WIN-LAB-01 AND process.pid:"4180" AND event.id:4104
host.name:WIN-LAB-01 AND service.name:"CsgTelemetryForwarder" AND event.id:7036
```

The full 4104 block records `sc.exe stop CsgTelemetryForwarder`, `sc.exe config UpdateHelper start= auto`, and `sc.exe start CsgTelemetryForwarder`, in that order. Event 7036 records the forwarder stopping at 09:51:26Z and returning to Running at 09:51:33Z. The same script then disables Defender, stages documents, and attempts an outbound transfer. Events 5007, Sysmon 11, and Sysmon 3 provide follow-on evidence.

## Noise and conclusion

The 11 Variant E results from free-text `OpsTelemetry` plus event 7036 name `OpsTelemetrySvc`, a different service whose Running/Stopped state is not a startup-mode change. Search `service.name:"OpsTelemetry"` for an exact identity. Other decoys include a correct-direction 7040 on the wrong host, an Automatic → Disabled event for the similar-name service, and a read-only `Get-Service` / `sc.exe qc` script.

The event sequence makes a telemetry gap and link to CSG’s observed result plausible, but a script-block record shows captured command content, not successful execution. With no matching 7040 for the target service, students should not claim the command’s success or causation is confirmed.

**Full-credit response:** “CSG independently records UpdateHelper changing Manual to Automatic. Its executable path leads to a matching service process and a child PowerShell process. Event 4104 records the forwarder stop, configuration request, and restart; 7036 records the forwarder stop and recovery. Later Defender, archive, and network records show malicious follow-on activity. The matching target-service 7040 is absent, so classify this as Partially explained: the evidence supports a connection but does not prove the configuration command succeeded or caused the state change.”

---

# Case 3 — Between the Snapshots

**Instructor-only · Variant A example · WIN-LAB-01 · 26 September 2026 · all times UTC · 15,020 events**

Snapshot A 09:30; Snapshot B 10:00. Wazuh archive 09:00–12:00; the UI displays browser-local time.

## What happened

DeviceHealthSvc changes Manual → Automatic at 09:37:12 and returns to Manual at 09:39:15. DeviceHealthCheck.exe starts at 09:37:25 and exits at 09:39:00. At 09:38:10, a scheduled task is registered and remains configured. Only the task appears in Snapshot Delta; CSG’s separate timeline retains all five intermediate changes.

## Answers and matching evidence

| Item / finding | Collect | Decisive match |
| --- | --- | --- |
| Service cycle · Consistent | Two SCM 7040 records | DeviceHealthSvc; Manual → Automatic and Automatic → Manual; exact host and values. |
| Process lifecycle · Consistent | Sysmon 1 + Sysmon 5 | DeviceHealthCheck.exe; PID 4160; same image path and host; parent services.exe / PPID 680. |
| Persistent task · Consistent | Task Scheduler 106 + PowerShell 4104 | Exact CacheRefresh task/action in both; the script is part of the process chain that disables Defender and stages data. |

## Clues and search

The service binary and process image are C:\ProgramData\CsgLab\Stage\DeviceHealthCheck.exe. The task is \Microsoft\Windows\DeviceHealth\CacheRefresh; its action invokes that image with --inventory. The restored service and short-lived process leave no boundary difference, so read the CSG timeline before searching Wazuh.

```text
host.name:WIN-LAB-01 AND process.pid:4160
event.id:4104 AND CacheRefresh
```

## Noise and distractors

- 15,000 routine records, 10 deliberate decoys, and 6 required records for full credit.
- 09:37:23: same process name/path and parent, but PID 4161 instead of 4160. It is a different process instance.
- 09:37:40: CacheRefresh-Telemetry with --stage. Both task identity and action differ. At 09:37:42, an exact-name task occurs on WIN-OPS-07, also with --stage.
- Nearby update-service changes and DeviceHealthSvcSvc records refer to other services. Exact-looking service activity on WIN-OPS-07 belongs to another host.

## How the evidence maps together

CSG records DeviceHealthSvc changing Manual → Automatic → Manual and DeviceHealthCheck.exe starting/exiting between captures. Two 7040s confirm the service cycle; Sysmon 1/5 confirm the process lifecycle. The CacheRefresh task is the Snapshot Delta. 4104 names its exact action, and Scheduler 106 confirms registration. Its process-linked script records Defender disablement and staging, corroborated by 5007 and Sysmon 11/3. The service/process are transient; the task persists. Outbound activity is an attempt, not proof of receipt.

## Full-credit explanation

Choose Consistent for all three items. Collect 2 service and 2 process records. For the task, collect both Task Scheduler 106 and PowerShell 4104; compare their exact task name and action. Explain how the transient process and restored service hide in the boundary snapshots, while the linked script reveals the malicious purpose of the task.

*Instructor answer reference • For A–E identifiers and exact CSG-to-Wazuh searches, see variant-answer-key.md.*


<div style="page-break-before: always;"></div>


# Case 4 — The Relay Takes Hold

**Instructor-only · Variant A example · WIN-LAB-01 · 26 September 2026 · all times UTC · 15,027 events**

Snapshot A 09:30; Snapshot B 10:00; Snapshot C 10:30. Wazuh archive 09:00–12:00; the UI displays browser-local time.

## What happened

This is a two-stage intrusion. At 09:39, a remote maintenance logon starts PowerShell. Its 4104 script requests `DeviceCacheSvc` change from Manual to Automatic and starts the service image `C:\ProgramData\CsgLab\Stage\CacheHost.exe`. CSG captures the service change and process by Snapshot B. At 10:08, a child PowerShell process of CacheHost.exe registers a hidden startup task, launches a second CacheHost.exe instance as a listener on TCP 8448, disables Defender, stages an archive, and attempts an outbound POST. CSG captures the task and listener in Snapshot C. The identical image path and parent/child PIDs connect A→B to B→C.

## Answers and matching evidence

| Finding | Collect | Decisive match |
| --- | --- | --- |
| Service mode · Consistent | SCM 7040 + Sysmon 1 + stage-A 4104 | Exact service, Manual → Automatic direction, service image, and the script request. |
| Service image process · Consistent | Sysmon 1 + stage-B 4104 | PID 7460, exact image path, `services.exe` parent; later PowerShell names this parent PID. |
| Startup task · Consistent | Task Scheduler 106 + stage-B 4104 | Exact `CacheHealth` task and `CacheHost.exe --serve 8448` action. |
| Listener process · Consistent | Sysmon 1 + stage-B 4104 | PID 7520, same image and command as task action, PowerShell parent PID 7480. |
| Listener · Consistent | Security 5154 + stage-B 4104 | TCP 8448, 0.0.0.0, PID 7520, and exact CacheHost.exe path. |

## Clues and searches

Start with A→B: compare service identity and start-type direction, then match the service binary to Sysmon PID 7460. Carry that exact path and PID into B→C. The second 4104 process is child PID 7480 of 7460; its task command and `Start-Process` launch point to the second CacheHost.exe PID 7520. Event 106 confirms the task, Sysmon 1 confirms the listener process, and 5154 confirms Windows permitted that process to listen.

```text
host.name:WIN-LAB-01 AND service.name:"DeviceCacheSvc" AND event.id:7040
host.name:WIN-LAB-01 AND process.pid:7460 AND event.id:1
host.name:WIN-LAB-01 AND task.name:"\Microsoft\Windows\Diagnostics\CacheHealth" AND event.id:106
host.name:WIN-LAB-01 AND process.pid:7520 AND event.id:1
host.name:WIN-LAB-01 AND listener.local_port:8448 AND event.id:5154
event.id:4104 AND CacheHealth
```

## Noise and malicious context

- 15,000 routine events and 14 planted lookalikes. The five findings share seven distinct required records because each 4104 script block links more than one stage.
- 09:39:27: same service, but Automatic → Disabled rather than Manual → Automatic. A same-name match has the wrong transition.
- 09:39:35: CacheHost.exe has the expected path and parent but the wrong PID. Near 10:08:56, a second near-match has the expected command and PowerShell parent but PID 7521 instead of 7520.
- Around 10:08:52–58, a similar task name, an exact-looking task on the wrong host, and TCP 8448 owned by svchost.exe compete with the real task and listener. Verify host, full object, action, PID, and parent.
- Defender 5007, Sysmon 11, and Sysmon 3 follow the listener setup. They record defense evasion, archive creation, and an outbound attempt to a reserved test address; they do not establish receipt by a remote server.

## How the evidence maps together

A → B: CSG records DeviceCacheSvc Manual → Automatic; 7040 confirms direction and Sysmon 1 identifies service image PID 7460. Stage-A 4104 records config/start. B → C: child PowerShell PID 7480 creates CacheHealth (106 confirms its action) and launches listener PID 7520 (Sysmon 1); 5154 confirms TCP 8448 was permitted. Shared ancestry joins both stages. Events 5007 and Sysmon 11/3 show Defender disablement, archive creation, and an outbound attempt. Reject decoys sharing only name, path, port, or time; no server receipt is shown.

*Instructor answer reference • For A–E identifiers and exact CSG-to-Wazuh searches, see variant-answer-key.md.*


<div style="page-break-before: always;"></div>


# Final Investigation

**Instructor-only · Variant A example · WIN-LAB-01 · 26 September 2026 · all times UTC · 15,025 events**

Snapshot A 09:30; Snapshot B 10:00. Wazuh archive 09:00–12:00; the UI displays browser-local time.

## What happened

CSG records RemoteAssistSvc switching to Automatic (09:37:12), TelemetryStage.exe starting (09:37:25), its listener opening (09:37:29), a task appearing (09:37:45), and a Run value being set (09:38:01). The process exits at 09:39:01, the listener closes at 09:39:05, and the service returns to Manual at 09:39:15. The task and Run value persist in Snapshot B.

## Answers and matching evidence

| Item / finding | Collect | Decisive match or gap |
| --- | --- | --- |
| Service / Consistent | Two SCM 7040 | RemoteAssistSvc; both opposite start-type transitions. |
| Process / Consistent | Sysmon 1 + 5 | TelemetryStage.exe, PID 5160, image path, parent services.exe / PPID 680. |
| Listener / Partially explained | Security 5154; trace child Sysmon 1 → PowerShell 4104 for threat context | 0.0.0.0:4443, TCP, PID 5160 and image; the PowerShell child has parent PID 5160; no matching close event. |
| Task / Partially explained | PowerShell 4104 naming the exact task and action | CSG records task creation/persistence, and the malicious script requests the same name/action. No valid host/task/action registration event 106 is present. |
| Run value / Consistent | Sysmon 13 plus PowerShell 4104 | 09:38:01; exact DeviceHealthStage value and data in both records; Sysmon 13 directly confirms the write. |

## Clues linking the objects

The shared image is C:\ProgramData\CsgLab\Stage\TelemetryStage.exe. The task \Microsoft\Windows\DeviceHealth\InventoryRefresh and HKLM\Software\Microsoft\Windows\CurrentVersion\Run\DeviceHealthStage both invoke it with --stage. The listener uses PID 5160. In raw Sysmon 13, check targetObject, details, image, and processId. The record uses a sanitized reference structure with fictional values.

## Noise and distractors

- 15,000 routine records, 14 deliberate decoys, and 7 distinct full-credit records (the 4104 context record is collected for both persistence findings).
- 09:37:08: RemoteAssistSvcHelper; 09:37:23: PID 5161; 09:37:28: the same port owned by svchost.exe/PID 5161. Reject identity mismatches.
- 09:37:40: InventoryRefresh-Telemetry; 09:37:42: exact task on WIN-OPS-07. Neither registers the case task on its host.
- 09:38:00: correct Run value with .exe.old data; 09:38:03: a Run write on WIN-OPS-07. Check the complete data, arguments, and host.

## How the evidence maps together

CSG records the service cycle, PID process start/exit, and listener open/close; task and Run value persist in B. 7040 and Sysmon 1/5 confirm service/process; 5154 confirms PID 5160 was permitted to listen on TCP 4443, but no close or inbound-session event exists. Sysmon 13 confirms the Run write. Child PowerShell 4104 (parent PID 5160) names the exact task/action and Run data alongside malicious commands. No Scheduler 106: the task is Partially explained. Sysmon 11/3 show archive creation and an outbound attempt, not receipt.

## Full-credit explanation

Collect 2/2/1/1/2 records for the five items above (the same 4104 record links both persistence findings). Explain the shared paths/PIDs and the missing task-registration and listener-close events. Event 5154 supports listening, not an inbound session. Start-type changes alone do not prove a service start, and persistence does not prove later execution.

*Instructor answer reference • For A–E identifiers and exact CSG-to-Wazuh searches, see variant-answer-key.md.*
