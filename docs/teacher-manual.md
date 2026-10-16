# Teacher’s manual and answer key

**Instructor-only material.** Do not distribute this file as a student handout. Variant-specific answers and evidence IDs also live in the backend-only `answer-key.private.json` files.

**Instructor references:** [One-page technical explanations](case-technical-explanations.md) · [A–E variant answer key with CSG-to-Wazuh clues](variant-answer-key.md) · [Word document](case-technical-explanations.docx).

## Lab model

The lab teaches three independent evidence layers:

1. **Snapshots and Snapshot Delta:** Cases may use two or three ordered captures. A Snapshot Delta compares adjacent captures (A→B or B→C) and describes what changed across that interval.
2. **CSG State Change Timeline:** CSG separately records selected activity between captures. A process can be created and terminate, a listener can open and close, or a service start type can change and return while two captures agree.
3. **Wazuh / Windows telemetry:** Archived event records form an independent source. They can support all, part, or none of a CSG observation. Wazuh does not produce the CSG record.

The CSG State Change Timeline is not generated from Wazuh events, but the two sources can describe the same incident. In each case, event 4104 exposes PowerShell commands; Sysmon process records provide the parent/child PID and image paths; event 5007 records Defender real-time protection being disabled; Sysmon 11 records an archive; and Sysmon 3 records an outbound connection. Match service names, task names/actions, Run value data, image paths, host, and time to the CSG findings. This lets students connect attacker intent and execution to observed state, including changes whose native Windows event is missing. A script block shows requested commands, not that each command succeeded. The archive and connection show attempted transfer; no server-side record proves receipt.

## Scoring and full-credit standard

Each investigation item is scored out of 100: 50 for the expected classification, 40 for the evidence rule, and 10 for a valid explanation of at least 20 characters. Some items require both a direct state event and a correlated 4104 threat-context event; students should explain that the 4104 links intent but does not independently prove the state change. Case 2 and the Final task item are `PARTIALLY_EXPLAINED`: CSG state, process ancestry, and script content support a connection, but the corresponding native change/registration event is absent. Selecting a prohibited distractor costs the evidence points. Cases 1 and 2 have one item each, Case 3 has three, Case 4 has five, and the Final Investigation has five.

The platform checks explanation length, not the quality of the reasoning. The instructor CSV includes each item ID and submitted explanation for content review. For full instructional credit, require the written answer to name the host and object, explain the operation or before/after values, place it within the snapshot window, and connect the suspicious process or script to the CSG finding using the exact path, PID, task, service, or value. Students must also state what remains unproven when the native event is absent. In the Final Investigation, have them connect service binary path → process image/parent → listener PID/path → child PowerShell → task action and Run value data. Event 4104 supplies the malicious commands; event 106 and Sysmon 13 independently support the task and Run value respectively, while the task registration event is deliberately absent.

## Before class

1. Start the lab and choose **Guided** mode for ordered unlocks or **Challenge** mode for open access to enabled cases.
2. In the instructor console, confirm the class is active and Cases 1–4 and the Final Investigation are enabled.
3. Share the URL and class code. Students may use a display name or anonymous mode.
4. Each session receives one of five variants. Confirm the host in the case header before helping a student search. Variant-specific object names are listed below.

| Variant | Host | Case 1 service | Case 2 service | Case 3 service / process / task | Case 4 service / process / task / port | Final service / process / task / Run value / port |
|---|---|---|---|---|---|---|
| A | `WIN-LAB-01` | `BackupAgent` | `UpdateHelper` | `DeviceHealthSvc` / `DeviceHealthCheck.exe` / `\Microsoft\Windows\DeviceHealth\CacheRefresh` | `DeviceCacheSvc` / `CacheHost.exe` / `\Microsoft\Windows\Diagnostics\CacheHealth` / 8448 | `RemoteAssistSvc` / `TelemetryStage.exe` / `\Microsoft\Windows\DeviceHealth\InventoryRefresh` / `DeviceHealthStage` / 4443 |
| B | `WIN-LAB-02` | `UpdateBridge` | `CloudSyncBridge` | `InventoryTelemetry` / `InventoryStage.exe` / `\Microsoft\Windows\Inventory\CacheRefresh` | `InventoryCacheSvc` / `InventoryHost.exe` / `\Microsoft\Windows\Inventory\CacheHealth` / 8449 | `InventoryBrokerSvc` / `InventoryStage.exe` / `\Microsoft\Windows\Inventory\InventoryRefresh` / `InventoryStage` / 4444 |
| C | `WIN-LAB-03` | `MonitorRelay` | `InventoryAgent` | `MetricsRelaySvc` / `MetricsStage.exe` / `\Microsoft\Windows\Metrics\CacheRefresh` | `MetricsCacheSvc` / `MetricsHost.exe` / `\Microsoft\Windows\Metrics\CacheHealth` / 8450 | `MetricsSupportSvc` / `MetricsStage.exe` / `\Microsoft\Windows\Metrics\InventoryRefresh` / `MetricsStage` / 4445 |
| D | `WIN-LAB-04` | `PatchCoordinator` | `PatchCoordinator` | `PolicyBrokerSvc` / `PolicyStage.exe` / `\Microsoft\Windows\Policy\CacheRefresh` | `PolicyCacheSvc` / `PolicyHost.exe` / `\Microsoft\Windows\Policy\CacheHealth` / 8451 | `PolicyCacheSvc` / `PolicyStage.exe` / `\Microsoft\Windows\Policy\InventoryRefresh` / `PolicyStage` / 4446 |
| E | `WIN-LAB-05` | `TelemetryHelper` | `OpsTelemetry` | `EndpointHealthSvc` / `EndpointStage.exe` / `\Microsoft\Windows\Endpoint\CacheRefresh` | `EndpointCacheSvc` / `EndpointHost.exe` / `\Microsoft\Windows\Endpoint\CacheHealth` / 8452 | `EndpointAssistSvc` / `EndpointStage.exe` / `\Microsoft\Windows\Endpoint\InventoryRefresh` / `EndpointStage` / 4447 |

All variants use the same logical incident sequence and the same redacted classroom executable root: `C:\ProgramData\CsgLab\Stage\<process-name>`.

## Student workflow by stage

### Stage 1 — Briefing

Students read the objective, endpoint, and observation window. Have them say what question they are answering: what persisted at each capture, what changed across each adjacent pair, what CSG observed between captures, and what the independent Wazuh source supports.

### Stage 2 — CSG State

1. Open **CSG State** and check the host, snapshot times, counts, and collector health.
2. Select each snapshot and search its inventory for the target object. Expand a matching inventory record to inspect all recorded attributes. A three-capture case has a middle state; compare A→B before moving to B→C.
3. Expand each **Snapshot Delta** card. Confirm its named interval, full before/after fields, and any linked CSG observations before you move to Wazuh.
4. Read the **CSG State Change Timeline** as a separate CSG source. Follow timestamps and object-specific fields. Matching adjacent snapshots do not establish that nothing happened between captures.
5. For the final scenario, record the executable path and PID relationships linking the service, process, listener, task, and registry value.

### Stage 3 — Wazuh Events

Start with the full case archive window and narrow by host, event code/type, object identity, and transition fields. Confirm that any candidate also falls inside the relevant observation interval. The corpus contains more than 15,000 events per case and variant, including same-window lookalikes, similar names, incompatible values, and wrong-host records.

The search supports `field:value`, quoted phrases, `AND`, `OR`, and free text. Useful fields include `host.name`, `event.id`, `event.type`, `service.name`, `service.old_start_mode`, `service.new_start_mode`, `process.name`, `process.pid`, `process.executable_path`, `task.name`, `task.action`, `listener.local_port`, `listener.process_name`, `registry.key`, and `registry.value_name`. Event details show record provenance; the marked Sysmon 13 example preserves a sanitized raw field structure while using fictional values.

#### Live search and time-range controls

Typing in the event search field refreshes results after a 350 ms debounce; Enter applies the query immediately. Event category, event type, Windows Event ID, host, provider, and time controls combine with the text query. The Active Filters row above the results shows the effective search. The clear action removes the text and structured filters and resets the time to the full case window.

The From and To fields accept a custom date/time range. Presets count back from the archived case-window end, not the instructor’s current clock. The event-volume chart represents the same range: a click selects one minute and a drag selects a span; either updates the fields and refreshes results. Editing the fields highlights that range in the chart. Browser controls display local time; the case reference timestamps in this manual are UTC.

After checking the direct event candidate, search event 4104 and inspect the full script. Then follow the PowerShell process and parent PIDs through Sysmon, comparing the exact command target and executable with CSG. This is how students connect malicious intent to state findings when a native event is absent. For each candidate, ask:

1. Is the endpoint host exact?
2. Is the object identity exact, including PID, path, task name, registry value, or port where relevant?
3. Could this event type represent the CSG operation?
4. Do the before/after values agree?
5. Is the event inside the observation interval?

Time proximity only identifies candidates. Open details or raw JSON and check the fields. Add only supported Wazuh records to the tray for the currently selected investigation item. CSG State Change Timeline entries are CSG evidence; they are not Wazuh event selections.

### Stage 4 — Reconcile

Select each named investigation item, choose the classification, and explain the direct match, threat link, and any evidence gap. For full instructional credit, require students to explain object identity and transition semantics, not just a timestamp. Case 2 and the Final task require a partial classification because a script command and CSG state align while the native change/registration record is absent. Other items may require both a direct Windows event and correlated 4104 context.

### Stage 5 — Final debrief

After all case items are submitted, ask students to reconstruct the linked incident in order. A strong account distinguishes what persisted at each capture from activity that ended or returned. In Case 4, it carries the exact service path from A→B into B→C, then links the task action and listener PID to that same image and process ancestry. In the Final Investigation, it follows the service image to the process and child PowerShell, matches the exact task and Run value commands, and states which changes Wazuh directly confirms. The missing Final task-registration record weakens telemetry coverage but does not erase CSG’s observed persistence or the script’s link to that task.

## Answer key at a glance

Times below are UTC. The browser displays local time, so students should compare times within the same browser. Case 4 captures A at 09:30Z, B at 10:00Z, and C at 10:30Z. Cases 3 and Final capture A at 09:30Z and B at 10:00Z. The broader event search spans 09:00Z–12:00Z.

| Case / item | Classification | Full-credit Wazuh selection | CSG finding and decisive checks |
|---|---|---|---|
| 1 · Expected service addition | `CONSISTENT` | One 7045 `service_created` record plus PowerShell 4104 naming the same service. | Service absent in A and present in B. Event 7045 directly corroborates installation; shared image path and linked child process show why this service is malicious. |
| 2 · The Overnight Change | `PARTIALLY_EXPLAINED` | Use the CSG executable path to find the service process, follow its child PID to PowerShell 4104, and collect both same-host 7036 forwarder records. Cite later 5007 / Sysmon 11 / 3 as malicious follow-on context. | CSG confirms Manual → Automatic. The script and service-state records support a collection gap, but the target-service 7040 is absent. Do not claim the configuration command is proven to have executed. |
| 3 · Between the Snapshots — service cycle | `CONSISTENT` | Both matching 7040 `service_modified` events. | CSG records a Service start type changed observation from Manual → Automatic at 09:37:12Z and another from Automatic → Manual at 09:39:15Z. Snapshot A and Snapshot B agree because the service start type returned to Manual. |
| 3 · Short-lived process lifecycle | `CONSISTENT` | Sysmon 1 process creation and Sysmon 5 process termination for exact PID, executable, parent, and host. | CSG records Process Create at 09:37:25Z and Process Terminated at 09:39:00Z. The process is absent from both snapshots. |
| 3 · Scheduled task persists | `CONSISTENT` | Task Scheduler 106 for exact host, task, and action; PowerShell 4104 with the same requested task and action. | Task is absent in A, present in B, and CSG records Scheduled Task Registered at 09:38:10Z. The matching script is part of the same malicious child process chain. |
| 4 · Service startup changed · A→B | `CONSISTENT` | 7040 for Manual → Automatic, Sysmon 1 for the service image, and stage-A PowerShell 4104. | CSG records the start-type change at 09:39:22Z. The service path matches the process that appears by B; 4104 requests the change and starts the service. Reject the same-service opposite-direction and same-time service lookalike. |
| 4 · Service image starts · A→B | `CONSISTENT` | Sysmon 1 for exact PID, path, host, and `services.exe` parent; stage-B 4104 for the child process. | The process appears in Snapshot B. Its image matches the service binary; its PID is the parent PID in the later PowerShell start and script records. |
| 4 · Startup task added · B→C | `CONSISTENT` | Task Scheduler 106 for exact task/action plus stage-B PowerShell 4104. | CSG first sees the hidden startup task in C. The script requests the same action; the action uses the service image from A→B. Reject the `-Telemetry` task and wrong-host exact-name record. |
| 4 · Listener process starts · B→C | `CONSISTENT` | Sysmon 1 for exact listener PID/path and PowerShell parent; stage-B 4104. | The task and script launch a second instance of the same image. Its command line matches the task action and its PID owns the listener that follows. |
| 4 · Listener opened · B→C | `CONSISTENT` | Security 5154 for the exact TCP port, listener PID, process image, and host plus stage-B 4104. | CSG and Windows telemetry identify the same listening process. 5154 means Windows permitted the application to listen; it does not prove an inbound session. |
| Final · Temporary service reconfiguration | `CONSISTENT` | Both matching 7040 events. | CSG records a Service start type changed observation from Manual → Automatic at 09:37:12Z and another from Automatic → Manual at 09:39:15Z. There is no Snapshot Delta for the service because its start type returned to Manual. |
| Final · Short-lived process | `CONSISTENT` | Sysmon 1 and Sysmon 5 for exact PID, path, parent, and host. | CSG records Process Create at 09:37:25Z and Process Terminated at 09:39:01Z; absent in both snapshots. Its path matches the service binary. |
| Final · Temporary listener | `PARTIALLY_EXPLAINED` | One event 5154 `network_activity` for exact port, PID, process, and executable. | CSG records Listener Opened at 09:37:29Z and Listener Closed at 09:39:05Z. Windows/Wazuh event 5154 is a native “listen permitted” record that supports the CSG Listener Opened observation. There is no independent close record. |
| Final · Scheduled task persists | `PARTIALLY_EXPLAINED` | PowerShell 4104 with the exact task name and executable action. | CSG records registration at 09:37:45Z and persistence in Snapshot B. The malicious script requests that task/action, but no valid Task Scheduler 106 confirms registration. Reject similar-name and wrong-host lookalikes. |
| Final · Registry persistence | `CONSISTENT` | Sysmon 13 for the exact Run value/data plus PowerShell 4104 requesting the same value/data. | CSG records Registry Value Set at 09:38:01Z and the value persists in B. Sysmon 13 confirms the change; 4104 links the request to the malicious child process. |

## Detailed case notes and suggested searches

### Case 1 — The Expected Service

The service appears in Snapshot B with start type Automatic and runtime status Running. These are separate service fields. Search using the student’s assigned host and service, for example:

```text
host.name:WIN-LAB-01 AND event.id:7045
event.id:7045 AND host.name:WIN-LAB-01 AND service.name:"BackupAgent"
event.id:4104 AND BackupAgent
```

The exact-service 7045 query returns six rows. One is the in-window installation whose `ImagePath` matches CSG; five benign-context records use a routine-looking binary path at five distinct times after Snapshot B. Compare each `ImagePath` and time, then select the in-window 7045 and correlated 4104. The service's `agent.exe` name alone does not establish whether it is benign or malicious: follow the same image through Sysmon process creation to its child PowerShell process, then inspect 4104 for the persistence command, Defender disablement, and data staging. Similar service modifications are not creation evidence.

**Model explanation:** “The service is absent in Snapshot A and present in Snapshot B. Six 7045 rows name BackupAgent on WIN-LAB-01, but only one falls inside the snapshot interval and records the CSG `agent.exe` path. Five benign-context records with a different binary path occur at separate times after Snapshot B. I do not judge `agent.exe` by name alone: Sysmon shows it starting and launching PowerShell, and 4104 records the persistence command, Defender change, and data staging. The installation matches CSG, and its child process/script links it to malicious activity.”

### Case 2 — The Overnight Change

Use the CSG delta as the starting point: collect the host, exact service name, Manual → Automatic transition, unchanged runtime status, and the service executable path. The executable path is unchanged between captures but appears in the Wazuh service-process event. It is the pivot from persistent state to process activity.

For Variant A, the path is `C:\Program Files\UpdateHelper\agent.exe`; substitute the service shown in each student’s variant. The full A–E mapping and version-specific PIDs are in [variant-answer-key.md](variant-answer-key.md).

```text
host.name:WIN-LAB-01 AND service.name:"UpdateHelper" AND event.id:7040
host.name:WIN-LAB-01 AND process.executable_path:"C:\Program Files\UpdateHelper\agent.exe" AND event.id:1
host.name:WIN-LAB-01 AND process.parent_pid:"4160" AND event.id:1
host.name:WIN-LAB-01 AND process.pid:"4180" AND event.id:4104
host.name:WIN-LAB-01 AND service.name:"CsgTelemetryForwarder" AND event.id:7036
```

The exact-service 7040 search returns no matching target event. The path query finds the service image at PID 4160; its child PowerShell process is PID 4180. Event 4104 contains the ordered forwarder stop, service configuration request, and forwarder restart, followed by Defender disablement, archive staging, and an outbound attempt. Event 7036 records the forwarder stopping at 09:51:26Z and returning to Running at 09:51:33Z. Event 5007, Sysmon 11, and Sysmon 3 corroborate the later activity.

Do not misread the 11 results from a free-text `OpsTelemetry` + 7036 search in Variant E: those records name `OpsTelemetrySvc` and describe runtime state, not startup configuration for `OpsTelemetry`. A quoted exact `service.name` query removes that lookalike. Also reject the exact-service 7040 on the wrong host, the similar-name Automatic → Disabled 7040, and the separate read-only `Get-Service` / `sc.exe qc` script.

**Classification:** `PARTIALLY_EXPLAINED`. CSG confirms the resulting state, while the process and script records connect the suspicious command sequence to that service. The forwarder state events support a collection interruption. The absent target-service 7040 means the archive does not confirm that the configuration command succeeded or caused the state change.

### Case 3 — Between the Snapshots

The Snapshot Delta shows one scheduled task registered by Snapshot B. The service and process have no Snapshot Delta, but both have entries in the CSG State Change Timeline. Full credit requires six Wazuh records: two 7040 service records, Sysmon 1 and 5 for the process, Task Scheduler 106 for the task, and PowerShell 4104 with the same task name and executable action.

Example queries for Variant A:

```text
host.name:WIN-LAB-01 AND service.name:"DeviceHealthSvc" AND event.id:7040
host.name:WIN-LAB-01 AND process.pid:4160 AND event.id:1
host.name:WIN-LAB-01 AND process.pid:4160 AND event.id:5
host.name:WIN-LAB-01 AND task.name:"\Microsoft\Windows\DeviceHealth\CacheRefresh" AND event.id:106
event.id:4104 AND CacheRefresh
```

Check that the service path and process image are `C:\ProgramData\CsgLab\Stage\DeviceHealthCheck.exe`, and that the task action invokes the same image. Reject the near-time process lookalike with a different PID and task lookalike with a different task name.

**Model explanation:** “The service start type returned to Manual, so the snapshots agree, but CSG retained both transitions. CSG also recorded the process lifecycle and a task that persists. Wazuh matches both 7040 changes, Sysmon 1/5, and event 106’s task/action. The 4104 script requests that same task while its child process disables Defender and stages the SAM hive, connecting the persisted task to the malicious chain.”

### Case 4 — The Relay Takes Hold

This case has three captures. In A→B, `DeviceCacheSvc` changes Manual→Automatic and `CacheHost.exe` appears. In B→C, `\Microsoft\Windows\Diagnostics\CacheHealth` is registered and a second `CacheHost.exe` process starts to listen on TCP 8448. The same image path connects all three items. The task stores that image with `--serve 8448`; the second process uses the same command and is the PID named by Security 5154.

For Variant A, compare event IDs and exact fields:

```text
host.name:WIN-LAB-01 AND service.name:"DeviceCacheSvc" AND event.id:7040
host.name:WIN-LAB-01 AND process.pid:7460 AND event.id:1
host.name:WIN-LAB-01 AND task.name:"\Microsoft\Windows\Diagnostics\CacheHealth" AND event.id:106
host.name:WIN-LAB-01 AND process.pid:7520 AND event.id:1
host.name:WIN-LAB-01 AND listener.local_port:8448 AND event.id:5154
event.id:4104 AND CacheHealth
```

The first-stage 4104 records the service configuration/start request. The second-stage child PowerShell script creates the exact startup task, launches the second process, disables Defender, stages an archive, and attempts an outbound POST. Check its parent PID (7460) against the service process; then check that the listener process PID (7520) has the PowerShell parent and owns the port. Reject the service’s opposite-direction 7040, wrong-PID process, similar task/action, and same-port listener owned by another process.

**Full-credit reconstruction:** require exact identity and event operation for each delta: service 7040 + Sysmon 1 + stage-A 4104; service process Sysmon 1 + stage-B 4104; task 106 + stage-B 4104; listener process Sysmon 1 + stage-B 4104; listener 5154 + stage-B 4104. Explain how the first delta establishes the image and parent process that the second interval reuses to add persistence and expose a listener.

### Final Investigation — Transient Compromise with Persistent Foothold

The one scenario links five objects through one executable path. The service binary and process image match; the process parent is `services.exe`; the listener uses the process PID and image; the task action and registry value data invoke the same staged image. Students should follow that chain and distinguish it from events that merely occurred nearby.

For Variant A, useful searches are:

```text
host.name:WIN-LAB-01 AND service.name:"RemoteAssistSvc" AND event.id:7040
host.name:WIN-LAB-01 AND process.pid:5160 AND event.id:1
host.name:WIN-LAB-01 AND process.pid:5160 AND event.id:5
host.name:WIN-LAB-01 AND listener.local_port:4443 AND event.id:5154
host.name:WIN-LAB-01 AND task.name:"\Microsoft\Windows\DeviceHealth\InventoryRefresh" AND event.id:106
host.name:WIN-LAB-01 AND registry.value_name:DeviceHealthStage AND event.id:13
event.id:4104 AND DeviceHealthStage
```

Expected findings:

- The two exact service events independently support the CSG Service start type changed observations and restoration.
- Sysmon 1 and 5 corroborate process creation and termination. Confirm PID 5160, parent `services.exe`, and the staged executable path.
- Windows/Wazuh Event 5154 (“listen permitted”) supports CSG’s Listener Opened observation on TCP 4443 for the same PID/process/path. Sysmon 1 records PowerShell PID 5180 with parent PID 5160, linking the listener owner to event 4104’s malicious script. CSG also records Listener Closed, but no independent close event is available; classify the listener `PARTIALLY_EXPLAINED`. Do not infer an inbound session from 5154.
- No event 106 registers the exact task on the case host. Reject the `-Telemetry` task and wrong-host exact-name event. Event 4104 nevertheless requests the exact task/action in the malicious child script; CSG confirms it persisted. Collect 4104 and classify `PARTIALLY_EXPLAINED`, stating that native registration telemetry is missing.
- Sysmon 13 corroborates the exact `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\DeviceHealthStage` value and executable data. Event 4104 requests the same value/data; collect both to link the direct write to the malicious process.
- The service start type is back to Manual; the process and listener are absent; the task and Run value remain in Snapshot B.

**Model incident reconstruction:** “The service start type temporarily changed to Automatic, and the configured image ran as PID 5160. That process owned the listener and spawned PowerShell PID 5180. Its 4104 script requested the exact task and Run value later observed by CSG, disabled Defender, staged an archive, and opened an outbound connection. Sysmon 13 confirms the Run value; CSG confirms the task persisted although Task Scheduler 106 is missing. Event 5154 supports the listener opening but no close record exists. The result is a linked malicious incident with specific telemetry gaps, not an unrelated collection of suspicious events.”

## Instructor discussion prompts

- Which facts come from Snapshot A/B, which come from CSG State Change Timeline, and which come from Wazuh?
- Why can two identical snapshots still coexist with Process Create/Process Terminated observations and service start-type changes that later returned to their earlier value?
- Which identity fields connect the service, process, listener, task, and registry value?
- What can an analyst conclude when the Snapshot Delta and CSG State Change Timeline show state that independent Wazuh telemetry does not support?
- How do same-time and similar-name events become useful search leads without becoming proof?
