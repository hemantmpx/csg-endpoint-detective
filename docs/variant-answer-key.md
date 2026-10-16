# Variant Answer Key — CSG Clues to Wazuh Evidence

**Instructor-only. Do not share this key with students before the exercise.** It covers all five assigned versions (A–E) of each case. Version A is not the answer for every student: first check the variant and host shown in that student's case header, then use the matching row below.

The answer classifications and evidence rules are the same across versions. Hosts, service names, executable names, task paths, PIDs, and ports change. Replace the uppercase placeholders in a query with values from the student's row. Times in this key are UTC; the UI displays browser-local time.

## How to work from CSG into Wazuh

1. **Start with CSG.** Record the host, object name, snapshot pair or timeline interval, and the exact fields that changed. For a process, task, listener, or registry value, also note its path, PID, action, port, or value data when shown.
2. **Search Wazuh by identity and event meaning.** Scope to the assigned host, then search the object and event ID. A nearby timestamp is only a lead. Verify the event describes the same object and operation, and check its before/after values.
3. **Trace the threat link.** Inspect PowerShell 4104 and related process events. Match the exact script target, image path, parent PID, and command line. Defender 5007, Sysmon 11, and Sysmon 3 add context for defense evasion, archive creation, and outbound activity.
4. **State the limit.** A script-block record shows recorded command content; by itself it does not prove every command succeeded. A permitted listener or outbound connection does not prove an inbound session or that a remote server received data.

`host.name`, `event.id`, `service.name`, `service.old_start_mode`, `service.new_start_mode`, `process.pid`, `task.name`, `task.action`, `listener.local_port`, and `registry.value_name` are searchable fields in this lab.

---

## Case 1 — The Expected Service

### Version-specific CSG clue

In **Snapshot Delta**, look for a service absent in A and present in B. Its ending state is Automatic and Running under LocalSystem. Check the exact `binary_path`; it is the bridge from CSG's service record to the Windows installation and process events.

| Version | Host | Service in the CSG delta | Expected executable path | Answer |
|---|---|---|---|---|
| A | `WIN-LAB-01` | `BackupAgent` | `C:\Program Files\BackupAgent\agent.exe` | **CONSISTENT** |
| B | `WIN-LAB-02` | `UpdateBridge` | `C:\Program Files\UpdateBridge\agent.exe` | **CONSISTENT** |
| C | `WIN-LAB-03` | `MonitorRelay` | `C:\Program Files\MonitorRelay\agent.exe` | **CONSISTENT** |
| D | `WIN-LAB-04` | `PatchCoordinator` | `C:\Program Files\PatchCoordinator\agent.exe` | **CONSISTENT** |
| E | `WIN-LAB-05` | `TelemetryHelper` | `C:\Program Files\TelemetryHelper\agent.exe` | **CONSISTENT** |

### Answer for every version: **CONSISTENT**

Search for the exact service installation, then its script context:

```text
host.name:HOST AND event.id:7045
host.name:HOST AND service.name:"SERVICE" AND event.id:7045
host.name:HOST AND event.id:4104 AND SERVICE
```

The exact-service 7045 search returns six rows on the assigned host. One falls within the CSG snapshot interval and records the CSG `agent.exe` path. Five benign-context records use a routine-looking service-specific executable path at five distinct times after Snapshot B. Compare each timestamp and `ImagePath`, then collect the in-window 7045 and correlated 4104 PowerShell script block. Sysmon process creation shows the CSG binary running and launching PowerShell; 4104 names that service in a persistence command and records malicious follow-on actions, including Defender disablement and data staging. The filename `agent.exe` is not enough to judge intent; use process ancestry and script contents. A 7040 record is a start-type change, and 7036 is a runtime-state change; neither establishes service creation. Outbound activity is an attempt, not proof of receipt.

**Full-credit explanation:** “CSG shows `<SERVICE>` absent in Snapshot A and present in B on `<HOST>`, with this binary path: `<PATH>`. Same-host 7045 confirms that service installation. The matching process image and its child PowerShell 4104 link the service to the persistence command and malicious activity. The installation is Consistent; network evidence does not prove a successful transfer.”

---

## Case 2 — The Overnight Change

### CSG pivot and answers by version

In **Snapshot Delta**, the service changes from **Manual → Automatic** while runtime status remains Running. Expand the delta to read the full identity and executable path. Each variant uses `C:\Program Files\<SERVICE>\agent.exe`; the path remains unchanged across the snapshots and is a useful Wazuh process pivot.

| Variant | Host | Exact service | Service image PID | Child PowerShell PID | Answer |
|---|---|---|---:|---:|---|
| A | `WIN-LAB-01` | `UpdateHelper` | 4160 | 4180 | **PARTIALLY_EXPLAINED** |
| B | `WIN-LAB-02` | `CloudSyncBridge` | 4260 | 4280 | **PARTIALLY_EXPLAINED** |
| C | `WIN-LAB-03` | `InventoryAgent` | 4360 | 4380 | **PARTIALLY_EXPLAINED** |
| D | `WIN-LAB-04` | `PatchCoordinator` | 4460 | 4480 | **PARTIALLY_EXPLAINED** |
| E | `WIN-LAB-05` | `OpsTelemetry` | 4560 | 4580 | **PARTIALLY_EXPLAINED** |

### Full-credit investigation path

1. **Record the CSG facts.** Note the assigned host, exact service name, Manual → Automatic start-type change, unchanged Running status, interval, and executable path.
2. **Check the native configuration event.** In the same host and interval, search for the exact service and Windows event 7040:

   ```text
   host.name:HOST AND service.name:"SERVICE" AND event.id:7040
   ```

   There is no same-host 7040 for the target service in any version. Treat that as a gap in this archive, not proof nothing happened.
3. **Pivot on the CSG executable path.** Search the exact path for a process-start record. Open it and note the PID:

   ```text
   host.name:HOST AND process.executable_path:"C:\Program Files\SERVICE\agent.exe" AND event.id:1
   ```
4. **Follow the parent-child relationship.** Find the child process whose parent PID is the service PID, then search its PID for PowerShell event 4104:

   ```text
   host.name:HOST AND process.parent_pid:"SERVICE_PID" AND event.id:1
   host.name:HOST AND process.pid:"POWERSHELL_PID" AND event.id:4104
   ```

   Read the whole script block in order. It records a stop of `CsgTelemetryForwarder`, a request to set the CSG service to automatic, and a restart of the forwarder, followed by Defender disablement, document staging, and an outbound transfer attempt.
5. **Corroborate the collection window and follow-on activity.** Find the two exact-service 7036 events for `CsgTelemetryForwarder` (Stopped, then Running). Then inspect event 5007 and Sysmon 11 and 3 for Defender change, archive creation, and outbound connection attempt.

For Variant E, the CSG interval is 04:30–05:00 in Chicago on 26 September 2026 (09:30–10:00 UTC). A broad text search for `OpsTelemetry` with runtime-state events returns 11 `OpsTelemetrySvc` lookalikes. Those 7036 records describe Running/Stopped status for a different service; they are not eleven startup-setting changes. Use the exact query `service.name:"OpsTelemetry"` to exclude the longer name. The matching 7040 query still returns no target-service event.

### Noise to reject

- The `OpsTelemetrySvc` (or variant-specific `<SERVICE>Svc`) 7036 records are similar-name runtime events, not the CSG start-type change.
- A 7040 for the exact service on `WIN-OPS-07` has the right direction but the wrong host.
- A nearby 7040 for `<SERVICE>Svc` reports Automatic → Disabled, the wrong object and direction.
- A separate 4104 runs `Get-Service` and `sc.exe qc <SERVICE>`; it only queries configuration. The malicious 4104 is distinguished by its ordered stop/configure/start commands and later activity.

### Model answer

“CSG shows `<SERVICE>` changing from Manual to Automatic on `<HOST>` and provides the service image path. I found the matching service process by path, followed its child PID to PowerShell event 4104, and read the script’s ordered commands. Two 7036 records show the telemetry forwarder stopped and restarted; later Defender, file, and network events show malicious follow-on activity. The target service’s 7040 record is absent, so the evidence supports a likely connection and collection gap but does not prove that the configuration command succeeded or caused the observed state. Classification: **PARTIALLY_EXPLAINED**.”

---

## Case 3 — Between the Snapshots

### Version-specific CSG clues

The **CSG State Change Timeline** shows a service changing to Automatic and back to Manual, and a process starting and exiting between the snapshots. **Snapshot Delta** shows the scheduled task that remains. Use the task's complete path and action, and the process PID and image path, to pivot into Wazuh.

| Version | Host | Service | Process / PID | Scheduled task | Answers (service / process / task) |
|---|---|---|---|---|---|
| A | `WIN-LAB-01` | `DeviceHealthSvc` | `DeviceHealthCheck.exe` / `4160` | `\Microsoft\Windows\DeviceHealth\CacheRefresh` | **CONSISTENT / CONSISTENT / CONSISTENT** |
| B | `WIN-LAB-02` | `InventoryTelemetry` | `InventoryStage.exe` / `4260` | `\Microsoft\Windows\Inventory\CacheRefresh` | **CONSISTENT / CONSISTENT / CONSISTENT** |
| C | `WIN-LAB-03` | `MetricsRelaySvc` | `MetricsStage.exe` / `4360` | `\Microsoft\Windows\Metrics\CacheRefresh` | **CONSISTENT / CONSISTENT / CONSISTENT** |
| D | `WIN-LAB-04` | `PolicyBrokerSvc` | `PolicyStage.exe` / `4460` | `\Microsoft\Windows\Policy\CacheRefresh` | **CONSISTENT / CONSISTENT / CONSISTENT** |
| E | `WIN-LAB-05` | `EndpointHealthSvc` | `EndpointStage.exe` / `4560` | `\Microsoft\Windows\Endpoint\CacheRefresh` | **CONSISTENT / CONSISTENT / CONSISTENT** |

The binary path for each process is `C:\ProgramData\CsgLab\Stage\<PROCESS>`. The action stored in the CSG task is that path followed by `--inventory`. Across all versions, the timeline sequence is service Automatic at 09:37:12, process start at 09:37:25, task creation at 09:38:10, process exit at 09:39:00, and service Manual again at 09:39:15.

### Answers for every version

| Investigation item | Answer | Wazuh evidence to collect | Why it matches the CSG clue |
|---|---|---|---|
| Service cycle | **CONSISTENT** | Both SCM **7040** records | Same host/service and both directions: Manual → Automatic, then Automatic → Manual. |
| Process lifecycle | **CONSISTENT** | Sysmon **1** and **5** | Same host, PID, image path, and parent; these confirm start and exit between captures. |
| Persistent task | **CONSISTENT** | Task Scheduler **106** and PowerShell **4104** | Both identify the exact task path and `--inventory` action; the task remains in the ending inventory. |

Search using the identifiers from the student's row:

```text
host.name:HOST AND service.name:"SERVICE" AND event.id:7040
host.name:HOST AND process.pid:PID AND event.id:1
host.name:HOST AND process.pid:PID AND event.id:5
host.name:HOST AND task.name:"TASK" AND event.id:106
host.name:HOST AND event.id:4104 AND CacheRefresh
```

To explain why this is a security case, open the 4104 record and match its process parent to the CSG process/PID chain. It requests the same task/action and includes Defender-disable and staging commands; **5007** and Sysmon **11/3** corroborate those actions. The service and process are transient, so their absence from Snapshot B does not contradict the timeline. The task persists. The outbound event indicates an attempt, not confirmed receipt.

**Full-credit explanation:** “CSG records `<SERVICE>` changing to Automatic and back, and `<PROCESS>` PID `<PID>` starting and exiting between captures. Two 7040s and Sysmon 1/5 match those exact transitions and process identity. The task `<TASK>` persists; 106 and 4104 match its full path and action. The linked script contains malicious commands, tying the transient activity to the persistent task.”

---

## Case 4 — The Relay Takes Hold

### Version-specific CSG clues

Work through the three snapshots in order. For **A → B**, the service changes Manual → Automatic and its configured image appears as a process. For **B → C**, CSG records a new hidden task, a second process instance, and a listener. The task action, second process command line, and listener should all identify the same port and image.

| Version | Host | Service | Process / service PID | Child PowerShell PID | Task | Listener PID / TCP port | Answers (five items) |
|---|---|---|---|---|---|---|---|
| A | `WIN-LAB-01` | `DeviceCacheSvc` | `CacheHost.exe` / `7460` | `7480` | `\Microsoft\Windows\Diagnostics\CacheHealth` | `7520` / `8448` | **All five: CONSISTENT** |
| B | `WIN-LAB-02` | `InventoryCacheSvc` | `InventoryHost.exe` / `7560` | `7580` | `\Microsoft\Windows\Inventory\CacheHealth` | `7620` / `8449` | **All five: CONSISTENT** |
| C | `WIN-LAB-03` | `MetricsCacheSvc` | `MetricsHost.exe` / `7660` | `7680` | `\Microsoft\Windows\Metrics\CacheHealth` | `7720` / `8450` | **All five: CONSISTENT** |
| D | `WIN-LAB-04` | `PolicyCacheSvc` | `PolicyHost.exe` / `7760` | `7780` | `\Microsoft\Windows\Policy\CacheHealth` | `7820` / `8451` | **All five: CONSISTENT** |
| E | `WIN-LAB-05` | `EndpointCacheSvc` | `EndpointHost.exe` / `7860` | `7880` | `\Microsoft\Windows\Endpoint\CacheHealth` | `7920` / `8452` | **All five: CONSISTENT** |

The shared service/process image is `C:\ProgramData\CsgLab\Stage\<PROCESS>`. The task action is that image followed by `--serve <PORT>`. The first CSG service transition is at 09:39:22; the service image starts at 09:39:30. In B → C, the task appears at 10:08:53, the listener process at 10:08:55, and the listener at 10:08:57.

### Answers for every version: all five items are **CONSISTENT**

| Investigation item | Wazuh evidence to collect | How the CSG clue maps to Wazuh |
|---|---|---|
| Service start type · A → B | **7040**, Sysmon **1**, stage-A PowerShell **4104** | 7040 confirms Manual → Automatic; Sysmon 1's image/PID matches the configured service binary; 4104 records the service configuration/start commands. |
| Service image process · A → B | Sysmon **1**, stage-B PowerShell **4104** | Sysmon confirms the service process PID/path and `services.exe` parent; stage-B 4104's parent PID links the next stage to it. |
| Startup task · B → C | Task Scheduler **106**, stage-B **4104** | Exact task path and `--serve <PORT>` action match CSG's task record and the script request. |
| Listener process · B → C | Sysmon **1**, stage-B **4104** | Exact listener PID, path, command line, and PowerShell parent match the second process and task action. |
| Listener opened · B → C | Security **5154**, stage-B **4104** | Exact host, process PID/image, TCP port, and address match CSG. Event 5154 says Windows permitted the process to listen. |

Useful searches, filled from the row above:

```text
host.name:HOST AND service.name:"SERVICE" AND event.id:7040
host.name:HOST AND process.pid:SERVICE_PID AND event.id:1
host.name:HOST AND event.id:4104 AND SERVICE
host.name:HOST AND task.name:"TASK" AND event.id:106
host.name:HOST AND process.pid:LISTENER_PID AND event.id:1
host.name:HOST AND listener.local_port:PORT AND event.id:5154
host.name:HOST AND event.id:4104 AND CacheHealth
```

Follow the process ancestry: service PID → child PowerShell PID → listener PID. Confirm the full task path and its action. Reject records that only share a service name, executable path, task substring, port, or nearby time. Defender **5007**, Sysmon **11**, and Sysmon **3** show defense evasion, archive creation, and an outbound attempt; no remote receipt is established.

**Full-credit explanation:** “CSG's A→B delta and timeline identify `<SERVICE>`, its `<PROCESS>` image, and PID `<SERVICE_PID>`. 7040, Sysmon 1, and stage-A 4104 support that transition. In B→C, task `<TASK>` launches the same image with `--serve <PORT>`; event 106, Sysmon 1 for PID `<LISTENER_PID>`, and 5154 match its task, process, and listener. The child PID links both intervals into one incident.”

---

## Final Investigation — Transient Compromise with Persistent Foothold

### Version-specific CSG clues

The timeline shows a service change and reversion, process start and exit, listener open and close, then a scheduled task and Run value that remain in Snapshot B. The **Snapshot Delta** identifies the durable task and registry value. Use the service/process image path and PID to connect those durable artifacts to the transient activity.

| Version | Host | Service | Process / PID | Task | Run value | Listener port | Answers (service / process / listener / task / Run value) |
|---|---|---|---|---|---|---|---|
| A | `WIN-LAB-01` | `RemoteAssistSvc` | `TelemetryStage.exe` / `5160` | `\Microsoft\Windows\DeviceHealth\InventoryRefresh` | `DeviceHealthStage` | `4443` | **CONSISTENT / CONSISTENT / PARTIALLY EXPLAINED / PARTIALLY EXPLAINED / CONSISTENT** |
| B | `WIN-LAB-02` | `InventoryBrokerSvc` | `InventoryStage.exe` / `5260` | `\Microsoft\Windows\Inventory\InventoryRefresh` | `InventoryStage` | `4444` | **CONSISTENT / CONSISTENT / PARTIALLY EXPLAINED / PARTIALLY EXPLAINED / CONSISTENT** |
| C | `WIN-LAB-03` | `MetricsSupportSvc` | `MetricsStage.exe` / `5360` | `\Microsoft\Windows\Metrics\InventoryRefresh` | `MetricsStage` | `4445` | **CONSISTENT / CONSISTENT / PARTIALLY EXPLAINED / PARTIALLY EXPLAINED / CONSISTENT** |
| D | `WIN-LAB-04` | `PolicyCacheSvc` | `PolicyStage.exe` / `5460` | `\Microsoft\Windows\Policy\InventoryRefresh` | `PolicyStage` | `4446` | **CONSISTENT / CONSISTENT / PARTIALLY EXPLAINED / PARTIALLY EXPLAINED / CONSISTENT** |
| E | `WIN-LAB-05` | `EndpointAssistSvc` | `EndpointStage.exe` / `5560` | `\Microsoft\Windows\Endpoint\InventoryRefresh` | `EndpointStage` | `4447` | **CONSISTENT / CONSISTENT / PARTIALLY EXPLAINED / PARTIALLY EXPLAINED / CONSISTENT** |

For every row, the executable is `C:\ProgramData\CsgLab\Stage\<PROCESS>`. The Run value is under `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` and its data invokes that executable with `--stage`. Timeline times are the same in all versions: service Automatic 09:37:12; process start 09:37:25; listener open 09:37:29; task create 09:37:45; Run value create 09:38:01; process exit 09:39:01; listener close 09:39:05; service Manual 09:39:15.

### Answers for every version

| Investigation item | Answer | Wazuh evidence to collect | How it maps to CSG / why this rating |
|---|---|---|---|
| Temporary service cycle | **CONSISTENT** | Two **7040** events | Exact service and Manual → Automatic → Manual sequence. It returns to its original mode, so no persistent service delta remains. |
| Short-lived process | **CONSISTENT** | Sysmon **1** and **5** | Exact PID, process image, path, host, and parent match CSG's start and exit. It is absent from both boundary snapshots because it ended. |
| Temporary listener | **PARTIALLY EXPLAINED** | One **5154** event | Exact port/PID/image confirms Windows permitted listening and supports CSG's open transition. There is no corresponding Wazuh close record, so the entire lifecycle is not corroborated. No inbound session is established. |
| Persistent scheduled task | **PARTIALLY EXPLAINED** | PowerShell **4104** naming the exact task and action | CSG confirms task creation and persistence; the malicious script requests the same task/action. No matching Task Scheduler **106** confirms registration, so this is a strong link with a telemetry gap. |
| Persistent Run value | **CONSISTENT** | Sysmon **13** plus PowerShell **4104** | Sysmon 13 confirms the exact value/data write; 4104 names the same value/data in the malicious child process. |

Search from the exact values in the variant row:

```text
host.name:HOST AND service.name:"SERVICE" AND event.id:7040
host.name:HOST AND process.pid:PID AND event.id:1
host.name:HOST AND process.pid:PID AND event.id:5
host.name:HOST AND listener.local_port:PORT AND event.id:5154
host.name:HOST AND task.name:"TASK" AND event.id:106
host.name:HOST AND event.id:4104 AND InventoryRefresh
host.name:HOST AND registry.value_name:"RUN_VALUE" AND event.id:13
```

For the task query, an empty 106 result is expected. Do not treat that absence as proof the task is safe or as proof the script successfully registered it. Read the 4104 command and compare its complete task path/action to CSG. For the Run value, compare the complete value name and data in CSG, Sysmon 13, and 4104. The same 4104 process is a child of the listener-owning image PID; this links the service, listener, and persistence sequence. Sysmon 11/3 show archive creation and an outbound attempt, not receipt.

**Full-credit explanation:** “CSG shows `<SERVICE>` changing and reverting, PID `<PID>` starting and exiting, and port `<PORT>` opening and closing. Wazuh confirms the service and process, but only supports the listener opening, so classify that item Partially explained. The task persists and its exact action appears in 4104, but 106 is missing, so it is also Partially explained. Sysmon 13 plus 4104 confirm the exact Run value and malicious command. The findings connect through the same executable and process ancestry.”

---

## Instructor notes on answer consistency

These ratings match the private per-variant answer keys in each scenario package. The direct evidence count per item is the same for A–E; only the identifiers in the tables change. When a student has a different variant, score the object and host they actually received, not the Variant A example in [case technical explanations](case-technical-explanations.md). The interactive lab keeps these answer keys server-side; this instructor document is the readable teaching reference.
