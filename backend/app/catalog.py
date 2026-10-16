from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
import re

UTC = timezone.utc
BASE = datetime(2026, 9, 26, 9, 0, tzinfo=UTC)
VARIANTS = {
    "A": {"host": "WIN-LAB-01", "seed_offset": 101, "suffix": "BackupAgent"},
    "B": {"host": "WIN-LAB-02", "seed_offset": 202, "suffix": "UpdateBridge"},
    "C": {"host": "WIN-LAB-03", "seed_offset": 303, "suffix": "MonitorRelay"},
    "D": {"host": "WIN-LAB-04", "seed_offset": 404, "suffix": "PatchCoordinator"},
    "E": {"host": "WIN-LAB-05", "seed_offset": 505, "suffix": "TelemetryHelper"},
}

# Immutable scenario-side CSG evidence. This model is never populated from Wazuh rows.
@dataclass(frozen=True)
class CSGTransitionRecord:
    id: str
    source: str
    host: str
    observed_at: str
    category: str
    object_key: str
    transition: str
    before: dict | None
    after: dict | None


CASE_3_VARIANTS = {
    "A": {"service":"DeviceHealthSvc","process":"DeviceHealthCheck.exe","task":"\\Microsoft\\Windows\\DeviceHealth\\CacheRefresh","pid":4160},
    "B": {"service":"InventoryTelemetry","process":"InventoryStage.exe","task":"\\Microsoft\\Windows\\Inventory\\CacheRefresh","pid":4260},
    "C": {"service":"MetricsRelaySvc","process":"MetricsStage.exe","task":"\\Microsoft\\Windows\\Metrics\\CacheRefresh","pid":4360},
    "D": {"service":"PolicyBrokerSvc","process":"PolicyStage.exe","task":"\\Microsoft\\Windows\\Policy\\CacheRefresh","pid":4460},
    "E": {"service":"EndpointHealthSvc","process":"EndpointStage.exe","task":"\\Microsoft\\Windows\\Endpoint\\CacheRefresh","pid":4560},
}
CASE_4_VARIANTS = {
    "A": {"service":"DeviceCacheSvc","process":"CacheHost.exe","task":"\\Microsoft\\Windows\\Diagnostics\\CacheHealth","pid":7460,"script_pid":7480,"listener_pid":7520,"port":8448},
    "B": {"service":"InventoryCacheSvc","process":"InventoryHost.exe","task":"\\Microsoft\\Windows\\Inventory\\CacheHealth","pid":7560,"script_pid":7580,"listener_pid":7620,"port":8449},
    "C": {"service":"MetricsCacheSvc","process":"MetricsHost.exe","task":"\\Microsoft\\Windows\\Metrics\\CacheHealth","pid":7660,"script_pid":7680,"listener_pid":7720,"port":8450},
    "D": {"service":"PolicyCacheSvc","process":"PolicyHost.exe","task":"\\Microsoft\\Windows\\Policy\\CacheHealth","pid":7760,"script_pid":7780,"listener_pid":7820,"port":8451},
    "E": {"service":"EndpointCacheSvc","process":"EndpointHost.exe","task":"\\Microsoft\\Windows\\Endpoint\\CacheHealth","pid":7860,"script_pid":7880,"listener_pid":7920,"port":8452},
}
FINAL_VARIANTS = {
    "A": {"service":"RemoteAssistSvc","process":"TelemetryStage.exe","task":"\\Microsoft\\Windows\\DeviceHealth\\InventoryRefresh","registry_value":"DeviceHealthStage","port":4443,"pid":5160},
    "B": {"service":"InventoryBrokerSvc","process":"InventoryStage.exe","task":"\\Microsoft\\Windows\\Inventory\\InventoryRefresh","registry_value":"InventoryStage","port":4444,"pid":5260},
    "C": {"service":"MetricsSupportSvc","process":"MetricsStage.exe","task":"\\Microsoft\\Windows\\Metrics\\InventoryRefresh","registry_value":"MetricsStage","port":4445,"pid":5360},
    "D": {"service":"PolicyCacheSvc","process":"PolicyStage.exe","task":"\\Microsoft\\Windows\\Policy\\InventoryRefresh","registry_value":"PolicyStage","port":4446,"pid":5460},
    "E": {"service":"EndpointAssistSvc","process":"EndpointStage.exe","task":"\\Microsoft\\Windows\\Endpoint\\InventoryRefresh","registry_value":"EndpointStage","port":4447,"pid":5560},
}


def _incident_variables(case: dict, variant: str) -> dict:
    values = dict(VARIANTS[variant])
    aliases = case.get("variant_values", {}).get(variant, {})
    values.update(aliases)
    if "process" in values:
        values["image_path"] = f"C:\\ProgramData\\CsgLab\\Stage\\{values['process']}"
    values.setdefault("image_path", "C:\\Program Files\\{target}\\agent.exe")
    values.setdefault("pid", 4160 + (ord(variant) - 65) * 100)
    values.setdefault("port", 4443 + ord(variant) - 65)
    values.setdefault("task", "\\Microsoft\\Windows\\Maintenance\\InventoryRefresh")
    values.setdefault("registry_value", "InventoryStage")
    return values


def _expand(value, variables: dict):
    if isinstance(value, dict):
        return {k: _expand(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v, variables) for v in value]
    if isinstance(value, str):
        if value == "{pid}": return int(variables["pid"])
        if value == "{port}": return int(variables["port"])
        for key, replacement in variables.items():
            value = value.replace("{" + key + "}", str(replacement))
        return value
    return value


def _object_key(template: str, variables: dict) -> str:
    return str(_expand(template, variables)).casefold()


CASES = [
    {
        "id": "case-01", "slug": "expected-service", "title": "The Expected Service",
        "difficulty": "Easy", "sort_order": 1, "seed_version": 4,
        "learning_objective": "Match a service addition, then connect its executable to malicious activity.",
        "host": "WIN-LAB-01", "timeline_start": BASE.isoformat(), "timeline_end": (BASE + timedelta(hours=3)).isoformat(),
        "noise_seed": 42001, "snapshot_interval_minutes": 30, "minimum_events": 15000,
        "briefing": {
            "research_context": 'CyberStateGuardian (CSG) records endpoint state and changes between snapshots. Wazuh is an open-source SIEM that collects Windows, PowerShell, Defender, and Sysmon events. The sources are independent, but analysts correlate them by host, object name, executable path, process ancestry, command, and time to assess which activity is linked to an observed state change.',
            "scenario": "During a maintenance window on {host}, the {target} service appeared in the endpoint inventory. Snapshot A has no entry for it; Snapshot B shows it running as LocalSystem with Automatic startup. Its name suggests routine software. Investigate the executable and its activity before accepting that explanation.",
            "csg_observed": "CSG captured the service inventory before and after the maintenance window.",
            "what_this_case_teaches": "Find the state change first. Then check whether a Windows event describes the same host, service, and operation.",
            "technical_context": "Start type controls when a service can start: Manual, Automatic, or Disabled. Runtime status tells you whether it is Running or Stopped. Check which field the event actually describes.",
            "evidence_available": [
                {
                    "name": "Snapshot A",
                    "description": "Endpoint inventory at the beginning of the interval."
                },
                {
                    "name": "Snapshot B",
                    "description": "Endpoint inventory at the end of the interval."
                },
                {
                    "name": "Snapshot Delta",
                    "description": "Differences that remain when Snapshot A is compared with Snapshot B."
                },
                {
                    "name": "Wazuh / Windows telemetry",
                    "description": "Separate event logs. Compare the host, object, operation, values, and time with CSG."
                }
            ],
            "your_task": "Match the service installation record, then follow its executable into the process and PowerShell events. Use the command, parent PID, and shared path to explain why the service is part of the threat."
        },
        "delta_defs": [{"id":"d-service-add","category":"service","operation":"ADD","object_template":"service:{target}","before":None,"after":{"service_name":"{target}","display_name":"{target} Service","status":"running","start_mode":"automatic","binary_path":"C:\\Program Files\\{target}\\agent.exe","account":"LocalSystem"},"expected":"CONSISTENT","evidence":"service_created"}],
        "answer_explanations": {"d-service-add":"SCM 7045 directly supports the service addition on this host. Sysmon records the same service binary starting, then spawning PowerShell; event 4104 names this service in a persistence command and exposes Defender disablement and data staging. Together, the install and process chain link the CSG addition to malicious activity. The outbound request is an attempt, not proof of receipt."},
    },
    {
        "id": "case-02", "slug": "missing-service-event", "title": "The Overnight Change",
        "difficulty": "Easy / Medium", "sort_order": 2, "seed_version": 5,
        "learning_objective": "Correlate endpoint state with surrounding event evidence and assess what each source can establish.",
        "host": "WIN-LAB-02", "timeline_start": BASE.isoformat(), "timeline_end": (BASE + timedelta(hours=3)).isoformat(),
        "noise_seed": 42002, "snapshot_interval_minutes": 30, "minimum_events": 15000,
        "briefing": {
            "research_context": 'CyberStateGuardian (CSG) captures endpoint state and records changes between snapshots. Wazuh is an open-source SIEM; this lab models a deployment configured to collect Windows, Defender, PowerShell, and Sysmon events. Correlate the sources by host, object, executable path, PID, command, and time. One source can reveal a change while another reveals the process and intent behind it.',
            "scenario": "An overnight maintenance window on {host} is followed by activity that needs review. Reconstruct the sequence from endpoint state and event logs, then assess whether the activity is consistent with expected administration.",
            "csg_observed": "CSG provides endpoint snapshots and a separate record of changes observed between captures. Begin with the object and attributes recorded in the state evidence.",
            "what_this_case_teaches": "Use endpoint state to form a testable lead, then compare it with independent event records. Explain where the sources agree, where they differ, and what the evidence cannot establish.",
            "technical_context": "Services have separate configuration and runtime state. Windows events, process records, and script content describe different parts of activity; compare the exact object, relevant fields, process relationships, and time before inferring cause.",
            "evidence_available": [
                {
                    "name": "Snapshot A and Snapshot B",
                    "description": "Endpoint inventories at the beginning and end of the interval."
                },
                {
                    "name": "Snapshot Delta",
                    "description": "Differences that remain when Snapshot A is compared with Snapshot B."
                },
                {
                    "name": "Wazuh / Windows telemetry",
                    "description": "Separate event logs. Compare the host, object, operation, values, and time with CSG."
                }
            ],
            "your_task": "Compare the snapshots. Expand the relevant Snapshot Delta and note the host, exact object identity, changed values, and any other identifying attributes. Use those CSG details as pivots into Wazuh, reconstruct the surrounding activity, and explain what each source can and cannot confirm."
        },
        "delta_defs": [{"id":"d-service-mode","category":"service","operation":"MODIFY","object_template":"service:{target}","before":{"service_name":"{target}","display_name":"{target} Service","status":"running","start_mode":"manual","binary_path":"C:\\Program Files\\{target}\\agent.exe","account":"LocalSystem"},"after":{"service_name":"{target}","display_name":"{target} Service","status":"running","start_mode":"automatic","binary_path":"C:\\Program Files\\{target}\\agent.exe","account":"LocalSystem"},"expected":"PARTIALLY_EXPLAINED","evidence":"service_modified"}],
        "answer_explanations": {"d-service-mode":"CSG independently confirms {target} changed Manual → Automatic. Same-host PowerShell 4104 shows `sc.exe stop CsgTelemetryForwarder`, `sc.exe config {target} start= auto`, and `sc.exe start CsgTelemetryForwarder` in that order. Forwarder stop/start records bracket the attempted change, and the matching 7040 is absent. The same script disables Defender, stages documents, and attempts an outbound transfer. Classify it PARTIALLY_EXPLAINED: the sequence links malicious intent to the observed result and offers a credible explanation for the logging gap, but the script block and CSG snapshots do not prove that the config command executed or caused the change."},
    },
    {
        "id": "case-03", "slug": "complete-state-model", "title": "Between the Snapshots",
        "difficulty": "Medium", "sort_order": 3, "seed_version": 1,
        "learning_objective": "Connect a malicious process chain to persisted and transient CSG changes.",
        "host": "WIN-LAB-03", "timeline_start": BASE.isoformat(), "timeline_end": (BASE + timedelta(hours=3)).isoformat(),
        "noise_seed": 42003, "snapshot_interval_minutes": 30, "minimum_events": 15000,
        "briefing": {
            "research_context": 'CyberStateGuardian (CSG) records endpoint state and changes between snapshots. Wazuh is an open-source SIEM that collects Windows, PowerShell, Defender, and Sysmon events. The sources are independent, but analysts correlate them by host, object name, executable path, process ancestry, command, and time to assess which activity is linked to an observed state change.',
            "scenario": "On {host}, {service} briefly changed from Manual to Automatic and back. In the same interval, {process} started and exited, while a new task, {task}, remained configured. The service returned to its original state before Snapshot B. Follow the shared executable and process identifiers to investigate what happened between captures.",
            "csg_observed": "CSG recorded changes inside the interval, including activity that may no longer appear in Snapshot B.",
            "what_this_case_teaches": "A process may start and exit, or a service may change and change back, between snapshots. Read the CSG timeline as well as the inventories.",
            "technical_context": "A process can start and exit before the next snapshot. A service can return to its earlier configuration. A scheduled task can remain configured after the activity that created it ends.",
            "evidence_available": [
                {
                    "name": "Snapshot A / Snapshot B",
                    "description": "Endpoint inventories at the beginning and end of the interval."
                },
                {
                    "name": "Snapshot Delta",
                    "description": "Differences that remain when Snapshot A is compared with Snapshot B."
                },
                {
                    "name": "CSG State Change Timeline",
                    "description": "Changes recorded by CSG between snapshots, including activity that later ended or reverted."
                },
                {
                    "name": "Wazuh / Windows telemetry",
                    "description": "Separate event logs. Compare the host, object, operation, values, and time with CSG."
                }
            ],
            "your_task": "Identify what persisted and what ended. Trace the child process, its security-setting and data-staging commands, and the task it requested. Match the task and action across the script, CSG timeline, and Wazuh registration event."
        },
        "variant_values": CASE_3_VARIANTS,
        "incident": {
            "snapshot_minutes": [30, 60],
            "initial_state": [
                {"category":"service","object_template":"service:{service}","display_name":"{service}","attributes":{"service_name":"{service}","display_name":"{service} Service","status":"running","start_mode":"manual","binary_path":"{image_path}","account":"LocalSystem"}},
            ],
            "transitions": [
                {"id":"t-service-auto","at_offset_seconds":2232,"category":"service","object_template":"service:{service}","transition":"MODIFY","before":{"start_mode":"manual"},"after":{"start_mode":"automatic"}},
                {"id":"t-process-start","at_offset_seconds":2245,"category":"process","object_template":"process:{pid}:{process}","transition":"START","before":None,"after":{"name":"{process}","pid":"{pid}","parent":"services.exe","ppid":680,"executable_path":"{image_path}","command_line":"{image_path} --inventory"}},
                {"id":"t-task-create","at_offset_seconds":2290,"category":"scheduled_task","object_template":"task:{task}","transition":"CREATE","before":None,"after":{"task_name":"{task}","action":"{image_path} --inventory","run_as":"SYSTEM","enabled":True},"delta_id":"d-task-add"},
                {"id":"t-process-exit","at_offset_seconds":2340,"category":"process","object_template":"process:{pid}:{process}","transition":"EXIT","before":{"name":"{process}","pid":"{pid}","parent":"services.exe","ppid":680,"executable_path":"{image_path}","command_line":"{image_path} --inventory"},"after":None},
                {"id":"t-service-manual","at_offset_seconds":2355,"category":"service","object_template":"service:{service}","transition":"MODIFY","before":{"start_mode":"automatic"},"after":{"start_mode":"manual"}},
            ],
            "telemetry": [
                {"transition_id":"t-service-auto","coverage":"recorded"},
                {"transition_id":"t-process-start","coverage":"recorded"},
                {"transition_id":"t-task-create","coverage":"recorded"},
                {"transition_id":"t-process-exit","coverage":"recorded"},
                {"transition_id":"t-service-manual","coverage":"recorded"},
            ],
            "telemetry_distractors": [
                {"id":"distractor-process-lookalike","type":"process"},
                {"id":"distractor-task-lookalike","type":"task"},
            ],
            "delta_ids": {"task:{task}":"d-task-add"},
        },
        "investigation_defs": [
            {"id":"c-service-cycle","kind":"transition","title":"Service configuration cycle","category":"service","object_template":"service:{service}","transition_ids":["t-service-auto","t-service-manual"],"expected":"CONSISTENT","required_transition_ids":["t-service-auto","t-service-manual"],"require_all_evidence":True,"prohibited_event_suffixes":["near-0","near-1","near-2","near-3","near-4","near-5","wrong-host"],"explanation":"CSG recorded the service change and reversion; Wazuh 7040 confirms both. Its image path matches the short-lived process that spawns the malicious PowerShell child. Event 4104 exposes the security-control change and data staging, so identical boundary snapshots hide part of a connected incident."},
            {"id":"c-process-lifecycle","kind":"transition","title":"Short-lived process lifecycle","category":"process","object_template":"process:{pid}:{process}","transition_ids":["t-process-start","t-process-exit"],"expected":"CONSISTENT","required_transition_ids":["t-process-start","t-process-exit"],"require_all_evidence":True,"prohibited_event_suffixes":["distractor-process-lookalike"],"explanation":"CSG recorded the process start and exit while both snapshots show the process absent. Wazuh Sysmon 1/5 match the PID, image path, and host. The process image matches the service binary and is the parent of the PowerShell child whose 4104 script disables Defender and stages data, linking this transient process to the malicious activity."},
            {"id":"d-task-add","kind":"delta","title":"Scheduled task persists","category":"scheduled_task","object_template":"task:{task}","transition_ids":["t-task-create"],"expected":"CONSISTENT","required_transition_ids":["t-task-create"],"required_event_suffixes":["malicious-script-block"],"require_all_evidence":True,"prohibited_event_suffixes":["distractor-task-lookalike","distractor-task-lookalike-wrong-host"],"explanation":"The task persists from Snapshot A to Snapshot B. CSG records its creation; Wazuh event 106 confirms the exact name and action. PowerShell 4104 shows the same process chain requesting that task and action while disabling Defender and staging data, linking the registered task to the malicious activity."},
        ],
    },
    {
        "id": "case-04", "slug": "staged-relay", "title": "The Relay Takes Hold",
        "difficulty": "Medium / Hard", "sort_order": 4, "seed_version": 2,
        "learning_objective": "Reconstruct a two-stage compromise across three snapshots and connect each durable delta to the next stage of attacker activity.",
        "host": "WIN-LAB-04", "timeline_start": BASE.isoformat(), "timeline_end": (BASE + timedelta(hours=3)).isoformat(),
        "noise_seed": 42004, "snapshot_interval_minutes": 30, "minimum_events": 15000,
        "briefing": {
            "research_context": "CyberStateGuardian (CSG) records endpoint state at collection boundaries and selected changes between them. Wazuh is an open-source SIEM configured here for Windows, PowerShell, Defender, and Sysmon telemetry. Compare each adjacent snapshot pair, then follow host, service image, process ID, parent process, task action, and listener ownership across the independent sources.",
            "scenario": "Three captures on {host} show a staged intrusion. Between Snapshot A and B, {service} changes from Manual to Automatic and its {process} image appears in the running process inventory. Between B and C, the same image is registered in {task} and begins listening on TCP {port}. The sequence resembles a quiet maintenance relay. Trace the service-to-process relationship and then decide whether the later task and listener are routine support activity or a foothold being established.",
            "csg_observed": "CSG captured three endpoint states. Compare A→B and B→C separately: the first interval changes service configuration and process inventory; the second adds a task and a listener.",
            "what_this_case_teaches": "A sequence across adjacent snapshot deltas can reveal more than an isolated before/after pair. Establish the first link, then carry its exact image path and PID forward to test whether later persistence and network exposure belong to the same activity.",
            "technical_context": "A service start type controls startup behavior. A scheduled task stores a later execution action. A listener accepts inbound connections on a local address and port. Process telemetry, PowerShell script blocks, task registration, and Windows Filtering Platform records describe different parts of the sequence; correlate their identities rather than treating any one timestamp as proof.",
            "evidence_available": [
                {"name":"Snapshots A, B, and C","description":"Three endpoint inventories. Each adjacent pair represents a separate observation interval."},
                {"name":"Snapshot Delta","description":"The durable differences for A→B and B→C; check the interval named on each record."},
                {"name":"CSG State Change Timeline","description":"Selected state transitions CSG observed across the full capture window."},
                {"name":"Wazuh / Windows telemetry","description":"Independent events for service configuration, process ancestry, script content, task registration, and listener permission."}
            ],
            "your_task": "Investigate both intervals in order. First match the service start-type change and process image. Then test whether the task action and listener PID/path continue that chain. Inspect PowerShell 4104 for the attacker’s purpose, and reject records that only share a name, port, or nearby time."
        },
        "variant_values": CASE_4_VARIANTS,
        "incident": {
            "snapshot_minutes": [30, 60, 90],
            "initial_state": [
                {"category":"service","object_template":"service:{service}","display_name":"{service}","attributes":{"service_name":"{service}","display_name":"Windows {process} Maintenance","status":"running","start_mode":"manual","binary_path":"{image_path}","account":"LocalSystem","service_type":"own_process","publisher":"Northstar Endpoint Tools","file_version":"3.8.2.17","description":"Local inventory cache coordination"}}
            ],
            "transitions": [
                {"id":"t-service-auto","at_offset_seconds":2362,"category":"service","object_template":"service:{service}","transition":"MODIFY","before":{"start_mode":"manual"},"after":{"start_mode":"automatic"}},
                {"id":"t-process-start","at_offset_seconds":2370,"category":"process","object_template":"process:{pid}:{process}","transition":"START","before":None,"after":{"name":"{process}","pid":"{pid}","parent":"services.exe","ppid":680,"executable_path":"{image_path}","command_line":"{image_path} --worker","integrity_level":"System","signed":"true","publisher":"Northstar Endpoint Tools","sha256":"c4b12d77a8e94024f631d5a36b7c92044a16efbf51d903e0"}},
                {"id":"t-task-create","at_offset_seconds":4133,"category":"scheduled_task","object_template":"task:{task}","transition":"CREATE","before":None,"after":{"task_name":"{task}","action":"{image_path} --serve {port}","run_as":"SYSTEM","enabled":True,"trigger":"At startup","author":"SYSTEM","hidden":"true"}},
                {"id":"t-listener-process-start","at_offset_seconds":4135,"category":"process","object_template":"process:{listener_pid}:{process}","transition":"START","before":None,"after":{"name":"{process}","pid":"{listener_pid}","parent":"powershell.exe","ppid":"{script_pid}","executable_path":"{image_path}","command_line":"{image_path} --serve {port}","integrity_level":"System","signed":"true","publisher":"Northstar Endpoint Tools","sha256":"c4b12d77a8e94024f631d5a36b7c92044a16efbf51d903e0"}},
                {"id":"t-listener-open","at_offset_seconds":4137,"category":"listener","object_template":"listener:tcp:0.0.0.0:{port}","transition":"OPEN","before":None,"after":{"protocol":"tcp","local_address":"0.0.0.0","local_port":"{port}","pid":"{listener_pid}","process_name":"{process}","executable_path":"{image_path}","state":"LISTENING"}}
            ],
            "telemetry": [
                {"transition_id":"t-service-auto","coverage":"recorded"},
                {"transition_id":"t-process-start","coverage":"recorded"},
                {"transition_id":"t-task-create","coverage":"recorded"},
                {"transition_id":"t-listener-process-start","coverage":"recorded"},
                {"transition_id":"t-listener-open","coverage":"recorded"}
            ],
            "delta_ids": {"service:{service}":"d-service-auto","process:{pid}:{process}":"d-process-add","task:{task}":"d-task-add","process:{listener_pid}:{process}":"d-listener-process-add","listener:tcp:0.0.0.0:{port}":"d-listener-add"},
            "distractor_offsets": {"service":2350,"process":2375,"task":4132,"listener":4138},
            "telemetry_distractors": [
                {"id":"distractor-service-lookalike","type":"service"},
                {"id":"distractor-process-lookalike","type":"process"},
                {"id":"distractor-listener-process-lookalike","type":"process","offset_seconds":4136,"pid_source":"listener_pid","pid_offset":1,"parent":"powershell.exe","ppid_source":"script_pid","command_line_template":"{image_path} --serve {port}"},
                {"id":"distractor-task-lookalike","type":"task"},
                {"id":"distractor-listener-other-process","type":"listener"}
            ]
        },
        "investigation_defs": [
            {"id":"d-service-auto","kind":"delta","title":"Service startup changed · A→B","category":"service","object_template":"service:{service}","delta_id":"d-service-auto","transition_ids":["t-service-auto"],"expected":"CONSISTENT","required_transition_ids":["t-service-auto","t-process-start"],"required_event_suffixes":["stage-a-script-block"],"require_all_evidence":True,"prohibited_event_suffixes":["distractor-service-lookalike","same-service-opposite-direction"],"explanation":"From Snapshot A to B, {service} changes Manual → Automatic and {process} appears with the same executable path configured on the service. Wazuh 7040 confirms the exact start-type change; Sysmon 1 confirms the process instance and parent. The first-stage PowerShell 4104 script requests the change and starts the service. The path, host, operation, and order link the first durable delta to the next stage; a nearby or opposite-direction service record does not."},
            {"id":"d-process-add","kind":"delta","title":"Service image starts · A→B","category":"process","object_template":"process:{pid}:{process}","delta_id":"d-process-add","transition_ids":["t-process-start"],"expected":"CONSISTENT","required_transition_ids":["t-process-start"],"required_event_suffixes":["stage-b-script-block"],"require_all_evidence":True,"prohibited_event_suffixes":["distractor-process-lookalike","distractor-listener-process-lookalike"],"explanation":"The process appears by Snapshot B. Sysmon 1 matches its PID, path, host, and services.exe parent. The later child PowerShell 4104 shares this parent PID and names the task action and listener port, carrying the service-image link into the second stage."},
            {"id":"d-task-add","kind":"delta","title":"Startup task added · B→C","category":"scheduled_task","object_template":"task:{task}","delta_id":"d-task-add","transition_ids":["t-task-create"],"expected":"CONSISTENT","required_transition_ids":["t-task-create"],"required_event_suffixes":["stage-b-script-block"],"require_all_evidence":True,"prohibited_event_suffixes":["distractor-task-lookalike","distractor-task-lookalike-wrong-host"],"explanation":"The task first appears between Snapshots B and C. CSG records its full path and hidden startup action; Task Scheduler 106 confirms the same task and action. The child 4104 script requests that action and also disables Defender and stages data. Its parent process ID and executable path match the service image found in A→B."},
            {"id":"d-listener-process-add","kind":"delta","title":"Listener process starts · B→C","category":"process","object_template":"process:{listener_pid}:{process}","delta_id":"d-listener-process-add","transition_ids":["t-listener-process-start"],"expected":"CONSISTENT","required_transition_ids":["t-listener-process-start"],"required_event_suffixes":["stage-b-script-block"],"require_all_evidence":True,"prohibited_event_suffixes":["distractor-process-lookalike","distractor-listener-process-lookalike"],"explanation":"A second instance of the same executable appears after the startup task is registered. Sysmon 1 identifies the exact PID and the PowerShell parent; its command line matches the task action and the process owns the listener in the following transition. The task stores the same action for the next startup."},
            {"id":"d-listener-add","kind":"delta","title":"Listener opened · B→C","category":"listener","object_template":"listener:tcp:0.0.0.0:{port}","delta_id":"d-listener-add","transition_ids":["t-listener-open"],"expected":"CONSISTENT","required_transition_ids":["t-listener-open"],"required_event_suffixes":["stage-b-script-block"],"require_all_evidence":True,"prohibited_event_suffixes":["distractor-listener-other-process","distractor-listener-process-lookalike"],"explanation":"The listener appears between Snapshots B and C. Security 5154 confirms Windows permitted the exact image and PID to listen on the same TCP port CSG records. The PowerShell child script launches that listener and creates the persistent task; Sysmon process ancestry ties it to the service image established in A→B."}
        ]
    },
    {
        "id": "case-final", "slug": "final-investigation", "title": "Final Investigation — Transient Compromise with Persistent Foothold",
        "difficulty": "Challenge", "sort_order": 5, "seed_version": 2,
        "learning_objective": "Reconstruct one linked incident from durable state, transient CSG transitions, and mixed independent Wazuh evidence.",
        "host": "WIN-LAB-01", "timeline_start": BASE.isoformat(), "timeline_end": (BASE + timedelta(hours=3)).isoformat(),
        "noise_seed": 42006, "snapshot_interval_minutes": 30, "minimum_events": 15000,
        "briefing": {
            "research_context": 'CyberStateGuardian (CSG) records endpoint state and changes between snapshots. Wazuh is an open-source SIEM that collects Windows, PowerShell, Defender, and Sysmon events. The sources are independent, but analysts correlate them by host, object name, executable path, process ancestry, command, and time to assess which activity is linked to an observed state change.',
            "scenario": "On {host}, {service} temporarily changed startup mode while {process} ran and opened a network listener. The process ended and the service configuration reverted, but a scheduled task and registry Run value remained. Trace their executable paths and process identifiers to reconstruct the activity and assess what the logs support.",
            "csg_observed": "CSG recorded changes to several related objects. Some remain in Snapshot B; others appear only in the timeline.",
            "what_this_case_teaches": "Link objects by executable path, PID, parent process, task action, and registry data. A close timestamp is a lead to inspect, not proof of a link.",
            "technical_context": "A listener is a process waiting for connections on a local address and port. A scheduled task stores a program to run. A registry Run value starts a program at sign-in. Match their paths and process IDs where available.",
            "evidence_available": [
                {
                    "name": "Snapshot A / Snapshot B",
                    "description": "Endpoint inventories at the beginning and end of the interval."
                },
                {
                    "name": "Snapshot Delta",
                    "description": "Differences that remain when Snapshot A is compared with Snapshot B."
                },
                {
                    "name": "CSG State Change Timeline",
                    "description": "Changes recorded by CSG between snapshots, including activity that later ended or reverted."
                },
                {
                    "name": "Wazuh / Windows telemetry",
                    "description": "Separate event logs. Compare the host, object, operation, values, and time with CSG."
                }
            ],
            "your_task": "Reconstruct the sequence from service to parent process, child PowerShell, listener, task, and Run value. Match exact object names and executable data across CSG and Wazuh; identify the malicious intent and state where telemetry is missing."
        },
        "variant_values": FINAL_VARIANTS,
        "incident": {
            "snapshot_minutes": [30, 60],
            "initial_state": [
                {"category":"service","object_template":"service:{service}","display_name":"{service}","attributes":{"service_name":"{service}","display_name":"{service} Service","status":"running","start_mode":"manual","binary_path":"{image_path}","account":"LocalSystem"}},
            ],
            "transitions": [
                {"id":"t-service-auto","at_offset_seconds":2232,"category":"service","object_template":"service:{service}","transition":"MODIFY","before":{"start_mode":"manual"},"after":{"start_mode":"automatic"}},
                {"id":"t-process-start","at_offset_seconds":2245,"category":"process","object_template":"process:{pid}:{process}","transition":"START","before":None,"after":{"name":"{process}","pid":"{pid}","parent":"services.exe","ppid":680,"executable_path":"{image_path}","command_line":"{image_path} --stage"}},
                {"id":"t-listener-open","at_offset_seconds":2249,"category":"listener","object_template":"listener:tcp:0.0.0.0:{port}","transition":"OPEN","before":None,"after":{"protocol":"tcp","local_address":"0.0.0.0","local_port":"{port}","pid":"{pid}","process_name":"{process}","executable_path":"{image_path}"}},
                {"id":"t-task-create","at_offset_seconds":2265,"category":"scheduled_task","object_template":"task:{task}","transition":"CREATE","before":None,"after":{"task_name":"{task}","action":"{image_path} --stage","run_as":"SYSTEM","enabled":True},"delta_id":"d-task-add"},
                {"id":"t-registry-create","at_offset_seconds":2281,"category":"registry_autorun","object_template":"registry:HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{registry_value}","transition":"CREATE","before":None,"after":{"registry_key":"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","value_name":"{registry_value}","value_data":"{image_path} --stage"},"delta_id":"d-registry-add"},
                {"id":"t-process-exit","at_offset_seconds":2341,"category":"process","object_template":"process:{pid}:{process}","transition":"EXIT","before":{"name":"{process}","pid":"{pid}","parent":"services.exe","ppid":680,"executable_path":"{image_path}","command_line":"{image_path} --stage"},"after":None},
                {"id":"t-listener-close","at_offset_seconds":2345,"category":"listener","object_template":"listener:tcp:0.0.0.0:{port}","transition":"CLOSE","before":{"protocol":"tcp","local_address":"0.0.0.0","local_port":"{port}","pid":"{pid}","process_name":"{process}","executable_path":"{image_path}"},"after":None},
                {"id":"t-service-manual","at_offset_seconds":2355,"category":"service","object_template":"service:{service}","transition":"MODIFY","before":{"start_mode":"automatic"},"after":{"start_mode":"manual"}},
            ],
            "telemetry": [
                {"transition_id":"t-service-auto","coverage":"recorded"},
                {"transition_id":"t-process-start","coverage":"recorded"},
                {"transition_id":"t-listener-open","coverage":"recorded"},
                {"transition_id":"t-task-create","coverage":"missing"},
                {"transition_id":"t-registry-create","coverage":"recorded"},
                {"transition_id":"t-process-exit","coverage":"recorded"},
                {"transition_id":"t-listener-close","coverage":"missing"},
                {"transition_id":"t-service-manual","coverage":"recorded"},
            ],
            "delta_ids": {"task:{task}":"d-task-add", "registry:HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{registry_value}":"d-registry-add"},
            "telemetry_distractors": [
                {"id":"distractor-task-lookalike","type":"task"},
                {"id":"distractor-registry-lookalike","type":"registry"},
                {"id":"distractor-service-conflict","type":"service"},
                {"id":"distractor-listener-other-process","type":"listener"},
                {"id":"distractor-process-lookalike","type":"process"},
            ],
        },
        "investigation_defs": [
            {"id":"c-service-cycle","kind":"transition","title":"Temporary service reconfiguration","category":"service","object_template":"service:{service}","transition_ids":["t-service-auto","t-service-manual"],"expected":"CONSISTENT","required_transition_ids":["t-service-auto","t-service-manual"],"require_all_evidence":True,"prohibited_event_suffixes":["distractor-service-conflict","near-0","near-1","near-2","near-3","near-4","near-5","wrong-host"],"explanation":"CSG recorded Manual → Automatic → Manual for the same service, and Wazuh 7040 confirms both changes. Its configured image path matches the short-lived process, which spawns the child PowerShell process responsible for the malicious commands in event 4104."},
            {"id":"c-process-lifecycle","kind":"transition","title":"Short-lived process","category":"process","object_template":"process:{pid}:{process}","transition_ids":["t-process-start","t-process-exit"],"expected":"CONSISTENT","required_transition_ids":["t-process-start","t-process-exit"],"require_all_evidence":True,"prohibited_event_suffixes":["distractor-process-lookalike"],"explanation":"CSG records the process start and exit; Sysmon 1/5 match the same PID, parent, image path, and host. Its child PowerShell process contains malicious Defender-disable, staging, and persistence commands in event 4104, tying the transient CSG process to the threat."},
            {"id":"c-listener-lifecycle","kind":"transition","title":"Temporary listener","category":"listener","object_template":"listener:tcp:0.0.0.0:{port}","transition_ids":["t-listener-open","t-listener-close"],"expected":"PARTIALLY_EXPLAINED","required_transition_ids":["t-listener-open"],"require_all_evidence":True,"prohibited_event_suffixes":["distractor-listener-other-process"],"explanation":"CSG recorded the listener opening and closing on the process-owned port. Wazuh event 5154 supports the listener opening and ties it to the same process and executable, but the archived event set contains no matching close record."},
            {"id":"d-task-add","kind":"delta","title":"Scheduled task persists","category":"scheduled_task","object_template":"task:{task}","transition_ids":["t-task-create"],"expected":"PARTIALLY_EXPLAINED","required_transition_ids":[],"acceptable_event_suffixes":["malicious-script-block"],"require_all_evidence":False,"prohibited_event_suffixes":["distractor-task-lookalike","distractor-task-lookalike-wrong-host"],"explanation":"The task is absent in Snapshot A and persists in Snapshot B; CSG records its creation. PowerShell 4104 names this exact task and executable action in a script that also disables Defender and stages data, tying the CSG finding to the malicious process. No Task Scheduler 106 confirms registration, so this is a strong cross-source link with a remaining telemetry gap, not direct event confirmation."},
            {"id":"d-registry-add","kind":"delta","title":"Registry persistence","category":"registry_autorun","object_template":"registry:HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{registry_value}","transition_ids":["t-registry-create"],"expected":"CONSISTENT","required_transition_ids":["t-registry-create"],"required_event_suffixes":["malicious-script-block"],"require_all_evidence":True,"prohibited_event_suffixes":["distractor-registry-lookalike","distractor-registry-lookalike-wrong-host"],"explanation":"The Run value is absent from Snapshot A and persists in Snapshot B. CSG records its creation; Sysmon 13 confirms the exact value data and executable. PowerShell 4104 names the same Run value and data in the malicious child process, linking the persistence change to the threat activity."},
        ],
    },
]


def case_by_slug(slug: str) -> dict:
    return next(case for case in CASES if case["slug"] == slug)


def target_name(case: dict, variant: str) -> str:
    if case["id"] == "case-01":
        return VARIANTS[variant]["suffix"]
    if case["id"] == "case-02":
        return ["UpdateHelper", "CloudSyncBridge", "InventoryAgent", "PatchCoordinator", "OpsTelemetry"][ord(variant)-65]
    return case.get("variant_values", {}).get(variant, {}).get("service", "WIN-LAB")


def materialize_delta(case: dict, definition: dict, variant: str) -> dict:
    target = target_name(case, variant)
    def expand(value):
        if isinstance(value, dict):
            return {k: expand(v) for k, v in value.items()}
        if isinstance(value, str):
            return value.replace("{target}", target)
        return value
    return {**definition, "object_key": expand(definition["object_template"]), "before": expand(definition["before"]), "after": expand(definition["after"])}


def materialize_incident(case: dict, variant: str) -> tuple[dict[str, dict], dict[str, dict], list[dict]]:
    incident = case["incident"]
    variables = _incident_variables(case, variant)
    initial: dict[str, dict] = {}
    for definition in incident["initial_state"]:
        key = _object_key(definition["object_template"], variables)
        initial[key] = {"category":definition["category"],"object_key":key,"display_name":_expand(definition.get("display_name", key), variables),"attributes":_expand(definition["attributes"], variables)}
    state = deepcopy(initial)
    records = []
    transitions = sorted(incident["transitions"], key=lambda item:item["at_offset_seconds"])
    for definition in transitions:
        key = _object_key(definition["object_template"], variables)
        before = _expand(definition.get("before"), variables)
        after = _expand(definition.get("after"), variables)
        action = definition["transition"]
        current = state.get(key)
        if action == "MODIFY":
            if not current or not before or any(current["attributes"].get(k) != v for k,v in before.items()):
                raise ValueError(f"Invalid CSG transition precondition: {case['slug']} {definition['id']}")
            current["attributes"].update(after or {})
        elif action in {"ADD","CREATE","START","OPEN"}:
            if current or after is None:
                raise ValueError(f"Invalid CSG transition creation: {case['slug']} {definition['id']}")
            state[key] = {"category":definition["category"],"object_key":key,"display_name":_expand(definition.get("display_name", key.split(":",1)[-1]), variables),"attributes":deepcopy(after)}
        elif action in {"REMOVE","EXIT","CLOSE"}:
            if not current or (before and any(current["attributes"].get(k) != v for k,v in before.items())):
                raise ValueError(f"Invalid CSG transition removal: {case['slug']} {definition['id']}")
            del state[key]
        else:
            raise ValueError(f"Unsupported CSG transition: {action}")
        records.append(asdict(CSGTransitionRecord(
            id=definition["id"], source="csg", host=VARIANTS[variant]["host"],
            observed_at=(BASE+timedelta(seconds=definition["at_offset_seconds"])).isoformat(),
            category=definition["category"], object_key=key, transition=action, before=before, after=after,
        )))
    return initial, state, records


def materialize_snapshot_states(case: dict, variant: str) -> list[dict[str, dict]]:
    """Replay the CSG incident independently at each configured snapshot boundary."""
    incident = case["incident"]
    variables = _incident_variables(case, variant)
    initial: dict[str, dict] = {}
    for definition in incident["initial_state"]:
        key = _object_key(definition["object_template"], variables)
        initial[key] = {"category":definition["category"],"object_key":key,"display_name":_expand(definition.get("display_name", key), variables),"attributes":_expand(definition["attributes"], variables)}

    transitions = sorted(incident["transitions"], key=lambda item:item["at_offset_seconds"])
    states=[]
    for minute in incident.get("snapshot_minutes", [30, 60]):
        state=deepcopy(initial)
        for definition in transitions:
            if definition["at_offset_seconds"] > minute*60:
                break
            key=_object_key(definition["object_template"], variables)
            before=_expand(definition.get("before"), variables)
            after=_expand(definition.get("after"), variables)
            action=definition["transition"]
            current=state.get(key)
            if action=="MODIFY":
                if not current or not before or any(current["attributes"].get(k)!=v for k,v in before.items()):
                    raise ValueError(f"Invalid CSG snapshot replay precondition: {case['slug']} {definition['id']}")
                current["attributes"].update(after or {})
            elif action in {"ADD","CREATE","START","OPEN"}:
                if current or after is None:
                    raise ValueError(f"Invalid CSG snapshot replay creation: {case['slug']} {definition['id']}")
                state[key]={"category":definition["category"],"object_key":key,"display_name":_expand(definition.get("display_name", key.split(":",1)[-1]), variables),"attributes":deepcopy(after)}
            elif action in {"REMOVE","EXIT","CLOSE"}:
                if not current or (before and any(current["attributes"].get(k)!=v for k,v in before.items())):
                    raise ValueError(f"Invalid CSG snapshot replay removal: {case['slug']} {definition['id']}")
                del state[key]
            else:
                raise ValueError(f"Unsupported CSG transition: {action}")
        states.append(state)
    return states


def scenario_delta_defs(case: dict, variant: str = "A") -> list[dict]:
    if not case.get("incident"):
        return [{**materialize_delta(case, item, variant),"before_snapshot_index":0,"after_snapshot_index":1} for item in case["delta_defs"]]
    states=materialize_snapshot_states(case,variant)
    variables = _incident_variables(case, variant)
    ids = {_object_key(template, variables): delta_id for template,delta_id in case["incident"].get("delta_ids", {}).items()}
    deltas=[]
    for pair_index,(before_state,after_state) in enumerate(zip(states,states[1:])):
        for key in sorted(before_state.keys() | after_state.keys()):
            before=before_state.get(key); after=after_state.get(key)
            if before and after and before["attributes"]==after["attributes"]:
                continue
            if before is None: operation="ADD"
            elif after is None: operation="REMOVE"
            else: operation="MODIFY"
            fallback="d-"+re.sub(r"[^a-z0-9]+","-",key).strip("-")[-42:]+f"-{chr(97+pair_index)}-{chr(98+pair_index)}"
            delta_id=ids.get(key,fallback)
            deltas.append({"id":delta_id,"category":(after or before)["category"],"operation":operation,"object_key":key,"before":deepcopy(before["attributes"]) if before else None,"after":deepcopy(after["attributes"]) if after else None,"before_snapshot_index":pair_index,"after_snapshot_index":pair_index+1})
    return deltas


def materialize_transitions(case: dict, variant: str) -> list[dict]:
    if not case.get("incident"):
        return []
    return materialize_incident(case, variant)[2]


def investigation_defs(case: dict, variant: str = "A") -> list[dict]:
    if case.get("investigation_defs"):
        variables=_incident_variables(case,variant)
        return [_expand(definition,variables) | {"object_key":_object_key(definition["object_template"],variables)} for definition in case["investigation_defs"]]
    items=[]
    for delta in scenario_delta_defs(case,variant):
        definition=next((d for d in case["delta_defs"] if d["id"]==delta["id"]),{})
        prohibited=( ["near-0","near-1","near-2","near-3","near-4","near-5","wrong-host",*[f"benign-install-copy-{index}" for index in range(5)]] if case["id"]=="case-01" else ["same-object-wrong-transition","wrong-host","service-query-lookalike"] if case["id"]=="case-02" else [] )
        required_suffixes=["evidence","malicious-script-block"] if case["id"]=="case-01" else ["malicious-script-block","forwarder-stopped","forwarder-started"] if case["id"]=="case-02" else []
        acceptable_suffixes=["malicious-defender-change","malicious-archive-created","malicious-outbound-connection"] if case["id"]=="case-02" else []
        items.append({"id":delta["id"],"kind":"delta","title":delta["object_key"].split(":",1)[-1],"category":delta["category"],"object_key":delta["object_key"],"delta_id":delta["id"],"transition_ids":[],"expected":definition.get("expected","UNEXPLAINED"),"required_transition_ids":[],"required_event_suffixes":required_suffixes,"acceptable_event_suffixes":acceptable_suffixes,"prohibited_event_suffixes":prohibited,"require_all_evidence":case["id"] in {"case-01","case-02"},"explanation":case.get("answer_explanations",{}).get(delta["id"],"Review the observation window and event coverage.")})
    return items


def public_case(case: dict, variant: str = "A") -> dict:
    deltas = [{k:v for k,v in item.items() if k not in {"expected","evidence","object_template"}} for item in scenario_delta_defs(case,variant)]
    exercises=[]
    for item in investigation_defs(case,variant):
        exercises.append({k:item[k] for k in ("id","kind","title","category","object_key","transition_ids","delta_id") if k in item})
    public_fields={"id","slug","title","difficulty","sort_order","learning_objective","timeline_start","timeline_end","snapshot_interval_minutes","minimum_events","briefing"}
    result={k:v for k,v in case.items() if k in public_fields}
    variables=_incident_variables(case,variant) | {"target":target_name(case,variant)}
    result["briefing"]=_expand(case["briefing"],variables)
    result.update({"host":VARIANTS[variant]["host"],"deltas":deltas,"investigations":exercises,"variant":variant,"target":target_name(case,variant)})
    return result
