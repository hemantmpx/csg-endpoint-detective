# Student guide

## How the evidence is organized

Snapshots are ordered endpoint captures. A two-capture case uses **Snapshot A** and **Snapshot B**; a three-capture case adds **Snapshot C**. A **Snapshot Delta** compares one adjacent pair (A→B or B→C) and shows an object’s before/after state for that interval.

Snapshots are boundary observations. A delta shows what changed across its pair, but not necessarily the full sequence between captures. If two adjacent snapshots agree for an object, that does not prove that nothing happened between them.

The **CSG State Change Timeline** lists selected state changes CSG independently observed between the snapshots. This is a CSG evidence source, not a Wazuh event list. Its labels use object-specific terms, such as *Service start type changed*, *Process Create*, *Process Terminated*, *Scheduled Task Registered*, *Registry Value Set*, *Listener Opened*, and *Listener Closed*.

**Wazuh / Windows telemetry** is a separate event source. Wazuh does not produce the CSG observation. Compare both sources by host, object, operation, values, executable path, process ancestry, command, and interval. Windows event terminology can differ from CSG's description of related activity. Even when the native change event is missing, a command and matching CSG state can link attacker intent to the observed outcome; describe that as a correlation and state what is not confirmed.

The briefing introduces the case and task; inspect the case-specific state evidence in CSG State. Use **Meet your evidence** to explore **Snapshots**, **CSG timeline**, and **Wazuh logs**. The arrows browse sources and recorded CSG changes; **Inspect CSG timeline** opens the highlighted record. Open **Background for this case** or **Available evidence** for more detail. After submitting a reconciliation, **Test your instinct** offers an optional, ungraded reflection question with feedback.

## Investigation sequence

The four-stage navigation stays below the case heading. Select **Case briefing**, **CSG state**, **Wazuh events**, or **Reconcile** to jump between stages; the highlighted stage shows where you are. The **Investigator tip** offers one short reminder and a button for the next step. The case queue shows your progress and available cases. In guided mode, finishing a case unlocks the next. Your instructor can also limit which cases are available.

1. Read the case briefing, endpoint host, and observation interval.
2. In **CSG State**, compare each adjacent pair. Search the selected inventory for the object, expand its row, and open the matching Snapshot Delta. Read the full before/after fields; attributes that stayed the same, such as an executable path, can still identify the object in Wazuh.
3. Review the **CSG State Change Timeline** in timestamp order. The overview markers show how many changes CSG recorded in each minute; select a marker, then a record to jump to its timeline row. Record the object identity and relevant fields before searching events.
4. In **Wazuh Events**, search and filter the archived event corpus. Open candidate details and compare the host, object identity, event operation, before/after values, and time.
5. In **Reconcile**, select the investigation item, collect only supporting Wazuh events, choose a classification, and explain the comparison. An empty evidence tray can be correct after a reasonable search finds no valid match.

## Using Wazuh event search

The search field updates results automatically about 350 ms after you stop typing. Press Enter to apply the current search immediately. Text search and structured filters combine: a record must match the search text, each selected filter, and the selected time range.

The filter controls include event category, event type, Windows event ID, host, provider, and time. The **Active filters** row above the results shows the effective search so you can see why a record is included or excluded. Select the × on an active filter to remove it. Use **Clear filters** to remove the text and structured filters and return to the full case window.

If you are unsure where to start, open **Search tips** above the controls. It walks through scoping the time window, combining search filters, inspecting records, and collecting candidates.

You can use free text or field searches such as:

```text
process.name:PolicyStage.exe
host.name:WIN-LAB-04 AND event.id:7040
process.pid:4460 AND event.id:1
```

The search syntax supports `field:value`, quoted phrases, `AND`, and `OR`. Quote `service.name` to match a service name exactly; free-text searches can also return longer names that contain the same text. The filter controls combine with the query. Use `rule.level:12` to find the lab’s custom high-severity alert. A nearby timestamp is a lead, not proof of a state match.

## Filtering by time

The time preset is based on the archived case window, not the computer’s current time. **Last 5 minutes**, **Last 15 minutes**, **Last 30 minutes**, and **Last 1 hour** count back from the end of the case’s archive window. **Full case window** restores the complete time span. Choose **Custom range** or edit the **From** and **To** date/time fields to set any valid interval.

Use the text search box for event text or `field:value` terms; enter date/time bounds in **From** and **To** below the other filters. For example, set From to `09:35` and To to `09:42` in the case’s displayed date. The search box does not take a time-range expression.

The date/time fields display in your browser’s local time. The selected range updates results automatically when both bounds are valid and the start is not later than the end. The event-volume chart uses the same time range: click a bar to select its minute or drag across bars to select a wider interval. The chart selection updates the fields, and editing the fields highlights the matching part of the chart.

If no records match, the results area says **No events match the current search and filters.** This describes the active query; it does not mean the archived dataset is unavailable.

## Inspecting and collecting a record

Open an event row to review its timestamp, host, Windows event ID and provider, normalized fields, and provenance. The details expand directly below that row, even for a single search result. **Filter this host** and **Filter this event ID** apply that record’s values to the current search. Use **View raw event JSON** when you need to check the archived field envelope. Collect a record only when its identity and operation support the selected investigation item. Evidence trays are item-specific. Choose the item in **Collecting evidence for** above the search controls and review the tray after changing it. Collected events can also be opened from the CSG and Reconcile trays; press Escape to close their inspector.

For service evidence, distinguish **start type** (Manual, Automatic, Disabled) from **runtime status** (Running, Stopped, Paused). For linked objects, compare stable fields such as executable path, PID, parent process, task action, registry value data, listener port, host, and compatible times.

Each case contains Wazuh events that let you connect the threat to the CSG objects. Start with the 4104 PowerShell script block: check whether its command names the changed service, scheduled task, or Run value. Follow the PowerShell PID and parent PID through Sysmon process events; compare executable paths and task or registry data with the CSG timeline and snapshots. Event 5007 records Defender real-time protection being disabled; correlate it by host, setting, and time because it has no PowerShell PID. Sysmon 11 records the staged archive, and Sysmon 3 records an outbound connection. Together these clues expose malicious intent and attempted transfer, though they do not prove the remote server accepted the data.

Use each event for what it can establish. A matching SCM, Task Scheduler, Sysmon, or registry event can directly corroborate a change. A script naming the exact object can connect attacker intent to a CSG-observed result, even when the native change event is missing; it does not prove that the command succeeded. Explain both the link and the remaining gap. A missing native event is not proof that the change was benign or did not happen.
