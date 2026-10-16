# What each case teaches

CSG snapshots show what was on an endpoint at particular times. Wazuh events show activity reported by logging sources. The research idea is to compare both: state helps show **what changed**, while event evidence may help explain **how it changed**. A match must fit the host, object, action, and time—not just happen nearby.

## Case 1 — The Expected Service

A new service appears and remains on the endpoint. Students start from that state change, find the service-install event, and follow the service program into later process and script activity. This teaches how persistent state and event details can support one another, and why a familiar-looking service name is not enough to decide whether it is safe.

## Case 2 — The Overnight Change

A service changes its startup setting, but the expected Windows change event is missing. CSG still shows the changed setting; Wazuh contains clues about a temporary interruption to event forwarding and other activity. This teaches that missing telemetry does not erase a state change, while also reminding us that the available evidence may not prove exactly what caused it.

## Case 3 — Between the Snapshots

A service changes and then returns to its earlier setting, and a process starts and exits before the next capture. A scheduled task remains afterward. This teaches why two snapshots can miss short-lived activity, why CSG's between-capture timeline matters, and how event records can help reconstruct the interval.

## Case 4 — The Relay Takes Hold

The first snapshot interval shows a service and its program; the next shows a task and a network listener created by related activity. Students use process identity and parent-child links to connect the stages. This teaches how evidence across A→B and B→C can form one timeline, while similar names or nearby timestamps alone do not establish a link.

## Case 5 — Final Investigation

Several objects change across the endpoint: services, processes, a listener, a scheduled task, and a registry value. Some changes have direct event support and some do not. This teaches how to reconcile several evidence types, explain partial support or gaps, and keep conclusions within what the records actually show.
