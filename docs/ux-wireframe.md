# UX wireframe description

## Entry and briefing

The join view asks for the class code and a display name or anonymous alias. The case desk uses a narrow progress rail and a briefing panel with host, observation window, learning objective, and an action into the CSG workspace. Five cases build from a corroborated durable change and a missing event, through transient state and a linked three-snapshot intrusion, to the final multi-object investigation.

## CSG state workspace

```text
┌ CSG Endpoint Detective ── CASE / 03 ── Host WIN-LAB-01 ── Save status ┐
├ Navigation: Briefing | CSG State | Wazuh Events | Reconcile            ┤
│ Snapshot A · 09:30 ─ interval A→B ─ Snapshot B · 10:00 ─ interval B→C ─ Snapshot C │
│ Category counts: Services | Tasks | Registry | Listeners | Processes   │
│ ┌ Searchable full inventory ┐ ┌ Snapshot Delta ────────────────────┐ │
│ │ all state attributes      │ │ expand before/after detail         │ │
│ │                           │ └──────────────────────────────────────┘ │
│ └───────────────────────────┘                                          │
│ ┌ CSG State Change Timeline · INDEPENDENT CSG RECORDS ───────────────┐ │
│ │ time | category action | object identity | before/after | CSG      │ │
│ └────────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
```

Each Snapshot Delta compares one adjacent pair and expands inline to show all before/after fields and related CSG observations. It does not navigate away to Reconcile. The separate CSG State Change Timeline preserves selected changes that reverted or ended before a later capture. Case 3 demonstrates a return to prior state; The Relay Takes Hold uses A→B and B→C to show a linked intrusion across three captures. Cases 1 and 2 have no CSG timeline records, so that section clearly says none are configured for those cases.

## Wazuh Event Investigation Console

```text
┌ Wazuh Event Investigation Console · ARCHIVED LAB EVIDENCE ───────────┐
│ query bar · category · event type · event ID · provider · host        │
│ archive-relative presets · custom From/To · clear filters             │
│ volume histogram selects and reflects the same time range             │
│ 15,xxx events · 1–100 shown                                          │
│ time | event ID | type | host | process/object | add evidence         │
│ selected row → details drawer → normalized fields | raw JSON          │
│ detail drawer identifies generated vs sanitized reference structure   │
└───────────────────────────────────────────────────────────────────────┘
```

Broad results contain routine Windows activity, same-time lookalikes, similar object names, wrong-host records, and incompatible values. No event is pinned or ranked as the answer. Students compare normalized fields or raw JSON against the CSG observation before collecting evidence.

## Reconcile and reveal

The worksheet selects one Snapshot Delta or CSG State Change Timeline item, shows its source and values, and links to the Wazuh evidence tray for that item. Students choose among `CONSISTENT`, `PARTIALLY_EXPLAINED`, `UNEXPLAINED`, `CONTRADICTED`, and `INSUFFICIENT_EVIDENCE`, then explain the host, identity, operation, values, and observation boundary. Submission reveals the backend result and accepted/rejected event reasons. The reveal states that an unexplained result is an evidence gap, not an accusation.

The Final Investigation uses five connected items: service cycle, process lifecycle, listener lifecycle, scheduled task addition, and registry addition. After the case sequence is complete, the debrief reinforces the linked incident and the difference between durable state, intermediate CSG history, and independent event evidence.

## Instructor

The instructor view provides a roster-by-case matrix, online/completed counts, all five classification distributions, anonymized search history, lab controls, reset action, and CSV export. Instructor authentication is checked server-side.
