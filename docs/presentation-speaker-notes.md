# CyberStateGuardian research presentation: slide-by-slide speaker notes

These notes explain the point of each slide, how to talk through its visual, and what the evidence does and does not support. Slides 1–9 present the research. Slide 10 is the only slide that turns to the classroom investigation.

## 1. CyberStateGuardian: reconciling endpoint state and event telemetry

**Purpose:** Introduce the research question without claiming that one product replaces another.

**Explain:** CyberStateGuardian (CSG) records selected endpoint state at collection times and compares those observations. Wazuh collects event records from configured sources such as Windows and Sysmon. The project asks what an analyst can learn by keeping those two evidence sources independent and then checking whether they describe the same object and change.

**Talk through the animation:** The two orbiting inputs represent the separate state and event evidence planes. They meet at reconciliation only after the system can compare identity, operation, and time. Emphasize that the inputs are not merged into one raw data source.

**Suggested wording:** “My research is about whether a periodic view of endpoint state can add useful, auditable context to the event stream that a SIEM already collects.”

## 2. Persistent state and event telemetry measure different things

**Purpose:** Define the central distinction in plain terms.

**Explain:** A snapshot is a picture of what the probe sees at one collection boundary. If a service is Manual in one capture and Automatic in the next, the state comparison shows that it changed somewhere in that interval. It does not reveal who changed it or every step that occurred. Event telemetry records activity reported by configured providers and delivered to the SIEM. Those records may be delayed, unavailable, or outside the query window.

**Talk through the controls:** Select each view. The state view shows before and after values. The event view shows a provider-to-index path and reminds the audience that event time and delivery time differ. The combined view states the research problem: compare the evidence without assuming that a nearby event caused the state change.

**Key distinction:** “No matching event in this search” means the searched evidence did not explain the change at that time. It does not prove that nothing happened or that the change was malicious.

## 3. Framework design: two inputs, one deterministic reconciliation process

**Purpose:** Show where the research contribution fits in a security architecture.

**Explain:** CSG collects the state observation and its source health. Wazuh supplies independently collected event evidence. The framework normalizes the event fields needed for comparison, then applies a versioned deterministic rule to the target, event type, operation, and time boundary. The output is a finding with the events that support it, the gaps that remain, and an audit record.

**Emphasize independence:** CSG's state record is not created from a Wazuh event. This matters when the event is late or absent: a state change can remain visible even when the event search cannot yet explain it.

**AI boundary:** The optional assistant comes after the deterministic result. It can help an analyst consider hypotheses or next steps. It cannot create state facts, choose the reconciliation result, change risk or authorization, or take action on an endpoint.

## 4. Matching semantics: relevance requires more than nearby time

**Purpose:** Explain how the system decides whether an event supports a state change.

**Explain the checks in order:** First confirm the endpoint. Then compare the stable identity of the object, such as the exact service name, registry value, process ID, or task action. Check that the event type can describe the operation, and that any before-and-after values agree. Finally, confirm that the timestamp and source health fit the allowed observation boundary.

**Talk through the example:** A service changing Manual → Automatic can be supported by an event for that same service on that same host with compatible values. A same-host event for a different service is a distractor, even if it happened at almost the same time.

**Explain the result labels:** `CONSISTENT` means eligible event evidence supports the observation. `PARTIALLY EXPLAINED` means it supports only part of the observed change. `UNEXPLAINED` means no eligible event explains it in the evidence available for the decision. `CONTRADICTED` means the evidence conflicts. `INSUFFICIENT EVIDENCE` means the system cannot make a safe decision. None of these labels alone establishes malicious intent.

## 5. Research questions

**Purpose:** State what is being evaluated, not just what the application does.

**Primary comparison:** Compare three views of the same kind of change: event-only evidence, state-only observation, and their deterministic reconciliation. The question is whether reconciliation preserves change visibility when event evidence is degraded and whether it improves the quality of the evidence relationship.

**The four questions:**

1. Does independent state observation preserve visibility when event telemetry is delayed, degraded, or unavailable?
2. Can a versioned, latency-aware rule distinguish an event that is merely late from one that is absent at the decision deadline?
3. Can deterministic grouping connect related changes without combining unrelated objects?
4. Does AI guidance improve an analyst's work beyond the same evidence dossier and a fixed playbook?

**Hypothesis shown:** State observation should preserve visibility for persistent changes in the tested gaps, while exact identity checks should reject wrong-object events. This is a testable expectation, not a result about all endpoints or attacks.

## 6. Experimental design

**Purpose:** Make the controlled comparison understandable and show how success was judged.

**Describe one trial:** A trial is one controlled run, not one event row. In a change trial, the service was added and then its startup mode changed, giving two linked transitions to examine. The experiment varied Wazuh event availability/timing and whether a lookalike record named the correct service. It held the Windows 11 ARM64 host, CSG probe, time boundary, identity checks, and scoring rules constant. Outcomes were whether CSG saw the state transition, whether an eligible event was available, and whether reconciliation linked the right event or preserved a gap. No-change trials checked for false findings.

**Explain the animated sequence:** The moving marker follows four steps: make the controlled change; set the event condition; collect state and event evidence; apply the same matching rules. The six selectable conditions show what was changed:

- **All expected events:** both exact service events are available.
- **Events arrive later:** matching records become searchable after a delay.
- **Forwarding interrupted:** the exact event pair is not available in the decision window.
- **Event missing at deadline:** the target record is absent from the bounded search.
- **Event for another service:** a same-host event exists but refers to a different object.
- **Nothing changed:** a control for checking false findings.

**Sample accounting:** Ten runs were assigned to each of the six conditions: 60 planned. Two runs failed during execution and remain visible in the report; they were not silently replaced. The completed set contains 48 service-change trials and 10 no-change checks. In the complete-event and wrong-service conditions, 9 of 10 assigned runs completed; the other conditions had 10 completions each.

**Outcomes:** For each completed change trial, ask whether CSG observed both transitions, whether the exact Wazuh evidence was available at the decision point, and whether reconciliation linked the correct event or kept the gap/distractor explicit. The no-change trials check whether the system creates a target finding when no target change occurred.

**Scope:** These were controlled, benign state changes on one VM. They are useful for evaluating visibility and evidence association, but they are not a malicious-versus-benign attack-detection test.

## 7. Empirical results

**Purpose:** Present the count in words and make the denominator unambiguous.

**Start with the cohort:** The main panel shows the retrospective service study: 60 runs planned, 58 completed, including 48 service-change trials and 10 no-change checks. The two failed runs remain in the accounting, but are not included in the completed-trial outcome counts.

**Explain “19 of 48”:** Each of the 48 completed change trials had two service transitions: service added, then startup mode changed. “19 of 48” means that in 19 trials, Wazuh had **both** exact target events together. It is not “19 events,” not 19 attacks, and not an accuracy score. The animated grid uses one square per completed change trial; blue means both exact events were available. The remaining 29 squares mean at least one of the pair was missing at the decision point.

**Then separate trial pairs from individual events:** Across the 48 trials there were 96 individual transitions. Wazuh had an exact event for 56 of those transitions; 40 had no eligible target event available by the decision point. That is why the count of individual events differs from the number of trials with a complete pair.

**State and reconciliation:** The direct CSG probe observed both planned state changes in all 48 completed change trials. CSG also retained the target finding and made the evidence outcome explicit in all 48: link eligible events, or leave the finding as an evidence gap. This does not mean reconciliation increased the probe's state sensitivity; the state-only probe already saw those changes.

**Controls:** The same-host wrong-service event was rejected in all 9 completed distractor trials. No target finding appeared in the 10 no-change checks.

**Separate follow-up campaigns:** The tabs are distinct studies; do not add their counts together. The service holdout had 30 completed trials: 10 complete-event, 10 wrong-service, and 10 no-change trials. The frozen scorer passed all 30. In its complete condition, exact records appeared in all 10 Wazuh alert-index searches, while the raw archive contained fewer exact records. The registry holdout had 90 trials: 30 complete, 30 bounded-gap with a wrong-value lookalike, and 30 no-change. In the gap group, CSG saw the target value change and rejected the unrelated event in all 30 trials; no target finding appeared in the no-change group.

**Important limit:** These counts come from repeated runs on one Windows endpoint. Registry values and service images were inert; the positive experimental changes were benign. The studies measure the tested mechanism, not detection of real attacks or performance across a population of endpoints. The full result file includes descriptive Wilson intervals; the slide omits them so the trial outcomes are easier to follow.

## 8. Interpretation

**Purpose:** State the contribution and the boundaries of the result.

**Contribution:** CSG did not make more state changes visible than the direct probe in the R2 comparison. Its added value is that it records how the state finding relates to independently collected events: exact support can be cited, a wrong-object lookalike can be rejected, and missing telemetry remains a visible gap instead of being guessed away.

**What the study does not show:** It does not show that every unexplained state change is malicious, that CSG is superior to a full SIEM deployment, or that the result generalizes to other Windows hosts. There was no labeled attack corpus, independent-host replication, or operational SOC comparison in these results.

**Suggested wording:** “These experiments support a narrow mechanism claim: under the tested conditions, independent state observation preserved visibility, and exact-object reconciliation made the evidence relationship auditable.”

## 9. AI response assistance

**Purpose:** Show how a bounded assistant can help analysts move from a fixed finding to focused, evidence-led investigation, and how the research will evaluate that contribution.

**Walk through the workflow:** Deterministic CSG first establishes the finding, risk, and authorization. It packages the target facts, event citations, evidence gaps, and source-health context. The optional language model can then organize that material into cited hypotheses, discriminating evidence to collect, and proportionate response options. The analyst remains responsible for evaluating and acting on the guidance.

**Explain the three study arms:** The evaluation compares the same dossier in three forms: dossier alone, dossier plus a fixed playbook, and dossier plus AI guidance. This design can show whether AI adds practical value beyond both the underlying evidence and a consistent, non-generative checklist. Reviewers can assess actionability, information gained, hypothesis quality, evidence grounding, and safety/proportionality.

**Research progression:** The one-case pilot establishes the bounded workflow and its guardrails. The next stage is a blinded human review of the three conditions, using shared measures to compare their investigative value. Present this as a concrete evaluation plan: the system design is in place, and the study is structured to measure the assistant's incremental contribution.

**Suggested wording:** “The assistant does not decide what happened. It helps an analyst work through a fixed, cited evidence package. Our next experiment compares that guidance with the dossier alone and a standard playbook, so we can measure whether it makes the investigation more useful.”

## 10. Applying the framework: a staged investigation

**Purpose:** End with one practical application of the research ideas. This is the only slide devoted to the lab exercises.

**Explain the options:** “The Expected Service” applies state-to-event matching and rejects same-time lookalikes. “The Overnight Change” follows CSG's startup-mode delta into PowerShell evidence and a temporary telemetry interruption, while distinguishing a plausible explanation from proof that the command succeeded. “The Relay Takes Hold → Final Investigation” follows related process and persistence evidence across multiple adjacent snapshot intervals.

**Close:** Ask learners to begin with the object and before/after attributes recorded by CSG, search Wazuh using those identifiers, check identity and event semantics, and state what remains unknown. The lab is an application of the framework; it is not additional evidence for the research results.
