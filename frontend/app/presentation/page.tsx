"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import {
  Activity, ArrowDown, ArrowLeft, ArrowRight, BrainCircuit,
  Check, ChevronLeft, ChevronRight, Clock3, Expand, Fingerprint,
  GitMerge, Layers3, Minimize2, RotateCcw, Search, Shield,
  ShieldCheck, X,
} from "lucide-react";
import ThemeToggle from "../theme-toggle";
import DeveloperCredit from "../developer-credit";
import "./presentation.css";

type Slide = { section: string; title: string; subtitle: string; takeaway: string };
type EvidenceView = "state" | "events" | "combined";
type ResultSet = "r2" | "service" | "registry";

const slides: Slide[] = [
  {
    section: "TITLE",
    title: "CyberStateGuardian:\nreconciling endpoint state\nand event telemetry",
    subtitle: "A transition-aware framework and controlled evaluation of persistent host state with Wazuh event evidence.",
    takeaway: "Hemant Upadhyay · Research conducted under the guidance and support of Dr. Shuja",
  },
  {
    section: "01 · PROBLEM FORMULATION",
    title: "Persistent state and\nevent telemetry measure\ndifferent things.",
    subtitle: "A snapshot records what a probe observes at a collection boundary. Event telemetry records activity reported by event sources.",
    takeaway: "The research problem is whether independent observations can be reconciled without treating time proximity as causality.",
  },
  {
    section: "02 · FRAMEWORK DESIGN",
    title: "Two independent inputs\nfeed one deterministic\nreconciliation process.",
    subtitle: "The CSG probe supplies authoritative state; Wazuh supplies independently collected Windows and Sysmon event evidence.",
    takeaway: "State deltas remain independent of event rows; reconciliation records how the sources agree, disagree, or leave a gap.",
  },
  {
    section: "03 · MATCHING SEMANTICS",
    title: "A candidate event must\nexplain this transition\non this endpoint.",
    subtitle: "CSG evaluates host, expected event type, stable target identity, operation, transition values, and a justified time boundary.",
    takeaway: "An exact match supports consistency; missing evidence remains explicit, while an unrelated same-host event is rejected.",
  },
  {
    section: "04 · RESEARCH QUESTIONS",
    title: "The research tests\nvisibility, association,\nand analyst assistance.",
    subtitle: "The central comparison is event-only evidence versus state-only observation versus their deterministic reconciliation.",
    takeaway: "Each question needs a distinct outcome measure: detection visibility is not the same as evidence quality or analyst utility.",
  },
  {
    section: "05 · EXPERIMENTAL DESIGN",
    title: "The study isolates event\navailability and object\nidentity.",
    subtitle: "Controlled service trials change the Wazuh evidence condition while keeping the endpoint probe and matching rules fixed.",
    takeaway: "Each trial asks: did CSG see the change, did Wazuh have the right event, and did reconciliation link only valid evidence?",
  },
  {
    section: "06 · EMPIRICAL RESULTS",
    title: "CSG saw each tested\nstate change; complete\nWazuh pairs were less common.",
    subtitle: "Of 48 completed service-change trials, Wazuh had both exact event records in 19 trials—about four in ten.",
    takeaway: "That is a count of trials with both events, not every event. The next slide makes the comparison explicit.",
  },
  {
    section: "07 · INTERPRETATION",
    title: "Reconciliation adds\nmeaning to a state finding.\nIt does not add probe hits.",
    subtitle: "The main result is complementary evidence: CSG retained the state change, while Wazuh event availability varied by trial.",
    takeaway: "The added result is the auditable relationship—CONSISTENT or UNEXPLAINED—not increased state sensitivity over the probe.",
  },
  {
    section: "08 · AI RESPONSE ASSISTANCE",
    title: "AI helps turn a fixed\nfinding into evidence-led\ninvestigative guidance.",
    subtitle: "After deterministic reconciliation, a bounded evidence dossier can support cited hypotheses and focused next steps.",
    takeaway: "The pilot establishes the guarded workflow; a three-arm review will measure its value against a dossier and fixed playbook.",
  },
  {
    section: "09 · APPLICATION",
    title: "Applying the framework:\na staged investigation.",
    subtitle: "The final exercise moves from one state delta to a multi-stage case, using the same research logic at each step.",
    takeaway: "Begin with the object CSG observed; use its stable attributes to search Wazuh; explain exact matches and remaining gaps.",
  },
];

const conditions = [
  { id: "complete", name: "All expected events", n: "9 completed · 10 assigned", setup: "Both exact service events are available.", expected: "CSG observes both service changes.", result: "The exact events support a CONSISTENT finding.", tone: "complete" },
  { id: "delayed", name: "Events arrive later", n: "10 completed · 10 assigned", setup: "The matching events become searchable after a delay.", expected: "CSG observes both service changes.", result: "The events are linked after retrieval.", tone: "complete" },
  { id: "interruption", name: "Forwarding interrupted", n: "10 completed · 10 assigned", setup: "The exact event pair is unavailable in the decision window.", expected: "CSG observes both service changes.", result: "Keep the change visible; do not invent an event link.", tone: "gap" },
  { id: "capture", name: "Event missing at deadline", n: "10 completed · 10 assigned", setup: "The target event is absent from the bounded search.", expected: "CSG observes both service changes.", result: "Record an evidence gap as UNEXPLAINED.", tone: "gap" },
  { id: "distractor", name: "Event for another service", n: "9 completed · 10 assigned", setup: "A same-host event exists, but names a different service.", expected: "CSG observes the target service changes.", result: "Reject the lookalike; do not cite it as the match.", tone: "reject" },
  { id: "nochange", name: "Nothing changed", n: "10 completed · 10 assigned", setup: "No service change is made; this checks for false findings.", expected: "No target delta should appear.", result: "No target finding should be produced.", tone: "neutral" },
];

const resultSets: Record<ResultSet, {
  label: string; heading: string; subheading: string;
  metrics: { label: string; value: string; detail: string; percent: number; tone: string }[];
  trialMarks: { total: number; positive: number; caption: string; positiveLabel: string; otherLabel: string };
  finding: string; limitation: string;
}> = {
  r2: {
    label: "Service comparison · R2",
    heading: "Retrospective service study",
    subheading: "60 trials planned · 58 completed · 48 service changes + 10 no-change checks · 2 failures kept in the record",
    metrics: [
      { label: "Both exact Wazuh events", value: "19 of 48 trials", detail: "About 4 in 10 trials had both the service-install and start-mode event.", percent: 39.6, tone: "blue" },
      { label: "State seen by CSG", value: "All 48 trials", detail: "The probe observed both planned service changes in every completed change trial.", percent: 100, tone: "green" },
      { label: "Reconciliation outcome", value: "All 48 trials", detail: "CSG kept the state finding and linked valid events or recorded a gap.", percent: 100, tone: "violet" },
    ],
    trialMarks: { total: 48, positive: 19, caption: "Each square is one completed service-change trial. Blue means both exact Wazuh events were found.", positiveLabel: "19 had both events", otherLabel: "29 did not have a complete pair" },
    finding: "Each trial contained two service transitions, for 96 in total. Wazuh had exact events for 56 individual transitions; for 40, no eligible target event was available at the decision point. Same-host lookalikes were rejected in 9 of 9 completed trials, and the 10 no-change checks produced no false target finding.",
    limitation: "Retrospective analysis · one Windows 11 ARM64 VM · benign controlled changes. This does not measure attack-detection accuracy.",
  },
  service: {
    label: "Service holdout · v3",
    heading: "Prospective service holdout",
    subheading: "30 trials · 10 with expected events · 10 with a wrong-service lookalike · 10 with no change · one Windows host",
    metrics: [
      { label: "Expected events", value: "10 of 10", detail: "Both exact service events were linked to the CSG changes.", percent: 100, tone: "green" },
      { label: "Wrong-service event", value: "10 of 10", detail: "The same-host lookalike was rejected every time.", percent: 100, tone: "violet" },
      { label: "No-change check", value: "10 of 10", detail: "No target finding appeared when nothing changed.", percent: 100, tone: "blue" },
    ],
    trialMarks: { total: 10, positive: 10, caption: "These squares show the 10-trial complete-event condition, not all 30 holdout trials.", positiveLabel: "exact event matched", otherLabel: "no exact event" },
    finding: "All 30 trials passed the frozen scoring rules. The service image was safe, inert, and never executed. In the complete condition, exact events appeared in Wazuh's alert index in all 10 trials; the raw archive index contained fewer exact records, so source/index choice matters.",
    limitation: "Repeated trials on one Windows host; the small sample gives wide uncertainty. Temporary forwarding interruption is not a test of permanent event loss.",
  },
  registry: {
    label: "Registry holdout · v1",
    heading: "Prospective registry holdout",
    subheading: "90 trials · 30 with the target event · 30 with a wrong-value lookalike · 30 with no change · one endpoint",
    metrics: [
      { label: "Target event available", value: "30 of 30", detail: "CSG linked the exact event to the registry change.", percent: 100, tone: "green" },
      { label: "Target event missing", value: "30 of 30", detail: "CSG still observed the changed registry value.", percent: 100, tone: "blue" },
      { label: "Wrong-value lookalike", value: "30 of 30", detail: "The unrelated event was rejected; the evidence gap remained visible.", percent: 100, tone: "violet" },
    ],
    trialMarks: { total: 30, positive: 30, caption: "These squares show the 30-trial complete-event condition, not all 90 registry trials.", positiveLabel: "exact event matched", otherLabel: "no exact event" },
    finding: "In the 30 gap trials, a same-host event of the right general type referred to a different registry value. CSG kept the target state change and rejected that lookalike. All 30 no-change checks also produced no target finding.",
    limitation: "The registry values were inert and never executed. One endpoint and bounded gaps do not establish malicious intent, permanent event loss, or general performance.",
  },
};

function Visual({ index }: { index: number }) {
  const [evidenceView, setEvidenceView] = useState<EvidenceView>("combined");
  const [conditionId, setConditionId] = useState("interruption");
  const [resultSet, setResultSet] = useState<ResultSet>("r2");
  const [aiView, setAiView] = useState("assistant");
  const [exercise, setExercise] = useState("service");

  if (index === 0) return <div className="hero-orbit research-orbit" aria-label="Independent state and event data entering reconciliation">
    <div className="orbit orbit-one"/><div className="orbit orbit-two"/><div className="orbit orbit-three"/>
    <div className="orbit-core"><GitMerge size={32}/><span>CSG FRAMEWORK</span></div>
    <div className="orbit-node state-node"><Layers3/><b>STATE PLANE</b><small>persistent observations</small></div>
    <div className="orbit-node event-node"><Activity/><b>EVENT PLANE</b><small>Windows · Sysmon</small></div>
    <div className="orbit-node context-node"><Fingerprint/><b>RECONCILIATION</b><small>identity · operation · time</small></div>
    <div className="orbit-spark spark-a"/><div className="orbit-spark spark-b"/><div className="orbit-spark spark-c"/>
  </div>;

  if (index === 1) {
    const content: Record<EvidenceView, { title: string; text: string; label: string }> = {
      state: { title: "State is a sampled assertion", text: "At capture A, a service is absent or configured Manual. At capture B, it is present or configured Automatic. The delta narrows the change to an interval; it does not name the actor or every action in between.", label: "PERSISTENT STATE · SNAPSHOT A → SNAPSHOT B" },
      events: { title: "Telemetry is a reported event stream", text: "Windows and Sysmon records describe events observed by configured providers and delivered through Wazuh. A missing record can reflect collection, forwarding, indexing, or query boundaries.", label: "TRANSIENT TELEMETRY · PROVIDER → AGENT → INDEX" },
      combined: { title: "The two sources answer different questions", text: "A state delta says that an object changed. A Wazuh event may explain how. Exact identity and compatible transition fields connect them; an absent event leaves a visible evidence gap.", label: "RESEARCH OBJECT · STATE CHANGE ↔ EVENT EVIDENCE" },
    };
    const selected = content[evidenceView];
    return <div className="evidence-explorer">
      <div className="explorer-tabs" role="group" aria-label="Explore the evidence planes">
        {([["state", "State snapshots"], ["events", "Event telemetry"], ["combined", "Research problem"]] as [EvidenceView, string][]).map(([id, label]) => <button key={id} className={evidenceView === id ? "active" : ""} onClick={() => setEvidenceView(id)} aria-pressed={evidenceView === id}>{label}</button>)}
      </div>
      <div className="explorer-content" key={evidenceView}>
        <div className="explorer-copy"><small>{selected.label}</small><h3>{selected.title}</h3><p>{selected.text}</p></div>
        <div className={`plane-demo plane-demo-${evidenceView}`}>
          <div className="plane-snapshot"><span>A · CAPTURE</span><b>{evidenceView === "events" ? "event source" : "service state"}</b><small>{evidenceView === "events" ? "System · Sysmon" : "Manual · absent"}</small></div>
          <div className="plane-interval"><i/><b>{evidenceView === "events" ? "reported activity" : evidenceView === "state" ? "state transition" : "reconcile"}</b><i/></div>
          <div className="plane-snapshot after"><span>B · CAPTURE</span><b>{evidenceView === "events" ? "indexed record" : "service state"}</b><small>{evidenceView === "events" ? "may be delayed or missing" : "Automatic · present"}</small></div>
          <div className="plane-timeline"><Clock3 size={13}/><span>{evidenceView === "events" ? "event time ≠ guaranteed delivery time" : "transition occurred within an observation interval"}</span></div>
        </div>
      </div>
      <div className="explorer-foot"><span><Layers3/> sampled state</span><span><Activity/> reported event</span><span><GitMerge/> exact association is tested</span></div>
    </div>;
  }

  if (index === 2) return <div className="architecture-visual research-architecture">
    <div className="arch-host-boundary"><span>WINDOWS ENDPOINT</span><div className="arch-inputs">
      <div className="arch-source csg-source"><Layers3/><span><b>Native CSG probe</b><small>authoritative state source</small></span></div>
      <div className="arch-source wazuh-source"><Activity/><span><b>Windows + Sysmon</b><small>collected through Wazuh</small></span></div>
    </div></div>
    <div className="arch-fan-in"><div/><div/><ArrowDown/></div>
    <div className="research-flow"><div className="flow-step"><b>01</b><span><strong>Snapshot + source health</strong><small>timestamped state objects</small></span></div><div className="flow-step"><b>02</b><span><strong>Normalize event evidence</strong><small>provider-independent fields</small></span></div></div>
    <div className="arch-down"><ArrowDown/></div>
    <div className="arch-engine"><GitMerge/><span><b>Versioned deterministic reconciliation</b><small>target · event type · operation · time boundary</small></span><Check/></div>
    <div className="arch-down"><ArrowDown/></div>
    <div className="arch-result"><ShieldCheck/><span><b>Finding + evidence dossier</b><small>matched events · gaps · audit record</small></span></div>
    <div className="arch-ai"><div className="ai-chip"><BrainCircuit/><span><b>Optional post-reconciliation assistant</b><small>bounded evidence → investigative guidance</small></span></div><div className="ai-guardrail"><Shield size={14}/> The model cannot author CSG facts or change findings, risk, authorization, or reconciliation.</div></div>
  </div>;

  if (index === 3) return <div className="reconcile-visual">
    <div className="reconcile-gates">
      {[["01", "Host", "same endpoint identity"], ["02", "Target", "stable object key"], ["03", "Operation", "expected transition"], ["04", "Boundary", "event time + source health"]].map(([n, label, detail]) => <div className="gate" key={n}><b>{n}</b><span>{label}<small>{detail}</small></span><Check/></div>)}
    </div>
    <div className="gate-out"><ArrowDown/><span>eligible evidence</span></div>
    <div className="outcome-row"><div className="outcome consistent"><span/>CONSISTENT<small>exact support</small></div><div className="outcome partial"><span/>PARTIALLY EXPLAINED<small>incomplete support</small></div><div className="outcome gap"><span/>UNEXPLAINED<small>evidence gap</small></div><div className="outcome contradicted"><span/>CONTRADICTED<small>conflicting evidence</small></div><div className="outcome insufficient"><span/>INSUFFICIENT EVIDENCE<small>cannot decide</small></div></div>
    <div className="reconcile-note"><Shield size={15}/> Time proximity makes a candidate. Identity and transition semantics establish whether it is relevant.</div>
    <div className="reconcile-example"><div><small>CSG DELTA</small><b>Service A · Manual → Automatic</b></div><ArrowRight/><div className="valid"><small>WAZUH EVENT</small><b>Same host + service + 7040 values</b></div><div className="reject-example"><X/><span>Same host, different service: reject as target evidence</span></div></div>
  </div>;

  if (index === 4) return <div className="research-visual research-question-board">
    <div className="research-primary"><small>PRIMARY COMPARATIVE QUESTION</small><p>What additional state-change visibility and evidence-association value does deterministic reconciliation provide over <em>event-only</em> and <em>state-only</em> baselines?</p><div><span>complete telemetry</span><span>interrupted / bounded gap</span><span>same-host distractor</span></div></div>
    <div className="research-grid">
      <div><b>RQ1</b><span>Does independent state observation retain change visibility when event telemetry is degraded or unavailable?</span></div>
      <div><b>RQ2</b><span>Can versioned, latency-aware reconciliation distinguish delayed evidence from evidence absent at a deadline?</span></div>
      <div><b>RQ3</b><span>Can deterministic incident grouping link related changes without merging unrelated findings?</span></div>
      <div className="ai-rq"><b>RQ4</b><span>Does grounded AI guidance add value beyond the same evidence dossier and a fixed playbook?</span></div>
    </div>
    <div className="hypothesis-strip"><span>H1</span> State preserves persistent-change visibility during tested event gaps; exact matching rejects wrong-object telemetry.</div>
  </div>;

  if (index === 5) {
    const condition = conditions.find((item) => item.id === conditionId) ?? conditions[0];
    return <div className="method-visual">
      <div className="method-meta"><div><small>R2 · ONE WINDOWS 11 ARM64 HOST</small><b>One controlled service-change procedure</b></div><span>60 planned · 58 completed · 2 failures retained</span></div>
      <div className="protocol-flow" aria-label="Trial procedure: make a controlled change, set the event condition, collect state and event evidence, then apply the same match rules">
        <div className="protocol-step"><i>01</i><b>Make a change</b><small>Manual → Automatic</small></div>
        <div className="protocol-step"><i>02</i><b>Set the condition</b><small>Change event availability</small></div>
        <div className="protocol-step"><i>03</i><b>Collect evidence</b><small>CSG state + Wazuh events</small></div>
        <div className="protocol-step"><i>04</i><b>Score the result</b><small>Same exact-match rules</small></div>
      </div>
      <div className="method-section-label"><span>Choose a condition</span><small>Five change conditions + one no-change control · 10 trials planned in each</small></div>
      <div className="condition-picker" role="group" aria-label="Select an experimental condition">{conditions.map((item) => <button key={item.id} className={conditionId === item.id ? `selected ${item.tone}` : ""} onClick={() => setConditionId(item.id)} aria-pressed={conditionId === item.id}><span>{item.name}</span><small>{item.n}</small></button>)}</div>
      <div className={`condition-result condition-${condition.tone}`} key={condition.id}>
        <div className="condition-title"><span>WHAT CHANGES IN THIS CONDITION</span><b>{condition.name}</b><small>{condition.n}</small></div>
        <div className="condition-columns"><div><Activity/><small>WAZUH SETUP</small><b>{condition.setup}</b></div><div><Layers3/><small>STATE CHECK</small><b>{condition.expected}</b></div><div><GitMerge/><small>EXPECTED DECISION</small><b>{condition.result}</b></div></div>
      </div>
      <div className="method-rigor"><span><Activity/> Varied: event availability and target identity</span><span><Layers3/> Measured: state seen, valid event, correct finding</span><span><Check/> Fixed: host, probe, time boundary, and scoring rules</span><span><X/> Failed runs stay counted; not replaced</span></div>
      <div className="method-note">The 58 completed runs were 48 change trials and 10 no-change checks. Each change trial included two linked service transitions: service added, then start mode changed.</div>
    </div>;
  }

  if (index === 6) {
    const data = resultSets[resultSet];
    return <div className="results-explorer">
      <div className="result-tabs" role="group" aria-label="Choose a research result set">{(Object.entries(resultSets) as [ResultSet, typeof data][]).map(([id, item]) => <button key={id} className={resultSet === id ? "active" : ""} onClick={() => setResultSet(id)} aria-pressed={resultSet === id}>{item.label}</button>)}</div>
      <div className="result-heading"><div><small>FROZEN RESEARCH DATA</small><h3>{data.heading}</h3></div><p>{data.subheading}</p></div>
      <div className="result-metrics" key={resultSet}>{data.metrics.map((metric) => <div className={`result-metric ${metric.tone}`} key={metric.label}><small>{metric.label}</small><b>{metric.value}</b><i>{metric.detail}</i><div className="metric-track"><i style={{ width: `${metric.percent}%` }}/></div></div>)}</div>
      <div className="trial-visual" key={`${resultSet}-trial-marks`}>
        <div className="trial-visual-head"><div><small>HOW TO READ THE COUNT</small><b>{data.trialMarks.caption}</b></div><span>{data.trialMarks.positiveLabel}</span></div>
        <div className={`trial-markers ${resultSet === "r2" ? "many-markers" : ""}`} role="img" aria-label={`${data.trialMarks.positive} of ${data.trialMarks.total} trials: ${data.trialMarks.positiveLabel}; remaining trials: ${data.trialMarks.otherLabel}`}>
          {Array.from({ length: data.trialMarks.total }, (_, i) => <i key={i} className={i < data.trialMarks.positive ? "matched" : ""} style={{ "--mark-delay": `${Math.min(i, 19) * 24}ms` } as React.CSSProperties} />)}
        </div>
        <div className="trial-legend"><span><i className="legend-match"/>{data.trialMarks.positive} {data.trialMarks.positiveLabel}</span><span><i/>{data.trialMarks.total - data.trialMarks.positive} {data.trialMarks.otherLabel}</span></div>
      </div>
      <div className="result-finding"><GitMerge/><p>{data.finding}</p></div>
      <div className="result-limit"><Shield size={14}/><span>{data.limitation}</span></div>
    </div>;
  }

  if (index === 7) return <div className="interpretation-visual">
    <div className="interpretation-row observed"><div className="interpretation-index">01</div><div><small>OBSERVED</small><h3>CSG kept the state change visible.</h3><p>It observed both service changes in all 48 completed change trials. Wazuh had both exact events together in 19 trials; some exact events were still present in other trials.</p></div><div className="interpretation-mark"><Layers3/></div></div>
    <div className="interpretation-row contribution"><div className="interpretation-index">02</div><div><small>INCREMENTAL VALUE</small><h3>CSG made the state-to-event relationship explicit.</h3><p>Exact events were linked as supporting evidence; missing target events remained visible as gaps. Same-host events for a different service were rejected.</p></div><div className="interpretation-mark"><GitMerge/></div></div>
    <div className="interpretation-row boundary"><div className="interpretation-index">03</div><div><small>NOT ESTABLISHED</small><h3>Attack-detection efficacy, superiority, and generalization.</h3><p>The changes were benign and controlled; repeated trials were performed on one Windows 11 ARM64 VM. No labeled attack corpus or independent-host replication is in these results.</p></div><div className="interpretation-mark"><Shield/></div></div>
    <div className="interpretation-callout">Interpret the result as <b>retained state visibility + auditable evidence association</b>, not as a claim that every unexplained change is malicious.</div>
  </div>;

  if (index === 8) {
    const aiText: Record<string, { label: string; text: string; role: string }> = {
      dossier: { label: "CSG evidence dossier", text: "Persisted CSG facts, target delta, event matches or gaps, reconciliation status, source health, authorization, risk, and evidence identifiers.", role: "DETERMINISTIC BASELINE" },
      playbook: { label: "Dossier + fixed playbook", text: "The same evidence plus a reproducible category-specific investigation checklist. Controls for receiving any advice at all.", role: "NON-GENERATIVE GUIDANCE BASELINE" },
      assistant: { label: "Dossier + AI guidance", text: "The same bounded evidence package plus cited hypotheses, discriminating evidence requests, and proportionate response options.", role: "MODEL-ASSISTED CONDITION" },
    };
    const selected = aiText[aiView];
    return <div className="ai-study-visual">
      <div className="ai-flow-line"><div className="ai-flow-node fixed"><GitMerge/><span><b>Deterministic CSG</b><small>finding + risk + authorization fixed</small></span></div><ArrowRight/><div className="ai-flow-node package"><Layers3/><span><b>Bounded evidence package</b><small>target-scoped · hashed · untrusted text</small></span></div><ArrowRight/><div className="ai-flow-node model"><BrainCircuit/><span><b>Optional language model</b><small>guidance only</small></span></div></div>
      <div className="ai-review-box">
        <div className="ai-review-head"><div><small>THREE-ARM EVALUATION DESIGN</small><b>Same dossier · different assistance</b></div><span>MEASURE VALUE OVER BASELINES</span></div>
        <div className="ai-condition-tabs" role="group" aria-label="Compare AI study review conditions">{Object.entries(aiText).map(([id, item]) => <button key={id} className={aiView === id ? "active" : ""} onClick={() => setAiView(id)} aria-pressed={aiView === id}>{item.label}</button>)}</div>
        <div className="ai-condition-copy" key={aiView}><small>{selected.role}</small><p>{selected.text}</p></div>
        <div className="ai-outcomes"><span>Next-step actionability</span><span>Information gain</span><span>Hypothesis quality</span><span>Evidence grounding</span><span>Safety + proportionality</span></div>
      </div>
      <div className="ai-integrity"><ShieldCheck/><span><b>Guardrails</b> schema validation · evidence-ID checks · failure recorded · CSG facts rendered separately · blinded human semantic review</span></div>
      <div className="ai-limit">Current stage: one-case bounded workflow pilot. Next: blinded review comparing the dossier, fixed playbook, and AI-guided outputs.</div>
    </div>;
  }

  const exercises: Record<string, { label: string; title: string; objective: string; task: string; stage: string }> = {
    service: { label: "State/event baseline", title: "The Expected Service", objective: "Assess whether event telemetry corroborates a persistent service change.", task: "Match host, service identity, operation, start-mode values, and interval; reject same-time lookalikes.", stage: "ONE SNAPSHOT DELTA · ONE TARGET OBJECT" },
    gap: { label: "Bounded telemetry gap", title: "The Overnight Change", objective: "Trace the state finding into process evidence when the native service-change event is missing.", task: "Pivot on the service path, inspect the PowerShell process chain and forwarder events, then state what the absent 7040 does and does not prove.", stage: "STATE PIVOT · TELEMETRY GAP · QUALIFIED CONCLUSION" },
    linked: { label: "Multi-stage correlation", title: "The Relay Takes Hold → Final Investigation", objective: "Follow related activity across adjacent captures and transient events.", task: "Connect service and process identity to later persistence artifacts; classify each evidence relationship separately.", stage: "A → B → C · MULTIPLE OBJECTS · DIFFERENT EVIDENCE STATUS" },
  };
  const selectedExercise = exercises[exercise];
  return <div className="labs-visual handoff-visual">
    <div className="exercise-tabs" role="group" aria-label="Explore the applied exercises">{Object.entries(exercises).map(([id, item]) => <button key={id} className={exercise === id ? "active" : ""} onClick={() => setExercise(id)} aria-pressed={exercise === id}>{item.label}</button>)}</div>
    <div className="exercise-card" key={exercise}><div className="exercise-number">APPLIED EXERCISE · {String(Object.keys(exercises).indexOf(exercise) + 1).padStart(2, "0")}</div><small>{selectedExercise.stage}</small><h3>{selectedExercise.title}</h3><p>{selectedExercise.objective}</p><div className="exercise-task"><Search/><span><b>Investigation task</b>{selectedExercise.task}</span></div></div>
    <div className="lab-method"><span>CSG OBSERVATION</span><ArrowRight/><span>WAZUH PIVOT</span><ArrowRight/><span>FIELD CHECK</span><ArrowRight/><span>RECONCILE</span></div>
    <Link href="/" className="start-lab"><ArrowRight size={16}/> Open the investigation interface</Link>
  </div>;
}

export default function PresentationPage() {
  const [active, setActive] = useState(0);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const deckRef = useRef<HTMLElement>(null);

  const go = useCallback((next: number) => setActive(Math.max(0, Math.min(slides.length - 1, next))), []);
  const toggleFullscreen = useCallback(async () => {
    if (!document.fullscreenElement) await deckRef.current?.requestFullscreen?.();
    else await document.exitFullscreen?.();
  }, []);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.altKey || event.ctrlKey || event.metaKey) return;
      if (["ArrowRight", "PageDown", " "].includes(event.key)) { event.preventDefault(); setActive((n) => Math.min(slides.length - 1, n + 1)); }
      if (["ArrowLeft", "PageUp"].includes(event.key)) { event.preventDefault(); setActive((n) => Math.max(0, n - 1)); }
      if (event.key === "Home") setActive(0);
      if (event.key === "End") setActive(slides.length - 1);
    };
    const onFullscreen = () => setIsFullscreen(Boolean(document.fullscreenElement));
    window.addEventListener("keydown", onKeyDown);
    document.addEventListener("fullscreenchange", onFullscreen);
    return () => { window.removeEventListener("keydown", onKeyDown); document.removeEventListener("fullscreenchange", onFullscreen); };
  }, []);

  const slide = slides[active];
  return <main className="presentation-shell" ref={deckRef}>
    <div className="presentation-atmosphere" aria-hidden="true"><i/><i/><i/></div>
    <header className="presentation-topbar">
      <Link className="presentation-back" href="/" aria-label="Return to home"><ArrowLeft size={16}/><span>Home</span></Link>
      <div className="presentation-mark"><span>CYBERSTATEGUARDIAN</span><i/>RESEARCH PRESENTATION</div>
      <div className="presentation-tools"><span className="keyboard-hint">← → <small>navigate</small></span><ThemeToggle/><button className="fullscreen-button" onClick={toggleFullscreen} aria-label={isFullscreen ? "Exit fullscreen" : "Enter fullscreen"}>{isFullscreen ? <Minimize2 size={16}/> : <Expand size={16}/>}</button></div>
    </header>
    <section className="presentation-stage" aria-label="CyberStateGuardian research presentation" aria-live="polite">
      <div className="slide-index"><span>{String(active + 1).padStart(2, "0")}</span><i/>10</div>
      <article className="presentation-slide" key={active}>
        <div className={`slide-copy slide-copy-${active}`}><div className="slide-kicker"><span/>{slide.section}</div><h1>{slide.title}</h1><p>{slide.subtitle}</p><div className={`slide-cue ${active === 0 ? "title-byline" : ""}`}><span>{active === 0 ? "AUTHOR" : "TAKEAWAY"}</span>{slide.takeaway}</div></div>
        <div className={`slide-visual slide-visual-${active}`}><Visual index={active}/></div>
      </article>
      <div className="presentation-controls"><button className="nav-arrow" onClick={() => go(active - 1)} disabled={active === 0} aria-label="Previous slide"><ChevronLeft size={20}/></button><div className="slide-progress" aria-label={`Slide ${active + 1} of ${slides.length}`}><div className="progress-track"><i style={{ width: `${((active + 1) / slides.length) * 100}%` }}/></div><span>{String(active + 1).padStart(2, "0")} <small>/ 10</small></span></div><div className="slide-dots" aria-label="Choose a slide">{slides.map((item, n) => <button key={item.section} className={n === active ? "active" : ""} onClick={() => go(n)} aria-label={`Go to slide ${n + 1}: ${item.section}`} aria-current={n === active ? "step" : undefined}/>)}</div><button className="nav-arrow next-arrow" onClick={() => go(active === slides.length - 1 ? 0 : active + 1)} aria-label={active === slides.length - 1 ? "Return to title slide" : "Next slide"}>{active === slides.length - 1 ? <RotateCcw size={17}/> : <ChevronRight size={20}/>}</button></div>
    </section>
    <footer className="presentation-footer"><DeveloperCredit/></footer>
  </main>;
}
