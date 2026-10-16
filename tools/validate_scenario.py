#!/usr/bin/env python3
"""Validate generated scenario packages against the canonical CSG incident catalog."""
import gzip
import json
import re
import sys
from datetime import datetime
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"backend"))
from app.catalog import CASES, VARIANTS, BASE, scenario_delta_defs, materialize_transitions, investigation_defs
from app.generator import generate_case_events, special_event_id, transition_event_id

SECRET=re.compile(r"(?i)(password|api[_-]?key|secret|token)\s*[:=]")
PERSONAL=re.compile(r"(?i)(Hemant|S-1-5-21-438591313|192\.168\.64\.5)")


def load_events(path):
    with gzip.open(path,"rt",encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def validate(root:Path)->list[str]:
    errors=[]
    case=next((item for item in CASES if item["slug"]==root.name),None)
    if case is None: return ["directory does not match an active scenario"]
    required_files={"manifest.json","briefing.md","snapshots.json","deltas.json","transitions.json","events.jsonl.gz","answer-key.private.json"}
    missing=required_files-{p.name for p in root.iterdir()}
    if missing: errors.append("missing scenario files: "+", ".join(sorted(missing)))
    if errors: return errors
    manifest=json.loads((root/"manifest.json").read_text())
    snapshots=json.loads((root/"snapshots.json").read_text())
    deltas=json.loads((root/"deltas.json").read_text())
    transitions=json.loads((root/"transitions.json").read_text())
    answer_key=json.loads((root/"answer-key.private.json").read_text())
    packaged_events=load_events(root/"events.jsonl.gz")
    if manifest.get("id")!=case["id"] or manifest.get("slug")!=case["slug"]: errors.append("manifest does not match catalog identity")
    expected_snapshot_count=len(case.get("incident",{}).get("snapshot_minutes",[30,60]))
    if len(snapshots)!=expected_snapshot_count: errors.append("snapshot package count does not match the canonical observation boundaries")
    else:
        times=[datetime.fromisoformat(item["observed_at"]) for item in snapshots]
        if times!=sorted(times) or len(times)!=len(set(times)): errors.append("snapshot times are not strictly ordered")
        if len({item.get("host_id") for item in snapshots})!=1: errors.append("snapshot hosts do not match")
        for snapshot in snapshots:
            if "inventory" not in snapshot: errors.append("snapshot package must include its generated inventory")
    if len(packaged_events)<case.get("minimum_events",15000): errors.append("event corpus is below configured minimum")
    event_ids=[event["id"] for event in packaged_events]
    if len(event_ids)!=len(set(event_ids)): errors.append("duplicate event IDs")

    expected_deltas=scenario_delta_defs(case,"A")
    if {item["id"] for item in deltas}!={item["id"] for item in expected_deltas}: errors.append("packaged durable deltas differ from canonical state replay")
    expected_transitions=materialize_transitions(case,"A")
    if transitions!=expected_transitions: errors.append("packaged CSG transition history differs from canonical incident definition")
    if any(item.get("source")!="csg" for item in transitions): errors.append("transition history contains a record that is not explicitly CSG-sourced")
    stamps=[datetime.fromisoformat(item["observed_at"]) for item in transitions]
    if stamps!=sorted(stamps): errors.append("CSG transition records are not in timestamp order")
    if snapshots and transitions:
        start=datetime.fromisoformat(snapshots[0]["observed_at"])
        end=datetime.fromisoformat(snapshots[-1]["observed_at"])
        if any(not start<stamp<end for stamp in stamps): errors.append("CSG transition falls outside the snapshot boundaries")

    answers=answer_key.get("answers",[])
    expected_answer_keys={(variant,item["id"]) for variant in VARIANTS for item in investigation_defs(case,variant)}
    actual_answer_keys={(item["variant"],item["delta_id"]) for item in answers}
    if actual_answer_keys!=expected_answer_keys: errors.append("answer key does not cover each variant-specific investigation item exactly once")
    event_sets={"A":set(event_ids)}
    for variant in VARIANTS:
        if variant!="A": event_sets[variant]={event["id"] for event in generate_case_events(case,variant)}
    for answer in answers:
        ids=event_sets.get(answer["variant"],set())
        for field in ("required_evidence_ids","acceptable_evidence_ids","prohibited_distractor_ids"):
            if not set(answer.get(field,[])).issubset(ids): errors.append(f"{answer['variant']} {answer['delta_id']} references an absent event in {field}")

    if case.get("incident"):
        configured={item["transition_id"]:item["coverage"] for item in case["incident"].get("telemetry",[])}
        transition_ids={item["id"] for item in transitions}
        if set(configured)!=transition_ids: errors.append("every CSG transition must have explicit Wazuh coverage configuration")
        for transition_id,coverage in configured.items():
            eid=transition_event_id(case,"A",transition_id)
            present=eid in set(event_ids)
            if (coverage=="recorded")!=present: errors.append(f"Wazuh coverage setting disagrees with generated telemetry for {transition_id}")
        if not case.get("incident",{}).get("initial_state"): errors.append("incident has no explicit Snapshot A state")

    public_text="\n".join((root/name).read_text() for name in ("manifest.json","briefing.md","snapshots.json","deltas.json","transitions.json"))
    if SECRET.search(public_text): errors.append("possible secret found in public scenario files")
    if PERSONAL.search(public_text): errors.append("personal/research identifier found in public scenario files")
    if any(item.get("source")!="csg" for item in transitions): errors.append("CSG transitions are not separate from Wazuh event records")
    return errors


if __name__=="__main__":
    active={case["slug"] for case in CASES}
    roots=[Path(value) for value in sys.argv[1:]] or sorted((ROOT/"scenarios").iterdir())
    failed=False
    if not sys.argv[1:]:
        existing={path.name for path in roots if path.is_dir()}
        if existing!=active:
            print("scenario directories: FAIL")
            print(f"  expected {sorted(active)}, found {sorted(existing)}")
            failed=True
    for root in roots:
        if not root.is_dir(): continue
        errors=validate(root)
        print(f"{root.name}: {'FAIL' if errors else 'OK'}")
        for error in errors: print("  - "+error)
        failed|=bool(errors)
    raise SystemExit(1 if failed else 0)
