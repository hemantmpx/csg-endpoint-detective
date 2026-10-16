#!/usr/bin/env python3
"""Materialize frozen student scenario packages from the canonical backend catalog."""
import gzip
import json
import shutil
import sys
from datetime import timedelta
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"backend"))
from app.catalog import CASES, VARIANTS, BASE, _expand, _incident_variables, target_name, scenario_delta_defs, materialize_transitions, investigation_defs
from app.generator import generate_case_events, special_event_id, transition_event_id
from app.main import build_inventory

RETIRED_SLUGS=("wrong-service","wrong-transition","invisible-process")


def answer_for(case, variant, definition):
    telemetry={item["transition_id"]:item["coverage"] for item in case.get("incident",{}).get("telemetry",[])}
    required=[transition_event_id(case,variant,tid) for tid in definition.get("required_transition_ids",[]) if telemetry.get(tid)=="recorded"]
    required.extend(special_event_id(case,variant,suffix) for suffix in definition.get("required_event_suffixes",[]))
    acceptable=[transition_event_id(case,variant,tid) for tid in definition.get("acceptable_transition_ids",[]) if telemetry.get(tid)=="recorded"]
    acceptable.extend(special_event_id(case,variant,suffix) for suffix in definition.get("acceptable_event_suffixes",[]))
    prohibited=[special_event_id(case,variant,suffix) for suffix in definition.get("prohibited_event_suffixes",[])]
    return {
        "variant":variant,
        "delta_id":definition["id"],
        "expected_classification":definition["expected"],
        "required_evidence_ids":required,
        "acceptable_evidence_ids":acceptable,
        "prohibited_distractor_ids":prohibited,
        "require_all_evidence":definition.get("require_all_evidence",False),
        "explanation":definition["explanation"],
        "learning_notes":case["learning_objective"],
    }


def main():
    for slug in RETIRED_SLUGS:
        path=ROOT/"scenarios"/slug
        if path.exists(): shutil.rmtree(path)

    for case in CASES:
        directory=ROOT/"scenarios"/case["slug"]
        directory.mkdir(parents=True,exist_ok=True)
        manifest={k:case[k] for k in ["id","slug","title","difficulty","timeline_start","timeline_end","snapshot_interval_minutes","noise_seed","minimum_events","seed_version"] if k in case}
        manifest.update({"host":VARIANTS["A"]["host"],"variant_key":"A","provenance":"deterministic fictional classroom telemetry with a separately modeled CSG transition stream"})
        (directory/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
        briefing=_expand(case["briefing"],_incident_variables(case,"A")|{"target":target_name(case,"A")})
        if isinstance(briefing,dict):
            sections=[
                ("Research perspective",briefing.get("research_context","")),
                ("Scenario",briefing.get("scenario","")),
                ("What CSG observed",briefing.get("csg_observed","")),
                ("What this case teaches",briefing.get("what_this_case_teaches","")),
                ("Technical context",briefing.get("technical_context","")),
            ]
            rendered=[f"# {case['title']}"]
            rendered.extend(f"## {heading}\n\n{body}" for heading,body in sections if body)
            evidence=briefing.get("evidence_available",[])
            if evidence:
                rendered.append("## Evidence available to you\n\n"+"\n".join(f"- **{item['name']}:** {item['description']}" for item in evidence))
            task=briefing.get("your_task","")
            if task: rendered.append(f"## Your task\n\n{task}")
            briefing_text="\n\n".join(rendered)+"\n"
        else:
            briefing_text=f"# {case['title']}\n\n{briefing}\n"
        (directory/"briefing.md").write_text(briefing_text)

        snapshots=[]
        minutes=case.get("incident",{}).get("snapshot_minutes",[30,60])
        for index,minute in enumerate(minutes):
            snapshot_id=f"{case['id']}-A-snapshot-{index+1}"
            _,inventory,header=build_inventory(case,"A",index)
            snapshots.append(header|{"observed_at":(BASE+timedelta(minutes=minute)).isoformat(),"inventory_source":"canonical scenario state replay plus deterministic classroom baseline inventory","inventory":inventory})
        (directory/"snapshots.json").write_text(json.dumps(snapshots,indent=2)+"\n")

        public_deltas=[]
        for item in scenario_delta_defs(case,"A"):
            before_ix=item.get("before_snapshot_index",0)
            after_ix=item.get("after_snapshot_index",len(snapshots)-1)
            public_deltas.append({k:v for k,v in item.items() if k not in {"expected","evidence","object_template"}}|{
                "before_snapshot_id":snapshots[before_ix]["snapshot_id"],
                "after_snapshot_id":snapshots[after_ix]["snapshot_id"],
                "observation_window":{"start":snapshots[before_ix]["observed_at"],"end":snapshots[after_ix]["observed_at"]},
            })
        (directory/"deltas.json").write_text(json.dumps(public_deltas,indent=2)+"\n")
        (directory/"transitions.json").write_text(json.dumps(materialize_transitions(case,"A"),indent=2)+"\n")

        answers=[]
        for variant in VARIANTS:
            answers.extend(answer_for(case,variant,item) for item in investigation_defs(case,variant))
        (directory/"answer-key.private.json").write_text(json.dumps({"scenario_id":case["id"],"answers":answers},indent=2)+"\n")

        events=generate_case_events(case,"A")
        with gzip.open(directory/"events.jsonl.gz","wt",encoding="utf-8") as handle:
            for event in events: handle.write(json.dumps(event,separators=(",",":"),default=str)+"\n")
        print(f"{case['slug']}: {len(events):,} frozen events; {len(public_deltas)} durable deltas; {len(materialize_transitions(case,'A'))} CSG transitions")

if __name__=="__main__": main()
