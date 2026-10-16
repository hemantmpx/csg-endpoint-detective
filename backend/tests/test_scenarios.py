import json
import sys
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"backend"))
from app.catalog import CASES, public_case, scenario_delta_defs, materialize_incident, _incident_variables
from app.generator import generate_case_events, special_event_id, transition_event_id, _transition_event
from app.main import build_inventory, prune_uncovered_transition_events
from sqlalchemy.dialects import postgresql
from types import SimpleNamespace

class ScenarioIntegrityTests(unittest.TestCase):
    def test_all_case_briefings_share_the_student_structure_without_answer_leaks(self):
        required={"scenario","csg_observed","what_this_case_teaches","technical_context","evidence_available","your_task"}
        for case in CASES:
            with self.subTest(case=case["slug"]):
                briefing=case["briefing"]
                self.assertTrue(required.issubset(briefing))
                self.assertTrue(briefing["scenario"] and briefing["your_task"])
                public_text=json.dumps(briefing).lower()
                for private_detail in ("event.id:","7040","7045","5154","unexplained","partially_explained"):
                    self.assertNotIn(private_detail,public_text)

    def test_public_case_does_not_include_answer_fields(self):
        for case in CASES:
            public=json.dumps(public_case(case,"A"))
            self.assertNotIn('"expected"',public)
            self.assertNotIn('"evidence"',public)
            self.assertNotIn("answer_explanations",public)

    def test_noise_seed_is_deterministic_and_large(self):
        case=CASES[0]
        one=generate_case_events(case,"A")
        two=generate_case_events(case,"A")
        self.assertGreaterEqual(len(one),15000)
        self.assertTrue(all(e["scenario_slug"]==case["slug"] and e["variant"]=="A" for e in one))
        self.assertEqual([e["id"] for e in one],[e["id"] for e in two])
        self.assertEqual([e["timestamp"] for e in one],[e["timestamp"] for e in two])

    def test_redacted_sysmon_example_contains_no_original_identifiers(self):
        case=next(c for c in CASES if c["id"]=="case-final")
        event=next(e for e in generate_case_events(case,"A") if e["provenance"]=="redacted_research_structure")
        raw=event["raw"]
        self.assertEqual(raw["data"]["win"]["system"]["eventID"],"13")
        self.assertIn("targetObject",raw["data"]["win"]["eventdata"])
        raw_text=json.dumps(raw)
        self.assertNotIn("Hemant",raw_text)
        self.assertNotIn("S-1-5-21-438591313",raw_text)
        self.assertNotIn("192.168.64.5",raw_text)

    def test_snapshot_pair_contains_only_declared_state_changes(self):
        for case in CASES:
            snapshot_count=len(case.get("incident",{}).get("snapshot_minutes",[30,60]))
            declared=scenario_delta_defs(case,"A")
            snapshot_ids=[]
            for pair_index in range(snapshot_count-1):
                before_id,before,_=build_inventory(case,"A",pair_index)
                after_id,after,_=build_inventory(case,"A",pair_index+1)
                snapshot_ids.extend((before_id,after_id))
                old={o["object_key"]:o["attributes"] for o in before}
                new={o["object_key"]:o["attributes"] for o in after}
                changed={key for key in old.keys()&new.keys() if old[key]!=new[key]}
                added=new.keys()-old.keys();removed=old.keys()-new.keys()
                actual=changed|added|removed
                expected={item["object_key"].casefold() for item in declared if item.get("before_snapshot_index",0)==pair_index}
                actual={key.casefold() for key in actual}
                self.assertEqual(actual,expected,f"{case['slug']} pair {pair_index}")
                self.assertEqual(len(actual),len(expected),f"{case['slug']} pair {pair_index}")
            self.assertEqual(len(set(snapshot_ids)),snapshot_count,case["slug"])

    def test_unexplained_service_cases_have_distinct_distractor_ids(self):
        case=CASES[1]
        good=generate_case_events(case,"A")
        distractor=special_event_id(case,"A","same-object-wrong-transition")
        self.assertIn(distractor,{e["id"] for e in good})
        self.assertNotIn("same-object-wrong-transition",distractor)

    def test_listener_close_never_maps_to_the_listen_permitted_event(self):
        case=next(c for c in CASES if c["id"]=="case-final")
        _,_,transitions=materialize_incident(case,"D")
        by_id={item["id"]:item for item in transitions}
        variables=_incident_variables(case,"D")
        open_event=_transition_event(case,"D",by_id["t-listener-open"],variables)
        self.assertEqual(open_event["event_code"],"5154")
        self.assertEqual(open_event["normalized"]["listener"]["operation"],"open")
        with self.assertRaisesRegex(ValueError,"No independent Windows telemetry mapping"):
            _transition_event(case,"D",by_id["t-listener-close"],variables)
        event_ids={event["id"] for event in generate_case_events(case,"D")}
        self.assertNotIn(transition_event_id(case,"D","t-listener-close"),event_ids)

    def test_startup_prunes_only_rows_for_transitions_declared_missing(self):
        case=next(c for c in CASES if c["id"]=="case-final")
        class DeleteCapture:
            def __init__(self): self.statement=None; self.commits=0
            def execute(self,statement): self.statement=statement; return SimpleNamespace(rowcount=1)
            def commit(self): self.commits+=1
        db=DeleteCapture()
        self.assertEqual(prune_uncovered_transition_events(db,case,"D"),1)
        compiled=db.statement.compile(dialect=postgresql.dialect())
        self.assertIn("final-investigation",repr(compiled.params))
        self.assertIn("D",repr(compiled.params))
        self.assertIn(transition_event_id(case,"D","t-listener-close"),repr(compiled.params))
        self.assertEqual(db.commits,1)

if __name__=="__main__": unittest.main()
