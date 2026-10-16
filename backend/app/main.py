from __future__ import annotations

import csv
import hashlib
import hmac
import io
import os
from copy import deepcopy
from pathlib import Path
import re
import uuid
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, select, func, cast, String, and_, or_, delete, distinct
from sqlalchemy.orm import sessionmaker, Session

from .catalog import CASES, VARIANTS, BASE, case_by_slug, public_case, materialize_delta, scenario_delta_defs, materialize_transitions, investigation_defs, materialize_incident, materialize_snapshot_states
from .generator import generate_case_events, malicious_context_events, transition_event_id, special_event_id
from .models import Base, Event, StudentSession, EvidenceSelection, Submission, SearchHistory, LabControl, ScenarioSeed

UTC = timezone.utc
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://csg:csg@localhost:5432/csg_classroom")
engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=30, max_overflow=30)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
CLASS_CODE = os.getenv("CLASS_CODE", "CY530")
ADDITIONAL_CLASS_CODES = tuple(
    code.strip().casefold()
    for code in os.getenv("ADDITIONAL_CLASS_CODES", "").split(",")
    if code.strip()
)
ACCEPTED_CLASS_CODES = tuple(dict.fromkeys((CLASS_CODE.strip().casefold(), *ADDITIONAL_CLASS_CODES)))
INSTRUCTOR_PASSWORD = os.getenv("INSTRUCTOR_PASSWORD", "")
SCENARIO_DIR=Path(os.getenv("SCENARIO_DIR",str(Path(__file__).resolve().parents[2]/"scenarios")))
app = FastAPI(title="CSG Endpoint Detective API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","), allow_credentials=True, allow_methods=["GET","POST","PUT","DELETE","PATCH"], allow_headers=["Content-Type","X-Instructor-Password"])

def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def prune_uncovered_transition_events(db:Session,case:dict,variant:str)->int:
    """Remove stale generated rows for transitions declared missing in the archive."""
    missing_ids=[
        transition_event_id(case,variant,item["transition_id"])
        for item in case.get("incident",{}).get("telemetry",[])
        if item.get("coverage")=="missing"
    ]
    if not missing_ids: return 0
    result=db.execute(delete(Event).where(
        Event.scenario_slug==case["slug"],
        Event.variant==variant,
        Event.id.in_(missing_ids),
    ))
    removed=result.rowcount or 0
    if removed: db.commit()
    return removed

def seed_malicious_context_events(db:Session,case:dict,variant:str,marker:ScenarioSeed|None=None)->int:
    """Backfill threat clues without replacing case data or student submissions."""
    rows=malicious_context_events(case,variant)
    for row in rows:
        row["scenario_slug"]=case["slug"]
        row["variant"]=variant
    ids=[row["id"] for row in rows]
    existing=list(db.scalars(select(Event).where(Event.scenario_slug==case["slug"],Event.variant==variant,Event.id.in_(ids))).all()) if ids else []
    present={event.id:event for event in existing}
    missing=[row for row in rows if row["id"] not in present]
    fields=("timestamp","host_name","event_code","event_type","provider","object_key","service_name","process_name","registry_key","normalized","raw","search_text","provenance","scenario_slug","variant")
    changed=[row for row in rows if row["id"] in present and any(getattr(present[row["id"]],field)!=row.get(field) for field in fields)]
    if missing:
        db.bulk_insert_mappings(Event,missing)
        if marker:
            marker.event_count+=len(missing)
    if changed:
        db.bulk_update_mappings(Event,changed)
    if missing or changed:
        db.commit()
    return len(missing)

def refresh_case_events_in_place(db:Session,case:dict,variant:str,marker:ScenarioSeed)->None:
    """Refresh a revised case corpus without removing evidence selections or submissions."""
    rows=generate_case_events(case,variant)
    for row in rows:
        row["scenario_slug"]=case["slug"]
        row["variant"]=variant
    existing_rows=db.scalars(select(Event).where(Event.scenario_slug==case["slug"],Event.variant==variant)).all()
    existing={event.id:event for event in existing_rows}
    fields=("timestamp","host_name","event_code","event_type","provider","object_key","service_name","process_name","registry_key","normalized","raw","search_text","provenance","scenario_slug","variant")
    changed=[{"id":row["id"],**{field:row.get(field) for field in fields}} for row in rows if row["id"] in existing and any(getattr(existing[row["id"]],field)!=row.get(field) for field in fields)]
    missing=[row for row in rows if row["id"] not in existing]
    if changed: db.bulk_update_mappings(Event,changed)
    if missing: db.bulk_insert_mappings(Event,missing)
    marker.version=case.get("seed_version",1)
    marker.event_count=max(len(rows),len(existing_rows)+len(missing))
    marker.seeded_at=datetime.now(UTC)
    db.commit()

def seed_events():
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        active_slugs={case["slug"] for case in CASES}
        control=db.get(LabControl,1)
        if not control:
            control=LabControl(id=1,active=True,mode="challenge",enabled_cases=[c["slug"] for c in CASES])
            db.add(control); db.commit()
        else:
            enabled=set(control.enabled_cases or [])
            # Preserve the former Case 3 enablement when its teaching objective is replaced.
            if "wrong-service" in enabled: enabled.add("complete-state-model")
            # Add the newly introduced multi-snapshot case once; later instructor choices persist.
            if "staged-relay" in active_slugs and not db.get(ScenarioSeed,"staged-relay:A"):
                enabled.add("staged-relay")
            enabled.difference_update({"wrong-service","wrong-transition","invisible-process"})
            control.enabled_cases=[c["slug"] for c in CASES if c["slug"] in enabled and c["slug"] in active_slugs]
            db.commit()

        # Remove retired case data so old submissions cannot break current instructor summaries.
        known_slugs=set(db.scalars(select(distinct(Event.scenario_slug))).all())
        known_slugs.update(db.scalars(select(distinct(Submission.scenario_slug))).all())
        retired_slugs=known_slugs-active_slugs
        if retired_slugs:
            db.execute(delete(EvidenceSelection).where(EvidenceSelection.scenario_slug.in_(retired_slugs)))
            db.execute(delete(Submission).where(Submission.scenario_slug.in_(retired_slugs)))
            db.execute(delete(SearchHistory).where(SearchHistory.scenario_slug.in_(retired_slugs)))
            db.execute(delete(Event).where(Event.scenario_slug.in_(retired_slugs)))
            db.commit()

        for case in CASES:
            for variant in VARIANTS:
                seed_id=f"{case['slug']}:{variant}"
                marker=db.get(ScenarioSeed,seed_id)
                pruned=prune_uncovered_transition_events(db,case,variant)
                exists=db.scalar(select(func.count()).select_from(Event).where(Event.scenario_slug==case["slug"],Event.variant==variant)) or 0
                version=case.get("seed_version",1)
                if marker and marker.version!=version and case["id"] in {"case-01","case-02"}:
                    refresh_case_events_in_place(db,case,variant,marker)
                    continue
                if marker and marker.version==version and exists>=case.get("minimum_events",15000):
                    added=seed_malicious_context_events(db,case,variant,marker)
                    if pruned or added:
                        marker.event_count=exists
                        marker.event_count=max(marker.event_count,exists+added)
                        marker.seeded_at=datetime.now(UTC)
                        db.commit()
                    continue
                # Cases 1 and 2 predate the seed manifest, but their deterministic corpus is unchanged.
                if not marker and exists and case["id"] in {"case-01","case-02"}:
                    db.add(ScenarioSeed(id=seed_id,version=version,event_count=exists,seeded_at=datetime.now(UTC)))
                    db.commit()
                    marker=db.get(ScenarioSeed,seed_id)
                    if case["id"] in {"case-01","case-02"}:
                        refresh_case_events_in_place(db,case,variant,marker)
                        continue
                    seed_malicious_context_events(db,case,variant,marker)
                    continue
                db.execute(delete(EvidenceSelection).where(EvidenceSelection.scenario_slug==case["slug"]))
                db.execute(delete(Submission).where(Submission.scenario_slug==case["slug"]))
                db.execute(delete(SearchHistory).where(SearchHistory.scenario_slug==case["slug"]))
                db.execute(delete(Event).where(Event.scenario_slug==case["slug"],Event.variant==variant))
                rows = generate_case_events(case, variant)
                for start in range(0, len(rows), 2500):
                    db.bulk_insert_mappings(Event, rows[start:start+2500])
                if marker:
                    marker.version=version; marker.event_count=len(rows); marker.seeded_at=datetime.now(UTC)
                else:
                    db.add(ScenarioSeed(id=seed_id,version=version,event_count=len(rows),seeded_at=datetime.now(UTC)))
                db.commit()

@app.on_event("startup")
def startup():
    if not INSTRUCTOR_PASSWORD:
        raise RuntimeError("INSTRUCTOR_PASSWORD must be set before the classroom API starts")
    seed_events()

class JoinRequest(BaseModel):
    class_code: str = Field(min_length=3, max_length=24)
    display_name: str = Field(default="", max_length=64)
    anonymous: bool = False

class SubmissionRequest(BaseModel):
    delta_id: str = Field(min_length=3, max_length=80)
    classification: str
    explanation: str = Field(min_length=20, max_length=3000)

@app.get("/api/health")
def health():
    try:
        with engine.connect() as c: c.execute(select(1))
        return {"status":"ok","service":"classroom","version":"1.0.0"}
    except Exception:
        raise HTTPException(503, "Database is not ready")

@app.get("/api/lab")
def lab():
    with SessionLocal() as db: control=db.get(LabControl,1)
    return {"title":"CY530 CSG Investigation Lab","active":control.active if control else True,"mode":control.mode if control else "challenge","class_code_required":True,"cases_enabled":True}

def current_student(request: Request, db: Session) -> StudentSession:
    sid=request.cookies.get("csg_student")
    student=db.get(StudentSession, sid) if sid else None
    if not student: raise HTTPException(401,"Join the classroom lab first")
    control=db.get(LabControl,1)
    if control and not control.active: raise HTTPException(403,"The instructor has paused the classroom lab")
    student.last_seen_at=datetime.now(UTC)
    db.commit()
    return student

def assert_case_available(slug:str,student:StudentSession,db:Session):
    control=db.get(LabControl,1)
    if control and slug not in set(control.enabled_cases or []): raise HTTPException(404,"Case is not enabled")
    if control and control.mode=="guided":
        completed=completed_scenarios(db,student.id)
        for case in CASES:
            if case["slug"] not in completed:
                if slug!=case["slug"]: raise HTTPException(403,"Complete the current case to unlock this investigation")
                break

def completed_scenarios(db:Session,student_id:str)->set[str]:
    rows=db.scalars(select(Submission).where(Submission.student_id==student_id)).all()
    submitted={}
    for row in rows: submitted.setdefault(row.scenario_slug,set()).add(row.delta_id)
    completed=set()
    for case in CASES:
        required={item["id"] for item in investigation_defs(case,"A")}
        if required.issubset(submitted.get(case["slug"],set())): completed.add(case["slug"])
    return completed

@app.post("/api/sessions")
def join(payload: JoinRequest, response: Response, db: Session=Depends(db_session)):
    control=db.get(LabControl,1)
    if control and not control.active: raise HTTPException(403,"The instructor has not started the lab")
    supplied_code=payload.class_code.strip().casefold()
    if not any(hmac.compare_digest(supplied_code, accepted) for accepted in ACCEPTED_CLASS_CODES):
        raise HTTPException(403,"That class code is not active")
    sid=str(uuid.uuid4())
    variant=chr(65+(uuid.UUID(sid).int % 5))
    name=(f"Student {ord(variant)-64:02d}" if payload.anonymous else payload.display_name.strip()) or f"Student {int(uuid.UUID(sid).int % 99)+1:02d}"
    if len(name)>64: raise HTTPException(422,"Display name is too long")
    now=datetime.now(UTC)
    db.add(StudentSession(id=sid,display_name=name,variant=variant,created_at=now,last_seen_at=now)); db.commit()
    response.set_cookie("csg_student",sid,httponly=True,samesite="lax",secure=os.getenv("COOKIE_SECURE","false").lower()=="true",max_age=60*60*12,path="/")
    return {"display_name":name,"variant":variant,"cases_available":len(CASES)}

@app.get("/api/sessions/me")
def me(request: Request, db: Session=Depends(db_session)):
    student=current_student(request,db)
    submissions=db.scalars(select(Submission).where(Submission.student_id==student.id)).all()
    progress={}
    for sub in submissions: progress.setdefault(sub.scenario_slug,[]).append({"delta_id":sub.delta_id,"classification":sub.classification,"score":sub.score,"correct":sub.correct})
    return {"display_name":student.display_name,"variant":student.variant,"progress":progress,"completed_cases":len(completed_scenarios(db,student.id))}

@app.get("/api/cases")
def list_cases(request: Request, db: Session=Depends(db_session)):
    student=current_student(request,db)
    done=completed_scenarios(db,student.id)
    control=db.get(LabControl,1); enabled=set(control.enabled_cases or []) if control else {c["slug"] for c in CASES}
    unlocked={c["slug"] for c in CASES}
    if control and control.mode=="guided":
        unlocked=set()
        for c in CASES:
            unlocked.add(c["slug"])
            if c["slug"] not in done: break
    return [{"slug":c["slug"],"id":c["id"],"title":c["title"],"difficulty":c["difficulty"],"learning_objective":c["learning_objective"],"completed":c["slug"] in done,"delta_count":len(scenario_delta_defs(c,student.variant)),"item_count":len(investigation_defs(c,student.variant)),"locked":c["slug"] not in unlocked or c["slug"] not in enabled} for c in CASES]

@app.get("/api/cases/{slug}")
def get_case(slug: str, request: Request, db: Session=Depends(db_session)):
    student=current_student(request,db)
    try: case=case_by_slug(slug)
    except StopIteration: raise HTTPException(404,"Case not found")
    assert_case_available(slug,student,db)
    result=public_case(case,student.variant)
    # Public route deliberately omits expected classifications and answer explanations.
    result["exercise_ids"]=[item["id"] for item in result["investigations"]]
    return result

def build_inventory(case: dict, variant: str, snap_index: int) -> tuple[str, list[dict], dict]:
    minutes=case.get("incident",{}).get("snapshot_minutes",[30,60])
    observed=BASE+timedelta(minutes=minutes[snap_index])
    sid=f"{case['id']}-{variant}-snapshot-{snap_index+1}"
    # Keep ordinary inventory stable across adjacent snapshots; only the declared
    # scenario objects should contribute to a state delta.
    rng=__import__("random").Random(case["noise_seed"]+ord(variant))
    services=["Appinfo","AppXSvc","BITS","BrokerInfrastructure","CryptSvc","Dhcp","Dnscache","EventLog","LanmanServer","Spooler","W32Time","WinDefend","Winmgmt","WSearch","wuauserv"]
    while len(services)<263:
        services.append(f"WindowsService{len(services):03d}")
    processes=["explorer.exe","svchost.exe","RuntimeBroker.exe","SearchHost.exe","StartMenuExperienceHost.exe","OneDrive.exe","msedge.exe","MsMpEng.exe","services.exe","dwm.exe"]
    while len(processes)<171: processes.append(f"WorkerHost{len(processes):03d}.exe")
    objects=[]
    for name in services:
        attrs={"service_name":name,"display_name":name,"status":"running" if rng.random()<.65 else "stopped","start_mode":rng.choice(["automatic","manual","disabled"]),"binary_path":f"C:\\Windows\\System32\\{name}.exe","account":"LocalSystem"}
        objects.append({"category":"service","object_key":f"service:{name.lower()}","display_name":name,"attributes":attrs})
    for i,name in enumerate(processes):
        attrs={"name":name,"pid":1000+i*17,"ppid":4 if name=="services.exe" else 1280,"executable_path":f"C:\\Windows\\System32\\{name}","username":"LAB\\student","create_time":(BASE-timedelta(minutes=8+i%9)).isoformat()}
        objects.append({"category":"process","object_key":f"process:{attrs['pid']}:{name.lower()}","display_name":name,"attributes":attrs})
    for port,proc in [(53,"svchost.exe"),(135,"svchost.exe"),(445,"System"),(3389,"svchost.exe")]+[(8000+i,"svchost.exe") for i in range(20)]:
        attrs={"protocol":"tcp","local_address":"0.0.0.0","local_port":port,"pid":1200+port,"process_name":proc}
        objects.append({"category":"listener","object_key":f"listener:tcp:0.0.0.0:{port}","display_name":f"TCP {port}","attributes":attrs})
    for i in range(92):
        task=f"\\Microsoft\\Windows\\Maintenance\\Task{i:02d}"
        attrs={"task_name":task,"action":"C:\\Windows\\System32\\svchost.exe","run_as":"SYSTEM","enabled":True}
        objects.append({"category":"scheduled_task","object_key":f"task:{task.lower()}","display_name":task,"attributes":attrs})
    for i in range(11):
        key=f"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\App{i:02d}"
        attrs={"registry_key":key,"value_name":f"App{i:02d}","value_data":"C:\\Program Files\\Common Files\\app.exe"}
        objects.append({"category":"registry_autorun","object_key":f"registry:{key.lower()}","display_name":key,"attributes":attrs})
    for user in ["LAB\\Administrator","LAB\\Helpdesk"]:
        objects.append({"category":"privileged_group_member","object_key":f"group:administrators:{user.lower()}","display_name":user,"attributes":{"group_name":"Administrators","member":user}})
    if case.get("incident"):
        states=materialize_snapshot_states(case,variant)
        if snap_index>=len(states): raise HTTPException(404,"Snapshot not found")
        state=states[snap_index]
        for key,obj in state.items():
            objects=[o for o in objects if not (o["category"]==obj["category"] and o["object_key"].casefold()==key)]
            objects.append(deepcopy(obj))
    else:
        defs=[materialize_delta(case,d,variant) for d in case["delta_defs"]]
        for delta in defs:
            if delta["before"] is None and snap_index==0: continue
            if delta["before"] is None and snap_index==1 or delta["before"] is not None:
                identity=str(delta["object_key"]).lower()
                prefix={"service":"service:","scheduled_task":"task:","registry_autorun":"registry:"}.get(delta["category"],delta["category"]+":")
                if not identity.startswith(prefix): identity=prefix+identity
                display=str(delta["object_key"]).split(":",1)[-1]
                obj={"category":delta["category"],"object_key":identity,"display_name":display,"attributes":delta["after"] if snap_index==1 else delta["before"]}
                objects=[o for o in objects if not (o["category"]==delta["category"] and o["object_key"].lower()==identity)]
                if snap_index==1: objects.append(obj)
                elif delta["before"] is not None: objects.append({**obj,"attributes":delta["before"]})
    counts={cat:sum(1 for o in objects if o["category"]==cat) for cat in ["service","process","listener","scheduled_task","registry_autorun","privileged_group_member","defender_exclusion"]}
    return sid,objects,{"snapshot_id":sid,"host_id":VARIANTS[variant]["host"],"observed_at":observed.isoformat(),"objects_count":len(objects),"counts":counts,"collector_health":{"service":"healthy","process":"healthy","listener":"healthy","scheduled_task":"healthy","registry_autorun":"healthy","privileged_group_member":"healthy","defender_exclusion":"healthy"}}

@app.get("/api/cases/{slug}/timeline")
def timeline(slug: str, request: Request, db: Session=Depends(db_session)):
    student=current_student(request,db); case=case_by_slug(slug); assert_case_available(slug,student,db)
    snaps=[]
    snapshot_count=len(case.get("incident",{}).get("snapshot_minutes",[30,60]))
    for ix in range(snapshot_count):
        _,_,header=build_inventory(case,student.variant,ix); snaps.append(header)
    deltas=[]
    for item in scenario_delta_defs(case,student.variant):
        before_ix=item.get("before_snapshot_index",0); after_ix=item.get("after_snapshot_index",len(snaps)-1)
        deltas.append({"id":item["id"],"category":item["category"],"operation":item["operation"],"object_key":item["object_key"],"before":item["before"],"after":item["after"],"before_snapshot_id":snaps[before_ix]["snapshot_id"],"after_snapshot_id":snaps[after_ix]["snapshot_id"],"window":{"start":snaps[before_ix]["observed_at"],"end":snaps[after_ix]["observed_at"]}})
    transitions=materialize_transitions(case,student.variant)
    investigations=investigation_defs(case,student.variant)
    done={s.delta_id:s for s in db.scalars(select(Submission).where(Submission.student_id==student.id,Submission.scenario_slug==slug)).all()}
    return {"snapshots":snaps,"deltas":deltas,"transitions":transitions,"investigations":[{k:item[k] for k in ("id","kind","title","category","object_key","transition_ids","delta_id") if k in item} for item in investigations],"submissions":{k:{"classification":v.classification,"score":v.score,"correct":v.correct} for k,v in done.items()}}

@app.get("/api/cases/{slug}/snapshots/{snapshot_id}")
def snapshot(slug: str,snapshot_id:str,request:Request,category:str|None=None,q:str="",page:int=1,page_size:int=100,db:Session=Depends(db_session)):
    student=current_student(request,db); case=case_by_slug(slug); assert_case_available(slug,student,db)
    match=re.search(r"snapshot-(\d+)$",snapshot_id)
    ix=int(match.group(1))-1 if match else -1
    snapshot_count=len(case.get("incident",{}).get("snapshot_minutes",[30,60]))
    if not case.get("incident"): snapshot_count=2
    if ix<0 or ix>=snapshot_count: ix=-1
    if ix<0 or not snapshot_id.startswith(f"{case['id']}-{student.variant}-"): raise HTTPException(404,"Snapshot not found")
    _,items,_=build_inventory(case,student.variant,ix)
    if category: items=[item for item in items if item["category"]==category]
    if q: items=[item for item in items if q.casefold() in (item["display_name"]+str(item["attributes"])).casefold()]
    total=len(items); page_size=min(500,max(1,page_size)); page=max(1,page)
    return {"total":total,"page":page,"page_size":page_size,"items":items[(page-1)*page_size:page*page_size]}

TOKEN_RE=re.compile(r'([A-Za-z][\w.]*:"(?:\\.|[^"])*"|"(?:\\.|[^"])*"|\bAND\b|\bOR\b|[^\s]+)',re.I)
FIELD_MAP={
    "timestamp":lambda:cast(Event.timestamp,String),"event.id":lambda:Event.event_code,"event.type":lambda:Event.event_type,"event.category":lambda:Event.normalized["event"]["category"].as_string(),"host.name":lambda:Event.host_name,
    "process.name":lambda:Event.process_name,"process.pid":lambda:cast(Event.normalized["process"]["pid"].as_string(),String),"process.parent":lambda:Event.normalized["process"]["parent"].as_string(),"process.parent_pid":lambda:cast(Event.normalized["process"]["ppid"].as_string(),String),"process.executable_path":lambda:Event.normalized["process"]["executable_path"].as_string(),
    "service.name":lambda:Event.service_name,"service.old_start_mode":lambda:Event.normalized["service"]["old_start_mode"].as_string(),"service.new_start_mode":lambda:Event.normalized["service"]["new_start_mode"].as_string(),
    "task.name":lambda:Event.normalized["task"]["name"].as_string(),"task.action":lambda:Event.normalized["task"]["action"].as_string(),"listener.local_port":lambda:cast(Event.normalized["listener"]["local_port"].as_string(),String),"listener.process_name":lambda:Event.normalized["listener"]["process_name"].as_string(),
    "registry.key":lambda:Event.registry_key,"registry.value_name":lambda:Event.normalized["registry"]["value_name"].as_string(),"user.name":lambda:Event.normalized["user"]["name"].as_string(),
    "source.ip":lambda:Event.normalized["source"]["ip"].as_string(),"destination.ip":lambda:Event.normalized["destination"]["ip"].as_string(),"source.port":lambda:Event.normalized["source"]["port"].as_string(),"destination.port":lambda:Event.normalized["destination"]["port"].as_string(),
    "rule.id":lambda:Event.normalized["rule"]["id"].as_string(),"rule.level":lambda:Event.normalized["rule"]["level"].as_string(),"message":lambda:Event.normalized["message"].as_string(),
}
EXACT_QUERY_FIELDS={"host.name","event.id","process.pid","process.parent_pid","service.name","process.name","process.executable_path"}

def parse_query(query: str):
    if not query.strip() or query.strip()=="*": return None
    if len(query)>500: raise HTTPException(422,"Search is limited to 500 characters")
    tokens=TOKEN_RE.findall(query)
    if not tokens: return None
    index=0
    def atom():
        nonlocal index
        if index>=len(tokens) or tokens[index].upper() in {"AND","OR"}: raise HTTPException(422,"Incomplete search expression")
        token=tokens[index]; index+=1
        if ":" in token:
            field,value=token.split(":",1); field=field.lower()
            if field not in FIELD_MAP: raise HTTPException(422,f"Unsupported field: {field}")
        else: field="_text"; value=token
        if value.startswith('"') and value.endswith('"'): value=value[1:-1].replace('\\"','"')
        return ("term",field,value)
    def conjunction():
        nonlocal index
        node=atom()
        while index<len(tokens) and tokens[index].upper()!="OR":
            if tokens[index].upper()=="AND": index+=1
            right=atom(); node=("and",node,right)
        return node
    node=conjunction()
    while index<len(tokens):
        if tokens[index].upper()!="OR": raise HTTPException(422,"Use AND or OR between search terms")
        index+=1; node=("or",node,conjunction())
    return node

def compile_query(ast):
    if ast is None: return None
    op=ast[0]
    if op=="term":
        _,field,value=ast
        if field=="_text": return Event.search_text.ilike(f"%{value}%")
        # Structured identifiers should not match host, name, or numeric
        # prefixes. Free-text search remains substring based.
        if field in EXACT_QUERY_FIELDS:
            return func.lower(FIELD_MAP[field]())==value.casefold()
        return FIELD_MAP[field]().ilike(f"%{value}%")
    lhs,rhs=compile_query(ast[1]),compile_query(ast[2])
    return and_(lhs,rhs) if op=="and" else or_(lhs,rhs)

def event_public(e:Event):
    return {"id":e.id,"timestamp":e.timestamp.isoformat(),"host_name":e.host_name,"event_code":e.event_code,"event_type":e.event_type,"provider":e.provider,"object_key":e.object_key,"service_name":e.service_name,"process_name":e.process_name,"registry_key":e.registry_key,"normalized":e.normalized,"provenance":e.provenance}

def parse_search_time_range(start:str|None,end:str|None):
    """Parse archive-time bounds; unzoned values are interpreted as UTC."""
    try:
        lower=datetime.fromisoformat(start.replace("Z","+00:00")) if start else None
        upper=datetime.fromisoformat(end.replace("Z","+00:00")) if end else None
    except ValueError:
        raise HTTPException(422,"Invalid time filter")
    if lower and lower.tzinfo is None: lower=lower.replace(tzinfo=UTC)
    if upper and upper.tzinfo is None: upper=upper.replace(tzinfo=UTC)
    if lower and upper and lower>upper:
        raise HTTPException(422,"Start time must be earlier than or equal to end time")
    return lower,upper

def timestamp_in_search_range(timestamp:datetime,lower:datetime|None,upper:datetime|None)->bool:
    """Inclusive-boundary counterpart used by the archive range filter."""
    if timestamp.tzinfo is None: timestamp=timestamp.replace(tzinfo=UTC)
    if lower and timestamp<lower: return False
    if upper and timestamp>upper: return False
    return True

@app.get("/api/events")
def search_events(request:Request,slug:str,q:str="",event_type:str|None=None,event_category:str|None=None,event_code:str|None=None,provider:str|None=None,host:str|None=None,start:str|None=None,end:str|None=None,page:int=1,page_size:int=100,db:Session=Depends(db_session)):
    student=current_student(request,db); case=case_by_slug(slug); assert_case_available(slug,student,db)
    page_size=min(500,max(1,page_size)); page=max(1,page)
    base_clauses=[Event.scenario_slug==slug,Event.variant==student.variant]
    ast=parse_query(q); compiled=compile_query(ast)
    if compiled is not None: base_clauses.append(compiled)
    if event_type: base_clauses.append(Event.event_type==event_type)
    if event_category: base_clauses.append(Event.normalized["event"]["category"].as_string()==event_category)
    if event_code: base_clauses.append(Event.event_code==event_code)
    if provider: base_clauses.append(Event.provider==provider)
    if host: base_clauses.append(Event.host_name==host)
    lower,upper=parse_search_time_range(start,end)
    clauses=list(base_clauses)
    if lower: clauses.append(Event.timestamp>=lower)
    if upper: clauses.append(Event.timestamp<=upper)
    where=and_(*clauses)
    total=db.scalar(select(func.count()).select_from(Event).where(where)) or 0
    rows=db.scalars(select(Event).where(where).order_by(Event.timestamp.desc(),Event.id).offset((page-1)*page_size).limit(page_size)).all()
    bucket_time=func.date_trunc("minute",Event.timestamp)
    # Keep case-window volume visible while a narrower range is active.
    # The UI overlays the selected range so chart and controls share one time state.
    histogram=db.execute(select(bucket_time,func.count()).where(and_(*base_clauses)).group_by(bucket_time).order_by(bucket_time)).all()
    db.add(SearchHistory(student_id=student.id,scenario_slug=slug,query=q,result_count=total,created_at=datetime.now(UTC))); db.commit()
    return {"total":total,"page":page,"page_size":page_size,"rows":[event_public(e) for e in rows],"histogram":[{"time":t.isoformat(),"count":n} for t,n in histogram],"histogram_interval":"1m"}

@app.get("/api/events/{event_id}")
def event_detail(event_id:str,request:Request,db:Session=Depends(db_session)):
    student=current_student(request,db); e=db.get(Event,event_id)
    if not e or e.variant!=student.variant: raise HTTPException(404,"Event not found")
    return event_public(e)|{"raw":e.raw}

@app.get("/api/cases/{slug}/evidence")
def evidence_tray(slug:str,delta_id:str,request:Request,db:Session=Depends(db_session)):
    student=current_student(request,db); case=case_by_slug(slug); assert_case_available(slug,student,db)
    selections=db.scalars(select(EvidenceSelection).where(EvidenceSelection.student_id==student.id,EvidenceSelection.scenario_slug==slug,EvidenceSelection.delta_id==delta_id)).all()
    events=[]
    for item in selections:
        ev=db.get(Event,item.event_id)
        if ev and ev.variant==student.variant: events.append(event_public(ev))
    return {"items":events}

def allowed_investigation_ids(case:dict,variant:str)->set[str]:
    return {item["id"] for item in investigation_defs(case,variant)}

@app.put("/api/cases/{slug}/evidence/{delta_id}/{event_id}")
def select_evidence(slug:str,delta_id:str,event_id:str,request:Request,db:Session=Depends(db_session)):
    student=current_student(request,db); case=case_by_slug(slug); assert_case_available(slug,student,db); ev=db.get(Event,event_id)
    if not ev or ev.scenario_slug!=slug or ev.variant!=student.variant: raise HTTPException(404,"Event not found")
    if delta_id not in allowed_investigation_ids(case,student.variant): raise HTTPException(404,"Investigation item not found")
    exists=db.scalar(select(EvidenceSelection).where(EvidenceSelection.student_id==student.id,EvidenceSelection.scenario_slug==slug,EvidenceSelection.delta_id==delta_id,EvidenceSelection.event_id==event_id))
    if not exists: db.add(EvidenceSelection(student_id=student.id,scenario_slug=slug,delta_id=delta_id,event_id=event_id,selected_at=datetime.now(UTC))); db.commit()
    return {"selected":True}

@app.delete("/api/cases/{slug}/evidence/{delta_id}/{event_id}")
def remove_evidence(slug:str,delta_id:str,event_id:str,request:Request,db:Session=Depends(db_session)):
    student=current_student(request,db)
    db.execute(delete(EvidenceSelection).where(EvidenceSelection.student_id==student.id,EvidenceSelection.scenario_slug==slug,EvidenceSelection.delta_id==delta_id,EvidenceSelection.event_id==event_id)); db.commit()
    return {"selected":False}

@lru_cache(maxsize=12)
def private_answers(slug:str)->dict:
    path=SCENARIO_DIR/slug/"answer-key.private.json"
    if not path.is_file(): raise RuntimeError(f"Private answer key is missing for {slug}")
    import json
    return json.loads(path.read_text())

def answer_spec(case:dict,delta_id:str,variant:str)->dict:
    answer=next((item for item in private_answers(case["slug"])["answers"] if item["variant"]==variant and item["delta_id"]==delta_id),None)
    if answer is None: raise HTTPException(404,"Investigation item not found")
    return {"expected":answer["expected_classification"],"required":answer["required_evidence_ids"],"acceptable":answer["acceptable_evidence_ids"],"prohibited":answer["prohibited_distractor_ids"],"require_all":answer.get("require_all_evidence",False),"explanation":answer["explanation"]}

@app.post("/api/cases/{slug}/submissions")
def submit(slug:str,payload:SubmissionRequest,request:Request,db:Session=Depends(db_session)):
    student=current_student(request,db); case=case_by_slug(slug); assert_case_available(slug,student,db)
    if payload.classification not in {"CONSISTENT","PARTIALLY_EXPLAINED","UNEXPLAINED","CONTRADICTED","INSUFFICIENT_EVIDENCE"}: raise HTTPException(422,"Choose a reconciliation label")
    if payload.delta_id not in allowed_investigation_ids(case,student.variant): raise HTTPException(404,"Investigation item not found")
    selected=db.scalars(select(EvidenceSelection).where(EvidenceSelection.student_id==student.id,EvidenceSelection.scenario_slug==slug,EvidenceSelection.delta_id==payload.delta_id)).all()
    selected_ids={s.event_id for s in selected}
    spec=answer_spec(case,payload.delta_id,student.variant)
    expected=spec["expected"]
    classification_correct=payload.classification==expected
    if spec["required"] and spec["require_all"]:
        matched=set(spec["required"]).issubset(selected_ids)
    elif spec["required"]:
        matched=bool(set(spec["required"]) & selected_ids)
    elif spec["acceptable"]:
        matched=bool(set(spec["acceptable"]) & selected_ids)
    else:
        matched=not selected_ids
    matched=matched and not bool(set(spec["prohibited"]) & selected_ids)
    evidence_score=40 if matched else (15 if classification_correct and not spec["prohibited"] else 0)
    score=(50 if classification_correct else 0)+evidence_score+10
    result_correct=classification_correct and matched
    sub=Submission(student_id=student.id,scenario_slug=slug,delta_id=payload.delta_id,classification=payload.classification,explanation=payload.explanation.strip(),submitted_at=datetime.now(UTC),score=score,correct=result_correct,evidence_ids=list(selected_ids))
    prior=db.scalar(select(Submission).where(Submission.student_id==student.id,Submission.scenario_slug==slug,Submission.delta_id==payload.delta_id))
    if prior:
        prior.classification=sub.classification; prior.explanation=sub.explanation; prior.submitted_at=sub.submitted_at; prior.score=sub.score; prior.correct=sub.correct; prior.evidence_ids=sub.evidence_ids
    else: db.add(sub)
    db.commit()
    review=[]
    for eid in selected_ids:
        ev=db.get(Event,eid)
        if not ev: continue
        accepted=eid in spec["acceptable"] or eid in spec["required"]
        reason=("Correlated threat context: PowerShell 4104 names the same service or persistence object/action in a malicious script. It links attacker intent to this CSG finding, but does not alone prove the change succeeded." if accepted and ev.event_type=="powershell_script_block" else "Matches the required host, object, event type, transition, and observation interval." if accepted else "Does not establish this state transition: its host, object identity, event semantics, or before/after values do not match.")
        review.append({"event_id":eid,"event_type":ev.event_type,"object_key":ev.object_key,"accepted":accepted,"reason":reason})
    if expected=="PARTIALLY_EXPLAINED" and payload.delta_id=="d-service-mode":
        learning_note="CSG independently confirms the Manual → Automatic result. PowerShell 4104 records the forwarder stop, exact service config request, and forwarder restart; matching 7036 records bracket the telemetry gap. This supports deliberate interruption, but the missing 7040 means the config command's success and causal role remain unconfirmed."
    elif expected=="PARTIALLY_EXPLAINED" and payload.delta_id=="d-task-add":
        learning_note="CSG confirms that this task persisted, and PowerShell 4104 names its exact task and action in the malicious process. No Task Scheduler 106 confirms registration, so the cross-source link is strong while native registration telemetry is missing."
    else:
        learning_note=("UNEXPLAINED means the available Wazuh telemetry did not explain the CSG observation. It does not by itself mean malicious." if expected=="UNEXPLAINED" else "PARTIALLY_EXPLAINED means Wazuh supports part of the CSG transition history, while another transition lacks matching event evidence." if expected=="PARTIALLY_EXPLAINED" else "Snapshots show what persisted; CSG transition records preserve intermediate state changes; Wazuh is independent corroborating evidence.")
    return {"student_classification":payload.classification,"csg_classification":expected,"correct":result_correct,"classification_correct":classification_correct,"score":score,"explanation":payload.explanation,"csg_explanation":spec["explanation"],"evidence_review":review,"required_evidence_count":len(spec["required"]),"learning_note":learning_note}

def require_instructor(request:Request):
    cookie=request.cookies.get("csg_instructor")
    expected=hmac.new(INSTRUCTOR_PASSWORD.encode(),b"csg-instructor",hashlib.sha256).hexdigest()
    if not cookie or not hmac.compare_digest(cookie,expected): raise HTTPException(401,"Instructor sign-in required")

@app.post("/api/instructor/session")
def instructor_login(payload:dict,response:Response):
    password=str(payload.get("password",""))
    if not hmac.compare_digest(password,INSTRUCTOR_PASSWORD): raise HTTPException(403,"Instructor password is not valid")
    token=hmac.new(INSTRUCTOR_PASSWORD.encode(),b"csg-instructor",hashlib.sha256).hexdigest()
    response.set_cookie("csg_instructor",token,httponly=True,samesite="lax",secure=os.getenv("COOKIE_SECURE","false").lower()=="true",max_age=60*60*12,path="/")
    return {"authenticated":True}

@app.get("/api/instructor/summary")
def instructor_summary(request:Request,db:Session=Depends(db_session)):
    require_instructor(request)
    students=db.scalars(select(StudentSession).order_by(StudentSession.created_at)).all()
    submissions=db.scalars(select(Submission)).all()
    by_student={s.id:{} for s in students}; stats={c["slug"]:{"submissions":0,"correct":0,"classifications":{}} for c in CASES}
    for sub in submissions:
        by_student.setdefault(sub.student_id,{})[sub.scenario_slug]=sub
        item=stats[sub.scenario_slug]; item["submissions"]+=1; item["correct"]+=int(sub.correct); item["classifications"][sub.classification]=item["classifications"].get(sub.classification,0)+1
    now=datetime.now(UTC)
    roster=[{"id":s.id,"display_name":s.display_name,"variant":s.variant,"online":(now-s.last_seen_at).total_seconds()<300,"progress":{slug:{"correct":v.correct,"score":v.score,"classification":v.classification} for slug,v in by_student.get(s.id,{}).items()}} for s in students]
    control=db.get(LabControl,1)
    complete_count=sum(len(completed_scenarios(db,s.id))==len(CASES) for s in students)
    return {"lab":"CY530 CSG Investigation Lab","active":control.active if control else True,"mode":control.mode if control else "challenge","enabled_cases":control.enabled_cases if control else [c["slug"] for c in CASES],"students":len(students),"online":sum(r["online"] for r in roster),"completed":complete_count,"cases":[{"slug":c["slug"],"title":c["title"],**stats[c["slug"]]} for c in CASES],"roster":roster}

@app.get("/api/instructor/search-history")
def instructor_history(request:Request,db:Session=Depends(db_session)):
    require_instructor(request)
    rows=db.execute(select(SearchHistory,StudentSession.display_name).join(StudentSession,SearchHistory.student_id==StudentSession.id).order_by(SearchHistory.created_at.desc()).limit(300)).all()
    return [{"student":f"Analyst {s.student_id[:4].upper()}","scenario":s.scenario_slug,"query":s.query,"result_count":s.result_count,"created_at":s.created_at.isoformat()} for s,name in rows]

@app.get("/api/instructor/export.csv")
def instructor_export(request:Request,db:Session=Depends(db_session)):
    require_instructor(request)
    rows=db.execute(select(Submission,StudentSession.display_name,StudentSession.created_at).join(StudentSession,Submission.student_id==StudentSession.id).order_by(Submission.submitted_at)).all()
    stream=io.StringIO(); writer=csv.writer(stream); writer.writerow(["Student","Case","Investigation Item","Classification","Correct","Score","Selected Evidence Count","Explanation","Started","Submitted"])
    for s,name,started in rows: writer.writerow([name,s.scenario_slug,s.delta_id,s.classification,s.correct,s.score,len(s.evidence_ids or []),s.explanation,started.isoformat(),s.submitted_at.isoformat()])
    return Response(stream.getvalue(),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=csg-class-results.csv"})

@app.patch("/api/instructor/lab")
def instructor_lab(request:Request,payload:dict,db:Session=Depends(db_session)):
    require_instructor(request)
    control=db.get(LabControl,1)
    if not control: control=LabControl(id=1,active=True,mode="challenge",enabled_cases=[c["slug"] for c in CASES]); db.add(control)
    if "active" in payload: control.active=bool(payload["active"])
    if payload.get("mode") in {"guided","challenge"}: control.mode=payload["mode"]
    if "enabled_cases" in payload:
        allowed={c["slug"] for c in CASES}; control.enabled_cases=[s for s in payload["enabled_cases"] if s in allowed]
    db.commit()
    return {"active":control.active,"mode":control.mode,"enabled_cases":control.enabled_cases}

@app.post("/api/instructor/students/{student_id}/reset")
def instructor_reset(student_id:str,request:Request,db:Session=Depends(db_session)):
    require_instructor(request)
    if not db.get(StudentSession,student_id): raise HTTPException(404,"Student session not found")
    db.execute(delete(EvidenceSelection).where(EvidenceSelection.student_id==student_id)); db.execute(delete(Submission).where(Submission.student_id==student_id)); db.execute(delete(SearchHistory).where(SearchHistory.student_id==student_id)); db.commit()
    return {"reset":True}

@app.get("/api/cases/{slug}/submissions/{delta_id}")
def get_submission(slug:str,delta_id:str,request:Request,db:Session=Depends(db_session)):
    student=current_student(request,db); case=case_by_slug(slug)
    sub=db.scalar(select(Submission).where(Submission.student_id==student.id,Submission.scenario_slug==slug,Submission.delta_id==delta_id))
    if not sub: raise HTTPException(404,"No submission yet")
    spec=answer_spec(case,delta_id,student.variant)
    review=[]
    for eid in sub.evidence_ids or []:
        ev=db.get(Event,eid)
        if not ev: continue
        accepted=eid in spec["acceptable"] or eid in spec["required"]
        review.append({"event_id":eid,"event_type":ev.event_type,"object_key":ev.object_key,"accepted":accepted,"reason":"Matches the evidence conditions for this delta." if accepted else "Does not establish this state transition: host, object identity, event semantics, or before/after values differ."})
    learning_note=("UNEXPLAINED means the available Wazuh telemetry did not explain the CSG observation. It does not by itself mean malicious." if spec["expected"]=="UNEXPLAINED" else "PARTIALLY_EXPLAINED means Wazuh supports part of the CSG transition history, while another transition lacks matching event evidence." if spec["expected"]=="PARTIALLY_EXPLAINED" else "Snapshots show what persisted; CSG transition records preserve intermediate state changes; Wazuh is independent corroborating evidence.")
    return {"student_classification":sub.classification,"csg_classification":spec["expected"],"correct":sub.correct,"classification_correct":sub.classification==spec["expected"],"score":sub.score,"explanation":sub.explanation,"csg_explanation":spec["explanation"],"evidence_review":review,"required_evidence_count":len(spec["required"]),"learning_note":learning_note}
