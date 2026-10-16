#!/usr/bin/env python3
"""Standard-library concurrent classroom API exercise; defaults to 50 users / 10 min."""
import argparse
import concurrent.futures
import http.cookiejar
import json
import random
import statistics
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--base-url",default="http://localhost:8080")
    parser.add_argument("--users",type=int,default=50)
    parser.add_argument("--duration",type=int,default=600)
    parser.add_argument("--class-code",default="CY530")
    args=parser.parse_args()
    lock=threading.Lock(); latencies=[]; errors=[]; requests=0
    stop_at=time.monotonic()+args.duration
    def request(opener,path,method="GET",body=None):
        nonlocal requests
        data=json.dumps(body).encode() if body is not None else None
        req=urllib.request.Request(args.base_url+path,data=data,method=method,headers={"Content-Type":"application/json"})
        start=time.perf_counter()
        try:
            with opener.open(req,timeout=10) as response:
                payload=response.read(); status=response.status
            elapsed=(time.perf_counter()-start)*1000
            with lock: requests+=1; latencies.append(elapsed)
            if status>=400: raise RuntimeError(f"HTTP {status}")
            return json.loads(payload) if payload else {}
        except Exception as exc:
            elapsed=(time.perf_counter()-start)*1000
            with lock: requests+=1; latencies.append(elapsed); errors.append(str(exc))
            return None
    def learner(n):
        opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        join=request(opener,"/api/sessions","POST",{"class_code":args.class_code,"display_name":f"Load Analyst {n:02d}"})
        if not join:return
        cases=request(opener,"/api/cases")
        if not cases:return
        slug=cases[0]["slug"]
        case=request(opener,f"/api/cases/{slug}")
        if not case:return
        timeline=request(opener,f"/api/cases/{slug}/timeline")
        if not timeline:return
        delta_id=timeline["deltas"][0]["id"] if timeline["deltas"] else "transient-activity"
        while time.monotonic()<stop_at:
            request(opener,f"/api/events?{urllib.parse.urlencode({'slug':slug,'page_size':100})}")
            query="event.type:process_start AND host.name:"+case["host"]
            result=request(opener,f"/api/events?{urllib.parse.urlencode({'slug':slug,'q':query,'page_size':100})}")
            if result and result.get("rows"):
                event=result["rows"][0]
                request(opener,f"/api/events/{urllib.parse.quote(event['id'],safe='')}")
                request(opener,f"/api/cases/{slug}/evidence/{delta_id}/{urllib.parse.quote(event['id'],safe='')}","PUT")
            request(opener,f"/api/cases/{slug}/submissions","POST",{"delta_id":delta_id,"classification":"INSUFFICIENT_EVIDENCE","explanation":"Load exercise submission with sufficient analyst reasoning text."})
            time.sleep(random.uniform(7.0,10.0))
    started=time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.users) as pool:
        futures=[pool.submit(learner,i+1) for i in range(args.users)]
        for future in concurrent.futures.as_completed(futures):
            try: future.result()
            except Exception as exc:
                with lock: errors.append(str(exc))
    elapsed=time.monotonic()-started
    ordered=sorted(latencies)
    def pct(p): return round(ordered[min(len(ordered)-1,int((len(ordered)-1)*p))],1) if ordered else 0
    print(f"Users: {args.users}; elapsed: {elapsed:.1f}s; requests: {requests}; RPS: {requests/elapsed:.2f}")
    print(f"Latency ms: p50={pct(.50)} p95={pct(.95)} p99={pct(.99)}; errors={len(errors)} ({(100*len(errors)/max(1,requests)):.2f}%)")
    if errors: print("Sample errors:"," | ".join(errors[:8]))
    if errors or pct(.95)>=500: raise SystemExit(1)

if __name__=="__main__": main()
