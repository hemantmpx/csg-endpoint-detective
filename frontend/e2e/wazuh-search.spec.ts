import { test, expect } from "@playwright/test";

test.use({reducedMotion:"reduce"});

const snapshots=[
  {snapshot_id:"case-01-A-snapshot-1",host_id:"WIN-LAB-01",observed_at:"2026-09-26T09:30:00Z",objects_count:563,counts:{service:263,process:171},collector_health:{service:"healthy"}},
  {snapshot_id:"case-01-A-snapshot-2",host_id:"WIN-LAB-01",observed_at:"2026-09-26T10:00:00Z",objects_count:564,counts:{service:264,process:171},collector_health:{service:"healthy"}},
];
const transitions=[
  {id:"service-auto",source:"csg",host:"WIN-LAB-01",observed_at:"2026-09-26T09:37:12Z",category:"service",object_key:"service:policybrokersvc",transition:"MODIFY",before:{start_mode:"manual"},after:{start_mode:"automatic"}},
  {id:"proc-create",source:"csg",host:"WIN-LAB-01",observed_at:"2026-09-26T09:37:25Z",category:"process",object_key:"process:4460:policystage.exe",transition:"START",before:null,after:{name:"PolicyStage.exe",pid:4460,parent:"services.exe",ppid:680,executable_path:"C:\\ProgramData\\CsgLab\\Stage\\PolicyStage.exe"}},
  {id:"task-create",source:"csg",host:"WIN-LAB-01",observed_at:"2026-09-26T09:38:10Z",category:"scheduled_task",object_key:"task:\\microsoft\\windows\\policy\\cacherefresh",transition:"CREATE",before:null,after:{task_name:"\\Microsoft\\Windows\\Policy\\CacheRefresh",action:"C:\\ProgramData\\CsgLab\\Stage\\PolicyStage.exe --inventory"}},
  {id:"registry-set",source:"csg",host:"WIN-LAB-01",observed_at:"2026-09-26T09:38:20Z",category:"registry_autorun",object_key:"registry:hklm\\run\\policy",transition:"CREATE",before:null,after:{registry_key:"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",value_name:"Policy",value_data:"C:\\ProgramData\\CsgLab\\Stage\\PolicyStage.exe"}},
  {id:"listener-open",source:"csg",host:"WIN-LAB-01",observed_at:"2026-09-26T09:38:25Z",category:"listener",object_key:"listener:tcp:0.0.0.0:4446",transition:"OPEN",before:null,after:{protocol:"tcp",local_address:"0.0.0.0",local_port:4446,pid:4460,process_name:"PolicyStage.exe",executable_path:"C:\\ProgramData\\CsgLab\\Stage\\PolicyStage.exe"}},
  {id:"proc-terminated",source:"csg",host:"WIN-LAB-01",observed_at:"2026-09-26T09:39:00Z",category:"process",object_key:"process:4460:policystage.exe",transition:"EXIT",before:{name:"PolicyStage.exe",pid:4460,parent:"services.exe",ppid:680,executable_path:"C:\\ProgramData\\CsgLab\\Stage\\PolicyStage.exe"},after:null},
  {id:"listener-close",source:"csg",host:"WIN-LAB-01",observed_at:"2026-09-26T09:39:05Z",category:"listener",object_key:"listener:tcp:0.0.0.0:4446",transition:"CLOSE",before:{protocol:"tcp",local_address:"0.0.0.0",local_port:4446,pid:4460,process_name:"PolicyStage.exe",executable_path:"C:\\ProgramData\\CsgLab\\Stage\\PolicyStage.exe"},after:null},
];
const briefing={
  scenario:"An endpoint review flagged a service-level change during a maintenance interval.",
  csg_observed:"The case includes two endpoint snapshots and selected CSG observations between them.",
  what_this_case_teaches:"Compare independent evidence sources using object identity and operation semantics.",
  technical_context:"A service start type is configuration; runtime status is a separate field.",
  evidence_available:[{name:"Snapshot A",description:"Beginning endpoint state."}],
  your_task:"Determine what persisted and whether Windows telemetry independently supports the CSG observations.",
};

async function enterStudentLab(page:any){
  await page.goto("/");
  await page.getByLabel("CLASS CODE").fill("CY530");
  await page.getByLabel("ANALYST DISPLAY NAME").fill("Alex Chen");
  await page.getByRole("button",{name:/Enter the lab/}).click();
  await expect(page.getByRole("heading",{name:"The Expected Service"})).toBeVisible();
}

test("CSG timeline terminology and live combined Wazuh filters",async({page},testInfo)=>{
  const requests:URL[]=[];
  await page.route("**/api/**",async route=>{
    const request=route.request();const url=new URL(request.url());const path=url.pathname;const method=request.method();
    if(path==="/api/sessions"&&method==="POST")return route.fulfill({json:{display_name:"Alex Chen",variant:"A"}});
    if(path==="/api/sessions/me")return route.fulfill({json:{display_name:"Alex Chen",variant:"A",progress:{},completed_cases:0}});
    if(path==="/api/cases"&&method==="GET")return route.fulfill({json:[{slug:"expected-service",id:"case-01",title:"The Expected Service",difficulty:"Easy",learning_objective:"Compare endpoint state with independent event telemetry.",completed:false,locked:false,delta_count:1,item_count:1}]});
    if(path==="/api/cases/expected-service"&&method==="GET")return route.fulfill({json:{id:"case-01",slug:"expected-service",title:"The Expected Service",difficulty:"Easy",host:"WIN-LAB-01",briefing,learning_objective:"Compare endpoint state with independent event telemetry.",variant:"A",target:"BackupAgent",timeline_start:"2026-09-26T09:00:00Z",timeline_end:"2026-09-26T12:00:00Z",deltas:[{id:"d-service-add",category:"service",operation:"ADD",object_key:"service:BackupAgent",before:null,after:{service_name:"BackupAgent",status:"running",start_mode:"automatic"},window:{start:snapshots[0].observed_at,end:snapshots[1].observed_at}}],investigations:[]}});
    if(path==="/api/cases/expected-service/timeline")return route.fulfill({json:{snapshots,deltas:[{id:"d-service-add",category:"service",operation:"ADD",object_key:"service:BackupAgent",before:null,after:{service_name:"BackupAgent",status:"running",start_mode:"automatic"},window:{start:snapshots[0].observed_at,end:snapshots[1].observed_at}}],transitions,investigations:[],submissions:{}}});
    if(path.startsWith("/api/cases/expected-service/snapshots/"))return route.fulfill({json:{total:1,page:1,page_size:100,items:[{category:"service",object_key:"service:backupagent",display_name:"BackupAgent",attributes:{service_name:"BackupAgent",status:"running",start_mode:"automatic"}}]}});
    if(path==="/api/cases/expected-service/evidence")return route.fulfill({json:{items:[]}});
    if(path==="/api/cases/expected-service/submissions/d-service-add")return route.fulfill({status:404,json:{detail:"No submission yet"}});
    if(path==="/api/events"&&method==="GET"){
      requests.push(url);
      return route.fulfill({json:{total:url.searchParams.get("q")==="NoSuchEvent"?0:1,page:Number(url.searchParams.get("page")||1),page_size:100,rows:[],histogram:[{time:"2026-09-26T09:36:00Z",count:4},{time:"2026-09-26T09:39:00Z",count:7}],histogram_interval:"1m"}});
    }
    return route.fulfill({status:404,json:{detail:"Unhandled test route"}});
  });

  await enterStudentLab(page);
  await page.getByText("Background for this case",{exact:true}).click();
  await expect(page.getByRole("heading",{name:"Technical context"})).toBeVisible();
  await page.getByRole("button",{name:"CSG timeline",exact:true}).click();
  await expect(page.locator(".tour-transition")).toContainText("Service start type changed");
  await page.getByRole("button",{name:"Next CSG observation"}).click();
  await expect(page.locator(".tour-transition")).toContainText("Process Create");
  await page.getByRole("button",{name:"Inspect CSG timeline",exact:true}).click();
  await expect(page.locator("#csg-transition-proc-create")).toHaveClass(/is-focused/);
  await page.locator(".timeline-transition-marker").first().click();
  await expect(page.getByRole("region",{name:"CSG changes in selected minute"})).toContainText("Process Create");
  await page.getByRole("region",{name:"CSG changes in selected minute"}).getByRole("button",{name:/Process Create/}).click();
  await expect(page.locator("#csg-transition-proc-create")).toHaveClass(/is-focused/);
  await page.getByRole("button",{name:"Clear timeline selection"}).click();
  const boxes=await page.locator(".timeline-transition-marker").evaluateAll(markers=>markers.map(marker=>{const box=marker.getBoundingClientRect();return {x:box.x,y:box.y,width:box.width,height:box.height}}));
  for(let i=0;i<boxes.length;i++)for(let j=i+1;j<boxes.length;j++){
    const left=boxes[i],right=boxes[j];
    const overlap=left.x<right.x+right.width&&left.x+left.width>right.x&&left.y<right.y+right.height&&left.y+left.height>right.y;
    expect(overlap).toBe(false);
  }
  await page.evaluate(()=>window.scrollTo({top:0,behavior:"instant"}));
  await page.screenshot({animations:"disabled",path:testInfo.outputPath("csg-timeline-desktop.png"),fullPage:true});
  await expect(page.getByRole("heading",{name:"CSG State Change Timeline"})).toBeVisible();
  await expect(page.getByText("Service start type changed").first()).toBeVisible();
  await expect(page.getByText("Manual → Automatic")).toBeVisible();
  await expect(page.getByText("Process Create").first()).toBeVisible();
  await expect(page.getByText("Process Terminated").first()).toBeVisible();
  await expect(page.getByText("Scheduled Task Registered").first()).toBeVisible();
  await expect(page.getByText("Registry Value Set").first()).toBeVisible();
  await expect(page.getByText("Listener Opened").first()).toBeVisible();
  await expect(page.getByText("Listener Closed").first()).toBeVisible();
  await expect(page.getByText(/Image path: .*PolicyStage\.exe · PID: 4460 · Parent: services\.exe · PPID: 680/).first()).toBeVisible();
  await expect(page.getByText(/Task path: \\Microsoft\\Windows\\Policy\\CacheRefresh/)).toBeVisible();
  await expect(page.getByText(/Local port: 4446 · PID: 4460/).first()).toBeVisible();
  await expect(page.getByText(/Value name: Policy · Value data: .*PolicyStage\.exe/)).toBeVisible();

  await page.getByRole("navigation",{name:"Investigation sections"}).getByRole("button",{name:/Wazuh events/i}).click();
  await expect.poll(()=>requests.length).toBeGreaterThan(0);
  expect(await page.getByRole("button",{name:"Search",exact:true}).count()).toBe(0);
  let before=requests.length;
  await page.getByLabel("Search events").pressSequentially("PolicyStage.exe",{delay:15});
  await expect.poll(()=>requests.at(-1)?.searchParams.get("q"),{timeout:4000}).toBe("PolicyStage.exe");
  await expect.poll(()=>requests.length,{timeout:4000}).toBe(before+1);

  await page.getByLabel("Time range preset").selectOption("last15");
  await expect.poll(()=>requests.at(-1)?.searchParams.get("start")).toBe("2026-09-26T11:45:00.000Z");
  await expect.poll(()=>requests.at(-1)?.searchParams.get("end")).toBe("2026-09-26T12:00:00.000Z");
  await page.getByLabel("Time range preset").selectOption("full");
  await expect.poll(()=>requests.at(-1)?.searchParams.get("start")).toBe("2026-09-26T09:00:00Z");

  await page.getByLabel("Event category").selectOption("process");
  await expect.poll(()=>requests.at(-1)?.searchParams.get("event_category")).toBe("process");
  await page.getByLabel("Event type").selectOption("process_start");
  await expect.poll(()=>requests.at(-1)?.searchParams.get("event_type")).toBe("process_start");
  await page.getByLabel("Windows event ID").selectOption("1");
  await expect.poll(()=>requests.at(-1)?.searchParams.get("event_code")).toBe("1");
  await page.getByLabel("Event host").selectOption("WIN-LAB-01");
  await expect.poll(()=>requests.at(-1)?.searchParams.get("host")).toBe("WIN-LAB-01");
  await page.getByLabel("Event provider").selectOption("Microsoft-Windows-Sysmon");
  await expect.poll(()=>requests.at(-1)?.searchParams.get("provider")).toBe("Microsoft-Windows-Sysmon");
  await page.getByLabel("Start date and time").fill("2026-09-26T09:35");
  await page.getByLabel("End date and time").fill("2026-09-26T09:42");
  await expect.poll(()=>requests.at(-1)?.searchParams.get("start")).toBeTruthy();
  await expect.poll(()=>requests.at(-1)?.searchParams.get("end")).toBeTruthy();
  const combined=requests.at(-1)!;
  expect(combined.searchParams.get("q")).toBe("PolicyStage.exe");
  expect(combined.searchParams.get("event_category")).toBe("process");
  expect(combined.searchParams.get("event_type")).toBe("process_start");
  expect(combined.searchParams.get("event_code")).toBe("1");
  expect(combined.searchParams.get("host")).toBe("WIN-LAB-01");
  expect(combined.searchParams.get("provider")).toBe("Microsoft-Windows-Sysmon");
  expect(Date.parse(combined.searchParams.get("end")!)).toBeGreaterThan(Date.parse(combined.searchParams.get("start")!));
  await expect(page.getByText("Search: PolicyStage.exe")).toBeVisible();
  await expect(page.getByText("Host: WIN-LAB-01")).toBeVisible();
  await expect(page.getByText(/Time:/)).toBeVisible();

  await page.getByLabel("Search events").fill("NoSuchEvent");
  await expect(page.getByText("No events match the current search and filters.")).toBeVisible({timeout:4000});
  await page.getByRole("button",{name:/Clear filters/}).click();
  await expect.poll(()=>requests.at(-1)?.searchParams.get("q")).toBe("");
  expect(requests.at(-1)?.searchParams.get("event_category")).toBeNull();
  expect(requests.at(-1)?.searchParams.get("event_type")).toBe("");
  expect(requests.at(-1)?.searchParams.get("host")).toBeNull();
  expect(requests.at(-1)?.searchParams.get("provider")).toBeNull();
  expect(requests.at(-1)?.searchParams.get("start")).toBe("2026-09-26T09:00:00Z");
  expect(requests.at(-1)?.searchParams.get("end")).toBe("2026-09-26T12:00:00Z");

  const minuteBars=page.locator(".histogram-bars .histogram-bar");
  await minuteBars.nth(36).click();
  await expect.poll(()=>requests.at(-1)?.searchParams.get("start")).toBe("2026-09-26T09:36:00.000Z");
  await expect.poll(()=>requests.at(-1)?.searchParams.get("end")).toBe("2026-09-26T09:37:00.000Z");
  await minuteBars.nth(36).dragTo(minuteBars.nth(40));
  await expect.poll(()=>requests.at(-1)?.searchParams.get("start")).toBe("2026-09-26T09:36:00.000Z");
  await expect.poll(()=>requests.at(-1)?.searchParams.get("end")).toBe("2026-09-26T09:41:00.000Z");
});
