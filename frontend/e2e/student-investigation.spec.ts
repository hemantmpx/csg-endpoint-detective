import { test, expect } from "@playwright/test";

test.use({reducedMotion:"reduce"});

test("student inspects state, collects a Wazuh event, and sees the reveal after submitting", async ({ page }, testInfo) => {
  let selected=false;
  let submitted=false;
  const event={
    id:"case-01-A-evt-a91fc0d1",timestamp:"2026-09-26T09:53:17.432Z",host_name:"WIN-LAB-01",event_code:"7045",event_type:"service_created",provider:"Service Control Manager",object_key:"service:backupagent",service_name:"BackupAgent",process_name:"services.exe",provenance:"generated",
    normalized:{event:{id:"7045",type:"service_created",category:"service"},host:{name:"WIN-LAB-01"},service:{name:"BackupAgent",binary_path:"C:\\Program Files\\BackupAgent\\agent.exe"},process:{name:"services.exe"},message:"A service was installed: BackupAgent"},
    raw:{agent:{id:"lab-01",name:"WIN-LAB-01"},data:{win:{system:{eventID:"7045",providerName:"Service Control Manager"},eventdata:{serviceName:"BackupAgent"}}}}
  };
  const reveal={student_classification:"CONSISTENT",csg_classification:"CONSISTENT",correct:true,classification_correct:true,score:100,csg_explanation:"A service installation record matches the same host, service identity, event window, and ADD operation.",evidence_review:[{event_id:event.id,event_type:event.event_type,object_key:event.object_key,accepted:true,reason:"Matches required host, object, event type, transition, and observation interval."}],learning_note:"Reconcile host, object, operation, transition, and time."};
  const snapshots=[
    {snapshot_id:"case-01-A-snapshot-1",host_id:"WIN-LAB-01",observed_at:"2026-09-26T09:30:00Z",objects_count:563,counts:{service:263,process:171,listener:24,scheduled_task:92,registry_autorun:11,privileged_group_member:2},collector_health:{service:"healthy"}},
    {snapshot_id:"case-01-A-snapshot-2",host_id:"WIN-LAB-01",observed_at:"2026-09-26T10:00:00Z",objects_count:564,counts:{service:264,process:171,listener:24,scheduled_task:92,registry_autorun:11,privileged_group_member:2},collector_health:{service:"healthy"}}
  ];
  await page.route("**/api/**",async route=>{
    const request=route.request();const url=new URL(request.url());const path=url.pathname;const method=request.method();
    if(path==="/api/sessions"&&method==="POST")return route.fulfill({json:{display_name:"Alex Chen",variant:"A"}});
    if(path==="/api/sessions/me")return route.fulfill({json:{display_name:"Alex Chen",variant:"A",progress:{},completed_cases:0}});
    if(path==="/api/cases"&&method==="GET")return route.fulfill({json:[{slug:"expected-service",id:"case-01",title:"The Expected Service",difficulty:"Easy",learning_objective:"Match a durable service addition to its exact creation record.",completed:submitted,locked:false,delta_count:1} ]});
    if(path==="/api/cases/expected-service"&&method==="GET")return route.fulfill({json:{id:"case-01",slug:"expected-service",title:"The Expected Service",difficulty:"Easy",host:"WIN-LAB-01",briefing:{scenario:"A Windows service changed during maintenance. Compare the endpoint snapshots with the archived Windows logs.",csg_observed:"CSG captured the service inventory before and after the maintenance window.",what_this_case_teaches:"Compare state with independent telemetry.",technical_context:"Start type is separate from runtime status.",evidence_available:[{name:"Snapshot A",description:"Beginning endpoint state."},{name:"Snapshot B",description:"Ending endpoint state."}],your_task:"Find the service change, collect any matching event, and explain the fields you checked."},learning_objective:"Match a durable service addition to its exact creation record.",variant:"A",target:"BackupAgent",timeline_start:"2026-09-26T09:00:00Z",timeline_end:"2026-09-26T12:00:00Z",deltas:[{id:"d-service-add",category:"service",operation:"ADD",object_key:"service:BackupAgent",before:null,after:{service_name:"BackupAgent",start_mode:"automatic"},window:{start:snapshots[0].observed_at,end:snapshots[1].observed_at}}],exercise_ids:["d-service-add"]}});
    if(path==="/api/cases/expected-service/timeline")return route.fulfill({json:{snapshots,deltas:[{id:"d-service-add",category:"service",operation:"ADD",object_key:"service:BackupAgent",before:null,after:{service_name:"BackupAgent",start_mode:"automatic"},window:{start:snapshots[0].observed_at,end:snapshots[1].observed_at}}],submissions:{},transitions:[],investigations:[{id:"d-service-add",kind:"delta",title:"BackupAgent",category:"service",object_key:"service:BackupAgent",transition_ids:[],delta_id:"d-service-add"}],transient_only:false}});
    if(path.startsWith("/api/cases/expected-service/snapshots/"))return route.fulfill({json:{total:1,page:1,page_size:100,items:[{category:"service",object_key:"service:backupagent",display_name:"BackupAgent",attributes:{service_name:"BackupAgent",status:"running",start_mode:"automatic"}}]}});
    if(path==="/api/cases/expected-service/evidence"&&method==="GET")return route.fulfill({json:{items:selected?[event]:[]}});
    if(path==="/api/cases/expected-service/evidence/d-service-add/"+event.id&&method==="PUT"){selected=true;return route.fulfill({json:{selected:true}})}
    if(path==="/api/cases/expected-service/evidence/d-service-add/"+event.id&&method==="DELETE"){selected=false;return route.fulfill({json:{selected:false}})}
    if(path==="/api/cases/expected-service/submissions/d-service-add"&&method==="GET")return route.fulfill({status:submitted?200:404,json:submitted?reveal:{detail:"No submission yet"}});
    if(path==="/api/cases/expected-service/submissions"&&method==="POST"){submitted=true;return route.fulfill({json:reveal})}
    if(path==="/api/events"&&method==="GET")return route.fulfill({json:{total:url.searchParams.get("host")?1:15008,page:1,page_size:100,rows:[event],histogram:[{time:"2026-09-26T09:53:00Z",count:9}],histogram_interval:"1m"}});
    if(path==="/api/events/"+event.id&&method==="GET")return route.fulfill({json:event});
    return route.fulfill({status:404,json:{detail:"Unhandled test route"}});
  });

  await page.goto("/");
  await page.getByLabel("CLASS CODE").fill("CY530");
  await page.getByLabel("ANALYST DISPLAY NAME").fill("Alex Chen");
  await page.getByRole("button",{name:/Enter the lab/}).click();
  await expect(page.getByRole("heading",{name:"The Expected Service"})).toBeVisible();
  await expect(page.getByRole("heading",{name:"Meet your evidence."})).toBeVisible();
  await expect(page.getByRole("heading",{name:"Technical context"})).toBeHidden();
  await page.getByText("Test your instinct",{exact:true}).click();
  await page.getByRole("button",{name:"Corroborating evidence that strengthens the investigation timeline."}).click();
  await expect(page.getByRole("status")).toContainText("Right. Matching host, service identity");
  await page.getByText("Test your instinct",{exact:true}).click();
  await page.evaluate(()=>window.scrollTo({top:0,behavior:"instant"}));
  await page.screenshot({animations:"disabled",path:testInfo.outputPath("briefing-desktop.png"),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);
  await page.evaluate(()=>window.scrollTo({top:0,behavior:"instant"}));
  await page.screenshot({animations:"disabled",path:testInfo.outputPath("briefing-mobile.png"),fullPage:true});
  await page.setViewportSize({width:1440,height:1000});
  await page.getByRole("button",{name:"Inspect CSG state",exact:true}).click();
  await expect(page.getByRole("heading",{name:/Beginning endpoint state/})).toBeVisible();
  await expect(page.getByText("BackupAgent",{exact:true}).first()).toBeVisible();
  await page.getByRole("navigation",{name:"Investigation sections"}).getByRole("button",{name:/Wazuh events/i}).click();
  await expect(page.getByText("15,008")).toBeVisible();
  await page.locator(".event-row-main").first().click();
  await expect(page.getByText("EVENT DETAILS")).toBeVisible();
  await expect(page.getByRole("button",{name:"View raw event JSON"})).toBeVisible();
  await page.getByRole("button",{name:"View raw event JSON"}).click();
  await expect(page.locator(".raw-json")).toContainText("serviceName");
  const detailBox=await page.locator(".event-detail-drawer").boundingBox();
  expect(detailBox!.height).toBeGreaterThan(350);
  await page.evaluate(()=>window.scrollTo({top:0,behavior:"instant"}));
  await page.screenshot({animations:"disabled",path:testInfo.outputPath("wazuh-details-desktop.png"),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);
  await page.evaluate(()=>window.scrollTo({top:0,behavior:"instant"}));
  await page.screenshot({animations:"disabled",path:testInfo.outputPath("wazuh-details-mobile.png"),fullPage:true});
  await page.setViewportSize({width:1440,height:1000});
  await page.getByRole("button",{name:"Filter this host"}).click();
  await expect(page.getByLabel("Event host")).toHaveValue("WIN-LAB-01");
  await expect(page.locator(".results-topline")).toContainText("1 matching event");
  await page.locator(".event-row-main").first().click();
  await expect(page.locator(".event-detail-drawer")).toContainText("C:\\Program Files\\BackupAgent\\agent.exe");
  expect((await page.locator(".event-detail-drawer").boundingBox())!.height).toBeGreaterThan(350);
  await page.getByRole("button",{name:"Remove host filter"}).click();
  await expect(page.getByLabel("Event host")).toHaveValue("");
  await expect(page.locator(".event-detail-drawer")).toHaveCount(0);
  await page.locator(".event-row-main").first().click();
  await page.getByRole("button",{name:"Add to investigation",exact:true}).last().click();
  await expect(page.getByRole("button",{name:/1 collected/})).toBeVisible();
  await page.getByRole("button",{name:/Reconcile/}).click();
  await page.locator(".evidence-tray .tray-event-main").click();
  await expect(page.getByRole("dialog",{name:"Collected event details"})).toBeVisible();
  await expect(page.getByRole("dialog").getByText("BackupAgent",{exact:true})).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.locator(".evidence-tray .tray-event-main")).toBeFocused();
  await page.getByRole("button",{name:/^Consistent/}).click();
  await page.getByLabel(/Analyst reasoning/).fill("The event names the same host and service, and records its creation in the snapshot interval.");
  await page.evaluate(()=>window.scrollTo({top:0,behavior:"instant"}));
  await page.screenshot({animations:"disabled",path:testInfo.outputPath("reconcile-desktop.png"),fullPage:true});
  await page.getByRole("button",{name:/Submit reconciliation/}).click();
  await expect(page.getByText("CSG RESULT")).toBeVisible();
  await expect(page.getByText("CORRECT")).toBeVisible();
});
