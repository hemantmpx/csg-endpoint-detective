"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import ThemeToggle from "./theme-toggle";
import DeveloperCredit from "./developer-credit";
import { Activity, ArrowRight, Fingerprint, LockKeyhole, Presentation, ShieldCheck, Waypoints } from "lucide-react";

export default function Home() {
  const router=useRouter();
  const [code,setCode]=useState("");
  const [name,setName]=useState("");
  const [anonymous,setAnonymous]=useState(false);
  const [error,setError]=useState("");
  const [busy,setBusy]=useState(false);
  async function join(e:React.FormEvent){
    e.preventDefault();setBusy(true);setError("");
    try{
      const res=await fetch("/api/sessions",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json"},body:JSON.stringify({class_code:code.trim(),display_name:name,anonymous})});
      const data=await res.json();if(!res.ok)throw new Error(data.detail||"Unable to join the lab");
      router.push("/lab");
    }catch(err){setError(err instanceof Error?err.message:"Unable to connect to the classroom lab")}
    finally{setBusy(false)}
  }
  return <main className="entry-shell">
    <div className="entry-grid" aria-hidden="true"><span/><span/><span/><span/><span/><span/><span/><span/></div>
    <header className="entry-brand"><span className="brand-icon"><ShieldCheck size={21}/></span><div><strong>CSG <b>Endpoint Detective</b></strong><small>CLASSROOM INVESTIGATION LAB</small></div><Link className="presentation-link" href="/presentation" aria-label="Project presentation" title="Project presentation"><Presentation size={16}/><span>Project presentation</span><ArrowRight size={14}/></Link><ThemeToggle/></header>
    <section className="entry-content">
      <div className="entry-copy">
        <div className="eyebrow"><span className="eyebrow-line"/> CY530 · ENDPOINT INVESTIGATION LAB</div>
        <div className="entry-author"><strong>Hemant Upadhyay</strong><small>Research conducted under the guidance and support of Dr. Shuja</small></div>
        <h1>Follow the change.<br/><em>Find the evidence.</em></h1>
        <p>Compare CSG snapshots, search Wazuh records, and explain what the evidence supports.</p>
        <div className="entry-points">
          <div><span><Activity size={17}/></span><strong>Compare endpoint state</strong><small>Before, after, and changes in between</small></div>
          <div><span><Waypoints size={17}/></span><strong>Investigate the event logs</strong><small>Search, filter, and inspect raw records</small></div>
          <div><span><Fingerprint size={17}/></span><strong>Explain your finding</strong><small>Match the fields. Account for the gaps.</small></div>
        </div>
      </div>
      <form className="join-card" onSubmit={join}>
        <div className="card-overline">STUDENT ACCESS <span>CY530</span></div>
        <h2>Join the lab</h2>
        <p>Use the class code from your instructor.</p>
        <label>CLASS CODE<input required value={code} onChange={e=>setCode(e.target.value)} placeholder="Provided by your instructor" maxLength={24} autoCapitalize="none" autoComplete="off" autoCorrect="off" spellCheck={false}/><small>Class codes are not case-sensitive.</small></label>
        <label>ANALYST DISPLAY NAME<input value={name} disabled={anonymous} onChange={e=>setName(e.target.value)} placeholder="e.g. Alex Chen" maxLength={64}/></label>
        <label className="checkbox-row"><input type="checkbox" checked={anonymous} onChange={e=>setAnonymous(e.target.checked)}/><span><strong>Use a classroom alias</strong><small>A display name will be assigned for you.</small></span></label>
        {error&&<div className="form-error" role="alert">{error}</div>}
        <button className="join-button" disabled={busy}>{busy?"Connecting…":"Enter the lab"}<ArrowRight size={17}/></button>
        <div className="privacy-note"><LockKeyhole size={13}/> No student ID or email required</div>
      </form>
    </section>
    <footer className="entry-footer"><span>CY530 · CSG ENDPOINT DETECTIVE</span><DeveloperCredit/><a href="/instructor">INSTRUCTOR ACCESS <ArrowRight size={12}/></a></footer>
  </main>
}
