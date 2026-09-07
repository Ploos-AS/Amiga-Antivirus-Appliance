package webui

import "net/http"

// New returns a same-origin web UI handler that delegates non-UI routes to api.
func New(api http.Handler) http.Handler {
	return &handler{api: api}
}

type handler struct {
	api http.Handler
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/", "/ui/":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		setUIHeaders(w, "text/html; charset=utf-8")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(indexHTML))
		}
	case "/ui/app.js":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		setUIHeaders(w, "text/javascript; charset=utf-8")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(appJS))
		}
	case "/ui/style.css":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		setUIHeaders(w, "text/css; charset=utf-8")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(styleCSS))
		}
	default:
		if h.api == nil {
			http.NotFound(w, r)
			return
		}
		h.api.ServeHTTP(w, r)
	}
}

func setUIHeaders(w http.ResponseWriter, contentType string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
}

const indexHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AAA — Amiga AntiVirus Appliance</title><link rel="stylesheet" href="/ui/style.css"></head>
<body><header><div><h1>AAA</h1><p>Amiga AntiVirus Appliance</p></div><span id="health" class="badge">checking…</span></header><main>
<section class="panel"><h2>Scan a file</h2><p class="muted">Upload an Amiga disk image, archive or file for analysis.</p><div class="upload-row"><input id="file" type="file"><button id="scan" type="button">Scan</button></div><p id="upload-status" class="status" aria-live="polite"></p></section>
<section class="panel"><div class="section-head"><div><h2>Scan history</h2><p class="muted">Recent jobs recorded by the AAA daemon.</p></div><button id="refresh" type="button" class="secondary">Refresh</button></div><div class="table-wrap"><table><thead><tr><th>ID</th><th>State</th><th>Submitted</th><th>Result</th></tr></thead><tbody id="scans"><tr><td colspan="4" class="muted">Loading…</td></tr></tbody></table></div></section>
<section id="details" class="panel hidden"><div class="section-head"><div><h2>Scan result</h2><p id="result-name" class="muted"></p></div><button id="close-details" type="button" class="secondary">Close</button></div><div id="result"></div></section>
</main><footer><span id="version">AAA</span> · local appliance UI</footer><script src="/ui/app.js" defer></script></body></html>`

const appJS = `"use strict";
const $ = id => document.getElementById(id), scans = $("scans");
function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));}
function humanBytes(n){if(!Number.isFinite(Number(n)))return "—";let v=Number(n),u="B";for(const x of ["KiB","MiB","GiB"]){if(v<1024)break;v/=1024;u=x;}return (u==="B"?v:v.toFixed(1))+" "+u;}
function badge(v){const s=String(v||"unknown");return '<span class="state '+esc(s)+'">'+esc(s)+'</span>';}
function field(k,v,mono=false){if(v===undefined||v===null||v==="")return "";return '<div class="kv"><span>'+esc(k)+'</span><'+(mono?'code':'strong')+'>'+esc(v)+'</'+(mono?'code':'strong')+'></div>';}
function jsonBlock(title,v){if(!v)return "";return '<details><summary>'+esc(title)+'</summary><pre>'+esc(JSON.stringify(v,null,2))+'</pre></details>';}
function renderMembers(items){if(!Array.isArray(items)||!items.length)return "";return '<div class="members">'+items.map(m=>'<div class="member"><div class="member-head"><strong>'+esc(m.name||"member")+'</strong>'+badge(m.verdict)+'</div>'+field("Format",m.format)+field("Size",humanBytes(m.size))+field("SHA-256",m.sha256,true)+(m.detection?'<p class="detection">'+esc(m.detection)+'</p>':"")+(m.error?'<p class="bad-text">'+esc(m.error)+'</p>':"")+renderMembers(m.children)+jsonBlock("Member analysis",Object.fromEntries(Object.entries(m).filter(([k])=>!["name","size","sha256","format","verdict","detection","error","children"].includes(k))))+'</div>').join("")+'</div>';}
function kindLabel(k){return ({native:"AAA Native",clamav:"ClamAV","historical-amiga":"Historical Amiga"})[k]||k||"Engine";}
function renderComponents(items){if(!Array.isArray(items)||!items.length)return "";return '<div class="components"><h4>Support components</h4>'+items.map(c=>'<div class="component">'+field("Component",c.name)+field("Kind",c.kind)+field("Version",c.version)+field("SHA-256",c.sha256,true)+field("Source",c.source)+'</div>').join("")+'</div>';}
function renderEngineCard(e){const title=e.engine_name||e.engine_id||kindLabel(e.kind);return '<article class="engine-card"><div class="engine-head"><div><span class="eyebrow">'+esc(kindLabel(e.kind))+'</span><h4>'+esc(title)+'</h4></div>'+badge(e.status==="error"?"error":e.verdict)+'</div>'+field("Engine ID",e.engine_id,true)+field("Version",e.engine_version)+field("Database",e.database_id)+field("DB version",e.database_version)+field("OS profile",e.os_profile)+field("Input SHA-256",e.input_sha256,true)+field("Binary SHA-256",e.binary_sha256,true)+field("Raw evidence SHA-256",e.raw_evidence_sha256,true)+(e.detection_name?'<div class="alert compact"><strong>Detection</strong><p>'+esc(e.detection_name)+'</p></div>':"")+(e.error?'<p class="bad-text">'+esc(e.error)+'</p>':"")+renderComponents(e.components)+'</article>';}
function renderEngines(items){if(!Array.isArray(items)||!items.length)return '<section class="result-card wide"><h3>Engine evidence</h3><p class="muted">No attributed engine records were stored for this scan.</p></section>';const verdicts=new Set(items.filter(e=>e.status==="completed").map(e=>String(e.verdict||"unknown")));const disagreement=verdicts.size>1;const errors=items.filter(e=>e.status==="error").length;return '<section class="result-card wide"><div class="section-head"><div><h3>Engine evidence</h3><p class="muted">Independent analysis results with version and database provenance.</p></div><div class="engine-summary">'+(disagreement?'<span class="state suspicious">disagreement</span>':'<span class="state clean">consistent</span>')+(errors?'<span class="state error">'+errors+' error'+(errors===1?'':'s')+'</span>':'')+'</div></div>'+(disagreement?'<div class="warning"><strong>Engine disagreement</strong><p>Completed engines reported different verdicts. Review each engine independently; no evidence has been hidden by the aggregate view.</p></div>':'')+'<div class="engine-grid">'+items.map(renderEngineCard).join("")+'</div></section>';}
function renderResult(r){const known=new Set(["path","name","size","sha256","format","verdict","detection","engine_results","archive","preservation_image","member_results","adf","filesystem","hunk","bootblock_match"]);const extra=Object.fromEntries(Object.entries(r).filter(([k])=>!known.has(k)));return '<div class="result-hero"><div><span class="eyebrow">Aggregate verdict</span><div class="verdict">'+badge(r.verdict)+'</div></div><div class="hero-meta">'+field("Format",r.format)+field("Size",humanBytes(r.size))+field("SHA-256",r.sha256,true)+'</div></div>'+(r.detection?'<div class="alert"><strong>Detection</strong><p>'+esc(r.detection)+'</p></div>':"")+renderEngines(r.engine_results)+'<div class="result-grid"><section class="result-card"><h3>Native AAA analysis</h3>'+jsonBlock("Bootblock match",r.bootblock_match)+jsonBlock("ADF analysis",r.adf)+jsonBlock("Filesystem analysis",r.filesystem)+jsonBlock("Hunk analysis",r.hunk)+(!r.bootblock_match&&!r.adf&&!r.filesystem&&!r.hunk?'<p class="muted">No format-specific native analysis details.</p>':"")+'</section><section class="result-card"><h3>Container / preservation</h3>'+jsonBlock("Archive analysis",r.archive)+jsonBlock("Preservation image",r.preservation_image)+(!r.archive&&!r.preservation_image?'<p class="muted">Not an archive or preservation-image result.</p>':"")+'</section></div>'+(Array.isArray(r.member_results)&&r.member_results.length?'<section class="result-card wide"><h3>Archive members</h3>'+renderMembers(r.member_results)+'</section>':"")+(Object.keys(extra).length?'<section class="result-card wide"><h3>Additional attributed evidence</h3><p class="muted">Fields added by later API revisions are preserved here.</p>'+jsonBlock("Additional evidence",extra)+'</section>':"")+'<details class="raw"><summary>Raw API result</summary><pre>'+esc(JSON.stringify(r,null,2))+'</pre></details>';}
async function json(url,opt){const x=await fetch(url,opt),b=await x.json().catch(()=>({}));if(!x.ok)throw new Error(b.error||("HTTP "+x.status));return b;}
async function loadHealth(){try{const h=await json("/healthz");$("health").textContent=h.status==="ok"?"healthy":h.status;$("health").className="badge good";}catch{$("health").textContent="unavailable";$("health").className="badge bad";}}
async function loadVersion(){try{const v=await json("/version");$("version").textContent="AAA "+v.version+" · API "+v.api_version;}catch{}}
async function loadScans(){scans.innerHTML='<tr><td colspan="4" class="muted">Loading…</td></tr>';try{const jobs=await json("/api/v1/scans");if(!jobs.length){scans.innerHTML='<tr><td colspan="4" class="muted">No scans yet.</td></tr>';return;}scans.innerHTML=jobs.map(j=>'<tr><td><code>'+esc(j.id)+'</code></td><td>'+badge(j.state)+'</td><td>'+esc(new Date(j.submitted_at).toLocaleString())+'</td><td><button class="secondary result-button" data-id="'+esc(j.id)+'">View</button></td></tr>').join("");document.querySelectorAll(".result-button").forEach(b=>b.addEventListener("click",()=>showResult(b.dataset.id)));}catch(e){scans.innerHTML='<tr><td colspan="4" class="bad-text">'+esc(e.message)+'</td></tr>';}}
async function showResult(id){try{const r=await json("/api/v1/scans/"+encodeURIComponent(id)+"/results");$("result-name").textContent=r.name||id;$("result").innerHTML=renderResult(r);$("details").classList.remove("hidden");$("details").scrollIntoView({behavior:"smooth"});}catch(e){$("result-name").textContent=id;$("result").innerHTML='<p class="bad-text">'+esc(e.message)+'</p>';$("details").classList.remove("hidden");}}
async function submit(){const f=$("file").files[0];if(!f){$("upload-status").textContent="Choose a file first.";return;}$("scan").disabled=true;$("upload-status").textContent="Uploading…";try{const r=await json("/api/v1/scans",{method:"POST",headers:{"Content-Type":"application/octet-stream","X-AAA-Filename":f.name},body:f});$("upload-status").textContent="Queued as "+r.id+(r.duplicate?" (payload already stored; re-scan queued)":"");await loadScans();}catch(e){$("upload-status").textContent=e.message;}finally{$("scan").disabled=false;}}
$("scan").addEventListener("click",submit);$("refresh").addEventListener("click",loadScans);$("close-details").addEventListener("click",()=>$("details").classList.add("hidden"));loadHealth();loadVersion();loadScans();setInterval(loadHealth,30000);setInterval(loadScans,10000);`

const styleCSS = `:root{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color-scheme:dark;background:#111827;color:#e5e7eb}*{box-sizing:border-box}body{margin:0;background:#0b1020}header,main,footer{max-width:1100px;margin:auto}header{display:flex;align-items:center;justify-content:space-between;padding:2rem 1rem 1rem}h1{font-size:2rem;margin:0}h2,h3,h4{margin:.1rem 0 .35rem}p{margin:.2rem 0}.muted{color:#9ca3af}.badge,.state{display:inline-block;border-radius:999px;padding:.3rem .65rem;background:#374151;font-size:.85rem}.good,.succeeded,.clean,.consistent{background:#064e3b;color:#a7f3d0}.bad,.failed,.canceled,.infected,.error{background:#7f1d1d;color:#fecaca}.running{background:#1e3a8a;color:#bfdbfe}.pending,.unknown,.suspicious{background:#78350f;color:#fde68a}main{padding:0 1rem 2rem}.panel,.result-card{background:#151c2e;border:1px solid #283044;border-radius:12px;padding:1.1rem;margin:1rem 0;box-shadow:0 10px 30px #0004}.section-head,.upload-row,.member-head,.result-hero,.engine-head,.engine-summary{display:flex;gap:1rem;align-items:center;justify-content:space-between}.engine-summary{justify-content:flex-end;flex-wrap:wrap}.upload-row{justify-content:flex-start;margin-top:1rem;flex-wrap:wrap}button,input::file-selector-button{border:0;border-radius:8px;padding:.65rem .9rem;background:#2563eb;color:white;font-weight:600;cursor:pointer}.secondary,input::file-selector-button{background:#374151}button:disabled{opacity:.55;cursor:default}.status{min-height:1.4rem;margin-top:.8rem}.table-wrap{overflow:auto;margin-top:1rem}table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid #283044;padding:.7rem .45rem;white-space:nowrap}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.result-hero{background:#0f172a;border-radius:10px;padding:1rem;margin-top:1rem;align-items:flex-start}.eyebrow{display:block;color:#9ca3af;font-size:.8rem;text-transform:uppercase;letter-spacing:.08em}.verdict{margin-top:.4rem}.hero-meta{min-width:55%}.kv{display:grid;grid-template-columns:8rem 1fr;gap:.7rem;padding:.25rem 0}.kv span{color:#9ca3af}.kv code{overflow-wrap:anywhere}.result-grid,.engine-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}.result-card{margin:1rem 0;box-shadow:none}.wide{width:100%}.engine-card{background:#0f172a;border:1px solid #334155;border-radius:10px;padding:1rem}.engine-card .kv{grid-template-columns:7rem 1fr}.components{border-top:1px solid #334155;margin-top:.8rem;padding-top:.7rem}.component{border-left:2px solid #475569;padding-left:.7rem;margin-top:.6rem}details{border-top:1px solid #283044;padding:.55rem 0}summary{cursor:pointer;font-weight:600}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1020;padding:1rem;border-radius:8px;max-height:50vh;overflow:auto}.raw{margin-top:1rem}.alert,.warning{border-left:4px solid #dc2626;background:#450a0a;padding:.8rem 1rem;margin:1rem 0}.warning{border-left-color:#d97706;background:#451a03}.compact{margin:.7rem 0}.members{display:grid;gap:.7rem;margin-top:.7rem}.member{border:1px solid #283044;border-radius:8px;padding:.75rem}.member .members{margin-left:1rem}.detection,.bad-text{color:#fecaca}.hidden{display:none}footer{padding:0 1rem 2rem;color:#6b7280;font-size:.85rem}@media(max-width:700px){header{padding-top:1.2rem}.section-head,.result-hero,.engine-head{align-items:flex-start}.result-grid,.engine-grid{grid-template-columns:1fr}.hero-meta{min-width:0}.kv,.engine-card .kv{grid-template-columns:6rem 1fr}th:nth-child(3),td:nth-child(3){display:none}}`
