package webui

import (
	"net/http"
	"strings"
)

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
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AAA — Amiga AntiVirus Appliance</title>
<link rel="stylesheet" href="/ui/style.css">
</head>
<body>
<header><div><h1>AAA</h1><p>Amiga AntiVirus Appliance</p></div><span id="health" class="badge">checking…</span></header>
<main>
<section class="panel">
<h2>Scan a file</h2>
<p class="muted">Upload an Amiga disk image, archive or file for analysis.</p>
<div class="upload-row"><input id="file" type="file"><button id="scan" type="button">Scan</button></div>
<p id="upload-status" class="status" aria-live="polite"></p>
</section>
<section class="panel">
<div class="section-head"><div><h2>Scan history</h2><p class="muted">Recent jobs recorded by the AAA daemon.</p></div><button id="refresh" type="button" class="secondary">Refresh</button></div>
<div class="table-wrap"><table><thead><tr><th>ID</th><th>State</th><th>Submitted</th><th>Result</th></tr></thead><tbody id="scans"><tr><td colspan="4" class="muted">Loading…</td></tr></tbody></table></div>
</section>
<section id="details" class="panel hidden"><div class="section-head"><h2>Scan result</h2><button id="close-details" type="button" class="secondary">Close</button></div><pre id="result"></pre></section>
</main>
<footer><span id="version">AAA</span> · local appliance UI</footer>
<script src="/ui/app.js" defer></script>
</body>
</html>`

const appJS = `"use strict";
const $ = (id) => document.getElementById(id);
const scans = $("scans");
function esc(value) { return String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c])); }
async function json(url, options) { const r = await fetch(url, options); const body = await r.json().catch(() => ({})); if (!r.ok) throw new Error(body.error || ("HTTP " + r.status)); return body; }
async function loadHealth() { try { const h = await json("/healthz"); $("health").textContent = h.status === "ok" ? "healthy" : h.status; $("health").className = "badge good"; } catch { $("health").textContent = "unavailable"; $("health").className = "badge bad"; } }
async function loadVersion() { try { const v = await json("/version"); $("version").textContent = "AAA " + v.version + " · API " + v.api_version; } catch {} }
async function loadScans() { scans.innerHTML = '<tr><td colspan="4" class="muted">Loading…</td></tr>'; try { const jobs = await json("/api/v1/scans"); if (!jobs.length) { scans.innerHTML = '<tr><td colspan="4" class="muted">No scans yet.</td></tr>'; return; } scans.innerHTML = jobs.map(j => '<tr><td><code>'+esc(j.id)+'</code></td><td><span class="state '+esc(j.state)+'">'+esc(j.state)+'</span></td><td>'+esc(new Date(j.submitted_at).toLocaleString())+'</td><td><button class="secondary result-button" data-id="'+esc(j.id)+'">View</button></td></tr>').join(""); document.querySelectorAll(".result-button").forEach(b => b.addEventListener("click", () => showResult(b.dataset.id))); } catch (e) { scans.innerHTML = '<tr><td colspan="4" class="bad-text">'+esc(e.message)+'</td></tr>'; } }
async function showResult(id) { try { const r = await json("/api/v1/scans/"+encodeURIComponent(id)+"/results"); $("result").textContent = JSON.stringify(r, null, 2); $("details").classList.remove("hidden"); $("details").scrollIntoView({behavior:"smooth"}); } catch (e) { $("result").textContent = e.message; $("details").classList.remove("hidden"); } }
async function submit() { const f = $("file").files[0]; if (!f) { $("upload-status").textContent = "Choose a file first."; return; } $("scan").disabled = true; $("upload-status").textContent = "Uploading…"; try { const r = await json("/api/v1/scans", {method:"POST", headers:{"Content-Type":"application/octet-stream","X-AAA-Filename":f.name}, body:f}); $("upload-status").textContent = "Queued as " + r.id + (r.duplicate ? " (payload already stored; re-scan queued)" : ""); await loadScans(); } catch (e) { $("upload-status").textContent = e.message; } finally { $("scan").disabled = false; } }
$("scan").addEventListener("click", submit); $("refresh").addEventListener("click", loadScans); $("close-details").addEventListener("click", () => $("details").classList.add("hidden"));
loadHealth(); loadVersion(); loadScans(); setInterval(loadHealth, 30000); setInterval(loadScans, 10000);`

const styleCSS = `:root{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color-scheme:dark;background:#111827;color:#e5e7eb}*{box-sizing:border-box}body{margin:0;background:#0b1020}header,main,footer{max-width:1100px;margin:auto}header{display:flex;align-items:center;justify-content:space-between;padding:2rem 1rem 1rem}h1{font-size:2rem;margin:0}h2{margin:.1rem 0 .35rem}p{margin:.2rem 0}.muted{color:#9ca3af}.badge,.state{display:inline-block;border-radius:999px;padding:.3rem .65rem;background:#374151;font-size:.85rem}.good,.succeeded{background:#064e3b;color:#a7f3d0}.bad,.failed,.canceled{background:#7f1d1d;color:#fecaca}.running{background:#1e3a8a;color:#bfdbfe}.pending{background:#78350f;color:#fde68a}main{padding:0 1rem 2rem}.panel{background:#151c2e;border:1px solid #283044;border-radius:12px;padding:1.1rem;margin:1rem 0;box-shadow:0 10px 30px #0004}.section-head,.upload-row{display:flex;gap:1rem;align-items:center;justify-content:space-between}.upload-row{justify-content:flex-start;margin-top:1rem;flex-wrap:wrap}button,input::file-selector-button{border:0;border-radius:8px;padding:.65rem .9rem;background:#2563eb;color:white;font-weight:600;cursor:pointer}.secondary,input::file-selector-button{background:#374151}button:disabled{opacity:.55;cursor:default}.status{min-height:1.4rem;margin-top:.8rem}.table-wrap{overflow:auto;margin-top:1rem}table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid #283044;padding:.7rem .45rem;white-space:nowrap}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1020;padding:1rem;border-radius:8px;max-height:60vh;overflow:auto}.hidden{display:none}.bad-text{color:#fecaca}footer{padding:0 1rem 2rem;color:#6b7280;font-size:.85rem}@media(max-width:650px){header{padding-top:1.2rem}.section-head{align-items:flex-start}th:nth-child(3),td:nth-child(3){display:none}}`

var _ = strings.Builder{}
