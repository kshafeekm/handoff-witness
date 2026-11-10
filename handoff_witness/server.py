"""Loopback-only, controlled browser fixture. Labels are NOT authenticated input.

The browser timer makes a real HTTP request. Its token supplies fixture ancestry,
not an unforgeable causal proof. Recorder and receiver share a trust domain here.
"""

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .core import Recorder, verify

PAGE = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Handoff Witness · Research Lab</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#0c1424;color:#edf2fc}body{max-width:1000px;margin:60px auto;padding:0 24px}small,.muted{color:#a1b0ca}h1{font-size:44px;letter-spacing:-2px;margin:12px 0}h2{font-size:19px}p{line-height:1.65}code{color:#89e4c7}.tag{color:#89e4c7;letter-spacing:3px;font-size:12px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}.card{background:#152139;border:1px solid #30405a;border-radius:16px;padding:25px;margin:24px 0}button{border:0;border-radius:8px;padding:13px 18px;font-size:14px;font-weight:600;cursor:pointer;background:#8ce4c8;color:#102c26;margin:5px 8px 5px 0}button.secondary{background:#2b3b57;color:#edf2fc}button:disabled{opacity:.45;cursor:wait}strong{color:#8ce4c8}table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;border-bottom:1px solid #30405a;padding:13px 7px}th{color:#a1b0ca;font-weight:400}.warn{border-left:3px solid #e4bc78;padding-left:16px;color:#decaa6}#status{min-height:30px}a{color:#8ce4c8}@media(max-width:650px){.grid{display:block}h1{font-size:34px}body{margin:30px auto}}
</style>
<div class="tag">HANDOFF WITNESS / LOCAL RESEARCH LAB</div>
<h1>Control changes.<br>Origins should not.</h1>
<p class="muted">A delayed request can arrive after someone else takes the controls.<br>Compare current-controller labeling with recorded causal ancestry.</p>
<div class="grid"><section class="card"><h2>1 · Schedule an agent request</h2><p>The fixture records an agent input and registers a browser timer. The request fires after five seconds.</p><button id="schedule">Schedule agent request</button></section><section class="card"><h2>2 · Simulate human takeover</h2><p>Switch control before the timer fires. The pending request retains its original ancestry.</p><button class="secondary" id="takeover">Simulate human takeover</button><p>Controller: <strong id="controller">agent</strong></p></section></div>
<p id="status" aria-live="polite">Ready. Schedule a request, then simulate takeover.</p>
<section class="card"><h2>Observed requests</h2><table><thead><tr><th>Request</th><th>Current-controller baseline</th><th>Recorded origin</th><th>Observation</th></tr></thead><tbody id="rows"></tbody></table><p class="muted" id="empty">No requests received yet.</p></section>
<p class="warn">Controlled fixture, not a secure browser adapter. Actor labels and causal tokens are supplied by the demo. Signatures protect the record from modification; they do not authenticate a physical human or establish legal responsibility.</p>
<p><button class="secondary" id="export">Export signed evidence</button><span id="saved" class="muted"></span></p>
<script>
async function api(path,body){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})});if(!r.ok)throw Error(await r.text());return r.json()}
async function refresh(){const s=await(await fetch('/api/state')).json();document.querySelector('#controller').textContent=s.controller;const rows=document.querySelector('#rows');rows.replaceChildren();for(const r of s.requests){const tr=document.createElement('tr');for(const v of [r.request_id.slice(0,8),r.controller_at_dispatch,r.attribution,r.stage]){const td=document.createElement('td');td.textContent=v;tr.append(td)}rows.append(tr)}document.querySelector('#empty').hidden=s.requests.length>0}
document.querySelector('#schedule').onclick=async()=>{try{const r=await api('/api/schedule');document.querySelector('#status').textContent='Timer scheduled. Simulate human takeover now; request arrives in 5 seconds.';document.querySelector('#schedule').disabled=true;await refresh();setTimeout(async()=>{try{await fetch('/target/'+r.token);await refresh();document.querySelector('#status').textContent='Request received. Compare the controller with the recorded origin.'}catch(e){document.querySelector('#status').textContent=e.message}finally{document.querySelector('#schedule').disabled=false}},5000)}catch(e){document.querySelector('#status').textContent=e.message}};
document.querySelector('#takeover').onclick=async()=>{await api('/api/handoff');await refresh()};
document.querySelector('#export').onclick=async()=>{const r=await api('/api/export');document.querySelector('#saved').textContent='Saved '+r.path};refresh();
</script></html>"""


def make_server(port=8765, out="artifacts/browser"):
    recorder, pending, lock = Recorder(), {}, threading.Lock()
    recorder.handoff("agent")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, body, content_type="application/json"):
            raw = body.encode() if isinstance(body, str) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(raw)

        def loopback_host(self):
            return self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"

        def do_GET(self):
            # Reject DNS-rebinding hosts and cross-site subrequests that would add
            # unrelated rows to the signed fixture log.
            if not self.loopback_host() or self.headers.get("Sec-Fetch-Site") not in {None, "same-origin", "none"}:
                return self.reply(403, {"error": "loopback same-origin request required"})
            if self.path == "/":
                return self.reply(200, PAGE, "text/html; charset=utf-8")
            with lock:
                if self.path == "/api/state":
                    return self.reply(200, {"controller": recorder.state.controller, "requests": recorder.state.requests})
                if self.path.startswith("/target/"):
                    token = self.path.removeprefix("/target/")
                    parent = pending.pop(token, None)
                    recorder.request([parent] if parent else [], f"http://127.0.0.1:{self.server.server_port}{self.path}", stage="receiver_observed")
                    return self.reply(200, {"received": True})
            self.reply(404, {"error": "not found"})

        def do_POST(self):
            # No cross-origin mutation; bind loopback and reject foreign browser origins.
            allowed = f"http://127.0.0.1:{self.server.server_port}"
            if self.headers.get("Origin") not in {None, allowed} or not self.loopback_host():
                return self.reply(403, {"error": "loopback origin required"})
            if self.headers.get("Content-Type") != "application/json":
                return self.reply(415, {"error": "JSON required"})
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if size < 0 or size > 1024:
                    return self.reply(413, {"error": "body too large"})
                json.loads(self.rfile.read(size) or b"{}")
            except (ValueError, json.JSONDecodeError):
                return self.reply(400, {"error": "invalid JSON"})
            with lock:
                if self.path == "/api/schedule":
                    recorder.handoff("agent")
                    root = recorder.input("agent")
                    token = secrets.token_urlsafe(18)
                    pending[token] = recorder.effect([root], "fixture browser timer")
                    return self.reply(200, {"token": token})
                if self.path == "/api/handoff":
                    recorder.handoff("human")
                    return self.reply(200, {"controller": "human"})
                if self.path == "/api/export":
                    verify(recorder.records, recorder.checkpoint(), recorder.key.public_key())
                    recorder.save(out)
                    return self.reply(200, {"path": str(Path(out).resolve())})
            self.reply(404, {"error": "not found"})

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve(port, out):
    server = make_server(port, out)
    print(f"Research demo: http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
