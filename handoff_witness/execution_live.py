"""Receiver-checked browser execution through the approval gate (virtual passkey)."""
import argparse
import asyncio
import hashlib
import json
import platform
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from webauthn import generate_registration_options, options_to_json, verify_registration_response
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import AuthenticatorSelectionCriteria, UserVerificationRequirement

from .approval import ApprovalGate, verify_bundle
from .core import digest, export_public
from .execution import ApprovedBrowser
from .execution_audit import verify_execution


def verify_fixture_audit(out, executor, gate, credential_id, credential_key):
    """Use the live harness's anchors, not identities declared by the evidence."""
    checkpoint = executor.journal.snapshot()[1]
    if checkpoint != json.loads((out / "audit/checkpoint.json").read_text()):
        raise ValueError("Exported checkpoint differs from the harness checkpoint")
    result = verify_execution(json.loads((out / "audit/bundle.json").read_text()), checkpoint,
        executor_key=executor.journal.key.public_key(), gate_key=gate.key.public_key(),
        credential_id=credential_id, credential_public_key=credential_key,
        rp_id=gate.rp_id, origin=gate.origin)
    (out / "audit-result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


class ExecutionFixture:
    def __init__(self):
        self.ledger = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def handle_request(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                owner.ledger.append({"path": self.path, "method": self.command,
                                     "body_sha256": hashlib.sha256(body).hexdigest(),
                                     "headers_sha256": digest({k.lower(): v for k, v in self.headers.items()})})
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/redirect-target")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path == "/index":
                    data = b'''<!doctype html><title>Approval execution fixture</title>
                    <link rel="icon" href="data:,">
                    <img src="/image-denied"><iframe src="/frame-denied"></iframe>
                    <script src="/script-denied"></script><p>Approved page</p>'''
                elif self.path == "/worker":
                    data = b"fetch('/worker-denied').then(() => postMessage('unexpected')).catch(() => postMessage('blocked'));"
                else:
                    data = b"<!doctype html><title>Test fixture</title>OK"
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript" if self.path == "/worker" else "text/html")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = handle_request
            do_POST = handle_request

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://localhost:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


async def run(out, channel=None):
    from playwright.async_api import async_playwright, Error

    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    with ExecutionFixture() as fixture:
        key = Ed25519PrivateKey.generate()
        gate = ApprovalGate(out / "gate.sqlite", rp_id="localhost", origin=fixture.base, signing_key=key)
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True, **({"channel": channel} if channel else {}))
            executor = None
            try:
                # Isolated trusted approval surface; never given to the browsing agent.
                control = await browser.new_context(service_workers="block")
                async def control_route(route):
                    if route.request.url == fixture.base + "/approval-ui":
                        await route.continue_()
                    else:
                        await route.abort()
                await control.route("**/*", control_route)
                ui = await control.new_page()
                cdp = await control.new_cdp_session(ui)
                await cdp.send("WebAuthn.enable")
                await cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {"protocol": "ctap2", "transport": "internal", "hasResidentKey": True, "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})
                await ui.goto(fixture.base + "/approval-ui")
                registration_options = generate_registration_options(rp_id="localhost", rp_name="Execution Test", user_name="virtual-user", user_id=b"execution-test-user", authenticator_selection=AuthenticatorSelectionCriteria(user_verification=UserVerificationRequirement.REQUIRED))
                registration = await ui.evaluate("async o => (await navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(o)})).toJSON()", json.loads(options_to_json(registration_options)))
                enrolled = verify_registration_response(credential=registration, expected_challenge=registration_options.challenge, expected_rp_id="localhost", expected_origin=fixture.base, require_user_verification=True)
                gate.enroll_trusted(enrolled.credential_id, enrolled.credential_public_key, enrolled.sign_count)
                fixture.ledger.clear()  # Exclude explicitly separate approval-control bootstrap.
                bundles, before_dispatch, saved_ids = [], [], []
                lock = asyncio.Lock()

                async def approve(binding):
                    path = urlsplit(binding["url"]).path
                    if path == "/timeout":
                        await asyncio.Future()
                    if path == "/error":
                        raise RuntimeError("Injected approval service failure")
                    if path == "/replay":
                        return saved_ids[0]
                    if path not in {"/index", "/post", "/redirect", "/worker", "/changed", "/revoked"}:
                        return None
                    async with lock:
                        before_dispatch.append(not any(r["path"] == path for r in fixture.ledger))
                        if path == "/changed":
                            binding["body_sha256"] = "0" * 64
                        options = gate.begin(binding, enrolled.credential_id)
                        assertion = await ui.evaluate("async o => (await navigator.credentials.get({publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(o)})).toJSON()", options["publicKey"])
                        bundle = gate.finish(options["approval_id"], assertion)
                        verify_bundle(bundle, gate_key=key.public_key(), credential_id=enrolled.credential_id, credential_public_key=enrolled.credential_public_key, expected_binding=binding, rp_id="localhost", origin=fixture.base)
                        bundles.append(bundle)
                        saved_ids.append(options["approval_id"])
                        if path == "/revoked":
                            gate.revoke(enrolled.credential_id)
                        return options["approval_id"]

                executor = await ApprovedBrowser.create(browser, gate, approve, allowed_origins=[fixture.base], approval_timeout=8)
                page = await executor.new_page()
                try:
                    await page.goto(fixture.base + "/no-approval")
                    denied_navigation = False
                except Error:
                    denied_navigation = True
                await page.close()
                page = await executor.new_page()
                await page.goto(fixture.base + "/index")
                async def fetch(path, method="GET", body=None):
                    return await page.evaluate("async a => {try {let r = await fetch(a.path, {method:a.method, ...(a.body === null ? {} : {body:a.body})}); return {status:r.status};} catch(e) {return {blocked:true};}}", {"path": path, "method": method, "body": body})
                post = await fetch("/post", "POST", "approved-body")
                changed = await fetch("/changed", "POST", "actual-body")
                replay = await fetch("/replay")
                redirect = await fetch("/redirect")
                denied = await fetch("/fetch-denied")
                error = await fetch("/error")
                # Approval timeout is reduced only for the explicit timeout fixture.
                executor._timeout = 0.05
                timeout = await fetch("/timeout")
                executor._timeout = 8
                outside = await fetch(fixture.base.replace("localhost", "127.0.0.1") + "/outside")
                worker = await page.evaluate("() => new Promise(resolve => {let w = new Worker('/worker'); w.onmessage = e => {w.terminate(); resolve(e.data)}; w.onerror = () => resolve('worker-error');})")
                socket = await page.evaluate("url => new Promise(resolve => {let ws = new WebSocket(url); ws.onopen = () => {ws.close(); resolve('opened')}; ws.onerror = () => resolve('blocked'); ws.onclose = () => resolve('blocked');})", fixture.base.replace("http:", "ws:") + "/ws")
                # Real window.open exercises the context-wide popup interception.
                async with page.expect_popup() as opened:
                    await page.evaluate("window.open('/popup-denied')")
                popup = await opened.value
                try:
                    await popup.wait_for_load_state()
                except Error:
                    pass
                revoked = await fetch("/revoked")
                await executor.close()
                executor.save_evidence(out / "audit")
                audit = verify_fixture_audit(out, executor, gate, enrolled.credential_id, enrolled.credential_public_key)
                counts = Counter(r["path"] for r in fixture.ledger)
                expected = Counter({"/index": 1, "/post": 1, "/redirect": 1, "/worker": 1})
                successful = [e for e in executor.events if e["status"] == "response_received"]
                binding_matches = all(any(r["path"] == urlsplit(e["binding"]["url"]).path and
                                          all(r[k] == e["binding"][k] for k in ("method", "body_sha256", "headers_sha256"))
                                          for r in fixture.ledger) for e in successful)
                checks = {"unapproved_navigation_blocked": denied_navigation,
                          "verified_journal_matches_receiver": Counter(urlsplit(r["binding"]["url"]).path for r in audit["requests"]) == counts and all(
                              r["stage"] == "relay_prepared" and any(row["path"] == urlsplit(r["binding"]["url"]).path and
                              all(row[k] == r["binding"][k] for k in ("method", "body_sha256", "headers_sha256")) for row in fixture.ledger)
                              for r in audit["requests"]),
                          "approved_post_received": post == {"status": 200},
                          "changed_body_blocked": changed == {"blocked": True},
                          "reused_approval_blocked": replay == {"blocked": True},
                          "redirect_not_followed": redirect == {"status": 502},
                          "fetch_without_approval_blocked": denied == {"blocked": True},
                          "approval_error_blocks": error == {"blocked": True},
                          "approval_timeout_blocks": timeout == {"blocked": True},
                          "outside_origin_blocked": outside == {"blocked": True},
                          "worker_fetch_blocked": worker == "blocked",
                          "websocket_blocked": socket == "blocked",
                          "revoked_approval_blocked": revoked == {"blocked": True},
                          "receiver_contains_only_approved_operations": counts == expected,
                          "receiver_bytes_match_binding": binding_matches and len(successful) == 4,
                          "no_receiver_arrival_before_approval": all(before_dispatch),
                          "popup_and_subresources_intercepted": {"/popup-denied", "/image-denied", "/frame-denied", "/script-denied"} <= {urlsplit(e["url"]).path for e in executor.events}}
                report = {"kind": "approval_gated_browser_execution", "browser_version": browser.version,
                          "playwright_version": version("playwright"), "python_version": platform.python_version(),
                          "checks": checks, "passed": all(checks.values()), "receiver_path_counts": dict(counts),
                          "limitations": ["Virtual authenticator, not a human approval ceremony.",
                                          "Trusted browser/controller HTTP(S) boundary, not OS egress isolation.",
                                          "Redirects and WebSockets blocked; service workers disabled.",
                                          "Broker relays responses; it is not the browser native HTTP transport.",
                                          "Receiver ledger shares the test process; no independent execution witness."]}
                for name, value in [("report.json", report), ("receiver.json", fixture.ledger), ("execution.json", executor.events), ("approvals.json", bundles)]:
                    (out / name).write_text(json.dumps(value, indent=2) + "\n")
                (out / "gate-public.pem").write_bytes(export_public(key.public_key()))
                (out / "credential-public.cbor").write_bytes(enrolled.credential_public_key)
                (out / "credential-id.txt").write_text(bytes_to_base64url(enrolled.credential_id))
                executor = None
                return report
            finally:
                if executor is not None:
                    await executor.close()
                    (out / "execution.json").write_text(json.dumps(executor.events, indent=2) + "\n")
                    (out / "receiver.json").write_text(json.dumps(fixture.ledger, indent=2) + "\n")
                await browser.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--channel", choices=["chrome", "chromium"])
    args = parser.parse_args()
    async def bounded_run():
        return await asyncio.wait_for(run(args.out, args.channel), 120)
    report = asyncio.run(bounded_run())
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
