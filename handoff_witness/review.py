"""Local, capability-bootstrapped review UI for the controlled browser executor.

A fresh run enrolls one credential. Possession of the one-time local bootstrap
capability authorizes enrollment; this is not identity proof or OS isolation.
"""
import argparse
import asyncio
import hmac
import json
import secrets
import threading
import time
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from webauthn import generate_registration_options, options_to_json, verify_registration_response
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import AuthenticatorSelectionCriteria, UserVerificationRequirement

from .approval import ApprovalError, ApprovalGate
from .core import canonical, export_public
from .execution import ApprovedBrowser


class ReviewHub:
    """All methods run on the owning asyncio loop; HTTP threads use that loop."""
    def __init__(self, gate, *, ttl=120, max_pending=32, clock=time.monotonic):
        self.gate, self.ttl, self.max_pending, self.clock = gate, ttl, max_pending, clock
        self.credential_id = None
        self.credential_public_key = None
        self.registration = None
        self.pending = {}
        self.events, self.bundles = [], []
        self.enrolled = asyncio.Event()
        self.closed = False

    async def __call__(self, binding):
        if self.closed or self.credential_id is None or len(self.pending) >= self.max_pending:
            return None
        review_id = secrets.token_hex(24)
        item = {"id": review_id, "binding": json.loads(canonical(binding)),
                "deadline": self.clock() + self.ttl, "options": None,
                "future": asyncio.get_running_loop().create_future()}
        self.pending[review_id] = item
        try:
            return await asyncio.wait_for(item["future"], self.ttl)
        except asyncio.TimeoutError:
            self.events.append({"id": review_id, "status": "expired"})
            return None
        finally:
            self.pending.pop(review_id, None)

    def _item(self, review_id):
        item = self.pending.get(review_id)
        if not item or item["future"].done() or self.clock() >= item["deadline"]:
            raise ApprovalError("Request is no longer pending")
        return item

    async def handle(self, path, payload):
        if self.closed:
            raise ApprovalError("Review service is closed")
        if path == "/api/state":
            return {"enrolled": self.credential_id is not None,
                    "pending": [{"id": item["id"], "binding": item["binding"],
                                 "seconds_remaining": max(0, int(item["deadline"] - self.clock()))}
                                for item in self.pending.values() if not item["future"].done()],
                    "events": self.events[-20:]}
        if path == "/api/register/options":
            if self.credential_id is not None:
                raise ApprovalError("Credential already enrolled for this run")
            if self.registration is None or self.clock() >= self.registration[1]:
                options = generate_registration_options(rp_id=self.gate.rp_id, rp_name="Handoff Witness Local Review",
                    user_name="local-reviewer", user_id=secrets.token_bytes(32),
                    authenticator_selection=AuthenticatorSelectionCriteria(user_verification=UserVerificationRequirement.REQUIRED))
                self.registration = (options, self.clock() + 120)
            return json.loads(options_to_json(self.registration[0]))
        if path == "/api/register/finish":
            if self.credential_id is not None or self.registration is None or self.clock() >= self.registration[1]:
                raise ApprovalError("Registration unavailable or expired")
            result = verify_registration_response(credential=payload["credential"], expected_challenge=self.registration[0].challenge,
                expected_rp_id=self.gate.rp_id, expected_origin=self.gate.origin, require_user_verification=True)
            self.gate.enroll_trusted(result.credential_id, result.credential_public_key, result.sign_count)
            self.credential_id = result.credential_id
            self.credential_public_key = result.credential_public_key
            self.registration = None
            self.enrolled.set()
            return {"enrolled": True}
        item = self._item(payload.get("id"))
        if path == "/api/deny":
            item["future"].set_result(None)
            self.events.append({"id": item["id"], "status": "denied"})
            return {"status": "denied"}
        if path == "/api/approve/options":
            remaining = int(item["deadline"] - self.clock())
            if remaining < 1:
                raise ApprovalError("Request expired")
            if item["options"] is None:
                item["options"] = self.gate.begin(item["binding"], self.credential_id, ttl=min(300, remaining))
            return item["options"]
        if path == "/api/approve/finish":
            if item["options"] is None:
                raise ApprovalError("Begin approval first")
            approval_id = item["options"]["approval_id"]
            bundle = self.gate.finish(approval_id, payload["credential"])
            self.bundles.append(bundle)
            item["future"].set_result(approval_id)
            self.events.append({"id": item["id"], "status": "credential_verified", "approval_id": approval_id})
            return {"status": "credential_verified"}
        raise ApprovalError("Unknown review operation")

    def close(self):
        self.closed = True
        for item in self.pending.values():
            if not item["future"].done():
                item["future"].set_result(None)
                self.events.append({"id": item["id"], "status": "closed"})


ASSETS = Path(__file__).with_name("review_assets")


class ReviewServer:
    """Loopback-only server with exact Host/Origin, one-use bootstrap, and CSRF."""
    def __init__(self):
        self.token, self.cookie, self.csrf = (secrets.token_urlsafe(32) for _ in range(3))
        self.bootstrapped = False
        self.auth_lock = threading.Lock()
        self.hub = self.loop = None
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass  # Never log bootstrap secrets, assertions, or request URLs.

            def setup(self):
                super().setup()
                self.connection.settimeout(5)

            def reply(self, status, value, *, content_type="application/json", cookie=False):
                data = value if isinstance(value, bytes) else json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
                self.send_header("Permissions-Policy", "publickey-credentials-get=(self), publickey-credentials-create=(self)")
                if cookie:
                    self.send_header("Set-Cookie", f"hw_review={owner.cookie}; HttpOnly; SameSite=Strict; Path=/")
                self.end_headers()
                self.wfile.write(data)

            def authenticated(self):
                jar = SimpleCookie()
                try:
                    jar.load(self.headers.get("Cookie", ""))
                    value = jar["hw_review"].value if "hw_review" in jar else ""
                    return owner.bootstrapped and value.isascii() and hmac.compare_digest(value, owner.cookie)
                except (CookieError, ValueError, TypeError):
                    return False

            def do_GET(self):
                if self.headers.get("Host") != owner.authority:
                    return self.reply(403, {"error": "Invalid Host"})
                assets = {"/": ("index.html", "text/html; charset=utf-8"),
                          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                          "/style.css": ("style.css", "text/css; charset=utf-8")}
                if self.path in assets:
                    filename, content_type = assets[self.path]
                    return self.reply(200, (ASSETS / filename).read_bytes(), content_type=content_type)
                if self.path == "/api/state" and self.authenticated():
                    return self.dispatch({})
                if self.path == "/api/session" and self.authenticated():
                    return self.reply(200, {"csrf": owner.csrf})
                return self.reply(403, {"error": "Session required"})

            def do_POST(self):
                if self.headers.get("Host") != owner.authority or self.headers.get("Origin") != owner.origin:
                    return self.reply(403, {"error": "Invalid Host or Origin"})
                if self.headers.get("Content-Type", "").split(";")[0] != "application/json" or self.headers.get("Transfer-Encoding"):
                    return self.reply(415, {"error": "JSON body required"})
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= 65536:
                        return self.reply(413, {"error": "Invalid body size"})
                    payload = json.loads(self.rfile.read(length))
                    if not isinstance(payload, dict):
                        raise ValueError("Object required")
                except (ValueError, TimeoutError):
                    return self.reply(400, {"error": "Invalid body"})
                if self.path == "/api/session":
                    token = payload.get("token")
                    with owner.auth_lock:
                        if owner.bootstrapped or not isinstance(token, str) or not token.isascii() or not hmac.compare_digest(token, owner.token):
                            return self.reply(403, {"error": "Bootstrap unavailable"})
                        owner.bootstrapped = True
                    return self.reply(200, {"csrf": owner.csrf}, cookie=True)
                csrf = self.headers.get("X-Review-CSRF", "")
                if not self.authenticated() or not csrf.isascii() or not hmac.compare_digest(csrf, owner.csrf):
                    return self.reply(403, {"error": "Session and CSRF token required"})
                if self.path not in {"/api/register/options", "/api/register/finish", "/api/deny", "/api/approve/options", "/api/approve/finish"}:
                    return self.reply(404, {"error": "Unknown endpoint"})
                return self.dispatch(payload)

            def dispatch(self, payload):
                future = asyncio.run_coroutine_threadsafe(owner.hub.handle(self.path, payload), owner.loop)
                try:
                    return self.reply(200, future.result(timeout=10))
                except Exception:
                    future.cancel()
                    return self.reply(400, {"error": "Operation rejected; request remains blocked"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.authority = f"localhost:{self.server.server_port}"
        self.origin = "http://" + self.authority
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def bootstrap_url(self):
        return self.origin + "/#" + self.token

    def start(self, hub):
        self.hub, self.loop = hub, asyncio.get_running_loop()
        self.thread.start()

    def close(self):
        if self.thread.is_alive():
            self.server.shutdown()
            self.thread.join(timeout=3)
        self.server.server_close()


async def run(out, *, url=None, channel=None):
    from playwright.async_api import async_playwright
    from .execution_live import ExecutionFixture

    if url is not None:
        from .execution import Operation
        Operation.build("validate", "validate", "GET", url, {})
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    server = ReviewServer()
    key = Ed25519PrivateKey.generate()
    hub = ReviewHub(ApprovalGate(out / "gate.sqlite", rp_id="localhost", origin=server.origin, signing_key=key))
    server.start(hub)
    fixture = None
    executor = None
    try:
        if url is None:
            fixture = ExecutionFixture().__enter__()
            url = fixture.base + "/index"
        parsed = urlsplit(url)
        origin = parsed.scheme + "://" + parsed.netloc
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=False, **({"channel": channel} if channel else {}))
            try:
                control = await browser.new_context(service_workers="block")
                async def control_route(route):
                    if route.request.url.startswith(server.origin + "/"):
                        await route.continue_()
                    else:
                        await route.abort()
                await control.route("**/*", control_route)
                ui = await control.new_page()
                await ui.goto(server.bootstrap_url)
                print("Local review opened. Enroll a passkey, then review each request. Close the review window to end the run.", flush=True)
                finished = asyncio.Event()
                ui.on("close", lambda _: finished.set())
                browser.on("disconnected", lambda _: finished.set())
                async def browsing():
                    nonlocal executor
                    await hub.enrolled.wait()
                    executor = await ApprovedBrowser.create(browser, hub.gate, hub, allowed_origins=[origin], approval_timeout=125)
                    page = await executor.new_page()
                    try:
                        await page.goto(url, timeout=0)
                    except Exception:
                        pass  # Denial is expected; evidence is in executor.events.
                task = asyncio.create_task(browsing())
                await finished.wait()
                hub.close()
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                if executor:
                    await executor.close()
            finally:
                await browser.close()
    finally:
        hub.close()
        await asyncio.to_thread(server.close)
        if fixture:
            await asyncio.to_thread(fixture.__exit__)
        (out / "approvals.json").write_text(json.dumps(hub.bundles, indent=2) + "\n")
        (out / "review.json").write_text(json.dumps(hub.events, indent=2) + "\n")
        (out / "execution.json").write_text(json.dumps(executor.events if executor else [], indent=2) + "\n")
        (out / "gate-public.pem").write_bytes(export_public(key.public_key()))
        if executor is not None and executor._closed:
            executor.save_evidence(out / "audit")
        if hub.credential_id is not None:
            (out / "credential-public.cbor").write_bytes(hub.credential_public_key)
            (out / "credential-id.txt").write_text(bytes_to_base64url(hub.credential_id))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--url", help="Initial HTTP(S) URL; only this exact origin is allowed. Default: local fixture.")
    parser.add_argument("--channel", choices=["chrome", "chromium"])
    args = parser.parse_args()
    asyncio.run(run(args.out, url=args.url, channel=args.channel))


if __name__ == "__main__":
    main()
