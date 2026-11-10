"""Hermetic browser integration experiment: fresh context, loopback fixtures.

The harness simulates a handoff, never a physical human. A separate HTTP ledger
observes receipt but does not supply attribution labels to the collector.
"""
import argparse
import asyncio
import json
import platform
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
from pathlib import Path
from urllib.parse import urlsplit

from .capture import Capture
from .cdp import collect
from .core import verify


class Fixture:
    def __init__(self):
        self.arrived = threading.Event()
        self.release = threading.Event()
        self.ledger = []
        self.lock = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                with owner.lock:
                    owner.ledger.append({"path": self.path, "method": "GET", "received_monotonic_ns": time.monotonic_ns()})
                if self.path == "/start":
                    owner.arrived.set()
                    if not owner.release.wait(timeout=10):
                        self.send_error(504, "test gate timed out")
                        return
                    self.send_response(302)
                    self.send_header("Location", "/landing")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path == "/landing":
                    body = b'''<!doctype html><title>Local handoff test</title>
                    <h1>Controlled browser fixture</h1>
                    <script>setTimeout(async () => {
                      await fetch('/delayed'); window.delayedDone = true;
                    }, 25);</script>'''
                else:
                    body = b"<!doctype html><title>Local fixture</title>OK"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


async def run(out, channel=None):
    from playwright.async_api import async_playwright

    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    blocked = []
    with Fixture() as fixture:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True, **({"channel": channel} if channel else {}))
            try:
                context = await browser.new_context(service_workers="block")

                async def local_only(route):
                    if route.request.url.startswith(fixture.base + "/"):
                        await route.continue_()
                    else:
                        blocked.append(route.request.url)
                        await route.abort()

                await context.route("**/*", local_only)
                page = await context.new_page()
                session = await context.new_cdp_session(page)
                capture = await Capture(session).start()
                navigation = asyncio.create_task(capture.navigate(fixture.base + "/start"))
                try:
                    if not await asyncio.to_thread(fixture.arrived.wait, 8):
                        raise RuntimeError("Navigation did not reach local test server")
                    # Gate the server response: handoff definitely precedes redirect.
                    capture.handoff("human")
                    fixture.release.set()
                    await asyncio.wait_for(navigation, 10)
                    await page.wait_for_function("window.delayedDone === true", timeout=10000)
                    # Navigation outside the adapter under a human control marker
                    # must remain unknown; it is NOT a physical human interaction.
                    await page.goto(fixture.base + "/unbound", wait_until="load")
                    trace = capture.stop()
                    capture.save(out / "capture.json")
                finally:
                    fixture.release.set()
                    if not navigation.done():
                        navigation.cancel()
                        await asyncio.gather(navigation, return_exceptions=True)
                    capture.stop()
                recorder, analysis = collect(trace)
                recorder.save(out / "evidence")
                verify(recorder.records, recorder.checkpoint(), recorder.key.public_key())
                expected = {"/start": "agent", "/landing": "agent", "/delayed": "unknown", "/unbound": "unknown"}
                checks = []
                for path, actor in expected.items():
                    matches = [r for r in analysis["requests"] if urlsplit(r["url"]).path == path]
                    received = [r for r in fixture.ledger if r["path"] == path]
                    checks.append({"path": path, "expected_attribution": actor, "observed_attributions": [r["attribution"] for r in matches], "received_count": len(received), "passed": len(matches) == 1 and len(received) == 1 and matches[0]["attribution"] == actor})
                redirected = [r for r in analysis["requests"] if urlsplit(r["url"]).path == "/landing"]
                handoff_passed = len(redirected) == 1 and redirected[0]["controller_at_dispatch"] == "human"
                baseline_matches = sum(r["controller_at_dispatch"] == expected[urlsplit(r["url"]).path] for r in analysis["requests"] if urlsplit(r["url"]).path in expected)
                report = {"kind": "controlled_live_browser_integration", "browser_version": browser.version, "playwright_version": version("playwright"), "python_version": platform.python_version(), "platform": platform.platform(), "passed": all(c["passed"] for c in checks) and handoff_passed and not blocked, "checks": checks, "redirect_observed_after_handoff": handoff_passed, "current_controller_contract_matches": baseline_matches, "receiver_path_counts": dict(Counter(r["path"] for r in fixture.ledger)), "blocked_nonlocal_urls": blocked, "limitations": ["Handoff is simulated, not authenticated human input.", "Unknown is a conservative collector target, not a ground-truth actor.", "Browser and capture harness are trusted; no OS compromise resistance.", "Receiver ledger is separately observed in the same test process, not an independent security witness.", "Four authored cases are integration checks, not representative accuracy."]}
                observed_paths = Counter(urlsplit(r["url"]).path for r in analysis["requests"])
                received_paths = Counter(r["path"] for r in fixture.ledger)
                report["browser_request_count"] = analysis["request_count"]
                report["unmatched_browser_paths_at_snapshot"] = dict(observed_paths - received_paths)
                report["limitations"].append("Unmatched browser events are snapshot differences, not proof that a request never reaches the server.")
                (out / "analysis.json").write_text(json.dumps(analysis, indent=2) + "\n")
                (out / "receiver.json").write_text(json.dumps(fixture.ledger, indent=2) + "\n")
                (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
                return report
            finally:
                await browser.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="New output directory; existing directories are never overwritten")
    parser.add_argument("--channel", choices=["chrome", "chromium"], default=None)
    args = parser.parse_args()
    report = asyncio.run(run(args.out, args.channel))
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
