"""Opt-in adapter for a caller-owned Playwright-compatible CDP session.

Never connects to a user's browser automatically. The harness and CDP transport
are trusted. Human takeover is a harness assertion, not physical-input evidence.
"""
import asyncio
import copy
import json
import secrets
import uuid
from pathlib import Path

from .core import EvidenceError

OBSERVER_WORLD = "hw-observer"
INPUT_BINDING = "__hwTrustedInput"
# Runs in an isolated world before page scripts. Page code cannot reach this
# world's listener or binding, and synthetic page events have isTrusted=false.
OBSERVER_SOURCE = """(() => {
  for (const type of ['pointerdown', 'keydown']) {
    window.addEventListener(type, event => {
      if (event.isTrusted) globalThis.%s(JSON.stringify({type: event.type}));
    }, true);
  }
})();""" % INPUT_BINDING
LINEAGE_EVENTS = ("Page.frameNavigated", "Page.frameAttached", "Page.frameRequestedNavigation",
                  "Runtime.bindingCalled", "Runtime.executionContextCreated", "Target.attachedToTarget",
                  "Target.detachedFromTarget")
# Persistent-state observation: which cookies a request carried, which a response
# set, and DOM storage writes. document.cookie and IndexedDB writes raise none of these.
STATE_EVENTS = ("Network.requestWillBeSentExtraInfo", "Network.responseReceivedExtraInfo",
                "DOMStorage.domStorageItemAdded", "DOMStorage.domStorageItemUpdated",
                "DOMStorage.domStorageItemRemoved", "DOMStorage.domStorageItemsCleared")
WORKER_TARGETS = frozenset({"worker", "shared_worker", "service_worker"})


def reduce_state_event(method, params):
    """Keep only what state lineage needs. Cookie and storage values, storage
    keys, and request/response headers are dropped before anything is recorded."""
    if not isinstance(params, dict):
        return {}
    if method == "Network.requestWillBeSentExtraInfo":
        cookies = []
        for item in params.get("associatedCookies") or []:
            cookie = item.get("cookie") if isinstance(item, dict) else None
            if isinstance(cookie, dict):
                cookies.append({"cookie": {k: cookie.get(k) for k in ("name", "domain", "path")},
                                "blockedReasons": list(item.get("blockedReasons") or [])})
        return {"requestId": params.get("requestId"), "associatedCookies": cookies}
    if method == "Network.responseReceivedExtraInfo":
        if "setCookies" in params:
            return {k: params.get(k) for k in ("requestId", "statusCode", "setCookies")}
        headers = params.get("headers") if isinstance(params.get("headers"), dict) else {}
        raw = "\n".join(str(v) for k, v in headers.items() if str(k).lower() == "set-cookie")
        cookies = []
        for line in raw.split("\n"):
            name, _, rest = line.partition("=")
            if not name.strip() or not _:
                continue
            domain = next((a.partition("=")[2].strip() for a in rest.split(";")[1:]
                           if a.partition("=")[0].strip().lower() == "domain"), None)
            cookies.append({"name": name.strip(), "domain": domain or None})
        return {"requestId": params.get("requestId"), "statusCode": params.get("statusCode"), "setCookies": cookies}
    if method in STATE_EVENTS:
        storage = params.get("storageId") if isinstance(params.get("storageId"), dict) else {}
        return {"storageId": {k: storage.get(k) for k in ("securityOrigin", "isLocalStorage")}}
    return params


class Capture:
    """Mediated agent channel plus passive observation of one page target.

    With lineage=True the adapter also records frame/document events, worker and
    service-worker sessions (auto-attached, non-flattened), async initiator
    stacks, trusted input observed in an isolated world, and reduced state
    events (cookie names carried and set, DOM storage writes; never values).
    Only methods on this object count as agent commands; anything else reaching
    the page is unmediated.
    """
    def __init__(self, session, *, lineage=False):
        self.session = session
        self.lineage = lineage
        self._handlers = []
        self._tasks = set()
        self.session_id = str(uuid.uuid4())
        self.trace = []
        self.controller = "agent"
        self.active = False
        self.inflight = False
        self.sequence = 0
        self.listener = self._request

    async def start(self):
        if self.active or self.trace:
            raise EvidenceError("Capture instances cannot be restarted")
        self.active = True
        self.session.on("Network.requestWillBeSent", self.listener)
        try:
            await self.session.send("Network.enable")
            if self.lineage:
                await self._start_lineage()
        except BaseException:
            self._remove_listeners()
            self.active = False
            raise
        self.handoff("agent")
        return self

    def _event_listener(self, method):
        def handler(params):
            if not self.active:
                return
            self._record("receive", {"method": method, "params": reduce_state_event(method, params) if method in STATE_EVENTS else params})
            if method == "Target.attachedToTarget" and params.get("targetInfo", {}).get("type") in WORKER_TARGETS:
                task = asyncio.ensure_future(self._enable_child(params["sessionId"]))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)
        return handler

    def _child_message(self, params):
        if not self.active:
            return
        try:
            message = json.loads(params.get("message", ""))
        except ValueError:
            return
        if isinstance(message, dict):
            if message.get("method") in STATE_EVENTS:
                message = {**message, "params": reduce_state_event(message["method"], message.get("params"))}
            self.trace.append({"channel": "receive", "session": self.session_id + "/" + params.get("sessionId", ""),
                               "parent": self.session_id, "message": copy.deepcopy(message)})

    async def _setup(self, method, params=None):
        """Observation setup command; recorded but never an agent action."""
        self.trace.append({"channel": "setup", "session": self.session_id, "method": method, "params": copy.deepcopy(params or {})})
        return await self.session.send(method, params or {})

    async def _enable_child(self, child):
        for number, method in enumerate(("Network.enable", "Runtime.runIfWaitingForDebugger"), 1):
            try:
                await self.session.send("Target.sendMessageToTarget",
                                        {"sessionId": child, "message": json.dumps({"id": number, "method": method})})
            except Exception:
                return  # Worker may already have exited; its requests stay unobserved.

    async def _start_lineage(self):
        for method in LINEAGE_EVENTS + STATE_EVENTS:
            handler = self._event_listener(method)
            self._handlers.append((method, handler))
            self.session.on(method, handler)
        self._handlers.append(("Target.receivedMessageFromTarget", self._child_message))
        self.session.on("Target.receivedMessageFromTarget", self._child_message)
        await self._setup("Page.enable")
        await self._setup("Runtime.enable")
        await self._setup("Debugger.enable")
        await self._setup("Debugger.setAsyncCallStackDepth", {"maxDepth": 32})
        await self._setup("DOMStorage.enable")
        await self._setup("Runtime.addBinding", {"name": INPUT_BINDING, "executionContextName": OBSERVER_WORLD})
        await self._setup("Page.addScriptToEvaluateOnNewDocument", {"source": OBSERVER_SOURCE, "worldName": OBSERVER_WORLD})
        await self._setup("Target.setAutoAttach", {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": False})

    def _remove_listeners(self):
        self.session.remove_listener("Network.requestWillBeSent", self.listener)
        for method, handler in self._handlers:
            self.session.remove_listener(method, handler)
        self._handlers = []

    def _record(self, channel, message):
        self.trace.append({"channel": channel, "session": self.session_id, "message": copy.deepcopy(message)})

    def _request(self, params):
        if self.active:
            self._record("receive", {"method": "Network.requestWillBeSent", "params": params})

    def handoff(self, controller):
        if not self.active or controller not in {"human", "agent"}:
            raise EvidenceError("Active capture and valid controller required")
        self.controller = controller
        self.trace.append({"channel": "harness", "controller": controller})

    async def navigate(self, url):
        if not self.active or self.controller != "agent" or self.inflight:
            raise EvidenceError("Navigation requires agent control and no pending navigation")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise EvidenceError("Only HTTP(S) navigation is supported")
        self.inflight = True
        self.sequence += 1
        command_id = self.sequence
        params = {"url": url}
        self._record("send", {"id": command_id, "method": "Page.navigate", "params": params})
        try:
            result = await self.session.send("Page.navigate", params)
            self._record("receive", {"id": command_id, "result": result})
            return result
        except BaseException:
            self._record("receive", {"id": command_id, "error": {"message": "navigation failed or cancelled"}})
            raise
        finally:
            self.inflight = False

    async def _command(self, method, params):
        """Send one command on the mediated agent channel and record both halves."""
        if not self.active or self.controller != "agent" or self.inflight:
            raise EvidenceError("Agent commands require agent control and no pending command")
        self.inflight = True
        self.sequence += 1
        command_id = self.sequence
        self._record("send", {"id": command_id, "method": method, "params": copy.deepcopy(params)})
        try:
            result = await self.session.send(method, params)
            self._record("receive", {"id": command_id, "result": result})
            return result
        except BaseException:
            self._record("receive", {"id": command_id, "error": {"message": "command failed or cancelled"}})
            raise
        finally:
            self.inflight = False

    async def click(self, x, y):
        """Agent pointer click through the mediated channel (trusted browser input)."""
        if not all(isinstance(v, (int, float)) for v in (x, y)):
            raise EvidenceError("Click coordinates required")
        for kind in ("mousePressed", "mouseReleased"):
            await self._command("Input.dispatchMouseEvent", {"type": kind, "x": x, "y": y, "button": "left", "clickCount": 1})

    async def evaluate_isolated(self, expression):
        """Run agent script in a fresh isolated world, tagged with an unguessable sourceURL."""
        if not self.lineage or not isinstance(expression, str):
            raise EvidenceError("Lineage capture and script text required")
        tree = await self._setup("Page.getFrameTree")
        world = await self._setup("Page.createIsolatedWorld", {"frameId": tree["frameTree"]["frame"]["id"],
                                                               "worldName": "hw-agent-" + secrets.token_hex(8)})
        source = "hw-agent-" + secrets.token_hex(16) + ".js"
        return await self._command("Runtime.evaluate", {"expression": expression + "\n//# sourceURL=" + source,
                                                        "contextId": world["executionContextId"]})

    async def drain(self):
        if self._tasks:
            await asyncio.gather(*tuple(self._tasks), return_exceptions=True)

    def stop(self):
        if self.inflight:
            raise EvidenceError("Wait for navigation response before stopping capture")
        if self.active:
            self._remove_listeners()
            self.active = False
        return copy.deepcopy(self.trace)

    def save(self, path):
        if self.active or self.inflight:
            raise EvidenceError("Stop capture before exporting a consistent transcript")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.trace, indent=2) + "\n")
