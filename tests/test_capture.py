import asyncio
import json

import pytest

from handoff_witness.capture import Capture
from handoff_witness.cdp import collect
from handoff_witness.core import EvidenceError


class Session:
    def __init__(self):
        self.listeners = {}
        self.handoff = None

    def on(self, name, callback):
        self.listeners[name] = callback

    def remove_listener(self, name, callback):
        assert self.listeners[name] == callback
        del self.listeners[name]

    async def send(self, method, params=None):
        if method == "Network.enable":
            return {}
        request = {"requestId": "1", "loaderId": "l", "frameId": "f", "type": "Document", "request": {"url": params["url"], "method": "GET"}, "initiator": {"type": "other"}}
        self.listeners["Network.requestWillBeSent"](request)
        if self.handoff:
            self.handoff()
        request = {**request, "request": {"url": "https://fixture.invalid/next", "method": "GET"}, "redirectResponse": {"url": params["url"]}}
        self.listeners["Network.requestWillBeSent"](request)
        return {"loaderId": "l", "frameId": "f"}


def test_adapter_response_race_and_handoff(tmp_path):
    async def exercise():
        session = Session()
        capture = await Capture(session).start()
        session.handoff = lambda: capture.handoff("human")
        await capture.navigate("https://fixture.invalid/start")
        with pytest.raises(EvidenceError):
            await capture.navigate("https://fixture.invalid/forbidden")
        with pytest.raises(EvidenceError):
            capture.save(tmp_path / "active.json")
        trace = capture.stop()
        assert not session.listeners
        capture.save(tmp_path / "trace.json")
        assert json.loads((tmp_path / "trace.json").read_text()) == trace
        rows = collect(trace)[1]["requests"]
        assert [r["attribution"] for r in rows] == ["agent", "agent"]
        assert rows[1]["controller_at_dispatch"] == "human"
    asyncio.run(exercise())


def test_failed_navigation_never_creates_binding():
    class Failed(Session):
        async def send(self, method, params=None):
            result = await super().send(method, params)
            if method == "Page.navigate":
                raise RuntimeError("transport closed")
            return result

    async def exercise():
        capture = await Capture(Failed()).start()
        with pytest.raises(RuntimeError):
            await capture.navigate("https://fixture.invalid/start")
        assert all(r["attribution"] == "unknown" for r in collect(capture.stop())[1]["requests"])
    asyncio.run(exercise())


def test_start_failure_removes_listener():
    class Failed(Session):
        async def send(self, *args):
            raise RuntimeError("cannot enable")

    async def exercise():
        session = Failed()
        capture = Capture(session)
        with pytest.raises(RuntimeError):
            await capture.start()
        assert not capture.active
        assert not session.listeners
    asyncio.run(exercise())


def test_stop_during_navigation_refused():
    async def exercise():
        session = Session()
        capture = await Capture(session).start()
        def stop_early():
            with pytest.raises(EvidenceError):
                capture.stop()
        session.handoff = stop_early
        await capture.navigate("https://fixture.invalid/start")
        capture.stop()
    asyncio.run(exercise())
