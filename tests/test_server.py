import json
import threading
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import pytest

from handoff_witness.server import make_server


def test_real_http_handoff_and_token_replay(tmp_path):
    server = make_server(0, tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"

    def call(path, post=False, origin=None):
        headers = {"Content-Type": "application/json"}
        if origin:
            headers["Origin"] = origin
        with urlopen(Request(base + path, data=b"{}" if post else None, headers=headers), timeout=3) as response:
            return json.load(response)

    try:
        token = call("/api/schedule", True)["token"]
        call("/api/handoff", True)
        call("/target/" + token)
        first = call("/api/state")["requests"][-1]
        assert first["attribution"] == "agent"
        assert first["controller_at_dispatch"] == "human"
        assert first["stage"] == "receiver_observed"
        call("/target/" + token)
        assert call("/api/state")["requests"][-1]["attribution"] == "unknown"
        call("/api/export", True)
        assert (tmp_path / "checkpoint.json").exists()
        with pytest.raises(HTTPError) as caught:
            call("/api/handoff", True, "https://other.invalid")
        assert caught.value.code == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_get_requires_loopback_host_and_same_site(tmp_path):
    import http.client
    server = make_server(0, tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def status(path, **headers):
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        try:
            connection.putrequest("GET", path, skip_host="Host" in headers)
            for name, value in headers.items():
                connection.putheader(name, value)
            connection.endheaders()
            return connection.getresponse().status
        finally:
            connection.close()

    try:
        assert status("/api/state") == 200
        assert status("/api/state", Host="rebound.invalid") == 403
        assert status("/target/forged", **{"Sec-Fetch-Site": "cross-site"}) == 403
        assert status("/target/same", **{"Sec-Fetch-Site": "same-origin"}) == 200
        with urlopen(f"http://127.0.0.1:{server.server_port}/api/state", timeout=3) as response:
            urls = [r["url"] for r in json.load(response)["requests"]]
        assert not any(u.endswith("/target/forged") for u in urls)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
