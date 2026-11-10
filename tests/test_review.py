import asyncio
import http.client
import json

import pytest

from handoff_witness.approval import ApprovalError
from handoff_witness.review import ReviewHub, ReviewServer
from test_approval import setup


async def pending(hub, binding):
    task = asyncio.create_task(hub(binding))
    await asyncio.sleep(0)
    item = next(iter(hub.pending.values()))
    return task, item


def test_queue_requires_verified_assertion(setup):
    gate, auth, _, _, binding = setup
    async def run():
        hub = ReviewHub(gate)
        hub.credential_id = auth.id
        task, item = await pending(hub, binding)
        assert not task.done()
        options = await hub.handle('/api/approve/options', {'id': item['id']})
        assert not task.done()
        with pytest.raises(Exception):
            await hub.handle('/api/approve/finish', {'id': item['id'], 'credential': {}})
        assert not task.done()
        result = await hub.handle('/api/approve/finish', {'id': item['id'], 'credential': auth.assertion(options)})
        assert result['status'] == 'credential_verified'
        assert await task == options['approval_id']
        with pytest.raises(ApprovalError):
            await hub.handle('/api/approve/finish', {'id': item['id'], 'credential': auth.assertion(options)})
    asyncio.run(run())


def test_deny_then_stale_assertion_cannot_release_request(setup):
    gate, auth, _, _, binding = setup
    async def run():
        hub = ReviewHub(gate)
        hub.credential_id = auth.id
        task, item = await pending(hub, binding)
        options = await hub.handle('/api/approve/options', {'id': item['id']})
        await hub.handle('/api/deny', {'id': item['id']})
        with pytest.raises(ApprovalError):
            await hub.handle('/api/approve/finish', {'id': item['id'], 'credential': auth.assertion(options)})
        assert await task is None
    asyncio.run(run())


def test_expiration_cancellation_and_capacity(setup):
    gate, auth, _, _, binding = setup
    async def run():
        now = [1000]
        hub = ReviewHub(gate, ttl=10, max_pending=1, clock=lambda: now[0])
        assert await hub(binding) is None
        hub.credential_id = auth.id
        task, item = await pending(hub, binding)
        assert await hub(binding) is None
        options = await hub.handle('/api/approve/options', {'id': item['id']})
        now[0] += 11
        with pytest.raises(ApprovalError):
            await hub.handle('/api/approve/finish', {'id': item['id'], 'credential': auth.assertion(options)})
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        assert not hub.pending
        task, _ = await pending(hub, binding)
        hub.close()
        assert await task is None
        assert await hub(binding) is None
    asyncio.run(run())


def test_queue_timeout_returns_denial(setup):
    gate, auth, _, _, binding = setup
    async def run():
        hub = ReviewHub(gate, ttl=0.01)
        hub.credential_id = auth.id
        assert await hub(binding) is None
        assert not hub.pending
        assert hub.events[-1]['status'] == 'expired'
    asyncio.run(run())


def test_binding_snapshot_survives_caller_mutation(setup):
    gate, auth, _, _, binding = setup
    async def run():
        hub = ReviewHub(gate)
        hub.credential_id = auth.id
        task, item = await pending(hub, binding)
        original = binding['url']
        binding['url'] = 'https://changed.invalid/'
        assert item['binding']['url'] == original
        hub.close()
        await task
    asyncio.run(run())


def test_http_session_origin_csrf_and_bootstrap(setup):
    gate, *_ = setup
    async def run():
        server = ReviewServer()
        server.start(ReviewHub(gate))
        def request(method, path, data=None, **headers):
            conn = http.client.HTTPConnection('127.0.0.1', server.server.server_port)
            body = json.dumps(data) if data is not None else None
            default = {'Host': server.authority, 'Origin': server.origin, 'Content-Type': 'application/json'}
            default.update(headers)
            try:
                conn.request(method, path, body=body, headers=default)
                response = conn.getresponse()
                return response.status, dict(response.getheaders()), response.read()
            finally:
                conn.close()
        async def call(*args, **kwargs):
            return await asyncio.to_thread(request, *args, **kwargs)
        try:
            assert (await call('GET', '/api/state'))[0] == 403
            assert (await call('POST', '/api/session', {'token': server.token}, Origin='https://attacker.invalid'))[0] == 403
            assert (await call('POST', '/api/session', {'token': server.token}, Host='attacker.invalid'))[0] == 403
            status, headers, body = await call('POST', '/api/session', {'token': server.token})
            assert status == 200
            cookie = headers['Set-Cookie'].split(';')[0]
            csrf = json.loads(body)['csrf']
            assert 'HttpOnly' in headers['Set-Cookie'] and 'SameSite=Strict' in headers['Set-Cookie']
            assert (await call('POST', '/api/session', {'token': server.token}))[0] == 403
            assert (await call('GET', '/api/state', Cookie=cookie))[0] == 200
            assert (await call('POST', '/api/register/options', {}, Cookie=cookie))[0] == 403
            auth_headers = {'Cookie': cookie, 'X-Review-CSRF': csrf}
            assert (await call('POST', '/api/register/options', {}, **auth_headers))[0] == 200
            assert (await call('POST', '/api/register/options', {}, Origin='null', **auth_headers))[0] == 403
            status, headers, body = await call('GET', '/')
            assert status == 200 and 'frame-ancestors' in headers['Content-Security-Policy']
            assert headers['X-Frame-Options'] == 'DENY'
            assert 'Access-Control-Allow-Origin' not in headers
            assert server.token.encode() not in body
        finally:
            await asyncio.to_thread(server.close)
    asyncio.run(run())
