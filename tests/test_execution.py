import asyncio
from unittest.mock import patch

import pytest

from handoff_witness.approval import ApprovalError
from handoff_witness.execution import ApprovedBrowser, HTTPBroker, Operation
from test_approval import setup  # Shared cryptographic fixture; not physical user verification.


def operation(binding, **changes):
    return Operation.build(binding['session'], binding['request_id'], changes.get('method', 'POST'),
                           changes.get('url', 'https://fixture.invalid/post'),
                           changes.get('headers', {'content-type': 'text/plain'}), changes.get('body', b'payload'))


def approve_operation(setup, op):
    gate, auth, *_ = setup
    options = gate.begin(op.binding(), auth.id)
    gate.finish(options['approval_id'], auth.assertion(options))
    return options['approval_id']


@pytest.mark.parametrize('changes', [
    {'headers': {'Host': 'attacker.invalid'}},
    {'headers': {'content-length': '999'}},
    {'headers': {'transfer-encoding': 'chunked'}},
    {'headers': {'upgrade': 'websocket'}},
    {'headers': {'expect': '100-continue'}},
    {'headers': {'x-inject': 'a\r\nb: c'}},
    {'headers': {'Host': 'fixture.invalid', 'host': 'fixture.invalid'}},
    {'url': 'https://user:password@fixture.invalid/'},
    {'url': 'https://fixture.invalid/path#fragment'},
    {'url': 'https://fixture.invalid/path#'},
    {'url': 'https://fixture.invalid/path\n'},
    {'url': 'file:///etc/passwd'},
    {'method': 'CONNECT'},
])
def test_reject_ambiguous_or_unsupported_operations(setup, changes):
    with pytest.raises((ApprovalError, ValueError)):
        operation(setup[-1], **changes)


def test_no_approval_opens_no_connection(setup):
    gate, _, _, _, binding = setup
    with patch('handoff_witness.execution.http.client.HTTPSConnection') as connection:
        with pytest.raises(ApprovalError):
            HTTPBroker(gate).dispatch(operation(binding), 'missing')
        connection.assert_not_called()


def test_changed_body_opens_no_connection(setup):
    gate, _, _, _, binding = setup
    op = operation(binding)
    approval_id = approve_operation(setup, op)
    with patch('handoff_witness.execution.http.client.HTTPSConnection') as connection:
        with pytest.raises(ApprovalError):
            HTTPBroker(gate).dispatch(operation(binding, body=b'changed'), approval_id)
        connection.assert_not_called()


@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
def test_exact_bytes_once_and_redirect_not_followed(setup, status):
    gate, _, _, _, binding = setup
    op = operation(binding)
    approval_id = approve_operation(setup, op)
    with patch('handoff_witness.execution.http.client.HTTPSConnection') as connection:
        client = connection.return_value
        client.getresponse.return_value.status = status
        receipt, response = HTTPBroker(gate).dispatch(op, approval_id)
        assert response.status == 502
        assert receipt['reservation']['binding'] == op.binding()
        client.putrequest.assert_called_once_with('POST', '/post', skip_host=True, skip_accept_encoding=True)
        assert [c.args for c in client.putheader.call_args_list] == list(op.headers)
        client.endheaders.assert_called_once_with(b'payload')
        client.close.assert_called_once()
        with pytest.raises(ApprovalError):
            HTTPBroker(gate).dispatch(op, approval_id)
        connection.assert_called_once()


def test_transport_failure_consumes_approval_without_retry(setup):
    gate, _, _, _, binding = setup
    op = operation(binding)
    approval_id = approve_operation(setup, op)
    with patch('handoff_witness.execution.http.client.HTTPSConnection') as connection:
        connection.return_value.endheaders.side_effect = OSError('uncertain send')
        with pytest.raises(OSError):
            HTTPBroker(gate).dispatch(op, approval_id)
        with pytest.raises(ApprovalError):
            HTTPBroker(gate).dispatch(op, approval_id)
        connection.assert_called_once()


def test_expiry_checked_at_dispatch(setup):
    gate, _, _, now, binding = setup
    op = operation(binding)
    approval_id = approve_operation(setup, op)
    now[0] += 120
    with patch('handoff_witness.execution.http.client.HTTPSConnection') as connection:
        with pytest.raises(ApprovalError):
            HTTPBroker(gate).dispatch(op, approval_id)
        connection.assert_not_called()


def test_revocation_checked_at_dispatch(setup):
    gate, auth, _, _, binding = setup
    op = operation(binding)
    approval_id = approve_operation(setup, op)
    gate.revoke(auth.id)
    with patch('handoff_witness.execution.http.client.HTTPSConnection') as connection:
        with pytest.raises(ApprovalError):
            HTTPBroker(gate).dispatch(op, approval_id)
        connection.assert_not_called()


class Request:
    url = 'https://fixture.invalid/post'
    method = 'POST'
    redirected_from = None
    post_data_buffer = b'payload'

    async def all_headers(self):
        return {'content-type': 'text/plain'}


class Route:
    def __init__(self):
        self.request = Request()
        self.aborted = False

    async def abort(self, *_):
        self.aborted = True

    async def continue_(self):
        raise AssertionError('Native requests must never continue')

    async def fulfill(self, **kwargs):
        self.response = kwargs


@pytest.mark.parametrize('failure', ['deny', 'timeout', 'error', 'mutation'])
def test_route_fails_closed(setup, failure):
    gate, auth, *_ = setup

    async def run():
        async def callback(binding):
            if failure == 'deny':
                return None
            if failure == 'timeout':
                await asyncio.Future()
            if failure == 'error':
                raise RuntimeError('unavailable')
            binding['url'] = 'https://fixture.invalid/changed'
            options = gate.begin(binding, auth.id)
            gate.finish(options['approval_id'], auth.assertion(options))
            return options['approval_id']
        executor = ApprovedBrowser(None, gate, callback, allowed_origins=['https://fixture.invalid'], approval_timeout=0.01)
        route = Route()
        with patch('handoff_witness.execution.http.client.HTTPSConnection') as connection:
            await executor._route(route)
            connection.assert_not_called()
        assert route.aborted
        assert not hasattr(route, 'response')
    asyncio.run(run())


def test_empty_query_delimiter_preserved(setup):
    gate, _, _, _, binding = setup
    op = operation(binding, url='https://fixture.invalid/post?')
    approval_id = approve_operation(setup, op)
    with patch('handoff_witness.execution.http.client.HTTPSConnection') as connection:
        client = connection.return_value
        client.getresponse.return_value.status = 302
        HTTPBroker(gate).dispatch(op, approval_id)
        client.putrequest.assert_called_once_with('POST', '/post?', skip_host=True, skip_accept_encoding=True)


def test_oversized_response_spends_approval(setup):
    gate, _, _, _, binding = setup
    op = operation(binding)
    approval_id = approve_operation(setup, op)
    with patch('handoff_witness.execution.http.client.HTTPSConnection') as connection:
        response = connection.return_value.getresponse.return_value
        response.status = 200
        response.read.return_value = b'12345'
        with pytest.raises(ApprovalError, match='may have executed'):
            HTTPBroker(gate, max_response_bytes=4).dispatch(op, approval_id)
        with pytest.raises(ApprovalError):
            HTTPBroker(gate).dispatch(op, approval_id)
        connection.assert_called_once()


def test_cancellation_before_approval_opens_no_connection(setup):
    gate, *_ = setup

    async def run():
        pending = asyncio.Event()
        async def callback(binding):
            pending.set()
            await asyncio.Future()
        executor = ApprovedBrowser(None, gate, callback, allowed_origins=['https://fixture.invalid'], approval_timeout=10)
        with patch('handoff_witness.execution.http.client.HTTPSConnection') as connection:
            task = asyncio.create_task(executor._route(Route()))
            await pending.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            connection.assert_not_called()
        assert executor.events[0]['status'] == 'blocked'
    asyncio.run(run())


def raw_server(reply):
    """Loopback server that reads one request head/body and writes raw bytes."""
    import socket
    import threading
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)

    def serve():
        conn, _ = listener.accept()
        with conn:
            data = b''
            while b'\r\n\r\n' not in data:
                data += conn.recv(4096)
            head, _, body = data.partition(b'\r\n\r\n')
            length = next((int(line.split(b':', 1)[1]) for line in head.split(b'\r\n')
                           if line.lower().startswith(b'content-length:')), 0)
            while len(body) < length:
                body += conn.recv(4096)
            conn.sendall(reply)
        listener.close()
    threading.Thread(target=serve, daemon=True).start()
    return listener.getsockname()[1]


def test_interim_responses_are_not_relayed_as_final(setup):
    from handoff_witness.execution_audit import ExecutionJournal
    gate, _, _, _, binding = setup
    port = raw_server(b'HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n'
                      b'HTTP/1.1 102 Processing\r\n\r\n'
                      b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello')
    op = operation(binding, url=f'http://127.0.0.1:{port}/post')
    approval_id = approve_operation(setup, op)
    journal = ExecutionJournal(binding['session'])
    _, response = HTTPBroker(gate, journal=journal).dispatch(op, approval_id)
    assert (response.status, response.body) == (200, b'hello')
    statuses = [r['event']['data'].get('status') for r in journal.records]
    assert statuses[-2:] == [200, 200]


def test_protocol_switch_is_rejected_after_spending_approval(setup):
    from handoff_witness.execution_audit import ExecutionJournal
    gate, _, _, _, binding = setup
    port = raw_server(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
    op = operation(binding, url=f'http://127.0.0.1:{port}/post')
    approval_id = approve_operation(setup, op)
    journal = ExecutionJournal(binding['session'])
    with pytest.raises(ApprovalError, match='may have executed'):
        HTTPBroker(gate, journal=journal).dispatch(op, approval_id)
    assert [r['event']['kind'] for r in journal.records][-2:] == ['response_headers_received', 'attempt_failed']
    with pytest.raises(ApprovalError):
        HTTPBroker(gate).dispatch(op, approval_id)


@pytest.mark.parametrize('hostname,address,allowed', [
    ('fixture.invalid', '93.184.216.34', True),
    ('fixture.invalid', '127.0.0.1', False),
    ('fixture.invalid', '10.0.0.5', False),
    ('fixture.invalid', '169.254.169.254', False),
    ('fixture.invalid', '::1', False),
    ('127.0.0.1', '127.0.0.1', True),
    ('127.0.0.1', '127.0.0.2', False),
    ('localhost', '127.0.0.1', True),
    ('localhost', '93.184.216.34', False),
])
def test_destination_address_policy(hostname, address, allowed):
    from handoff_witness.execution import address_allowed
    assert address_allowed(hostname, address) is allowed


def test_rebinding_hostname_spends_approval_without_connecting(setup):
    from handoff_witness.execution_audit import ExecutionJournal
    gate, _, _, _, binding = setup
    op = operation(binding)
    approval_id = approve_operation(setup, op)
    journal = ExecutionJournal(binding['session'])
    broker = HTTPBroker(gate, journal=journal, resolver=lambda host, port: '127.0.0.1')
    with patch('handoff_witness.execution.http.client.HTTPSConnection') as connection:
        with pytest.raises(ApprovalError, match='destination policy'):
            broker.dispatch(op, approval_id)
        connection.assert_not_called()
    started = next(r['event']['data'] for r in journal.records if r['event']['kind'] == 'attempt_started')
    assert started['addresses'] == ['127.0.0.1']
    assert journal.records[-1]['event']['kind'] == 'attempt_failed'


def test_connection_uses_pinned_address(setup):
    gate, _, _, _, binding = setup
    port = raw_server(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')
    op = operation(binding, url=f'http://pinned.localhost:{port}/post')
    approval_id = approve_operation(setup, op)
    lookups = []

    def resolver(host, port_):
        lookups.append(host)
        return ['::1', '127.0.0.1']  # IPv6 refused first, as for 'localhost' on macOS
    import socket
    real = socket.getaddrinfo

    def numeric_only(host, *args, **kwargs):
        assert host in {'::1', '127.0.0.1'}, 'second DNS lookup of the hostname'
        return real(host, *args, **kwargs)
    with patch('socket.getaddrinfo', side_effect=numeric_only):
        _, response = HTTPBroker(gate, resolver=resolver).dispatch(op, approval_id)
    assert response.body == b'ok' and lookups == ['pinned.localhost']


def test_mixed_policy_answer_rejected(setup):
    gate, _, _, _, binding = setup
    op = operation(binding)
    approval_id = approve_operation(setup, op)
    broker = HTTPBroker(gate, resolver=lambda host, port: ['93.184.216.34', '10.0.0.7'])
    with patch('handoff_witness.execution.http.client.HTTPSConnection') as connection:
        with pytest.raises(ApprovalError, match='destination policy'):
            broker.dispatch(op, approval_id)
        connection.assert_not_called()
