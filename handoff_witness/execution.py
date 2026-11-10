"""Approval-gated HTTP broker for a fresh, trusted Playwright browser context.

Never continues intercepted requests. Browser route callbacks obtain approval,
then an immutable operation is reserved and sent once by a separate HTTP client.
This is not OS network isolation; the host, browser, and controller are trusted.
"""
import asyncio
import hashlib
import http.client
import ipaddress
import json
import re
import secrets
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from .approval import ApprovalError, validate_binding
from .core import digest
from .execution_audit import ExecutionJournal


@dataclass(frozen=True)
class Operation:
    session: str
    request_id: str
    method: str
    url: str
    headers: tuple[tuple[str, str], ...]
    body: bytes

    @classmethod
    def build(cls, session, request_id, method, url, headers, body=b""):
        parsed = urlsplit(url)
        # Do not let URL normalization change the operation after approval.
        if not parsed.hostname or parsed.username is not None or parsed.password is not None or "#" in url:
            raise ApprovalError("Invalid execution URL")
        if any(ord(c) <= 32 or ord(c) >= 127 for c in url):
            raise ApprovalError("Execution URL must be encoded ASCII")
        parsed.port  # Validate the port before any approval or connection.
        normalized = {}
        for name, value in headers.items():
            name = name.lower()
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-z-]+", name) or name in normalized:
                raise ApprovalError("Invalid or duplicate request header")
            if not isinstance(value, str) or any(ord(c) < 32 or ord(c) > 126 for c in value):
                raise ApprovalError("Only printable ASCII header values are supported")
            normalized[name] = value
        if "transfer-encoding" in normalized or "upgrade" in normalized or "expect" in normalized:
            raise ApprovalError("Streaming, upgrades, and Expect are unsupported")
        if normalized.get("host", parsed.netloc) != parsed.netloc:
            raise ApprovalError("Host does not match request URL")
        normalized["host"] = parsed.netloc
        normalized["connection"] = "close"
        body = bytes(body)
        if "content-length" in normalized and normalized["content-length"] != str(len(body)):
            raise ApprovalError("Content length does not match body")
        if body or method in {"POST", "PUT", "PATCH"} or "content-length" in normalized:
            normalized["content-length"] = str(len(body))
        operation = cls(session, request_id, method, url, tuple(sorted(normalized.items())), body)
        validate_binding(operation.binding())
        return operation

    def binding(self):
        return {"session": self.session, "request_id": self.request_id, "method": self.method,
                "url": self.url, "body_sha256": hashlib.sha256(self.body).hexdigest(),
                "headers_sha256": digest(dict(self.headers))}


class _FinalResponse(http.client.HTTPResponse):
    """Skip interim 1xx responses (e.g. 103 Early Hints) until the final response.

    http.client skips only 100 Continue. A 101 protocol switch is returned so the
    broker can reject it explicitly; it is never relayed as a final response.
    """
    MAX_INTERIM = 32

    def _read_status(self):
        for _ in range(self.MAX_INTERIM):
            version, status, reason = super()._read_status()
            if status in (100, 101) or not 100 <= status < 200:
                return version, status, reason  # begin() itself skips 100 headers.
            http.client.parse_headers(self.fp)
        raise http.client.HTTPException("Too many interim responses")


@dataclass(frozen=True)
class Response:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


def address_allowed(hostname, address, allow_private=False):
    """Destination policy applied to the single address the broker will contact.

    An IP-literal URL may contact only that address; localhost names only loopback.
    Other names must resolve to a globally routable address unless the operator
    explicitly allows private destinations (DNS-rebinding protection).
    """
    resolved = ipaddress.ip_address(address)
    try:
        return resolved == ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        pass
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return resolved.is_loopback
    return resolved.is_global or allow_private


def resolve_once(hostname, port):
    """Resolve exactly once; the broker connects only to these addresses, in order."""
    infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(info[4][0] for info in infos))
    if not addresses:
        raise ApprovalError("Destination did not resolve")
    return addresses


def _pinned_connector(addresses, peers):
    """Replacement for HTTPConnection._create_connection using only pinned addresses."""
    def connect(target, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, *rest):
        error = None
        for address in addresses:
            try:
                sock = socket.create_connection((address, target[1]), timeout, source_address)
            except OSError as exc:
                error = exc
                continue
            peers.append(address)
            return sock
        raise error or OSError("No pinned address accepted the connection")
    return connect


class HTTPBroker:
    """One connection per reservation, no redirects, cookies, proxy env, or retries."""
    def __init__(self, gate, *, timeout=10, max_response_bytes=8 * 1024 * 1024, journal=None,
                 allow_private_addresses=False, resolver=None):
        self.gate, self.timeout, self.max_response_bytes = gate, timeout, max_response_bytes
        self.journal = journal
        self.allow_private_addresses, self.resolver = allow_private_addresses, resolver

    def _record(self, kind, **data):
        if self.journal is not None:
            self.journal.append(kind, **data)

    def dispatch(self, operation, approval_id):
        # Rebuild to reject invalid operations even if directly constructed.
        checked = Operation.build(operation.session, operation.request_id, operation.method,
                                  operation.url, dict(operation.headers), operation.body)
        if checked != operation:
            raise ApprovalError("Noncanonical operation")
        receipt = self.gate.reserve(approval_id, operation.binding())
        self._record("reserved", receipt=receipt)
        # No socket/DNS lookup is created before successful reservation. Once spent,
        # an error/cancellation is not grounds to retry this operation automatically.
        parsed = urlsplit(operation.url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            resolved = (self.resolver or resolve_once)(parsed.hostname, port)
            addresses = [resolved] if isinstance(resolved, str) else list(resolved)
        except Exception:
            self._record("attempt_started", request_id=operation.request_id, addresses=[])
            self._record("attempt_failed", request_id=operation.request_id, error_type="ResolutionError")
            raise
        self._record("attempt_started", request_id=operation.request_id, addresses=addresses)
        cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        connection, peers = None, []
        try:
            # Every resolved address must satisfy the policy, so a rebinding answer
            # cannot hide behind an acceptable first record.
            if not addresses or not all(address_allowed(parsed.hostname, a, self.allow_private_addresses) for a in addresses):
                raise ApprovalError("Resolved address violates destination policy; no connection made")
            connection = cls(parsed.hostname, parsed.port, timeout=self.timeout)
            connection.response_class = _FinalResponse
            # Connect only to pinned addresses; HTTPS still verifies the certificate
            # and SNI against the approved hostname. No second DNS lookup occurs.
            connection._create_connection = _pinned_connector(addresses, peers)
            target = parsed.path or "/"
            if "?" in operation.url:
                target += "?" + parsed.query
            connection.putrequest(operation.method, target, skip_host=True, skip_accept_encoding=True)
            for name, value in operation.headers:
                connection.putheader(name, value)
            connection.endheaders(operation.body if operation.body else None)
            response = connection.getresponse()
            peer = peers[-1] if peers else None  # None only when the transport is mocked.
            self._record("response_headers_received", request_id=operation.request_id, status=response.status, peer=peer)
            if response.status < 200:
                raise ApprovalError("Protocol switching unsupported; request may have executed")
            # Never give the browser a redirect to follow outside interception.
            if 300 <= response.status < 400:
                relay = Response(502, (("content-type", "text/plain"),), b"Redirect blocked; destination requires a new approved request.")
            else:
                body = response.read(self.max_response_bytes + 1)
                if len(body) > self.max_response_bytes:
                    raise ApprovalError("Response exceeds configured limit; request may have executed")
                # http.client dechunks, but does not decompress. Preserve content-encoding.
                headers = tuple((k.lower(), v) for k, v in response.getheaders()
                                if k.lower() not in {"connection", "transfer-encoding", "content-length", "set-cookie", "refresh", "alt-svc"})
                relay = Response(response.status, headers, body)
            self._record("relay_prepared", request_id=operation.request_id, status=relay.status,
                         body_sha256=hashlib.sha256(relay.body).hexdigest())
            return receipt, relay
        except Exception as exc:
            self._record("attempt_failed", request_id=operation.request_id, error_type=type(exc).__name__)
            raise
        finally:
            if connection is not None:
                connection.close()


class ApprovedBrowser:
    """Creates its own context; install before pages exist and close on shutdown.

    approve(binding) is an async trusted-controller callback returning an already
    verified approval ID, or None to deny. It must NOT trust page/agent claims.
    Never expose the context, gate, callback, or Playwright connection to an agent.
    """
    def __init__(self, context, gate, approve, *, allowed_origins, approval_timeout):
        self._context, self._approve = context, approve
        self.session = secrets.token_hex(24)
        self.journal = ExecutionJournal(self.session)
        self._broker = HTTPBroker(gate, journal=self.journal)
        self._origins = frozenset(allowed_origins)
        self._timeout = approval_timeout
        self.events = []
        self._closing = False
        self._closed = False
        self._jobs = set()

    def _completed(self, job):
        self._jobs.discard(job)
        if not job.cancelled():
            job.exception()  # Retrieve failures even if the route was cancelled.

    @classmethod
    async def create(cls, browser, gate, approve, *, allowed_origins, approval_timeout=120):
        origins = tuple(allowed_origins)
        if not origins or approval_timeout <= 0:
            raise ValueError("Explicit origin allowlist and positive approval timeout required")
        for origin in origins:
            parsed = urlsplit(origin)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username is not None:
                raise ValueError("Allowlist entries must be exact HTTP(S) origins")
            parsed.port
        context = await browser.new_context(service_workers="block", accept_downloads=False)
        owner = cls(context, gate, approve, allowed_origins=origins, approval_timeout=approval_timeout)
        try:
            await context.route("**/*", owner._route)
            await context.route_web_socket("**/*", owner._websocket)
        except BaseException:
            await context.close()
            raise
        return owner

    async def new_page(self):
        if self._closing:
            raise RuntimeError("Browser execution boundary is closed")
        return await self._context.new_page()

    async def _websocket(self, route):
        self.events.append({"status": "blocked", "url": route.url, "reason": "WebSockets unsupported"})
        await route.close()

    async def _route(self, route):
        event = {"status": "blocked", "url": route.request.url}
        try:
            if self._closing:
                raise ApprovalError("Executor is closing")
            request = route.request
            parsed = urlsplit(request.url)
            if parsed.scheme + "://" + parsed.netloc not in self._origins:
                raise ApprovalError("Destination outside allowlist")
            if request.redirected_from is not None:
                raise ApprovalError("Browser redirect chains unsupported")
            operation = Operation.build(self.session, secrets.token_hex(24), request.method,
                                        request.url, await request.all_headers(), request.post_data_buffer or b"")
            event["binding"] = operation.binding()
            # Callback sees only a copy. It cannot mutate the operation to be sent.
            approval_id = await asyncio.wait_for(self._approve(json.loads(json.dumps(operation.binding()))), self._timeout)
            if not approval_id or self._closing:
                raise ApprovalError("Approval denied or executor closing")
            event["approval_id"] = approval_id
            job = asyncio.create_task(asyncio.to_thread(self._broker.dispatch, operation, approval_id))
            self._jobs.add(job)
            job.add_done_callback(self._completed)
            # Cancellation may not stop a socket after reservation; do not retry.
            receipt, response = await asyncio.shield(job)
            event.update(status="response_received", reservation=receipt, response_status=response.status)
            headers = dict(response.headers)
            headers["cache-control"] = "no-store"
            await route.fulfill(status=response.status, headers=headers, body=response.body)
        except asyncio.CancelledError:
            event["status"] = "cancelled_execution_not_established" if "approval_id" in event else "blocked"
            event["reason"] = "Route cancelled; an already reserved request may still execute"
            raise
        except Exception as exc:
            # Includes denial, timeout, verification, storage, and transport failures.
            # Do not claim a transport failure proves no bytes were sent.
            event["reason"] = type(exc).__name__ + ": " + str(exc)
            if "approval_id" in event:
                event["status"] = "failed_execution_not_established"
            try:
                await route.abort("blockedbyclient")
            except Exception:
                pass  # Page/context may have closed. Never fall back to continue_.
        finally:
            self.events.append(event)

    async def close(self):
        self._closing = True
        await self._context.close()
        if self._jobs:
            await asyncio.gather(*tuple(self._jobs), return_exceptions=True)
        self._closed = True

    def save_evidence(self, directory):
        if not self._closed or self._jobs:
            raise RuntimeError("Close the executor and await broker jobs before exporting")
        self.journal.save(directory, self._broker.gate)
