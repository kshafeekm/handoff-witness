# Approval-gated browser execution

`ApprovedBrowser` connects the WebAuthn gate to real HTTP(S) execution in a fresh
Playwright browser context. Each intercepted request waits for the trusted
approval callback. Denial, timeout, errors, missing approval, changed operations,
expiry, revocation, and reused approvals fail closed. The route never calls
`continue_` or falls back to native browser networking.

## Execution sequence

1. Intercept navigation, subresource, or script request at the context route.
2. Enforce the explicit origin allowlist and reject unsupported request forms.
3. Freeze URL, method, final headers, body bytes, session, and random request ID.
4. Ask the trusted approval callback to obtain and verify a WebAuthn assertion
   for that binding. The callback receives a copy, not the frozen operation.
5. In the broker thread, atomically reserve the approval against the frozen
   binding before creating a socket or performing DNS resolution.
6. Send exactly one HTTP request with those headers/body. No automatic retries,
   redirects, cookie jar additions, or environment-proxy configuration apply.
7. Relay the buffered response into the browser using `route.fulfill`.

The broker supplies `Host`, `Connection: close`, and any required `Content-Length`
**before** computing the header digest. `http.client` automatic Host and
Accept-Encoding headers are disabled. Header hashing uses the canonical JSON map
of lowercase names to values; wire case/order are not claimed to be preserved.
The integration fixture compares received header/body hashes against the approval.
HTTPS uses Python's default certificate validation.

All HTTP 3xx responses become a local 502 response. No redirect destination is
contacted. Request and approve that destination separately if needed. The initial
redirect-producing request itself still requires approval and reaches its server.

## Run the receiver-checked test

```sh
python -m pip install -e '.[dev,browser]'
python -m playwright install chromium
python -m handoff_witness.execution_live --out artifacts/execution-new
```

For installed Chrome, append `--channel chrome`. Use a new output directory.
The fixture uses a virtual authenticator on a separate trusted control page;
real passkeys and personal browser profiles are not accessed. The control-page
bootstrap is explicitly excluded from the test receiver ledger.

The test exercises approved navigation and POST, denied navigation/fetch/image/
iframe/script/popup requests, a worker's denied fetch, WebSockets, redirects,
changed body binding, approval reuse, revocation, callback failure, and timeout.
The receiver must observe **only** `/index`, `/post`, `/redirect`, and `/worker`,
once each; received method/header/body hashes must match the reserved operations.
Artifacts include assertions, signed reservations, a signed execution journal,
the receiver ledger, and a versioned report. The journal authenticates broker
statements; the diagnostic `execution.json` and receiver ledger remain unsigned.
Receiver and executor are in one test process, not independent witnesses. See
[execution audit instructions](EXECUTION_AUDIT.md).

## Connect a trusted approval service

```python
from handoff_witness.execution import ApprovedBrowser

async def approve(binding):
    options = gate.begin(binding, enrolled_credential_id)
    # Show this binding on the trusted approval UI. The callback must obtain an
    # assertion from the enrolled credential; an agent's "approved" flag is invalid.
    assertion = await approval_ui.obtain_assertion(options)
    gate.finish(options["approval_id"], assertion)
    return options["approval_id"]  # Return None to deny instead.

executor = await ApprovedBrowser.create(
    browser, gate, approve,
    allowed_origins=["https://destination.example"],
    approval_timeout=120,
)
try:
    page = await executor.new_page()
    await page.goto("https://destination.example/")
finally:
    await executor.close()
```

`approval_ui` above is an application integration point. For the included local
implementation, pass `ReviewHub` as the callback or run
`handoff-witness review`; see [interactive review](REVIEW.md). The standalone
execution test implements the callback with native WebAuthn and a virtual credential.
Keep the approval UI in a separate trusted context. Do not make its origin an
ungated exception in the browsing context. Do not expose the raw Playwright
connection/context, Python callbacks, database, or gate key to untrusted agents.

## Scope and failure semantics

- This explicitly gates the new controlled context. Existing `serve`, `live`,
  and `Capture` APIs remain observation experiments; they do not enforce approval.
- Service workers are blocked when the context is created. WebSocket routes close
  without connecting to their servers. Interception is installed before pages.
- This is **not OS-level egress confinement**. WebRTC/UDP, DNS speculation,
  preconnect, browser background services, extensions, other contexts, external
  protocols, and controller/OS compromise are outside the guarantee. A deployment
  requiring every network packet to be mediated needs process/network isolation
  that permits egress only through the broker. That isolation is not implemented.
- Browser HTTP requests are relayed by Python, so TLS fingerprint, HTTP version,
  connection behavior, and some browser semantics differ. Only finite buffered
  responses up to 8 MiB are supported; streaming and upgrades are rejected.
  Set-Cookie, Refresh, and Alt-Svc response headers are dropped. This prototype
  is not a general-purpose authenticated web browser.
- Consuming approval authorizes **one attempt**, not guaranteed success. A timeout,
  disconnect, oversized response, cancellation, or crash may occur after the
  server receives bytes. The approval stays spent and is never automatically
  retried. Closing waits for already-started broker jobs; it cannot retract a send.
- Revocation is checked at reservation. Revocation after that point does not undo
  an in-flight request. Database rollback/duplication and clock/key integrity
  retain the approval gate's existing trust assumptions.
- Approval evidence does not establish initiation, comprehension, or liability.
  The attribution engine remains separate and does not infer a human root.
- **Fixed in v0.2** (v0.1.0 defects): interim 1xx responses are skipped and a
  `101` is rejected after the approval is spent; the destination is resolved
  once, every resolved address must satisfy the policy (loopback only for
  `localhost` names, global addresses otherwise unless `allow_private_addresses`),
  and the broker connects only to pinned addresses, journaling the candidates
  (`attempt_started.addresses`) and the connected peer
  (`response_headers_received.peer`). Keepalive/`sendBeacon` after teardown and
  SharedWorker traffic are still untested against interception.

Routing behavior is based on the official [Playwright network documentation](https://playwright.dev/python/docs/network)
and [route API](https://playwright.dev/python/docs/api/class-route). In particular,
ordinary redirect continuation is not a per-hop authorization boundary, which is
why this implementation never continues routes or automatically follows redirects.
