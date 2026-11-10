# Interactive request review

The local review interface connects a passkey ceremony to the controlled browser
executor. It shows each pending URL and method, lets the reviewer approve one
attempt or deny the request, and requires successful credential verification
before the executor can consume approval. It never approves requests automatically.

## Start a session

From the repository, with browser dependencies installed:

```sh
python -m pip install -e '.[dev,browser]'
python -m playwright install chromium
handoff-witness review --out artifacts/review-session
```

For installed Chrome, append `--channel chrome`. A new output directory is
required. The command opens a dedicated review window; register a passkey there.
Once enrollment succeeds, a separate controlled browsing context requests the
local fixture. Review its navigation and subsequent subresource requests one at
a time. Close the review window to end the run and export evidence.

To start at a chosen destination instead, supply `--url https://destination.example/`.
Only that exact origin is allowed. This is experimental browsing through the
HTTP broker; redirects, cookies set by responses, streaming, and other features
have deliberate restrictions described in [execution scope](EXECUTION.md).

A compatible authenticator is required for manual enrollment. It may ask for a
PIN or biometric check and may create a passkey in your authenticator. The runner
does not create a virtual authenticator or simulate your approval. Each new run
requires enrollment again; persistent passkey/account management is not provided.
A cancelled or unavailable ceremony grants no approval. The request can still be
denied or allowed to expire.

## What is shown and retained

- Destination URL, HTTP method, remaining review time, and individual approve/deny
  controls. URLs are rendered with text nodes, never as HTML or clickable links.
- Session/request identifiers and body/header hashes under expandable details.
  **Contents of the body and headers are not displayed.** A hash commitment is
  not a readable transaction preview or proof that the reviewer understood it.
- Recent credential approvals, denials, and expirations. Credential approval is
  labeled as approval for an attempt, not success at the destination.
- On shutdown, local `approvals.json`, `review.json`, `execution.json`, the gate
  database, and public keys. These artifacts contain URLs and assertions; use
  synthetic sessions. The gate signing key is ephemeral and is not exported.
- If an executor was created and closed normally, `audit/` contains its signed
  journal, terminal checkpoint, and public key. See [offline audit](EXECUTION_AUDIT.md).

The queue holds at most 32 requests, each for at most 120 seconds. Overflow,
timeout, closure, stale IDs, and invalid assertions do not release a request.
Reloading the review page recovers the session using its HTTP-only cookie.
Closing it denies pending reviews; already reserved attempts cannot be retracted.

## Enrollment and web boundary

The server binds to `127.0.0.1` on a random port and uses a `localhost` origin.
The dedicated review window receives a random, one-use bootstrap capability in
the URL fragment. JavaScript removes it from the address bar and exchanges it
for an HTTP-only, SameSite=Strict session cookie and an in-memory CSRF token.
The capability is not logged or exported. Possession of this capability is the
**authority to enroll the one reviewer credential for that run**; it does not
establish a real-world identity. A stolen capability can compromise enrollment.

Mutations require the exact Host and Origin, JSON content type, the session
cookie, and a custom CSRF header. The initial exchange requires the capability
instead. There is no permissive CORS policy. The UI sends no external assets;
CSP, frame denial, no-referrer, no-store, and nosniff headers reduce exposure.
The cookie lacks Secure because this experiment uses loopback HTTP; this server
must not be exposed through a public or remote forwarding endpoint.

The UI and enrollment service are trusted parts of the system. Local malware,
a compromised controller, browser/OS compromise, or access to the bootstrap
capability remains outside the guarantee. The control context is separate from
the agent browsing context and is never an ungated exception inside that context.
There is no claim of a hardware-protected display or non-frameable human intent.

These checks follow the [OWASP CSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
and WebAuthn's [origin requirements](https://www.w3.org/TR/webauthn-3/).
Chromium documents support for [localhost WebAuthn origins](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/content/browser/webauth/origins.md).

## Repeatable UI test

```sh
python -m handoff_witness.review_live --out artifacts/review-test
```

This separate harness uses a **virtual test authenticator**. It clicks the real
UI controls, checks that the receiver sees nothing before approval and one
request afterward, denies later requests, reloads the session, and tests hostile
URL rendering. It exports desktop/mobile screenshots and a report. It never
uses real passkeys or personal browser profiles. These are integration checks,
not a usability study or physical-human authentication evaluation.
