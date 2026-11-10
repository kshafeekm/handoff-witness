# Credential approval is separate from initiation

The approval module binds a WebAuthn assertion to one exact request descriptor.
It adds evidence of credential approval, not a human-origin label. A verified
assertion must never turn an agent-originated action into a human-originated one.
This applies established WebAuthn and transaction-binding techniques; it is not
claimed as a new cryptographic invention.

## What is checked

The challenge is SHA-256 over a canonical document containing a random nonce,
approval ID, credential ID, relying-party ID, origin, expiry, and request binding.
The binding contains session, unique request ID, method, exact URL, body digest,
and header digest. The gate verifies the assertion using a previously enrolled
credential key, requires user-presence and user-verification flags, and checks the
RP, origin, challenge, signature, and applicable authenticator counter.

SQLite transactions make challenge approval and dispatch reservation atomic.
The approval ID can be reserved once; the same session/request ID also cannot be
reserved again using a new approval. Replay state survives process restart when
the same database is retained. RP, origin, and gate signing key are pinned in the
database configuration. Credential revocation and expiry are checked again at
reservation. A crash after reservation does not silently make an approval reusable.

An enrollment call is a privileged administrative boundary. The caller must first
authenticate and authorize enrollment and verify the registration ceremony.
The new [local review service](REVIEW.md) verifies registration before calling
this API. Its one-use bootstrap capability authorizes enrollment for that run;
it is not a production account or identity system.

## Minimal API

```python
from handoff_witness.approval import ApprovalGate

# gate_key is an externally protected, persistently managed Ed25519 key.
gate = ApprovalGate("gate.sqlite", rp_id="approve.example",
                    origin="https://approve.example", signing_key=gate_key)
gate.enroll_trusted(credential_id, verified_cose_public_key, sign_count)
options = gate.begin(request_binding, credential_id)
# Render request_binding on a trusted approval surface; obtain a WebAuthn
# assertion with options["publicKey"] through navigator.credentials.get().
bundle = gate.finish(options["approval_id"], assertion)
# Executor computes the final operation binding, never accepts the agent's copy.
receipt = gate.reserve(options["approval_id"], actual_operation_binding)
# Only now may the trusted executor attempt exactly that operation.
```

`reserve` alone is a one-use admission decision, not an execution wrapper or a
server receipt. The new [execution broker](EXECUTION.md) computes the header/body
hashes from a frozen operation, reserves approval, and sends those bytes once.
Use `ApprovedBrowser` explicitly: the original capture/demo adapters do not
automatically acquire this boundary. The broker blocks redirects; a destination
must be requested and approved separately. The gate still trusts its executor.

## Browser integration test

```sh
python -m pip install -e '.[dev,browser]'
python -m playwright install chromium
python -m handoff_witness.approval_live --out artifacts/approval-new
```

Use `--channel chrome` for installed Google Chrome. The harness creates a fresh
browser context, enables a **virtual test authenticator**, performs registration
and authentication, verifies the resulting assertion, tests destination
substitution and replay, and exports evidence. It does not access real passkeys.

Local validation passed with Chrome 156.0.8078.80, Playwright 1.64.1,
py_webauthn 3.0.1, and Python 3.14.7. The virtual authenticator simulates user
verification: this test establishes protocol interoperability, not human presence
or biometric integrity. The proposed operation is reserved, not transmitted.

## Offline verification

The run exports `approval.json`, `reservation.json`, `binding.json`,
`gate-public.pem`, `credential-public.cbor`, and `credential-id.txt`. Use the
exact origin from the approval's challenge document (the test uses a random port):

```sh
handoff-witness verify-approval artifacts/approval-new/approval.json \
  --gate-key artifacts/approval-new/gate-public.pem \
  --credential-key artifacts/approval-new/credential-public.cbor \
  --credential-id artifacts/approval-new/credential-id.txt \
  --binding artifacts/approval-new/binding.json \
  --rp-id localhost --origin http://localhost:PORT
```

For adversarial verification, obtain gate and credential keys independently of
the bundle. The demo supplies local trust anchors only. Offline verification
checks historical credential evidence; it cannot determine current revocation,
global replay, or whether a reserved operation actually executed.

## Remaining trust assumptions

- WebAuthn proves credential use and authenticator-reported flags, not that a
  person read, understood, or voluntarily chose the displayed operation.
- The authenticator generally signs an opaque challenge, not a trusted display of
  the URL. A malicious approval UI can still mislead a user. The local review UI
  adds frame denial and CSRF checks, but not a hardware-protected display.
- Enrollment, credential ownership mapping, RP UI, gate, clock, database,
  executor, and key custody are trusted. No hardware attestation or OS isolation
  is claimed. Code sharing the gate's privileges can bypass it.
- Database rollback or copying replay state into independent gates can defeat
  one-use guarantees. Distributed replay protection is not implemented.
- The fixture database contains pending/approved operations and assertions;
  keep it private. Signing keys in the test are ephemeral and are not persisted.

Sources: [WebAuthn standard](https://www.w3.org/TR/webauthn-3/) and
[py_webauthn authentication](https://duo-labs.github.io/py_webauthn/authentication.html).
