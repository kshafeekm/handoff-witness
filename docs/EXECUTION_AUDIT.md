# Verify an execution journal

Every `ApprovedBrowser` session now has a separate executor signing key. Its
broker records the gate's signed reservation, then appends signed observations as
the attempt progresses. Each record commits to the previous record. A signed
terminal checkpoint commits to the session, record count, and final record.

## What the verifier can check

`handoff-witness verify-execution` requires the executor key, a retained terminal
checkpoint, the gate key, enrolled credential ID and public key, and expected RP
ID/origin. It checks:

1. Every referenced WebAuthn assertion against the supplied credential and RP.
2. The gate signature on both the approval bundle and reservation receipt.
3. The reservation's approval digest, exact binding, approval ID, session,
   and timestamp within the approval's historical validity interval.
4. Unique approval and request IDs within the journal. A referenced approval
   cannot be missing or replaced, and unrelated approvals are not accepted.
5. Executor signatures, sequence, hash chain, checkpoint, and lifecycle ordering
   for each request, including interleaved concurrent requests.

The lifecycle starts at `reserved`, then `attempt_started`. Once the broker
receives upstream headers, it records `response_headers_received` with the real
status. `relay_prepared` records the status and body hash prepared for the
browser. For example, an upstream 302 produces a separately recorded local 502;
the redirect destination was not followed. `attempt_failed` can follow the
start or receipt of headers. It preserves the uncertainty of a failed send.
A terminal snapshot ending at `reserved` or `attempt_started` reports only the
stage actually recorded; an absent response is not a statement that no bytes
were sent. Concurrent records are ordered by append, not by an external clock.

## Generate and verify

```sh
python -m handoff_witness.execution_live --out artifacts/audit-example
```

The execution and review harnesses, and an orderly interactive review shutdown,
export an `audit/` subdirectory. It contains `bundle.json` (records and exactly
the referenced approvals), `checkpoint.json`, and `executor-public.pem`. The
parent directory contains the gate/credential public keys and credential ID.
If an interactive session ends before a browser executor is created, there is
no execution journal. Assemblies from older unsigned exports cannot be upgraded
into historical signed observations by this tool.

To check a **local fixture**, replace `PORT` with the review origin's actual
port from its WebAuthn challenge document, then run:

```sh
run=artifacts/audit-example
handoff-witness verify-execution "$run/audit/bundle.json" \
  --checkpoint "$run/audit/checkpoint.json" \
  --executor-key "$run/audit/executor-public.pem" \
  --gate-key "$run/gate-public.pem" \
  --credential-key "$run/credential-public.cbor" \
  --credential-id "$run/credential-id.txt" \
  --rp-id localhost --origin 'http://localhost:PORT'
```

Successful output lists each binding, upstream/relay observations, and separate
`approval`, `initiation`, and `remote_execution` conclusions. A verification
error exits nonzero. The harness also checks its saved bundle using its in-memory
keys and checkpoint and writes `audit-result.json` alongside the integration report.

For an adversarial audit, obtain expected identities, RP/origin and the terminal
checkpoint independently. Accepting replacement keys and checkpoint beside an
attacker's replacement bundle authenticates nothing about the original history.
A stale but genuine checkpoint does not establish freshness. The signer runs in
the trusted controller process; separate executor and gate keys are role
separation, not independent administrative control.

## Evidence limits

- The journal covers **reserved broker attempts**. Denials, pre-reservation
  failures, browser activity outside the broker, and the legacy `execution.json`
  diagnostic list are outside its signed record set. A missing entry is not
  proof of global absence. The verifier does not read or authenticate that list.
- A reservation authorizes one attempt. The verifier checks unique use within
  the supplied session; global replay prevention still depends on gate state.
- The broker signs observations in memory. Normal shutdown waits for broker
  jobs before export. A crash can lose the journal; reservation in SQLite and
  journal append are not one atomic transaction. If append fails before a send,
  the reservation remains spent. No crash-safe external checkpoint service or
  append-only remote log is claimed.
- `relay_prepared` does not prove browser delivery, remote business completion,
  or human initiation. A failed attempt may already have reached the destination.
  An authenticated receiver or independently operated witness is future work.
- `initiation: not_established` is intentional. Attribution records have a
  separate protocol and trust anchor; this verifier does not infer a human actor
  from credential use, or join records by similar URLs or timing.
- Verification is historical. It does not check current revocation, bind the
  URL to a country, or establish consent, intent, or legal responsibility.
