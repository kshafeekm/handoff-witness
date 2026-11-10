# Threat model and evidence contract

## Version 0.3: stored state

- **State isolation.** Exclusion has a second precondition: no agent-written
  state reachable when the request is made. Stores are the live document (DOM,
  script heap), the profile (cookies, web storage, IndexedDB, caches,
  service-worker registrations) and server state.
- **Stored-state relay.** A page the agent loaded writes state; a page the
  person later loads reads it and issues a request. Request lineage sees only
  the person's navigation and reports `not_agent`, although the request would
  not exist without the agent. This is not an exotic attack: sign-in cookies,
  carts and drafts are the same mechanism, and handing a session over is meant
  to share them.
- **Adversarial page.** In addition to the v0.2 powers, a page may write any
  state its origin can reach, and its server may keep state across requests and
  across host names. State that predates capture has no lineage.
- **State rules** only add agent roots. Observed state writes (response
  cookies, web storage, service-worker registration, injected scripts) taint
  later readers; host taint treats every document on, and response from, a host
  the agent contacted as carrying agent state. Neither rule sees reads, so both
  contest state nothing consumed. Human-written state is not tracked.
- **Measured limits.** Request lineage alone reports 40 of 45 relay effects
  `not_agent`; observed writes leave 15 (IndexedDB, server state); host taint
  leaves 5 (server state shared across host names) and contests 10 of 15
  human-only controls. No browser-side observer sees cross-host server state.
- **Partitioning.** One storage partition per controller blocks client-state
  relays and the continuity they share a mechanism with. It does not reach
  server state. The prototype emulates it with separate browser contexts for
  measurement; it is not a deployed defense.
- **Trade-off.** Shared state across the handoff, a `not_agent` label for what
  the person then does, and soundness of that label cannot all hold. Dropping
  exclusion never mislabels and never clears the agent.

## Version 0.2: mediation and exclusion

- **Mediated channel.** Agent actions issued through the capture adapter
  (navigate, pointer input, isolated-world evaluation) are recorded commands and
  become agent roots. Everything else that reaches the browser is unmediated.
- **Positive agent evidence** needs an authentic transcript and sound lineage
  edges, not complete mediation.
- **Exclusion (`not_agent`)** means no mediated command explains the cause. It
  needs complete mediation; an agent that bypasses the channel is
  indistinguishable from a person in the transcript (measured: the bypass
  template is wrong under every collector that uses exclusion). Complete
  mediation is not sufficient: see state isolation above. It never means
  `human`.
- **Adversarial page.** May run main-world JavaScript, navigate itself, submit
  forms, open popups and frames, dispatch synthetic events, and imitate the
  `hw-agent-…` source-URL format. It cannot reach isolated worlds, the DevTools
  session, or the recorder. Popups escape observation (missing, not mislabeled).
- **Trusted input** is observed in an isolated world (`isTrusted` events only).
  Input inside a mediated pointer command is the agent's; other trusted input
  adds an exclusion root to the document (label `mixed` with agent lineage).


## Version 0.1

The recorder, its Ed25519 key, Python runtime, and fixture-defined causal edges are
trusted. An adversary may edit, omit, reorder, replay, or substitute exported
records but cannot obtain the signing key or replace the verifier's independently
pinned key and retained checkpoint.

Verified means the signed statements form a well-formed, anchored history. It
does not mean the statements describe reality. Malicious signers can fabricate
coherent histories. Checkpoint custody is an assumption, not an implemented
transparency service. Removing a prefix breaks the sequence and hash chain
against any checkpoint. Suffix truncation is detectable only against a retained
later checkpoint; rollback of both the log and checkpoint is not detectable
without external freshness evidence. Since v0.2, `verify` and `verify_execution`
accept `expected_session` (CLI `--session`); pass it whenever one key may sign
several sessions, otherwise another session's log and checkpoint also verify.

## Attribution semantics

Each input has a recorded actor and control epoch. Effects inherit the union of
their parents' actor sets. A request reports human or agent for a singleton set,
mixed for both, and unknown when any ancestry is absent or unknown. Edges must
point to previously recorded events; duplicate IDs and forward references fail
verification. Control changes do not change previous roots.

These are provenance labels, not counterfactual proof of psychological causation.
Mixed means the collector asserted multiple contributing parents. Unknown must
never be silently converted to human. Missing approval is not evidence of denial.
The attribution engine does not infer approval. A separate WebAuthn module now
verifies request-bound credential approval and reserves it once; it does not alter
causal roots or prove physical human initiation. See [approval assumptions](APPROVALS.md).

The optional local review service uses a one-time bootstrap capability to
authorize initial passkey enrollment. Possession of that capability is a trust
boundary, not proof of identity. Its isolated UI, exact-origin and CSRF checks,
and frame denial do not protect against local malware or a compromised controller.
Body/header hashes are displayed, but their contents are not. See [review scope](REVIEW.md).

## Browser fixture boundary

The loopback server assigns a fresh correlation token to an explicit agent input
and a scheduled effect. JavaScript issues a fetch after a timer; the receiving
handler records the matched ancestry. Handoff changes the displayed controller.
This produces real HTTP traffic, but the fixture's labels and token are not
trusted physical-input provenance. The browser timer and server share a controlled
experiment; there is no independent security witness.

Unknown tokens are recorded as unknown; already-consumed tokens cannot establish
ancestry a second time. A stolen unconsumed token could be used first by another
actor, which is a known failure outside the fixture assumptions. Requests can
also bypass the fixture entirely. These limitations must not be hidden by signing.

## Intended research model

An opt-in `ApprovedBrowser` now mediates intercepted HTTP(S) requests in a fresh
context. The trusted Python broker consumes approval before opening a connection
and never continues the browser's native request. Service workers are disabled,
WebSockets are blocked, and redirects are returned as errors. This is not a
browser/OS sandbox: raw Playwright control, other contexts, WebRTC, speculative
connections, browser background traffic, and non-HTTP protocols require separate
egress isolation. See [execution scope](EXECUTION.md). Approval does not change
attribution labels, and local transport observations are not independent receipts.

A future collector must authenticate separate human and agent input channels,
track causal relationships at the browser runtime boundary, and mediate all
in-scope outbound requests. Agent claims and page JavaScript cannot assign their
own trusted actor labels. An input event's `isTrusted` flag alone is not a proof
of physical human input or authorization.

We must specify whether an attacker controls the agent, page, user account,
recorder, or OS. A claim resisting dishonest users requires protection from that
user's ability to modify the collector and keys, potentially through isolation
or attestation. This protection does not exist in v0.1. Both parties colluding
with the trusted collector defeats the model.

## Evidence lifecycle

The controlled broker signs reservation and transport-stage observations under
a separate executor key. The verifier cross-checks the gate reservation and
credential assertion against the binding and a pinned terminal checkpoint. This
authenticates trusted executor statements, not an independent server receipt or
actor identity. Records are in memory until orderly export; crashes can lose
records. Denied/pre-reservation routes and unsigned diagnostics are outside the
journal. See [execution audit assumptions](EXECUTION_AUDIT.md).

- Per-run ephemeral private key; public key exported for convenience.
- No remote transmission, public logging, or government integration.
- No asserted wall-clock proof or proof of legal jurisdiction.
- Full URL disclosure in local artifacts; do not collect personal sessions.
- Retention, external witnessing, key rotation, crash recovery, and selective
  disclosure require separate implementation and evaluation.

## Instruction-history extension

The `DecisionWitness` module records user-channel instructions and revisions,
external text, model inputs/outputs, and the proposed operation. A later denial
cannot overwrite the revision referenced by an earlier decision. It records
the trusted controller's assertions, not physical human identity or mental intent.

Distinguish three adversaries:

- A malicious user can steer an agent through direct or indirect instructions.
  Agent initiation does not exonerate that user. User text cannot itself grant
  the separate request-bound approval in the measured fixture.
- A malicious page supplies untrusted external text. This is a different input
  channel from the user's instruction, even if both influence the model.
- A dishonest recorder controls the trusted evidence boundary and can sign a
  coherent fiction. Export integrity verification cannot detect that fiction.

Deletion and rollback detection require an independently retained final
checkpoint and key. An old valid checkpoint cannot establish freshness. The
pilot's witnesses are created during replay of archived outputs, not attested
at the original model invocation. Paired prompt interventions estimate changes
in output under the experimental setup; they do not establish legal blame.
