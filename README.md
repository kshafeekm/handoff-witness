# Handoff Witness

[![Code: MIT](https://img.shields.io/badge/code-MIT-blue.svg)](LICENSE)
[![Paper: CC BY 4.0](https://img.shields.io/badge/paper-CC_BY_4.0-blue.svg)](paper/LICENSE.txt)
[![Python: 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

**Who Caused the Access? Evidence Boundaries in Human-Agent Browser Handoffs**

Trace recorded request origins across human–agent handoffs, require request-bound
approval before browser execution, and audit retained instruction changes.

[Quick start](#quick-start) · [Paper and reproduction](paper/README.md) ·
[Threat model](docs/THREAT_MODEL.md) · [Contributing](CONTRIBUTING.md) ·
[Citation](#citation)

No release is published yet. The Git checkout holds the code, paper source, and
compact results; the paper PDF and the archive with raw runs are built by
`paper/package.py` (see [Paper and reproduction](paper/README.md)).

A runnable research prototype that preserves recorded request origins when control
changes between a human and an agent. An agent-originated timer can fire after a
human takes over; the current controller is not necessarily the initiating actor.

**Status: experimental, pre-publication. Novelty is unverified.** This project
authenticates recorder statements, not human intent, physical input, or legal
responsibility. It does not detect access to prohibited sites or determine laws.

**Version 0.3** corrects a guarantee that version 0.2 overstated. Agent
actions routed through a mediated, logged channel can be evidenced positively;
human origin cannot be evidenced from a browser transcript, so the collector
emits `not_agent` (exclusion), never `human`. Version 0.2 said that label was
sound under complete mediation. It also needs *state isolation*: no
agent-written state reachable when the request is made. A handoff breaks that
on purpose, because the cookies, storage, workers and server session that let a
person continue an agent's work also let the agent's work continue through the
person.

On a predeclared 32-template workload (375 targets), a collector that follows
request lineage alone reports 40 of 45 requests that depend on agent-written
state as `not_agent`, with mediation complete. Counterfactual twins confirm
each of the 45 needs both parties. Following observed state writes leaves 15;
tainting every host the agent contacted leaves 5 and contests 10 of 15
human-only controls. The last 5 are server state shared across host names,
which no browser-side observer sees. One storage partition per controller
blocks all six client-state relays, neither server-state relay, and legitimate
continuity by the same mechanism. A deployment can have shared state, an
exonerating label, or a sound one, but on this evidence not all three.

The full collector labels 340 of 375 targets correctly, 10 wrong (the mediation
bypass and the cross-host relay), 20 contested, 5 missing (popups); the
current-controller baseline is wrong on 125. On the 20 templates of version 0.2
every label matches that release (180 of 200). A second seed reproduces every
count. A counterbalanced 1,152-output local-model pilot (appendix, unchanged)
shows that the apparent effect of indirect pressure occurs only when the
restricted option has the letter the models prefer; the fixed approval broker
delivers none of the 486 restricted proposals and all 310 public ones.
Everything is synthetic loopback data with simulated human actions. See
[paper and reproduction](paper/README.md).

## Quick start

Python 3.11+:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
handoff-witness demo
handoff-witness benchmark
handoff-witness serve
```

Open **http://127.0.0.1:8765**, schedule an agent request, and simulate human
takeover before the five-second timer fires. A real HTTP request reaches the
loopback server. The display compares the current-controller baseline with
recorded causal ancestry. This is a controlled browser fixture: the simulated
human label is not evidence that a physical person interacted.

For the dependency versions used in the initial local verification, install
`requirements-tested.txt` before the editable package. See
[validation notes](docs/VALIDATION.md) for the tested environment and scope.

Without installing the package, run `python -m handoff_witness.cli` in place of
`handoff-witness` from the repository root.

## Verify evidence

```sh
handoff-witness verify artifacts/demo/events.jsonl \
  --trusted-key artifacts/demo/recorder-public.pem \
  --checkpoint artifacts/demo/checkpoint.json
python -m pytest -q
```

The command above checks internal consistency for the demo. For meaningful
adversarial verification, obtain the public key independently and retain the
terminal checkpoint outside the recorder's control. Accepting a replacement key
and checkpoint alongside a replacement log does **not** authenticate history.
An old valid checkpoint cannot prove that no later events exist.

## Live browser integration test

```sh
python -m pip install -r requirements-browser-tested.txt
python -m playwright install chromium
python -m handoff_witness.live --out artifacts/live-run
```

Alternatively, use installed Google Chrome with `--channel chrome`. The runner
creates a fresh headless browser context, hosts its own loopback fixtures, and
closes that browser after the experiment. It does not attach to personal tabs or
profiles. Choose a new output directory for each run; existing results are never
overwritten. Exit status is nonzero if any contract check fails.

A server-side gate ensures simulated human takeover occurs before the redirect
response is released. An HTTP receiver ledger independently observes arrivals;
it supplies no actor labels to the collector. See
[live validation](docs/LIVE_VALIDATION.md) for results and limitations.

## Implemented

- Explicit control epochs and separate input, effect, and request records.
- Causal-root propagation across handoffs; agent, not-agent (exclusion), mixed, and
  unknown labels. The collector never emits `human` from a transcript.
- Conservative unknown propagation when any recorded ancestor is unobserved.
- Ed25519 signatures, hash chaining, and a signed terminal checkpoint.
- Offline structural, signature, sequence, and causal-parent validation.
- Eight deterministic fixture scenarios and a real loopback HTTP demo.
- A conservative CDP transcript collector and opt-in session adapter for agent
  navigations and redirect chains. See [collector instructions](docs/COLLECTOR.md).
- A v0.2 lineage collector (`lineage.py`) with switchable rules: navigation,
  redirect, document and renderer-navigation lineage, worker lineage
  (non-flattened auto-attach), injected-script lineage via unguessable
  `sourceURL` tags in async initiator stacks, isolated-world trusted-input
  taint, and exclusion. The capture adapter's lineage mode is the mediated
  agent channel (navigate, click, isolated-world evaluation).
- v0.3 state rules in the same collector: service-worker lineage, taint from
  observed state writes (response cookies, web storage, service-worker
  registration, injected scripts), and host taint. They only add agent roots,
  so they withdraw `not_agent` and never grant it. The adapter records cookie
  names and domains and storage-write origins; values and keys are dropped.
- Twelve stored-state templates with counterfactual twins (agent phase
  removed, human phase removed, one storage partition per controller).
- A passing live Chrome integration experiment with raw captures, signed evidence,
  a receiver ledger, and a versioned test report. CI configuration repeats it.
- A separate request-bound WebAuthn approval gate with persistent one-use dispatch
  reservation, revocation checks, and offline assertion verification. See
  [approval scope and tests](docs/APPROVALS.md). Approval never relabels initiation.
- A controlled browser execution broker that aborts unapproved requests, consumes
  exact request approval before network access, and blocks redirects and WebSockets.
  See [execution boundary and runnable test](docs/EXECUTION.md).
- A local passkey review UI with individual approve/deny controls, a bounded
  pending queue, and session/CSRF protections. See [interactive review](docs/REVIEW.md).
- A signed broker journal and offline verifier linking each reserved request
  to credential approval, the gate receipt, and subsequent broker observations.
  See [execution audit instructions](docs/EXECUTION_AUDIT.md).
- A seeded 20-template workload (`workload.py`) with seven adversarial pages,
  receiver checks, and correct/wrong/contested/unknown/missing scoring, with ten
  collector variants run over the same captures. See [evaluation results](docs/EVALUATION.md).
- A broker that skips interim 1xx responses, resolves each destination once,
  enforces an address policy (DNS-rebinding protection), connects only to pinned
  addresses, and journals the connected peer.
- Tests for modification, deletion, truncation, replay, wrong keys, malformed
  evidence, missing parents, and invalid actor/channel claims.

## Not implemented

- A protected browser/OS collector distinguishing physical input from automation.
- Popups and other new targets (unobserved; the adversarial popup page escapes
  the record), extensions, event-handler provenance finer than document-level
  taint, and enforcement of complete mediation outside the fixture. The capture
  service is not protected against a compromised harness or OS.
- State isolation. The state rules approximate it and stay wrong on server
  state shared across host names; they see writes, not reads, and miss
  IndexedDB and Cache writes except through host taint. Per-controller storage
  partitioning is emulated with separate contexts for measurement only.
  Human-written state is not tracked.
- Hardware attestation, an independently operated execution witness, external
  checkpoint custody, or trustworthy wall-clock timestamps.
- General delegation, policy compliance, and intent verification. The separate
  approval module now gates a dedicated browser context through an HTTP broker;
  OS-wide network isolation and protection from a compromised controller remain
  unimplemented. Capture records still report
  `authorization: not_evaluated`; no automatic authorization claim is inferred.
- Independent proof against a compromised recorder or operating system.

v0.1.0 defects (broker relayed interim 1xx responses as final, hostname-only
allowlist allowed DNS rebinding, verifiers lacked an expected-session check) are
fixed in v0.2. The code of v0.1 and v0.2 is not kept in this repository's
history; their compact results remain under `paper/results/v0.1` and
`paper/results/v0.2`, where metrics can be recomputed but runs cannot be
re-collected.

The browser fixture deliberately exposes its limitations: a token links a known
timer to a registered effect. Page code can steal or reuse a token. A replayed
token becomes unknown after its first use, but a stolen token used first could
still misattribute a request. **This fixture is not a secure browser adapter.**
The receiver and recorder are in the same process, not independent witnesses.

`dispatch_observed` and `receiver_observed` describe distinct observation stages.
The CDP collector adds `browser_request_observed`, which does not establish that
bytes reached a remote server (cache and cancellation can intervene).
Neither means the action was authorized or that a downstream operation completed.
`controller_at_dispatch` is the current controller at the observation point;
for receiver observations, this is receipt time, not a measured send time.

## Repository

| Path | Purpose |
|---|---|
| `handoff_witness/core.py` | Signed evidence and verifier |
| `handoff_witness/benchmark.py` | Synthetic scenarios and baseline |
| `handoff_witness/lineage.py` | Lineage collector with switchable rules, exclusion, and v0.3 state rules |
| `handoff_witness/workload.py` | Predeclared 32-template workload (v3), counterfactual twins, scoring, ablations |
| `handoff_witness/steering_v2.py` | Counterbalanced model pilot (appendix) |
| `handoff_witness/evaluate.py` | v0.1 eight-template workload (kept for the archived results) |
| `handoff_witness/server.py` | Loopback browser experiment |
| `handoff_witness/cdp.py` | Conservative CDP transcript attribution |
| `handoff_witness/capture.py` | Opt-in CDP session capture adapter |
| `handoff_witness/live.py` | Repeatable live Chrome/Chromium integration experiment |
| `handoff_witness/approval.py` | WebAuthn approval and persistent one-use reservation |
| `handoff_witness/approval_live.py` | Virtual-authenticator browser integration test |
| `handoff_witness/execution.py` | Approval-gated browser context and HTTP broker |
| `handoff_witness/execution_audit.py` | Signed broker lifecycle records and anchored offline verification |
| `handoff_witness/execution_live.py` | Receiver-checked execution and bypass tests |
| `handoff_witness/review.py` | Local review service, passkey enrollment, and interactive runner |
| `handoff_witness/review_live.py` | Receiver-checked review UI test with a virtual authenticator |
| `tests/` | Integrity, semantics, and HTTP tests |
| `docs/THREAT_MODEL.md` | Trust boundaries and limits |
| `docs/RESEARCH_PLAN.md` | Experiments needed before publication |
| `paper/main.tex` | Preprint manuscript with controlled evaluation; see paper/README.md for submission status |
| `paper/results/` | Measured report, manifest, per-request scores, and generated table |

## Research honesty

Passing the eight synthetic cases demonstrates implemented semantics, not performance on
representative browsing or resistance to malicious websites. The expected roots
are controlled by the fixture. Do not report the resulting score as a measured
security guarantee. We need independently labeled workloads and an actual
protected collector before making a publication-level attribution claim.

The v0.3 workload has 375 targets over 32 authored templates. The full
collector: 340 correct, 10 wrong (the mediation bypass and the cross-host
server-state relay), 20 contested (`mixed`: cross-channel input and two
stored-state controls), 0 unknown, 5 missing (popups). The v0.2 collector on
the same captures: 310 correct, 45 wrong, 40 of them stored-state effects
reported `not_agent`. Without exclusion: 200 correct, 0 wrong, 5 contested, 165
unknown. The current-controller baseline: 245 correct, 125 wrong, 5 missing.
The templates were written with knowledge of the collector and human actions
are simulated; these counts are not a security guarantee or a population
estimate. Twelve stored-state templates show the relay exists, not how often
real sites do it. The prior-art search behind the stored-state claim was a
short keyword search, so the claim is the measurement and the rules, not
priority. (v0.2 on 20 templates: 180 correct, 5 wrong, 10 contested, 5 missing.
v0.1 on eight templates: 45 correct, 25 unknown, 5 missing; baseline 50
correct, 20 wrong.)

Related work and the candidate novelty boundary are recorded in
[the research plan](docs/RESEARCH_PLAN.md). No first-ever claim is made.

## Privacy

Evidence currently contains full URLs. Use local fixtures, never live personal
browsing. Artifacts are gitignored, and ephemeral signing keys are not written to
disk. Selective disclosure and URL commitments are future work; hashing a URL
alone would not hide predictable destinations from dictionary attacks.

## License

- **Software and accompanying documentation:** [MIT](LICENSE).
- **Manuscript and compiled paper:** [CC BY 4.0](paper/LICENSE.txt).

Third-party dependencies and cited publications retain their own licenses.

## Citation

Maintained by **Shafeek Kakkidumban Manayil**, Independent Researcher.
Use [CITATION.cff](CITATION.cff) to cite the software. For the manuscript:

> Shafeek Kakkidumban Manayil. *Who Caused the Access? Evidence Boundaries in Human-Agent
> Browser Handoffs*. Unpublished manuscript, 2026.

No DOI or arXiv identifier has been assigned in this repository. Update citations
to the published record when one becomes available.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and reproducibility
guidelines, and [SECURITY.md](SECURITY.md) for vulnerability reporting and the
prototype's security scope.
