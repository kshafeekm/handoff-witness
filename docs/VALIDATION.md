# Initial validation

Date: November 5, 2026. Environment: macOS arm64, Python 3.14.7.

- Editable package installation and CLI entry point succeeded.
- `python -m pytest -q`: **24 passed**.
- Eight controlled semantics cases produced their expected labels. The
  current-controller baseline matched two. This is a fixture smoke test, not a
  statistically meaningful evaluation or a new security result.
- Local browser check: scheduled an agent-originated five-second JavaScript
  timer, simulated human takeover, and observed a real loopback fetch arriving.
  The receiver record reported current controller human and recorded origin
  agent. The exported log verified through the installed CLI.
- Screenshot and evidence are under gitignored `artifacts/browser/` in the
  development workspace. Fresh runs produce new ephemeral keys and identifiers.
- GitHub Actions configuration is provided but has not run remotely.
- The LaTeX scaffold has not been compiled or submitted.

The local sandbox initially refused listening sockets. The HTTP test and demo
were then run with explicit loopback access. No public server was started.

These checks do not validate physical human input, malicious-page attribution,
collector integrity against OS compromise, novelty, or legal applicability.

## CDP collector increment

- Expanded suite: **46 tests passed** on the same local Python environment.
- The synthetic CDP example produces agent, agent, unknown for initial navigation,
  post-handoff redirect, and delayed script fetch, respectively.
- Adapter contract tests exercise events preceding navigation replies, handoff
  during navigation, failed commands, listener cleanup, and refusing export while
  capture is active. At this milestone the adapter had not been validated against
  a live browser; see the subsequent [live validation](LIVE_VALIDATION.md).
- Signed metadata commits to the input transcript and source request envelopes.
  Input authenticity and complete browser coverage are not established by import.
- These are engineering checks, not paper-ready attribution accuracy results.

## Request-bound credential approval

The expanded local suite passed all **72 tests**.

The approval gate adds real WebAuthn signature verification, required user
verification flags, expiry/revocation checks, request binding, and persistent
one-use reservations. Unit tests use software-generated ES256 assertions and
exercise altered URLs/methods/bodies/headers/sessions, invalid signatures,
RP/origin mismatch, replay, restart, and concurrent reservation.

The browser integration at `artifacts/approval-live-001/` passed with a Chrome
virtual authenticator: credential verification succeeded, destination substitution
and approval reuse were rejected. No real human passkey was used and no reserved
operation was dispatched. A separate synthetic provenance check retained the
agent label after approval. These outcomes are protocol checks, not proof of
human intent or a claim that WebAuthn approval is a new invention.

## Approval-gated browser execution

- Expanded local suite: **102 tests passed** on November 5, 2026.
- The final controlled Chrome run in `artifacts/execution-live-003/` passed all
  **16 integration checks**, using Chrome 156.0.8078.80, Playwright 1.64.1,
  and Python 3.14.7. The preceding completed run also passed the same checks.
- Only four approved operations reached the receiver, once each: `/index`,
  `/post`, `/redirect`, and `/worker`. Received method and header/body digests
  matched the frozen bindings. No tested destination was received before approval.
- Unapproved navigation, fetch, image, iframe, script, popup, and worker fetches
  were blocked. WebSockets were closed without server connection. Redirect
  destinations were not followed. Substituted body bindings, reused approval,
  revocation, callback errors, and callback timeouts also blocked execution.
- Unit tests additionally verify expiry before connection, cancellation before
  approval, exact request serialization, all standard redirect statuses, and
  spent approvals after uncertain sends or oversized responses.
- The first harness attempt encountered a Chrome error-page navigation race
  following the intentionally denied navigation. Isolating that case in its own
  page resolved the harness issue; no enforcement bypass was observed.
- CI now includes this runner, but remote CI has not run. No novelty, OS-level
  network isolation, or physical-human approval claim follows from these tests.

See [execution scope and usage](EXECUTION.md). The approver is a virtual test
authenticator; the receiver shares the process. Artifacts are local and ignored
by Git. Existing observation-only demos do not automatically enforce approval.

## Local interactive review

- Expanded regression suite: **108 tests passed**.
- The review UI browser test passed six checks with Chrome 156.0.8078.80 and
  Playwright 1.64.1: no receiver arrival while waiting, one arrival after approval,
  denied requests absent, session recovery after reload, safe text rendering of
  hostile-looking URLs, and no unexpected receiver paths.
- The test uses the actual registration/approve/deny UI and native WebAuthn with
  a virtual authenticator. It does not use real passkeys or establish human intent.
- Unit tests additionally cover invalid assertions, stale approvals after denial,
  queue limits, expiry/cancellation/closure, immutable bindings, one-use bootstrap,
  unauthenticated access, Host/Origin/CSRF rejection, and response protection headers.
- Desktop and mobile layouts were visually inspected. A transient full-page
  screenshot redraw artifact after viewport resize was resolved by waiting for
  two animation frames before capture.
- The package wheel was built and confirmed to include all three review assets.
  The CLI exposes `handoff-witness review`; remote CI has not run.

See [manual usage and enrollment trust](REVIEW.md). Reports and screenshots are
under the ignored `artifacts/review-live-*` directories.

## Signed execution audit

- **145 regression tests passed**, including 37 execution-audit tests. Tests
  cover altered/deleted/reordered records, truncation against a retained
  checkpoint, replaced keys, substituted/missing approvals, invalid signatures,
  signed but impossible lifecycles, replay, concurrency, partial observations,
  post-expiry historical verification, and logging failure before network access.
- The Chrome execution fixture in `artifacts/audit-execution-001/` passed all
  **17 checks**. Its verified journal contained four reservations and 16 records;
  the four bindings matched requests at the receiver. The redirect recorded an
  upstream 302 and a local 502 response prepared by the broker.
- The interactive fixture in `artifacts/audit-review-001/` passed all **7 checks**.
  One virtual-passkey-approved request produced four signed records. The receiver
  saw that request once; denied paths never arrived. The unsigned receiver ledger
  is a test oracle in the same process, not an independent execution witness.
- Environment: Chrome 156.0.8078.80, Playwright 1.64.1, Python 3.14.7. CI is
  configured to run both fixtures, but remote CI has not run.

## Controlled attribution workload

- The expanded regression suite passed **164 tests**, including metric
  denominator checks and recomputation of the archived paper table and report.
- The final local evaluation completed 40 trials and 75 planned target requests.
  All requests reached the loopback receiver once. The page-target CDP collector
  captured 70; five worker requests were unobserved.
- The provenance method produced 45 correct assignments, 25 unknowns, and five
  missing observations. The baseline produced 50 correct and 20 wrong assignments,
  with the same five missing observations. Coverage and denominators are reported
  separately in [the evaluation notes](EVALUATION.md).
- The final run adds source fingerprints and full-run receiver reconciliation;
  its counts match the initial run. Authored templates are repeated development
  cases, not independent population samples or a held-out benchmark.
- Compact evidence and the generated table are checked into `paper/results`.
  The manuscript now describes methods, measured results, and negative findings.
  This was uncompiled at that stage; see the November 6 update below.

## Submission preparation, November 6, 2026

- Installed Tectonic 0.17.0 for manuscript compilation; Poppler renders the PDF.
- All 166 regression tests pass, including two additional paper-analysis checks.
- A new seed (20261106) produced the same aggregate and scenario metrics as the
  original seed (20261105), over a separate 40-trial, 75-target run.
- Both raw runs were re-collected from captured transcripts. All per-request
  rows matched the saved results; receiver reconciliation and signature
  consistency checks passed. Supplied verification anchors are not independent.
- Added post-hoc root-only and abstain-all baselines. Root-only assigns 25 of 75
  targets, while navigation plus redirect ancestry assigns 45. The controller
  baseline makes ten mistakes within those 45 assigned targets.
- Expanded the related-work comparison to PageGraph, WebREC, WebMCP-Phalanx,
  and service-side authority envelopes. No general superiority or priority
  claim is made, and prior systems were not benchmarked head-to-head.
- The compiled PDF and source/artifact ZIPs are produced under `output/`;
  package metadata records hashes. Nothing is submitted by the packaging script.
- The final nine-page PDF compiled without TeX warnings and every rendered page
  was inspected. The exact source ZIP rebuilt independently in a new directory.
- All 166 tests also passed from a clean extraction of the ancillary code/data
  archive after regenerating its tables. Both archived raw runs re-collected
  to the original rows and passed signature consistency checks there as well.
## Research extension validation, November 6, 2026

- 188 regression tests passed in the working repository and the clean extracted
  ancillary archive.
- Two pinned local models generated 288 retained outputs under a frozen plan.
- Browser replay reconciled 185 proposals per mode: 138 restricted arrivals
  natively, zero gated; all 47 public proposals arrived in both modes.
- All 288 decision witnesses verified and retained prior instructions after a
  later denial. Eight mutations per transcript were rejected against retained
  anchors (2,304 checks, not independent attacks).
- The separate live approval fault run passed all 17 checks.
- Clean extraction regenerated the four result tables and model-pilot summary
  byte for byte. Both original attribution runs re-collected exactly.
- The 14-page, six-table source archive compiled in isolation without TeX
  warnings; every rendered page was visually inspected.

The model pilot uses authored single-step tasks, two sizes of one model family,
and virtual approval. Signatures authenticate trusted-controller statements;
they do not prove human identity, mental intent, or legal liability. The original
collector's human-input and worker-coverage gaps remain. Full methods, negative
controls, failures, and reproduction instructions are in the manuscript.
