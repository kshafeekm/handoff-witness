# Controlled live browser validation

Date: November 5, 2026. Chrome **156.0.8078.80**, Playwright **1.64.1**,
Python **3.14.7**, macOS arm64. Initial run: `artifacts/live-001/`.

The actual `Capture` adapter and CDP importer were exercised together against a
fresh headless Chrome context. No personal browser profile was attached. Page
requests were restricted to the local fixture origin. The fixture server held
the initial response until the harness recorded a simulated human takeover,
making the handoff-before-redirect ordering explicit rather than timing-based.

| Received path | Collector target | Actual label | Receiver count |
|---|---|---|---|
| `/start` | agent | agent | 1 |
| `/landing` (redirect after handoff) | agent | agent | 1 |
| `/delayed` (script fetch) | unknown | unknown | 1 |
| `/unbound` (navigation outside the capture adapter) | unknown | unknown | 1 |

All four integration checks passed. The redirect was observed while the current
controller was human but retained agent ancestry. No page request to a nonlocal
origin was attempted in the run. Evidence passed the offline signature, chain,
and semantic verifier. This verifier was supplied the locally generated anchors,
not an independently provisioned production trust anchor.

The initial capture also included a favicon event without a matching receiver
entry at the report snapshot. Its origin remained unknown. A CDP request event
is therefore kept separate from evidence of server receipt; the snapshot alone
does not establish why an entry is unmatched or whether it could arrive later.

The receiver ledger observes real HTTP arrival and does not feed attribution
labels into the collector. It runs in the same trusted test process, however,
and is not an independently secured third-party witness.

Unknown is a target for conservative behavior, **not a ground-truth actor**.
Matching four authored targets is not 100% real-world attribution accuracy. The
current-controller baseline matches one of these targets, but that comparison
is only a demonstration of the contract; it is not a comparative research result.

## Reproduce

```sh
python -m pip install -e '.[dev]' -r requirements-browser-tested.txt
python -m playwright install chromium
python -m handoff_witness.live --out artifacts/live-new
```

For installed Chrome, add `--channel chrome` and omit the Chromium installation.
The output directory must not already exist. Runs export:

- `capture.json`: raw CDP/harness transcript.
- `receiver.json`: independently observed HTTP arrivals with local monotonic times.
- `analysis.json`: collector classifications, reasons, and coverage.
- `evidence/`: signed log, terminal checkpoint, and public key.
- `report.json`: browser/runtime versions, checks, and limitations.

Generated runs are gitignored because future captures could contain sensitive
data. The checked-in fixtures and harness reproduce the experiment. CI now has a
browser-integration job that retains generated artifacts; it has not yet run
remotely. Browser and OS differences may expose new failures.

## Remaining research work

Authenticate and protect input channels; track delayed script and worker ancestry;
test concurrent human/agent activity and malicious pages; establish external
checkpoint custody; evaluate on held-out workloads; and verify the novelty claim.
The live run does not authenticate a human, infer intent, or establish liability.
