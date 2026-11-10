# Controlled attribution evaluation

## Version 0.3 (current)

```sh
python -m pip install -r requirements-tested.txt -r requirements-browser-tested.txt -e .
python -m handoff_witness.workload --channel chrome --repeats 5 --seed 20261109 --out artifacts/attribution-new
python paper/analyze.py
python paper/verify_runs.py artifacts/attribution-new
```

Protocol `attribution-workload/v3`: 32 authored templates in four groups (the
eight v0.1 templates, five mediated-channel templates, seven adversarial pages,
twelve stored-state templates), five repetitions, 160 trials, 375 target
requests. The manifest is written before the browser starts and records the
source convention, fifteen collector variants, the expected twin deliveries,
and hashes of `workload.py`, `capture.py`, `lineage.py`, and `core.py`.

### Stored-state group

Each template has two phases separated by a handoff. The agent channel
navigates to a page; the human channel then navigates to a second page, and a
target *effect* request is issued only if state from the first phase is
present. Nine relays vary the store (localStorage, localStorage written by a
late timer, a `Set-Cookie` cookie, a `document.cookie` cookie, IndexedDB, a
service worker, the DOM of a human-loaded page, server state on the same host,
server state reached under another host name). Three controls issue the effect
whatever the agent did (the human channel writes and reads its own state; the
agent writes a key nothing reads; the agent writes nothing).

The effect's assigned source is `joint` in the relays and `human` in the
controls. Each stored trial is followed by three delivery-only twins in fresh
contexts without capture: agent phase removed, human phase removed, and one
browser context per controller. A relay trial is valid only if the effect
arrives in the trial and in neither of the first two twins. The partitioned
twin is a measurement, not a validity check.

### Scoring

Agent on agent-sourced and not-agent on human-sourced targets are correct;
other agent/not-agent labels are wrong; `mixed` is contested; observed but
unlabeled is unknown; unobserved is missing. On a `joint` target, `mixed` or
`agent` is correct and `not_agent` is wrong (a false exoneration).

The browser's own fetch of the service-worker script is required but not
scored. Whether CDP reports it depends on a race between worker start-up and
attachment: a discarded pilot saw it in 2 of 5 trials, and neither reported run
saw it. It is declared auxiliary in the manifest.

| Method (primary run, seed 20261109) | Correct | Wrong | Contested | Unknown | Missing |
|---|---:|---:|---:|---:|---:|
| Current controller | 245 | 125 | 0 | 0 | 5 |
| v0.1 rules (navigation + redirect) | 140 | 0 | 0 | 230 | 5 |
| Request lineage (v0.2 collector) | 310 | 45 | 10 | 5 | 5 |
| + service-worker lineage | 315 | 45 | 10 | 0 | 5 |
| + observed state writes | 335 | 20 | 15 | 0 | 5 |
| + host taint (v0.3 collector, full) | 340 | 10 | 20 | 0 | 5 |
| Full without exclusion | 200 | 0 | 5 | 165 | 5 |

The replication run (seed 20261110) produced identical counts.

| Stored effect | v0.2 | + writes | + host | No agent phase | No human phase | Partitioned |
|---|---|---|---|---:|---:|---:|
| localStorage | **not_agent** | mixed | mixed | 0/5 | 0/5 | 0/5 |
| localStorage, late timer | **not_agent** | mixed | mixed | 0/5 | 0/5 | 0/5 |
| Cookie (`Set-Cookie`) | **not_agent** | mixed | mixed | 0/5 | 0/5 | 0/5 |
| Cookie (`document.cookie`) | **not_agent** | mixed | mixed | 0/5 | 0/5 | 0/5 |
| IndexedDB | **not_agent** | **not_agent** | mixed | 0/5 | 0/5 | 0/5 |
| Service worker | unknown | agent | agent | 0/5 | 0/5 | 0/5 |
| DOM of a human-loaded page | **not_agent** | mixed | mixed | 0/5 | 0/5 | n/a |
| Server state, same host | **not_agent** | **not_agent** | mixed | 0/5 | 0/5 | 5/5 |
| Server state, other host | **not_agent** | **not_agent** | **not_agent** | 0/5 | 0/5 | 5/5 |
| Control: human writes, human reads | not_agent | not_agent | not_agent | 0/5 | 0/5 | 5/5 |
| Control: agent writes, nothing reads | not_agent | *mixed* | *mixed* | 5/5 | 0/5 | 5/5 |
| Control: agent visits, writes nothing | not_agent | not_agent | *mixed* | 5/5 | 0/5 | 5/5 |

Bold is a wrong label; italic is a contested label on a human-only effect. In
the first control the "no agent phase" twin omits the human channel's own
write, so it delivers nothing.

Reading the result:

- Request lineage reports 40 of 45 relay effects `not_agent` with mediation
  complete. Observed writes leave 15, host taint leaves 5.
- The remaining 5 are server state shared across host names. No browser-side
  rule sees it; closing it needs server-side evidence or giving up exclusion.
- Host taint contests 10 of 15 human-only control effects. That is its price,
  and this workload under-samples it: outside the stored group, few templates
  put a person on a host the agent already touched.
- Partitioning blocks the six client-state relays and neither server-state
  relay, and it would block legitimate continuity the same way.
- On the 20 templates of version 0.2 the full collector gives the published
  counts (180 correct, 5 wrong, 10 contested, 5 missing). Its five wrong labels
  are the mediation bypass; its contested labels are cross-channel input; its
  missing targets are popups. Without document and renderer-navigation
  lineage, exclusion mislabels form auto-submission.

See `paper/results/` for per-scenario and ablation tables.

## Version 0.2 (archived)

Protocol `attribution-workload/v2`: the first 20 templates above, 100 trials,
200 targets, ten collector variants. Results: current controller 115 correct
and 80 wrong; v0.1 rules 90 correct and 105 unknown; lineage without exclusion
145 correct, 5 contested, 45 unknown; lineage with exclusion 180 correct, 5
wrong, 10 contested (5 missing in every row). Compact results are under
`paper/results/v0.2`; the code that produced them is not kept in this
repository's history, so they can be recomputed but not re-collected.

## Version 0.1 (archived)

The section below describes the v0.1 eight-template workload. Its compact
results are under `paper/results/v0.1`; its code is not kept in this repository's history.

This evaluates attribution coverage and errors in the existing CDP observation
adapter. It does **not** use the approval broker, an LLM, physical human input,
or a real-world website. It is a reproducible engineering workload, not evidence
that the complete research problem is solved.

## Reproduce

```sh
python -m pip install -r requirements-tested.txt -r requirements-browser-tested.txt -e .
python -m playwright install chromium
python -m handoff_witness.evaluate --repeats 5 --seed 20261105 --out artifacts/evaluation-new
```

Append `--channel chrome` to use installed Chrome. A new directory is required.
The runner creates 40 fresh browser contexts across eight authored scenarios and
five repetitions. Requests are confined to its loopback server. Each repeat has
15 planned targets, for 75 total. Scenario order and callback jitter are seeded.

The manifest is written before launching the browser. It specifies the source
assignment, neutral request paths, control changes, supported trigger channel,
and callback delay. It records hashes of the runner, collector, capture adapter,
and core recorder. This is local predeclaration, not external preregistration.

## Scenarios and oracle

| Scenario | Requests per trial | Assigned source | Mechanism |
|---|---:|---|---|
| Agent direct | 1 | agent | Navigation through the capture adapter |
| Agent redirect, stable control | 3 | agent | Initial request plus two redirects |
| Agent redirect, takeover | 3 | agent | Fixture holds the initial response until simulated human takeover |
| Agent callback, takeover | 2 | agent | Document plus deferred callback released after takeover |
| Unbound agent direct | 1 | agent | Navigation outside the adapter, under an agent marker |
| Simulated human direct | 1 | human | Harness navigation under a human marker |
| Simulated human callback, takeover | 2 | human | Document plus deferred callback after agent takeover |
| Agent worker, takeover | 2 | agent | Document plus worker fetch after simulated human takeover |

“Human” is a fixture label, not an authenticated person. Delayed effects inherit
the fixture's assigned initiating channel by experiment definition. The release
barrier is experiment synchronization, not an additional attributed human input.
This definition does not establish causal attribution for arbitrary page code.

The collector receives the regular protocol transcript, not the manifest or
receiver label. The receiver independently records HTTP arrivals, but the driver,
collector, and receiver share a trusted process. This is measurement separation,
not independent security witnessing. The authored scenarios are known development
cases, not held-out workloads.

## Denominators and failure handling

Both methods use the same captured events. The baseline assigns the current
controller at the observation; the collector propagates supported provenance.
Every planned target stays in the denominator. An unknown assignment means an
event was captured but unresolved. Missing means the target reached the receiver
but no event was captured; it is not silently relabeled unknown.

The runner checks per-trial and final receiver counts. Missing or duplicate
receiver requests, duplicate target observations, unexpected target paths,
driver errors, or omitted trial rows invalidate aggregate metrics. Non-target
browser observations and receiver paths remain in diagnostic artifacts rather
than quietly disappearing. There is no statistical confidence interval: repeated
authored templates are not independent samples of a browsing population.

For `N` targets, `O` observed events, `K` non-unknown predictions, and `C` correct
predictions, report `O/N`, `K/N`, `C/K` (undefined if `K=0`), and `C/N` separately.
Confusion matrices include agent, human, mixed, unknown, and missing predictions.

## Measured result

The final local run, `artifacts/evaluation-003`, used Chrome 156.0.8078.80,
Playwright 1.64.1, Python 3.14.7, and macOS arm64. All 40 trials passed the
completeness checks. The receiver saw all 75 targets; the page-target collector
observed 70. The first run produced the same aggregate counts.

| Metric | Provenance collector | Current controller |
|---|---:|---:|
| Correct assignments | 45 | 50 |
| Incorrect assignments | 0 | 20 |
| Unknown assignments | 25 | 0 |
| Unobserved requests | 5 | 5 |
| Attribution coverage | 60.0% | 93.3% |
| Accuracy among assignments | 100.0% | 71.4% |
| Correct fraction of all targets | 60.0% | 66.7% |
| False human assignments | 0 | 15 |
| False agent assignments | 0 | 5 |

**This is a tradeoff, not a general superiority result.** The baseline returned
five more correct assignments as well as 20 wrong ones. The provenance collector
left all 15 simulated-human-source targets unknown, plus ten agent-source targets.
The collector creates roots only from agent navigation commands, so it cannot
output a human or mixed label: its 100% accuracy among assignments and zero false
human assignments follow from that design, not from measurement.
The five worker effect requests reached the server but were invisible to the
page-target capture. Repetition demonstrates repeatability on these templates,
not population-level efficacy or novelty.

## Artifacts and paper

Each trial saves the raw CDP capture, receiver rows, collector analysis, signed
provenance evidence, and validity checks. The run root contains the complete
receiver ledger, manifest, per-request scores, aggregate report, and generated
LaTeX table. The table and compact JSON inputs are checked into `paper/results`;
raw captures stay in the ignored artifacts directory.

A regression test recomputes the checked-in report's metrics and LaTeX table from
its saved rows and checks the manifest digest. The manuscript includes this table
and describes the missing worker observations and limited human coverage. The November 6 submission package adds a second-seed repeatability check, a
post-hoc root-only ablation, and a compiled manuscript. See `paper/README.md`
for build commands and the distinction between a prepared preprint and a
validated general-purpose attribution system.
