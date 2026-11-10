# Preprint and submission package (version 0.3)

Title: **Who Caused the Access? Evidence Boundaries in Human-Agent Browser Handoffs**

Author: **Shafeek Kakkidumban Manayil**, Independent Researcher.
License: CC BY 4.0 for the manuscript; MIT for software.

A bounded systems research note. It does not identify physical people, assign
legal responsibility, or decide which sites are permitted. Related work and the
claimed scope are in Section 3 of the paper. The paper claims a measurement and
a set of rules, not priority: the prior-art search for stored state was a short
keyword search, and the paper says so.

## What changed in 0.3

- **A corrected guarantee.** Version 0.2 said a `not_agent` label was sound
  under complete mediation. It also needs *state isolation*: no agent-written
  state reachable when the request is made. A handoff breaks that on purpose,
  because the cookies, storage, workers and server session a person inherits
  are how they continue the agent's work.
- **Stored-state workload** (`handoff_witness/workload.py`, protocol v3): twelve
  new templates. Nine relay an agent-phase write to a request the person's page
  issues (localStorage, a late storage write, header and script cookies,
  IndexedDB, a service worker, the DOM of a human-loaded page, server state on
  the same host and across hosts); three are human-only controls. 32 templates,
  160 trials and 375 targets per run. Primary seed 20261109, replication 20261110.
- **Counterfactual twins.** Every stored trial is re-run without the agent
  phase, without the human phase, and with one storage partition per
  controller. A relay counts only if the effect needs both phases.
- **State rules** (`handoff_witness/lineage.py`): service-worker lineage, taint
  from observed state writes, and host taint. They only add agent roots, so
  they can turn `not_agent` into `mixed` and never the reverse.
- **Capture** (`handoff_witness/capture.py`): names and domains of cookies sent
  and set, and the origin of web-storage writes. Values, keys and headers are
  dropped before recording.

Version 0.2 changes (lineage collector, 20-template workload, broker and
verifier fixes, counterbalanced pilot) are described in the paper's change log.

## Results

| Method (375 targets) | Correct | Wrong | Contested | Unknown | Missing |
|---|---:|---:|---:|---:|---:|
| Current controller | 245 | 125 | 0 | 0 | 5 |
| v0.1 rules | 140 | 0 | 0 | 230 | 5 |
| Request lineage (v0.2 collector) | 310 | 45 | 10 | 5 | 5 |
| + observed state writes | 335 | 20 | 15 | 0 | 5 |
| + host taint (v0.3 collector) | 340 | 10 | 20 | 0 | 5 |
| v0.3 collector without exclusion | 200 | 0 | 5 | 165 | 5 |

On the 45 relay effects, each of which needs both parties:

| Collector | Reported `not_agent` (wrong) | Human-only controls contested (of 15) |
|---|---:|---:|
| Request lineage (v0.2) | 40 | 0 |
| + observed state writes | 15 | 5 |
| + host taint (v0.3) | 5 | 10 |

The five that remain are server state shared across host names, which no
browser-side observer sees. One storage partition per controller blocks all six
client-state relays (30 of 30 trials) and neither server-state relay (10 of 10
deliver); it also blocks legitimate continuity, since the header-cookie relay
is mechanically a sign-in. The other five wrong labels are the mediation-bypass
template; contested labels are cross-channel input and two stored-state
controls; missing targets are popups. On the 20 templates of version 0.2 every
label matches that release (180 of 200). The replication run is identical.

Pilot (unchanged): for Qwen3-1.7B, indirect pressure raises restricted choices
by 18.1 points [10.4, 26.4], all of it when the restricted option is labeled A
(45/72 vs 0/72); the gate delivers 0 of 486 restricted and 310 of 310 public
proposals.

## Build

From the repository root:

```sh
python paper/analyze.py
python paper/analyze_steering.py --source artifacts/steering-v2-20261109 --browser artifacts/steering-browser-v2-20261109
mkdir -p output/pdf
tectonic --keep-logs --keep-intermediates --outdir output/pdf paper/main.tex
python paper/package.py
python paper/check_package.py --compile
```

`check_package.py` verifies every archive member and checksum in a temporary
extraction, regenerates the seven result files, re-collects both attribution runs
with all fifteen collector variants and recounts the twin deliveries, verifies the 1,152 pilot transcripts and the
execution fault run, runs the test suite, and rebuilds the arXiv source. It
does not download models, run inference, launch a browser, or publish.

## Package outputs

- `output/pdf/handoff-witness-paper.pdf`
- `output/submission/arxiv-source.zip` (TeX, bibliography, `.bbl`, five result
  tables, and the code/data ZIP under `anc/`)
- `output/submission/handoff-witness-artifact.zip` (code, tests, docs, paper
  sources, compact results, raw runs: `data/primary`, `data/replication`,
  `data/steering-v2`, `data/steering-browser-v2`, `data/execution-study`)
- `output/submission/arxiv-metadata.txt`, `SHA256SUMS.txt`,
  `package-verification.json`

No private keys, enrollment tokens, approval databases, model weights, or
personal browsing are included. Bundled public keys and checkpoints show
internal consistency only, not independent authenticity or freshness.

## Reproduce from the artifact

```sh
python -m pip install -r requirements-tested.txt -r requirements-browser-tested.txt -e .
python -m pytest -q
python paper/analyze.py
python paper/verify_runs.py data/primary data/replication
python paper/analyze_steering.py
```

Fresh attribution runs: `python -m handoff_witness.workload --channel chrome
--repeats 5 --seed 20261109 --out artifacts/new-run`. Fresh inference needs
Apple Silicon, Python 3.12, and `requirements-model-tested.txt`; copy the
archived `plan.json` and `plan.sha256`, then run `handoff_witness.steering_v2
infer` for model indices 0 and 1 and `handoff_witness.steering_browser`. Report
new runs separately; browser or runtime versions may change results.

## Earlier versions

The v0.1 compact results are in `paper/results/v0.1` (`paper/analyze_v01.py`
recomputes their metrics). The v0.2 compact results are in
`paper/results/v0.2`. The code that produced both is not kept in this
repository's history, so those runs can be recomputed from the compact results
but not re-collected.

## Scope of readiness

The package supports a transparent preprint. It does not certify novelty or
guarantee acceptance. The templates were authored with knowledge of the
collector and human actions are simulated. Twelve stored-state templates show
that the relay exists; they do not show how often real sites do it or how much
of an ordinary session host taint would contest. Stronger claims need
independently designed workloads, server-side evidence, an authenticated input
path, broader target coverage (popups), and external replication. The author should read and understand the
complete manuscript before submitting it. AI assistance is disclosed in the paper.
