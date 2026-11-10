# Research plan

Working title: **Who Caused the Access? Verifiable Request Attribution Across
Human–Agent Browser Handoffs**

Repository name: `handoff-witness`. Status: candidate contribution, novelty not
established. This is not a completed literature review or a patent opinion.

## Hypothesis

Preserving recorded causal provenance across control changes reduces false
attribution of asynchronous requests compared with current-controller and timing
baselines, under explicit collector integrity and coverage assumptions.

## Existing work to compare

| Work | Existing capability / overlap |
|---|---|
| [The Case for Browser Provenance](https://www.usenix.org/legacy/event/tapp09/tech/full_papers/margo/margo_html/) (2009) | Browser causality and lineage |
| [Authenticated Delegation and Authorized AI Agents](https://arxiv.org/abs/2501.09674) (2025) | Human–agent authority delegation |
| [Notarized Agents](https://arxiv.org/abs/2606.04193) (2026 preprint) | Receiver-signed confidential action evidence |
| [The Verifiable Action Card](https://arxiv.org/abs/2609.18411) (2026 preprint) | Trusted approval bound to browser execution |
| [WebMCP-Phalanx](https://arxiv.org/abs/2608.24017) (2026 preprint) | Browser tool ownership, provenance, and lifecycle |
| [Signed Permissions and Action Receipts](https://www.ietf.org/archive/id/draft-izmaylov-agent-permission-receipts-02.html) (2026 draft) | Signed delegation, approval, receipts, and verification |

Candidate distinction: request provenance across mixed-control handoffs,
asynchronous descendants, and attribution disputes. Merely combining signatures,
causal graphs, and handoff logs is not automatically novel. Read full texts and
implementations, inspect their assumptions, and extend citation searches before
making a priority claim. An unused title is not evidence of novelty.

## Milestones

1. **Current:** deterministic provenance engine, signed evidence, verifier,
   controlled local browser fixture, and integrity tests.
   A subsequent CDP importer and opt-in capture adapter support a bounded subset:
   agent navigation bindings and redirect ancestry. Protocol fixtures and adapter
   contract tests pass; live Chrome integration now also passes. Script-origin
   tracking and a protected collector remain open.
   Request-bound credential approval and persistent one-use reservation are now
   separate supporting components. They use established WebAuthn techniques;
   they do not constitute the proposed novel handoff-attribution contribution.
   An opt-in browser context now sends approved requests through a one-shot HTTP
   broker. Receiver-side fixtures validate enforcement on selected browser paths;
   OS isolation and general browser networking coverage remain open.
   A seeded live workload now measures coverage and errors on eight authored
   templates repeated five times. It exposes unobserved worker traffic and
   unknown simulated-human origins; see [evaluation](EVALUATION.md). This is
   development evaluation, not a held-out or independently operated benchmark.
2. **Collector:** implement browser-level observation of initiating channels and
   supported async descendants. Document unsupported cases as unknown. A patched
   browser may be necessary; an extension-only approach needs a feasibility test.
3. **Independent oracle:** test fixture servers and a separate observer establish
   ground truth without feeding their labels into the evaluated collector.
4. **Adversarial evaluation:** fake human labels, forged handoffs, stale epochs,
   stolen correlation tokens, redirects, worker traffic, multi-tab activity,
   crashes, receipt deletion, and control-transfer races.
5. **Reproducibility:** versioned scenarios, multiple browsers/configurations,
   repeated runs, confidence intervals, dependency versions, and raw traces with
   synthetic data only. Separate tuning scenarios from held-out evaluation.
6. **Paper:** report negative results, unknown coverage, threat assumptions, and
   prior-art overlap. Submit only after the proposed method is implemented and
   its claim is supported.

## Baselines and metrics

Baselines: current controller, nearest input by timestamp, ordinary browser
initiator metadata, and signed agent logs. Implement relevant prior systems where
possible; explain incompatible threat models rather than manufacturing comparisons.

Metrics: actor confusion matrix; false human and false agent attribution; unknown
rate; accuracy conditional on coverage; mixed-cause correctness; tamper detection
by attack type; task success; per-request latency; storage cost; and performance
as handoff frequency and async delay increase. Accuracy without coverage can be
misleading, since declaring every request unknown avoids incorrect assertions.

The eight original semantics cases are smoke tests built around supplied causal
edges. The new 40-trial live workload uses controlled fixture source assignments
and receiver checks, but is still not evidence that the collector problem is solved.

## First feasibility gate

Can the collector link a delayed request to a protected initiating channel after
handoff without trusting page-provided labels? If not, narrow the claim, redesign
the collector, or publish a carefully evaluated limitation rather than promise
unconditional proof of human/agent causation.
