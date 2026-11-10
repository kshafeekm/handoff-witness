# CDP collector: bounded attribution, explicit unknowns

## v0.3 state rules

Three rules follow agent influence through stored state. They only add agent
roots: they can turn `not_agent` into `mixed`, never produce `not_agent`, and
never resolve `unknown`.

| Rule | Trigger | Effect | Blind to |
|---|---|---|---|
| `service_worker` | Request from a service-worker session | Inherits the document current when a worker for that script first attached | The fetch that woke the worker, so the person's part is unreported |
| `state_write` | Agent-rooted lineage set a cookie, wrote web storage, registered a service worker, or ran an injected script in a document | Agent roots for what answers a request carrying that cookie, for documents of that origin, or for that document | IndexedDB, Cache API, server state, reads |
| `state_host` | Agent-rooted lineage contacted a host | Agent roots for every later document on, and response from, that host name | State shared across host names; contests human-only activity on the host |

Details that matter when reading labels:

- A request is not tainted by a cookie it carries, because the browser attaches
  cookies to every request for the domain. What answers it is tainted.
- A carried cookie that no observed response set (`document.cookie` raises no
  event, or the cookie predates capture) is charged to every document seen in
  its domain.
- Taint is monotone within a session and transitive through responses and the
  cookies they set.
- Host taint is by host name, not registrable domain. The cookie rule ignores
  paths and credits an overwritten cookie to its observed setter.
- Human-written state is not tracked, so `agent` does not exclude a
  human-written dependency.

`Capture(session, lineage=True)` records the state events these rules need,
reduced before anything is stored: cookie name, domain and path for each
request (`Network.requestWillBeSentExtraInfo`), name and domain of each cookie
a response sets (`Network.responseReceivedExtraInfo`), and the origin of each
web-storage write (`DOMStorage` events). Cookie and storage values, storage
keys and headers are dropped. `RULES` is `V2_RULES + STATE_RULES`; pass
`V2_RULES` to reproduce the v0.2 collector on a v0.3 capture.

## v0.2 lineage mode

`Capture(session, lineage=True)` turns the adapter into the mediated agent
channel and observer: `navigate(url)`, `click(x, y)` (Input.dispatchMouseEvent),
and `evaluate_isolated(script)` (fresh isolated world, unguessable
`//# sourceURL=hw-agent-<128-bit>.js`) are recorded agent commands. It also
records frame and renderer-navigation events, worker sessions
(non-flattened auto-attach), async initiator stacks (depth 32), and `isTrusted`
pointer/key events from an isolated-world observer. Analyze with
`handoff_witness.lineage.collect(trace, rules)`; `RULES` lists the switchable
rules and `V1_RULES` reproduces the v0.1 rule set. Labels are `agent`,
`not_agent` (exclusion; requires complete mediation and state isolation),
`mixed`, and `unknown`.

## v0.1 collector

This collector consumes Chrome DevTools Protocol (CDP) messages and harness
control markers. It replaces fixture correlation tokens for a narrow request
class: agent-issued navigations and observed redirects. It does not solve
arbitrary callback attribution or authenticate physical human input.

## Reproduce

```sh
handoff-witness import-cdp examples/cdp-handoff.json --out artifacts/cdp
handoff-witness verify artifacts/cdp/events.jsonl \
  --trusted-key artifacts/cdp/recorder-public.pem \
  --checkpoint artifacts/cdp/checkpoint.json
```

The example is synthetic, not a recorded browser session. It contains an agent
navigation, human takeover, redirect, late navigation reply, and script fetch.
Expected labels: agent, agent, unknown. Importing makes no HTTP requests.
Signing imported data authenticates its interpretation, not its physical origin.

## Opt-in capture API

The application supplies an existing Playwright-compatible CDP session. This
library never automatically attaches to a personal browser.

```python
from handoff_witness.capture import Capture
from handoff_witness.cdp import collect

# context/page belong to a controlled test harness, not a personal profile.
session = await context.new_cdp_session(page)
capture = await Capture(session).start()
await capture.navigate("http://127.0.0.1:8765/")
capture.handoff("human")  # Harness assertion, not proof of physical input.
# Observe a bounded controlled experiment, then stop.
trace = capture.stop()
capture.save("artifacts/capture.json")
recorder, analysis = collect(trace)
recorder.save("artifacts/capture-evidence")
```

Playwright is optional, not required for import or unit tests. Adapter tests cover
events arriving before command replies. A controlled live Chrome run now also
validates the adapter and importer together. See [live validation](LIVE_VALIDATION.md).
The original web demo remains a separate token-based fixture experiment.

## Binding rules

1. Only captured `Page.navigate` commands during agent control can establish agent
   input roots. Commands are not labeled human simply because human control is active.
2. A successful reply must provide frame and loader IDs. Errors, downloads,
   missing responses, and same-document navigation do not create bindings.
3. A document GET must match session, frame, loader, URL (ignoring fragment),
   and ordering. Each binding is consumed once; ambiguous matches are unknown.
4. Redirect ancestry requires a prior request and a matching CDP redirect
   response with consistent session, request ID, frame, and loader.
5. Script stacks, similar URLs, page headers, timing, and current control never
   establish an initiating actor by themselves. Unsupported origins stay unknown.

Replies are pre-indexed because network events can precede command responses.
Control changes are still applied in capture order. No wall-clock proof is claimed.

## Evidence limits

`browser_request_observed` means CDP emitted `requestWillBeSent`, not that bytes
reached a remote server. Cache, service workers, or cancellation may intervene.
Authorization remains unevaluated. The legacy `controller_at_dispatch` output
field means current control at observation, not certified network-send time.

Each signed parent effect commits to the source envelope digest and the binding
reason. A signed import manifest commits to the complete input trace digest.
`analysis.json` is an unsigned convenience report. Input trace custody,
transport integrity, collector integrity, and independently retained checkpoints
remain assumptions. Imported files can be forged; signatures do not fix that.

One adapter observes one attached target. Other tabs, workers, out-of-process
iframes, browser restarts, and concurrent input need additional coverage. The
adapter refuses agent navigations during human control but cannot stop alternate
automation outside it. Raw traces can include sensitive URLs and headers: use
synthetic local sites only.

Protocol sources: [Network](https://chromedevtools.github.io/devtools-protocol/tot/Network/)
and [Page.navigate](https://chromedevtools.github.io/devtools-protocol/tot/Page/).
Pin Chromium and record its version for future empirical runs.
