"""Predeclared v3 attribution workload: lineage, exclusion, adversarial pages, stored state.

Assigned sources follow one fixed convention, written into the manifest before
execution: a request's source is the channel that issued the action, and a
page's autonomous behavior (timers, workers, refreshes, popups, frames) inherits
the channel that loaded that page. Human actions are harness-driven Playwright
calls outside the mediated agent channel; no physical person participates.

The stored group relays agent influence through state that outlives a request
chain. Its effect requests are joint: they occur only if an agent-channel write
and a later human-channel action both occur. Each stored trial is followed by
delivery-only twins (writer removed, reader removed, storage partitioned) that
check this and measure what per-controller storage partitioning blocks.
"""
import argparse
import asyncio
import hashlib
import json
import platform
import random
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
from pathlib import Path
from urllib.parse import urlsplit

from .capture import Capture
from .core import digest
from .lineage import RULES, V1_RULES, V2_RULES, collect

PROTOCOL = 'handoff-witness/attribution-workload/v3'
SOURCE_CONVENTION = ('source = channel that issued the action; autonomous page behavior inherits the channel '
                     'that loaded the page; human = harness-driven calls outside the mediated agent channel; '
                     'stored group: an effect is joint when it occurs only if an agent-channel state write and a later '
                     'human-channel action both occur (checked per trial by counterfactual twins)')
S = lambda name, source, nav, mode, group, takeover=None, hops=0: {
    'name': name, 'source': source, 'navigation': nav, 'mode': mode, 'group': group, 'takeover': takeover, 'hops': hops}
SCENARIOS = [
    S('agent_direct', 'agent', 'agent', 'direct', 'v1'),
    S('agent_redirect_stable', 'agent', 'agent', 'redirect', 'v1', hops=2),
    S('agent_redirect_handoff', 'agent', 'agent', 'redirect', 'v1', 'human', 2),
    S('agent_callback_handoff', 'agent', 'agent', 'callback', 'v1', 'human'),
    S('unbound_agent_direct', 'agent', 'unmediated', 'direct', 'v1'),
    S('simulated_human_direct', 'human', 'unmediated', 'direct', 'v1'),
    S('simulated_human_callback_handoff', 'human', 'unmediated', 'callback', 'v1', 'agent'),
    S('agent_worker_handoff', 'agent', 'agent', 'worker', 'v1', 'human'),
    S('agent_script_callback_handoff', 'agent', 'agent', 'agent_script', 'mediated', 'human'),
    S('agent_click_callback_handoff', 'agent', 'agent', 'agent_click', 'mediated', 'human'),
    S('human_click_on_agent_page', 'human', 'agent', 'human_click', 'mediated', 'human'),
    S('agent_script_on_human_page', 'agent', 'unmediated', 'agent_script_human_page', 'mediated', 'human'),
    S('agent_click_on_human_page', 'agent', 'unmediated', 'agent_click_human_page', 'mediated', 'human'),
    S('adv_meta_refresh_handoff', 'agent', 'agent', 'meta_refresh', 'adversarial', 'human'),
    S('adv_script_navigation_handoff', 'agent', 'agent', 'script_navigation', 'adversarial', 'human'),
    S('adv_form_autosubmit_handoff', 'agent', 'agent', 'form_submit', 'adversarial', 'human'),
    S('adv_popup_handoff', 'agent', 'agent', 'popup', 'adversarial', 'human'),
    S('adv_iframe_fetch_handoff', 'agent', 'agent', 'iframe', 'adversarial', 'human'),
    S('adv_forged_agent_sourceurl', 'human', 'unmediated', 'forged_sourceurl', 'adversarial', 'agent'),
    S('adv_synthetic_input_handoff', 'agent', 'agent', 'synthetic_input', 'adversarial', 'human'),
    # Stored state: phase A writes (navigation channel), control changes, the human then loads h0.
    S('st_storage_relay', 'joint', 'agent', 'st_storage', 'stored', 'human'),
    S('st_storage_late_write', 'joint', 'agent', 'st_storage_late', 'stored', 'human'),
    S('st_cookie_relay', 'joint', 'agent', 'st_cookie', 'stored', 'human'),
    S('st_script_cookie_relay', 'joint', 'agent', 'st_script_cookie', 'stored', 'human'),
    S('st_indexeddb_relay', 'joint', 'agent', 'st_idb', 'stored', 'human'),
    S('st_service_worker_relay', 'joint', 'agent', 'st_sw', 'stored', 'human'),
    S('st_dom_relay', 'joint', 'unmediated', 'st_dom', 'stored', 'human'),
    S('st_server_state_relay', 'joint', 'agent', 'st_server', 'stored', 'human'),
    S('st_server_state_cross_host', 'joint', 'agent', 'st_server_cross', 'stored', 'human'),
    S('st_human_state_control', 'human', 'unmediated', 'st_human_state', 'stored', 'human'),
    S('st_agent_unread_state', 'human', 'agent', 'st_unread', 'stored', 'human'),
    S('st_agent_no_state', 'human', 'agent', 'st_none', 'stored', 'human'),
]
COOKIE_STATE = {'st_cookie', 'st_script_cookie'}
SERVER_STATE = {'st_server', 'st_server_cross'}
ARMS = {'no_writer': 'nw', 'no_reader': 'nr', 'partitioned': 'pt'}
NAVIGATING = {'meta_refresh', 'script_navigation', 'form_submit'}
FIXTURE_FILES = ['workload.py', 'capture.py', 'lineage.py', 'core.py']
_LADDER = [('v1_navigation_redirect', V1_RULES),
           ('plus_document_lineage', V1_RULES | {'document_lineage', 'renderer_navigation'}),
           ('plus_worker', V1_RULES | {'document_lineage', 'renderer_navigation', 'worker'}),
           ('plus_agent_script', V1_RULES | {'document_lineage', 'renderer_navigation', 'worker', 'agent_script'}),
           ('plus_input_taint', set(V2_RULES) - {'exclusion'}),
           ('v02_full', set(V2_RULES)),
           ('plus_service_worker', set(V2_RULES) | {'service_worker'}),
           ('plus_state_write', set(V2_RULES) | {'service_worker', 'state_write'}),
           ('full', set(RULES))]
_LEAVE_ONE_OUT = [('full_without_input_taint', set(RULES) - {'input_taint'}),
                  ('full_without_agent_script', set(RULES) - {'agent_script'}),
                  ('full_without_worker', set(RULES) - {'worker'}),
                  ('full_without_document_lineage', set(RULES) - {'document_lineage', 'renderer_navigation'}),
                  ('full_without_state_write', set(RULES) - {'state_write'}),
                  ('full_without_exclusion', set(RULES) - {'exclusion'})]
VARIANTS = dict(_LADDER + _LEAVE_ONE_OUT)


def plan(repeats=5, seed=20261109):
    if type(repeats) is not int or not 1 <= repeats <= 100:
        raise ValueError('Repeats must be 1–100')
    rng = random.Random(seed)
    trials = []
    for repetition in range(repeats):
        cases = list(SCENARIOS)
        rng.shuffle(cases)
        for case in cases:
            trials.append({**case, 'trial_id': f't{len(trials):04d}', 'repetition': repetition,
                           'callback_delay_ms': rng.choice([0, 5, 20])})
    return {'protocol': PROTOCOL, 'seed': seed, 'repeats': repeats, 'trials': trials,
            'source_convention': SOURCE_CONVENTION,
            'target_source_rule': ('top-level load and redirect hops: navigating channel; other targets: scenario source; '
                                   'stored group: r0 navigating channel, h0 human, effect scenario source'),
            'auxiliary_paths': ('the service worker script fetch (sw.js) is issued by the browser and reaches the collector only '
                                'when attachment wins a race; it is not a scored target and its observation is reported separately'),
            'stored_twins': {'arms': {'no_writer': 'phase A omitted', 'no_reader': 'phase B omitted',
                                      'partitioned': 'one browser context per controlling channel (not applicable to st_dom)'},
                             'expected_effect_deliveries': {s['name']: twin_expectation(s) for s in SCENARIOS if s['group'] == 'stored'},
                             'rule': 'A stored trial is valid only if no_writer and no_reader match; partitioned is a measurement'},
            'implementation_sha256': {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                      for name in FIXTURE_FILES},
            'collector_variants': {k: sorted(v) for k, v in VARIANTS.items()},
            'primary_variant': 'full',
            'scoring': {'correct': ('agent label for agent source; not_agent or human label for human source; '
                                    'mixed or agent label for joint source (the agent contribution is reported)'),
                        'wrong': 'any other agent/not_agent/human label; for joint source, not_agent or human (false exoneration)',
                        'contested': 'mixed label on an agent or human source (reported separately, neither correct nor wrong)',
                        'unknown': 'observed but unassigned', 'missing': 'not observed by the collector'},
            'analysis_rule': 'All planned targets; invalid trials invalidate aggregate metrics',
            'population': f'{len(SCENARIOS)} authored templates; repetitions are not independent samples of real-world browsing'}


def twin_expectation(trial):
    """Effect deliveries each counterfactual twin must show for the assigned source to hold."""
    return {'no_writer': 0 if trial['source'] == 'joint' or trial['mode'] == 'st_human_state' else 1, 'no_reader': 0}


def target_source(trial, path):
    """Top-level load (and its redirects) belong to the navigating channel."""
    resource = path.rsplit('/', 1)[-1]
    if trial['group'] == 'stored' and resource == 'h0':
        return 'human'
    if resource.startswith('r'):
        return 'agent' if trial['navigation'] == 'agent' or trial['name'] == 'unbound_agent_direct' else 'human'
    return trial['source']


def expected_paths(trial):
    prefix = '/trial/' + trial['trial_id']
    paths = [prefix + '/r0']
    if trial['group'] == 'stored':
        return paths + ([] if trial['mode'] == 'st_dom' else [prefix + '/h0']) + [prefix + '/effect']
    if trial['mode'] == 'redirect':
        paths += [prefix + '/r' + str(i) for i in range(1, trial['hops'] + 1)]
    elif trial['mode'] == 'iframe':
        paths += [prefix + '/frame', prefix + '/effect']
    elif trial['mode'] != 'direct':
        paths.append(prefix + '/effect')
    return paths


def auxiliary_paths(trial):
    """Requests the trial must cause but that are not scored (see plan()['auxiliary_paths'])."""
    return ['/trial/' + trial['trial_id'] + '/sw.js'] if trial['mode'] == 'st_sw' else []


def label_outcome(label, source):
    if label in {'unknown', 'missing'}:
        return label
    if label not in {'agent', 'human', 'not_agent', 'mixed'}:
        raise ValueError('Invalid label')
    if source == 'joint':
        return 'correct' if label in {'mixed', 'agent'} else 'wrong'
    if label == 'mixed':
        return 'contested'
    return 'correct' if (label == 'agent') == (source == 'agent') else 'wrong'


def metrics(rows, method):
    if not rows or any(not r['trial_valid'] for r in rows):
        raise ValueError('Metrics require a complete, valid workload')
    outcomes = Counter(label_outcome(r[method], r['assigned_source']) for r in rows)
    labels = Counter((r['assigned_source'], r[method]) for r in rows)
    n = len(rows)
    known = outcomes['correct'] + outcomes['wrong']
    return {'total_targets': n, 'correct': outcomes['correct'], 'wrong': outcomes['wrong'],
            'contested': outcomes['contested'], 'unknown': outcomes['unknown'], 'missing': outcomes['missing'],
            'attribution_coverage': known / n, 'conditional_accuracy': outcomes['correct'] / known if known else None,
            'correct_fraction': outcomes['correct'] / n,
            'false_agent': labels[('human', 'agent')],
            'false_not_agent': sum(labels[(s, l)] for s in ('agent', 'joint') for l in ('not_agent', 'human')),
            'confusion': {f'{s}->{l}': c for (s, l), c in sorted(labels.items())}}


def page_html(trial, base):
    target = json.dumps(base + '/trial/' + trial['trial_id'] + '/effect')
    delay = trial['callback_delay_ms']
    done = "document.documentElement.dataset.done='1'"
    mode = trial['mode']
    body, script = '', 'window.fixtureReady=true;'
    if mode == 'callback':
        script = f"window.release=()=>setTimeout(async()=>{{await fetch({target});{done}}},{delay});window.fixtureReady=true;"
    elif mode == 'worker':
        worker = f"postMessage('ready');onmessage=()=>setTimeout(async()=>{{await fetch({target});postMessage('done')}},{delay});"
        script = (f"const w=new Worker(URL.createObjectURL(new Blob([{json.dumps(worker)}],{{type:'text/javascript'}})));"
                  f"w.onmessage=e=>{{if(e.data==='ready')window.fixtureReady=true;else{{{done};w.terminate()}}}};"
                  "window.release=()=>w.postMessage('go');")
    elif mode in {'agent_click', 'agent_click_human_page'}:
        body = "<button id='act' style='position:absolute;left:20px;top:20px;width:120px;height:40px'>Act</button>"
        script = ("let open;const gate=new Promise(r=>open=r);window.release=()=>open();"
                  f"document.getElementById('act').addEventListener('click',()=>gate.then(()=>setTimeout(async()=>{{await fetch({target});{done}}},{delay})));"
                  "window.fixtureReady=true;")
    elif mode == 'human_click':
        body = "<button id='act' style='position:absolute;left:20px;top:20px;width:120px;height:40px'>Act</button>"
        script = (f"document.getElementById('act').addEventListener('click',async()=>{{await fetch({target});{done}}});"
                  "window.release=()=>{};window.fixtureReady=true;")
    elif mode == 'meta_refresh':
        script = ("window.release=()=>{const m=document.createElement('meta');m.httpEquiv='refresh';"
                  f"m.content='0;url='+{target};document.head.append(m)}};window.fixtureReady=true;")
    elif mode == 'script_navigation':
        script = f"window.release=()=>setTimeout(()=>{{location.href={target}}},{delay});window.fixtureReady=true;"
    elif mode == 'form_submit':
        script = (f"window.release=()=>setTimeout(()=>{{const f=document.createElement('form');f.method='GET';f.action={target};"
                  "document.body.append(f);f.submit()},%d);window.fixtureReady=true;" % delay)
    elif mode == 'popup':
        script = f"window.release=()=>{{window.open({target},'_blank');{done}}};window.fixtureReady=true;"
    elif mode == 'iframe':
        frame = json.dumps(base + '/trial/' + trial['trial_id'] + '/frame')
        script = (f"window.release=()=>setTimeout(()=>{{const i=document.createElement('iframe');i.src={frame};"
                  "document.body.append(i)},%d);window.fixtureReady=true;" % delay)
    elif mode == 'forged_sourceurl':
        forged = f"setTimeout(async()=>{{await fetch({target});{done}}},{delay})\n//# sourceURL=hw-agent-{'0' * 32}.js"
        script = f"window.release=()=>(0,eval)({json.dumps(forged)});window.fixtureReady=true;"
    elif mode == 'synthetic_input':
        script = ("window.release=()=>{for(const t of ['pointerdown','keydown'])"
                  "{document.dispatchEvent(new Event(t,{bubbles:true}));window.dispatchEvent(new Event(t))}"
                  f"setTimeout(async()=>{{await fetch({target});{done}}},{delay})}};window.fixtureReady=true;")
    return ("<!doctype html><link rel='icon' href='data:,'><title>Local workload</title><body>" + body +
            "<script>" + script + "</script></body>")


DONE = "document.documentElement.dataset.done='1'"
_PAGE = "<!doctype html><link rel='icon' href='data:,'><title>Local workload</title><body><script>%s</script></body>"


def stored_html(trial, base, resource):
    """Writer (r0) and reader (h0) pages of a stored-state trial."""
    prefix = base + '/trial/' + trial['trial_id']
    target, delay, mode = json.dumps(prefix + '/effect'), trial['callback_delay_ms'], trial['mode']
    ready = 'window.fixtureReady=true;'
    idb = "const o=indexedDB.open('hw',1);o.onupgradeneeded=()=>o.result.createObjectStore('kv');o.onsuccess=()=>{"
    if resource == 'r0':
        script = ready
        if mode in {'st_storage', 'st_human_state'}:
            script = f"localStorage.setItem('hw-next',{target});" + ready
        elif mode == 'st_storage_late':
            script = f"window.release=()=>setTimeout(()=>{{localStorage.setItem('hw-next',{target});{DONE}}},{delay});" + ready
        elif mode == 'st_script_cookie':
            script = "document.cookie='hw=1; path=/';" + ready
        elif mode == 'st_idb':
            script = idb + f"const t=o.result.transaction('kv','readwrite');t.objectStore('kv').put({target},'next');t.oncomplete=()=>{{o.result.close();{ready}}}}};"
        elif mode == 'st_sw':
            script = f"navigator.serviceWorker.register({json.dumps(prefix + '/sw.js')}).then(()=>navigator.serviceWorker.ready).then(()=>{{{ready}}});"
        elif mode == 'st_dom':
            script = (f"window.release=()=>setTimeout(async()=>{{const u=document.documentElement.dataset.hwNext;if(u)await fetch(u);{DONE}}},{delay});" + ready)
        elif mode == 'st_unread':
            script = "localStorage.setItem('hw-other','1');" + ready
    elif mode in {'st_storage', 'st_storage_late', 'st_human_state'}:
        script = f"setTimeout(async()=>{{const u=localStorage.getItem('hw-next');if(u)await fetch(u);{DONE}}},{delay});"
    elif mode == 'st_idb':
        script = (f"setTimeout(()=>{{{idb}const g=o.result.transaction('kv').objectStore('kv').get('next');"
                  f"g.onsuccess=async()=>{{if(g.result)await fetch(g.result);{DONE}}}}}}},{delay});")
    elif mode in {'st_unread', 'st_none'}:
        script = f"setTimeout(async()=>{{await fetch({target});{DONE}}},{delay});"
    else:  # st_sw: the worker, not the page, issues the effect
        script = f"setTimeout(()=>{{{DONE}}},{delay});"
    return _PAGE % script


def service_worker_js(trial, base):
    target = json.dumps(base + '/trial/' + trial['trial_id'] + '/effect')
    return ("self.addEventListener('install',()=>self.skipWaiting());self.addEventListener('fetch',e=>{"
            f"if(new URL(e.request.url).pathname.endsWith('/h0'))e.waitUntil(fetch({target}))}});")


class WorkloadFixture:
    def __init__(self, trials):
        self.trials = {trial['trial_id']: trial for trial in trials}
        for trial in trials:  # delivery-only twins of stored trials
            if trial['group'] == 'stored':
                for suffix in ARMS.values():
                    twin = trial['trial_id'] + '-' + suffix
                    self.trials[twin] = {**trial, 'trial_id': twin}
        self.flags = set()
        self.ledger = []
        self.arrived = {t: threading.Event() for t in self.trials}
        self.release = {t: threading.Event() for t in self.trials}
        self.lock = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def send(self, status, data=b'', content_type='text/html', extra=()):
                self.send_response(status)
                self.send_header('Content-Type', content_type)
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Length', str(len(data)))
                for name, value in extra:
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                path = urlsplit(self.path).path
                parts = path.split('/')
                with owner.lock:
                    owner.ledger.append({'path': path, 'method': 'GET', 'monotonic_ns': time.monotonic_ns()})
                if len(parts) != 4 or parts[1] != 'trial' or parts[2] not in owner.trials:
                    return self.send(404)
                trial_id, resource = parts[2:]
                trial = owner.trials[trial_id]
                if trial['group'] == 'stored':
                    return self.stored(trial, trial_id, resource)
                if trial['mode'] == 'redirect' and resource.startswith('r') and int(resource[1:]) < trial['hops']:
                    if resource == 'r0':
                        owner.arrived[trial_id].set()
                        if not owner.release[trial_id].wait(10):
                            return self.send(504)
                    return self.send(302, extra=[('Location', '/trial/' + trial_id + '/r' + str(int(resource[1:]) + 1))])
                done = "<script>document.documentElement.dataset.done='1'</script>"
                if resource == 'r0':
                    data = page_html(trial, owner.base)
                elif resource == 'frame':
                    data = (f"<!doctype html><script>fetch({json.dumps(owner.base + '/trial/' + trial_id + '/effect')})"
                            ".then(()=>parent.document.documentElement.dataset.done='1')</script>")
                elif resource == 'effect' and trial['mode'] in NAVIGATING | {'popup'}:
                    data = "<!doctype html><link rel='icon' href='data:,'><title>effect</title>" + done
                else:
                    return self.send(200, b'ok', 'text/plain')
                self.send(200, data.encode())

            def stored(self, trial, trial_id, resource):
                mode, done_page = trial['mode'], (_PAGE % (DONE + ';')).encode()
                if resource == 'r0':
                    if mode in SERVER_STATE:
                        with owner.lock:
                            owner.flags.add(trial_id)
                    extra = [('Set-Cookie', 'hw=1; Path=/; HttpOnly')] if mode == 'st_cookie' else []
                    return self.send(200, stored_html(trial, owner.base, 'r0').encode(), extra=extra)
                if resource == 'sw.js' and mode == 'st_sw':
                    return self.send(200, service_worker_js(trial, owner.base).encode(), 'text/javascript')
                if resource == 'h0' and mode != 'st_dom':
                    if mode in COOKIE_STATE:
                        relay = any(part.strip() == 'hw=1' for part in (self.headers.get('Cookie') or '').split(';'))
                    elif mode in SERVER_STATE:
                        with owner.lock:
                            relay = trial_id in owner.flags
                    else:
                        return self.send(200, stored_html(trial, owner.base, 'h0').encode())
                    if relay:  # relative Location: the effect stays on the host that served h0
                        return self.send(302, extra=[('Location', '/trial/' + trial_id + '/effect')])
                    return self.send(200, done_page)
                if resource == 'effect':
                    if mode in COOKIE_STATE | SERVER_STATE:
                        return self.send(200, done_page)
                    return self.send(200, b'ok', 'text/plain')
                self.send(404)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.base = f'http://127.0.0.1:{self.server.server_port}'
        self.alt = f'http://localhost:{self.server.server_port}'  # same server, different host name
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        for release in self.release.values():
            release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def effect_count(self, trial_id):
        with self.lock:
            return sum(r['path'] == '/trial/' + trial_id + '/effect' for r in self.ledger)


async def drive(page, capture, fixture, trial, target, session):
    """Harness actions for one trial. Barriers release page work only after control changed."""
    first_observed = asyncio.Event()
    def observed(params):
        if params.get('request', {}).get('url') == target:
            first_observed.set()
    session.on('Network.requestWillBeSent', observed)
    navigation = None
    try:
        if trial['mode'] == 'redirect':
            navigation = asyncio.create_task(capture.navigate(target))
            received = await asyncio.wait_for(asyncio.to_thread(fixture.arrived[trial['trial_id']].wait, 8), 9)
            if not received:
                raise RuntimeError('Initial redirect request never reached receiver')
            await asyncio.wait_for(first_observed.wait(), 5)
            if trial['takeover']:
                capture.handoff(trial['takeover'])
            fixture.release[trial['trial_id']].set()
            await asyncio.wait_for(navigation, 10)
            return
        if trial['navigation'] == 'agent':
            await asyncio.wait_for(capture.navigate(target), 10)
        else:
            await page.goto(target, timeout=10000)  # Unmediated channel (simulated human or bypass).
        await page.wait_for_function('window.fixtureReady === true', timeout=10000)
        mode = trial['mode']
        if mode == 'direct':
            return
        if mode in {'agent_script_human_page', 'agent_click_human_page'}:
            capture.handoff('agent')  # Agent assists on a page the human loaded.
        if mode in {'agent_script', 'agent_script_human_page'}:
            script = (f"new Promise(r=>document.addEventListener('hw-release',r,{{once:true}})).then(()=>setTimeout(async()=>"
                      f"{{await fetch({json.dumps(fixture.base + '/trial/' + trial['trial_id'] + '/effect')});"
                      f"document.documentElement.dataset.done='1'}},{trial['callback_delay_ms']}));0")
            await capture.evaluate_isolated(script)
        elif mode in {'agent_click', 'agent_click_human_page'}:
            box = await page.locator('#act').bounding_box()
            await capture.click(box['x'] + box['width'] / 2, box['y'] + box['height'] / 2)
        capture.handoff(trial['takeover'])
        if mode == 'human_click':
            await page.click('#act')  # Unmediated trusted input after takeover.
        elif mode in {'agent_script', 'agent_script_human_page'}:
            await page.evaluate("document.dispatchEvent(new Event('hw-release'))")
        else:
            # Fixture barrier, not an attributed action: release only after the
            # initiating document exists and the control marker has changed.
            await page.evaluate('window.release()')
        if mode in NAVIGATING:
            await page.wait_for_url('**/effect*', timeout=10000)
        await page.wait_for_function("document.documentElement.dataset.done === '1'", timeout=10000)
        if mode == 'popup':
            await asyncio.sleep(0.5)
    finally:
        if navigation is not None and not navigation.done():
            navigation.cancel()
            await asyncio.gather(navigation, return_exceptions=True)
        session.remove_listener('Network.requestWillBeSent', observed)


_READY, _DONE = 'window.fixtureReady === true', "document.documentElement.dataset.done === '1'"


async def drive_stored(page, capture, fixture, trial):
    """Phase A writes state, control changes, then the human channel acts (phase B)."""
    mode = trial['mode']
    url = lambda name, base=fixture.base: base + '/trial/' + trial['trial_id'] + '/' + name
    if trial['navigation'] == 'agent':
        await asyncio.wait_for(capture.navigate(url('r0')), 10)
    else:
        await page.goto(url('r0'), timeout=10000)
    await page.wait_for_function(_READY, timeout=10000)
    if mode == 'st_dom':  # agent assists on the human's page, then the page's own code reads what it left
        capture.handoff('agent')
        await capture.evaluate_isolated(f"document.documentElement.dataset.hwNext={json.dumps(url('effect'))};0")
        capture.handoff('human')
        await page.evaluate('window.release()')
        await page.wait_for_function(_DONE, timeout=10000)
        return
    if mode == 'st_human_state':
        capture.handoff('agent')  # the agent holds control and does nothing
    capture.handoff('human')
    if mode == 'st_storage_late':  # the agent-loaded page writes only after the human took over
        await page.evaluate('window.release()')
        await page.wait_for_function(_DONE, timeout=10000)
    await page.goto(url('h0', fixture.alt if mode == 'st_server_cross' else fixture.base), timeout=10000)
    await page.wait_for_function(_DONE, timeout=10000)
    if mode == 'st_sw':
        for _ in range(150):
            if fixture.effect_count(trial['trial_id']):
                break
            await asyncio.sleep(0.02)


async def run_arm(browser, fixture, trial, arm):
    """Delivery-only twin: plain browser actions, no capture. Returns effect deliveries (None if not applicable)."""
    mode = trial['mode']
    if arm == 'partitioned' and mode == 'st_dom':
        return None  # the state is the document itself
    twin = {**trial, 'trial_id': trial['trial_id'] + '-' + ARMS[arm]}
    url = lambda name, base=fixture.base: base + '/trial/' + twin['trial_id'] + '/' + name
    contexts = [await browser.new_context(service_workers='allow')]
    try:
        page = await contexts[0].new_page()
        if mode == 'st_dom':
            await page.goto(url('r0'), timeout=10000)
            await page.wait_for_function(_READY, timeout=10000)
            if arm != 'no_writer':
                await page.evaluate(f"document.documentElement.dataset.hwNext={json.dumps(url('effect'))};0")
            if arm != 'no_reader':
                await page.evaluate('window.release()')
                await page.wait_for_function(_DONE, timeout=10000)
        else:
            if arm != 'no_writer':
                await page.goto(url('r0'), timeout=10000)
                await page.wait_for_function(_READY, timeout=10000)
                if mode == 'st_storage_late':
                    await page.evaluate('window.release()')
                    await page.wait_for_function(_DONE, timeout=10000)
            if arm != 'no_reader':
                if arm == 'partitioned' and trial['navigation'] == 'agent':  # one storage partition per controller
                    contexts.append(await browser.new_context(service_workers='allow'))
                    page = await contexts[-1].new_page()
                await page.goto(url('h0', fixture.alt if mode == 'st_server_cross' else fixture.base), timeout=10000)
                await page.wait_for_function(_DONE, timeout=10000)
        await asyncio.sleep(0.3)  # absence is judged after the reader finished plus this margin
    finally:
        for context in contexts:
            await context.close()
    return fixture.effect_count(twin['trial_id'])


def score_trial(trial, analyses, ledger):
    paths = expected_paths(trial)
    full = analyses['full']
    observed = {}
    for request in full['requests']:
        observed.setdefault(urlsplit(request['url']).path, []).append(request)
    received = Counter(r['path'] for r in ledger)
    auxiliary = auxiliary_paths(trial)
    extra = sorted(p for p in set(observed) | set(received)
                   if p.startswith('/trial/' + trial['trial_id'] + '/') and p not in paths and p not in auxiliary)
    # A service worker script may be fetched again by the browser's update check.
    valid = (not extra and all(received[p] == 1 and len(observed.get(p, [])) <= 1 for p in paths)
             and all(received[p] >= 1 for p in auxiliary))
    by_variant = {}
    for variant, analysis in analyses.items():
        index = {}
        for request in analysis['requests']:
            index.setdefault(urlsplit(request['url']).path, []).append(request)
        by_variant[variant] = index
    rows = []
    for path in paths:
        matches = observed.get(path, [])
        request = matches[0] if len(matches) == 1 else None
        row = {'trial_id': trial['trial_id'], 'scenario': trial['name'], 'group': trial['group'], 'path': path,
               'assigned_source': target_source(trial, path), 'receiver_count': received[path],
               'browser_observation_count': len(matches), 'trial_valid': valid,
               'current_controller': request['controller_at_dispatch'] if request else 'missing',
               'collector_reason': request['reason'] if request else 'not_observed',
               'state_taint': request.get('state_taint') if request else None,
               'observer_session': request['observer_session'] if request else None}
        for variant, index in by_variant.items():
            found = index.get(path, [])
            row[variant] = found[0]['attribution'] if len(found) == 1 else 'missing'
        rows.append(row)
    return rows, {'valid': valid, 'unexpected_target_paths': extra,
                  'auxiliary': {p.rsplit('/', 1)[-1]: sorted(r['attribution'] for r in observed.get(p, [])) for p in auxiliary}}


async def run_trial(browser, fixture, trial, directory):
    directory.mkdir()
    context = await browser.new_context(service_workers='allow')
    blocked = []
    async def local_only(route):
        if route.request.url.startswith((fixture.base + '/', fixture.alt + '/')):
            await route.continue_()
        else:
            blocked.append(route.request.url)
            await route.abort()
    await context.route('**/*', local_only)
    page = await context.new_page()
    session = await context.new_cdp_session(page)
    capture = await Capture(session, lineage=True).start()
    capture.handoff('agent' if trial['navigation'] == 'agent' or trial['name'] == 'unbound_agent_direct' else 'human')
    target = fixture.base + expected_paths(trial)[0]
    error = None
    started = time.perf_counter()
    try:
        if trial['group'] == 'stored':
            await drive_stored(page, capture, fixture, trial)
        else:
            await drive(page, capture, fixture, trial, target, session)
        await session.send('Runtime.evaluate', {'expression': '0'})
        await asyncio.sleep(0.05)
    except Exception as exc:
        error = type(exc).__name__ + ': ' + str(exc)
    finally:
        fixture.release[trial['trial_id']].set()
        await capture.drain()
        trace = capture.stop()
        await context.close()
    elapsed = time.perf_counter() - started
    prefix = '/trial/' + trial['trial_id'] + '/'
    with fixture.lock:
        ledger = [dict(row) for row in fixture.ledger if row['path'].startswith(prefix)]
    (directory / 'capture.json').write_text(json.dumps(trace, indent=2) + '\n')
    (directory / 'receiver.json').write_text(json.dumps(ledger, indent=2) + '\n')
    analyses = {}
    for variant, rules in VARIANTS.items():
        recorder, analysis = collect(trace, rules)
        analyses[variant] = analysis
        if variant == 'full':
            recorder.save(directory / 'provenance')
            (directory / 'analysis.json').write_text(json.dumps(analysis, indent=2) + '\n')
    rows, check = score_trial(trial, analyses, ledger)
    check.update(error=error, blocked_nonlocal_urls=blocked, wall_seconds=elapsed)
    if trial['group'] == 'stored':
        arms = {}
        for arm in ARMS:
            try:
                arms[arm] = await run_arm(browser, fixture, trial, arm)
            except Exception as exc:
                arms[arm] = type(exc).__name__ + ': ' + str(exc)
        expected = twin_expectation(trial)
        check.update(arms=arms, arms_expected=expected, twins_consistent=all(arms[a] == n for a, n in expected.items()))
        (directory / 'arms.json').write_text(json.dumps(arms, indent=2) + '\n')
        error = error or (None if check['twins_consistent'] and isinstance(arms['partitioned'], (int, type(None)))
                          else 'Counterfactual twins do not support the assigned source')
        check['error'] = error
    if error or blocked:
        check['valid'] = False
        for row in rows:
            row['trial_valid'] = False
    (directory / 'check.json').write_text(json.dumps(check, indent=2) + '\n')
    return rows, check


METHODS = ['current_controller', *VARIANTS]


def arm_counts(manifest, ledger):
    """Effect deliveries per stored trial and twin arm, recomputed from the receiver ledger."""
    received = Counter(r['path'] for r in ledger)
    out = {}
    for trial in manifest['trials']:
        if trial['group'] == 'stored':
            out[trial['trial_id']] = {arm: None if arm == 'partitioned' and trial['mode'] == 'st_dom' else
                                      received['/trial/' + trial['trial_id'] + '-' + suffix + '/effect'] for arm, suffix in ARMS.items()}
    return out


def summarize_arms(manifest, ledger):
    counts, out = arm_counts(manifest, ledger), {}
    for trial in manifest['trials']:
        if trial['group'] == 'stored':
            entry = out.setdefault(trial['name'], {'trials': 0, **{arm: 0 for arm in ARMS}})
            entry['trials'] += 1
            for arm in ARMS:
                value = counts[trial['trial_id']][arm]
                entry[arm] = None if value is None else entry[arm] + value
    return out


def summarize(manifest, rows, checks, browser_version, ledger, *, playwright_version=None):
    expected = Counter((t['trial_id'], p) for t in manifest['trials'] for p in expected_paths(t))
    observed = Counter((r['trial_id'], r['path']) for r in rows)
    planned = Counter(p for _, p in expected.elements())
    twins = {'/trial/' + t['trial_id'] + '-' + suffix + '/' for t in manifest['trials'] if t['group'] == 'stored' for suffix in ARMS.values()}
    unscored = {p for t in manifest['trials'] for p in auxiliary_paths(t)}
    receiver = Counter(r['path'] for r in ledger if r['path'].startswith('/trial/') and r['path'] not in unscored
                       and r['path'].rsplit('/', 1)[0] + '/' not in twins)
    auxiliary = Counter()
    for check in checks:
        for name, found in check.get('auxiliary', {}).items():
            auxiliary[name + ':trials'] += 1
            auxiliary[name + ':observed'] += bool(found)
            for label in found:
                auxiliary[name + ':' + label] += 1
    arms = arm_counts(manifest, ledger)
    twins_ok = all(arms[t['trial_id']][arm] == n for t in manifest['trials'] if t['group'] == 'stored'
                   for arm, n in twin_expectation(t).items())
    valid = (len(checks) == len(manifest['trials']) and all(c['valid'] for c in checks)
             and expected == observed and receiver == planned and twins_ok)
    groups = sorted({s['group'] for s in SCENARIOS})
    return {'kind': 'controlled_attribution_evaluation', 'protocol': PROTOCOL, 'manifest_sha256': digest(manifest),
            'browser_version': browser_version, 'playwright_version': playwright_version,
            'python_version': platform.python_version(), 'platform': platform.platform(),
            'trial_count': len(checks), 'target_count': len(rows), 'valid_for_analysis': valid,
            'failed_trials': [c for c in checks if not c['valid']][:5],
            'metrics': {m: metrics(rows, m) for m in METHODS} if valid else None,
            'by_group': {g: {m: metrics([r for r in rows if r['group'] == g], m) for m in METHODS} for g in groups} if valid else None,
            'by_scenario': {s['name']: {m: metrics([r for r in rows if r['scenario'] == s['name']], m) for m in METHODS}
                            for s in SCENARIOS} if valid else None,
            'stored_arms': summarize_arms(manifest, ledger),
            'auxiliary_observations': dict(sorted(auxiliary.items())),
            'limitations': [f'{len(SCENARIOS)} authored templates, not representative or held-out browsing.',
                            'Human actions are harness-driven Playwright calls outside the mediated channel; no physical input.',
                            'Assigned sources follow the predeclared convention; autonomous page behavior inherits the loading channel.',
                            'Receiver, driver, and collector share a process; labels are withheld from collector input only.',
                            'Exclusion (not_agent) is sound only under complete mediation; unbound_agent_direct tests a bypass.',
                            'Joint sources are established by delivery-only twins of each stored trial, run after it without capture.',
                            'State rules track agent-written state only; an agent label does not exclude human-written state.',
                            'Variants up to v02_full are the v0.2 rules over v0.3 captures, which also record service worker requests.']}


async def run(out, *, repeats=5, seed=20261109, channel=None):
    from playwright.async_api import async_playwright
    manifest = plan(repeats, seed)
    directory = Path(out)
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    rows, checks = [], []
    with WorkloadFixture(manifest['trials']) as fixture:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True, **({'channel': channel} if channel else {}))
            try:
                for index, trial in enumerate(manifest['trials']):
                    trial_rows, check = await run_trial(browser, fixture, trial, directory / trial['trial_id'])
                    rows.extend(trial_rows)
                    checks.append(check)
                    if (index + 1) % len(SCENARIOS) == 0:
                        print(json.dumps({'completed_trials': index + 1, 'planned_trials': len(manifest['trials'])}), flush=True)
            finally:
                await browser.close()
        ledger = list(fixture.ledger)
        report = summarize(manifest, rows, checks, browser.version, ledger, playwright_version=version('playwright'))
    (directory / 'receiver.json').write_text(json.dumps(ledger, indent=2) + '\n')
    (directory / 'rows.json').write_text(json.dumps(rows, indent=2) + '\n')
    (directory / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True)
    parser.add_argument('--repeats', type=int, default=5)
    parser.add_argument('--seed', type=int, default=20261109)
    parser.add_argument('--channel', choices=['chrome', 'chromium'])
    args = parser.parse_args()
    report = asyncio.run(run(args.out, repeats=args.repeats, seed=args.seed, channel=args.channel))
    print(json.dumps({k: report[k] for k in ('valid_for_analysis', 'trial_count', 'target_count', 'failed_trials')}, indent=2))
    if report['valid_for_analysis']:
        for method, m in report['metrics'].items():
            print(method, {k: m[k] for k in ('correct', 'wrong', 'contested', 'unknown', 'missing')})
    raise SystemExit(0 if report['valid_for_analysis'] else 1)


if __name__ == '__main__':
    main()
