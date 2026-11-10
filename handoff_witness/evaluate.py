"""Predeclared, local browser workload for attribution coverage and error analysis.

Human source labels are harness assignments, not authenticated physical input.
No LLM or personal browsing is used; this is an engineering evaluation.
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
from .cdp import collect
from .core import digest

PROTOCOL = 'handoff-witness/attribution-workload/v1'
SCENARIOS = [
    {'name': 'agent_direct', 'source': 'agent', 'mode': 'direct', 'tracked': True, 'takeover': None, 'hops': 0},
    {'name': 'agent_redirect_stable', 'source': 'agent', 'mode': 'redirect', 'tracked': True, 'takeover': None, 'hops': 2},
    {'name': 'agent_redirect_handoff', 'source': 'agent', 'mode': 'redirect', 'tracked': True, 'takeover': 'human', 'hops': 2},
    {'name': 'agent_callback_handoff', 'source': 'agent', 'mode': 'callback', 'tracked': True, 'takeover': 'human', 'hops': 0},
    {'name': 'unbound_agent_direct', 'source': 'agent', 'mode': 'direct', 'tracked': False, 'takeover': None, 'hops': 0},
    {'name': 'simulated_human_direct', 'source': 'human', 'mode': 'direct', 'tracked': False, 'takeover': None, 'hops': 0},
    {'name': 'simulated_human_callback_handoff', 'source': 'human', 'mode': 'callback', 'tracked': False, 'takeover': 'agent', 'hops': 0},
    {'name': 'agent_worker_handoff', 'source': 'agent', 'mode': 'worker', 'tracked': True, 'takeover': 'human', 'hops': 0},
]


def plan(repeats=5, seed=20261105):
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
            'implementation_sha256': {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                      for name in ['evaluate.py', 'capture.py', 'cdp.py', 'core.py']},
            'label_semantics': 'Assigned initiating fixture channel; human is simulated, not physical input',
            'metrics': ['observation_coverage', 'attribution_coverage', 'conditional_accuracy',
                        'correct_fraction_all_requests', 'false_human_count', 'false_agent_count', 'confusion'],
            'analysis_rule': 'All planned target requests; missing observations are explicit, invalid trials invalidate aggregate metrics',
            'population': 'Eight authored templates; repetitions are not independent samples of real-world browsing'}


def expected_paths(trial):
    prefix = '/trial/' + trial['trial_id']
    paths = [prefix + '/r0']
    if trial['mode'] == 'redirect':
        paths += [prefix + '/r' + str(i) for i in range(1, trial['hops'] + 1)]
    elif trial['mode'] in {'callback', 'worker'}:
        paths.append(prefix + '/effect')
    return paths


def score_trial(trial, analysis, ledger):
    """Join predeclared targets to observations; never give labels to collect()."""
    paths = expected_paths(trial)
    observed = {}
    for request in analysis['requests']:
        observed.setdefault(urlsplit(request['url']).path, []).append(request)
    received = Counter(r['path'] for r in ledger)
    extra = sorted(p for p in set(observed) | set(received) if p.startswith('/trial/' + trial['trial_id'] + '/') and p not in paths)
    valid = not extra and all(received[p] == 1 and len(observed.get(p, [])) <= 1 for p in paths)
    rows = []
    for path in paths:
        matches = observed.get(path, [])
        request = matches[0] if len(matches) == 1 else None
        rows.append({'trial_id': trial['trial_id'], 'scenario': trial['name'], 'path': path,
                     'assigned_source': trial['source'], 'receiver_count': received[path],
                     'browser_observation_count': len(matches), 'trial_valid': valid,
                     'provenance': request['attribution'] if request else 'missing',
                     'current_controller': request['controller_at_dispatch'] if request else 'missing',
                     'collector_reason': request['reason'] if request else 'not_observed'})
    return rows, {'valid': valid, 'unexpected_target_paths': extra,
                  'non_target_observation_paths': sorted(set(observed) - set(paths)),
                  'non_target_receiver_paths': sorted(set(received) - set(paths))}


def metrics(rows, method):
    if not rows or any(not r['trial_valid'] for r in rows):
        raise ValueError('Metrics require a complete, valid workload')
    if method not in {'provenance', 'current_controller'}:
        raise ValueError('Unknown method')
    labels = ['agent', 'human', 'mixed', 'unknown', 'missing']
    confusion = {source: {label: 0 for label in labels} for source in ['agent', 'human']}
    for row in rows:
        predicted = row[method]
        if predicted not in labels or row['assigned_source'] not in confusion:
            raise ValueError('Invalid workload label')
        confusion[row['assigned_source']][predicted] += 1
    total = len(rows)
    observed = sum(r['browser_observation_count'] == 1 for r in rows)
    known = sum(r[method] in {'agent', 'human', 'mixed'} for r in rows)
    correct = sum(r[method] == r['assigned_source'] for r in rows)
    return {'total_targets': total, 'observed_targets': observed,
            'known_predictions': known, 'correct_predictions': correct,
            'unknown_predictions': sum(r[method] == 'unknown' for r in rows),
            'missing_predictions': sum(r[method] == 'missing' for r in rows),
            'observation_coverage': observed / total, 'attribution_coverage': known / total,
            'conditional_accuracy': correct / known if known else None,
            'correct_fraction_all_requests': correct / total,
            'false_human_count': confusion['agent']['human'],
            'false_agent_count': confusion['human']['agent'], 'confusion': confusion}


class WorkloadFixture:
    def __init__(self, trials):
        self.trials = {trial['trial_id']: trial for trial in trials}
        self.ledger = []
        self.arrived = {t: threading.Event() for t in self.trials}
        self.release = {t: threading.Event() for t in self.trials}
        self.lock = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                parts = self.path.split('/')
                with owner.lock:
                    owner.ledger.append({'path': self.path, 'method': 'GET', 'monotonic_ns': time.monotonic_ns()})
                if len(parts) != 4 or parts[1] != 'trial' or parts[2] not in owner.trials:
                    self.send_error(404)
                    return
                trial_id, resource = parts[2:]
                trial = owner.trials[trial_id]
                if trial['mode'] == 'redirect' and resource.startswith('r') and int(resource[1:]) < trial['hops']:
                    if resource == 'r0':
                        owner.arrived[trial_id].set()
                        if not owner.release[trial_id].wait(10):
                            self.send_error(504)
                            return
                    self.send_response(302)
                    self.send_header('Location', '/trial/' + trial_id + '/r' + str(int(resource[1:]) + 1))
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                target = owner.base + '/trial/' + trial_id + '/effect'
                script = 'window.fixtureReady=true;'
                if resource == 'r0' and trial['mode'] == 'callback':
                    script = f'''window.release = null;
                    new Promise(resolve => window.release=resolve).then(() => setTimeout(async () => {{
                      await fetch({json.dumps(target)}); window.fixtureDone=true;
                    }}, {trial['callback_delay_ms']})); window.fixtureReady=true;'''
                elif resource == 'r0' and trial['mode'] == 'worker':
                    worker = f'''postMessage('ready'); onmessage=()=>setTimeout(async()=>{{await fetch({json.dumps(target)});postMessage('done')}},{trial['callback_delay_ms']});'''
                    script = f'''const w=new Worker(URL.createObjectURL(new Blob([{json.dumps(worker)}],{{type:'text/javascript'}})));
                    w.onmessage=e=>{{if(e.data==='ready')window.fixtureReady=true;else{{window.fixtureDone=true;w.terminate()}}}};
                    window.release=()=>w.postMessage('go');'''
                data = ("<!doctype html><link rel='icon' href='data:,'><title>Local workload</title><script>" + script + '</script>').encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.base = f'http://127.0.0.1:{self.server.server_port}'
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


async def run_trial(browser, fixture, trial, directory):
    directory.mkdir()
    context = await browser.new_context(service_workers='block')
    blocked = []
    async def local_only(route):
        if route.request.url.startswith(fixture.base + '/'):
            await route.continue_()
        else:
            blocked.append(route.request.url)
            await route.abort()
    await context.route('**/*', local_only)
    page = await context.new_page()
    session = await context.new_cdp_session(page)
    capture = await Capture(session).start()
    capture.handoff(trial['source'])
    target = fixture.base + expected_paths(trial)[0]
    first_observed = asyncio.Event()
    def observed(params):
        if params.get('request', {}).get('url') == target:
            first_observed.set()
    session.on('Network.requestWillBeSent', observed)
    navigation = None
    error = None
    started = time.perf_counter()
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
        elif trial['tracked']:
            await asyncio.wait_for(capture.navigate(target), 10)
        else:
            await page.goto(target, timeout=10000)
        await page.wait_for_function('window.fixtureReady === true', timeout=10000)
        if trial['mode'] in {'callback', 'worker'}:
            capture.handoff(trial['takeover'])
            # Fixture barrier, not an attributed human action: release only after
            # the initiating document/callback exists and the control marker changed.
            await page.evaluate('window.release()')
            await page.wait_for_function('window.fixtureDone === true', timeout=10000)
        await session.send('Runtime.evaluate', {'expression': '0'})
    except Exception as exc:
        error = type(exc).__name__ + ': ' + str(exc)
    finally:
        fixture.release[trial['trial_id']].set()
        if navigation is not None and not navigation.done():
            navigation.cancel()
            await asyncio.gather(navigation, return_exceptions=True)
        trace = capture.stop()
        session.remove_listener('Network.requestWillBeSent', observed)
        await context.close()
    elapsed = time.perf_counter() - started
    prefix = '/trial/' + trial['trial_id'] + '/'
    with fixture.lock:
        ledger = [dict(row) for row in fixture.ledger if row['path'].startswith(prefix)]
    # Save raw observations before analysis. Neither labels nor oracle paths are
    # supplied to the collector; it sees only the standard protocol transcript.
    (directory / 'capture.json').write_text(json.dumps(trace, indent=2) + '\n')
    (directory / 'receiver.json').write_text(json.dumps(ledger, indent=2) + '\n')
    analysis_started = time.perf_counter()
    recorder, analysis = collect(trace)
    analysis_seconds = time.perf_counter() - analysis_started
    recorder.save(directory / 'provenance')
    (directory / 'analysis.json').write_text(json.dumps(analysis, indent=2) + '\n')
    rows, check = score_trial(trial, analysis, ledger)
    check.update(error=error, blocked_nonlocal_urls=blocked, wall_seconds=elapsed, analysis_seconds=analysis_seconds)
    if error or blocked:
        check['valid'] = False
        for row in rows:
            row['trial_valid'] = False
    (directory / 'check.json').write_text(json.dumps(check, indent=2) + '\n')
    return rows, check


def summarize(manifest, rows, checks, browser_version, ledger, *, playwright_version=None):
    expected = Counter((t['trial_id'], p, t['source']) for t in manifest['trials'] for p in expected_paths(t))
    observed = Counter((r['trial_id'], r['path'], r['assigned_source']) for r in rows)
    receiver_counts = Counter(r['path'] for r in ledger if r['path'].startswith('/trial/'))
    planned_counts = Counter(p for _, p, _ in expected.elements())
    valid = len(checks) == len(manifest['trials']) and all(check['valid'] for check in checks) and expected == observed and receiver_counts == planned_counts
    return {'kind': 'controlled_attribution_evaluation', 'protocol': PROTOCOL,
            'manifest_sha256': digest(manifest), 'browser_version': browser_version,
            'playwright_version': playwright_version, 'python_version': platform.python_version(),
            'platform': platform.platform(), 'trial_count': len(checks), 'target_count': len(rows),
            'valid_for_analysis': valid,
            'non_target_receiver_paths': dict(Counter(r['path'] for r in ledger if not r['path'].startswith('/trial/'))),
            'metrics': {method: metrics(rows, method) for method in ['provenance', 'current_controller']} if valid else None,
            'by_scenario': {case['name']: {method: metrics([r for r in rows if r['scenario'] == case['name']], method)
                           for method in ['provenance', 'current_controller']} for case in SCENARIOS} if valid else None,
            'limitations': ['Eight authored templates, not representative or held-out browsing.',
                            'Human labels and handoffs are simulated by a trusted harness; no physical input or LLM tested.',
                            'Delayed callback/worker sources are fixture assignments, not independently secured causal evidence.',
                            'Receiver and driver share a process. Labels are withheld from collector input, not from the trusted experiment operator.',
                            'Repeated templates are not independent population samples; no population confidence interval is inferred.',
                            'This evaluates the observation adapter, not the approval broker or end-to-end legal compliance.']}


async def run(out, *, repeats=5, seed=20261105, channel=None):
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
    if report['valid_for_analysis']:
        (directory / 'results.tex').write_text(latex_results(report))
    return report


def latex_results(report):
    if not report['valid_for_analysis']:
        raise ValueError('Cannot publish metrics for an invalid run')
    lines = [r'\begin{table}[ht]', r'\centering', r'\begin{tabular}{lrrrrr}',
             r'Method & Assigned & Correct & Wrong & Unknown & Unobserved \\', r'\hline']
    for method, label in [('provenance', 'Provenance collector'), ('current_controller', 'Current controller')]:
        m = report['metrics'][method]
        counts = [m['known_predictions'], m['correct_predictions'], m['known_predictions'] - m['correct_predictions'],
                  m['unknown_predictions'], m['missing_predictions']]
        lines.append(label + ' & ' + ' & '.join(str(n) for n in counts) + r' \\')
    lines += [r'\end{tabular}',
              r'\caption{Controlled workload: ' + str(report['target_count']) + ' planned requests across ' + str(report['trial_count']) +
              r' trials. Assigned source labels are fixture-defined; human sources are simulated.}',
              r'\label{tab:attribution}', r'\end{table}']
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True)
    parser.add_argument('--repeats', type=int, default=5)
    parser.add_argument('--seed', type=int, default=20261105)
    parser.add_argument('--channel', choices=['chrome', 'chromium'])
    args = parser.parse_args()
    report = asyncio.run(run(args.out, repeats=args.repeats, seed=args.seed, channel=args.channel))
    print(json.dumps({key: report[key] for key in ['valid_for_analysis', 'trial_count', 'target_count', 'metrics']}, indent=2))
    raise SystemExit(0 if report['valid_for_analysis'] else 1)


if __name__ == '__main__':
    main()
