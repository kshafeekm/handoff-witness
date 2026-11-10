"""Re-collect archived v0.3 attribution runs from their raw captures.

For every trial: re-run each collector variant over capture.json, re-score it
against the receiver ledger, compare with the archived rows and checks, and
verify the signed provenance against its bundled key and checkpoint (internal
consistency only, not independent authenticity). Counterfactual-twin deliveries
are recounted from the run's receiver ledger. Source files must match the hashes
pinned in the manifest; verify v0.1 and v0.2 runs from their own source trees.
"""
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handoff_witness.core import digest, verify
from handoff_witness.lineage import collect
from handoff_witness.workload import PROTOCOL, VARIANTS, arm_counts, score_trial, summarize, twin_expectation


def check_run(directory):
    directory = Path(directory)
    read = lambda name: json.loads((directory / name).read_text())
    manifest, report = read('manifest.json'), read('report.json')
    assert manifest['protocol'] == PROTOCOL, 'Not a v0.3 run; verify earlier runs from their own source trees'
    assert digest(manifest) == report['manifest_sha256']
    for name, expected in manifest['implementation_sha256'].items():
        assert hashlib.sha256((ROOT / 'handoff_witness' / name).read_bytes()).hexdigest() == expected, name
    assert manifest['collector_variants'] == {k: sorted(v) for k, v in VARIANTS.items()}
    scored, checks = [], []
    twins = arm_counts(manifest, read('receiver.json'))
    for trial in manifest['trials']:
        folder = directory / trial['trial_id']
        trace = json.loads((folder / 'capture.json').read_text())
        ledger = json.loads((folder / 'receiver.json').read_text())
        analyses = {variant: collect(trace, rules)[1] for variant, rules in VARIANTS.items()}
        rows, check = score_trial(trial, analyses, ledger)
        archived = json.loads((folder / 'check.json').read_text())
        assert archived['error'] is None and archived['blocked_nonlocal_urls'] == []
        for key, value in check.items():
            assert archived[key] == value, (trial['trial_id'], key)
        if trial['group'] == 'stored':  # Twins ran after the capture and are recounted from the ledger.
            expected = twin_expectation(trial)
            assert archived['arms'] == twins[trial['trial_id']] and archived['arms_expected'] == expected
            assert archived['twins_consistent'] and all(twins[trial['trial_id']][arm] == n for arm, n in expected.items())
        assert all(r['url'].startswith(('http://127.0.0.1:', 'http://localhost:')) for r in analyses['full']['requests'])
        provenance = folder / 'provenance'
        records = [json.loads(line) for line in (provenance / 'events.jsonl').read_text().splitlines()]
        result = verify(records, json.loads((provenance / 'checkpoint.json').read_text()),
                        load_pem_public_key((provenance / 'recorder-public.pem').read_bytes()))
        assert [r['attribution'] for r in result['requests']] == [r['attribution'] for r in analyses['full']['requests']]
        assert digest(trace) in records[0]['event']['data']['label']
        scored.extend(rows)
        checks.append(check)
    assert scored == read('rows.json')
    recomputed = summarize(manifest, scored, checks, report['browser_version'], read('receiver.json'),
                           playwright_version=report['playwright_version'])
    for field in ['valid_for_analysis', 'trial_count', 'target_count', 'metrics', 'by_group', 'by_scenario',
                  'stored_arms', 'auxiliary_observations']:
        assert recomputed[field] == report[field], field
    return {'directory': str(directory), 'trials': len(checks), 'targets': len(scored),
            'collector_variants': len(VARIANTS), 'raw_recollection': 'passed',
            'signature_consistency': 'passed', 'independent_authenticity': 'not_established'}


if __name__ == '__main__':
    if len(sys.argv) < 2:
        raise SystemExit('Supply one or more v0.3 attribution run directories')
    for path in sys.argv[1:]:
        print(json.dumps(check_run(path)))
