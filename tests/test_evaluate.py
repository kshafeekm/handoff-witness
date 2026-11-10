from collections import Counter

import pytest

from handoff_witness.evaluate import SCENARIOS, expected_paths, metrics, plan, score_trial, summarize


def case(name):
    return {**next(s for s in SCENARIOS if s['name'] == name), 'trial_id': 't0000'}


def observation(path, prediction='agent', controller='human'):
    return {'url': 'http://127.0.0.1:9999' + path, 'attribution': prediction,
            'controller_at_dispatch': controller, 'reason': 'test'}


def test_plan_is_balanced_seeded_and_predeclares_targets():
    first = plan(5, 123)
    assert first == plan(5, 123)
    assert first != plan(5, 124)
    assert len(first['trials']) == 40
    assert Counter(t['name'] for t in first['trials']) == {s['name']: 5 for s in SCENARIOS}
    assert len({t['trial_id'] for t in first['trials']}) == 40
    assert sum(len(expected_paths(t)) for t in first['trials']) == 75


@pytest.mark.parametrize('repeats', [0, -1, 101, True, 1.5])
def test_invalid_repetition_count(repeats):
    with pytest.raises(ValueError):
        plan(repeats)


def test_missing_observations_are_not_dropped_or_called_unknown():
    trial = case('agent_worker_handoff')
    paths = expected_paths(trial)
    rows, check = score_trial(trial, {'requests': [observation(paths[0])]}, [{'path': p} for p in paths])
    assert check['valid']
    assert len(rows) == 2
    assert rows[1]['provenance'] == rows[1]['current_controller'] == 'missing'
    result = metrics(rows, 'provenance')
    assert result['observation_coverage'] == result['attribution_coverage'] == 0.5
    assert result['correct_fraction_all_requests'] == 0.5
    assert result['conditional_accuracy'] == 1
    assert result['missing_predictions'] == 1 and result['unknown_predictions'] == 0


def test_abstention_does_not_inflate_total_correct_fraction():
    trial = case('agent_callback_handoff')
    paths = expected_paths(trial)
    observations = [observation(paths[0], 'agent', 'agent'), observation(paths[1], 'unknown', 'human')]
    rows, _ = score_trial(trial, {'requests': observations}, [{'path': p} for p in paths])
    witness = metrics(rows, 'provenance')
    baseline = metrics(rows, 'current_controller')
    assert witness['known_predictions'] == 1
    assert witness['conditional_accuracy'] == 1
    assert witness['correct_fraction_all_requests'] == baseline['correct_fraction_all_requests'] == 0.5
    assert baseline['false_human_count'] == 1
    assert baseline['conditional_accuracy'] == 0.5


@pytest.mark.parametrize('change', ['missing_receiver', 'duplicate_receiver', 'duplicate_browser', 'extra_target'])
def test_invalid_trial_blocks_aggregate_metrics(change):
    trial = case('agent_direct')
    path = expected_paths(trial)[0]
    observations = [observation(path)]
    ledger = [{'path': path}]
    if change == 'missing_receiver':
        ledger.clear()
    elif change == 'duplicate_receiver':
        ledger *= 2
    elif change == 'duplicate_browser':
        observations *= 2
    else:
        ledger.append({'path': '/trial/t0000/unplanned'})
    rows, check = score_trial(trial, {'requests': observations}, ledger)
    assert not check['valid']
    with pytest.raises(ValueError):
        metrics(rows, 'provenance')


def test_receiver_labels_never_replace_prediction():
    trial = case('simulated_human_direct')
    path = expected_paths(trial)[0]
    rows, _ = score_trial(trial, {'requests': [observation(path, 'unknown', 'human')]}, [{'path': path}])
    result = metrics(rows, 'provenance')
    assert result['conditional_accuracy'] is None
    assert result['correct_predictions'] == 0
    assert result['confusion']['human']['unknown'] == 1


def test_false_agent_and_false_human_are_distinct():
    agent = case('agent_direct')
    human = case('simulated_human_direct')
    path = expected_paths(agent)[0]
    rows_a, _ = score_trial(agent, {'requests': [observation(path, 'human')]}, [{'path': path}])
    rows_h, _ = score_trial(human, {'requests': [observation(path, 'agent')]}, [{'path': path}])
    result = metrics(rows_a + rows_h, 'provenance')
    assert result['false_agent_count'] == result['false_human_count'] == 1
    assert result['correct_fraction_all_requests'] == 0


@pytest.mark.parametrize('change', ['omitted_row', 'duplicate_row', 'wrong_source', 'late_duplicate_receiver'])
def test_aggregate_reconciles_all_planned_targets(change):
    manifest = plan(1)
    rows, checks, ledger = [], [], []
    for trial in manifest['trials']:
        paths = expected_paths(trial)
        received = [{'path': p} for p in paths]
        trial_rows, check = score_trial(trial, {'requests': [observation(p) for p in paths]}, received)
        rows.extend(trial_rows)
        checks.append(check)
        ledger.extend(received)
    if change == 'omitted_row':
        rows.pop()
    elif change == 'duplicate_row':
        rows.append(rows[0])
    elif change == 'wrong_source':
        rows[0]['assigned_source'] = 'human' if rows[0]['assigned_source'] == 'agent' else 'agent'
    else:
        ledger.append(ledger[0])
    report = summarize(manifest, rows, checks, 'test-browser', ledger)
    assert not report['valid_for_analysis']
    assert report['metrics'] is None


def test_archived_paper_results_recompute_from_saved_rows():
    import json
    from pathlib import Path
    from handoff_witness.core import digest
    from handoff_witness.evaluate import latex_results
    from paper.analyze_v01 import booktabs
    directory = Path(__file__).resolve().parents[1] / 'paper/results/v0.1'
    report = json.loads((directory / 'report.json').read_text())
    manifest = json.loads((directory / 'manifest.json').read_text())
    rows = json.loads((directory / 'rows.json').read_text())
    assert digest(manifest) == report['manifest_sha256']
    assert len(rows) == report['target_count']
    for method in ['provenance', 'current_controller']:
        assert metrics(rows, method) == report['metrics'][method]
        for name, summary in report['by_scenario'].items():
            assert metrics([r for r in rows if r['scenario'] == name], method) == summary[method]
    assert (directory / 'evaluation_results.tex').read_text() == booktabs(latex_results(report))


def test_paper_ablation_decisions_do_not_use_source_labels():
    from paper.analyze_v01 import root_only
    for reason, prediction, count, expected in [
        ('matched_agent_navigation', 'agent', 1, 'agent'),
        ('cdp_redirect_chain', 'agent', 1, 'unknown'),
        ('script_input_origin_unresolved', 'unknown', 1, 'unknown'),
        ('not_observed', 'missing', 0, 'missing'),
    ]:
        for label in ['agent', 'human']:
            assert root_only({'collector_reason': reason, 'provenance': prediction,
                              'browser_observation_count': count,
                              'assigned_source': label}) == expected


def test_submission_supplement_and_replication_are_reproducible():
    import json
    from paper.analyze_v01 import RESULTS, analyze, load_run, tables
    rows, report, manifest = load_run(RESULTS)
    replication_rows, replication_report, replication_manifest = load_run(RESULTS / 'replication')
    supplement = json.loads((RESULTS / 'supplement.json').read_text())
    computed = analyze(rows)
    for key, value in computed.items():
        assert supplement[key] == value
    scenario_tex, ablation_tex = tables(rows, computed)
    assert (RESULTS / 'scenario_results.tex').read_text() == scenario_tex
    assert (RESULTS / 'ablation_results.tex').read_text() == ablation_tex
    assert manifest['seed'] != replication_manifest['seed']
    assert manifest['implementation_sha256'] == replication_manifest['implementation_sha256']
    assert report['metrics'] == replication_report['metrics']
    assert report['by_scenario'] == replication_report['by_scenario']
    assert len(replication_rows) == 75
