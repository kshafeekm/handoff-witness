"""Recompute the v0.3 attribution results from archived rows and write the tables.

Checks each run's manifest digest and recomputes every reported metric from the
per-target rows. No browser is launched; raw captures are re-collected by
verify_runs.py. Ablations are separate collector runs over the same captures,
not post-hoc relabelling of decisions.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handoff_witness.core import digest
from handoff_witness.workload import ARMS, METHODS, SCENARIOS, VARIANTS, label_outcome, metrics, twin_expectation

RESULTS = ROOT / 'paper/results'
RUNS = RESULTS / 'attribution'
LABELS = {
    'current_controller': 'Current controller (baseline)',
    'v1_navigation_redirect': 'v0.1 rules: navigation + redirect',
    'plus_document_lineage': '+ document and renderer navigation',
    'plus_worker': '+ worker lineage',
    'plus_agent_script': '+ injected-script stacks',
    'plus_input_taint': '+ input taint',
    'v02_full': '+ exclusion (v0.2 collector)',
    'plus_service_worker': '+ service worker lineage',
    'plus_state_write': '+ observed state writes',
    'full': '+ host taint (v0.3 collector)',
    'full_without_input_taint': 'Full $-$ input taint',
    'full_without_agent_script': 'Full $-$ injected-script stacks',
    'full_without_worker': 'Full $-$ worker lineage',
    'full_without_document_lineage': 'Full $-$ document lineage',
    'full_without_state_write': 'Full $-$ observed state writes',
    'full_without_exclusion': 'Full $-$ exclusion',
}
SHORT = {
    'agent_direct': 'Agent navigation', 'agent_redirect_stable': 'Redirect, stable control',
    'agent_redirect_handoff': 'Redirect, takeover', 'agent_callback_handoff': 'Page timer, takeover',
    'unbound_agent_direct': 'Agent bypasses mediation', 'simulated_human_direct': 'Human navigation',
    'simulated_human_callback_handoff': 'Human page timer, takeover', 'agent_worker_handoff': 'Worker, takeover',
    'agent_script_callback_handoff': 'Injected script, takeover', 'agent_click_callback_handoff': 'Agent click, takeover',
    'human_click_on_agent_page': 'Human click on agent page', 'agent_script_on_human_page': 'Injected script on human page',
    'agent_click_on_human_page': 'Agent click on human page', 'adv_meta_refresh_handoff': 'Meta refresh',
    'adv_script_navigation_handoff': 'Script navigation', 'adv_form_autosubmit_handoff': 'Form auto-submit',
    'adv_popup_handoff': 'Popup (window.open)', 'adv_iframe_fetch_handoff': 'Iframe fetch',
    'adv_forged_agent_sourceurl': 'Forged agent sourceURL', 'adv_synthetic_input_handoff': 'Synthetic input events',
    'st_storage_relay': 'localStorage', 'st_storage_late_write': 'localStorage, written by a timer',
    'st_cookie_relay': 'Cookie (Set-Cookie header)', 'st_script_cookie_relay': 'Cookie (document.cookie)',
    'st_indexeddb_relay': 'IndexedDB', 'st_service_worker_relay': 'Service worker',
    'st_dom_relay': 'DOM of a human-loaded page', 'st_server_state_relay': 'Server state, same host',
    'st_server_state_cross_host': 'Server state, other host', 'st_human_state_control': 'Human writes, human reads',
    'st_agent_unread_state': 'Agent writes, nothing reads', 'st_agent_no_state': 'Agent visits, writes nothing',
}
GROUP = {'v1': 'v0.1', 'mediated': 'Mediated', 'adversarial': 'Adversarial', 'stored': 'Stored'}
COUNTS = ('correct', 'wrong', 'contested', 'unknown', 'missing')
STATE_VARIANTS = ('v02_full', 'plus_state_write', 'full')
TEX = {'not_agent': r'not\_agent', 'agent': 'agent', 'mixed': 'mixed', 'unknown': 'unknown', 'missing': 'missing'}


def load_run(directory):
    read = lambda name: json.loads((directory / name).read_text())
    manifest, report, rows = read('manifest.json'), read('report.json'), read('rows.json')
    assert digest(manifest) == report['manifest_sha256'] and report['valid_for_analysis']
    assert len(rows) == report['target_count']
    for method in METHODS:
        assert metrics(rows, method) == report['metrics'][method]
        for scenario in SCENARIOS:
            subset = [r for r in rows if r['scenario'] == scenario['name']]
            assert metrics(subset, method) == report['by_scenario'][scenario['name']][method]
    for scenario in SCENARIOS:  # Every stored template's twins support its assigned source.
        if scenario['group'] == 'stored':
            arms = report['stored_arms'][scenario['name']]
            assert all(arms[arm] == n * arms['trials'] for arm, n in twin_expectation(scenario).items())
    return manifest, report, rows


def pct(value):
    return '--' if value is None else f'{100 * value:.1f}\\%'


def counts(m):
    return ' & '.join(str(m[k]) for k in COUNTS)


def main_table(report):
    lines = [r'\begin{table}[tb]', r'\centering\small', r'\setlength{\tabcolsep}{5pt}', r'\begin{tabular}{@{}lrrrrrrr@{}}', r'\toprule',
             r'Method & Correct & Wrong & Contested & Unknown & Missing & Coverage & Accuracy \\', r'\midrule']
    names = {'current_controller': 'Current controller', 'v1_navigation_redirect': 'v0.1 rules',
             'v02_full': 'Request lineage (v0.2)', 'plus_state_write': '+ observed state writes',
             'full': '+ host taint (v0.3)'}
    for method, name in names.items():
        m = report['metrics'][method]
        lines.append(f"{name} & {counts(m)} & {pct(m['attribution_coverage'])} & {pct(m['conditional_accuracy'])} \\\\")
    repeats = report['trial_count'] // len(SCENARIOS)
    lines += [r'\bottomrule', r'\end{tabular}',
              r'\caption{Primary run: ' + str(report['target_count']) + ' planned targets in ' + str(report['trial_count']) +
              r' trials (' + str(len(SCENARIOS)) + r' templates $\times$ ' + str(repeats) + r'). Coverage counts correct plus '
              r'wrong labels over all targets; accuracy is correct over correct plus wrong. Contested means a \emph{mixed} '
              r'label on a single-source target. For a joint target, \emph{mixed} or \emph{agent} is correct and '
              r'\emph{not\_agent} is wrong. The replication run (different seed) produced identical counts.}',
              r'\label{tab:attribution}', r'\end{table}']
    return '\n'.join(lines) + '\n'


def scenario_table(report):
    lines = [r'\begin{table}[tb]', r'\centering\footnotesize', r'\setlength{\tabcolsep}{4pt}',
             r'\begin{tabularx}{\linewidth}{@{}Xlrrrrrrr@{}}', r'\toprule',
             r'& & & \multicolumn{5}{c}{v0.3 collector} & Controller \\', r'\cmidrule(lr){4-8}\cmidrule(l){9-9}',
             r'Scenario & Group & $N$ & Corr. & Wrong & Cont. & Unk. & Miss. & Wrong \\', r'\midrule']
    for scenario in SCENARIOS:
        if scenario['group'] == 'stored':
            continue
        s = report['by_scenario'][scenario['name']]
        f, c = s['full'], s['current_controller']
        assert [f[k] for k in COUNTS] == [s['v02_full'][k] for k in COUNTS]  # State rules change no label here.
        lines.append(f"{SHORT[scenario['name']]} & {GROUP[scenario['group']]} & {f['total_targets']} & {counts(f)} & {c['wrong']} \\\\")
    lines += [r'\bottomrule', r'\end{tabularx}',
              r'\caption{Primary run, request-lineage scenarios (five trials each; $N$ counts target requests). Group v0.1 '
              r'repeats the earliest workload; Mediated adds agent actions through the mediated channel and human input on '
              r'agent pages; Adversarial pages try to move requests out of, or into, agent lineage. The state rules change '
              r'no label in these 20 templates, so the v0.2 collector has the same counts.}',
              r'\label{tab:scenarios}', r'\end{table}']
    return '\n'.join(lines) + '\n'


def effect_labels(rows, scenario, method):
    return sorted({r[method] for r in rows if r['scenario'] == scenario and r['path'].endswith('/effect')})


def stored_table(report, rows):
    lines = [r'\begin{table}[tb]', r'\centering\footnotesize', r'\setlength{\tabcolsep}{3.5pt}',
             r'\begin{tabularx}{\linewidth}{@{}Xllllrrr@{}}', r'\toprule',
             r'& & \multicolumn{3}{c}{Label of the effect request} & \multicolumn{3}{c}{Effect deliveries in twins} \\',
             r'\cmidrule(lr){3-5}\cmidrule(l){6-8}',
             r'State that carries the influence & Source & v0.2 & + writes & + host & No writer & No reader & Partitioned \\', r'\midrule']
    for scenario in SCENARIOS:
        if scenario['group'] != 'stored':
            continue
        if scenario['name'] == 'st_human_state_control':
            lines.append(r'\midrule')
        cells = []
        for method in STATE_VARIANTS:
            labels = effect_labels(rows, scenario['name'], method)
            assert len(labels) == 1  # Every trial of a template received the same label.
            outcome = label_outcome(labels[0], scenario['source'])
            cells.append({'wrong': r'\textbf{%s}', 'contested': r'\emph{%s}'}.get(outcome, '%s') % TEX[labels[0]])
        arms = report['stored_arms'][scenario['name']]
        twins = ['--' if arms[arm] is None else f"{arms[arm]}/{arms['trials']}" for arm in ARMS]
        lines.append(f"{SHORT[scenario['name']]} & {scenario['source']} & {' & '.join(cells)} & {' & '.join(twins)} \\\\")
    lines += [r'\bottomrule', r'\end{tabularx}',
              r'\caption{Stored-state scenarios, primary run (five trials each; all five agree in every cell). The effect '
              r'request is issued from a document the human channel loaded, after the agent channel acted. Columns: v0.2 '
              r'request lineage, plus observed state writes, plus host taint. \textbf{Bold} is a wrong label (a joint effect '
              r'reported as \emph{not\_agent}); \emph{italic} is a contested label on a human-only effect. Twins re-run each '
              r'trial without capture: with the agent phase removed, with the human phase removed, and with one browser '
              r'storage partition per controlling channel (not applicable to the single-document row).}',
              r'\label{tab:stored}', r'\end{table}']
    return '\n'.join(lines) + '\n'


def ablation_table(report):
    lines = [r'\begin{table}[tb]', r'\centering\small', r'\begin{tabular}{@{}lrrrrr@{}}', r'\toprule',
             r'Collector rules & Correct & Wrong & Contested & Unknown & Missing \\', r'\midrule']
    for method in METHODS:
        if method in {'full_without_input_taint', 'plus_service_worker'}:
            lines.append(r'\midrule')
        lines.append(f"{LABELS[method]} & {counts(report['metrics'][method])} \\\\")
    lines += [r'\bottomrule', r'\end{tabular}',
              r'\caption{Ablations on the primary run. Each row re-runs the offline collector with a rule set over the '
              r'same raw captures: the request-lineage ladder, the three state rules, then leave-one-out from the full '
              r'collector. No row uses assigned source labels.}',
              r'\label{tab:ablation}', r'\end{table}']
    return '\n'.join(lines) + '\n'


def stored_summary(report, rows):
    effects = [r for r in rows if r['group'] == 'stored' and r['path'].endswith('/effect')]
    joint = [r for r in effects if r['assigned_source'] == 'joint']
    controls = [r for r in effects if r['assigned_source'] == 'human']
    relays = {s['name']: report['stored_arms'][s['name']] for s in SCENARIOS if s['group'] == 'stored' and s['source'] == 'joint'}
    applicable = {k: v for k, v in relays.items() if v['partitioned'] is not None}
    return {
        'joint_effect_targets': len(joint), 'human_control_effect_targets': len(controls),
        'false_exoneration': {m: sum(r[m] == 'not_agent' for r in joint) for m in STATE_VARIANTS},
        'joint_unknown': {m: sum(r[m] == 'unknown' for r in joint) for m in STATE_VARIANTS},
        'joint_labeled_agent_not_mixed': {m: sum(r[m] == 'agent' for r in joint) for m in STATE_VARIANTS},
        'contested_human_controls': {m: sum(r[m] == 'mixed' for r in controls) for m in STATE_VARIANTS},
        'false_exoneration_by_scenario': {m: sorted({r['scenario'] for r in joint if r[m] == 'not_agent'}) for m in STATE_VARIANTS},
        'partition': {'applicable_relay_trials': sum(v['trials'] for v in applicable.values()),
                      'relays_blocked': sum(v['trials'] - v['partitioned'] for v in applicable.values()),
                      'not_blocked': sorted(k for k, v in applicable.items() if v['partitioned']),
                      'control_trials_delivered': sum(report['stored_arms'][s['name']]['partitioned'] for s in SCENARIOS
                                                      if s['group'] == 'stored' and s['source'] == 'human'),
                      'control_trials': sum(report['stored_arms'][s['name']]['trials'] for s in SCENARIOS
                                            if s['group'] == 'stored' and s['source'] == 'human')},
    }


def group_counts(report, method, groups):
    return [sum(report['by_group'][g][method][k] for g in groups) for k in COUNTS]


def analyze(report, replication, rows):
    m = report['metrics']
    full, controller, v02, writes = m['full'], m['current_controller'], m['v02_full'], m['plus_state_write']
    loss = lambda x: f"{x['wrong']}e + {x['contested']}c + {x['unknown']}u + {x['missing']}m"
    return {
        'primary_seed': None, 'replication_seed': None,
        'same_aggregate_metrics': report['metrics'] == replication['metrics'],
        'same_scenario_metrics': report['by_scenario'] == replication['by_scenario'],
        'same_stored_arms': report['stored_arms'] == replication['stored_arms'],
        'auxiliary_observations': {'primary': report['auxiliary_observations'], 'replication': replication['auxiliary_observations']},
        'full_errors_by_scenario': {k: v['full']['wrong'] for k, v in report['by_scenario'].items() if v['full']['wrong']},
        'full_contested_by_scenario': {k: v['full']['contested'] for k, v in report['by_scenario'].items() if v['full']['contested']},
        'full_missing_by_scenario': {k: v['full']['missing'] for k, v in report['by_scenario'].items() if v['full']['missing']},
        # The 20 request-lineage templates reproduce the v0.2 counts under both collectors.
        'request_lineage_groups': {method: dict(zip(COUNTS, group_counts(report, method, ('v1', 'mediated', 'adversarial'))))
                                   for method in ('v02_full', 'full')},
        'stored_group': {method: dict(zip(COUNTS, group_counts(report, method, ('stored',))))
                         for method in ('current_controller',) + STATE_VARIANTS},
        'stored': stored_summary(report, rows),
        'loss_functions': {'current_controller': loss(controller), 'request_lineage_v02': loss(v02),
                           'plus_state_write': loss(writes), 'full': loss(full)},
        'state_tradeoff': {'fewer_wrong_than_v02': {'plus_state_write': v02['wrong'] - writes['wrong'], 'full': v02['wrong'] - full['wrong']},
                           'extra_contested_than_v02': {'plus_state_write': writes['contested'] - v02['contested'],
                                                        'full': full['contested'] - v02['contested']}},
    }


def main():
    manifest, report, rows = load_run(RUNS / 'primary')
    other_manifest, replication, other_rows = load_run(RUNS / 'replication')
    assert manifest['implementation_sha256'] == other_manifest['implementation_sha256']
    assert manifest['seed'] != other_manifest['seed']
    assert stored_table(report, rows) == stored_table(replication, other_rows)
    supplement = analyze(report, replication, rows)
    supplement.update(primary_seed=manifest['seed'], replication_seed=other_manifest['seed'],
                      browser_version=report['browser_version'], variants={k: sorted(v) for k, v in VARIANTS.items()})
    (RESULTS / 'supplement.json').write_text(json.dumps(supplement, indent=2) + '\n')
    (RESULTS / 'attribution_results.tex').write_text(main_table(report))
    (RESULTS / 'scenario_results.tex').write_text(scenario_table(report))
    (RESULTS / 'stored_results.tex').write_text(stored_table(report, rows))
    (RESULTS / 'ablation_results.tex').write_text(ablation_table(report))
    print(json.dumps(supplement, indent=2))


if __name__ == '__main__':
    main()
