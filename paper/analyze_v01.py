"""v0.1 archive: recompute the earlier post-hoc ablation from recorded decisions.

The v0.1 code is not kept in this repository's history, so the v0.1 runs cannot
be re-collected. This script only recomputes metrics from the archived rows.

Run from the repository root with the project Python environment.
No new browser measurements are created by this script.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handoff_witness.core import digest
from handoff_witness.evaluate import metrics, latex_results

RESULTS = ROOT / 'paper/results/v0.1'
NAMES = {
    'agent_direct': 'Agent direct',
    'agent_redirect_stable': 'Redirect, stable control',
    'agent_redirect_handoff': 'Redirect, takeover',
    'agent_callback_handoff': 'Agent callback, takeover',
    'unbound_agent_direct': 'Unbound agent direct',
    'simulated_human_direct': 'Simulated human direct',
    'simulated_human_callback_handoff': 'Human callback, takeover',
    'agent_worker_handoff': 'Agent worker, takeover',
}


def root_only(row):
    if row['browser_observation_count'] == 0:
        return 'missing'
    if row['collector_reason'] == 'matched_agent_navigation':
        return row['provenance']
    return 'unknown'


def load_run(directory):
    rows = json.loads((directory / 'rows.json').read_text())
    report = json.loads((directory / 'report.json').read_text())
    manifest = json.loads((directory / 'manifest.json').read_text())
    assert report['valid_for_analysis']
    assert digest(manifest) == report['manifest_sha256']
    assert len(rows) == report['target_count']
    for method in ['provenance', 'current_controller']:
        assert metrics(rows, method) == report['metrics'][method]
    return rows, report, manifest


def analyze(rows):
    # Source labels are used only by metrics(), after decisions are fixed.
    roots = [{**r, 'provenance': root_only(r)} for r in rows]
    abstain = [{**r, 'provenance': 'missing' if r['browser_observation_count'] == 0
                else 'unknown'} for r in rows]
    always_agent = [{**r, 'provenance': 'missing' if r['browser_observation_count'] == 0
                     else 'agent'} for r in rows]
    return {
        'analysis_type': 'post_hoc_offline_decision_ablation',
        'provenance': metrics(rows, 'provenance'),
        'current_controller': metrics(rows, 'current_controller'),
        'root_only': metrics(roots, 'provenance'),
        'abstain_all': metrics(abstain, 'provenance'),
        'always_agent': metrics(always_agent, 'provenance'),
        'common_assignment_count': sum(r['provenance'] != 'unknown' and
                                       r['browser_observation_count'] == 1 for r in rows),
        'controller_errors_on_provenance_assignments': sum(
            r['provenance'] not in {'unknown', 'missing'} and
            r['current_controller'] != r['assigned_source'] for r in rows),
    }


def tables(rows, analysis):
    end = r' \\'
    scenarios = [r'\begin{table}[tb]', r'\centering\small',
                 r'\begin{tabularx}{\linewidth}{@{}Xrrrrrr@{}}', r'\toprule',
                 'Scenario & $N$ & P correct & P wrong & P unknown & Missing & C wrong' + end,
                 r'\midrule']
    for key, name in NAMES.items():
        subset = [r for r in rows if r['scenario'] == key]
        p, c = metrics(subset, 'provenance'), metrics(subset, 'current_controller')
        values = [len(subset), p['correct_predictions'],
                  p['known_predictions'] - p['correct_predictions'],
                  p['unknown_predictions'], p['missing_predictions'],
                  c['known_predictions'] - c['correct_predictions']]
        scenarios.append(name + ' & ' + ' & '.join(map(str, values)) + end)
    scenarios += [r'\bottomrule', r'\end{tabularx}',
                  r'\caption{Primary run by scenario. P: provenance; C: current controller. Missing requests are shared by both methods. Each scenario has five trials; $N$ counts requests.}',
                  r'\label{tab:scenarios}', r'\end{table}']
    ablation = [r'\begin{table}[tb]', r'\centering\small',
                r'\begin{tabular}{@{}lrrrrr@{}}', r'\toprule',
                'Decision rule & Correct & Wrong & Unknown & Missing & Coverage' + end,
                r'\midrule']
    for key, label in [('current_controller', 'Current controller'),
                       ('always_agent', 'Always agent when observed'),
                       ('provenance', 'Navigation + redirect ancestry'),
                       ('root_only', 'Matched navigation roots only'),
                       ('abstain_all', 'Abstain on every observation')]:
        m = analysis[key]
        values = [m['correct_predictions'], m['known_predictions'] - m['correct_predictions'],
                  m['unknown_predictions'], m['missing_predictions']]
        ablation.append(label + ' & ' + ' & '.join(map(str, values)) +
                        f" & {m['attribution_coverage']*100:.1f}\\%" + end)
    ablation += [r'\bottomrule', r'\end{tabular}',
                 r'\caption{Post-hoc offline ablation on the same 75 targets. Root-only suppresses every non-root assignment; abstain-all is a sanity baseline. Neither is a new browser run.}',
                 r'\label{tab:ablation}', r'\end{table}']
    return '\n'.join(scenarios) + '\n', '\n'.join(ablation) + '\n'


def booktabs(tex):
    """Restyle the pinned evaluate.latex_results output to match the other tables."""
    for old, new in [(r'\begin{table}[ht]', r'\begin{table}[tb]'), (r'\centering', r'\centering\small'),
                     (r'\begin{tabular}{lrrrrr}', r'\begin{tabular}{@{}lrrrrr@{}}' + '\n' + r'\toprule'),
                     (r'\hline', r'\midrule'), (r'\end{tabular}', r'\bottomrule' + '\n' + r'\end{tabular}')]:
        assert tex.count(old) == 1, old
        tex = tex.replace(old, new)
    return tex


def main():
    rows, report, manifest = load_run(RESULTS)
    analysis = analyze(rows)
    other_rows, other_report, other_manifest = load_run(RESULTS / 'replication')
    analysis['replication'] = {
        'primary_seed': manifest['seed'], 'replication_seed': other_manifest['seed'],
        'same_implementation': manifest['implementation_sha256'] == other_manifest['implementation_sha256'],
        'same_aggregate_metrics': report['metrics'] == other_report['metrics'],
        'same_scenario_metrics': report['by_scenario'] == other_report['by_scenario'],
        'trial_count': other_report['trial_count'], 'target_count': len(other_rows),
    }
    assert analysis['replication']['same_implementation']
    (RESULTS / 'supplement.json').write_text(json.dumps(analysis, indent=2) + '\n')
    scenario_tex, ablation_tex = tables(rows, analysis)
    (RESULTS / 'evaluation_results.tex').write_text(booktabs(latex_results(report)))
    (RESULTS / 'scenario_results.tex').write_text(scenario_tex)
    (RESULTS / 'ablation_results.tex').write_text(ablation_tex)
    print(json.dumps({k: v for k, v in analysis.items() if k not in
                      {'provenance', 'current_controller', 'root_only', 'abstain_all'}}, indent=2))


if __name__ == '__main__':
    main()
