"""The v0.3 paper tables and supplement must regenerate from the archived rows."""
import importlib.util
import json
from pathlib import Path

from handoff_witness.core import digest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("analyze_v3", ROOT / "paper/analyze.py")
analyze = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analyze)
COUNTS = ("correct", "wrong", "contested", "unknown", "missing")
counts = lambda m: tuple(m[k] for k in COUNTS)


def test_tables_regenerate_and_replication_matches():
    manifest, report, rows = analyze.load_run(analyze.RUNS / "primary")
    other_manifest, replication, other_rows = analyze.load_run(analyze.RUNS / "replication")
    assert manifest["seed"] != other_manifest["seed"]
    assert manifest["implementation_sha256"] == other_manifest["implementation_sha256"]
    assert report["metrics"] == replication["metrics"] and report["by_scenario"] == replication["by_scenario"]
    assert report["stored_arms"] == replication["stored_arms"]
    results = analyze.RESULTS
    assert (results / "attribution_results.tex").read_text() == analyze.main_table(report)
    assert (results / "scenario_results.tex").read_text() == analyze.scenario_table(report)
    assert (results / "stored_results.tex").read_text() == analyze.stored_table(report, rows)
    assert analyze.stored_table(report, rows) == analyze.stored_table(replication, other_rows)
    assert (results / "ablation_results.tex").read_text() == analyze.ablation_table(report)
    supplement = json.loads((results / "supplement.json").read_text())
    for key, value in analyze.analyze(report, replication, rows).items():
        if value is not None:
            assert supplement[key] == value


def test_headline_counts_and_error_locations():
    _, report, rows = analyze.load_run(analyze.RUNS / "primary")
    assert (report["trial_count"], report["target_count"]) == (160, 375)
    assert counts(report["metrics"]["v02_full"]) == (310, 45, 10, 5, 5)
    assert counts(report["metrics"]["plus_state_write"]) == (335, 20, 15, 0, 5)
    assert counts(report["metrics"]["full"]) == (340, 10, 20, 0, 5)
    wrong = lambda method: {r["scenario"] for r in rows if analyze.label_outcome(r[method], r["assigned_source"]) == "wrong"}
    # The mediation bypass, and state that crosses hosts on the server.
    assert wrong("full") == {"unbound_agent_direct", "st_server_state_cross_host"}
    assert wrong("plus_state_write") == wrong("full") | {"st_indexeddb_relay", "st_server_state_relay"}
    assert not any(r[m] == "human" for r in rows for m in analyze.METHODS if m != "current_controller")
    assert report["metrics"]["full"]["false_agent"] == 0


def test_request_lineage_alone_exonerates_stored_state_relays():
    _, report, rows = analyze.load_run(analyze.RUNS / "primary")
    stored = analyze.stored_summary(report, rows)
    assert (stored["joint_effect_targets"], stored["human_control_effect_targets"]) == (45, 15)
    assert stored["false_exoneration"] == {"v02_full": 40, "plus_state_write": 15, "full": 5}
    assert stored["joint_unknown"] == {"v02_full": 5, "plus_state_write": 0, "full": 0}
    assert stored["contested_human_controls"] == {"v02_full": 0, "plus_state_write": 5, "full": 10}
    partition = stored["partition"]
    assert (partition["relays_blocked"], partition["applicable_relay_trials"]) == (30, 40)
    assert partition["not_blocked"] == ["st_server_state_cross_host", "st_server_state_relay"]
    assert partition["control_trials_delivered"] == partition["control_trials"] == 15


def test_state_rules_do_not_change_the_request_lineage_templates():
    _, report, _ = analyze.load_run(analyze.RUNS / "primary")
    old = ("v1", "mediated", "adversarial")
    assert analyze.group_counts(report, "v02_full", old) == analyze.group_counts(report, "full", old) == [180, 5, 10, 0, 5]
    # ... which are the counts the archived v0.2 runs reported for their full collector.
    archived = ROOT / "paper/results/v0.2/attribution"
    for run in ("primary", "replication"):
        manifest = json.loads((archived / run / "manifest.json").read_text())
        old_report = json.loads((archived / run / "report.json").read_text())
        assert digest(manifest) == old_report["manifest_sha256"] and old_report["valid_for_analysis"]
        assert counts(old_report["metrics"]["full"]) == (180, 5, 10, 0, 5)
