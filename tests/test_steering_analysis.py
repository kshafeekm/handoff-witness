import importlib.util
from pathlib import Path

import pytest

from handoff_witness.steering_v2 import build_cases

spec = importlib.util.spec_from_file_location("analyze_steering", Path(__file__).resolve().parents[1] / "paper/analyze_steering.py")
analysis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analysis)


def rows_for(choose):
    rows = []
    for c in build_cases():
        selected = choose(c)
        rows.append({**{k: c[k] for k in ("task", "family", "seed", "variant", "public", "restricted",
                                         "arrangement", "restricted_first")},
                     "selected": selected, "fence_tolerant_selected": selected})
    return rows


def test_letter_bias_appears_as_label_sensitivity_not_a_paired_effect():
    rows = rows_for(lambda c: "A")
    group = [r for r in rows if r["variant"] == "indirect"]
    label = analysis.contrast(group, "selected", lambda r: r["restricted"] == "A", 1)
    order = analysis.contrast(group, "selected", lambda r: r["restricted_first"], 1)
    assert label["difference"] == 1 and label["ci95_percentile"] == [1, 1]
    assert order["difference"] == 0
    assert analysis.paired_v2(rows, "indirect", "selected", 1)["difference"] == 0
    assert analysis.letter_preference([r for r in rows if r["variant"] == "benign"], "selected")["index"] == 1


def test_paired_difference_matches_task_seed_and_arrangement():
    # Abstain in benign; choose the restricted label under explicit instruction.
    rows = rows_for(lambda c: c["restricted"] if c["variant"] == "explicit" else "abstain")
    result = analysis.paired_v2(rows, "explicit", "selected", 1)
    assert result["difference"] == 1 and result["pairs"] == 144 and result["clusters"] == 12
    assert analysis.paired_v2(rows, "indirect", "selected", 1)["difference"] == 0
    counts = analysis.counts_for([r for r in rows if r["variant"] == "benign"], "selected")
    assert counts == {"public": 0, "restricted": 0, "abstain": 144, "invalid": 0}


def test_invalid_outputs_stay_in_denominators():
    rows = rows_for(lambda c: c["restricted"] if c["restricted_first"] and c["variant"] == "external" else "invalid")
    group = [r for r in rows if r["variant"] == "external"]
    order = analysis.contrast(group, "selected", lambda r: r["restricted_first"], 1)
    assert order["p_if_true"] == 1 and order["p_if_false"] == 0 and order["n_each"] == [72, 72]
    assert analysis.paired_v2(rows, "external", "selected", 1)["difference"] == pytest.approx(0.5)
