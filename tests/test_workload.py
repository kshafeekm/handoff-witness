import pytest

from handoff_witness.workload import (SCENARIOS, arm_counts, auxiliary_paths, expected_paths, label_outcome, metrics, plan, stored_html,
                                      target_source, twin_expectation)


def test_plan_is_seeded_and_complete():
    a, b = plan(2, 1), plan(2, 1)
    assert a == b and len(a["trials"]) == 2 * len(SCENARIOS)
    assert plan(2, 2)["trials"] != a["trials"]
    with pytest.raises(ValueError):
        plan(0)


@pytest.mark.parametrize("label,source,outcome", [
    ("agent", "agent", "correct"), ("not_agent", "human", "correct"), ("human", "human", "correct"),
    ("not_agent", "agent", "wrong"), ("agent", "human", "wrong"), ("human", "agent", "wrong"),
    ("mixed", "agent", "contested"), ("unknown", "human", "unknown"), ("missing", "agent", "missing"),
])
def test_label_outcomes(label, source, outcome):
    assert label_outcome(label, source) == outcome


def test_top_level_load_belongs_to_navigating_channel():
    trial = next(s for s in SCENARIOS if s["name"] == "human_click_on_agent_page")
    trial = {**trial, "trial_id": "t0000"}
    paths = expected_paths(trial)
    assert [target_source(trial, p) for p in paths] == ["agent", "human"]
    bypass = {**next(s for s in SCENARIOS if s["name"] == "unbound_agent_direct"), "trial_id": "t0001"}
    assert target_source(bypass, expected_paths(bypass)[0]) == "agent"


def test_metrics_reject_invalid_trials():
    row = {"trial_valid": False, "assigned_source": "agent", "full": "agent"}
    with pytest.raises(ValueError):
        metrics([row], "full")


@pytest.mark.parametrize("label,outcome", [
    ("mixed", "correct"), ("agent", "correct"), ("not_agent", "wrong"), ("human", "wrong"),
    ("unknown", "unknown"), ("missing", "missing"),
])
def test_joint_source_requires_the_agent_contribution_to_be_reported(label, outcome):
    assert label_outcome(label, "joint") == outcome


def test_joint_false_exoneration_counts_as_false_not_agent():
    rows = [{"trial_valid": True, "assigned_source": "joint", "full": label} for label in ("not_agent", "mixed", "agent")]
    result = metrics(rows, "full")
    assert (result["correct"], result["wrong"], result["contested"], result["false_not_agent"]) == (2, 1, 0, 1)


def test_stored_targets_and_sources():
    by_name = {s["name"]: {**s, "trial_id": "t0000"} for s in SCENARIOS}
    sources = lambda name: [(p.rsplit("/", 1)[-1], target_source(by_name[name], p)) for p in expected_paths(by_name[name])]
    assert sources("st_storage_relay") == [("r0", "agent"), ("h0", "human"), ("effect", "joint")]
    # The worker script fetch is required but not scored: its observation is a race.
    assert sources("st_service_worker_relay") == [("r0", "agent"), ("h0", "human"), ("effect", "joint")]
    worker = next(t for t in plan(1, 1)["trials"] if t["name"] == "st_service_worker_relay")
    assert auxiliary_paths(worker) == ["/trial/" + worker["trial_id"] + "/sw.js"]
    assert not any(auxiliary_paths(t) for t in plan(1, 1)["trials"] if t["name"] != "st_service_worker_relay")
    assert sources("st_dom_relay") == [("r0", "human"), ("effect", "joint")]
    assert sources("st_human_state_control") == [("r0", "human"), ("h0", "human"), ("effect", "human")]
    assert sources("st_agent_no_state") == [("r0", "agent"), ("h0", "human"), ("effect", "human")]


def test_twin_expectations_define_joint_and_control_sources():
    for scenario in SCENARIOS:
        if scenario["group"] != "stored":
            continue
        expected = twin_expectation(scenario)
        assert expected["no_reader"] == 0
        if scenario["source"] == "joint":
            assert expected["no_writer"] == 0  # no effect without the agent's write
    assert twin_expectation(next(s for s in SCENARIOS if s["name"] == "st_agent_unread_state"))["no_writer"] == 1
    assert plan(1)["stored_twins"]["expected_effect_deliveries"]["st_storage_relay"] == {"no_writer": 0, "no_reader": 0}


def test_stored_pages_keep_writer_and_reader_apart():
    trial = {**next(s for s in SCENARIOS if s["name"] == "st_storage_relay"), "trial_id": "t0000", "callback_delay_ms": 0}
    writer, reader = stored_html(trial, "http://127.0.0.1:1", "r0"), stored_html(trial, "http://127.0.0.1:1", "h0")
    assert "setItem" in writer and "fetch(" not in writer
    assert "getItem" in reader and "/effect" not in reader  # the reader learns the target only from stored state


def test_arm_counts_come_from_the_receiver_ledger():
    manifest = plan(1)
    stored = next(t for t in manifest["trials"] if t["name"] == "st_cookie_relay")
    dom = next(t for t in manifest["trials"] if t["name"] == "st_dom_relay")
    ledger = [{"path": "/trial/" + stored["trial_id"] + "-pt/effect"}, {"path": "/trial/" + stored["trial_id"] + "/effect"}]
    counts = arm_counts(manifest, ledger)
    assert counts[stored["trial_id"]] == {"no_writer": 0, "no_reader": 0, "partitioned": 1}
    assert counts[dom["trial_id"]]["partitioned"] is None
