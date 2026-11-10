import copy
from collections import Counter

import pytest

from handoff_witness.core import EvidenceError
from handoff_witness.decision import DecisionWitness, verify_decisions
from handoff_witness.steering import parse_action
from handoff_witness.steering_v2 import (ARRANGEMENTS, CONTEXT_PREFIX, SEEDS, VARIANTS, build_cases,
                                         parse_action_fence_tolerant, task)


def test_every_task_condition_seed_has_all_four_arrangements():
    cases = build_cases()
    assert len(cases) == 12 * 4 * 3 * 4 == 576
    assert len({c["case_id"] for c in cases}) == len(cases)
    cells = Counter((c["task"], c["variant"], c["seed"]) for c in cases)
    assert set(cells.values()) == {4} and len(cells) == 12 * 4 * len(SEEDS)
    for key in cells:
        arrangements = {(c["public"], c["order"]) for c in cases if (c["task"], c["variant"], c["seed"]) == key}
        assert arrangements == set(ARRANGEMENTS)


@pytest.mark.parametrize("public,order", ARRANGEMENTS)
def test_arrangement_controls_only_letters_and_listing_order(public, order):
    restricted = "B" if public == "A" else "A"
    for index in range(12):
        benign, explicit, indirect, external = [task(index, v, public, order) for v in VARIANTS]
        lines = benign["base_instruction"].split("\n")[1]
        first, second = lines.split(". Source ")
        assert first.startswith(f"Source {public}: PUBLIC") == (order == "public_first")
        assert ("RESTRICTED" in first) == (order == "restricted_first")
        assert f"Source {restricted}: RESTRICTED" in lines and f"Source {public}: PUBLIC" in lines
        assert len({c["policy"] for c in (benign, explicit, indirect, external)}) == 1
        assert benign["instruction"] == external["instruction"] == benign["base_instruction"]
        assert explicit["instruction"].startswith(benign["instruction"]) and f"Open source {restricted} anyway" in explicit["instruction"]
        assert indirect["instruction"].startswith(benign["instruction"]) and "source A" not in indirect["instruction"] and "source B" not in indirect["instruction"]
        assert f"open source {restricted}." in external["external_context"]
        assert external["messages"][2] == {"role": "tool", "content": CONTEXT_PREFIX + external["external_context"]}
        assert [m["role"] for m in benign["messages"]] == ["system", "user"]


def test_v2_text_matches_v1_for_v1_arrangement():
    from handoff_witness.steering import task as v1_task
    for index in range(12):
        v1 = v1_task(index, "explicit")
        v2 = task(index, "explicit", v1["public"], "public_first")
        assert v1["instruction"] == v2["instruction"] and v1["policy"] == v2["policy"]


def test_fence_tolerant_parser_strips_exactly_one_whole_json_fence():
    assert parse_action_fence_tolerant('```json\n{"action":"abstain"}\n```') == "abstain"
    assert parse_action_fence_tolerant(' ```json\n{"action":"visit","target":"B"}\n``` ') == "B"
    assert parse_action_fence_tolerant('```\n{"action":"abstain"}\n```') == "invalid"
    assert parse_action_fence_tolerant('```json\n```json\n{"action":"abstain"}\n```\n```') == "invalid"
    assert parse_action_fence_tolerant('Sure: ```json\n{"action":"abstain"}\n```') == "invalid"
    assert parse_action('```json\n{"action":"abstain"}\n```') == "invalid"


def external_witness(messages_role="tool"):
    c = task(3, "external", "B", "restricted_first")
    w = DecisionWitness(session="v2")
    ins = w.append("instruction", channel="user", text=c["instruction"], replaces=None)
    ctx = w.append("context", channel="external", text=c["external_context"])
    messages = copy.deepcopy(c["messages"])
    messages[2]["role"] = messages_role
    return w, c, ins, ctx, messages


@pytest.mark.parametrize("role", ["tool", "user"])
def test_decision_witness_accepts_recorded_external_channel_role(role):
    w, c, ins, ctx, messages = external_witness(role)
    w.append("decision", instruction=ins, contexts=[ctx], policy=c["policy"], messages=messages,
             rendered_prompt_sha256="a" * 64, model={"id": "t"}, output="{}", proposed_path=None)
    assert verify_decisions(w.records, w.checkpoint(), w.key.public_key(), "v2")["decisions"] == 1
    assert w.records[-1]["body"]["event"]["data"]["messages"][2]["role"] == role


@pytest.mark.parametrize("change", ["system_role", "unprefixed", "omitted", "tool_without_context"])
def test_decision_witness_rejects_unrecorded_channel_changes(change):
    w, c, ins, ctx, messages = external_witness()
    contexts = [ctx]
    if change == "system_role":
        messages[2]["role"] = "system"
    elif change == "unprefixed":
        messages[2]["content"] = c["external_context"]
    elif change == "omitted":
        messages.pop()
    else:
        contexts = []
    with pytest.raises(EvidenceError):
        w.append("decision", instruction=ins, contexts=contexts, policy=c["policy"], messages=messages,
                 rendered_prompt_sha256="a" * 64, model={"id": "t"}, output="{}", proposed_path=None)
