import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from handoff_witness.core import EvidenceError
from handoff_witness.decision import DecisionWitness, verify_decisions
from handoff_witness.steering import parse_action, task


def witness():
    w = DecisionWitness(session="test-session")
    c = task(0, "indirect")
    w.append("instruction", channel="user", text=c["base_instruction"], replaces=None)
    w.append("instruction", channel="user", text=c["instruction"], replaces=0)
    d = w.append("decision", instruction=1, contexts=[], policy=c["policy"], messages=c["messages"],
                 rendered_prompt_sha256="a" * 64, model={"id": "test"}, output='{"action":"visit","target":"B"}',
                 proposed_path="/fixture/test/B")
    b = {"session": "browser", "request_id": "request", "method": "GET", "url": "http://localhost:1234/fixture/test/B",
         "body_sha256": "a" * 64, "headers_sha256": "b" * 64}
    w.append("binding", decision=d, binding=b)
    return w


def test_original_instruction_survives_later_denial():
    w = witness()
    w.append("instruction", channel="user", text="I never asked for this.", replaces=1)
    result = verify_decisions(w.records, w.checkpoint(), w.key.public_key(), w.session)
    assert result == {"instructions": 3, "decisions": 1, "bindings": 1,
                      "intent": "not_inferred", "legal_responsibility": "not_inferred"}
    assert w.records[2]["body"]["event"]["data"]["instruction"] == 1


@pytest.mark.parametrize("attack", ["instruction_edit", "origin_relabel", "output_edit", "binding_edit", "delete", "reorder", "duplicate", "truncate", "session_replay", "key_replace"])
def test_export_manipulations_rejected_with_retained_anchors(attack):
    w = witness()
    records, cp, key, session = copy.deepcopy(w.records), w.checkpoint(), w.key.public_key(), w.session
    if attack == "instruction_edit":
        records[1]["body"]["event"]["data"]["text"] = "Only use public sources"
    elif attack == "origin_relabel":
        records[1]["body"]["event"]["data"]["channel"] = "external"
    elif attack == "output_edit":
        records[2]["body"]["event"]["data"]["output"] = '{"action":"abstain"}'
    elif attack == "binding_edit":
        records[3]["body"]["event"]["data"]["binding"]["url"] += "-changed"
    elif attack == "delete":
        records.pop(1)
    elif attack == "reorder":
        records[0], records[1] = records[1], records[0]
    elif attack == "duplicate":
        records.insert(1, records[0])
    elif attack == "truncate":
        records.pop()
    elif attack == "session_replay":
        session = "another-session"
    else:
        key = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(EvidenceError):
        verify_decisions(records, cp, key, session)


def test_stale_valid_anchor_is_not_freshness_proof():
    w = witness()
    old_records, old_cp = copy.deepcopy(w.records), w.checkpoint()
    w.append("instruction", channel="user", text="A later instruction", replaces=1)
    with pytest.raises(EvidenceError):
        verify_decisions(old_records, w.checkpoint(), w.key.public_key(), w.session)
    # Known limitation: supplying the old checkpoint alongside the old log succeeds.
    assert verify_decisions(old_records, old_cp, w.key.public_key(), w.session)["instructions"] == 2


def test_dishonest_trusted_recorder_can_sign_a_coherent_fiction():
    # No browser or model has executed this history. Integrity still verifies:
    # signatures cannot authenticate the physical truth of trusted assertions.
    w = witness()
    assert verify_decisions(w.records, w.checkpoint(), w.key.public_key(), w.session)["decisions"] == 1


def test_binding_must_match_recorded_proposal_and_cannot_be_reused():
    w = witness()
    binding = w.records[-1]["body"]["event"]["data"]
    with pytest.raises(EvidenceError):
        w.append("binding", **binding)
    w.records.pop()
    wrong = copy.deepcopy(binding)
    wrong["binding"]["url"] = "http://localhost:1234/fixture/test/A"
    with pytest.raises(EvidenceError):
        w.append("binding", **wrong)


def test_decision_cannot_silently_omit_current_instruction_or_external_context():
    w = witness()
    d = copy.deepcopy(w.records[2]["body"]["event"]["data"])
    d["instruction"] = 0
    with pytest.raises(EvidenceError):
        w.append("decision", **d)
    d["instruction"] = 1
    d["contexts"] = [200]
    with pytest.raises(EvidenceError):
        w.append("decision", **d)


@pytest.mark.parametrize("value", ['{"action":"visit","target":"C"}', '{"action":"visit","target":"A","reason":"ok"}',
                                  '{"action":"visit","target":"A","target":"B"}', '```json\n{"action":"abstain"}\n```', '[]', 'null'])
def test_model_parser_fails_closed(value):
    assert parse_action(value) == "invalid"


def test_plan_balances_target_positions_and_changes_only_intended_channels():
    for index in range(12):
        benign, indirect, external = [task(index, v) for v in ("benign", "indirect", "external")]
        assert benign["policy"] == indirect["policy"] == external["policy"]
        assert benign["instruction"] == external["instruction"]
        assert indirect["instruction"].startswith(benign["instruction"])
        assert len(external["messages"]) == 3
    assert sum(task(i, "benign")["public"] == "A" for i in range(12)) == 6


def test_boolean_indices_rejected():
    c = task(0, "benign")
    w = DecisionWitness(session="test-session")
    w.append("instruction", channel="user", text=c["instruction"], replaces=None)
    with pytest.raises(EvidenceError):
        w.append("decision", instruction=False, contexts=[], policy=c["policy"], messages=c["messages"],
                 rendered_prompt_sha256="a" * 64, model={"id": "test"}, output="{}", proposed_path=None)
