import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from handoff_witness.benchmark import CASES, scenario
from handoff_witness.core import EvidenceError, Recorder, digest, sign, verify


@pytest.mark.parametrize("case", CASES)
def test_attribution(case):
    result, _ = scenario(*case)
    assert result["witness"] == result["expected"]


def fixture():
    return scenario(*CASES[0])[1]


@pytest.mark.parametrize("attack", ["edit", "delete", "reorder", "truncate", "replay", "session"])
def test_record_tampering(attack):
    r = fixture()
    records = copy.deepcopy(r.records)
    if attack == "edit":
        records[-1]["event"]["data"]["url"] = "https://changed.invalid/"
    elif attack == "delete":
        del records[1]
    elif attack == "reorder":
        records[1], records[2] = records[2], records[1]
    elif attack == "truncate":
        records.pop()
    elif attack == "replay":
        records.append(records[-1])
    else:
        records[-1]["event"]["session"] = "another-session"
    with pytest.raises(EvidenceError):
        verify(records, r.checkpoint(), r.key.public_key())


def test_wrong_trust_anchor():
    r = fixture()
    with pytest.raises(EvidenceError):
        verify(r.records, r.checkpoint(), Ed25519PrivateKey.generate().public_key())


def test_old_checkpoint_cannot_cover_new_log():
    r = Recorder()
    r.handoff("agent")
    old = r.checkpoint()
    r.input("agent")
    with pytest.raises(EvidenceError):
        verify(r.records, old, r.key.public_key())


def test_missing_parent_cannot_be_claimed():
    r = Recorder()
    with pytest.raises(EvidenceError):
        r.effect(["invented"])


def test_input_cannot_claim_inactive_controller():
    r = Recorder()
    r.handoff("agent")
    with pytest.raises(EvidenceError):
        r.input("human")


def test_signed_invalid_semantics_rejected():
    r = fixture()
    records = copy.deepcopy(r.records)
    event = records[-1]["event"]
    event["data"]["parents"] = ["invented"]
    records[-1]["signature"] = sign(r.key, event)
    checkpoint = r.checkpoint()
    checkpoint["checkpoint"]["head"] = digest(records[-1])
    checkpoint["signature"] = sign(r.key, checkpoint["checkpoint"])
    with pytest.raises(EvidenceError):
        verify(records, checkpoint, r.key.public_key())


def test_duplicate_request_rejected():
    r = Recorder()
    r.request([], "https://fixture.invalid", request_id="one")
    with pytest.raises(EvidenceError):
        r.request([], "https://fixture.invalid", request_id="one")


@pytest.mark.parametrize("records,checkpoint", [([], {}), ([None], {}), ([], {"checkpoint": {}, "signature": "!"})])
def test_malformed_evidence(records, checkpoint):
    with pytest.raises(EvidenceError):
        verify(records, checkpoint, Ed25519PrivateKey.generate().public_key())


def test_shared_key_requires_expected_session():
    shared = fixture().key
    a, b = Recorder(key=shared, session="session-a"), Recorder(key=shared, session="session-b")
    for r in (a, b):
        r.handoff("agent")
        r.request([r.input("agent")], "https://example.invalid/")
    assert verify(b.records, b.checkpoint(), shared.public_key())["session"] == "session-b"
    with pytest.raises(EvidenceError, match="expected session"):
        verify(b.records, b.checkpoint(), shared.public_key(), expected_session="session-a")
    assert verify(a.records, a.checkpoint(), shared.public_key(), expected_session="session-a")["session"] == "session-a"
