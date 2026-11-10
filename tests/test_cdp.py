import copy
import json
from pathlib import Path

import pytest

from handoff_witness.cdp import collect
from handoff_witness.core import EvidenceError, verify


def trace():
    return json.loads((Path(__file__).parents[1] / "examples/cdp-handoff.json").read_text())


def test_redirect_survives_handoff_and_script_stays_unknown():
    recorder, report = collect(trace())
    assert [r["attribution"] for r in report["requests"]] == ["agent", "agent", "unknown"]
    assert report["requests"][1]["controller_at_dispatch"] == "human"
    assert report["known_fraction"] == 2 / 3
    assert verify(recorder.records, recorder.checkpoint(), recorder.key.public_key())["requests"][-1]["attribution"] == "unknown"


@pytest.mark.parametrize("mutation", ["missing_reply", "failed_reply", "same_document", "wrong_frame", "wrong_url", "wrong_session", "human_control", "download"])
def test_no_binding_without_exact_successful_command(mutation):
    rows = trace()
    if mutation == "missing_reply":
        rows.pop(5)
    elif mutation == "failed_reply":
        rows[5]["message"] = {"id": 1, "error": {"message": "failed"}}
    elif mutation == "same_document":
        del rows[5]["message"]["result"]["loaderId"]
    elif mutation == "wrong_frame":
        rows[5]["message"]["result"]["frameId"] = "different"
    elif mutation == "wrong_url":
        rows[1]["message"]["params"]["url"] = "https://other.invalid/"
    elif mutation == "wrong_session":
        rows[5]["session"] = "tab-b"
    elif mutation == "human_control":
        rows[0]["controller"] = "human"
    else:
        rows[5]["message"]["result"]["isDownload"] = True
    _, report = collect(rows)
    assert all(r["attribution"] == "unknown" for r in report["requests"])


def test_page_actor_claims_and_initiator_url_do_not_assign_human():
    rows = trace()
    rows[-1]["message"]["params"]["request"]["headers"] = {"X-Actor": "human"}
    rows[-1]["message"]["params"]["initiator"]["actor"] = "human"
    assert collect(rows)[1]["requests"][-1]["attribution"] == "unknown"


def test_request_id_reuse_is_not_a_redirect():
    rows = trace()
    del rows[4]["message"]["params"]["redirectResponse"]
    assert collect(rows)[1]["requests"][1]["attribution"] == "unknown"


def test_redirect_missing_ancestor_is_unknown():
    rows = trace()
    rows.pop(2)
    assert collect(rows)[1]["requests"][0]["attribution"] == "unknown"


def test_cross_tab_request_id_cannot_inherit():
    rows = trace()
    rows[4]["session"] = "tab-b"
    assert collect(rows)[1]["requests"][1]["attribution"] == "unknown"


def test_duplicate_event_deduplicated():
    rows = trace()
    rows.insert(3, copy.deepcopy(rows[2]))
    report = collect(rows)[1]
    assert report["request_count"] == 3
    assert report["ignored"]["duplicate_network_event"] == 1


def test_ambiguous_commands_not_arbitrarily_assigned():
    rows = trace()
    second = copy.deepcopy(rows[1])
    second["message"]["id"] = 2
    reply = copy.deepcopy(rows[5])
    reply["message"]["id"] = 2
    rows.insert(2, second)
    rows.append(reply)
    assert collect(rows)[1]["requests"][0]["reason"] == "ambiguous_navigation_binding"


def test_duplicate_command_rejected():
    rows = trace()
    rows.insert(2, rows[1])
    with pytest.raises(EvidenceError):
        collect(rows)


def test_missing_loader_does_not_match_unknown():
    rows = trace()
    del rows[2]["message"]["params"]["loaderId"]
    assert collect(rows)[1]["requests"][0]["attribution"] == "unknown"


def test_fragment_navigation_matches_network_url():
    rows = trace()
    rows[1]["message"]["params"]["url"] += "#section"
    assert collect(rows)[1]["requests"][0]["attribution"] == "agent"
