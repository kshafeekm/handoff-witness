import pytest

from handoff_witness.capture import INPUT_BINDING, OBSERVER_WORLD
from handoff_witness.core import EvidenceError, verify
from handoff_witness.lineage import RULES, V2_RULES, collect

PAGE = "page"
AGENT_URL = "hw-agent-" + "ab" * 16 + ".js"


def harness(controller):
    return {"channel": "harness", "controller": controller}


def send(i, method, params, session=PAGE):
    return {"channel": "send", "session": session, "message": {"id": i, "method": method, "params": params}}


def reply(i, result=None, session=PAGE):
    return {"channel": "receive", "session": session, "message": {"id": i, "result": result or {}}}


def event(method, params, session=PAGE, parent=None):
    row = {"channel": "receive", "session": session, "message": {"method": method, "params": params}}
    if parent:
        row["parent"] = parent
    return row


def request(rid, url, kind="Document", loader="L1", frame="F", initiator=None, session=PAGE, parent=None, **extra):
    params = {"requestId": rid, "loaderId": loader, "frameId": frame, "type": kind,
              "request": {"url": url, "method": "GET"}, "initiator": initiator or {"type": "other"}, **extra}
    return event("Network.requestWillBeSent", params, session, parent)


def committed(loader, frame="F", parent=None):
    frame_data = {"id": frame, "loaderId": loader}
    if parent:
        frame_data["parentId"] = parent
    return event("Page.frameNavigated", {"frame": frame_data})


def agent_page(url="http://t.test/a"):
    return [harness("agent"), send(1, "Page.navigate", {"url": url}), request("n1", url),
            reply(1, {"loaderId": "L1", "frameId": "F"}), committed("L1"),
            event("Runtime.executionContextCreated", {"context": {"id": 7, "name": OBSERVER_WORLD, "auxData": {"frameId": "F"}}})]


def human_page(url="http://t.test/h"):
    return [harness("human"), request("n1", url), committed("L1"),
            event("Runtime.executionContextCreated", {"context": {"id": 7, "name": OBSERVER_WORLD, "auxData": {"frameId": "F"}}})]


def script_request(rid="s1", stack=None):
    return request(rid, "http://t.test/effect", kind="Fetch", initiator={"type": "script", "stack": stack or {
        "callFrames": [{"url": "http://t.test/a"}], "parent": {"description": "setTimeout", "callFrames": []}}})


def labels(trace, rules=RULES):
    recorder, report = collect(trace, rules)
    verify(recorder.records, recorder.checkpoint(), recorder.key.public_key(), expected_session=recorder.session)
    return [r["attribution"] for r in report["requests"]]


def test_document_lineage_survives_handoff():
    assert labels(agent_page() + [harness("human"), script_request()]) == ["agent", "agent"]


def test_v1_rules_leave_page_script_unknown():
    assert labels(agent_page() + [harness("human"), script_request()], {"navigation", "redirect"}) == ["agent", "unknown"]


def test_exclusion_is_not_agent_never_human_and_can_be_disabled():
    trace = human_page() + [harness("agent"), script_request()]
    assert labels(trace) == ["not_agent", "not_agent"]
    assert labels(trace, set(RULES) - {"exclusion"}) == ["unknown", "unknown"]


def test_agent_script_stack_overrides_human_document():
    trace = human_page() + [harness("agent"), send(5, "Runtime.evaluate", {"expression": "x()\n//# sourceURL=" + AGENT_URL}),
                            reply(5, {"result": {}}), harness("human"),
                            script_request(stack={"callFrames": [{"url": "http://t.test/h"}],
                                                  "parent": {"callFrames": [{"url": AGENT_URL}]}})]
    assert labels(trace)[-1] == "agent"
    assert labels(trace, set(V2_RULES) - {"agent_script"})[-1] == "not_agent"
    # v3: the injection itself is a write to the document, so later page requests are contested.
    assert labels(trace, set(RULES) - {"agent_script"})[-1] == "mixed"


@pytest.mark.parametrize("forged", [AGENT_URL, "hw-agent-" + "0" * 32 + ".js"])
def test_page_cannot_forge_agent_script_lineage(forged):
    # No mediated Runtime.evaluate defined this sourceURL, so a page copying the format gains nothing.
    trace = human_page() + [script_request(stack={"callFrames": [{"url": forged}]})]
    assert labels(trace)[-1] == "not_agent"


def test_agent_command_under_human_control_is_not_a_root():
    trace = [harness("human"), send(1, "Page.navigate", {"url": "http://t.test/a"}), request("n1", "http://t.test/a"),
             reply(1, {"loaderId": "L1", "frameId": "F"})]
    assert labels(trace, {"navigation", "redirect"}) == ["unknown"]


def binding(session=PAGE):
    return event("Runtime.bindingCalled", {"name": INPUT_BINDING, "payload": "{}", "executionContextId": 7}, session)


def test_unexplained_trusted_input_taints_agent_document():
    trace = agent_page() + [harness("human"), binding(), script_request()]
    assert labels(trace)[-1] == "mixed"
    assert labels(trace, set(RULES) - {"input_taint"})[-1] == "agent"


def test_input_inside_mediated_pointer_command_is_agent():
    trace = agent_page() + [send(2, "Input.dispatchMouseEvent", {"type": "mousePressed", "x": 1, "y": 1}), reply(2),
                            send(3, "Input.dispatchMouseEvent", {"type": "mouseReleased", "x": 1, "y": 1}), binding(), reply(3),
                            harness("human"), script_request()]
    assert labels(trace)[-1] == "agent"


def test_worker_requests_inherit_creating_document():
    trace = agent_page() + [event("Target.attachedToTarget", {"sessionId": "w1", "targetInfo": {"type": "worker"}}),
                            harness("human"),
                            request("w-r", "http://t.test/effect", kind="Fetch", session=PAGE + "/w1", parent=PAGE,
                                    initiator={"type": "script"}, loader=None, frame=None)]
    assert labels(trace)[-1] == "agent"
    assert labels(trace, set(RULES) - {"worker"})[-1] == "unknown"


def test_renderer_navigation_inherits_requesting_document():
    trace = agent_page() + [harness("human"),
                            event("Page.frameRequestedNavigation", {"frameId": "F", "url": "http://t.test/next", "reason": "metaTagRefresh"}),
                            request("n2", "http://t.test/next", loader="L2")]
    assert labels(trace)[-1] == "agent"
    # Without the rule the same navigation looks browser-initiated: exclusion mislabels it.
    assert labels(trace, set(RULES) - {"renderer_navigation"})[-1] == "not_agent"


def test_child_frame_first_navigation_uses_parent_document():
    trace = agent_page() + [event("Page.frameAttached", {"frameId": "C", "parentFrameId": "F"}), harness("human"),
                            event("Page.frameRequestedNavigation", {"frameId": "C", "url": "http://t.test/frame", "reason": "initialFrameNavigation"}),
                            request("c1", "http://t.test/frame", loader="LC", frame="C", initiator={"type": "parser"}),
                            committed("LC", "C", parent="F"),
                            request("c2", "http://t.test/effect", kind="Fetch", loader="LC", frame="C", initiator={"type": "script"})]
    assert labels(trace)[-2:] == ["agent", "agent"]


def test_unknown_rule_and_bad_envelope_rejected():
    with pytest.raises(EvidenceError):
        collect([], {"telepathy"})
    with pytest.raises(EvidenceError):
        collect([{"channel": "page-claims-human"}])


# --- v3: state lineage -------------------------------------------------------

def human_reload(rid="n2", url="http://t.test/h", loader="L2"):
    """A human-turn navigation to a fresh document, then one script request from it."""
    return [harness("human"), request(rid, url, loader=loader), committed(loader),
            request("s1", "http://t.test/effect", kind="Fetch", loader=loader, initiator={"type": "script", "stack": {
                "callFrames": [{"url": url}]}})]


def stored(local=True, origin="http://t.test"):
    return event("DOMStorage.domStorageItemAdded", {"storageId": {"securityOrigin": origin, "isLocalStorage": local},
                                                    "key": "k", "newValue": "secret"})


def test_request_lineage_alone_exonerates_a_storage_relay():
    trace = agent_page() + [stored()] + human_reload()
    assert labels(trace, V2_RULES) == ["agent", "not_agent", "not_agent"]


@pytest.mark.parametrize("local", [True, False])
def test_agent_storage_write_taints_later_documents_of_that_origin(local):
    trace = agent_page() + [stored(local)] + human_reload()
    # The navigation request is still not_agent; what the new document then does is contested.
    assert labels(trace, set(RULES) - {"state_host"}) == ["agent", "not_agent", "mixed"]
    # A write to an origin with no matching live document is charged to every live document.
    other = agent_page() + [stored(local, "http://other.test")] + human_reload(url="http://other.test/h")
    assert labels(other, set(RULES) - {"state_host"}) == ["agent", "not_agent", "mixed"]
    cross = agent_page() + [stored(local)] + human_reload(url="http://elsewhere.test/h")
    assert labels(cross, set(RULES) - {"state_host"}) == ["agent", "not_agent", "not_agent"]


def test_human_storage_write_does_not_taint():
    trace = human_page() + [stored()] + human_reload()
    assert labels(trace) == ["not_agent", "not_agent", "not_agent"]


def cookie_set(rid="n1", header="sid=1; Path=/; HttpOnly"):
    return event("Network.responseReceivedExtraInfo", {"requestId": rid, "statusCode": 200, "headers": {"Set-Cookie": header}})


def cookie_sent(rid="n2", name="sid", domain="t.test", blocked=()):
    return event("Network.requestWillBeSentExtraInfo", {"requestId": rid, "headers": {"Cookie": name + "=1"}, "associatedCookies": [
        {"cookie": {"name": name, "domain": domain, "path": "/", "value": "1"}, "blockedReasons": list(blocked)}]})


def test_cookie_set_by_agent_response_taints_what_follows_a_request_carrying_it():
    rules = set(RULES) - {"state_host"}
    trace = agent_page() + [cookie_set()] + human_reload() + [cookie_sent()]  # extra-info order is not causal
    assert labels(trace, rules) == ["agent", "not_agent", "mixed"]
    assert labels(trace, V2_RULES) == ["agent", "not_agent", "not_agent"]
    blocked = agent_page() + [cookie_set()] + human_reload() + [cookie_sent(blocked=["SameSiteStrict"])]
    assert labels(blocked, rules) == ["agent", "not_agent", "not_agent"]
    # A different cookie that the human's own response set is explained, and does not taint.
    earlier = [harness("human"), request("n0", "http://t.test/h0", loader="L0"), committed("L0"), cookie_set("n0", "theme=1")]
    other_name = earlier + agent_page() + [cookie_set()] + human_reload() + [cookie_sent(name="theme")]
    assert labels(other_name, rules) == ["not_agent", "agent", "not_agent", "not_agent"]
    other_host = agent_page() + [cookie_set()] + human_reload() + [cookie_sent(domain="elsewhere.test")]
    assert labels(other_host, rules) == ["agent", "not_agent", "not_agent"]
    declared = agent_page() + [cookie_set(header="sid=1; Domain=.elsewhere.test")] + human_reload() + [cookie_sent(domain=".elsewhere.test")]
    assert labels(declared, rules) == ["agent", "not_agent", "mixed"]


def test_cookie_conditioned_redirect_is_contested():
    hop = request("n2", "http://t.test/effect", loader="L2", redirectResponse={"status": 302, "url": "http://t.test/h"})
    trace = agent_page() + [cookie_set(), harness("human"), request("n2", "http://t.test/h", loader="L2"), cookie_sent(), hop]
    assert labels(trace, set(RULES) - {"state_host"}) == ["agent", "not_agent", "mixed"]
    assert labels(trace, V2_RULES) == ["agent", "not_agent", "not_agent"]


def test_subresource_carrying_agent_cookie_taints_its_document_not_itself():
    sub = request("s0", "http://t.test/api", kind="Fetch", loader="L2", initiator={"type": "script", "stack": {"callFrames": [{"url": "http://t.test/h"}]}})
    trace = agent_page() + [cookie_set(), harness("human"), request("n2", "http://t.test/h", loader="L2"), committed("L2"), sub,
                            cookie_sent("s0"), request("s1", "http://t.test/effect", kind="Fetch", loader="L2",
                                                       initiator={"type": "script", "stack": {"callFrames": [{"url": "http://t.test/h"}]}})]
    assert labels(trace, set(RULES) - {"state_host"}) == ["agent", "not_agent", "not_agent", "mixed"]


def sw_attached(session="sw1", url="http://t.test/sw.js"):
    return event("Target.attachedToTarget", {"sessionId": session, "waitingForDebugger": True,
                                             "targetInfo": {"type": "service_worker", "url": url}})


def sw_request(session="sw1"):
    return request("sw-r", "http://t.test/effect", kind="Fetch", session=PAGE + "/" + session, parent=PAGE,
                   initiator={"type": "script"}, loader="", frame=None)


def test_service_worker_requests_inherit_the_registering_document():
    trace = agent_page() + [sw_attached()] + human_reload() + [sw_attached("sw2"), sw_request("sw2")]
    recorder, report = collect(trace, set(RULES) - {"state_host"})
    assert [r["attribution"] for r in report["requests"]] == ["agent", "not_agent", "mixed", "agent"]
    assert report["requests"][-1]["reason"] == "service_worker_lineage"
    assert report["requests"][2]["state_taint"] and not report["requests"][1]["state_taint"]
    assert labels(trace, V2_RULES) == ["agent", "not_agent", "not_agent", "unknown"]
    assert labels(trace, V2_RULES + ("service_worker",)) == ["agent", "not_agent", "not_agent", "agent"]


def test_service_worker_registered_under_human_control_is_not_agent():
    trace = human_page() + [sw_attached()] + human_reload() + [sw_request()]
    assert labels(trace) == ["not_agent", "not_agent", "not_agent", "not_agent"]


def test_host_taint_covers_unobserved_writes_on_the_same_host_only():
    rules = set(V2_RULES) | {"state_host"}
    assert labels(agent_page() + human_reload(), rules) == ["agent", "not_agent", "mixed"]
    assert labels(agent_page() + human_reload(), set(RULES) - {"state_host"}) == ["agent", "not_agent", "not_agent"]
    assert labels(agent_page() + human_reload(url="http://elsewhere.test/h"), rules) == ["agent", "not_agent", "not_agent"]
    assert labels(human_page() + human_reload(), rules) == ["not_agent", "not_agent", "not_agent"]


def test_state_rules_never_turn_unknown_into_a_label():
    trace = agent_page() + [stored(), cookie_set()] + human_reload() + [cookie_sent()]
    assert labels(trace, set(RULES) - {"exclusion"}) == ["agent", "unknown", "unknown"]


def test_state_rules_never_emit_human_or_remove_agent_roots():
    trace = agent_page() + [stored(), cookie_set(), sw_attached()] + human_reload() + [cookie_sent(), sw_request()]
    recorder, report = collect(trace)
    assert all(r["attribution"] in {"agent", "not_agent", "mixed", "unknown"} for r in report["requests"])
    before = labels(trace, V2_RULES + ("service_worker",))
    after = [r["attribution"] for r in report["requests"]]
    assert all(b == a or (b, a) == ("not_agent", "mixed") for b, a in zip(before, after))


def test_reduced_trace_gives_the_same_report_and_holds_no_values():
    from handoff_witness.capture import STATE_EVENTS, reduce_state_event
    from handoff_witness.core import canonical
    trace = agent_page() + [stored(), cookie_set()] + human_reload() + [cookie_sent()]
    reduced = [{**row, "message": {**row["message"], "params": reduce_state_event(row["message"]["method"], row["message"]["params"])}}
               if row.get("message", {}).get("method") in STATE_EVENTS else row for row in trace]
    assert b"secret" not in canonical(reduced) and b"sid=1" not in canonical(reduced)
    assert [r["attribution"] for r in collect(reduced)[1]["requests"]] == [r["attribution"] for r in collect(trace)[1]["requests"]]


def test_cookie_taint_is_transitive_through_a_human_request():
    # Agent sets sid; a human request carries sid and its response sets tok; a later request carries only tok.
    rules = set(RULES) - {"state_host"}
    trace = agent_page() + [cookie_set(), harness("human"), request("n2", "http://t.test/h", loader="L2"), cookie_sent("n2"),
                            cookie_set("n2", "tok=1"), committed("L2"), request("n3", "http://t.test/h2", loader="L3"),
                            cookie_sent("n3", name="tok"), committed("L3"),
                            request("s1", "http://t.test/effect", kind="Fetch", loader="L3",
                                    initiator={"type": "script", "stack": {"callFrames": [{"url": "http://t.test/h2"}]}})]
    assert labels(trace, rules) == ["agent", "not_agent", "not_agent", "mixed"]


def test_carried_cookie_without_an_observed_setter_is_charged_to_documents_of_its_domain():
    rules = set(RULES) - {"state_host"}
    assert labels(agent_page() + human_reload() + [cookie_sent()], rules) == ["agent", "not_agent", "mixed"]
    assert labels(human_page() + human_reload() + [cookie_sent()], rules) == ["not_agent", "not_agent", "not_agent"]
    elsewhere = agent_page() + human_reload(url="http://elsewhere.test/h") + [cookie_sent(domain="elsewhere.test")]
    assert labels(elsewhere, rules) == ["agent", "not_agent", "not_agent"]
    parent_domain = agent_page("http://a.t.test/a") + human_reload(url="http://b.t.test/h") + [cookie_sent(domain=".t.test")]
    assert labels(parent_domain, rules) == ["agent", "not_agent", "mixed"]
