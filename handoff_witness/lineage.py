"""Offline lineage collector (v3) over a trusted CDP transcript.

Extends the v1 navigation/redirect collector (cdp.py) with rules that can be
switched off one at a time for ablation:

- navigation: a top-level document GET bound to one mediated Page.navigate.
- redirect: a redirect hop inherits its predecessor in the same request chain.
- agent_script: a request whose (async) initiator stack contains a frame from a
  script the mediated channel injected under an unguessable sourceURL.
- worker: requests from an auto-attached worker inherit the document that
  existed when the worker attached.
- document_lineage: script/parser-initiated requests and child-frame documents
  inherit the lineage of the document that issued them.
- renderer_navigation: a navigation the renderer requested (meta refresh, script,
  form submission, link) inherits the lineage of the requesting document.
- input_taint: trusted input observed in a document joins that document's
  lineage: agent pointer commands contribute agent roots, unexplained trusted
  input contributes an "unmediated" exclusion root (label mixed when combined).
- exclusion: a browser-initiated top-level navigation that no mediated command
  explains receives an "unmediated" root, labeled not_agent. This is sound only
  if every agent action uses the mediated channel (complete mediation) and no
  agent-written state is reachable (state isolation); the state rules below
  approximate the second condition.
- service_worker: requests from a service worker inherit the document that
  existed when a worker for that script URL first attached.
- state_write: observed writes by agent-rooted lineage taint later readers:
  a cookie set by a response taints what follows a request that carries it;
  a carried cookie that no observed response set (document.cookie raises no
  event) is charged to every document seen in its domain; DOM storage and a
  registered service worker taint documents of that origin; an injected agent
  script taints the document it ran in. Blind to IndexedDB and Cache writes
  and to anything server-side.
- state_host: every document on, and every response from, a host that agent
  lineage has contacted is tainted. Covers client state the events miss, by
  host name only (not registrable domain); blind to server-side state shared
  across hosts.

State rules only ever add agent roots: they turn not_agent into mixed and never
produce not_agent. Human-written state is not tracked, so an agent label does
not exclude human-written state. State present before capture has no lineage.

No rule reads scenario names, source labels, page-supplied actor claims, or
timing heuristics. The transcript and capture harness are trusted inputs.
"""
import re
from collections import Counter
from urllib.parse import urldefrag, urlsplit

from .capture import INPUT_BINDING, OBSERVER_WORLD, STATE_EVENTS, reduce_state_event
from .core import EvidenceError, Recorder, canonical, digest, verify

V2_RULES = ("navigation", "redirect", "agent_script", "worker", "document_lineage",
            "renderer_navigation", "input_taint", "exclusion")
STATE_RULES = ("service_worker", "state_write", "state_host")
RULES = V2_RULES + STATE_RULES
V1_RULES = frozenset({"navigation", "redirect"})
AGENT_SOURCE = re.compile(r"//# sourceURL=(hw-agent-[0-9a-f]{32}\.js)\s*$")


def _text(value, name):
    if not isinstance(value, str) or not value:
        raise EvidenceError(f"Missing or invalid {name}")
    return value


def _stack_urls(stack):
    """All script URLs in a CDP initiator stack, including async parents."""
    urls, depth = set(), 0
    while isinstance(stack, dict) and depth < 64:
        for frame in stack.get("callFrames", []) or []:
            if isinstance(frame, dict) and isinstance(frame.get("url"), str):
                urls.add(frame["url"])
        stack, depth = stack.get("parent"), depth + 1
    return urls


def _index(trace):
    commands, replies = {}, {}
    for index, row in enumerate(trace):
        if not isinstance(row, dict) or row.get("channel") not in {"harness", "send", "receive", "setup"}:
            raise EvidenceError(f"Invalid trace envelope at row {index}")
        if row["channel"] == "harness":
            if set(row) != {"channel", "controller"} or row["controller"] not in {"human", "agent"}:
                raise EvidenceError("Invalid harness control marker")
            continue
        _text(row.get("session"), "session")
        if row["channel"] == "setup":
            continue
        message = row.get("message")
        if not isinstance(message, dict):
            raise EvidenceError("Invalid CDP message")
        if "id" in message:
            if type(message["id"]) is not int:
                raise EvidenceError("CDP command ID must be an integer")
            key = (row["session"], message["id"])
            destination = commands if row["channel"] == "send" else replies
            if key in destination:
                raise EvidenceError("Duplicate command or response ID")
            destination[key] = (index, message)
    return commands, replies


def _origin(url):
    parts = urlsplit(url or "")
    return parts.scheme + "://" + parts.netloc, (parts.hostname or "").lower()


def _cookie_index(trace):
    """Cookie names each request chain carried, and which chains set each name.

    Extra-info events are not ordered against requestWillBeSent, so they are
    pooled per request chain instead of being paired with single redirect hops.
    """
    carried, writers = {}, {}
    for row in trace:
        message = row.get("message") if isinstance(row, dict) and row.get("channel") == "receive" else None
        if not isinstance(message, dict) or message.get("method") not in STATE_EVENTS[:2]:
            continue
        params = reduce_state_event(message["method"], message.get("params"))
        chain = (row.get("session"), params.get("requestId"))
        for item in params.get("associatedCookies") or []:
            cookie = item.get("cookie") or {}
            if isinstance(cookie.get("name"), str) and not item.get("blockedReasons"):
                carried.setdefault(chain, set()).add((str(cookie.get("domain") or "").lstrip(".").lower(), cookie["name"]))
        for cookie in params.get("setCookies") or []:
            if isinstance(cookie, dict) and isinstance(cookie.get("name"), str):
                entry = (chain, str(cookie.get("domain") or "").lstrip(".").lower() or None)
                if entry not in writers.setdefault(cookie["name"], []):
                    writers[cookie["name"]].append(entry)
    return carried, writers


def _succeeded(replies, key, index):
    reply_index, reply = replies.get(key, (-1, {}))
    result = reply.get("result", {})
    ok = isinstance(result, dict) and reply_index > index and "error" not in reply and not result.get("exceptionDetails")
    return ok, reply_index, result


def collect(trace, rules=RULES):
    rules = frozenset(rules)
    if not rules <= set(RULES):
        raise EvidenceError("Unknown lineage rule")
    if not isinstance(trace, list):
        raise EvidenceError("Trace must be an array")
    commands, replies = _index(trace)
    carried_cookies, cookie_writers = _cookie_index(trace)
    sw_on, state_on, host_on = "service_worker" in rules, "state_write" in rules, "state_host" in rules

    bindings, pointer_windows, scripts = {}, [], {}
    for key, (index, command) in commands.items():
        method, params = command.get("method"), command.get("params", {})
        if not isinstance(params, dict):
            raise EvidenceError("Invalid command parameters")
        ok, reply_index, result = _succeeded(replies, key, index)
        if method == "Page.navigate" and ok and not result.get("errorText") and not result.get("isDownload"):
            if result.get("loaderId") and result.get("frameId") and params.get("frameId", result["frameId"]) == result["frameId"]:
                bindings[key] = (index, result["loaderId"], result["frameId"], urldefrag(_text(params.get("url"), "navigation URL"))[0])
        elif method == "Input.dispatchMouseEvent" and params.get("type") == "mousePressed":
            # Pair the press with the matching release reply, if any, as one window.
            release = next((k for k, (i, c) in sorted(commands.items(), key=lambda kv: kv[1][0])
                            if k[0] == key[0] and i > index and c.get("method") == "Input.dispatchMouseEvent"
                            and c.get("params", {}).get("type") == "mouseReleased"), None)
            end = replies.get(release, (reply_index, None))[0] if release else reply_index
            pointer_windows.append((index, max(end, reply_index), key))
        elif method == "Runtime.evaluate" and ok:
            match = AGENT_SOURCE.search(params.get("expression", "") or "")
            if match:
                scripts[match.group(1)] = key

    recorder = Recorder()
    recorder.effect([], canonical({"kind": "cdp_lineage_import", "trace_sha256": digest(trace), "rules": sorted(rules),
                                   "input_trust": "caller_supplied_not_authenticated"}).decode())
    roots, used, chains, seen = {}, set(), {}, set()
    observer_contexts, frame_doc, frame_parent = {}, {}, {}
    doc_event, doc_inputs, pending_nav, worker_effect = {}, {}, {}, {}
    main_frame = None
    rows, ignored = [], Counter()
    # State lineage. Every stored source is an event whose roots include "agent".
    chain_events, chain_hosts, sw_effect, sw_sessions = {}, {}, {}, set()
    doc_origin, doc_host, doc_state, doc_scripts = {}, {}, {}, {}
    storage_taint, sw_taint, host_taint, host_docs = {}, {}, {}, {}

    def agent_rooted(events):
        return [e for e in dict.fromkeys(events) if "agent" in recorder.state.roots[e]]

    def state_parents(doc):
        sources = list(doc_state.get(doc, []))
        if state_on:
            sources += doc_scripts.get(doc, []) + storage_taint.get(doc_origin.get(doc), []) + sw_taint.get(doc_origin.get(doc), [])
        if host_on and doc_host.get(doc) in host_taint:
            sources.append(host_taint[doc_host[doc]])
        return sources

    def lineage_parents(doc, read=None):
        if doc is None or doc_event.get(doc) is None:
            return []
        state = state_parents(doc)
        if read is not None:
            read.extend(state)
        return list(dict.fromkeys([doc_event[doc]] + (list(doc_inputs.get(doc, [])) if "input_taint" in rules else []) + state))

    def request_state(chain, host):
        """Agent-rooted state this request may have carried to its server."""
        sources = []
        if state_on:
            for domain, name in sorted(carried_cookies.get(chain, ())):
                explained = False
                for writer, declared in cookie_writers.get(name, ()):
                    if writer in chain_events and (declared == domain or (declared is None and domain in chain_hosts[writer])):
                        # The writer's own lineage, and any agent state the writer itself carried.
                        sources += chain_events[writer] + chains.get(writer, {}).get("state", [])
                        explained = True
                if not explained:
                    # No observed response set this cookie: a script did (document.cookie raises
                    # no event) or it predates the capture. Charge every document seen in its domain.
                    sources += [e for h, docs in host_docs.items() if h == domain or h.endswith("." + domain)
                                for d in docs for e in lineage_parents(d)]
        if host_on and host in host_taint:
            sources.append(host_taint[host])
        return agent_rooted(sources)

    for index, row in enumerate(trace):
        channel = row["channel"]
        if channel == "harness":
            recorder.handoff(row["controller"])
            continue
        if channel == "setup":
            continue
        session, message = row["session"], row["message"]
        agent_turn = recorder.state.controller == "agent"
        if channel == "send":
            key = (session, message.get("id"))
            method = message.get("method")
            # Mediated-channel commands are agent roots (transport ownership, not page claims).
            if agent_turn and method == "Page.navigate":
                roots[key] = recorder.input("agent")
            elif agent_turn and method == "Input.dispatchMouseEvent" and message.get("params", {}).get("type") == "mousePressed":
                roots[key] = recorder.input("agent")
            elif agent_turn and method == "Runtime.evaluate" and key in scripts.values():
                roots[key] = recorder.input("agent")
                # Injected script can change the document and any state it can reach.
                for doc in dict.fromkeys(d for d in frame_doc.values() if d is not None):
                    if state_on:
                        doc_scripts.setdefault(doc, []).append(roots[key])
                    if host_on and doc_host.get(doc):
                        host_taint.setdefault(doc_host[doc], roots[key])
            continue
        method, params = message.get("method"), message.get("params")
        if method is None:
            ignored["command_response"] += 1
            continue
        if not isinstance(params, dict):
            raise EvidenceError("Malformed CDP event")
        if method == "Runtime.executionContextCreated":
            context = params.get("context", {})
            if context.get("name") == OBSERVER_WORLD:
                observer_contexts[(session, context.get("id"))] = (context.get("auxData") or {}).get("frameId")
            continue
        if method == "Page.frameAttached":
            frame_parent[params.get("frameId")] = params.get("parentFrameId")
            continue
        if method == "Page.frameNavigated":
            frame = params.get("frame", {})
            fid, loader = frame.get("id"), frame.get("loaderId")
            if not frame.get("parentId"):
                main_frame = fid
            else:
                frame_parent[fid] = frame["parentId"]
            frame_doc[fid] = loader
            doc_inputs.setdefault(loader, [])
            continue
        if method == "Page.frameRequestedNavigation":
            fid = params.get("frameId")
            # A new child frame's first navigation is requested by its parent document.
            requester = frame_parent.get(fid) if params.get("reason") == "initialFrameNavigation" or fid not in frame_doc else fid
            pending_nav[(fid, urldefrag(params.get("url", ""))[0])] = {
                "doc": frame_doc.get(requester), "reason": params.get("reason")}
            continue
        if method == "Runtime.bindingCalled":
            if params.get("name") != INPUT_BINDING:
                continue
            frame = observer_contexts.get((session, params.get("executionContextId")))
            doc = frame_doc.get(frame)
            window = next((w for w in pointer_windows if w[2][0] == session and w[0] < index <= w[1] and w[2] in roots), None)
            # Trusted input inside a mediated pointer command is the agent's; any
            # other trusted input is unexplained by the mediated channel.
            source = roots[window[2]] if window else recorder.exclusion("trusted_input_without_mediated_command")
            if doc is not None:
                doc_inputs.setdefault(doc, []).append(source)
                if window and host_on and "input_taint" in rules and doc_host.get(doc):
                    host_taint.setdefault(doc_host[doc], source)
            continue
        if method in STATE_EVENTS:
            if method.startswith("DOMStorage.") and state_on:
                origin = (params.get("storageId") or {}).get("securityOrigin")
                live = list(dict.fromkeys(d for d in frame_doc.values() if d is not None))
                # The event names an origin, not a frame: every live document of
                # that origin is a possible writer (all live documents if none match).
                writers = [d for d in live if doc_origin.get(d) == origin] or live
                known = storage_taint.setdefault(origin, [])
                known += [e for e in agent_rooted([e for d in writers for e in lineage_parents(d)]) if e not in known]
            elif not (state_on and method.startswith("Network.")):  # extra-info events were indexed up front
                ignored[method] += 1
            continue
        if method == "Target.attachedToTarget":
            info = params.get("targetInfo", {})
            if info.get("type") == "service_worker":
                if sw_on:
                    script = str(info.get("url") or "")
                    if script not in sw_effect:
                        # A restarted worker keeps the lineage of its first attachment.
                        sw_effect[script] = recorder.effect(lineage_parents(frame_doc.get(main_frame)), canonical(
                            {"kind": "service_worker_attached", "script_url": script}).decode())
                        if state_on:
                            sw_taint.setdefault(_origin(script)[0], []).extend(agent_rooted([sw_effect[script]]))
                    worker_effect[session + "/" + _text(params.get("sessionId"), "worker session")] = sw_effect[script]
                    sw_sessions.add(session + "/" + params["sessionId"])
            elif info.get("type") in {"worker", "shared_worker"}:
                child = session + "/" + _text(params.get("sessionId"), "worker session")
                parents = lineage_parents(frame_doc.get(main_frame)) if "worker" in rules else []
                worker_effect[child] = recorder.effect(parents, canonical({"kind": "worker_attached", "target_type": info.get("type")}).decode())
            continue
        if method != "Network.requestWillBeSent":
            ignored[method] += 1
            continue
        request = params.get("request")
        if not isinstance(request, dict):
            raise EvidenceError("Malformed requestWillBeSent")
        fingerprint = digest(row)
        if fingerprint in seen:
            ignored["duplicate_network_event"] += 1
            continue
        seen.add(fingerprint)
        url, http_method = _text(request.get("url"), "request URL"), _text(request.get("method"), "request method")
        if not url.startswith(("http://", "https://")):
            ignored["non_http"] += 1
            continue
        initiator = params.get("initiator", {})
        if not isinstance(initiator, dict):
            raise EvidenceError("Invalid initiator metadata")
        rid = _text(params.get("requestId"), "requestId")
        loader, frame, kind = params.get("loaderId"), params.get("frameId"), params.get("type")
        chain_key = (session, rid)
        old = chains.get(chain_key)
        parents, reason, read, inherited = [], "no_rule_applies", [], []
        host = _origin(url)[1]
        stack_agent = sorted(u for u in _stack_urls(initiator.get("stack")) if u in scripts)
        if old:
            redirect = params.get("redirectResponse")
            if "redirect" in rules and isinstance(redirect, dict) and redirect.get("url") == old["url"] and loader == old["loader"] and frame == old["frame"]:
                # State the earlier hops carried may have shaped the redirect itself.
                inherited = old["state"]
                read.extend(inherited)
                parents, reason = list(dict.fromkeys([old["event"]] + inherited)), "cdp_redirect_chain"
            else:
                reason = "request_id_reuse_without_redirect_rule"
        elif "redirectResponse" in params:
            reason = "redirect_ancestor_missing"
        elif kind == "Document" and http_method == "GET" and "navigation" in rules and any(
                k[0] == session and b[0] < index and b[1:] == (loader, frame, urldefrag(url)[0]) and k in roots and k not in used
                for k, b in bindings.items()):
            candidates = [k for k, b in bindings.items() if k[0] == session and b[0] < index
                          and b[1:] == (loader, frame, urldefrag(url)[0]) and k in roots and k not in used]
            if len(candidates) == 1:
                used.add(candidates[0])
                parents, reason = [roots[candidates[0]]], "matched_agent_navigation"
            else:
                reason = "ambiguous_navigation_binding"
        elif session in worker_effect:
            if session in sw_sessions:
                parents, reason = [worker_effect[session]], "service_worker_lineage"
            elif "worker" in rules:
                parents, reason = [worker_effect[session]], "worker_lineage"
            else:
                reason = "worker_rule_disabled"
        elif stack_agent and "agent_script" in rules:
            script_roots = [roots[scripts[u]] for u in stack_agent if scripts[u] in roots]
            parents, reason = script_roots, "agent_script_stack"
        elif kind == "Document" and (frame, urldefrag(url)[0]) in pending_nav and "renderer_navigation" in rules:
            requested = pending_nav.pop((frame, urldefrag(url)[0]))
            parents, reason = lineage_parents(requested["doc"], read), "renderer_navigation:" + str(requested["reason"])
        elif kind == "Document" and frame in frame_parent and frame != main_frame and "document_lineage" in rules:
            parents, reason = lineage_parents(frame_doc.get(frame_parent[frame]), read), "child_frame_document"
        elif kind != "Document" and initiator.get("type") in {"script", "parser"} and "document_lineage" in rules:
            parents, reason = lineage_parents(frame_doc.get(frame), read), "document_script_lineage"
        elif kind == "Document" and frame == main_frame or (kind == "Document" and main_frame is None and frame not in frame_parent):
            if "exclusion" in rules and initiator.get("type") == "other":
                parents, reason = [recorder.exclusion("browser_initiated_without_mediated_command")], "exclusion_unmediated_navigation"
            else:
                reason = "unmediated_navigation_unlabeled"
        elif initiator.get("type") == "script":
            reason = "script_input_origin_unresolved"
        if not parents and reason.startswith(("document_script", "child_frame", "renderer_navigation", "worker")):
            reason += ":lineage_unknown"
        effect = recorder.effect(parents, canonical({"source_sha256": fingerprint, "reason": reason, "session": session,
                                                     "cdp_request_id": rid}).decode())
        event = recorder.request([effect], url, method=http_method, stage="browser_request_observed")
        chain_events.setdefault(chain_key, []).append(event)
        chain_hosts.setdefault(chain_key, set()).add(host)
        # A request is not tainted by the state it carries; what answers it is.
        own = request_state(chain_key, host)
        state = list(dict.fromkeys(inherited + own))
        chains[chain_key] = {"event": event, "url": url, "loader": loader, "frame": frame, "state": state}
        if kind == "Document" and loader:
            doc_event[loader] = event
            doc_inputs.setdefault(loader, [])
            doc_state[loader] = list(state)
            doc_origin[loader], doc_host[loader] = _origin(url)
            if loader not in host_docs.setdefault(host, []):
                host_docs[host].append(loader)
        elif state and "parent" not in row and frame_doc.get(frame) is not None:
            # The response to a subresource request reaches the document that asked for it.
            known = doc_state.setdefault(frame_doc[frame], [])
            known += [e for e in state if e not in known]
        if host_on and "agent" in recorder.state.roots[event]:
            host_taint.setdefault(host, event)
        result = recorder.state.requests[-1]
        rows.append({**result, "trace_index": index, "reason": reason, "source_sha256": fingerprint,
                     "state_taint": bool(agent_rooted(read)),
                     "observer_session": "worker" if "parent" in row else "page"})
    verify(recorder.records, recorder.checkpoint(), recorder.key.public_key(), expected_session=recorder.session)
    counts = Counter(r["attribution"] for r in rows)
    return recorder, {"kind": "offline_cdp_lineage_analysis", "rules": sorted(rules),
                      "input_trust": "caller_supplied_not_authenticated", "trace_sha256": digest(trace),
                      "request_count": len(rows), "attribution_counts": dict(counts), "ignored": dict(ignored),
                      "requests": rows}
