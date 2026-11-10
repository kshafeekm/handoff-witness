"""Offline CDP transcript collector, not an authenticated live capture service.

Trusted harness records sent Page.navigate commands and received CDP messages.
Replies may arrive after request events: pre-index successful replies, but apply
control changes in capture order. No timing or page-provided actor inference.
"""
from collections import Counter
from urllib.parse import urldefrag

from .core import EvidenceError, Recorder, canonical, digest, verify


def required_text(value, name):
    if not isinstance(value, str) or not value:
        raise EvidenceError(f"Missing or invalid {name}")
    return value


def collect(trace):
    if not isinstance(trace, list):
        raise EvidenceError("Trace must be an array")
    commands, replies = {}, {}
    # Every command/response ID is scoped to a distinct CDP attachment session.
    for index, row in enumerate(trace):
        if not isinstance(row, dict) or row.get("channel") not in {"harness", "send", "receive"}:
            raise EvidenceError(f"Invalid trace envelope at row {index}")
        if row["channel"] == "harness":
            if set(row) != {"channel", "controller"} or row["controller"] not in {"human", "agent"}:
                raise EvidenceError("Invalid harness control marker")
            continue
        required_text(row.get("session"), "session")
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
    bindings = {}
    for key, (index, command) in commands.items():
        if command.get("method") != "Page.navigate":
            continue
        reply_index, reply = replies.get(key, (-1, {}))
        result = reply.get("result", {})
        if not isinstance(result, dict) or reply_index <= index or "error" in reply or result.get("errorText") or result.get("isDownload"):
            continue
        params = command.get("params", {})
        if not isinstance(params, dict):
            raise EvidenceError("Invalid navigation parameters")
        url = required_text(params.get("url"), "navigation URL")
        # Same-document navigation lacks a new loader; never guess a request.
        if result.get("loaderId") and result.get("frameId"):
            loader = required_text(result["loaderId"], "loaderId")
            frame = required_text(result["frameId"], "frameId")
            if params.get("frameId", frame) != frame:
                continue
            bindings[key] = (index, loader, frame, urldefrag(url)[0])

    recorder, roots, chains, used, seen = Recorder(), {}, {}, set(), set()
    recorder.effect([], canonical({"kind": "cdp_import_manifest", "trace_sha256": digest(trace), "input_trust": "caller_supplied_not_authenticated"}).decode())
    rows, ignored = [], Counter()
    for index, row in enumerate(trace):
        if row["channel"] == "harness":
            recorder.handoff(row["controller"])
            continue
        session, message = row["session"], row["message"]
        if row["channel"] == "send":
            if message.get("method") == "Page.navigate":
                if "id" not in message:
                    raise EvidenceError("Navigation requires a command ID")
                # Recorded transport ownership, not a page's actor claim.
                if recorder.state.controller == "agent":
                    roots[(session, message["id"])] = recorder.input("agent")
            continue
        if message.get("method") != "Network.requestWillBeSent":
            ignored[message.get("method", "command_response")] += 1
            continue
        params = message.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("request"), dict):
            raise EvidenceError("Malformed requestWillBeSent")
        fingerprint = digest(row)
        if fingerprint in seen:
            ignored["duplicate_network_event"] += 1
            continue
        seen.add(fingerprint)
        request = params["request"]
        if not isinstance(params.get("initiator", {}), dict):
            raise EvidenceError("Invalid initiator metadata")
        url, method = required_text(request.get("url"), "request URL"), required_text(request.get("method"), "request method")
        if not url.startswith(("http://", "https://")):
            ignored["non_http"] += 1
            continue
        rid = required_text(params.get("requestId"), "requestId")
        key = (session, rid)
        loader, frame = params.get("loaderId"), params.get("frameId")
        old = chains.get(key)
        parents, reason = [], "no_authenticated_input_binding"
        if old:
            redirect = params.get("redirectResponse")
            if isinstance(redirect, dict) and redirect.get("url") == old["url"] and loader == old["loader"] and frame == old["frame"]:
                parents, reason = [old["event"]], "cdp_redirect_chain"
            else:
                reason = "request_id_reuse_without_matching_redirect"
        elif "redirectResponse" in params:
            reason = "redirect_ancestor_missing"
        elif params.get("type") == "Document" and method == "GET":
            candidates = [k for k, b in bindings.items() if k[0] == session and b[0] < index and b[1:] == (loader, frame, urldefrag(url)[0]) and k in roots and k not in used]
            if len(candidates) == 1:
                candidate = candidates[0]
                parents, reason = [roots[candidate]], "matched_agent_navigation"
                used.add(candidate)
            elif len(candidates) > 1:
                reason = "ambiguous_navigation_binding"
        if not parents and params.get("initiator", {}).get("type") == "script":
            reason = "script_input_origin_unresolved"
        # The signed effect preserves the source commitment and decision reason.
        effect = recorder.effect(parents, canonical({"source_sha256": fingerprint, "reason": reason, "session": session, "cdp_request_id": rid}).decode())
        event = recorder.request([effect], url, method=method, stage="browser_request_observed")
        chains[key] = {"event": event, "url": url, "loader": loader, "frame": frame}
        result = recorder.state.requests[-1]
        rows.append({**result, "trace_index": index, "reason": reason, "source_sha256": fingerprint})
    verify(recorder.records, recorder.checkpoint(), recorder.key.public_key())
    counts = Counter(r["attribution"] for r in rows)
    return recorder, {"kind": "offline_cdp_transcript_analysis", "input_trust": "caller_supplied_not_authenticated", "trace_sha256": digest(trace), "request_count": len(rows), "attribution_counts": dict(counts), "known_fraction": sum(r["attribution"] != "unknown" for r in rows) / len(rows) if rows else None, "ignored": dict(ignored), "requests": rows}
