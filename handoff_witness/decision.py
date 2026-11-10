"""Trusted-controller instruction history, distinct from intent and liability.

This records what a controller supplied to a model and what it proposed. It does
not authenticate a physical person or prove that a particular span caused output.
An independently retained checkpoint is required to detect suffix removal.
"""
import copy
import json
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .core import EvidenceError, ZERO, check_signature, digest, export_public, sign
from .approval import validate_binding

DOMAIN = "handoff-witness/decision/v1"


def validate_events(events):
    instructions, decisions, bound, contexts = {}, {}, set(), set()
    latest = None
    for seq, e in enumerate(events):
        if set(e) != {"kind", "data"} or not isinstance(e["data"], dict):
            raise EvidenceError("Invalid decision event")
        d = e["data"]
        if e["kind"] == "instruction":
            if set(d) != {"channel", "text", "replaces"} or d["channel"] != "user" or not isinstance(d["text"], str) or d["replaces"] != latest:
                raise EvidenceError("Instruction revision must extend the retained history")
            instructions[seq], latest = d, seq
        elif e["kind"] == "context":
            if set(d) != {"channel", "text"} or d["channel"] != "external" or not isinstance(d["text"], str):
                raise EvidenceError("Invalid external context")
            contexts.add(seq)
        elif e["kind"] == "decision":
            required = {"instruction", "contexts", "policy", "messages", "rendered_prompt_sha256", "model", "output", "proposed_path"}
            if set(d) != required or type(d["instruction"]) is not int or d["instruction"] != latest or latest is None:
                raise EvidenceError("Decision must bind the current instruction revision")
            if (not isinstance(d["contexts"], list) or any(type(i) is not int for i in d["contexts"])
                    or len(set(d["contexts"])) != len(d["contexts"]) or not set(d["contexts"]) <= contexts):
                raise EvidenceError("Unknown external context")
            expected = [{"role": "system", "content": d["policy"]},
                        {"role": "user", "content": instructions[latest]["text"]}]
            allowed = [expected]
            if d["contexts"]:
                # External text may arrive as a prefixed user turn (pilot v1) or in the
                # tool/retrieval role (pilot v2). The signed messages record which.
                content = "Untrusted retrieved page text:\n" + "\n".join(events[i]["data"]["text"] for i in d["contexts"])
                allowed = [expected + [{"role": role, "content": content}] for role in ("user", "tool")]
            if d["messages"] not in allowed or not isinstance(d["output"], str) or not isinstance(d["model"], dict):
                raise EvidenceError("Model input does not match recorded channels")
            if not isinstance(d["rendered_prompt_sha256"], str) or len(d["rendered_prompt_sha256"]) != 64:
                raise EvidenceError("Missing rendered prompt commitment")
            path = d["proposed_path"]
            if path is not None and (not isinstance(path, str) or not path.startswith("/fixture/") or "?" in path or "#" in path):
                raise EvidenceError("Invalid fixture proposal")
            decisions[seq] = d
        elif e["kind"] == "binding":
            if set(d) != {"decision", "binding"} or type(d["decision"]) is not int or d["decision"] not in decisions or d["decision"] in bound:
                raise EvidenceError("Unknown or reused decision")
            validate_binding(d["binding"])
            proposed = decisions[d["decision"]]["proposed_path"]
            parsed = urlsplit(d["binding"]["url"])
            if proposed is None or parsed.path != proposed or parsed.query or parsed.fragment or d["binding"]["method"] != "GET":
                raise EvidenceError("Execution binding differs from proposed operation")
            bound.add(d["decision"])
        else:
            raise EvidenceError("Unknown decision event kind")
    return {"instructions": len(instructions), "decisions": len(decisions), "bindings": len(bound),
            "intent": "not_inferred", "legal_responsibility": "not_inferred"}


class DecisionWitness:
    def __init__(self, key=None, session=None):
        self.key = key or Ed25519PrivateKey.generate()
        self.session = session or str(uuid.uuid4())
        self.records = []

    def append(self, kind, **data):
        event = copy.deepcopy({"kind": kind, "data": data})
        validate_events([r["body"]["event"] for r in self.records] + [event])
        body = {"domain": DOMAIN, "session": self.session, "seq": len(self.records),
                "previous": digest(self.records[-1]) if self.records else ZERO, "event": event}
        self.records.append({"body": body, "signature": sign(self.key, body)})
        return body["seq"]

    def checkpoint(self):
        body = {"domain": DOMAIN + "/checkpoint", "session": self.session,
                "count": len(self.records), "head": digest(self.records[-1]) if self.records else ZERO}
        return {"body": body, "signature": sign(self.key, body)}

    def save(self, directory):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "decision.json").write_text(json.dumps(self.records, indent=2) + "\n")
        (directory / "checkpoint.json").write_text(json.dumps(self.checkpoint(), indent=2) + "\n")
        (directory / "public.pem").write_bytes(export_public(self.key.public_key()))


def verify_decisions(records, checkpoint, trusted_key, expected_session):
    try:
        if set(checkpoint) != {"body", "signature"}:
            raise EvidenceError("Invalid decision checkpoint")
        c = checkpoint["body"]
        check_signature(trusted_key, c, checkpoint["signature"])
        if set(c) != {"domain", "session", "count", "head"} or c["domain"] != DOMAIN + "/checkpoint" or c["session"] != expected_session or type(c["count"]) is not int or c["count"] != len(records):
            raise EvidenceError("Checkpoint/session mismatch")
        previous, events = ZERO, []
        for seq, r in enumerate(records):
            if set(r) != {"body", "signature"}:
                raise EvidenceError("Invalid decision envelope")
            b = r["body"]
            check_signature(trusted_key, b, r["signature"])
            if set(b) != {"domain", "session", "seq", "previous", "event"} or b["domain"] != DOMAIN or b["session"] != expected_session or type(b["seq"]) is not int or b["seq"] != seq or b["previous"] != previous:
                raise EvidenceError("Decision chain mismatch")
            previous = digest(r)
            events.append(b["event"])
        if previous != c["head"]:
            raise EvidenceError("Decision terminal mismatch")
        return validate_events(events)
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError("Malformed decision evidence") from exc
