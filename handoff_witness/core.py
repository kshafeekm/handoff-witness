"""Signed causal event records and an offline, externally anchored verifier.

The recorder is a trusted component in this model. Signatures authenticate its
statements, not their physical truth. Browser adapters must establish provenance.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ACTORS = {"human", "agent"}
ZERO = "0" * 64
DOMAIN = "handoff-witness/v1"


class EvidenceError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sign(key, value):
    return base64.b64encode(key.sign(canonical(value))).decode()


def check_signature(key, value, signature):
    try:
        key.verify(base64.b64decode(signature, validate=True), canonical(value))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise EvidenceError("Invalid signature") from exc


def export_public(key):
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


EXCLUSION_BASES = {"browser_initiated_without_mediated_command", "trusted_input_without_mediated_command"}


def classify(roots):
    """Map recorded root actors to an attribution label.

    "unmediated" roots come from exclusion: an observed cause that no command on
    the mediated agent channel explains. Their label is "not_agent", never
    "human": exclusion is sound only if every agent action uses that channel.
    """
    if not roots or "unknown" in roots:
        return "unknown"
    if roots == {"unmediated"}:
        return "not_agent"
    if "agent" in roots:
        return "agent" if roots == {"agent"} else "mixed"
    return "human" if roots == {"human"} else "not_agent"


class State:
    """Validate semantics and propagate asserted causal roots without timing inference."""

    def __init__(self):
        self.controller = None
        self.epoch = 0
        self.roots = {}
        self.requests = []
        self.request_ids = set()

    def apply(self, event):
        kind, data, eid = event["kind"], event["data"], event["id"]
        if not isinstance(eid, str) or not eid or eid in self.roots:
            raise EvidenceError("Invalid or duplicate event id")
        if not isinstance(data, dict):
            raise EvidenceError("Event data must be an object")
        parents = data.get("parents", [])
        if not isinstance(parents, list) or any(not isinstance(p, str) or p not in self.roots for p in parents):
            raise EvidenceError("Unknown or forward causal parent")
        if len(set(parents)) != len(parents):
            raise EvidenceError("Duplicate causal parent")
        if kind == "handoff":
            if set(data) != {"controller", "epoch"} or data["controller"] not in ACTORS or type(data["epoch"]) is not int or data["epoch"] != self.epoch + 1:
                raise EvidenceError("Invalid handoff")
            self.controller, self.epoch = data["controller"], data["epoch"]
            roots = {"unknown"}  # Control ownership alone is never causal evidence.
        elif kind == "input":
            if set(data) != {"actor", "epoch"} or data["actor"] not in ACTORS or data["actor"] != self.controller or type(data["epoch"]) is not int or data["epoch"] != self.epoch:
                raise EvidenceError("Input channel does not match active control epoch")
            roots = {data["actor"]}
        elif kind == "exclusion":
            if set(data) != {"basis", "epoch"} or data["basis"] not in EXCLUSION_BASES or type(data["epoch"]) is not int or data["epoch"] != self.epoch:
                raise EvidenceError("Invalid exclusion root")
            roots = {"unmediated"}
        elif kind in {"effect", "request"}:
            required = {"parents", "label"} if kind == "effect" else {"parents", "request_id", "method", "url", "stage"}
            if set(data) != required:
                raise EvidenceError("Unexpected event fields")
            roots = set().union(*(self.roots[p] for p in parents)) if parents else {"unknown"}
            if kind == "effect" and not isinstance(data["label"], str):
                raise EvidenceError("Invalid effect label")
            if kind == "request":
                if not isinstance(data["request_id"], str) or not data["request_id"] or data["request_id"] in self.request_ids:
                    raise EvidenceError("Duplicate or invalid request id")
                if not isinstance(data["method"], str) or not data["method"] or not isinstance(data["url"], str) or not data["url"].startswith(("http://", "https://")) or data["stage"] not in {"dispatch_observed", "receiver_observed", "browser_request_observed"}:
                    raise EvidenceError("Invalid request metadata")
                self.request_ids.add(data["request_id"])
                self.requests.append({"request_id": data["request_id"], "url": data["url"], "method": data["method"], "attribution": classify(roots), "roots": sorted(roots), "controller_at_dispatch": self.controller, "authorization": "not_evaluated", "stage": data["stage"]})
        else:
            raise EvidenceError("Unknown event kind")
        self.roots[eid] = roots


class Recorder:
    def __init__(self, key=None, session=None):
        self.key = key or Ed25519PrivateKey.generate()
        self.session = session or str(uuid.uuid4())
        self.records = []
        self.state = State()

    def append(self, kind, **data):
        event = {"domain": DOMAIN, "session": self.session, "seq": len(self.records), "id": str(uuid.uuid4()), "previous": digest(self.records[-1]) if self.records else ZERO, "kind": kind, "data": data}
        self.state.apply(event)
        self.records.append({"event": event, "signature": sign(self.key, event)})
        return event["id"]

    def handoff(self, controller):
        return self.append("handoff", controller=controller, epoch=self.state.epoch + 1)

    def input(self, actor):
        return self.append("input", actor=actor, epoch=self.state.epoch)

    def exclusion(self, basis):
        """Root for an observed cause that the mediated agent channel does not explain."""
        return self.append("exclusion", basis=basis, epoch=self.state.epoch)

    def effect(self, parents, label="scheduled"):
        return self.append("effect", parents=parents, label=label)

    def request(self, parents, url, method="GET", request_id=None, stage="dispatch_observed"):
        return self.append("request", parents=parents, url=url, method=method, request_id=request_id or str(uuid.uuid4()), stage=stage)

    def checkpoint(self):
        body = {"domain": DOMAIN + "/checkpoint", "session": self.session, "count": len(self.records), "head": digest(self.records[-1]) if self.records else ZERO}
        return {"checkpoint": body, "signature": sign(self.key, body)}

    def save(self, directory):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "events.jsonl").write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in self.records))
        (directory / "checkpoint.json").write_text(json.dumps(self.checkpoint(), indent=2) + "\n")
        (directory / "recorder-public.pem").write_bytes(export_public(self.key.public_key()))


def verify(records, checkpoint, trusted_key, *, expected_session=None):
    """Caller supplies independently trusted key AND retained terminal checkpoint.

    A checkpoint delivered only alongside the log is not evidence of freshness.
    Pass expected_session when one key may sign more than one session.
    """
    try:
        if not isinstance(trusted_key, Ed25519PublicKey):
            raise EvidenceError("Expected an Ed25519 trust anchor")
        if set(checkpoint) != {"checkpoint", "signature"}:
            raise EvidenceError("Invalid checkpoint envelope")
        body = checkpoint["checkpoint"]
        check_signature(trusted_key, body, checkpoint["signature"])
        if set(body) != {"domain", "session", "count", "head"} or body["domain"] != DOMAIN + "/checkpoint" or type(body["count"]) is not int or body["count"] != len(records):
            raise EvidenceError("Checkpoint count or schema mismatch")
        if expected_session is not None and body["session"] != expected_session:
            raise EvidenceError("Checkpoint session differs from expected session")
        previous, state = ZERO, State()
        for seq, record in enumerate(records):
            if set(record) != {"event", "signature"}:
                raise EvidenceError("Invalid record envelope")
            event = record["event"]
            if set(event) != {"domain", "session", "seq", "id", "previous", "kind", "data"}:
                raise EvidenceError("Invalid event schema")
            check_signature(trusted_key, event, record["signature"])
            if event["domain"] != DOMAIN or event["session"] != body["session"] or type(event["seq"]) is not int or event["seq"] != seq or event["previous"] != previous:
                raise EvidenceError("Broken sequence, session, or hash chain")
            state.apply(event)
            previous = digest(record)
        if previous != body["head"]:
            raise EvidenceError("Terminal checkpoint mismatch")
        return {"integrity": "verified_against_supplied_anchors", "session": body["session"], "event_count": len(records), "requests": state.requests}
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError("Malformed evidence") from exc
