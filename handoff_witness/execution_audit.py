"""Anchored execution journal linking approval, reservation, and broker observations.

Signatures authenticate a trusted broker's statements, not an independent remote
witness. Keys and terminal checkpoint must be supplied through trusted channels.
"""
import json
import threading
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .approval import DOMAIN as APPROVAL_DOMAIN, validate_binding, verify_bundle
from .core import EvidenceError, ZERO, canonical, check_signature, digest, export_public, sign

DOMAIN = "handoff-witness/execution/v2"


def reservation_body(receipt):
    if not isinstance(receipt, dict) or set(receipt) != {"reservation", "signature"}:
        raise EvidenceError("Invalid reservation envelope")
    body = receipt["reservation"]
    if not isinstance(body, dict) or set(body) != {"domain", "approval_id", "binding", "approval_sha256", "status", "reserved_at"}:
        raise EvidenceError("Invalid reservation schema")
    if body["domain"] != APPROVAL_DOMAIN + "/reservation" or body["status"] != "reserved_for_dispatch":
        raise EvidenceError("Invalid reservation domain or status")
    if not isinstance(body["approval_id"], str) or not body["approval_id"] or type(body["reserved_at"]) is not int:
        raise EvidenceError("Invalid reservation identity or time")
    validate_binding(body["binding"])
    return body


class ExecutionState:
    def __init__(self, session):
        self.session = session
        self.requests = {}
        self.approval_ids = set()

    def apply(self, kind, data):
        if not isinstance(data, dict):
            raise EvidenceError("Invalid event payload")
        if kind == "reserved":
            if set(data) != {"receipt"}:
                raise EvidenceError("Invalid reserved event")
            body = reservation_body(data["receipt"])
            binding = body["binding"]
            request_id = binding["request_id"]
            if binding["session"] != self.session or request_id in self.requests or body["approval_id"] in self.approval_ids:
                raise EvidenceError("Reservation session mismatch or replay")
            self.approval_ids.add(body["approval_id"])
            self.requests[request_id] = {"binding": binding, "approval_id": body["approval_id"], "stage": "reserved"}
            return
        required = {"request_id"}
        if kind == "attempt_started":
            required |= {"addresses"}
        elif kind == "response_headers_received":
            required |= {"status", "peer"}
        elif kind == "relay_prepared":
            required |= {"status", "body_sha256"}
        elif kind == "attempt_failed":
            required |= {"error_type"}
        elif kind != "attempt_started":
            raise EvidenceError("Unknown execution event")
        if kind == "attempt_started" and (not isinstance(data["addresses"], list) or any(not isinstance(a, str) or not a for a in data["addresses"])):
            raise EvidenceError("Invalid pinned address list")
        if set(data) != required or not isinstance(data["request_id"], str) or data["request_id"] not in self.requests:
            raise EvidenceError("Missing reservation or invalid event schema")
        state = self.requests[data["request_id"]]
        allowed = {"attempt_started": {"reserved"}, "response_headers_received": {"attempt_started"},
                   "relay_prepared": {"response_headers_received"}, "attempt_failed": {"attempt_started", "response_headers_received"}}
        if state["stage"] not in allowed[kind]:
            raise EvidenceError("Invalid execution lifecycle transition")
        if "status" in data and (type(data["status"]) is not int or not 100 <= data["status"] <= 599):
            raise EvidenceError("Invalid HTTP response status")
        if kind == "relay_prepared":
            expected = 502 if 300 <= state["upstream_status"] < 400 else state["upstream_status"]
            if data["status"] != expected:
                raise EvidenceError("Relay status does not match upstream policy")
            value = data["body_sha256"]
            if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise EvidenceError("Invalid relay body digest")
            state.update(relay_status=data["status"], relay_body_sha256=value)
        if kind == "response_headers_received":
            state["upstream_status"] = data["status"]
        if kind == "attempt_failed":
            if not isinstance(data["error_type"], str) or not data["error_type"]:
                raise EvidenceError("Invalid error classification")
            state["error_type"] = data["error_type"]
        if kind == "attempt_started":
            state["addresses"] = data["addresses"]
        if kind == "response_headers_received":
            if data["peer"] is not None and data["peer"] not in state["addresses"]:
                raise EvidenceError("Contacted peer was not a pinned address")
            state["peer"] = data["peer"]
        state["stage"] = kind


class ExecutionJournal:
    def __init__(self, session, key=None):
        if not isinstance(session, str) or not session:
            raise EvidenceError("Execution session required")
        self.session, self.key = session, key or Ed25519PrivateKey.generate()
        self.records = []
        self._state = ExecutionState(session)
        self._lock = threading.Lock()

    def append(self, kind, **data):
        data = json.loads(canonical(data))
        with self._lock:
            event = {"domain": DOMAIN, "session": self.session, "seq": len(self.records),
                     "previous": digest(self.records[-1]) if self.records else ZERO,
                     "kind": kind, "data": data}
            signature = sign(self.key, event)
            self._state.apply(kind, data)
            self.records.append({"event": event, "signature": signature})

    def snapshot(self):
        with self._lock:
            records = json.loads(canonical(self.records))
            body = {"domain": DOMAIN + "/checkpoint", "session": self.session,
                    "count": len(records), "head": digest(records[-1]) if records else ZERO}
            return records, {"checkpoint": body, "signature": sign(self.key, body)}

    def save(self, directory, gate):
        """Caller must stop dispatch and await broker jobs before final export."""
        records, checkpoint = self.snapshot()
        approval_ids = [r["event"]["data"]["receipt"]["reservation"]["approval_id"]
                        for r in records if r["event"]["kind"] == "reserved"]
        bundle = {"format": DOMAIN + "/bundle", "records": records,
                  "approvals": [gate.approval_evidence(i) for i in approval_ids]}
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=False)
        (directory / "bundle.json").write_text(json.dumps(bundle, indent=2) + "\n")
        (directory / "checkpoint.json").write_text(json.dumps(checkpoint, indent=2) + "\n")
        (directory / "executor-public.pem").write_bytes(export_public(self.key.public_key()))


def verify_execution(bundle, checkpoint, *, executor_key, gate_key, credential_id,
                     credential_public_key, rp_id, origin, expected_session=None):
    """Validate a retained journal checkpoint and independently pinned role keys.

    Pass expected_session when one executor key may sign more than one session.

    No claim of global completeness, physical intent, or remote execution follows.
    """
    try:
        if not isinstance(executor_key, Ed25519PublicKey) or not isinstance(gate_key, Ed25519PublicKey):
            raise EvidenceError("Ed25519 executor and gate trust anchors required")
        if set(bundle) != {"format", "records", "approvals"} or bundle["format"] != DOMAIN + "/bundle":
            raise EvidenceError("Invalid execution bundle")
        if not isinstance(bundle["records"], list) or not isinstance(bundle["approvals"], list):
            raise EvidenceError("Invalid execution collections")
        if set(checkpoint) != {"checkpoint", "signature"}:
            raise EvidenceError("Invalid execution checkpoint")
        body = checkpoint["checkpoint"]
        check_signature(executor_key, body, checkpoint["signature"])
        if set(body) != {"domain", "session", "count", "head"} or body["domain"] != DOMAIN + "/checkpoint" or not isinstance(body["session"], str) or not body["session"] or type(body["count"]) is not int or body["count"] != len(bundle["records"]):
            raise EvidenceError("Checkpoint schema or count mismatch")
        if expected_session is not None and body["session"] != expected_session:
            raise EvidenceError("Checkpoint session differs from expected session")
        approvals = {}
        for approval in bundle["approvals"]:
            document = approval["evidence"]["challenge_document"]
            approval_id = document["id"]
            if approval_id in approvals:
                raise EvidenceError("Duplicate approval evidence")
            verify_bundle(approval, gate_key=gate_key, credential_id=credential_id,
                          credential_public_key=credential_public_key, expected_binding=document["binding"],
                          rp_id=rp_id, origin=origin)
            approvals[approval_id] = approval
        previous, state = ZERO, ExecutionState(body["session"])
        for sequence, record in enumerate(bundle["records"]):
            if set(record) != {"event", "signature"}:
                raise EvidenceError("Invalid execution record")
            event = record["event"]
            if set(event) != {"domain", "session", "seq", "previous", "kind", "data"}:
                raise EvidenceError("Invalid execution event schema")
            check_signature(executor_key, event, record["signature"])
            if event["domain"] != DOMAIN or event["session"] != body["session"] or type(event["seq"]) is not int or event["seq"] != sequence or event["previous"] != previous:
                raise EvidenceError("Broken execution chain")
            if event["kind"] == "reserved":
                receipt = event["data"]["receipt"]
                reservation = reservation_body(receipt)
                check_signature(gate_key, reservation, receipt["signature"])
                approval = approvals.get(reservation["approval_id"])
                if approval is None or digest(approval) != reservation["approval_sha256"]:
                    raise EvidenceError("Reservation approval commitment mismatch")
                document = approval["evidence"]["challenge_document"]
                if document["binding"] != reservation["binding"]:
                    raise EvidenceError("Approval/reservation binding mismatch")
                if not approval["evidence"]["verified_at"] <= reservation["reserved_at"] < document["expires_at"]:
                    raise EvidenceError("Reservation outside approval validity")
            state.apply(event["kind"], event["data"])
            previous = digest(record)
        if previous != body["head"] or set(approvals) != state.approval_ids:
            raise EvidenceError("Checkpoint head or referenced approval set mismatch")
        requests = []
        for result in state.requests.values():
            requests.append({**result, "approval": "credential_verified", "initiation": "not_established",
                             "observation_source": "trusted_executor_statement",
                             "remote_execution": "not_independently_established"})
        return {"integrity": "verified_against_supplied_anchors", "session": body["session"],
                "event_count": len(bundle["records"]), "request_count": len(requests), "requests": requests}
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError("Malformed execution evidence") from exc
