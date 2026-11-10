"""Request-bound WebAuthn approval and persistent one-use dispatch reservation.

Trusted enrollment, relying-party UI, gate, database, clock, and executor remain
assumptions. A verified credential is not proof of human initiation or intent.
"""
import hashlib
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from urllib.parse import urlsplit

from webauthn import generate_authentication_options, options_to_json, verify_authentication_response
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement

from .core import EvidenceError, canonical, check_signature, digest, export_public, sign

DOMAIN = "handoff-witness/approval/v1"


class ApprovalError(EvidenceError):
    pass


def validate_binding(binding):
    fields = {"session", "request_id", "method", "url", "body_sha256", "headers_sha256"}
    if not isinstance(binding, dict) or set(binding) != fields:
        raise ApprovalError("Invalid request binding schema")
    if any(not isinstance(v, str) or not v for v in binding.values()):
        raise ApprovalError("Binding fields must be nonempty strings")
    parsed = urlsplit(binding["url"])
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ApprovalError("Binding requires an absolute HTTP(S) URL without credentials or fragment")
    if binding["method"] not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        raise ApprovalError("Unsupported request method")
    for field in ("body_sha256", "headers_sha256"):
        if len(binding[field]) != 64 or any(c not in "0123456789abcdef" for c in binding[field]):
            raise ApprovalError("Expected lowercase SHA-256 digest")


def challenge_bytes(document):
    return hashlib.sha256(canonical(document)).digest()


def verify_bundle(bundle, *, gate_key, credential_id, credential_public_key, expected_binding, rp_id, origin):
    """Offline verify evidence against externally pinned identities.

    Does not check current revocation, expiry, database replay state, or whether
    dispatch occurred. Times and previous counters are gate-signed statements.
    """
    try:
        if set(bundle) != {"evidence", "signature"}:
            raise ApprovalError("Invalid approval envelope")
        evidence = bundle["evidence"]
        check_signature(gate_key, evidence, bundle["signature"])
        if evidence["status"] != "credential_verified":
            raise ApprovalError("Unexpected approval status")
        document = evidence["challenge_document"]
        if not document["issued_at"] <= evidence["verified_at"] < document["expires_at"]:
            raise ApprovalError("Approval outside validity period")
        validate_binding(expected_binding)
        if document["domain"] != DOMAIN or document["binding"] != expected_binding:
            raise ApprovalError("Approval does not match request")
        if document["rp_id"] != rp_id or document["origin"] != origin or document["credential_id"] != bytes_to_base64url(credential_id):
            raise ApprovalError("Approval identity mismatch")
        if evidence["assertion"].get("id") != document["credential_id"]:
            raise ApprovalError("Credential ID mismatch")
        verification = verify_authentication_response(
            credential=evidence["assertion"], expected_challenge=challenge_bytes(document),
            expected_rp_id=rp_id, expected_origin=origin,
            credential_public_key=credential_public_key,
            credential_current_sign_count=evidence["previous_sign_count"],
            require_user_verification=True,
        )
        if verification.credential_id != credential_id:
            raise ApprovalError("Credential ID mismatch")
        return {"approval": "credential_verified", "initiation": "not_established", "execution": "not_established", "approval_id": document["id"]}
    except Exception as exc:
        if isinstance(exc, ApprovalError):
            raise
        raise ApprovalError("Invalid approval evidence") from exc


class ApprovalGate:
    def __init__(self, database, *, rp_id, origin, signing_key, clock=time.time):
        parsed = urlsplit(origin)
        if parsed.hostname != rp_id or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ApprovalError("Use an exact RP hostname and origin")
        if parsed.scheme != "https" and not (parsed.scheme == "http" and rp_id in {"localhost", "127.0.0.1"}):
            raise ApprovalError("HTTPS required except for loopback experiments")
        self.database, self.rp_id, self.origin = str(database), rp_id, origin
        if self.database == ":memory:":
            raise ApprovalError("A persistent database path is required")
        self.key, self.clock = signing_key, clock
        with self._transaction() as db:
            for statement in [
                "CREATE TABLE IF NOT EXISTS credentials(id TEXT PRIMARY KEY, public_key BLOB NOT NULL, sign_count INTEGER NOT NULL, enabled INTEGER NOT NULL)",
                "CREATE TABLE IF NOT EXISTS challenges(id TEXT PRIMARY KEY, document TEXT NOT NULL, bundle TEXT)",
                "CREATE TABLE IF NOT EXISTS reservations(request_key TEXT PRIMARY KEY, approval_id TEXT UNIQUE NOT NULL, receipt TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS config(id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL)",
            ]:
                db.execute(statement)
            config = canonical({"rp_id": rp_id, "origin": origin, "gate_key_sha256": hashlib.sha256(export_public(signing_key.public_key())).hexdigest()}).decode()
            previous = db.execute("SELECT value FROM config WHERE id=1").fetchone()
            if previous and previous[0] != config:
                raise ApprovalError("Database RP, origin, or gate key mismatch")
            db.execute("INSERT OR IGNORE INTO config VALUES(1,?)", (config,))

    @contextmanager
    def _transaction(self):
        db = sqlite3.connect(self.database, timeout=10)
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def enroll_trusted(self, credential_id, public_key, sign_count=0):
        """Administrative trust boundary, NOT a public registration endpoint.

        Caller must verify a separately authorized registration ceremony first.
        Existing credentials cannot be replaced through this API.
        """
        if not isinstance(credential_id, bytes) or not credential_id or not isinstance(public_key, bytes) or not public_key or type(sign_count) is not int or sign_count < 0:
            raise ApprovalError("Invalid credential")
        with self._transaction() as db:
            try:
                db.execute("INSERT INTO credentials VALUES(?,?,?,1)", (bytes_to_base64url(credential_id), public_key, sign_count))
            except sqlite3.IntegrityError as exc:
                raise ApprovalError("Credential already enrolled") from exc

    def revoke(self, credential_id):
        with self._transaction() as db:
            db.execute("UPDATE credentials SET enabled=0 WHERE id=?", (bytes_to_base64url(credential_id),))

    def approval_evidence(self, approval_id):
        """Export historical signed evidence; does not grant or renew approval."""
        with self._transaction() as db:
            row = db.execute("SELECT bundle FROM challenges WHERE id=?", (approval_id,)).fetchone()
            if not row or row[0] is None:
                raise ApprovalError("Approved evidence unavailable")
            return json.loads(row[0])

    def begin(self, binding, credential_id, ttl=120):
        binding = json.loads(canonical(binding))
        validate_binding(binding)
        if type(ttl) is not int or not 1 <= ttl <= 300:
            raise ApprovalError("TTL must be 1–300 seconds")
        now, cid = int(self.clock()), bytes_to_base64url(credential_id)
        document = {"domain": DOMAIN, "id": secrets.token_hex(24), "nonce": secrets.token_hex(32), "binding": json.loads(canonical(binding)), "credential_id": cid, "rp_id": self.rp_id, "origin": self.origin, "issued_at": now, "expires_at": now + ttl}
        with self._transaction() as db:
            credential = db.execute("SELECT enabled FROM credentials WHERE id=?", (cid,)).fetchone()
            if not credential or not credential[0]:
                raise ApprovalError("Credential unavailable")
            db.execute("INSERT INTO challenges VALUES(?,?,NULL)", (document["id"], canonical(document).decode()))
        options = generate_authentication_options(rp_id=self.rp_id, challenge=challenge_bytes(document), timeout=ttl * 1000, allow_credentials=[PublicKeyCredentialDescriptor(id=credential_id)], user_verification=UserVerificationRequirement.REQUIRED)
        return {"approval_id": document["id"], "binding": document["binding"], "publicKey": json.loads(options_to_json(options))}

    def _load(self, db, approval_id):
        row = db.execute("SELECT document,bundle FROM challenges WHERE id=?", (approval_id,)).fetchone()
        if not row:
            raise ApprovalError("Unknown challenge")
        document = json.loads(row[0])
        now = int(self.clock())
        if not document["issued_at"] <= now < document["expires_at"]:
            raise ApprovalError("Challenge expired or clock moved backward")
        credential = db.execute("SELECT public_key,sign_count,enabled FROM credentials WHERE id=?", (document["credential_id"],)).fetchone()
        if not credential or not credential[2]:
            raise ApprovalError("Credential revoked or missing")
        return document, row[1], credential

    def finish(self, approval_id, assertion):
        assertion = json.loads(canonical(assertion))
        with self._transaction() as db:
            document, prior, credential = self._load(db, approval_id)
            if prior:
                raise ApprovalError("Challenge already approved")
            if not isinstance(assertion, dict) or assertion.get("id") != document["credential_id"]:
                raise ApprovalError("Credential ID mismatch")
            try:
                verification = verify_authentication_response(credential=assertion, expected_challenge=challenge_bytes(document), expected_rp_id=self.rp_id, expected_origin=self.origin, credential_public_key=credential[0], credential_current_sign_count=credential[1], require_user_verification=True)
            except Exception as exc:
                raise ApprovalError("WebAuthn assertion rejected") from exc
            if bytes_to_base64url(verification.credential_id) != document["credential_id"]:
                raise ApprovalError("Credential ID mismatch")
            self._load(db, approval_id)  # Recheck expiry after cryptographic verification.
            evidence = {"challenge_document": document, "assertion": assertion, "previous_sign_count": credential[1], "verified_at": int(self.clock()), "status": "credential_verified"}
            bundle = {"evidence": evidence, "signature": sign(self.key, evidence)}
            db.execute("UPDATE credentials SET sign_count=? WHERE id=?", (verification.new_sign_count, document["credential_id"]))
            db.execute("UPDATE challenges SET bundle=? WHERE id=?", (canonical(bundle).decode(), approval_id))
            return bundle

    def reserve(self, approval_id, actual_binding):
        """Atomically spend approval for one dispatch attempt; not an execution proof.

        Executor must compute actual_binding from the final outgoing operation.
        Crashes after reservation fail closed: approval is not automatically reused.
        """
        actual_binding = json.loads(canonical(actual_binding))
        validate_binding(actual_binding)
        with self._transaction() as db:
            document, bundle, _ = self._load(db, approval_id)
            if not bundle or actual_binding != document["binding"]:
                raise ApprovalError("Approval missing or operation changed")
            request_key = digest({"session": actual_binding["session"], "request_id": actual_binding["request_id"]})
            reservation = {"domain": DOMAIN + "/reservation", "approval_id": approval_id, "binding": actual_binding, "approval_sha256": digest(json.loads(bundle)), "status": "reserved_for_dispatch", "reserved_at": int(self.clock())}
            receipt = {"reservation": reservation, "signature": sign(self.key, reservation)}
            try:
                db.execute("INSERT INTO reservations VALUES(?,?,?)", (request_key, approval_id, canonical(receipt).decode()))
            except sqlite3.IntegrityError as exc:
                raise ApprovalError("Approval or request already reserved") from exc
            return receipt
