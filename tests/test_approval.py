import copy
import hashlib
from concurrent.futures import ThreadPoolExecutor

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from webauthn.helpers import bytes_to_base64url

from handoff_witness.approval import ApprovalError, ApprovalGate, verify_bundle
from handoff_witness.core import Recorder, canonical, digest, verify


class SoftwareAuthenticator:
    """Test-only cryptographic fixture; NOT physical user verification."""
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.id = b"fixture-credential"
        point = self.key.public_key().public_numbers()
        self.public = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: point.x.to_bytes(32, "big"), -3: point.y.to_bytes(32, "big")})

    def assertion(self, options, *, flags=5, origin="https://approval.example", rp="approval.example", count=1):
        client = canonical({"type": "webauthn.get", "challenge": options["publicKey"]["challenge"], "origin": origin, "crossOrigin": False})
        auth = hashlib.sha256(rp.encode()).digest() + bytes([flags]) + count.to_bytes(4, "big")
        signature = self.key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": bytes_to_base64url(self.id), "rawId": bytes_to_base64url(self.id), "type": "public-key", "response": {"clientDataJSON": bytes_to_base64url(client), "authenticatorData": bytes_to_base64url(auth), "signature": bytes_to_base64url(signature)}}


@pytest.fixture
def setup(tmp_path):
    auth, key, now = SoftwareAuthenticator(), Ed25519PrivateKey.generate(), [1000]
    gate = ApprovalGate(tmp_path / "gate.db", rp_id="approval.example", origin="https://approval.example", signing_key=key, clock=lambda: now[0])
    gate.enroll_trusted(auth.id, auth.public)
    binding = {"session": "s1", "request_id": "r1", "method": "GET", "url": "https://fixture.invalid/resource", "body_sha256": hashlib.sha256(b"").hexdigest(), "headers_sha256": digest({})}
    return gate, auth, key, now, binding


def approve(setup):
    gate, auth, _, _, binding = setup
    options = gate.begin(binding, auth.id)
    bundle = gate.finish(options["approval_id"], auth.assertion(options))
    return options, bundle


def test_valid_approval_does_not_relabel_initiation(setup):
    gate, auth, key, _, binding = setup
    options, bundle = approve(setup)
    result = verify_bundle(bundle, gate_key=key.public_key(), credential_id=auth.id, credential_public_key=auth.public, expected_binding=binding, rp_id=gate.rp_id, origin=gate.origin)
    assert result["approval"] == "credential_verified"
    assert result["initiation"] == "not_established"
    assert gate.reserve(options["approval_id"], binding)["reservation"]["status"] == "reserved_for_dispatch"
    recorder = Recorder()
    recorder.handoff("agent")
    source = recorder.input("agent")
    recorder.request([source], binding["url"], request_id=binding["request_id"])
    assert verify(recorder.records, recorder.checkpoint(), recorder.key.public_key())["requests"][0]["attribution"] == "agent"


@pytest.mark.parametrize("change", ["no_uv", "no_up", "origin", "rp", "challenge", "signature", "credential"])
def test_invalid_assertions(setup, change):
    gate, auth, _, _, binding = setup
    options = gate.begin(binding, auth.id)
    kwargs = {}
    signing_options = copy.deepcopy(options)
    if change == "no_uv":
        kwargs["flags"] = 1
    elif change == "no_up":
        kwargs["flags"] = 4
    elif change == "origin":
        kwargs["origin"] = "https://attacker.invalid"
    elif change == "rp":
        kwargs["rp"] = "attacker.invalid"
    elif change == "challenge":
        signing_options["publicKey"]["challenge"] = bytes_to_base64url(b"another challenge")
    assertion = auth.assertion(signing_options, **kwargs)
    if change == "signature":
        assertion["response"]["signature"] = bytes_to_base64url(b"bad signature")
    elif change == "credential":
        assertion["id"] = bytes_to_base64url(b"different credential")
    with pytest.raises(ApprovalError):
        gate.finish(options["approval_id"], assertion)


@pytest.mark.parametrize("field,value", [("url", "https://other.invalid/"), ("method", "POST"), ("session", "other"), ("request_id", "other"), ("body_sha256", "1"*64), ("headers_sha256", "1"*64)])
def test_request_substitution_does_not_spend_approval(setup, field, value):
    gate, _, _, _, binding = setup
    options, _ = approve(setup)
    with pytest.raises(ApprovalError):
        gate.reserve(options["approval_id"], {**binding, field: value})
    gate.reserve(options["approval_id"], binding)


def test_expired_challenge_and_approval(setup):
    gate, auth, _, now, binding = setup
    options = gate.begin(binding, auth.id, ttl=1)
    assertion = auth.assertion(options)
    now[0] += 1
    with pytest.raises(ApprovalError):
        gate.finish(options["approval_id"], assertion)
    options, _ = approve(setup)
    now[0] += 120
    with pytest.raises(ApprovalError):
        gate.reserve(options["approval_id"], binding)


def test_revocation_after_approval(setup):
    gate, auth, _, _, binding = setup
    options, _ = approve(setup)
    gate.revoke(auth.id)
    with pytest.raises(ApprovalError):
        gate.reserve(options["approval_id"], binding)


def test_same_assertion_cannot_finish_twice(setup):
    gate, auth, _, _, binding = setup
    options = gate.begin(binding, auth.id)
    assertion = auth.assertion(options)
    gate.finish(options["approval_id"], assertion)
    with pytest.raises(ApprovalError):
        gate.finish(options["approval_id"], assertion)


def test_persistent_and_concurrent_one_use(setup):
    gate, _, key, now, binding = setup
    options, _ = approve(setup)
    restarted = ApprovalGate(gate.database, rp_id=gate.rp_id, origin=gate.origin, signing_key=key, clock=lambda: now[0])
    def reserve(instance):
        try:
            instance.reserve(options["approval_id"], binding)
            return True
        except ApprovalError:
            return False
    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(reserve, [gate, restarted])) == [False, True]


def test_new_approval_cannot_reexecute_same_request(setup):
    gate, auth, _, _, binding = setup
    options, _ = approve(setup)
    gate.reserve(options["approval_id"], binding)
    second = gate.begin(binding, auth.id)
    gate.finish(second["approval_id"], auth.assertion(second, count=2))
    with pytest.raises(ApprovalError):
        gate.reserve(second["approval_id"], binding)


def test_offline_signature_and_binding_tampering(setup):
    gate, auth, key, _, binding = setup
    _, bundle = approve(setup)
    bundle["evidence"]["challenge_document"]["binding"]["url"] = "https://changed.invalid/"
    with pytest.raises(ApprovalError):
        verify_bundle(bundle, gate_key=key.public_key(), credential_id=auth.id, credential_public_key=auth.public, expected_binding=binding, rp_id=gate.rp_id, origin=gate.origin)


def test_zero_counter_credentials_still_have_challenge_replay_protection(setup):
    gate, auth, _, _, binding = setup
    options = gate.begin(binding, auth.id)
    assertion = auth.assertion(options, count=0)
    gate.finish(options["approval_id"], assertion)
    gate.reserve(options["approval_id"], binding)
    with pytest.raises(ApprovalError):
        gate.reserve(options["approval_id"], binding)


def test_database_cannot_accidentally_change_gate_key(setup):
    gate, _, _, _, _ = setup
    with pytest.raises(ApprovalError):
        ApprovalGate(gate.database, rp_id=gate.rp_id, origin=gate.origin, signing_key=Ed25519PrivateKey.generate())


def test_assertion_for_another_pending_challenge_rejected(setup):
    gate, auth, _, _, binding = setup
    first = gate.begin(binding, auth.id)
    second = gate.begin({**binding, "request_id": "r2"}, auth.id)
    with pytest.raises(ApprovalError):
        gate.finish(second["approval_id"], auth.assertion(first))


def test_backward_clock_rejected(setup):
    gate, auth, _, now, binding = setup
    options = gate.begin(binding, auth.id)
    now[0] -= 1
    with pytest.raises(ApprovalError):
        gate.finish(options["approval_id"], auth.assertion(options))


def test_reservation_without_approval_rejected(setup):
    gate, auth, _, _, binding = setup
    options = gate.begin(binding, auth.id)
    with pytest.raises(ApprovalError):
        gate.reserve(options["approval_id"], binding)


def test_unknown_credential_cannot_request_challenge(setup):
    gate, _, _, _, binding = setup
    with pytest.raises(ApprovalError):
        gate.begin(binding, b"not-enrolled")
