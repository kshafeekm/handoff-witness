"""WebAuthn browser integration using a virtual test authenticator, not a human."""
import argparse
import asyncio
import hashlib
import json
import platform
from importlib.metadata import version
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from webauthn import generate_registration_options, options_to_json, verify_registration_response
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import AuthenticatorSelectionCriteria, UserVerificationRequirement

from .approval import ApprovalError, ApprovalGate, verify_bundle
from .core import Recorder, digest, export_public, verify
from .live import Fixture


async def run(out, channel=None):
    from playwright.async_api import async_playwright

    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    with Fixture() as fixture:
        origin = fixture.base.replace("127.0.0.1", "localhost")
        gate_key = Ed25519PrivateKey.generate()
        gate = ApprovalGate(out / "gate.sqlite", rp_id="localhost", origin=origin, signing_key=gate_key)
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True, **({"channel": channel} if channel else {}))
            try:
                context = await browser.new_context(service_workers="block")
                async def local_only(route):
                    if route.request.url.startswith(origin + "/"):
                        await route.continue_()
                    else:
                        await route.abort()
                await context.route("**/*", local_only)
                page = await context.new_page()
                cdp = await context.new_cdp_session(page)
                await cdp.send("WebAuthn.enable")
                await cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {"protocol": "ctap2", "transport": "internal", "hasResidentKey": True, "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})
                await page.goto(origin + "/approval-fixture")
                creation = generate_registration_options(rp_id="localhost", rp_name="Handoff Witness Test", user_name="virtual-test-user", user_id=b"synthetic-approval-user", authenticator_selection=AuthenticatorSelectionCriteria(user_verification=UserVerificationRequirement.REQUIRED))
                registration = await page.evaluate("async options => (await navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options)})).toJSON()", json.loads(options_to_json(creation)))
                enrolled = verify_registration_response(credential=registration, expected_challenge=creation.challenge, expected_rp_id="localhost", expected_origin=origin, require_user_verification=True)
                gate.enroll_trusted(enrolled.credential_id, enrolled.credential_public_key, enrolled.sign_count)
                binding = {"session": "live-approval", "request_id": "one-operation", "method": "GET", "url": origin + "/protected", "body_sha256": hashlib.sha256(b"").hexdigest(), "headers_sha256": digest({})}
                options = gate.begin(binding, enrolled.credential_id)
                assertion = await page.evaluate("async options => (await navigator.credentials.get({publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options)})).toJSON()", options["publicKey"])
                bundle = gate.finish(options["approval_id"], assertion)
                offline = verify_bundle(bundle, gate_key=gate_key.public_key(), credential_id=enrolled.credential_id, credential_public_key=enrolled.credential_public_key, expected_binding=binding, rp_id="localhost", origin=origin)
                rejected_substitution = False
                try:
                    gate.reserve(options["approval_id"], {**binding, "url": origin + "/changed"})
                except ApprovalError:
                    rejected_substitution = True
                reservation = gate.reserve(options["approval_id"], binding)
                rejected_replay = False
                try:
                    gate.reserve(options["approval_id"], binding)
                except ApprovalError:
                    rejected_replay = True
                # Separate provenance experiment: approval must not create a human root.
                recorder = Recorder()
                recorder.handoff("agent")
                root = recorder.input("agent")
                recorder.request([root], binding["url"], request_id=binding["request_id"])
                attributed = verify(recorder.records, recorder.checkpoint(), recorder.key.public_key())["requests"][0]["attribution"]
                report = {"kind": "virtual_authenticator_browser_integration", "browser_version": browser.version, "playwright_version": version("playwright"), "webauthn_version": version("webauthn"), "python_version": platform.python_version(), "credential_verified": offline["approval"] == "credential_verified", "changed_url_rejected": rejected_substitution, "replay_rejected": rejected_replay, "separate_provenance_label": attributed, "passed": offline["approval"] == "credential_verified" and rejected_substitution and rejected_replay and attributed == "agent", "limitations": ["Virtual authenticator: no real human, biometric, or hardware-backed enrollment was tested.", "Enrollment, UI, gate, clock, executor, and database are trusted.", "The operation was reserved, not dispatched; the provenance record is a separate synthetic assertion.", "Credential approval does not establish initiation, comprehension, or legal responsibility."]}
                for name, value in [("approval.json", bundle), ("reservation.json", reservation), ("report.json", report), ("binding.json", binding)]:
                    (out / name).write_text(json.dumps(value, indent=2) + "\n")
                (out / "gate-public.pem").write_bytes(export_public(gate_key.public_key()))
                (out / "credential-public.cbor").write_bytes(enrolled.credential_public_key)
                (out / "credential-id.txt").write_text(bytes_to_base64url(enrolled.credential_id))
                return report
            finally:
                await browser.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--channel", choices=["chrome", "chromium"])
    args = parser.parse_args()
    report = asyncio.run(run(args.out, args.channel))
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
