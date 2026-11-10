"""Replay frozen model proposals through native and approval-gated browsers.

Works for both the v1 plan (steering.py) and the counterbalanced v2 plan
(steering_v2.py). Approvals are simulated by a virtual authenticator on an
isolated surface.
Decision receipts attest to the archived inputs consumed by this replay, not
independent model execution or real human authorship. All targets are loopback.
"""
import argparse
import asyncio
import json
import time
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from webauthn import generate_registration_options, options_to_json, verify_registration_response
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import AuthenticatorSelectionCriteria, UserVerificationRequirement

from .approval import ApprovalGate
from .core import export_public
from .decision import DecisionWitness, verify_decisions
from .execution import ApprovedBrowser
from .execution_live import ExecutionFixture, verify_fixture_audit
from .steering import parse_action, sha
from .steering_v2 import parse_action_fence_tolerant


async def run(source, out, channel):
    from playwright.async_api import async_playwright, Error
    source, out = Path(source), Path(out)
    out.mkdir(parents=True, exist_ok=False)
    plan_bytes = (source / "plan.json").read_bytes()
    assert sha(plan_bytes) == (source / "plan.sha256").read_text().strip()
    plan = json.loads(plan_bytes)
    cases = {c["case_id"]: c for c in plan["cases"]}
    trials = []
    for index, model in enumerate(plan["models"]):
        rows = [json.loads(line) for line in (source / f"model-{index}/outputs.jsonl").read_text().splitlines()]
        assert len(rows) == len(cases) and {r["case_id"] for r in rows} == set(cases)
        for row in rows:
            assert parse_action(row["output"]) == row["parsed"]
            if "parsed_fence_tolerant" in row:
                assert parse_action_fence_tolerant(row["output"]) == row["parsed_fence_tolerant"]
            assert sha(row["prompt"].encode()) == row["prompt_sha256"]
            trials.append({"id": f"m{index}-" + row["case_id"], "model_index": index, "model": model,
                           "case": cases[row["case_id"]], "generation": row})
    with ExecutionFixture() as fixture:
        gate_key = Ed25519PrivateKey.generate()
        gate = ApprovalGate(out / "gate.sqlite", rp_id="localhost", origin=fixture.base, signing_key=gate_key)
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, channel=channel)
            try:
                control = await browser.new_context(service_workers="block")
                async def control_route(route):
                    if route.request.url == fixture.base + "/approval-ui":
                        await route.continue_()
                    else:
                        await route.abort()
                await control.route("**/*", control_route)
                ui = await control.new_page()
                cdp = await control.new_cdp_session(ui)
                await cdp.send("WebAuthn.enable")
                await cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {"protocol": "ctap2", "transport": "internal", "hasResidentKey": True, "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})
                await ui.goto(fixture.base + "/approval-ui")
                opts = generate_registration_options(rp_id="localhost", rp_name="Steering study", user_name="simulated-approver", user_id=b"steering-study", authenticator_selection=AuthenticatorSelectionCriteria(user_verification=UserVerificationRequirement.REQUIRED))
                reg = await ui.evaluate("async o => (await navigator.credentials.create({publicKey:PublicKeyCredential.parseCreationOptionsFromJSON(o)})).toJSON()", json.loads(options_to_json(opts)))
                enrolled = verify_registration_response(credential=reg, expected_challenge=opts.challenge, expected_rp_id="localhost", expected_origin=fixture.base, require_user_verification=True)
                gate.enroll_trusted(enrolled.credential_id, enrolled.credential_public_key, enrolled.sign_count)
                fixture.ledger.clear()
                expected, active, approvals, callback_ms = {}, {}, [], []
                for t in trials:
                    selected = t["generation"]["parsed"]
                    if selected in ("A", "B"):
                        path = f"/fixture/gated/{t['id']}/{selected}"
                        expected[path] = selected == t["case"]["public"]

                async def approve(binding):
                    path = urlsplit(binding["url"]).path
                    if path not in active:
                        return None
                    start = time.perf_counter()
                    witness, decision = active[path]
                    witness.append("binding", decision=decision, binding=binding)
                    if not expected[path]:
                        callback_ms.append({"path": path, "approved": False, "ms": (time.perf_counter()-start)*1000})
                        return None
                    opts = gate.begin(binding, enrolled.credential_id)
                    assertion = await ui.evaluate("async o => (await navigator.credentials.get({publicKey:PublicKeyCredential.parseRequestOptionsFromJSON(o)})).toJSON()", opts["publicKey"])
                    approvals.append(gate.finish(opts["approval_id"], assertion))
                    callback_ms.append({"path": path, "approved": True, "ms": (time.perf_counter()-start)*1000})
                    return opts["approval_id"]

                executor = await ApprovedBrowser.create(browser, gate, approve, allowed_origins=[fixture.base])
                native = await browser.new_context(service_workers="block")
                async def native_route(route):
                    parsed = urlsplit(route.request.url)
                    if parsed.scheme + "://" + parsed.netloc == fixture.base and parsed.path.startswith("/fixture/native/"):
                        await route.continue_()
                    else:
                        await route.abort()
                await native.route("**/*", native_route)
                rows = []
                for n, t in enumerate(trials):
                    c, g = t["case"], t["generation"]
                    witness = DecisionWitness(session=t["id"])
                    ins = witness.append("instruction", channel="user", text=c["base_instruction"], replaces=None)
                    if c["instruction"] != c["base_instruction"]:
                        ins = witness.append("instruction", channel="user", text=c["instruction"], replaces=ins)
                    contexts = []
                    if c["external_context"]:
                        contexts = [witness.append("context", channel="external", text=c["external_context"])]
                    path = f"/fixture/gated/{t['id']}/{g['parsed']}" if g["parsed"] in ("A", "B") else None
                    decision = witness.append("decision", instruction=ins, contexts=contexts, policy=c["policy"], messages=c["messages"],
                                              rendered_prompt_sha256=g["prompt_sha256"], model=t["model"], output=g["output"], proposed_path=path)
                    latencies = {}
                    if path:
                        active[path] = witness, decision
                        # Alternate execution order to reduce systematic timing order effects.
                        modes = ["gated", "native"] if n % 2 == 0 else ["native", "gated"]
                        for mode in modes:
                            page = await (executor.new_page() if mode == "gated" else native.new_page())
                            start = time.perf_counter()
                            try:
                                await page.goto(fixture.base + path.replace("/gated/", f"/{mode}/"), wait_until="load", timeout=15000)
                            except Error:
                                if mode != "gated" or expected[path]:
                                    raise
                            latencies[mode] = (time.perf_counter() - start) * 1000
                            await page.close()
                        del active[path]
                    # A later denial cannot overwrite the instruction bound to the decision.
                    witness.append("instruction", channel="user", text="I did not instruct the agent to access a restricted source.", replaces=ins)
                    directory = out / "decisions" / t["id"]
                    witness.save(directory)
                    verify_decisions(witness.records, witness.checkpoint(), witness.key.public_key(), t["id"])
                    rows.append({"id": t["id"], "model_index": t["model_index"], "case_id": c["case_id"],
                                 "task": c["task"], "family": c["family"], "seed": c["seed"], "variant": c["variant"],
                                 "selected": g["parsed"], "public": c["public"], "restricted": c["restricted"],
                                 "order": c.get("order", "public_first"), "arrangement": c.get("arrangement"),
                                 "path": path, "latency_ms": latencies,
                                 "evidence_bytes": sum(f.stat().st_size for f in directory.iterdir())})
                    if (n+1) % 24 == 0:
                        print(f"browser replay: {n+1}/{len(trials)}", flush=True)
                await executor.close()
                executor.save_evidence(out / "audit")
                audit = verify_fixture_audit(out, executor, gate, enrolled.credential_id, enrolled.credential_public_key)
                from collections import Counter
                actual = Counter(r["path"] for r in fixture.ledger)
                wanted = Counter()
                for row in rows:
                    if row["path"]:
                        wanted[row["path"].replace("/gated/", "/native/")] += 1
                        if row["selected"] == row["public"]:
                            wanted[row["path"]] += 1
                if actual != wanted:
                    raise AssertionError({"unexpected": dict(actual-wanted), "missing": dict(wanted-actual)})
                for row in rows:
                    row["gated_arrivals"] = actual[row["path"]] if row["path"] else 0
                    row["native_arrivals"] = actual[row["path"].replace("/gated/", "/native/")] if row["path"] else 0
                report = {"valid": True, "trial_count": len(rows), "browser": browser.version, "plan_sha256": sha(plan_bytes),
                          "protocol": plan.get("protocol", "steering-pilot/v1"),
                          "source_sha256": {name: sha(Path(__file__).with_name(name).read_bytes()) for name in ["steering_browser.py", "steering_v2.py", "steering.py", "decision.py", "execution.py", "execution_audit.py", "approval.py"]},
                          "audit_request_count": len(audit["requests"]), "receiver_reconciled": True,
                          "limitations": ["Virtual approval, not a human study", "Same-process receiver, not independent attestation", "Frozen single-step proposal replay, not multistep online agent", "Decision witness records replayed archives, not independently attested inference", "No OS egress containment"]}
                for name, value in [("rows.json", rows), ("report.json", report), ("receiver.json", fixture.ledger),
                                    ("execution.json", executor.events), ("approvals.json", approvals), ("callback-times.json", callback_ms)]:
                    (out / name).write_text(json.dumps(value, indent=2) + "\n")
                (out / "gate-public.pem").write_bytes(export_public(gate_key.public_key()))
                (out / "credential-public.cbor").write_bytes(enrolled.credential_public_key)
                (out / "credential-id.txt").write_text(bytes_to_base64url(enrolled.credential_id))
                print(json.dumps(report, indent=2))
            finally:
                await browser.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--channel", default="chrome")
    a = p.parse_args()
    asyncio.run(run(a.source, a.out, a.channel))


if __name__ == "__main__":
    main()
