"""End-to-end review UI test with a virtual authenticator and local receiver."""
import argparse
import asyncio
import json
from importlib.metadata import version
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from webauthn.helpers import bytes_to_base64url

from .approval import ApprovalGate
from .core import export_public
from .execution import ApprovedBrowser
from .execution_live import ExecutionFixture, verify_fixture_audit
from .review import ReviewHub, ReviewServer


async def run(out, channel=None):
    from playwright.async_api import async_playwright

    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    server = ReviewServer()
    key = Ed25519PrivateKey.generate()
    hub = ReviewHub(ApprovalGate(out / 'gate.sqlite', rp_id='localhost', origin=server.origin, signing_key=key))
    server.start(hub)
    executor = None
    try:
        with ExecutionFixture() as fixture:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(headless=True, **({'channel': channel} if channel else {}))
                try:
                    control = await browser.new_context(service_workers='block', viewport={'width': 1120, 'height': 1000})
                    ui = await control.new_page()
                    cdp = await control.new_cdp_session(ui)
                    await cdp.send('WebAuthn.enable')
                    await cdp.send('WebAuthn.addVirtualAuthenticator', {'options': {'protocol':'ctap2','transport':'internal','hasResidentKey':True,'hasUserVerification':True,'isUserVerified':True,'automaticPresenceSimulation':True}})
                    await ui.goto(server.bootstrap_url)
                    await ui.get_by_role('button', name='Register a passkey').click()
                    await asyncio.wait_for(hub.enrolled.wait(), 15)
                    await ui.get_by_text('Passkey ready · approval required', exact=True).wait_for()
                    executor = await ApprovedBrowser.create(browser, hub.gate, hub, allowed_origins=[fixture.base], approval_timeout=125)
                    page = await executor.new_page()
                    navigation = asyncio.create_task(page.goto(fixture.base + '/approved-ui', timeout=20000))
                    await ui.locator('.request').wait_for()
                    held = not fixture.ledger and not navigation.done()
                    await ui.screenshot(path=str(out / 'review-desktop.png'), full_page=True)
                    await ui.get_by_role('button', name='Approve once with passkey').click()
                    await navigation
                    approved = [r['path'] for r in fixture.ledger] == ['/approved-ui']
                    fetch = asyncio.create_task(page.evaluate("async () => {try {await fetch('/denied-ui');return 'sent'}catch(e){return 'blocked'}}"))
                    await ui.locator('.destination').filter(has_text='/denied-ui').wait_for()
                    await ui.get_by_role('button', name='Deny', exact=True).click()
                    denied = await fetch == 'blocked' and not any(r['path'] == '/denied-ui' for r in fixture.ledger)
                    # Pending request survives reviewer page reload; session token is not in URL.
                    fetch = asyncio.create_task(page.evaluate("async () => {try {await fetch('/reload-denied');return 'sent'}catch(e){return 'blocked'}}"))
                    await ui.locator('.destination').filter(has_text='/reload-denied').wait_for()
                    await ui.reload()
                    await ui.locator('.destination').filter(has_text='/reload-denied').wait_for()
                    resumed = ui.url == server.origin + '/'
                    await ui.set_viewport_size({'width':390,'height':844})
                    await ui.evaluate('() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))')
                    await ui.screenshot(path=str(out / 'review-mobile.png'), full_page=True)
                    await ui.get_by_role('button', name='Deny', exact=True).click()
                    resumed = resumed and await fetch == 'blocked'
                    # Exercise malicious-looking content through the review rendering only.
                    binding = {'session':'fixture','request_id':'markup','method':'GET','url':'https://fixture.invalid/<img src=x onerror=alert(1)>','body_sha256':'0'*64,'headers_sha256':'0'*64}
                    pending = asyncio.create_task(hub(binding))
                    await ui.locator('.destination').filter(has_text='<img').wait_for()
                    safe_text = await ui.locator('.destination img').count() == 0
                    await ui.get_by_role('button', name='Deny', exact=True).click()
                    await pending
                    await executor.close()
                    executor.save_evidence(out / 'audit')
                    audit = verify_fixture_audit(out, executor, hub.gate, hub.credential_id, hub.credential_public_key)
                    checks = {'held_until_review':held,'approved_request_received_once':approved,
                              'signed_execution_matches_review': audit['request_count'] == 1 and audit['requests'][0]['binding']['url'] == fixture.base + '/approved-ui' and audit['requests'][0]['stage'] == 'relay_prepared',
                              'denied_request_never_received':denied,'review_session_survives_reload':resumed,
                              'untrusted_url_rendered_as_text':safe_text,
                              'receiver_only_approved_path':[r['path'] for r in fixture.ledger] == ['/approved-ui']}
                    report = {'kind':'interactive_review_ui_integration','browser_version':browser.version,
                              'playwright_version':version('playwright'),'checks':checks,'passed':all(checks.values()),
                              'limitations':['Virtual authenticator; no physical human or real passkey enrollment tested.',
                                             'Local review capability authorizes enrollment; identity and OS isolation are not established.']}
                    for name,value in [('report.json',report),('receiver.json',fixture.ledger),('execution.json',executor.events),('approvals.json',hub.bundles)]:
                        (out / name).write_text(json.dumps(value,indent=2)+'\n')
                    (out / 'gate-public.pem').write_bytes(export_public(key.public_key()))
                    (out / 'credential-public.cbor').write_bytes(hub.credential_public_key)
                    (out / 'credential-id.txt').write_text(bytes_to_base64url(hub.credential_id))
                    executor = None
                    return report
                finally:
                    hub.close()
                    if executor:
                        await executor.close()
                    await browser.close()
    finally:
        hub.close()
        await asyncio.to_thread(server.close)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True)
    parser.add_argument('--channel', choices=['chrome','chromium'])
    args = parser.parse_args()
    async def bounded():
        return await asyncio.wait_for(run(args.out,args.channel),90)
    report = asyncio.run(bounded())
    print(json.dumps(report,indent=2))
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
