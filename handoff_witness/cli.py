import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .benchmark import run, scenario
from .core import EvidenceError, verify


def main():
    parser = argparse.ArgumentParser(description="Experimental handoff request attribution")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo")
    demo.add_argument("--out", default="artifacts/demo")
    commands.add_parser("benchmark")
    browser = commands.add_parser("serve")
    browser.add_argument("--port", type=int, default=8765)
    browser.add_argument("--out", default="artifacts/browser")
    review = commands.add_parser("review", help="Open local passkey review and a controlled browser")
    review.add_argument("--out", required=True)
    review.add_argument("--url", help="Initial URL; defaults to a local fixture")
    review.add_argument("--channel", choices=["chrome", "chromium"])
    capture = commands.add_parser("import-cdp", help="Analyze a trusted harness transcript; input is not authenticated")
    capture.add_argument("trace", type=Path)
    capture.add_argument("--out", default="artifacts/cdp")
    audit = commands.add_parser("verify")
    audit.add_argument("events", type=Path)
    audit.add_argument("--trusted-key", required=True, type=Path)
    audit.add_argument("--checkpoint", required=True, type=Path)
    audit.add_argument("--session", help="Expected recorder session; recommended when a key signs several sessions")
    approval = commands.add_parser("verify-approval", help="Verify a request-bound credential assertion; not human intent")
    approval.add_argument("bundle", type=Path)
    approval.add_argument("--gate-key", required=True, type=Path)
    approval.add_argument("--credential-key", required=True, type=Path)
    approval.add_argument("--credential-id", required=True, type=Path)
    approval.add_argument("--binding", required=True, type=Path)
    approval.add_argument("--rp-id", required=True)
    approval.add_argument("--origin", required=True)
    execution = commands.add_parser("verify-execution", help="Audit anchored broker observations and request-bound approvals")
    execution.add_argument("bundle", type=Path)
    execution.add_argument("--checkpoint", required=True, type=Path)
    execution.add_argument("--executor-key", required=True, type=Path)
    execution.add_argument("--gate-key", required=True, type=Path)
    execution.add_argument("--credential-key", required=True, type=Path)
    execution.add_argument("--credential-id", required=True, type=Path)
    execution.add_argument("--rp-id", required=True)
    execution.add_argument("--origin", required=True)
    execution.add_argument("--session", help="Expected executor session; recommended when a key signs several sessions")
    args = parser.parse_args()
    try:
        if args.command == "review":
            import asyncio
            from .review import run as run_review
            asyncio.run(run_review(args.out, url=args.url, channel=args.channel))
            return
        if args.command == "serve":
            from .server import serve
            serve(args.port, args.out)
            return
        if args.command == "verify-execution":
            from webauthn.helpers import base64url_to_bytes
            from .execution_audit import verify_execution
            result = verify_execution(json.loads(args.bundle.read_text()), json.loads(args.checkpoint.read_text()),
                executor_key=load_pem_public_key(args.executor_key.read_bytes()),
                gate_key=load_pem_public_key(args.gate_key.read_bytes()),
                credential_id=base64url_to_bytes(args.credential_id.read_text().strip()),
                credential_public_key=args.credential_key.read_bytes(), rp_id=args.rp_id, origin=args.origin,
                expected_session=args.session)
        elif args.command == "verify-approval":
            from webauthn.helpers import base64url_to_bytes
            from .approval import verify_bundle
            result = verify_bundle(json.loads(args.bundle.read_text()), gate_key=load_pem_public_key(args.gate_key.read_bytes()), credential_id=base64url_to_bytes(args.credential_id.read_text().strip()), credential_public_key=args.credential_key.read_bytes(), expected_binding=json.loads(args.binding.read_text()), rp_id=args.rp_id, origin=args.origin)
        elif args.command == "import-cdp":
            from .cdp import collect
            recorder, result = collect(json.loads(args.trace.read_text()))
            recorder.save(args.out)
            (Path(args.out) / "analysis.json").write_text(json.dumps(result, indent=2) + "\n")
        elif args.command == "benchmark":
            result = run()
        elif args.command == "demo":
            result, recorder = scenario("agent timer after takeover", "agent", "human", "agent")
            recorder.save(args.out)
            result["artifacts"] = str(Path(args.out).resolve())
        else:
            records = [json.loads(line) for line in args.events.read_text().splitlines()]
            result = verify(records, json.loads(args.checkpoint.read_text()), load_pem_public_key(args.trusted_key.read_bytes()),
                            expected_session=args.session)
        print(json.dumps(result, indent=2))
    except (EvidenceError, OSError, ValueError) as exc:
        parser.exit(1, f"Verification failed: {exc}\n")


if __name__ == "__main__":
    main()
