"""Controlled synthetic benchmark, not a real-world security evaluation."""

from .core import Recorder, verify


def scenario(name, actor, controller, expected, mode="single"):
    recorder = Recorder()
    recorder.handoff(actor)
    root = recorder.input(actor)
    pending = recorder.effect([root], "timer registered")
    recorder.handoff(controller)
    parents = [pending]
    if mode == "mixed":
        parents.append(recorder.input(controller))
    elif mode == "unknown":
        parents = []
    elif mode == "partial":
        parents.append(recorder.effect([], "unobserved initiator"))
    elif mode == "redirect":
        pending = recorder.request(parents, "https://fixture.invalid/redirect")
        parents = [pending]
    recorder.request(parents, "https://fixture.invalid/target")
    result = verify(recorder.records, recorder.checkpoint(), recorder.key.public_key())["requests"][-1]
    return {"scenario": name, "expected": expected, "current_controller_baseline": controller, "witness": result["attribution"]}, recorder


CASES = [
    ("agent timer after human takeover", "agent", "human", "agent", "single"),
    ("human timer after agent takeover", "human", "agent", "human", "single"),
    ("agent remains in control", "agent", "agent", "agent", "single"),
    ("human remains in control", "human", "human", "human", "single"),
    ("joint causes across handoff", "agent", "human", "mixed", "mixed"),
    ("missing initiating evidence", "human", "agent", "unknown", "unknown"),
    ("partially observed ancestry", "agent", "human", "unknown", "partial"),
    ("redirect descendant after handoff", "agent", "human", "agent", "redirect"),
]


def run():
    rows = [scenario(*case)[0] for case in CASES]
    return {"kind": "synthetic_semantics_smoke_test", "case_count": len(rows), "baseline_correct": sum(r["current_controller_baseline"] == r["expected"] for r in rows), "witness_correct": sum(r["witness"] == r["expected"] for r in rows), "warning": "Fixture-supplied causal edges; not an empirical security or novelty claim.", "cases": rows}
