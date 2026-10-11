#!/usr/bin/env python3
"""Adversarial boundary fixture for host-owned operation identities."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from uuid import NAMESPACE_URL, uuid4, uuid5

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "src"))

from narf import (  # noqa: E402
    EffectBinding,
    FileConsumptionAuthority,
    FrozenState,
    NARFError,
    NARFGate,
    OperationBoundEffectExecutor,
    OperationBoundGate,
    ReceiptStore,
    Requirement,
    VerifierBinding,
    VerifierResult,
    canonical_json_digest,
    sha256_bytes,
)


def git_status() -> str:
    return subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, text=True
    )


def make_state(requirement: Requirement) -> FrozenState:
    return FrozenState(
        candidate_sha256=sha256_bytes(b"candidate-v1"),
        requirements_sha256=canonical_json_digest([asdict(requirement)]),
        policy_sha256=sha256_bytes(b"policy-v1"),
    )


def open_pass(gate, contract_id, task, state, callback):
    session = gate.open_session(
        contract_id,
        task,
        verifier_bindings=(
            VerifierBinding("host-check", "1", lambda: VerifierResult("PASS", b"proof")),
        ),
        effect_binding=EffectBinding("publish", "1", callback),
        state_probe=lambda: state,
    )
    session.execute("required")
    decision = session.finalize()
    if decision.get("result") != "PASS":
        raise RuntimeError("fixture failed to obtain authenticated PASS")
    return session


def freeze(gate, task, state, requirement, operation_id):
    return gate.freeze_contract(
        task,
        operation_id=operation_id,
        task_id="operation-boundary",
        requirements=(requirement,),
        effect_id="publish",
        effect_version="1",
        state=state,
    )


def run(output: Path) -> dict:
    before = git_status()
    rows = []

    with tempfile.TemporaryDirectory(prefix="narf-operation-boundary-") as name:
        root = Path(name)
        key = b"operation-boundary-key-material!!"
        if len(key) < 32:
            raise RuntimeError("fixture key too short")
        task = {"description": "same semantic external operation"}
        requirement = Requirement("required", "host-check", "1")
        state = make_state(requirement)

        # Case 1: same trusted-host operation ID across fresh contracts.
        store = ReceiptStore(root / "case1-receipts", key)
        gate = OperationBoundGate(store)
        authority = FileConsumptionAuthority(root / "case1-authority")
        executor = OperationBoundEffectExecutor(authority)
        operation_id = str(uuid4())
        calls = []
        first_id = freeze(gate, task, state, requirement, operation_id)
        second_id = freeze(gate, task, state, requirement, operation_id)
        first = open_pass(gate, first_id, task, state, lambda: calls.append("first") or "first")
        second = open_pass(gate, second_id, task, state, lambda: calls.append("second") or "second")
        first_result = executor.execute(first)
        second_blocked = False
        try:
            executor.execute(second)
        except NARFError as error:
            second_blocked = "already consumed" in str(error)
        passed = (
            first_id != second_id
            and first_result == "first"
            and second_blocked
            and calls == ["first"]
            and authority.is_reserved(operation_id)
        )
        rows.append(
            {
                "case": "stable-operation-id-blocks-fresh-contract",
                "result": "PASS" if passed else "FAIL",
                "distinct_contract_ids": first_id != second_id,
                "callback_invocations": len(calls),
                "second_blocked": second_blocked,
            }
        )

        # Case 2: distinct host-owned operation IDs are not globally one-shot.
        store2 = ReceiptStore(root / "case2-receipts", key)
        gate2 = OperationBoundGate(store2)
        authority2 = FileConsumptionAuthority(root / "case2-authority")
        executor2 = OperationBoundEffectExecutor(authority2)
        calls2 = []
        op_a, op_b = str(uuid4()), str(uuid4())
        session_a = open_pass(
            gate2,
            freeze(gate2, task, state, requirement, op_a),
            task,
            state,
            lambda: calls2.append("a") or "a",
        )
        session_b = open_pass(
            gate2,
            freeze(gate2, task, state, requirement, op_b),
            task,
            state,
            lambda: calls2.append("b") or "b",
        )
        passed2 = executor2.execute(session_a) == "a" and executor2.execute(session_b) == "b" and calls2 == ["a", "b"]
        rows.append(
            {
                "case": "distinct-operation-ids-remain-independent",
                "result": "PASS" if passed2 else "FAIL",
                "callback_invocations": len(calls2),
            }
        )

        # Case 3: tampering with the HMAC-bound operation identity fails closed.
        store3 = ReceiptStore(root / "case3-receipts", key)
        gate3 = OperationBoundGate(store3)
        op3 = str(uuid4())
        contract3 = freeze(gate3, task, state, requirement, op3)
        binding3 = str(uuid5(NAMESPACE_URL, "narf.operation-binding.v1:" + contract3))
        binding_path = store3.directory / f"{binding3}.json"
        envelope = json.loads(binding_path.read_text())
        envelope["payload"]["evidence"]["operation_id"] = str(uuid4())
        binding_path.write_text(json.dumps(envelope))
        tamper_blocked = False
        try:
            open_pass(gate3, contract3, task, state, lambda: "bad")
        except NARFError as error:
            tamper_blocked = "authenticated binding required" in str(error)
        rows.append(
            {
                "case": "tampered-operation-binding-blocked",
                "result": "PASS" if tamper_blocked else "FAIL",
                "blocked": tamper_blocked,
            }
        )

        # Case 4: a base NARF contract with no operation binding cannot enter this path.
        store4 = ReceiptStore(root / "case4-receipts", key)
        base4 = NARFGate(store4)
        gate4 = OperationBoundGate(store4)
        contract4 = base4.freeze_contract(
            task,
            task_id="operation-boundary",
            requirements=(requirement,),
            effect_id="publish",
            effect_version="1",
            state=state,
        )
        missing_blocked = False
        try:
            open_pass(gate4, contract4, task, state, lambda: "bad")
        except NARFError as error:
            missing_blocked = "authenticated binding required" in str(error)
        rows.append(
            {
                "case": "missing-operation-binding-blocked",
                "result": "PASS" if missing_blocked else "FAIL",
                "blocked": missing_blocked,
            }
        )

        # Case 5: MgNarf cannot infer business identity if the trusted host renumbers it.
        store5 = ReceiptStore(root / "case5-receipts", key)
        gate5 = OperationBoundGate(store5)
        authority5 = FileConsumptionAuthority(root / "case5-authority")
        executor5 = OperationBoundEffectExecutor(authority5)
        calls5 = []
        first5 = open_pass(
            gate5,
            freeze(gate5, task, state, requirement, str(uuid4())),
            task,
            state,
            lambda: calls5.append("first") or "first",
        )
        second5 = open_pass(
            gate5,
            freeze(gate5, task, state, requirement, str(uuid4())),
            task,
            state,
            lambda: calls5.append("second") or "second",
        )
        executor5.execute(first5)
        executor5.execute(second5)
        limitation = calls5 == ["first", "second"]
        rows.append(
            {
                "case": "trusted-host-renumbers-same-semantic-operation",
                "result": "LIMITATION_CONFIRMED" if limitation else "UNEXPECTED",
                "callback_invocations": len(calls5),
            }
        )

    after = git_status()
    counts = {
        "PASS": sum(row["result"] == "PASS" for row in rows),
        "LIMITATION_CONFIRMED": sum(row["result"] == "LIMITATION_CONFIRMED" for row in rows),
        "FAIL": sum(row["result"] == "FAIL" for row in rows),
        "UNEXPECTED": sum(row["result"] == "UNEXPECTED" for row in rows),
    }
    expected = counts == {"PASS": 4, "LIMITATION_CONFIRMED": 1, "FAIL": 0, "UNEXPECTED": 0}
    summary = {
        "claim": (
            "Fresh contracts sharing the same authenticated host-owned operation UUID cannot each enter the external effect while the consumption authority retains that operation token."
        ),
        "planned_cases": 5,
        "counts": counts,
        "result": "BOUNDARY_CONFIRMED" if expected and before == after else "FAIL",
        "source_unchanged": before == after,
        "cases": rows,
        "limits": [
            "The trusted host defines semantic operation identity; MgNarf cannot infer business equivalence.",
            "If the trusted host assigns a fresh operation UUID to the same real operation, both authorizations can execute; that case is intentionally LIMITATION_CONFIRMED.",
            "Rollback resistance still depends on the configured consumption authority domains.",
            "The legacy contract-scoped NARFGate path remains available for compatibility and retains its documented limitation.",
        ],
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (output / "cases.json").write_text(json.dumps(rows, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    summary = run(Path(args.output))
    return 0 if summary["result"] == "BOUNDARY_CONFIRMED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
