#!/usr/bin/env python3
"""Characterize cross-contract semantic idempotency.

This witness asks a narrow question: if a trusted host freezes the exact same
task, verifier requirement set, effect binding identity and frozen state twice,
do the two independently generated contracts share a consumption token?

The current reference model documents at-most-once per authorization/contract.
This fixture intentionally does not call a second invocation a security FAIL.
If both otherwise identical contracts can invoke the same callback once each,
the result is LIMITATION_CONFIRMED: operation-level idempotency requires a
host-owned stable operation identity outside the random contract UUID.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "src"))

from narf import (  # noqa: E402
    EffectBinding,
    FrozenState,
    NARFGate,
    ReceiptStore,
    Requirement,
    VerifierBinding,
    VerifierResult,
    canonical_json_digest,
)
from narf.rollback_guard import (  # noqa: E402
    FileConsumptionAuthority,
    RollbackProtectedEffectExecutor,
)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git_status() -> str:
    return subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=ROOT,
        text=True,
    )


def event_count(path: Path) -> int:
    return len(path.read_text().splitlines()) if path.exists() else 0


def append_event(path: Path, contract_id: str) -> str:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        raw = (json.dumps({"contract_id": contract_id}) + "\n").encode()
        if os.write(fd, raw) != len(raw):
            raise RuntimeError("short event write")
        os.fsync(fd)
    finally:
        os.close(fd)
    return "published"


def open_pass_session(gate, contract_id, task, state, events):
    def callback():
        return append_event(events, contract_id)

    session = gate.open_session(
        contract_id,
        task,
        verifier_bindings=[
            VerifierBinding("host-check", "1", lambda: VerifierResult("PASS", b"proof"))
        ],
        effect_binding=EffectBinding("publish", "1", callback),
        state_probe=lambda: state,
    )
    session.execute("required")
    decision = session.finalize()
    if decision.get("result") != "PASS":
        raise RuntimeError("fixture failed to obtain authenticated PASS")
    return session


def run(output: Path) -> dict:
    before = git_status()
    with tempfile.TemporaryDirectory(prefix="narf-operation-idempotency-") as name:
        root = Path(name)
        receipts = root / "receipts"
        authority_dir = root / "authority"
        events = root / "events.jsonl"

        store = ReceiptStore(receipts, os.urandom(32))
        gate = NARFGate(store)
        authority = FileConsumptionAuthority(authority_dir)
        executor = RollbackProtectedEffectExecutor(authority)

        requirement = Requirement("required", "host-check", "1")
        requirements = [requirement]
        task = {"description": "identical frozen operation", "target": "same-target"}
        state = FrozenState(
            candidate_sha256=sha(b"candidate-v1"),
            requirements_sha256=canonical_json_digest([asdict(requirement)]),
            policy_sha256=sha(b"policy-v1"),
        )

        contract_ids = [
            gate.freeze_contract(
                task,
                task_id="operation-idempotency-witness",
                requirements=requirements,
                effect_id="publish",
                effect_version="1",
                state=state,
            )
            for _ in range(2)
        ]

        semantic_fingerprint = canonical_json_digest(
            {
                "task": task,
                "task_id": "operation-idempotency-witness",
                "requirements": [asdict(requirement)],
                "effect_id": "publish",
                "effect_version": "1",
                "state": asdict(state),
            }
        )

        returned = []
        for contract_id in contract_ids:
            session = open_pass_session(gate, contract_id, task, state, events)
            returned.append(executor.execute(contract_id, session))

        after = git_status()
        distinct_contracts = len(set(contract_ids)) == 2
        both_reserved = all(authority.is_reserved(contract_id) for contract_id in contract_ids)
        calls = event_count(events)
        reproduced = (
            distinct_contracts
            and returned == ["published", "published"]
            and both_reserved
            and calls == 2
            and before == after
        )

        row = {
            "case": "identical-frozen-input-two-contracts",
            "result": "LIMITATION_CONFIRMED" if reproduced else "UNEXPECTED",
            "semantic_fingerprint": semantic_fingerprint,
            "contract_ids": contract_ids,
            "distinct_contract_ids": distinct_contracts,
            "authority_reserved_each_contract": both_reserved,
            "callback_invocations": calls,
            "source_unchanged": before == after,
        }

    summary = {
        "claim": (
            "The current consumption token is contract-scoped. Two independently frozen contracts "
            "with identical authorization inputs can each invoke the same callback once."
        ),
        "planned_cases": 1,
        "counts": {
            "LIMITATION_CONFIRMED": 1 if reproduced else 0,
            "UNEXPECTED": 0 if reproduced else 1,
        },
        "result": "LIMITATION_CONFIRMED" if reproduced else "UNEXPECTED",
        "source_unchanged": row["source_unchanged"],
        "case": row,
        "limits": [
            "This witness does not claim that two identical contracts are always the same business operation.",
            "It demonstrates that MgNarf itself has no stable host-owned operation idempotency key beyond contract_id.",
            "Current at-most-once claims remain valid at the individual authorization/contract boundary.",
        ],
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "case.json").write_text(json.dumps(row, indent=2) + "\n")
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    summary = run(Path(args.output))
    return 0 if summary["result"] == "LIMITATION_CONFIRMED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
