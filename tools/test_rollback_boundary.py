#!/usr/bin/env python3
"""Witness the documented rollback limitation of the filesystem receipt store.

A successful run returns LIMITATION_CONFIRMED, not PASS. It demonstrates that
restoring or deleting trusted receipt history can resurrect an already consumed
authorization when no monotonic checkpoint exists outside the rollback domain.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def dump(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def load_api():
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT / "src"))
    from narf import (
        EffectBinding,
        FrozenState,
        NARFGate,
        ReceiptStore,
        Requirement,
        VerifierBinding,
        VerifierResult,
    )
    return (
        EffectBinding,
        FrozenState,
        NARFGate,
        ReceiptStore,
        Requirement,
        VerifierBinding,
        VerifierResult,
    )


def effect_receipts(store):
    return sorted(
        path for path in store.directory.glob("*.json")
        if (store.load(path.stem) or {}).get("evidence_type") == "narf.effect"
    )


def effect_count(target: Path) -> int:
    return len(target.read_bytes().splitlines()) if target.exists() else 0


def fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def make_fixture(name: str):
    (
        EffectBinding,
        FrozenState,
        NARFGate,
        ReceiptStore,
        Requirement,
        VerifierBinding,
        VerifierResult,
    ) = load_api()
    root = Path(name)
    key = os.urandom(32)
    store = ReceiptStore(root / "receipts", key)
    gate = NARFGate(store)
    task = {"description": "rollback witness"}
    state = FrozenState(
        candidate_sha256=sha(b"candidate-v1"),
        requirements_sha256=sha(b"requirements-v1"),
        policy_sha256=sha(b"policy-v1"),
    )
    contract_id = gate.freeze_contract(
        task,
        task_id="rollback-witness",
        requirements=[Requirement("required", "host-check", "1")],
        effect_id="publish",
        effect_version="1",
        state=state,
    )
    target = root / "external-effect.log"

    def callback():
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            payload = b"effect\n"
            if os.write(fd, payload) != len(payload):
                raise RuntimeError("short external-effect write")
            os.fsync(fd)
        finally:
            os.close(fd)
        fsync_dir(root)
        return "effect-written"

    def session():
        current_store = ReceiptStore(root / "receipts", key)
        current = NARFGate(current_store).open_session(
            contract_id,
            task,
            verifier_bindings=[
                VerifierBinding("host-check", "1", lambda: VerifierResult("PASS", b"proof"))
            ],
            effect_binding=EffectBinding("publish", "1", callback),
            state_probe=lambda: state,
        )
        current.execute("required")
        decision = current.finalize()
        if decision["result"] != "PASS":
            raise RuntimeError("rollback witness failed to obtain baseline PASS")
        return current_store, current, decision

    return root, key, store, contract_id, task, asdict(state), target, session


def case_snapshot_restore(output: Path):
    with tempfile.TemporaryDirectory(prefix="narf-rollback-snapshot-") as name:
        root, key, store, contract_id, _task, _state, target, session = make_fixture(name)
        live_store, first, _decision = session()
        snapshot = root / "receipt-snapshot-before-consumption"
        shutil.copytree(live_store.directory, snapshot)

        first_result = first.execute_effect()
        first_receipts = effect_receipts(live_store)
        first_effect_id = first_receipts[0].stem if len(first_receipts) == 1 else None
        before_restore_effects = effect_count(target)

        shutil.rmtree(live_store.directory)
        shutil.copytree(snapshot, live_store.directory)
        restored = type(live_store)(live_store.directory, key)
        restored_contract_authenticated = restored.load(contract_id) is not None
        restored_effect_receipts = effect_receipts(restored)

        replay_store, replay_session, replay_decision = session()
        replay_result = replay_session.execute_effect()
        replay_receipts = effect_receipts(replay_store)
        replay_effect_id = replay_receipts[0].stem if len(replay_receipts) == 1 else None
        after_replay_effects = effect_count(target)

        confirmed = (
            first_result == "effect-written"
            and before_restore_effects == 1
            and first_effect_id is not None
            and restored_contract_authenticated
            and restored_effect_receipts == []
            and replay_decision["result"] == "PASS"
            and replay_result == "effect-written"
            and after_replay_effects == 2
            and replay_effect_id == first_effect_id
        )
        row = {
            "case": "restore-pre-consumption-snapshot",
            "result": "LIMITATION_CONFIRMED" if confirmed else "UNEXPECTED",
            "first_effect_id": first_effect_id,
            "replay_effect_id": replay_effect_id,
            "effects_before_restore": before_restore_effects,
            "restored_contract_authenticated": restored_contract_authenticated,
            "restored_consumption_receipts": len(restored_effect_receipts),
            "replay_decision": replay_decision,
            "effects_after_replay": after_replay_effects,
        }
        dump(output / "snapshot-restore.json", row)
        return row


def case_delete_consumption(output: Path):
    with tempfile.TemporaryDirectory(prefix="narf-rollback-delete-") as name:
        _root, _key, store, _contract_id, _task, _state, target, session = make_fixture(name)
        live_store, first, _decision = session()
        first_result = first.execute_effect()
        first_receipts = effect_receipts(live_store)
        first_effect_id = first_receipts[0].stem if len(first_receipts) == 1 else None
        before_delete_effects = effect_count(target)

        if len(first_receipts) == 1:
            first_receipts[0].unlink()
            fsync_dir(live_store.directory)

        replay_store, replay_session, replay_decision = session()
        replay_result = replay_session.execute_effect()
        replay_receipts = effect_receipts(replay_store)
        replay_effect_id = replay_receipts[0].stem if len(replay_receipts) == 1 else None
        after_replay_effects = effect_count(target)

        confirmed = (
            first_result == "effect-written"
            and before_delete_effects == 1
            and first_effect_id is not None
            and replay_decision["result"] == "PASS"
            and replay_result == "effect-written"
            and after_replay_effects == 2
            and replay_effect_id == first_effect_id
        )
        row = {
            "case": "delete-consumption-receipt",
            "result": "LIMITATION_CONFIRMED" if confirmed else "UNEXPECTED",
            "first_effect_id": first_effect_id,
            "replay_effect_id": replay_effect_id,
            "effects_before_delete": before_delete_effects,
            "replay_decision": replay_decision,
            "effects_after_replay": after_replay_effects,
        }
        dump(output / "delete-consumption.json", row)
        return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.output.is_absolute() or args.output.resolve().is_relative_to(ROOT):
        parser.error("--output must be absolute and outside the repository")
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)

    source_hashes = {
        str(path.relative_to(ROOT)): sha(path.read_bytes())
        for path in sorted((ROOT / "src/narf").glob("*.py"))
    }
    rows = [
        case_snapshot_restore(args.output),
        case_delete_consumption(args.output),
    ]
    source_unchanged = {
        str(path.relative_to(ROOT)): sha(path.read_bytes())
        for path in sorted((ROOT / "src/narf").glob("*.py"))
    } == source_hashes
    counts = {
        "LIMITATION_CONFIRMED": sum(row["result"] == "LIMITATION_CONFIRMED" for row in rows),
        "UNEXPECTED": sum(row["result"] == "UNEXPECTED" for row in rows),
    }
    reproduced = counts == {"LIMITATION_CONFIRMED": 2, "UNEXPECTED": 0} and source_unchanged
    summary = {
        "planned_cases": 2,
        "counts": counts,
        "source_unchanged": source_unchanged,
        "result": "LIMITATION_CONFIRMED" if reproduced else "UNEXPECTED",
        "security_interpretation": (
            "This is a reproduced limitation, not NARF PASS. Filesystem receipt history "
            "alone is not rollback-resistant."
        ),
        "required_hardening": (
            "Use a monotonic checkpoint or ledger outside the receipt-store rollback domain "
            "when privileged deletion or rollback is in the threat model."
        ),
    }
    dump(args.output / "summary.json", summary)
    print(json.dumps(summary, indent=2))
    return 0 if summary["result"] == "LIMITATION_CONFIRMED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
