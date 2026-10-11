#!/usr/bin/env python3
"""Verify rollback hardening with a consumption authority outside receipt rollback."""
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


def attempt(call):
    try:
        return {"returned": call(), "error": None}
    except Exception as error:
        return {"returned": None, "error": {
            "type": type(error).__name__,
            "message": str(error),
            "errno": getattr(error, "errno", None),
        }}


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
        canonical_json_digest,
    )
    from narf.rollback_guard import FileConsumptionAuthority, RollbackProtectedEffectExecutor
    return (
        EffectBinding,
        FrozenState,
        NARFGate,
        ReceiptStore,
        Requirement,
        VerifierBinding,
        VerifierResult,
        canonical_json_digest,
        FileConsumptionAuthority,
        RollbackProtectedEffectExecutor,
    )


def append_event(path: Path, label: str) -> str:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        raw = (json.dumps({"event": label, "pid": os.getpid()}) + "\n").encode()
        if os.write(fd, raw) != len(raw):
            raise RuntimeError("short event write")
        os.fsync(fd)
    finally:
        os.close(fd)
    dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return "published"


def event_count(path: Path) -> int:
    return len(path.read_text().splitlines()) if path.exists() else 0


def consumption_count(store) -> int:
    return sum(
        (store.load(path.stem) or {}).get("evidence_type") == "narf.effect"
        for path in store.directory.glob("*.json")
    )


def make_fixture(name: str):
    (
        _EffectBinding,
        FrozenState,
        NARFGate,
        ReceiptStore,
        Requirement,
        _VerifierBinding,
        _VerifierResult,
        canonical_json_digest,
        FileConsumptionAuthority,
        RollbackProtectedEffectExecutor,
    ) = load_api()

    root = Path(name)
    rollback_domain = root / "rollback-domain"
    authority_domain = root / "monotonic-domain"
    external_domain = root / "external-domain"
    external_domain.mkdir(mode=0o700)
    events = external_domain / "events.jsonl"

    key = os.urandom(32)
    store = ReceiptStore(rollback_domain / "receipts", key)
    gate = NARFGate(store)
    requirement = Requirement("required", "host-check", "1")
    requirements = [requirement]
    state = FrozenState(
        candidate_sha256=sha(b"candidate-v1"),
        requirements_sha256=canonical_json_digest([asdict(requirement)]),
        policy_sha256=sha(b"policy-v1"),
    )
    task = {"description": "rollback-protected fixture"}
    contract_id = gate.freeze_contract(
        task,
        task_id="rollback-hardening",
        requirements=requirements,
        effect_id="publish",
        effect_version="1",
        state=state,
    )
    authority = FileConsumptionAuthority(authority_domain)
    executor = RollbackProtectedEffectExecutor(authority)
    return {
        "root": root,
        "rollback_domain": rollback_domain,
        "authority_domain": authority_domain,
        "events": events,
        "key": key,
        "store": store,
        "gate": gate,
        "state": state,
        "task": task,
        "contract_id": contract_id,
        "authority": authority,
        "executor": executor,
        "ReceiptStore": ReceiptStore,
        "NARFGate": NARFGate,
        "FileConsumptionAuthority": FileConsumptionAuthority,
        "RollbackProtectedEffectExecutor": RollbackProtectedEffectExecutor,
    }


def open_pass_session(fixture, store=None, gate=None):
    EffectBinding, _FrozenState, _NARFGate, _ReceiptStore, _Requirement, VerifierBinding, VerifierResult, _canonical, _Authority, _Executor = load_api()
    store = store or fixture["store"]
    gate = gate or fixture["gate"]

    def callback():
        return append_event(fixture["events"], "external-effect")

    session = gate.open_session(
        fixture["contract_id"],
        fixture["task"],
        verifier_bindings=[
            VerifierBinding("host-check", "1", lambda: VerifierResult("PASS", b"proof"))
        ],
        effect_binding=EffectBinding("publish", "1", callback),
        state_probe=lambda: fixture["state"],
    )
    session.execute("required")
    decision = session.finalize()
    if decision["result"] != "PASS":
        raise RuntimeError("hardening fixture failed to obtain PASS")
    return session, decision


def expected_authority_block(result) -> bool:
    return (
        result["error"] is not None
        and result["error"]["type"] == "NARFError"
        and "external consumption authority already consumed" in result["error"]["message"]
    )


def run_restore_snapshot(output: Path):
    with tempfile.TemporaryDirectory(prefix="narf-rollback-hardening-") as name:
        fixture = make_fixture(name)
        session, first_decision = open_pass_session(fixture)

        snapshot = fixture["root"] / "pre-consumption-snapshot"
        shutil.copytree(fixture["rollback_domain"], snapshot)

        first_effect = fixture["executor"].execute(fixture["contract_id"], session)
        first_events = event_count(fixture["events"])
        first_consumptions = consumption_count(fixture["store"])

        shutil.rmtree(fixture["rollback_domain"])
        shutil.copytree(snapshot, fixture["rollback_domain"])

        new_store = fixture["ReceiptStore"](fixture["rollback_domain"] / "receipts", fixture["key"])
        new_gate = fixture["NARFGate"](new_store)
        replay_session, replay_decision = open_pass_session(fixture, new_store, new_gate)
        new_authority = fixture["FileConsumptionAuthority"](fixture["authority_domain"])
        new_executor = fixture["RollbackProtectedEffectExecutor"](new_authority)
        replay = attempt(lambda: new_executor.execute(fixture["contract_id"], replay_session))

        passed = (
            first_decision["result"] == "PASS"
            and first_effect == "published"
            and first_events == 1
            and first_consumptions == 1
            and replay_decision["result"] == "PASS"
            and expected_authority_block(replay)
            and event_count(fixture["events"]) == 1
            and consumption_count(new_store) == 0
            and new_authority.is_reserved(fixture["contract_id"])
            and new_store.load(fixture["contract_id"]) is not None
        )
        row = {
            "case": "restore-pre-consumption-receipt-snapshot",
            "result": "PASS" if passed else "FAIL",
            "first_events": first_events,
            "first_consumptions": first_consumptions,
            "replay_decision": replay_decision,
            "replay": replay,
            "events_after_replay": event_count(fixture["events"]),
            "consumptions_after_replay": consumption_count(new_store),
            "authority_reserved": new_authority.is_reserved(fixture["contract_id"]),
            "receipt_domain_restored": True,
            "authority_domain_restored": False,
        }
        dump(output / "restore-snapshot.json", row)
        return row


def run_delete_consumption(output: Path):
    with tempfile.TemporaryDirectory(prefix="narf-rollback-hardening-") as name:
        fixture = make_fixture(name)
        session, first_decision = open_pass_session(fixture)
        first_effect = fixture["executor"].execute(fixture["contract_id"], session)
        effect_receipts = [
            path for path in fixture["store"].directory.glob("*.json")
            if (fixture["store"].load(path.stem) or {}).get("evidence_type") == "narf.effect"
        ]
        if len(effect_receipts) != 1:
            raise RuntimeError("expected exactly one consumption receipt")
        effect_receipts[0].unlink()
        dfd = os.open(fixture["store"].directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

        new_store = fixture["ReceiptStore"](fixture["rollback_domain"] / "receipts", fixture["key"])
        new_gate = fixture["NARFGate"](new_store)
        replay_session, replay_decision = open_pass_session(fixture, new_store, new_gate)
        new_authority = fixture["FileConsumptionAuthority"](fixture["authority_domain"])
        new_executor = fixture["RollbackProtectedEffectExecutor"](new_authority)
        replay = attempt(lambda: new_executor.execute(fixture["contract_id"], replay_session))

        passed = (
            first_decision["result"] == "PASS"
            and first_effect == "published"
            and replay_decision["result"] == "PASS"
            and expected_authority_block(replay)
            and event_count(fixture["events"]) == 1
            and consumption_count(new_store) == 0
            and new_authority.is_reserved(fixture["contract_id"])
        )
        row = {
            "case": "delete-consumption-receipt",
            "result": "PASS" if passed else "FAIL",
            "replay_decision": replay_decision,
            "replay": replay,
            "events_after_replay": event_count(fixture["events"]),
            "consumptions_after_replay": consumption_count(new_store),
            "authority_reserved": new_authority.is_reserved(fixture["contract_id"]),
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
    rows = [run_restore_snapshot(args.output), run_delete_consumption(args.output)]
    unchanged = {
        str(path.relative_to(ROOT)): sha(path.read_bytes())
        for path in sorted((ROOT / "src/narf").glob("*.py"))
    } == source_hashes
    counts = {
        "PASS": sum(row["result"] == "PASS" for row in rows),
        "FAIL": sum(row["result"] == "FAIL" for row in rows),
    }
    summary = {
        "planned_cases": 2,
        "counts": counts,
        "source_unchanged": unchanged,
        "result": "PASS" if counts == {"PASS": 2, "FAIL": 0} and unchanged else "FAIL",
        "claim": "Receipt-domain rollback replay is blocked when the consumption authority remains outside that rollback domain.",
        "limits": [
            "The file-backed authority is rollback resistant only relative to a receipt snapshot that does not rewind the authority directory.",
            "If an attacker can also delete or roll back the authority directory, this reference configuration does not provide a monotonic guarantee.",
            "Production deployment still needs an independently protected monotonic service, ledger, fencing epoch, TPM/HSM primitive, database transaction domain, or equivalent.",
        ],
    }
    dump(args.output / "summary.json", summary)
    print(json.dumps(summary, indent=2))
    return 0 if summary["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
