#!/usr/bin/env python3
"""Measure multi-domain fencing against authority rollback and deletion."""
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
    from narf.rollback_guard import (
        AllOfConsumptionAuthority,
        FileConsumptionAuthority,
        RollbackProtectedEffectExecutor,
    )
    return (
        EffectBinding,
        FrozenState,
        NARFGate,
        ReceiptStore,
        Requirement,
        VerifierBinding,
        VerifierResult,
        canonical_json_digest,
        AllOfConsumptionAuthority,
        FileConsumptionAuthority,
        RollbackProtectedEffectExecutor,
    )


def append_event(path: Path) -> str:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        raw = (json.dumps({"event": "external-effect", "pid": os.getpid()}) + "\n").encode()
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


def sync_dir(path: Path) -> None:
    dfd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def restore_tree(snapshot: Path, target: Path) -> None:
    shutil.rmtree(target)
    shutil.copytree(snapshot, target)
    sync_dir(target.parent)


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
        AllOfConsumptionAuthority,
        FileConsumptionAuthority,
        RollbackProtectedEffectExecutor,
    ) = load_api()

    root = Path(name)
    receipt_domain = root / "receipt-domain"
    authority_domains = [root / f"authority-{label}" for label in ("a", "b", "c")]
    external_domain = root / "external-domain"
    external_domain.mkdir(mode=0o700)
    events = external_domain / "events.jsonl"

    key = os.urandom(32)
    store = ReceiptStore(receipt_domain / "receipts", key)
    gate = NARFGate(store)
    requirement = Requirement("required", "host-check", "1")
    state = FrozenState(
        candidate_sha256=sha(b"candidate-v1"),
        requirements_sha256=canonical_json_digest([asdict(requirement)]),
        policy_sha256=sha(b"policy-v1"),
    )
    task = {"description": "multi-domain fencing fixture"}
    contract_id = gate.freeze_contract(
        task,
        task_id="multidomain-fencing",
        requirements=[requirement],
        effect_id="publish",
        effect_version="1",
        state=state,
    )
    authorities = [FileConsumptionAuthority(path) for path in authority_domains]
    combined = AllOfConsumptionAuthority(authorities)
    executor = RollbackProtectedEffectExecutor(combined)
    return {
        "root": root,
        "receipt_domain": receipt_domain,
        "authority_domains": authority_domains,
        "events": events,
        "key": key,
        "store": store,
        "gate": gate,
        "state": state,
        "task": task,
        "contract_id": contract_id,
        "authorities": authorities,
        "combined": combined,
        "executor": executor,
        "ReceiptStore": ReceiptStore,
        "NARFGate": NARFGate,
        "AllOfConsumptionAuthority": AllOfConsumptionAuthority,
        "FileConsumptionAuthority": FileConsumptionAuthority,
        "RollbackProtectedEffectExecutor": RollbackProtectedEffectExecutor,
    }


def open_pass_session(fixture, store=None, gate=None):
    (
        EffectBinding,
        _FrozenState,
        _NARFGate,
        _ReceiptStore,
        _Requirement,
        VerifierBinding,
        VerifierResult,
        _canonical,
        _AllOf,
        _FileAuthority,
        _Executor,
    ) = load_api()
    store = store or fixture["store"]
    gate = gate or fixture["gate"]

    session = gate.open_session(
        fixture["contract_id"],
        fixture["task"],
        verifier_bindings=[
            VerifierBinding("host-check", "1", lambda: VerifierResult("PASS", b"proof"))
        ],
        effect_binding=EffectBinding(
            "publish", "1", lambda: append_event(fixture["events"])
        ),
        state_probe=lambda: fixture["state"],
    )
    session.execute("required")
    decision = session.finalize()
    if decision["result"] != "PASS":
        raise RuntimeError("multi-domain fixture failed to obtain PASS")
    return session, decision


def expected_authority_block(result) -> bool:
    return (
        result["error"] is not None
        and result["error"]["type"] == "NARFError"
        and "external consumption authority already consumed" in result["error"]["message"]
    )


def delete_local_effect_receipt(store) -> None:
    receipts = [
        path for path in store.directory.glob("*.json")
        if (store.load(path.stem) or {}).get("evidence_type") == "narf.effect"
    ]
    if len(receipts) != 1:
        raise RuntimeError("expected exactly one local effect receipt")
    receipts[0].unlink()
    sync_dir(store.directory)


def new_protected_stack(fixture):
    new_store = fixture["ReceiptStore"](
        fixture["receipt_domain"] / "receipts", fixture["key"]
    )
    new_gate = fixture["NARFGate"](new_store)
    authorities = [
        fixture["FileConsumptionAuthority"](path)
        for path in fixture["authority_domains"]
    ]
    combined = fixture["AllOfConsumptionAuthority"](authorities)
    executor = fixture["RollbackProtectedEffectExecutor"](combined)
    return new_store, new_gate, authorities, combined, executor


def run_rollback_case(output: Path, rolled_back: tuple[int, ...], case_name: str, expect_block: bool):
    with tempfile.TemporaryDirectory(prefix="narf-multidomain-") as name:
        fixture = make_fixture(name)
        session, first_decision = open_pass_session(fixture)

        receipt_snapshot = fixture["root"] / "receipt-snapshot"
        shutil.copytree(fixture["receipt_domain"], receipt_snapshot)
        authority_snapshots = []
        for index, domain in enumerate(fixture["authority_domains"]):
            snapshot = fixture["root"] / f"authority-snapshot-{index}"
            shutil.copytree(domain, snapshot)
            authority_snapshots.append(snapshot)

        first_effect = fixture["executor"].execute(fixture["contract_id"], session)
        first_events = event_count(fixture["events"])
        first_states = fixture["combined"].reservation_states(fixture["contract_id"])

        restore_tree(receipt_snapshot, fixture["receipt_domain"])
        for index in rolled_back:
            restore_tree(authority_snapshots[index], fixture["authority_domains"][index])

        new_store, new_gate, _authorities, combined, executor = new_protected_stack(fixture)
        replay_session, replay_decision = open_pass_session(fixture, new_store, new_gate)
        replay = attempt(lambda: executor.execute(fixture["contract_id"], replay_session))
        events_after = event_count(fixture["events"])
        consumptions_after = consumption_count(new_store)
        states_after = combined.reservation_states(fixture["contract_id"])

        if expect_block:
            passed = (
                first_decision["result"] == "PASS"
                and first_effect == "published"
                and first_events == 1
                and first_states == (True, True, True)
                and replay_decision["result"] == "PASS"
                and expected_authority_block(replay)
                and events_after == 1
                and consumptions_after == 0
                and any(states_after)
            )
            result = "PASS" if passed else "FAIL"
        else:
            limitation = (
                first_decision["result"] == "PASS"
                and first_effect == "published"
                and first_events == 1
                and replay_decision["result"] == "PASS"
                and replay["error"] is None
                and replay["returned"] == "published"
                and events_after == 2
                and consumptions_after == 1
                and states_after == (True, True, True)
            )
            result = "LIMITATION_CONFIRMED" if limitation else "FAIL"

        row = {
            "case": case_name,
            "result": result,
            "rolled_back_authority_indexes": list(rolled_back),
            "first_events": first_events,
            "first_authority_states": list(first_states),
            "replay_decision": replay_decision,
            "replay": replay,
            "events_after_replay": events_after,
            "consumptions_after_replay": consumptions_after,
            "authority_states_after_replay": list(states_after),
        }
        dump(output / f"{case_name}.json", row)
        return row


def run_delete_one_case(output: Path):
    with tempfile.TemporaryDirectory(prefix="narf-multidomain-") as name:
        fixture = make_fixture(name)
        session, first_decision = open_pass_session(fixture)
        first_effect = fixture["executor"].execute(fixture["contract_id"], session)
        delete_local_effect_receipt(fixture["store"])

        deleted = fixture["authorities"][1]._path(fixture["contract_id"])
        deleted.unlink()
        sync_dir(fixture["authority_domains"][1])

        new_store, new_gate, _authorities, combined, executor = new_protected_stack(fixture)
        replay_session, replay_decision = open_pass_session(fixture, new_store, new_gate)
        replay = attempt(lambda: executor.execute(fixture["contract_id"], replay_session))
        states_after = combined.reservation_states(fixture["contract_id"])
        passed = (
            first_decision["result"] == "PASS"
            and first_effect == "published"
            and replay_decision["result"] == "PASS"
            and expected_authority_block(replay)
            and event_count(fixture["events"]) == 1
            and consumption_count(new_store) == 0
            and states_after[0]
            and states_after[2]
        )
        row = {
            "case": "delete-one-of-three-authorities",
            "result": "PASS" if passed else "FAIL",
            "deleted_authority_index": 1,
            "replay_decision": replay_decision,
            "replay": replay,
            "events_after_replay": event_count(fixture["events"]),
            "consumptions_after_replay": consumption_count(new_store),
            "authority_states_after_replay": list(states_after),
        }
        dump(output / "delete-one-of-three-authorities.json", row)
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
        run_rollback_case(args.output, (0,), "rollback-one-of-three-authorities", True),
        run_rollback_case(args.output, (0, 1), "rollback-two-of-three-authorities", True),
        run_delete_one_case(args.output),
        run_rollback_case(args.output, (0, 1, 2), "rollback-all-three-authorities", False),
    ]
    unchanged = {
        str(path.relative_to(ROOT)): sha(path.read_bytes())
        for path in sorted((ROOT / "src/narf").glob("*.py"))
    } == source_hashes
    counts = {
        "PASS": sum(row["result"] == "PASS" for row in rows),
        "LIMITATION_CONFIRMED": sum(row["result"] == "LIMITATION_CONFIRMED" for row in rows),
        "FAIL": sum(row["result"] == "FAIL" for row in rows),
    }
    expected = {"PASS": 3, "LIMITATION_CONFIRMED": 1, "FAIL": 0}
    summary = {
        "planned_cases": 4,
        "counts": counts,
        "source_unchanged": unchanged,
        "result": "BOUNDARY_CONFIRMED" if counts == expected and unchanged else "FAIL",
        "claim": "With all-of independent consumption authorities, replay remains blocked while at least one authority domain preserves the consumed token.",
        "limits": [
            "The CI fixture fault-injects logically separate directories; it does not prove operational independence of real storage or administrators.",
            "If every configured authority domain is rolled back or deleted together, the same authorization can be resurrected; that case remains LIMITATION_CONFIRMED.",
            "This is an all-of fencing set, not a majority quorum. Majority acceptance can be unsafe for rollback replay if the accepting majority was rewound.",
            "Physical power-loss behavior, cross-machine linearizability, Byzantine authorities and exactly-once remote completion remain outside this claim.",
        ],
    }
    dump(args.output / "summary.json", summary)
    print(json.dumps(summary, indent=2))
    return 0 if summary["result"] == "BOUNDARY_CONFIRMED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
