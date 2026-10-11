#!/usr/bin/env python3
"""Measure a PostgreSQL consumption authority as a separate service boundary."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import multiprocessing as mp
import os
from pathlib import Path
import shutil
import sys
import tempfile
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
TABLE = "narf_consumption_ledger"


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def dump(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)


def attempt(call):
    try:
        return {"returned": call(), "error": None}
    except Exception as error:
        return {
            "returned": None,
            "error": {
                "type": type(error).__name__,
                "message": str(error),
                "errno": getattr(error, "errno", None),
            },
        }


def load_api():
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT / "src"))
    from narf import (
        AllOfConsumptionAuthority,
        EffectBinding,
        FileConsumptionAuthority,
        FrozenState,
        NARFError,
        NARFGate,
        PostgresConsumptionAuthority,
        ReceiptStore,
        Requirement,
        RollbackProtectedEffectExecutor,
        VerifierBinding,
        VerifierResult,
        canonical_json_digest,
    )
    return {
        "AllOfConsumptionAuthority": AllOfConsumptionAuthority,
        "EffectBinding": EffectBinding,
        "FileConsumptionAuthority": FileConsumptionAuthority,
        "FrozenState": FrozenState,
        "NARFError": NARFError,
        "NARFGate": NARFGate,
        "PostgresConsumptionAuthority": PostgresConsumptionAuthority,
        "ReceiptStore": ReceiptStore,
        "Requirement": Requirement,
        "RollbackProtectedEffectExecutor": RollbackProtectedEffectExecutor,
        "VerifierBinding": VerifierBinding,
        "VerifierResult": VerifierResult,
        "canonical_json_digest": canonical_json_digest,
    }


def psycopg_module():
    import psycopg
    return psycopg


def admin_execute(admin_dsn: str, sql: str) -> None:
    psycopg = psycopg_module()
    with psycopg.connect(admin_dsn, autocommit=True) as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql)


def reset_ledger(admin_dsn: str) -> None:
    admin_execute(admin_dsn, f"TRUNCATE TABLE {TABLE}")


def ledger_count(admin_dsn: str) -> int:
    psycopg = psycopg_module()
    with psycopg.connect(admin_dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT count(*) FROM {TABLE}")
            return int(cursor.fetchone()[0])


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


def make_fixture(name: str, app_dsn: str):
    api = load_api()
    root = Path(name)
    rollback_domain = root / "rollback-domain"
    external_domain = root / "external-domain"
    external_domain.mkdir(mode=0o700)
    events = external_domain / "events.jsonl"

    key = os.urandom(32)
    store = api["ReceiptStore"](rollback_domain / "receipts", key)
    gate = api["NARFGate"](store)
    requirement = api["Requirement"]("required", "host-check", "1")
    requirements = [requirement]
    state = api["FrozenState"](
        candidate_sha256=sha(b"candidate-v1"),
        requirements_sha256=api["canonical_json_digest"]([asdict(requirement)]),
        policy_sha256=sha(b"policy-v1"),
    )
    task = {"description": "postgres-authority-boundary"}
    contract_id = gate.freeze_contract(
        task,
        task_id="postgres-authority-boundary",
        requirements=requirements,
        effect_id="publish",
        effect_version="1",
        state=state,
    )
    files = [
        api["FileConsumptionAuthority"](root / "local-authority-a"),
        api["FileConsumptionAuthority"](root / "local-authority-b"),
    ]
    postgres = api["PostgresConsumptionAuthority"](app_dsn, table=TABLE)
    combined = api["AllOfConsumptionAuthority"]([files[0], files[1], postgres])
    executor = api["RollbackProtectedEffectExecutor"](combined)
    return {
        "api": api,
        "root": root,
        "rollback_domain": rollback_domain,
        "events": events,
        "key": key,
        "store": store,
        "gate": gate,
        "state": state,
        "task": task,
        "contract_id": contract_id,
        "files": files,
        "postgres": postgres,
        "executor": executor,
        "app_dsn": app_dsn,
    }


def open_pass_session(fixture, store=None, gate=None):
    api = fixture["api"]
    store = store or fixture["store"]
    gate = gate or fixture["gate"]

    def callback():
        return append_event(fixture["events"], "external-effect")

    session = gate.open_session(
        fixture["contract_id"],
        fixture["task"],
        verifier_bindings=[
            api["VerifierBinding"](
                "host-check",
                "1",
                lambda: api["VerifierResult"]("PASS", b"proof"),
            )
        ],
        effect_binding=api["EffectBinding"]("publish", "1", callback),
        state_probe=lambda: fixture["state"],
    )
    session.execute("required")
    decision = session.finalize()
    if decision["result"] != "PASS":
        raise RuntimeError("fixture failed to obtain PASS")
    return session, decision


def restore_local_history(fixture, snapshot: Path):
    shutil.rmtree(fixture["rollback_domain"])
    shutil.copytree(snapshot, fixture["rollback_domain"])
    for authority in fixture["files"]:
        path = authority._path(fixture["contract_id"])
        if path.exists():
            path.unlink()


def fresh_replay(fixture):
    api = fixture["api"]
    new_store = api["ReceiptStore"](fixture["rollback_domain"] / "receipts", fixture["key"])
    new_gate = api["NARFGate"](new_store)
    replay_session, decision = open_pass_session(fixture, new_store, new_gate)
    files = [
        api["FileConsumptionAuthority"](fixture["root"] / "local-authority-a"),
        api["FileConsumptionAuthority"](fixture["root"] / "local-authority-b"),
    ]
    postgres = api["PostgresConsumptionAuthority"](fixture["app_dsn"], table=TABLE)
    combined = api["AllOfConsumptionAuthority"]([files[0], files[1], postgres])
    executor = api["RollbackProtectedEffectExecutor"](combined)
    return attempt(lambda: executor.execute(fixture["contract_id"], replay_session)), decision


def expected_consumed(result) -> bool:
    return (
        result["error"] is not None
        and result["error"]["type"] == "NARFError"
        and "already consumed" in result["error"]["message"]
    )


def run_app_privilege_boundary(output: Path, app_dsn: str, admin_dsn: str):
    reset_ledger(admin_dsn)
    psycopg = psycopg_module()
    blocked = False
    error_type = None
    try:
        with psycopg.connect(app_dsn, autocommit=True) as connection:
            with connection.cursor() as cursor:
                cursor.execute(f"TRUNCATE TABLE {TABLE}")
    except Exception as error:
        blocked = True
        error_type = type(error).__name__
    passed = blocked and ledger_count(admin_dsn) == 0
    row = {
        "case": "app-role-cannot-truncate-ledger",
        "result": "PASS" if passed else "FAIL",
        "truncate_blocked": blocked,
        "error_type": error_type,
        "ledger_rows": ledger_count(admin_dsn),
    }
    dump(output / "app-role-privilege.json", row)
    return row


def run_local_rollback_pg_preserved(output: Path, app_dsn: str, admin_dsn: str):
    reset_ledger(admin_dsn)
    with tempfile.TemporaryDirectory(prefix="narf-postgres-boundary-") as name:
        fixture = make_fixture(name, app_dsn)
        session, first_decision = open_pass_session(fixture)
        snapshot = fixture["root"] / "pre-consumption-snapshot"
        shutil.copytree(fixture["rollback_domain"], snapshot)
        first_effect = fixture["executor"].execute(fixture["contract_id"], session)
        restore_local_history(fixture, snapshot)
        replay, replay_decision = fresh_replay(fixture)
        passed = (
            first_decision["result"] == "PASS"
            and first_effect == "published"
            and replay_decision["result"] == "PASS"
            and expected_consumed(replay)
            and event_count(fixture["events"]) == 1
            and ledger_count(admin_dsn) == 1
        )
        row = {
            "case": "all-local-history-rolled-back-postgres-preserved",
            "result": "PASS" if passed else "FAIL",
            "replay": replay,
            "events_after_replay": event_count(fixture["events"]),
            "ledger_rows": ledger_count(admin_dsn),
        }
        dump(output / "postgres-preserved.json", row)
        return row


class FakeSession:
    def __init__(self):
        self.effect_calls = 0

    def finalize(self):
        return {"result": "PASS"}

    def execute_effect(self):
        self.effect_calls += 1
        return "effect"


def run_unavailable_fail_closed(output: Path):
    api = load_api()
    with tempfile.TemporaryDirectory(prefix="narf-postgres-unavailable-") as name:
        file_authority = api["FileConsumptionAuthority"](Path(name) / "file")
        postgres = api["PostgresConsumptionAuthority"](
            "postgresql://narf_app:invalid@127.0.0.1:1/narf",
            table=TABLE,
            connect_timeout_seconds=1,
        )
        combined = api["AllOfConsumptionAuthority"]([file_authority, postgres])
        executor = api["RollbackProtectedEffectExecutor"](combined)
        token = str(uuid4())
        session = FakeSession()
        result = attempt(lambda: executor.execute(token, session))
        passed = (
            result["error"] is not None
            and result["error"]["type"] == "NARFError"
            and "unavailable" in result["error"]["message"]
            and session.effect_calls == 0
            and file_authority.is_reserved(token)
        )
        row = {
            "case": "postgres-unavailable-fails-closed",
            "result": "PASS" if passed else "FAIL",
            "attempt": result,
            "effect_calls": session.effect_calls,
            "earlier_file_reservation_preserved": file_authority.is_reserved(token),
        }
        dump(output / "unavailable.json", row)
        return row


def reserve_worker(app_dsn: str, token: str, queue):
    try:
        api = load_api()
        authority = api["PostgresConsumptionAuthority"](app_dsn, table=TABLE)
        authority.reserve(token)
        queue.put({"pid": os.getpid(), "result": "RESERVED"})
    except Exception as error:
        queue.put({"pid": os.getpid(), "result": "REJECTED", "type": type(error).__name__, "message": str(error)})


def run_concurrent_single_winner(output: Path, app_dsn: str, admin_dsn: str):
    reset_ledger(admin_dsn)
    token = str(uuid4())
    context = mp.get_context("spawn")
    queue = context.Queue()
    processes = [context.Process(target=reserve_worker, args=(app_dsn, token, queue)) for _ in range(4)]
    for process in processes:
        process.start()
    for process in processes:
        process.join(15)
    rows = [queue.get(timeout=5) for _ in processes]
    exitcodes = [process.exitcode for process in processes]
    reserved = sum(row["result"] == "RESERVED" for row in rows)
    rejected = [row for row in rows if row["result"] == "REJECTED"]
    passed = (
        exitcodes == [0, 0, 0, 0]
        and reserved == 1
        and len(rejected) == 3
        and all(row["type"] == "NARFError" and "already consumed" in row["message"] for row in rejected)
        and ledger_count(admin_dsn) == 1
    )
    row = {
        "case": "four-process-single-winner",
        "result": "PASS" if passed else "FAIL",
        "workers": rows,
        "exitcodes": exitcodes,
        "reserved": reserved,
        "rejected": len(rejected),
        "ledger_rows": ledger_count(admin_dsn),
    }
    dump(output / "concurrent.json", row)
    return row


def run_admin_truncate_limitation(output: Path, app_dsn: str, admin_dsn: str):
    reset_ledger(admin_dsn)
    with tempfile.TemporaryDirectory(prefix="narf-postgres-admin-truncate-") as name:
        fixture = make_fixture(name, app_dsn)
        session, first_decision = open_pass_session(fixture)
        snapshot = fixture["root"] / "pre-consumption-snapshot"
        shutil.copytree(fixture["rollback_domain"], snapshot)
        first_effect = fixture["executor"].execute(fixture["contract_id"], session)
        restore_local_history(fixture, snapshot)
        admin_execute(admin_dsn, f"TRUNCATE TABLE {TABLE}")
        replay, replay_decision = fresh_replay(fixture)
        limitation = (
            first_decision["result"] == "PASS"
            and first_effect == "published"
            and replay_decision["result"] == "PASS"
            and replay["error"] is None
            and replay["returned"] == "published"
            and event_count(fixture["events"]) == 2
            and ledger_count(admin_dsn) == 1
        )
        row = {
            "case": "privileged-postgres-ledger-reset",
            "result": "LIMITATION_CONFIRMED" if limitation else "FAIL",
            "replay": replay,
            "events_after_replay": event_count(fixture["events"]),
            "ledger_rows_after_replay": ledger_count(admin_dsn),
            "admin_history_reset": True,
        }
        dump(output / "admin-truncate.json", row)
        return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--app-dsn", required=True)
    parser.add_argument("--admin-dsn", required=True)
    args = parser.parse_args()
    if not args.output.is_absolute() or args.output.resolve().is_relative_to(ROOT):
        parser.error("--output must be absolute and outside the repository")
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)

    source_hashes = {
        str(path.relative_to(ROOT)): sha(path.read_bytes())
        for path in sorted((ROOT / "src/narf").glob("*.py"))
    }
    psycopg = psycopg_module()
    rows = [
        run_app_privilege_boundary(args.output, args.app_dsn, args.admin_dsn),
        run_local_rollback_pg_preserved(args.output, args.app_dsn, args.admin_dsn),
        run_unavailable_fail_closed(args.output),
        run_concurrent_single_winner(args.output, args.app_dsn, args.admin_dsn),
        run_admin_truncate_limitation(args.output, args.app_dsn, args.admin_dsn),
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
    expected = counts == {"PASS": 4, "LIMITATION_CONFIRMED": 1, "FAIL": 0}
    summary = {
        "planned_cases": 5,
        "counts": counts,
        "source_unchanged": unchanged,
        "psycopg_version": psycopg.__version__,
        "result": "BOUNDARY_CONFIRMED" if expected and unchanged else "FAIL",
        "claim": "A separately running PostgreSQL unique ledger blocks replay across complete local receipt/file-authority rollback while its ledger history is preserved.",
        "limits": [
            "The CI PostgreSQL service is a separate service process/container, not proof of independent administration or disaster-recovery control.",
            "A privileged PostgreSQL administrator that truncates or restores the ledger can resurrect authorization when every other history domain is also rewound.",
            "The runtime app role is intentionally limited to INSERT and SELECT; operational deployments must preserve equivalent least privilege.",
            "This does not establish Byzantine tolerance, cross-region linearizability, physical power-loss semantics, or exactly-once remote completion.",
        ],
    }
    dump(args.output / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["result"] == "BOUNDARY_CONFIRMED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
