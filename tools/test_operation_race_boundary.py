#!/usr/bin/env python3
"""Cross-process operation-id race plus database/local rollback boundary."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
TABLE = "narf_consumption_ledger"
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "src"))

from narf import (  # noqa: E402
    AllOfConsumptionAuthority,
    EffectBinding,
    FrozenState,
    OperationBoundEffectExecutor,
    OperationBoundGate,
    PostgresConsumptionAuthority,
    ReceiptStore,
    Requirement,
    SignedWitnessAuthority,
    VerifierBinding,
    VerifierResult,
    canonical_json_digest,
    sha256_bytes,
)


def dump(path: Path, value) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)


def append_event(path: Path, label: str) -> str:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
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


def state_and_requirement():
    requirement = Requirement("required", "host-check", "1")
    state = FrozenState(
        candidate_sha256=sha256_bytes(b"candidate-operation-race-v1"),
        requirements_sha256=canonical_json_digest([asdict(requirement)]),
        policy_sha256=sha256_bytes(b"policy-operation-race-v1"),
    )
    return state, requirement


def make_session(root: Path, operation_id: str, event_path: Path):
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    store = ReceiptStore(root / "receipts", os.urandom(32))
    gate = OperationBoundGate(store)
    state, requirement = state_and_requirement()
    task = {"description": "same-real-operation-across-fresh-contracts"}
    contract_id = gate.freeze_contract(
        task,
        operation_id=operation_id,
        task_id="operation-race-boundary",
        requirements=(requirement,),
        effect_id="publish",
        effect_version="1",
        state=state,
    )
    session = gate.open_session(
        contract_id,
        task,
        verifier_bindings=(VerifierBinding("host-check", "1", lambda: VerifierResult("PASS", b"proof")),),
        effect_binding=EffectBinding("publish", "1", lambda: append_event(event_path, "external-effect")),
        state_probe=lambda: state,
    )
    session.execute("required")
    decision = session.finalize()
    if decision.get("result") != "PASS":
        raise RuntimeError("fixture failed to obtain authenticated PASS")
    return session, contract_id


def make_executor(app_dsn: str, witness_url: str, witness_public_key: str):
    signed = SignedWitnessAuthority(
        witness_url,
        witness_public_key,
        timeout_seconds=3,
        allow_insecure_http=True,
    )
    postgres = PostgresConsumptionAuthority(app_dsn, table=TABLE)
    return OperationBoundEffectExecutor(AllOfConsumptionAuthority([signed, postgres])), signed


def worker(config_path: Path) -> int:
    config = json.loads(config_path.read_text())
    result_path = Path(config["result_path"])
    ready_path = Path(config["ready_path"])
    start_path = Path(config["start_path"])
    try:
        session, contract_id = make_session(
            Path(config["host_root"]), config["operation_id"], Path(config["event_path"])
        )
        executor, _signed = make_executor(
            config["app_dsn"], config["witness_url"], config["witness_public_key"]
        )
        dump(ready_path, {"pid": os.getpid(), "contract_id": contract_id, "ready": True})
        deadline = time.monotonic() + 15
        while not start_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not start_path.exists():
            raise RuntimeError("race start barrier timeout")
        try:
            returned = executor.execute(session)
            result = {"pid": os.getpid(), "contract_id": contract_id, "returned": returned, "error": None}
        except Exception as error:
            result = {
                "pid": os.getpid(),
                "contract_id": contract_id,
                "returned": None,
                "error": {"type": type(error).__name__, "message": str(error)},
            }
        dump(result_path, result)
        return 0
    except Exception as error:
        dump(
            result_path,
            {
                "pid": os.getpid(),
                "returned": None,
                "error": {"type": type(error).__name__, "message": str(error)},
                "fixture_error": True,
            },
        )
        return 2


def admin_execute(admin_dsn: str, sql: str) -> None:
    import psycopg
    with psycopg.connect(admin_dsn, autocommit=True) as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql)


def ledger_count(admin_dsn: str) -> int:
    import psycopg
    with psycopg.connect(admin_dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT count(*) FROM {TABLE}")
            return int(cursor.fetchone()[0])


def consumed_error(result: dict) -> bool:
    error = result.get("error")
    return isinstance(error, dict) and error.get("type") == "NARFError" and "already consumed" in error.get("message", "")


def run(output: Path, app_dsn: str, admin_dsn: str, witness_url: str, witness_public_key: str) -> dict:
    before = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, text=True
    )
    admin_execute(admin_dsn, f"TRUNCATE TABLE {TABLE}")
    operation_id = str(uuid4())

    with tempfile.TemporaryDirectory(prefix="narf-operation-race-") as name:
        root = Path(name)
        events = root / "external" / "events.jsonl"
        start_path = root / "START"
        configs = []
        processes = []
        for index in range(2):
            config = {
                "host_root": str(root / f"host-{index}"),
                "operation_id": operation_id,
                "event_path": str(events),
                "ready_path": str(root / f"ready-{index}.json"),
                "result_path": str(root / f"result-{index}.json"),
                "start_path": str(start_path),
                "app_dsn": app_dsn,
                "witness_url": witness_url,
                "witness_public_key": witness_public_key,
            }
            config_path = root / f"config-{index}.json"
            dump(config_path, config)
            configs.append(config)
            processes.append(
                subprocess.Popen(
                    [sys.executable, str(Path(__file__).resolve()), "--worker", str(config_path)],
                    cwd=ROOT,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
            )

        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if all(Path(config["ready_path"]).exists() for config in configs):
                break
            if any(process.poll() is not None for process in processes):
                break
            time.sleep(0.02)
        ready = all(Path(config["ready_path"]).exists() for config in configs)
        start_path.write_text("go\n")
        for process in processes:
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

        results = []
        for config in configs:
            path = Path(config["result_path"])
            results.append(json.loads(path.read_text()) if path.exists() else {"error": {"type": "MissingResult", "message": "worker result missing"}})

        successful = [result for result in results if result.get("returned") == "published" and result.get("error") is None]
        blocked = [result for result in results if consumed_error(result)]
        contract_ids = {result.get("contract_id") for result in results if result.get("contract_id")}
        _executor, signed = make_executor(app_dsn, witness_url, witness_public_key)
        witness_reserved = signed.is_reserved(operation_id)
        race_pass = (
            ready
            and len(successful) == 1
            and len(blocked) == 1
            and len(contract_ids) == 2
            and event_count(events) == 1
            and ledger_count(admin_dsn) == 1
            and witness_reserved
        )
        race_row = {
            "case": "two-host-processes-same-operation-race",
            "result": "PASS" if race_pass else "FAIL",
            "workers_ready": ready,
            "distinct_contracts": len(contract_ids),
            "successful_workers": len(successful),
            "blocked_workers": len(blocked),
            "callback_invocations": event_count(events),
            "postgres_rows": ledger_count(admin_dsn),
            "witness_reserved": witness_reserved,
            "worker_results": results,
        }
        dump(output / "race.json", race_row)

        for index in range(2):
            shutil.rmtree(root / f"host-{index}", ignore_errors=True)
        admin_execute(admin_dsn, f"TRUNCATE TABLE {TABLE}")

        replay_session, replay_contract = make_session(root / "fresh-host-after-rollback", operation_id, events)
        replay_executor, replay_signed = make_executor(app_dsn, witness_url, witness_public_key)
        try:
            replay_returned = replay_executor.execute(replay_session)
            replay_result = {"returned": replay_returned, "error": None}
        except Exception as error:
            replay_result = {"returned": None, "error": {"type": type(error).__name__, "message": str(error)}}
        replay_pass = (
            consumed_error(replay_result)
            and event_count(events) == 1
            and ledger_count(admin_dsn) == 0
            and replay_signed.is_reserved(operation_id)
            and replay_contract not in contract_ids
        )
        replay_row = {
            "case": "local-history-lost-postgres-reset-witness-preserved",
            "result": "PASS" if replay_pass else "FAIL",
            "fresh_contract": replay_contract,
            "callback_invocations": event_count(events),
            "postgres_rows_after_reset_replay": ledger_count(admin_dsn),
            "witness_reserved": replay_signed.is_reserved(operation_id),
            "replay": replay_result,
        }
        dump(output / "rollback-replay.json", replay_row)

    after = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, text=True
    )
    rows = [race_row, replay_row]
    counts = {"PASS": sum(row["result"] == "PASS" for row in rows), "FAIL": sum(row["result"] == "FAIL" for row in rows)}
    summary = {
        "planned_cases": 2,
        "counts": counts,
        "source_unchanged": before == after,
        "result": "BOUNDARY_CONFIRMED" if counts == {"PASS": 2, "FAIL": 0} and before == after else "FAIL",
        "operation_id": operation_id,
        "claim": "Two fresh contracts in two host processes sharing one authenticated operation UUID produce at most one callback through SignedWitness+PostgreSQL, and resetting all local host history plus PostgreSQL does not re-enable that operation while signed witness history is preserved.",
        "limits": [
            "The trusted host still defines semantic operation identity.",
            "The witness and PostgreSQL services run on one CI runner and do not prove independent production administration.",
            "Rollback of witness history together with PostgreSQL and all other preserving authority histories remains outside this protected boundary and is tested separately as LIMITATION_CONFIRMED.",
        ],
        "cases": rows,
    }
    dump(output / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--app-dsn")
    parser.add_argument("--admin-dsn")
    parser.add_argument("--witness-url")
    parser.add_argument("--witness-public-key")
    args = parser.parse_args()
    if args.worker is not None:
        return worker(args.worker)
    required = [args.output, args.app_dsn, args.admin_dsn, args.witness_url, args.witness_public_key]
    if any(value is None for value in required):
        parser.error("controller mode requires output, DSNs and witness connection")
    if not args.output.is_absolute() or args.output.resolve().is_relative_to(ROOT):
        parser.error("--output must be absolute and outside the repository")
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    summary = run(args.output, args.app_dsn, args.admin_dsn, args.witness_url, args.witness_public_key)
    return 0 if summary["result"] == "BOUNDARY_CONFIRMED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
