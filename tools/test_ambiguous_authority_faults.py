#!/usr/bin/env python3
"""Fault-inject ambiguous authority outcomes after durable reservation."""
from __future__ import annotations

import argparse
import base64
from dataclasses import asdict
import json
import os
from pathlib import Path
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
    NARFError,
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
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def attempt(call):
    try:
        return {"returned": call(), "error": None}
    except Exception as error:
        return {"returned": None, "error": {"type": type(error).__name__, "message": str(error)}}


def generate_private_key_file(path: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_text(base64.b64encode(raw).decode("ascii") + "\n", encoding="ascii")
    path.chmod(0o600)


class WitnessProcess:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.ledger_dir = self.root / "ledger"
        self.key_file = self.root / "private-key.b64"
        self.ready_file = self.root / "ready.json"
        self.process = None
        if not self.key_file.exists():
            generate_private_key_file(self.key_file)
        self.base_url = None
        self.public_key_base64 = None

    def start(self):
        self.ready_file.unlink(missing_ok=True)
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                str(ROOT / "tools" / "signed_witness_server.py"),
                "--host", "127.0.0.1",
                "--port", "0",
                "--ledger-directory", str(self.ledger_dir),
                "--private-key-file", str(self.key_file),
                "--ready-file", str(self.ready_file),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"witness exited early: {self.process.returncode}")
            if self.ready_file.exists():
                ready = json.loads(self.ready_file.read_text())
                self.base_url = f"http://{ready['host']}:{ready['port']}"
                self.public_key_base64 = ready["public_key_base64"]
                return self
            time.sleep(0.05)
        self.stop()
        raise RuntimeError("witness did not become ready")

    def stop(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process = None


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


def append_event(path: Path) -> str:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps({"pid": os.getpid(), "effect": "published"}) + "\n")
        output.flush()
        os.fsync(output.fileno())
    return "published"


def event_count(path: Path) -> int:
    return len(path.read_text().splitlines()) if path.exists() else 0


def make_session(root: Path, operation_id: str, events: Path):
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    store = ReceiptStore(root / "receipts", os.urandom(32))
    gate = OperationBoundGate(store)
    requirement = Requirement("required", "host-check", "1")
    state = FrozenState(
        candidate_sha256=sha256_bytes(b"candidate-ambiguous-authority-v1"),
        requirements_sha256=canonical_json_digest([asdict(requirement)]),
        policy_sha256=sha256_bytes(b"policy-ambiguous-authority-v1"),
    )
    task = {"description": "ambiguous-authority-fault"}
    contract_id = gate.freeze_contract(
        task,
        operation_id=operation_id,
        task_id="ambiguous-authority-fault",
        requirements=[requirement],
        effect_id="publish",
        effect_version="1",
        state=state,
    )
    session = gate.open_session(
        contract_id,
        task,
        verifier_bindings=[VerifierBinding("host-check", "1", lambda: VerifierResult("PASS", b"proof"))],
        effect_binding=EffectBinding("publish", "1", lambda: append_event(events)),
        state_probe=lambda: state,
    )
    session.execute("required")
    if session.finalize().get("result") != "PASS":
        raise RuntimeError("fixture failed to obtain PASS")
    return session, contract_id


def signed_authority(witness: WitnessProcess):
    return SignedWitnessAuthority(
        witness.base_url,
        witness.public_key_base64,
        timeout_seconds=2,
        allow_insecure_http=True,
    )


def inject_lost_signed_response(authority: SignedWitnessAuthority, call):
    """Lose one acknowledgement after the witness has durably handled the request.

    Inject at the authority response boundary rather than inside a particular
    HTTP client implementation so the ambiguity test remains transport-neutral.
    """
    original = authority._request
    used = False

    def lose_after_server_response(operation, token):
        nonlocal used
        payload = original(operation, token)
        if not used:
            used = True
            raise NARFError("effect: signed witness unavailable")
        return payload

    authority._request = lose_after_server_response
    try:
        return attempt(call)
    finally:
        authority._request = original


class CommitThenLoseAck:
    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        self.connection.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        result = self.connection.__exit__(exc_type, exc, tb)
        if exc_type is None:
            raise OSError("injected PostgreSQL commit acknowledgement loss")
        return result

    def cursor(self):
        return self.connection.cursor()

    def close(self):
        return self.connection.close()


def inject_postgres_commit_ack_loss(authority: PostgresConsumptionAuthority):
    original_connect = authority._connect
    used = False

    def connect():
        nonlocal used
        connection = original_connect()
        if not used:
            used = True
            return CommitThenLoseAck(connection)
        return connection

    authority._connect = connect


def consumed(result: dict) -> bool:
    error = result.get("error")
    return isinstance(error, dict) and "already consumed" in error.get("message", "")


def unavailable_or_transaction_failed(result: dict) -> bool:
    error = result.get("error")
    if not isinstance(error, dict):
        return False
    message = error.get("message", "")
    return "unavailable" in message or "transaction failed" in message


def run_signed_response_loss(root: Path, app_dsn: str, admin_dsn: str, restart: bool):
    admin_execute(admin_dsn, f"TRUNCATE TABLE {TABLE}")
    witness = WitnessProcess(root / "witness").start()
    operation_id = str(uuid4())
    events = root / "events.jsonl"
    try:
        session, first_contract = make_session(root / "host-first", operation_id, events)
        signed = signed_authority(witness)
        authority = AllOfConsumptionAuthority([
            signed,
            PostgresConsumptionAuthority(app_dsn, table=TABLE),
        ])
        first = inject_lost_signed_response(
            signed,
            lambda: OperationBoundEffectExecutor(authority).execute(session),
        )
        witness_reserved_after_loss = signed_authority(witness).is_reserved(operation_id)

        if restart:
            witness.stop()
            witness.start()

        retry_session, retry_contract = make_session(root / "host-retry", operation_id, events)
        retry_authority = AllOfConsumptionAuthority([
            signed_authority(witness),
            PostgresConsumptionAuthority(app_dsn, table=TABLE),
        ])
        retry = attempt(lambda: OperationBoundEffectExecutor(retry_authority).execute(retry_session))
        passed = (
            unavailable_or_transaction_failed(first)
            and consumed(retry)
            and first_contract != retry_contract
            and witness_reserved_after_loss
            and signed_authority(witness).is_reserved(operation_id)
            and ledger_count(admin_dsn) == 0
            and event_count(events) == 0
        )
        return {
            "case": "signed-response-loss-restart" if restart else "signed-response-loss-retry",
            "result": "PASS" if passed else "FAIL",
            "first": first,
            "retry": retry,
            "fresh_contract": first_contract != retry_contract,
            "witness_reserved": signed_authority(witness).is_reserved(operation_id),
            "postgres_rows": ledger_count(admin_dsn),
            "callback_invocations": event_count(events),
        }
    finally:
        witness.stop()


def run_postgres_commit_ack_loss(root: Path, app_dsn: str, admin_dsn: str, signed_first: bool):
    admin_execute(admin_dsn, f"TRUNCATE TABLE {TABLE}")
    witness = WitnessProcess(root / "witness").start()
    operation_id = str(uuid4())
    events = root / "events.jsonl"
    try:
        session, first_contract = make_session(root / "host-first", operation_id, events)
        postgres = PostgresConsumptionAuthority(app_dsn, table=TABLE)
        inject_postgres_commit_ack_loss(postgres)
        signed = signed_authority(witness)
        authorities = [signed, postgres] if signed_first else [postgres, signed]
        first = attempt(lambda: OperationBoundEffectExecutor(AllOfConsumptionAuthority(authorities)).execute(session))

        retry_session, retry_contract = make_session(root / "host-retry", operation_id, events)
        retry_signed = signed_authority(witness)
        retry_postgres = PostgresConsumptionAuthority(app_dsn, table=TABLE)
        retry_authorities = [retry_signed, retry_postgres] if signed_first else [retry_postgres, retry_signed]
        retry = attempt(lambda: OperationBoundEffectExecutor(AllOfConsumptionAuthority(retry_authorities)).execute(retry_session))
        witness_reserved = retry_signed.is_reserved(operation_id)
        expected_witness = signed_first
        passed = (
            unavailable_or_transaction_failed(first)
            and consumed(retry)
            and first_contract != retry_contract
            and ledger_count(admin_dsn) == 1
            and witness_reserved is expected_witness
            and event_count(events) == 0
        )
        return {
            "case": "signed-first-postgres-commit-ack-loss" if signed_first else "postgres-first-commit-ack-loss",
            "result": "PASS" if passed else "FAIL",
            "first": first,
            "retry": retry,
            "fresh_contract": first_contract != retry_contract,
            "witness_reserved": witness_reserved,
            "postgres_rows": ledger_count(admin_dsn),
            "callback_invocations": event_count(events),
        }
    finally:
        witness.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--app-dsn", required=True)
    parser.add_argument("--admin-dsn", required=True)
    args = parser.parse_args()
    if not args.output.is_absolute() or args.output.resolve().is_relative_to(ROOT):
        parser.error("--output must be absolute and outside repository")
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)

    before = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, text=True)
    with tempfile.TemporaryDirectory(prefix="narf-ambiguous-authority-") as name:
        root = Path(name)
        rows = [
            run_signed_response_loss(root / "case-1", args.app_dsn, args.admin_dsn, restart=False),
            run_signed_response_loss(root / "case-2", args.app_dsn, args.admin_dsn, restart=True),
            run_postgres_commit_ack_loss(root / "case-3", args.app_dsn, args.admin_dsn, signed_first=False),
            run_postgres_commit_ack_loss(root / "case-4", args.app_dsn, args.admin_dsn, signed_first=True),
        ]
    after = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, text=True)
    counts = {"PASS": sum(row["result"] == "PASS" for row in rows), "FAIL": sum(row["result"] == "FAIL" for row in rows)}
    summary = {
        "planned_cases": 4,
        "counts": counts,
        "source_unchanged": before == after,
        "result": "BOUNDARY_CONFIRMED" if counts == {"PASS": 4, "FAIL": 0} and before == after else "FAIL",
        "claim": "If reservation durability succeeds but its acknowledgement is lost, MgNarf never rolls the uncertain reservation back; retry with the same operation remains blocked and the external callback is not entered.",
        "availability_tradeoff": "An ambiguous committed reservation can permanently consume an operation without executing its callback. This is deliberate fail-closed behavior, not exactly-once completion.",
        "cases": rows,
    }
    dump(args.output / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["result"] == "BOUNDARY_CONFIRMED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
