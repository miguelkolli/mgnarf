#!/usr/bin/env python3
"""Measure the signed external witness boundary against database-control-plane rollback."""
from __future__ import annotations

import argparse
import base64
from dataclasses import asdict
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
TABLE = "narf_consumption_ledger"


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def dump(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)


def attempt(call):
    try:
        return {"returned": call(), "error": None}
    except Exception as error:
        return {"returned": None, "error": {"type": type(error).__name__, "message": str(error), "errno": getattr(error, "errno", None)}}


def load_api():
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT / "src"))
    from narf import (
        AllOfConsumptionAuthority, EffectBinding, FrozenState, NARFGate,
        PostgresConsumptionAuthority, ReceiptStore, Requirement,
        RollbackProtectedEffectExecutor, SignedWitnessAuthority,
        VerifierBinding, VerifierResult, canonical_json_digest,
    )
    return {
        "AllOfConsumptionAuthority": AllOfConsumptionAuthority,
        "EffectBinding": EffectBinding,
        "FrozenState": FrozenState,
        "NARFGate": NARFGate,
        "PostgresConsumptionAuthority": PostgresConsumptionAuthority,
        "ReceiptStore": ReceiptStore,
        "Requirement": Requirement,
        "RollbackProtectedEffectExecutor": RollbackProtectedEffectExecutor,
        "SignedWitnessAuthority": SignedWitnessAuthority,
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


def generate_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private_key = Ed25519PrivateKey.generate()
    private_raw = private_key.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    public_raw = private_key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return private_key, private_raw, public_raw


class WitnessProcess:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.ledger_dir = self.root / "ledger"
        self.key_file = self.root / "private-key.b64"
        self.ready_file = self.root / "ready.json"
        self.process = None
        if not self.key_file.exists():
            _private, private_raw, _public = generate_keypair()
            self.key_file.write_text(base64.b64encode(private_raw).decode("ascii") + "\n")
            self.key_file.chmod(0o600)
        self.base_url = None
        self.public_key_base64 = None
        self.public_key_fingerprint = None

    def start(self):
        if self.process is not None:
            raise RuntimeError("witness already running")
        self.ready_file.unlink(missing_ok=True)
        self.process = subprocess.Popen([
            sys.executable, "-I", str(ROOT / "tools" / "signed_witness_server.py"),
            "--host", "127.0.0.1", "--port", "0",
            "--ledger-directory", str(self.ledger_dir),
            "--private-key-file", str(self.key_file),
            "--ready-file", str(self.ready_file),
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"witness exited early: {self.process.returncode}")
            if self.ready_file.exists():
                ready = json.loads(self.ready_file.read_text())
                self.base_url = f"http://{ready['host']}:{ready['port']}"
                self.public_key_base64 = ready["public_key_base64"]
                self.public_key_fingerprint = ready["public_key_fingerprint"]
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


def append_event(path: Path, label: str) -> str:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        raw = (json.dumps({"event": label, "pid": os.getpid()}) + "\n").encode()
        if os.write(fd, raw) != len(raw):
            raise RuntimeError("short event write")
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return "published"


def event_count(path: Path) -> int:
    return len(path.read_text().splitlines()) if path.exists() else 0


def make_fixture(name: str, app_dsn: str, witness: WitnessProcess):
    api = load_api()
    root = Path(name)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    rollback_domain = root / "rollback-domain"
    external_domain = root / "external-domain"
    external_domain.mkdir(mode=0o700)
    events = external_domain / "events.jsonl"
    key = os.urandom(32)
    store = api["ReceiptStore"](rollback_domain / "receipts", key)
    gate = api["NARFGate"](store)
    requirement = api["Requirement"]("required", "host-check", "1")
    state = api["FrozenState"](
        candidate_sha256=sha(b"candidate-v1"),
        requirements_sha256=api["canonical_json_digest"]([asdict(requirement)]),
        policy_sha256=sha(b"policy-v1"),
    )
    task = {"description": "signed-witness-boundary"}
    contract_id = gate.freeze_contract(task, task_id="signed-witness-boundary", requirements=[requirement], effect_id="publish", effect_version="1", state=state)
    signed = api["SignedWitnessAuthority"](witness.base_url, witness.public_key_base64, timeout_seconds=2, allow_insecure_http=True)
    postgres = api["PostgresConsumptionAuthority"](app_dsn, table=TABLE)
    combined = api["AllOfConsumptionAuthority"]([signed, postgres])
    executor = api["RollbackProtectedEffectExecutor"](combined)
    return {
        "api": api, "root": root, "rollback_domain": rollback_domain,
        "events": events, "key": key, "store": store, "gate": gate,
        "state": state, "task": task, "contract_id": contract_id,
        "signed": signed, "postgres": postgres, "executor": executor,
        "app_dsn": app_dsn, "witness": witness,
    }


def open_pass_session(fixture, store=None, gate=None):
    api = fixture["api"]
    store = store or fixture["store"]
    gate = gate or fixture["gate"]
    def callback():
        return append_event(fixture["events"], "external-effect")
    session = gate.open_session(
        fixture["contract_id"], fixture["task"],
        verifier_bindings=[api["VerifierBinding"]("host-check", "1", lambda: api["VerifierResult"]("PASS", b"proof"))],
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


def fresh_replay(fixture):
    api = fixture["api"]
    new_store = api["ReceiptStore"](fixture["rollback_domain"] / "receipts", fixture["key"])
    new_gate = api["NARFGate"](new_store)
    replay_session, decision = open_pass_session(fixture, new_store, new_gate)
    signed = api["SignedWitnessAuthority"](fixture["witness"].base_url, fixture["witness"].public_key_base64, timeout_seconds=2, allow_insecure_http=True)
    postgres = api["PostgresConsumptionAuthority"](fixture["app_dsn"], table=TABLE)
    combined = api["AllOfConsumptionAuthority"]([signed, postgres])
    executor = api["RollbackProtectedEffectExecutor"](combined)
    return attempt(lambda: executor.execute(fixture["contract_id"], replay_session)), decision


def expected_consumed(result) -> bool:
    return result["error"] is not None and result["error"]["type"] == "NARFError" and "already consumed" in result["error"]["message"]


class FakeSession:
    def __init__(self): self.effect_calls = 0
    def finalize(self): return {"result": "PASS"}
    def execute_effect(self):
        self.effect_calls += 1
        return "effect"


def run_db_admin_reset_witness_preserved(output: Path, app_dsn: str, admin_dsn: str):
    reset_ledger(admin_dsn)
    with tempfile.TemporaryDirectory(prefix="narf-signed-witness-race-") as name:
        root = Path(name)
        witness = WitnessProcess(root / "witness").start()
        try:
            race_output = output / "operation-race-boundary"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools" / "test_operation_race_boundary.py"),
                    "--output", str(race_output),
                    "--app-dsn", app_dsn,
                    "--admin-dsn", admin_dsn,
                    "--witness-url", witness.base_url,
                    "--witness-public-key", witness.public_key_base64,
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=45,
            )
            summary_path = race_output / "summary.json"
            race_summary = json.loads(summary_path.read_text()) if summary_path.exists() else None
            passed = (
                completed.returncode == 0
                and isinstance(race_summary, dict)
                and race_summary.get("result") == "BOUNDARY_CONFIRMED"
                and race_summary.get("counts") == {"PASS": 2, "FAIL": 0}
                and race_summary.get("source_unchanged") is True
            )
            row = {
                "case": "operation-race-and-db-local-reset-witness-preserved",
                "result": "PASS" if passed else "FAIL",
                "operation_race": race_summary,
                "harness_exit_code": completed.returncode,
            }
        finally:
            witness.stop()
    dump(output / "witness-preserved.json", row)
    return row


def run_wrong_public_key_fails_closed(output: Path):
    api = load_api()
    with tempfile.TemporaryDirectory(prefix="narf-signed-witness-key-") as name:
        root = Path(name)
        witness = WitnessProcess(root / "witness").start()
        try:
            _wp, _wr, wrong_public = generate_keypair()
            authority = api["SignedWitnessAuthority"](witness.base_url, base64.b64encode(wrong_public).decode("ascii"), timeout_seconds=2, allow_insecure_http=True)
            token = str(uuid4())
            session = FakeSession()
            result = attempt(lambda: api["RollbackProtectedEffectExecutor"](authority).execute(token, session))
            correct = api["SignedWitnessAuthority"](witness.base_url, witness.public_key_base64, timeout_seconds=2, allow_insecure_http=True)
            reserved_despite_auth_failure = correct.is_reserved(token)
            passed = result["error"] is not None and result["error"]["type"] == "NARFError" and "authentication failed" in result["error"]["message"] and session.effect_calls == 0 and reserved_despite_auth_failure
            row = {"case": "wrong-public-key-fails-closed", "result": "PASS" if passed else "FAIL", "attempt": result, "effect_calls": session.effect_calls, "witness_may_have_consumed_token": reserved_despite_auth_failure}
        finally:
            witness.stop()
    dump(output / "wrong-key.json", row)
    return row


def run_unavailable_fails_closed(output: Path):
    api = load_api()
    _p, _pr, public_raw = generate_keypair()
    authority = api["SignedWitnessAuthority"]("http://127.0.0.1:1", base64.b64encode(public_raw).decode("ascii"), timeout_seconds=1, allow_insecure_http=True)
    session = FakeSession()
    result = attempt(lambda: api["RollbackProtectedEffectExecutor"](authority).execute(str(uuid4()), session))
    passed = result["error"] is not None and result["error"]["type"] == "NARFError" and "unavailable" in result["error"]["message"] and session.effect_calls == 0
    row = {"case": "signed-witness-unavailable-fails-closed", "result": "PASS" if passed else "FAIL", "attempt": result, "effect_calls": session.effect_calls}
    dump(output / "unavailable.json", row)
    return row


class FixedReplayHandler(BaseHTTPRequestHandler):
    server_version = "NARFReplayFixture/1"
    sys_version = ""
    def log_message(self, format, *args): return
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        raw = self.server.raw_envelope
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def run_signed_response_replay_blocked(output: Path):
    api = load_api()
    private_key, _private_raw, public_raw = generate_keypair()
    fingerprint = sha(public_raw)
    token = str(uuid4())
    stale_payload = {
        "version": "narf.signed-witness.response.v1", "operation": "reserve",
        "token": token, "nonce": "0" * 64, "domain": f"ed25519:{fingerprint}",
        "result": "RESERVED", "head_sequence": 1, "head_sha256": "a" * 64,
        "token_sequence": 1, "token_checkpoint_sha256": "a" * 64,
    }
    envelope = {"payload": stale_payload, "signature": base64.b64encode(private_key.sign(canonical_bytes(stale_payload))).decode("ascii")}
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixedReplayHandler)
    server.raw_envelope = canonical_bytes(envelope)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        authority = api["SignedWitnessAuthority"](f"http://127.0.0.1:{server.server_address[1]}", base64.b64encode(public_raw).decode("ascii"), timeout_seconds=2, allow_insecure_http=True)
        session = FakeSession()
        result = attempt(lambda: api["RollbackProtectedEffectExecutor"](authority).execute(token, session))
        passed = result["error"] is not None and result["error"]["type"] == "NARFError" and "binding mismatch" in result["error"]["message"] and session.effect_calls == 0
        row = {"case": "signed-response-replay-different-nonce", "result": "PASS" if passed else "FAIL", "attempt": result, "effect_calls": session.effect_calls}
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)
    dump(output / "nonce-replay.json", row)
    return row


def run_witness_rollback_limitation(output: Path, app_dsn: str, admin_dsn: str):
    reset_ledger(admin_dsn)
    with tempfile.TemporaryDirectory(prefix="narf-signed-witness-rollback-") as name:
        root = Path(name)
        witness = WitnessProcess(root / "witness").start()
        fixture = make_fixture(str(root / "fixture"), app_dsn, witness)
        session, first_decision = open_pass_session(fixture)
        local_snapshot = root / "pre-consumption-local"
        shutil.copytree(fixture["rollback_domain"], local_snapshot)
        witness_snapshot = root / "pre-consumption-witness"
        shutil.copytree(witness.ledger_dir, witness_snapshot)
        first_effect = fixture["executor"].execute(fixture["contract_id"], session)
        witness.stop()
        restore_local_history(fixture, local_snapshot)
        admin_execute(admin_dsn, f"TRUNCATE TABLE {TABLE}")
        shutil.rmtree(witness.ledger_dir)
        shutil.copytree(witness_snapshot, witness.ledger_dir)
        witness.start()
        try:
            replay, replay_decision = fresh_replay(fixture)
            witness_reserved = fixture["api"]["SignedWitnessAuthority"](witness.base_url, witness.public_key_base64, timeout_seconds=2, allow_insecure_http=True).is_reserved(fixture["contract_id"])
            limitation = first_decision["result"] == "PASS" and first_effect == "published" and replay_decision["result"] == "PASS" and replay["error"] is None and replay["returned"] == "published" and event_count(fixture["events"]) == 2 and ledger_count(admin_dsn) == 1 and witness_reserved
            row = {"case": "privileged-witness-history-rollback", "result": "LIMITATION_CONFIRMED" if limitation else "FAIL", "replay": replay, "events_after_replay": event_count(fixture["events"]), "postgres_rows_after_replay": ledger_count(admin_dsn), "witness_history_restored": True, "same_signing_key": True}
        finally:
            witness.stop()
    dump(output / "witness-rollback.json", row)
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

    source_hashes = {str(path.relative_to(ROOT)): sha(path.read_bytes()) for path in sorted((ROOT / "src/narf").glob("*.py"))}
    rows = [
        run_db_admin_reset_witness_preserved(args.output, args.app_dsn, args.admin_dsn),
        run_wrong_public_key_fails_closed(args.output),
        run_unavailable_fails_closed(args.output),
        run_signed_response_replay_blocked(args.output),
        run_witness_rollback_limitation(args.output, args.app_dsn, args.admin_dsn),
    ]
    unchanged = {str(path.relative_to(ROOT)): sha(path.read_bytes()) for path in sorted((ROOT / "src/narf").glob("*.py"))} == source_hashes
    counts = {
        "PASS": sum(row["result"] == "PASS" for row in rows),
        "LIMITATION_CONFIRMED": sum(row["result"] == "LIMITATION_CONFIRMED" for row in rows),
        "FAIL": sum(row["result"] == "FAIL" for row in rows),
    }
    summary = {
        "planned_cases": 5,
        "counts": counts,
        "source_unchanged": unchanged,
        "result": "BOUNDARY_CONFIRMED" if counts == {"PASS": 4, "LIMITATION_CONFIRMED": 1, "FAIL": 0} and unchanged else "FAIL",
        "claim": "Two fresh contracts in separate host processes sharing one authenticated operation UUID produce at most one callback, and resetting all local host history plus PostgreSQL does not re-enable that operation while the independently signed witness retains its consumed-token history.",
        "limits": [
            "The CI witness is a separate process/storage fixture on one runner; it does not prove independent production administration.",
            "Ed25519 authenticates witness responses and request nonces prevent replay of an older signed success response; signatures do not make witness storage monotonic.",
            "If privileged operators can roll back the witness ledger together with every other authority history, replay can return; that case is intentionally LIMITATION_CONFIRMED.",
            "The trusted host still defines semantic operation identity; deliberate renumbering remains a separate documented limitation.",
            "Exactly-once remote effect completion and physical-power-loss guarantees remain outside this boundary.",
        ],
    }
    dump(args.output / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["result"] == "BOUNDARY_CONFIRMED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
