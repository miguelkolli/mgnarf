#!/usr/bin/env python3
"""Measure the PostgreSQL fenced commit boundary with real transactions."""
from __future__ import annotations

from copy import deepcopy
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
SCOPE = "deployment:production-a"
INITIAL_REVISION = 11


def load_api():
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT / "src"))
    from narf import (
        AuthoritySnapshot,
        FencedEffectBinding,
        FencedOperationEffectExecutor,
        FencedOperationGate,
        FrozenState,
        PostgresConsumptionAuthority,
        PostgresFenceControlPlane,
        PostgresFencedTarget,
        PostgresFencingAuthority,
        ReceiptStore,
        Requirement,
        VerifierBinding,
        VerifierResult,
        sha256_bytes,
    )
    return locals()


def psycopg_module():
    import psycopg
    return psycopg


def advisory_key(scope: str) -> int:
    raw = hashlib.sha256(scope.encode("utf-8")).digest()[:8]
    return int.from_bytes(raw, "big", signed=True)


def dump(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def attempt(call):
    try:
        return {"returned": call(), "error": None}
    except Exception as error:
        return {"returned": None, "error": {"type": type(error).__name__, "message": str(error)}}


def admin_exec(admin_dsn: str, sql: str, params=()):
    psycopg = psycopg_module()
    with psycopg.connect(admin_dsn, autocommit=True) as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql, params)
            if cursor.description:
                return cursor.fetchall()
    return None


def reset(admin_dsn: str) -> None:
    admin_exec(admin_dsn, "TRUNCATE TABLE narf_fenced_effects, narf_fence_issuance, narf_consumption_ledger")
    admin_exec(
        admin_dsn,
        "UPDATE narf_fence_scopes SET authority_revision = %s, fence_sequence = 0 WHERE scope_id = %s",
        (INITIAL_REVISION, SCOPE),
    )


def scalar(admin_dsn: str, sql: str, params=()) -> int:
    rows = admin_exec(admin_dsn, sql, params)
    return int(rows[0][0])


def scope_state(admin_dsn: str):
    rows = admin_exec(
        admin_dsn,
        "SELECT authority_revision, fence_sequence FROM narf_fence_scopes WHERE scope_id = %s",
        (SCOPE,),
    )
    return {"authority_revision": int(rows[0][0]), "fence_sequence": int(rows[0][1])}


def actors():
    return {
        "builder": {"principal_id": "agent:builder", "trust_domain": "build-plane"},
        "verifier:security-review": {
            "principal_id": "reviewer:independent",
            "trust_domain": "review-plane",
        },
    }


def policy():
    return {
        "actors": actors(),
        "separation": [
            ["builder", "verifier:security-review", "principal_id"],
            ["builder", "verifier:security-review", "trust_domain"],
        ],
    }


def make_session(api, issuer_dsn: str, control_dsn: str, callback):
    root = tempfile.TemporaryDirectory(prefix="narf-postgres-fenced-")
    store = api["ReceiptStore"](Path(root.name) / "receipts", b"p" * 32)
    control = api["PostgresFenceControlPlane"](control_dsn)
    authority = api["PostgresFencingAuthority"](issuer_dsn)
    frozen_policy = policy()

    def authority_probe():
        return api["AuthoritySnapshot"](
            control.current_revision(SCOPE), deepcopy(frozen_policy["actors"])
        )

    gate = api["FencedOperationGate"](store, authority_probe)
    state = api["FrozenState"](
        api["sha256_bytes"](b"candidate"),
        api["sha256_bytes"](b"requirements"),
        api["sha256_bytes"](b"policy"),
    )
    requirement = api["Requirement"]("review", "security-review", "1")
    operation_id = str(uuid4())
    task = {"description": "postgres-fenced-target"}
    contract_id = gate.freeze_contract(
        task,
        operation_id=operation_id,
        fence_scope_id=SCOPE,
        fencing_authority_id=authority.authority_id,
        task_id="postgres-fenced-target",
        requirements=(requirement,),
        effect_id="deploy",
        effect_version="1",
        state=state,
        identity_policy=frozen_policy,
    )
    actor = frozen_policy["actors"]["verifier:security-review"]
    verifier = api["VerifierBinding"](
        "security-review",
        "1",
        lambda: api["VerifierResult"]("PASS", b"independent-proof"),
        principal_id=actor["principal_id"],
        trust_domain=actor["trust_domain"],
    )
    session = gate.open_session(
        contract_id,
        task,
        verifier_bindings=(verifier,),
        effect_binding=api["FencedEffectBinding"]("deploy", "1", SCOPE, callback),
        state_probe=lambda: state,
    )
    session.execute("review")
    executor = api["FencedOperationEffectExecutor"](
        api["PostgresConsumptionAuthority"](issuer_dsn), authority
    )
    return root, session, executor, operation_id, authority, control


def target(api, target_dsn: str):
    return api["PostgresFencedTarget"](
        target_dsn,
        fence_scope_id=SCOPE,
        authority_id="postgres-fencing-authority.v1",
        effect_id="deploy",
        effect_version="1",
    )


def run_current_fence(output, api, issuer_dsn, target_dsn, control_dsn, admin_dsn):
    reset(admin_dsn)
    pg_target = target(api, target_dsn)
    root, session, executor, operation_id, _authority, _control = make_session(
        api, issuer_dsn, control_dsn, lambda token: pg_target.commit(token, "baseline")
    )
    try:
        result = executor.execute(session)
        passed = (
            result == "committed"
            and scalar(admin_dsn, "SELECT count(*) FROM narf_fenced_effects") == 1
            and scalar(admin_dsn, "SELECT count(*) FROM narf_fence_issuance") == 1
            and scalar(admin_dsn, "SELECT count(*) FROM narf_consumption_ledger") == 1
            and scope_state(admin_dsn) == {"authority_revision": 11, "fence_sequence": 1}
        )
        row = {"case": "current-fence-commits", "result": "PASS" if passed else "FAIL", "returned": result, "operation_id": operation_id, "scope": scope_state(admin_dsn)}
        dump(output / "current.json", row)
        return row
    finally:
        root.cleanup()


def run_transition_after_local_check(output, api, issuer_dsn, target_dsn, control_dsn, admin_dsn):
    reset(admin_dsn)
    pg_target = target(api, target_dsn)
    control = api["PostgresFenceControlPlane"](control_dsn)

    def callback(token):
        control.advance(SCOPE, expected_revision=11, new_revision=12)
        return pg_target.commit(token, "must-not-commit")

    root, session, executor, operation_id, _authority, _control = make_session(
        api, issuer_dsn, control_dsn, callback
    )
    try:
        result = attempt(lambda: executor.execute(session))
        passed = (
            result["error"] is not None
            and "stale authority revision" in result["error"]["message"]
            and scalar(admin_dsn, "SELECT count(*) FROM narf_fenced_effects") == 0
            and scalar(admin_dsn, "SELECT count(*) FROM narf_fence_issuance") == 1
            and scalar(admin_dsn, "SELECT count(*) FROM narf_consumption_ledger") == 1
            and scope_state(admin_dsn) == {"authority_revision": 12, "fence_sequence": 1}
        )
        row = {"case": "authority-transition-after-local-check-rejects-old-fence", "result": "PASS" if passed else "FAIL", "attempt": result, "operation_id": operation_id, "scope": scope_state(admin_dsn), "newer_effect_required": False}
        dump(output / "transition-after-check.json", row)
        return row
    finally:
        root.cleanup()


def run_newer_fence_supersedes(output, api, issuer_dsn, target_dsn, admin_dsn):
    reset(admin_dsn)
    authority = api["PostgresFencingAuthority"](issuer_dsn)
    pg_target = target(api, target_dsn)
    old = authority.acquire(fence_scope_id=SCOPE, operation_id=str(uuid4()), expected_authority_revision=11, effect_id="deploy", effect_version="1")
    new = authority.acquire(fence_scope_id=SCOPE, operation_id=str(uuid4()), expected_authority_revision=11, effect_id="deploy", effect_version="1")
    old_result = attempt(lambda: pg_target.commit(old, "old"))
    new_result = attempt(lambda: pg_target.commit(new, "new"))
    passed = (
        old_result["error"] is not None
        and "stale fence sequence" in old_result["error"]["message"]
        and new_result == {"returned": "committed", "error": None}
        and scalar(admin_dsn, "SELECT count(*) FROM narf_fenced_effects") == 1
        and scope_state(admin_dsn) == {"authority_revision": 11, "fence_sequence": 2}
    )
    row = {"case": "newer-fence-supersedes-older", "result": "PASS" if passed else "FAIL", "old": old_result, "new": new_result, "scope": scope_state(admin_dsn)}
    dump(output / "supersede.json", row)
    return row


def hold_transition(control_dsn: str):
    psycopg = psycopg_module()
    connection = psycopg.connect(control_dsn)
    cursor = connection.cursor()
    cursor.execute("SELECT pg_advisory_xact_lock(%s)", (advisory_key(SCOPE),))
    cursor.execute("SELECT authority_revision FROM narf_fence_scopes WHERE scope_id = %s FOR UPDATE", (SCOPE,))
    cursor.execute("UPDATE narf_fence_scopes SET authority_revision = 12 WHERE scope_id = %s", (SCOPE,))
    return connection


def run_transition_serializes_acquire(output, api, issuer_dsn, control_dsn, admin_dsn):
    reset(admin_dsn)
    authority = api["PostgresFencingAuthority"](issuer_dsn)
    connection = hold_transition(control_dsn)
    result = {}
    try:
        def worker():
            result.update(attempt(lambda: authority.acquire(fence_scope_id=SCOPE, operation_id=str(uuid4()), expected_authority_revision=11, effect_id="deploy", effect_version="1")))

        thread = threading.Thread(target=worker)
        thread.start()
        time.sleep(0.25)
        blocked = thread.is_alive()
        connection.commit()
        thread.join(5)
        passed = (
            blocked
            and not thread.is_alive()
            and result.get("error") is not None
            and "authority revision changed" in result["error"]["message"]
            and scalar(admin_dsn, "SELECT count(*) FROM narf_fence_issuance") == 0
            and scope_state(admin_dsn) == {"authority_revision": 12, "fence_sequence": 0}
        )
        row = {"case": "transition-serializes-with-acquire", "result": "PASS" if passed else "FAIL", "blocked_before_transition_commit": blocked, "attempt": result, "scope": scope_state(admin_dsn)}
        dump(output / "acquire-race.json", row)
        return row
    finally:
        try:
            connection.close()
        except Exception:
            pass


def run_transition_serializes_commit(output, api, issuer_dsn, target_dsn, control_dsn, admin_dsn):
    reset(admin_dsn)
    authority = api["PostgresFencingAuthority"](issuer_dsn)
    pg_target = target(api, target_dsn)
    token = authority.acquire(fence_scope_id=SCOPE, operation_id=str(uuid4()), expected_authority_revision=11, effect_id="deploy", effect_version="1")
    connection = hold_transition(control_dsn)
    result = {}
    try:
        def worker():
            result.update(attempt(lambda: pg_target.commit(token, "must-not-commit")))

        thread = threading.Thread(target=worker)
        thread.start()
        time.sleep(0.25)
        blocked = thread.is_alive()
        connection.commit()
        thread.join(5)
        passed = (
            blocked
            and not thread.is_alive()
            and result.get("error") is not None
            and "stale authority revision" in result["error"]["message"]
            and scalar(admin_dsn, "SELECT count(*) FROM narf_fenced_effects") == 0
            and scope_state(admin_dsn) == {"authority_revision": 12, "fence_sequence": 1}
        )
        row = {"case": "transition-serializes-with-target-commit", "result": "PASS" if passed else "FAIL", "blocked_before_transition_commit": blocked, "attempt": result, "scope": scope_state(admin_dsn)}
        dump(output / "commit-race.json", row)
        return row
    finally:
        try:
            connection.close()
        except Exception:
            pass


def run_privileged_rollback_limitation(output, api, issuer_dsn, target_dsn, control_dsn, admin_dsn):
    reset(admin_dsn)
    authority = api["PostgresFencingAuthority"](issuer_dsn)
    control = api["PostgresFenceControlPlane"](control_dsn)
    pg_target = target(api, target_dsn)
    token = authority.acquire(fence_scope_id=SCOPE, operation_id=str(uuid4()), expected_authority_revision=11, effect_id="deploy", effect_version="1")
    control.advance(SCOPE, expected_revision=11, new_revision=12)
    admin_exec(admin_dsn, "UPDATE narf_fence_scopes SET authority_revision = 11, fence_sequence = 1 WHERE scope_id = %s", (SCOPE,))
    replay = attempt(lambda: pg_target.commit(token, "privileged-rollback"))
    limitation = replay == {"returned": "committed", "error": None} and scalar(admin_dsn, "SELECT count(*) FROM narf_fenced_effects") == 1
    row = {"case": "privileged-authoritative-state-rollback", "result": "LIMITATION_CONFIRMED" if limitation else "FAIL", "attempt": replay, "scope": scope_state(admin_dsn), "admin_rollback": True}
    dump(output / "rollback-limitation.json", row)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--issuer-dsn", required=True)
    parser.add_argument("--target-dsn", required=True)
    parser.add_argument("--control-dsn", required=True)
    parser.add_argument("--admin-dsn", required=True)
    args = parser.parse_args()
    if not args.output.is_absolute() or args.output.resolve().is_relative_to(ROOT):
        parser.error("--output must be absolute and outside repository")
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)

    api = load_api()
    rows = [
        run_current_fence(args.output, api, args.issuer_dsn, args.target_dsn, args.control_dsn, args.admin_dsn),
        run_transition_after_local_check(args.output, api, args.issuer_dsn, args.target_dsn, args.control_dsn, args.admin_dsn),
        run_newer_fence_supersedes(args.output, api, args.issuer_dsn, args.target_dsn, args.admin_dsn),
        run_transition_serializes_acquire(args.output, api, args.issuer_dsn, args.control_dsn, args.admin_dsn),
        run_transition_serializes_commit(args.output, api, args.issuer_dsn, args.target_dsn, args.control_dsn, args.admin_dsn),
        run_privileged_rollback_limitation(args.output, api, args.issuer_dsn, args.target_dsn, args.control_dsn, args.admin_dsn),
    ]
    counts = {
        "PASS": sum(row["result"] == "PASS" for row in rows),
        "LIMITATION_CONFIRMED": sum(row["result"] == "LIMITATION_CONFIRMED" for row in rows),
        "FAIL": sum(row["result"] == "FAIL" for row in rows),
    }
    summary = {
        "result": "BOUNDARY_CONFIRMED" if counts == {"PASS": 5, "LIMITATION_CONFIRMED": 1, "FAIL": 0} else "FAIL",
        "planned_cases": 6,
        "counts": counts,
        "cases": rows,
        "claim": "For this measured PostgreSQL advisory-lock transaction model, authority transitions and fence ordering are enforced at target commit; privileged rollback remains outside the measured guarantee.",
    }
    dump(args.output / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    raise SystemExit(0 if summary["result"] == "BOUNDARY_CONFIRMED" else 1)


if __name__ == "__main__":
    main()
