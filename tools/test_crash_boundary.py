#!/usr/bin/env python3
"""Measure NARF effect-reservation persistence across abrupt host-process exit.

This harness tests process crash behavior only. It does not claim physical
power-loss durability or exactly-once external completion.
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


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def dump(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def attempt(call):
    try:
        return {"returned": call(), "error": None}
    except Exception as error:
        return {"returned": None, "error": {"type": type(error).__name__,
                "message": str(error), "errno": getattr(error, "errno", None)}}


def load_api():
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT / "src"))
    from narf import (EffectBinding, FrozenState, NARFGate, ReceiptStore,
                      Requirement, VerifierBinding, VerifierResult)
    return EffectBinding, FrozenState, NARFGate, ReceiptStore, Requirement, VerifierBinding, VerifierResult


def build_session(config, callback):
    EffectBinding, FrozenState, NARFGate, ReceiptStore, _Requirement, VerifierBinding, VerifierResult = load_api()
    store = ReceiptStore(Path(config["root"]) / "receipts", bytes.fromhex(config["key_hex"]))
    state = FrozenState(**config["state"])
    session = NARFGate(store).open_session(
        config["contract_id"],
        config["task"],
        verifier_bindings=[VerifierBinding("host-check", "1", lambda: VerifierResult("PASS", b"proof"))],
        effect_binding=EffectBinding("publish", "1", callback),
        state_probe=lambda: state,
    )
    session.execute("required")
    decision = session.finalize()
    if decision["result"] != "PASS":
        raise RuntimeError("crash fixture failed to obtain PASS")
    return store, session, decision


def child(config):
    root = Path(config["root"])
    target = root / "target.bin"

    def callback():
        if config["mode"] == "crash-before-target":
            os._exit(71)
        if config["mode"] == "crash-after-target":
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(target, flags, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(b"external-effect")
                output.flush()
                os.fsync(output.fileno())
            dfd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
            os._exit(72)
        raise RuntimeError("unknown crash mode")

    _store, session, _decision = build_session(config, callback)
    session.execute_effect()
    raise RuntimeError("crash callback unexpectedly returned")


def launch_child(config):
    return subprocess.run(
        [sys.executable, "-I", str(Path(__file__).resolve()), "--child"],
        input=json.dumps(config), text=True, capture_output=True, timeout=15,
    )


def make_fixture(name: str):
    EffectBinding, FrozenState, NARFGate, ReceiptStore, Requirement, _VerifierBinding, _VerifierResult = load_api()
    root = Path(name)
    key = os.urandom(32)
    store = ReceiptStore(root / "receipts", key)
    gate = NARFGate(store)
    task = {"description": "crash persistence fixture"}
    state = FrozenState(
        candidate_sha256=sha(b"candidate-v1"),
        requirements_sha256=sha(b"requirements-v1"),
        policy_sha256=sha(b"policy-v1"),
    )
    contract_id = gate.freeze_contract(
        task,
        task_id="crash-boundary",
        requirements=[Requirement("required", "host-check", "1")],
        effect_id="publish",
        effect_version="1",
        state=state,
    )
    return root, store, {
        "root": str(root),
        "key_hex": key.hex(),
        "contract_id": contract_id,
        "task": task,
        "state": asdict(state),
    }


def consumption_count(store) -> int:
    return sum((store.load(path.stem) or {}).get("evidence_type") == "narf.effect"
               for path in store.directory.glob("*.json"))


def run_case(mode: str, expected_exit: int, expect_target: bool, output: Path):
    with tempfile.TemporaryDirectory(prefix="narf-crash-boundary-") as name:
        root, store, config = make_fixture(name)
        config["mode"] = mode
        crashed = launch_child(config)
        target = root / "target.bin"
        before_replay_count = consumption_count(store)
        replay_marker = root / "replay-callback-entered"

        def replay_callback():
            replay_marker.write_text("entered")
            return "unexpected"

        _store, replay_session, replay_decision = build_session(config, replay_callback)
        replay = attempt(replay_session.execute_effect)
        after_replay_count = consumption_count(store)
        target_bytes = target.read_bytes() if target.exists() else None
        passed = (
            crashed.returncode == expected_exit
            and replay_decision["result"] == "PASS"
            and before_replay_count == 1
            and after_replay_count == 1
            and replay["error"] is not None
            and replay["error"]["type"] == "NARFError"
            and "already consumed" in replay["error"]["message"]
            and not replay_marker.exists()
            and target.exists() == expect_target
            and (not expect_target or target_bytes == b"external-effect")
        )
        row = {
            "case": mode,
            "result": "PASS" if passed else "FAIL",
            "crash_exit": crashed.returncode,
            "crash_stderr": crashed.stderr,
            "consumption_before_replay": before_replay_count,
            "consumption_after_replay": after_replay_count,
            "replay_decision": replay_decision,
            "replay": replay,
            "replay_callback_entered": replay_marker.exists(),
            "target_exists": target.exists(),
            "target_sha256": sha(target_bytes) if target_bytes is not None else None,
        }
        dump(output / (mode + ".json"), row)
        return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.child:
        child(json.load(sys.stdin))
        return 99
    if args.output is None:
        parser.error("--output is required")
    if not args.output.is_absolute() or args.output.resolve().is_relative_to(ROOT):
        parser.error("--output must be absolute and outside the repository")
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)

    source_hashes = {str(path.relative_to(ROOT)): sha(path.read_bytes())
                     for path in sorted((ROOT / "src/narf").glob("*.py"))}
    rows = [
        run_case("crash-before-target", 71, False, args.output),
        run_case("crash-after-target", 72, True, args.output),
    ]
    unchanged = {str(path.relative_to(ROOT)): sha(path.read_bytes())
                 for path in sorted((ROOT / "src/narf").glob("*.py"))} == source_hashes
    counts = {"PASS": sum(row["result"] == "PASS" for row in rows),
              "FAIL": sum(row["result"] == "FAIL" for row in rows)}
    summary = {
        "planned_cases": 2,
        "counts": counts,
        "source_unchanged": unchanged,
        "result": "PASS" if counts == {"PASS": 2, "FAIL": 0} and unchanged else "FAIL",
        "limits": [
            "Process-exit persistence only; physical power-loss durability is not established.",
            "A reserved authorization may survive without a completed external effect; availability is intentionally sacrificed to preserve at-most-once invocation.",
            "Exactly-once remote completion remains a host/target protocol problem outside this reference gate.",
        ],
    }
    dump(args.output / "summary.json", summary)
    print(json.dumps(summary, indent=2))
    return 0 if summary["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
