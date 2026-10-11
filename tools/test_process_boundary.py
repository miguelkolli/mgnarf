#!/usr/bin/env python3
"""Exercise a trusted host process against a distinct, keyless Unix worker.

Exit 0: measured process-boundary checks passed. Exit 1: failed check.
Exit 2: credential switching unavailable, so the boundary is UNVERIFIED.
"""
from __future__ import annotations

import argparse
import collections
import errno
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
WORKER_UID = 65534
WORKER_GID = 65534


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


def switch_identity():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Linux root with credential-switch authority is required")
    os.setgroups([])
    os.setresgid(WORKER_GID, WORKER_GID, WORKER_GID)
    os.setresuid(WORKER_UID, WORKER_UID, WORKER_UID)
    identity = {"uids": list(os.getresuid()), "gids": list(os.getresgid()),
                "supplementary_groups": os.getgroups()}
    status = Path("/proc/self/status").read_text().splitlines()
    identity["effective_capabilities"] = next(line.split()[1] for line in status
                                                if line.startswith("CapEff:"))
    if (identity["uids"] != [WORKER_UID] * 3 or identity["gids"] != [WORKER_GID] * 3
            or identity["supplementary_groups"]
            or int(identity["effective_capabilities"], 16) != 0):
        raise RuntimeError("worker retained unexpected Unix authority")
    return identity


def worker(config):
    identity = switch_identity()
    result = {"pid": os.getpid(), "identity": identity, "mode": config["mode"]}
    if config["mode"] == "probe":
        return result

    candidate = Path(config["candidate"])
    if config["mode"] in ("produce", "mutate"):
        payload = bytes.fromhex(config["payload_hex"])
        candidate.write_bytes(payload)
        result["candidate_sha256"] = sha(payload)
        return result
    if config["mode"] == "attack":
        authority = Path(config["authority"])
        key = authority / "host.key"
        receipts = authority / "receipts"
        effects = authority / "effects"
        operations = {
            "read_key": lambda: key.read_bytes().hex(),
            "list_receipts": lambda: sorted(path.name for path in receipts.iterdir()),
            "write_receipt": lambda: (receipts / "worker.json").write_text("worker"),
            "write_effect": lambda: (effects / "worker.bin").write_bytes(b"worker"),
            "chmod_authority": lambda: authority.chmod(0o777),
        }
        result["operations"] = {name: attempt(call) for name, call in operations.items()}
        return result
    raise ValueError("unknown worker mode")


def launch(config):
    process = subprocess.run(
        [sys.executable, "-I", str(Path(__file__).resolve()), "--worker"],
        input=json.dumps(config), text=True, capture_output=True, timeout=15,
    )
    if process.returncode != 0:
        raise RuntimeError("worker failed: " + process.stderr[:2000])
    return json.loads(process.stdout)


def host_bindings():
    from narf import Requirement, VerifierResult
    from narf.process_host import CandidateVerifier

    requirements = (
        Requirement("shape", "shape-check", "1"),
        Requirement("policy", "policy-check", "1"),
    )
    verifiers = (
        CandidateVerifier("shape-check", "1", lambda raw: VerifierResult(
            "PASS" if raw.startswith(b"approved:") else "FAIL", raw)),
        CandidateVerifier("policy-check", "1", lambda raw: VerifierResult(
            "FAIL" if b"DENY" in raw else "PASS", b"policy:" + raw)),
    )
    return requirements, verifiers


def prepare_host(authority: Path, candidate: Path, key: bytes, effect_name: str):
    from narf.process_host import CandidateFileHost

    requirements, verifiers = host_bindings()
    host = CandidateFileHost(authority, candidate, key)
    host.prepare(
        {"description": "distinct-uid candidate publish"},
        task_id="process-boundary",
        policy=b"policy-v1",
        requirements=requirements,
        verifiers=verifiers,
        effect_name=effect_name,
    )
    return host


def make_fixture(name: str):
    root = Path(name)
    root.chmod(0o755)
    candidate_dir = root / "candidate"
    candidate_dir.mkdir(mode=0o700)
    os.chown(candidate_dir, WORKER_UID, WORKER_GID)
    authority = root / "authority"
    authority.mkdir(mode=0o700)
    key = secrets.token_bytes(32)
    key_file = authority / "host.key"
    key_file.write_bytes(key)
    key_file.chmod(0o600)
    return root, candidate_dir / "proposal.bin", authority, key


def denied(operation):
    error = operation["error"]
    return error is not None and error["errno"] in (errno.EACCES, errno.EPERM)


def baseline_case(output: Path):
    with tempfile.TemporaryDirectory(prefix="narf-process-baseline-") as name:
        _root, candidate, authority, key = make_fixture(name)
        produced = launch({"mode": "produce", "candidate": str(candidate),
                           "payload_hex": b"approved:worker-v1".hex()})
        host = prepare_host(authority, candidate, key, "published.bin")
        decision = host.verify()
        attack = launch({"mode": "attack", "candidate": str(candidate),
                         "authority": str(authority)})
        committed = attempt(host.commit)
        replay = attempt(host.commit)
        target = authority / "effects/published.bin"
        target_bytes = target.read_bytes() if target.exists() else None
        operations_denied = all(denied(item) for item in attack["operations"].values())
        passed = (
            decision["result"] == "PASS"
            and operations_denied
            and committed["error"] is None
            and target_bytes == b"approved:worker-v1"
            and replay["error"] is not None
            and replay["error"]["type"] == "NARFError"
            and "already consumed" in replay["error"]["message"]
        )
        row = {"case": "baseline", "result": "PASS" if passed else "FAIL",
               "worker": produced, "attack": attack, "decision": decision,
               "commit": committed, "replay": replay,
               "target_sha256": sha(target_bytes) if target_bytes is not None else None,
               "operations_denied": operations_denied}
        dump(output / "baseline.json", row)
        return row


def drift_case(output: Path):
    with tempfile.TemporaryDirectory(prefix="narf-process-drift-") as name:
        _root, candidate, authority, key = make_fixture(name)
        produced = launch({"mode": "produce", "candidate": str(candidate),
                           "payload_hex": b"approved:worker-v1".hex()})
        host = prepare_host(authority, candidate, key, "published.bin")
        decision = host.verify()
        mutated = launch({"mode": "mutate", "candidate": str(candidate),
                          "payload_hex": b"approved:worker-v2".hex()})
        committed = attempt(host.commit)
        target = authority / "effects/published.bin"
        passed = (
            decision["result"] == "PASS"
            and mutated["candidate_sha256"] != produced["candidate_sha256"]
            and committed["error"] is not None
            and committed["error"]["type"] == "NARFError"
            and "candidate_changed" in committed["error"]["message"]
            and not target.exists()
        )
        row = {"case": "candidate-drift-after-pass", "result": "PASS" if passed else "FAIL",
               "worker_initial": produced, "worker_mutation": mutated,
               "decision": decision, "commit": committed, "target_exists": target.exists()}
        dump(output / "drift.json", row)
        return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker(json.load(sys.stdin))))
        return 0
    if args.output is None:
        parser.error("--output is required")
    if not args.output.is_absolute() or args.output.resolve().is_relative_to(ROOT):
        parser.error("--output must be absolute and outside the repository")
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)

    preflight = attempt(lambda: launch({"mode": "probe"}))
    if preflight["error"] is not None:
        summary = {"result": "UNVERIFIED", "reason": "credential-switch preflight unavailable",
                   "preflight": preflight}
        dump(args.output / "summary.json", summary)
        print(json.dumps(summary, indent=2))
        return 2
    identity = preflight["returned"]["identity"]
    expected_identity = (identity["uids"] == [WORKER_UID] * 3
                         and identity["gids"] == [WORKER_GID] * 3
                         and identity["supplementary_groups"] == []
                         and int(identity["effective_capabilities"], 16) == 0)
    if not expected_identity:
        summary = {"result": "FAIL", "reason": "unexpected worker identity", "preflight": preflight}
        dump(args.output / "summary.json", summary)
        print(json.dumps(summary, indent=2))
        return 1

    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT / "src"))
    source_hashes = {str(path.relative_to(ROOT)): sha(path.read_bytes())
                     for path in sorted((ROOT / "src/narf").glob("*.py"))}
    runner_hash = sha(Path(__file__).read_bytes())
    rows = [baseline_case(args.output), drift_case(args.output)]
    counts = dict(collections.Counter(row["result"] for row in rows))
    unchanged = {str(path.relative_to(ROOT)): sha(path.read_bytes())
                 for path in sorted((ROOT / "src/narf").glob("*.py"))} == source_hashes
    summary = {
        "planned_cases": 2,
        "counts": counts,
        "worker_uid": WORKER_UID,
        "worker_gid": WORKER_GID,
        "preflight": preflight,
        "source_unchanged": unchanged,
        "runner_sha256": runner_hash,
        "result": "PASS" if counts == {"PASS": 2} and unchanged else "FAIL",
        "limits": [
            "Linux host-owned fixture only; this is not a production sandbox certification.",
            "Worker is a distinct UID/GID with no supplementary groups or effective capabilities.",
            "Rollback-resistant history, physical power-loss recovery and remote exactly-once completion remain unverified.",
        ],
    }
    dump(args.output / "summary.json", summary)
    print(json.dumps(summary, indent=2))
    return 0 if summary["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
