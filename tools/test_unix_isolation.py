#!/usr/bin/env python3
"""Measure a host-owned test fixture against a distinct, keyless Unix UID.

Exit 0: measured checks passed. Exit 1: failed check. Exit 2: unverified.
This harness does not implement a gate or modify the reference implementation.
"""
import argparse
import base64
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
ACTIONS = (
    "read-key", "overwrite-key", "unlink-key", "read-receipt",
    "overwrite-receipt", "unlink-receipt", "rename-receipt", "replace-receipt",
    "plant-symlink", "chmod-store", "rename-store", "rename-authority",
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def dump(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def attempt(action):
    try:
        return {"returned": action(), "error": None}
    except Exception as error:
        return {"returned": None, "error": {"type": type(error).__name__,
                "message": str(error), "errno": getattr(error, "errno", None)}}


def switch_identity():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Linux root with credential-switch authority is required")
    os.setgroups([])
    os.setresgid(65534, 65534, 65534)
    os.setresuid(65534, 65534, 65534)
    identity = {"uids": list(os.getresuid()), "gids": list(os.getresgid()),
                "supplementary_groups": os.getgroups()}
    status = Path("/proc/self/status").read_text().splitlines()
    identity["effective_capabilities"] = next(line.split()[1] for line in status
                                                if line.startswith("CapEff:"))
    if (identity["uids"] != [65534] * 3 or identity["gids"] != [65534] * 3
            or identity["supplementary_groups"]
            or int(identity["effective_capabilities"], 16) != 0):
        raise RuntimeError("worker retained unexpected Unix authority")
    return identity


def worker(config):
    switched = attempt(switch_identity)
    if switched["error"] is not None:
        return {"identity_switch": switched, "protected_operation_executed": False}
    result = {"identity_switch": switched, "pid": os.getpid(),
              "protected_operation_executed": False}
    if config["mode"] == "probe":
        return result

    root = Path(config["root"])
    authority, staging = root / "authority", root / "candidate/staging.json"
    receipt, key = Path(config["receipt"]), authority / "host.key"
    store = authority / "receipts"
    # PINKY: A denial only counts after our own readable/writable controls work.
    if (root / "public-control.txt").read_text() != "public control":
        raise RuntimeError("public traversal/read control failed")
    staging.write_text("candidate-controlled")
    if staging.read_text() != "candidate-controlled":
        raise RuntimeError("candidate staging write/read control failed")
    result.update(traversal_control=True, staging_control=True)

    def operation():
        action = config["action"]
        if action == "read-key":
            return {"bytes": len(key.read_bytes())}
        if action == "overwrite-key":
            return key.write_bytes(b"candidate-controlled")
        if action == "unlink-key":
            return key.unlink()
        if action == "read-receipt":
            return {"bytes": len(receipt.read_bytes())}
        if action == "overwrite-receipt":
            return receipt.write_text("{broken")
        if action == "unlink-receipt":
            return receipt.unlink()
        if action == "rename-receipt":
            return os.rename(receipt, root / "candidate/stolen.json")
        if action == "replace-receipt":
            return os.replace(staging, receipt)
        if action == "plant-symlink":
            return (store / "candidate-link.json").symlink_to(staging)
        if action == "chmod-store":
            return store.chmod(0o777)
        if action == "rename-store":
            return os.rename(store, root / "candidate/old-store")
        if action == "rename-authority":
            return os.rename(authority, root / "candidate/old-authority")
        raise ValueError("unknown planned action")

    result["protected_operation_executed"] = True
    result["operation"] = attempt(operation)
    return result


def launch(config):
    process = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--worker"],
                             input=json.dumps(config), text=True, capture_output=True, timeout=15)
    record = {"exit": process.returncode, "stderr": process.stderr}
    if process.returncode != 0:
        raise RuntimeError("child failed: " + process.stderr[:2000])
    record["result"] = json.loads(process.stdout)
    return record


def snapshot(authority):
    return {str(path.relative_to(authority)): {
                "sha256": sha(path.read_bytes()) if path.is_file() else None,
                "mode": oct(path.stat().st_mode & 0o777), "uid": path.stat().st_uid,
                "gid": path.stat().st_gid}
            for path in [authority, *sorted(authority.rglob("*"))]}


def run_case(case, output):
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT / "src"))
    from narf import (EffectBinding, FrozenState, NARFGate, ReceiptStore,
                      Requirement, VerifierBinding, VerifierResult)
    if Path(sys.modules["narf.gate"].__file__).resolve() != ROOT / "src/narf/gate.py":
        raise RuntimeError("unexpected NARF source module")

    with tempfile.TemporaryDirectory(prefix="narf-unix-fixture-") as name:
        root = Path(name)
        root.chmod(0o755)
        candidate = root / "candidate"
        candidate.mkdir(mode=0o700)
        os.chown(candidate, 65534, 65534)
        control = root / "public-control.txt"
        control.write_text("public control")
        control.chmod(0o644)
        authority = root / "authority"
        mode = 0o700 if case["layout"] == "private-directories" else 0o755
        authority.mkdir(mode=mode)
        authority.chmod(mode)
        key_path = authority / "host.key"
        key_path.write_bytes(secrets.token_bytes(32))
        key_path.chmod(0o600)
        store = ReceiptStore(authority / "receipts", key_path.read_bytes())
        store.directory.chmod(mode)
        gate = NARFGate(store)
        state = FrozenState(*(sha(item) for item in (b"candidate", b"requirements", b"policy")))
        task = {"description": "isolated Unix test fixture", "case": case["number"]}
        contract = gate.freeze_contract(task, task_id="unix-" + str(case["number"]),
                                       requirements=[Requirement("r", "v", "1")],
                                       effect_id="test-target", effect_version="1", state=state)

        def callback():
            for name in ("callbacks.jsonl", "targets.jsonl"):
                with (root / name).open("a") as stream:
                    stream.write(json.dumps({"pid": os.getpid(), "case": case["number"]}) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
            return "test-target-written"

        def session():
            current = gate.open_session(contract, task,
                       verifier_bindings=[VerifierBinding("v", "1", lambda: VerifierResult("PASS", b"proof"))],
                       effect_binding=EffectBinding("test-target", "1", callback), state_probe=lambda: state)
            current.execute("r")
            if current.finalize()["result"] != "PASS":
                raise AssertionError("host baseline lacked a real PASS decision")
            return current

        session().execute_effect()
        receipt = next(path for path in store.directory.glob("*.json")
                       if (store.load(path.stem) or {}).get("evidence_type") == "narf.effect")
        before = snapshot(authority)
        child = launch({"mode": "attack", "root": str(root), "receipt": str(receipt),
                        "action": case["action"]})  # No host key is supplied to the child.
        dump(output / "child.json", child)
        result = child["result"]
        if result["identity_switch"]["error"] is not None:
            raise RuntimeError("identity switch failed after successful preflight")
        if not (result.get("traversal_control") and result.get("staging_control")
                and result["protected_operation_executed"]):
            raise AssertionError("worker controls or attempted operation missing")
        error = result["operation"]["error"]
        unchanged = snapshot(authority) == before
        replay = attempt(session().execute_effect) if unchanged else None
        callbacks = len((root / "callbacks.jsonl").read_text().splitlines())
        targets = len((root / "targets.jsonl").read_text().splitlines())
        denied = error is not None and error["errno"] in (errno.EACCES, errno.EPERM)
        replay_denied = (replay is not None and replay["error"] is not None
                         and replay["error"]["type"] == "NARFError"
                         and "already consumed" in replay["error"]["message"])
        authenticated = all(store.load(path.stem) is not None
                            for path in store.directory.glob("*.json"))
        consumption_count = sum((store.load(path.stem) or {}).get("evidence_type") == "narf.effect"
                                for path in store.directory.glob("*.json"))
        row = {"case": case, "result": "PASS" if denied and unchanged and replay_denied
               and authenticated and consumption_count == callbacks == targets == 1 else "FAIL",
               "child": child, "host_snapshot_before": before, "host_unchanged_after_attack": unchanged,
               "replay": replay, "callbacks": callbacks, "targets": targets,
               "authenticated_consumption_receipts": consumption_count,
               "receipts_authenticated_at_capture": authenticated, "receipt_snapshots": []}
        for path in sorted(store.directory.glob("*.json")):
            raw = path.read_bytes()
            row["receipt_snapshots"].append({"file": path.name, "sha256": sha(raw),
                                            "raw_base64": base64.b64encode(raw).decode()})
        return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--expected-gate-blob")
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker(json.load(sys.stdin))))
        return 0
    if args.output is None:
        parser.error("--output requires a fresh evidence directory")
    if not args.output.is_absolute() or args.output.resolve().is_relative_to(ROOT):
        parser.error("--output must be absolute and outside the repository")
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    gate = ROOT / "src/narf/gate.py"
    raw = gate.read_bytes()
    gate_blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    cases = [{"number": number + 1, "action": action, "layout": layout}
             for number, (action, layout) in enumerate(
                 (action, layout) for action in ACTIONS
                 for layout in ("private-directories", "private-files"))]
    source_hashes = {str(path.relative_to(ROOT)): sha(path.read_bytes())
                     for path in sorted((ROOT / "src/narf").glob("*.py"))}
    plan = {"cases": cases, "gate_blob": gate_blob, "gate_sha256": sha(raw),
            "source_sha256": source_hashes,
            "runner_sha256": sha(Path(__file__).read_bytes()), "python": sys.version,
            "scope": "12 operations x 2 host-owned layouts, worker UID/GID 65534; no OS sandbox or production certification"}
    dump(args.output / "frozen-plan.json", plan)
    plan_hash = sha((args.output / "frozen-plan.json").read_bytes())
    preflight = attempt(lambda: launch({"mode": "probe"}))
    dump(args.output / "preflight.json", preflight)
    unavailable = (preflight["error"] is not None
                   or preflight["returned"]["result"]["identity_switch"]["error"] is not None)
    mismatch = args.expected_gate_blob is not None and args.expected_gate_blob != gate_blob
    rows = []
    for case in cases:
        output = args.output / ("case-%02d" % case["number"])
        output.mkdir(mode=0o700)
        if unavailable or mismatch:
            row = {"case": case, "result": "UNVERIFIED", "protected_operation_executed": False,
                   "reason": "expected gate blob mismatch" if mismatch else "credential-switch preflight unavailable"}
        else:
            checked = attempt(lambda: run_case(case, output))
            if checked["error"] is not None:
                row = {"case": case, "result": "FAIL", "harness_error": checked["error"]}
                if (output / "child.json").exists():
                    row["child"] = json.loads((output / "child.json").read_text())
            else:
                row = checked["returned"]
        row["plan_sha256"] = plan_hash
        dump(output / "evidence.json", row)
        rows.append(row)
    counts = dict(collections.Counter(row["result"] for row in rows))
    source_unchanged = {str(path.relative_to(ROOT)): sha(path.read_bytes())
                        for path in sorted((ROOT / "src/narf").glob("*.py"))} == source_hashes
    plan_unchanged = sha((args.output / "frozen-plan.json").read_bytes()) == plan_hash
    summary = {"planned_cases": len(cases), "counts": counts,
               "protected_operations_executed": sum(row.get("child", {}).get("result", {}).get(
                   "protected_operation_executed", False) for row in rows),
               "gate_source_unchanged": source_unchanged, "plan_unchanged": plan_unchanged,
               "result": "FAIL" if counts.get("FAIL") or not source_unchanged or not plan_unchanged else
                         "UNVERIFIED" if counts.get("UNVERIFIED") else "PASS",
               "limits": ["Host-owned fixture only; no deployment, rollback-resistant history, or power-loss claim.",
                          "Receipt keys are temporary and are not archived; capture-time MAC checks are recorded."]}
    dump(args.output / "summary.json", summary)
    print(json.dumps(summary, indent=2))
    return {"PASS": 0, "FAIL": 1, "UNVERIFIED": 2}[summary["result"]]


if __name__ == "__main__":
    raise SystemExit(main())
