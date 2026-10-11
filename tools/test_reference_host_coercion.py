#!/usr/bin/env python3
"""Verify TrustedFileHost preserves the strict task boundary before NARFGate."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "src"))

from narf import NARFError, Requirement, VerifierBinding, VerifierResult  # noqa: E402
from narf.reference_host import TrustedFileHost  # noqa: E402


def dump(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def prepare(host: TrustedFileHost, task: dict):
    requirement = Requirement("required", "host-check", "1")
    return host.prepare(
        task,
        task_id="reference-host-strict-boundary",
        candidate=b"candidate",
        policy=b"policy",
        requirements=[requirement],
        verifier_bindings=[VerifierBinding("host-check", "1", lambda: VerifierResult("PASS", b"proof"))],
        effect_name="effect.bin",
        payload=b"published",
    )


def rejected_case(root: Path, name: str, task: dict) -> dict:
    host = TrustedFileHost(root / name, os.urandom(32))
    try:
        prepare(host, task)
    except NARFError as error:
        passed = "canonical JSON required" in str(error)
        return {
            "case": name,
            "result": "PASS" if passed else "FAIL",
            "rejected": True,
            "error_type": type(error).__name__,
            "error": str(error),
            "effect_exists": False,
        }
    except Exception as error:
        return {
            "case": name,
            "result": "FAIL",
            "rejected": True,
            "error_type": type(error).__name__,
            "error": str(error),
            "effect_exists": False,
        }
    return {
        "case": name,
        "result": "FAIL",
        "rejected": False,
        "error_type": None,
        "error": None,
        "effect_exists": False,
    }


def valid_case(root: Path) -> dict:
    host = TrustedFileHost(root / "strict-valid-task", os.urandom(32))
    contract_id = prepare(host, {"items": [1, 2], "nested": {"enabled": True, "value": None}})
    decision = host.verify()
    effect = Path(host.commit())
    passed = decision.get("result") == "PASS" and effect.read_bytes() == b"published"
    return {
        "case": "strict-valid-task-still-executes",
        "result": "PASS" if passed else "FAIL",
        "contract_id": contract_id,
        "decision": decision.get("result"),
        "effect_exists": effect.exists(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.output.is_absolute() or args.output.resolve().is_relative_to(ROOT):
        parser.error("--output must be absolute and outside repository")
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)

    before = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, text=True
    )
    with tempfile.TemporaryDirectory(prefix="narf-reference-host-strict-") as name:
        root = Path(name)
        rows = [
            rejected_case(root, "integer-key-rejected-before-freeze", {1: "alpha"}),
            rejected_case(root, "tuple-rejected-before-freeze", {"items": (1, 2)}),
            valid_case(root),
        ]
    after = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, text=True
    )

    counts = {
        "PASS": sum(row["result"] == "PASS" for row in rows),
        "FAIL": sum(row["result"] == "FAIL" for row in rows),
    }
    summary = {
        "planned_cases": 3,
        "counts": counts,
        "source_unchanged": before == after,
        "result": "BOUNDARY_CONFIRMED" if counts == {"PASS": 3, "FAIL": 0} and before == after else "FAIL",
        "claim": "TrustedFileHost validates the caller's original task against MgNarf's strict JSON model before freezing or binding it; previously coercible integer-key and tuple tasks fail closed while a strict JSON task still reaches the effect.",
        "cases": rows,
    }
    dump(args.output / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["result"] == "BOUNDARY_CONFIRMED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
