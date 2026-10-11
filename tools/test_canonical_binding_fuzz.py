#!/usr/bin/env python3
"""Deterministic canonical JSON and authenticated-receipt fuzz boundary."""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "src"))

from narf import NARFError, ReceiptStore, canonical_json_digest  # noqa: E402
from narf.gate import canonical_json  # noqa: E402

SEED = 0x4D474E415246


def dump(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def text(rng: random.Random) -> str:
    alphabet = "abcXYZ09_- äöé中🙂"
    return "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 18)))


def strict_value(rng: random.Random, depth: int = 0):
    choices = ["null", "bool", "int", "float", "str"]
    if depth < 4:
        choices += ["list", "dict"]
    kind = rng.choice(choices)
    if kind == "null":
        return None
    if kind == "bool":
        return bool(rng.getrandbits(1))
    if kind == "int":
        return rng.randrange(-(10**30), 10**30)
    if kind == "float":
        return rng.uniform(-1e120, 1e120)
    if kind == "str":
        return text(rng)
    if kind == "list":
        return [strict_value(rng, depth + 1) for _ in range(rng.randrange(0, 6))]
    result = {}
    for _ in range(rng.randrange(0, 6)):
        result[text(rng)] = strict_value(rng, depth + 1)
    return result


class DictSubclass(dict):
    pass


class ListSubclass(list):
    pass


def run(output: Path, iterations: int, receipt_mutations: int) -> dict:
    before = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, text=True
    )
    rng = random.Random(SEED)
    digest_map: dict[str, str] = {}
    generated = 0
    roundtrip_failures = []
    digest_collisions = []

    for index in range(iterations):
        value = strict_value(rng)
        encoded = canonical_json(value)
        parsed = json.loads(encoded)
        recanonical = canonical_json(parsed)
        if recanonical != encoded:
            roundtrip_failures.append({"index": index, "encoded": encoded, "recanonical": recanonical})
            break
        digest = canonical_json_digest(value)
        previous = digest_map.setdefault(digest, encoded)
        if previous != encoded:
            digest_collisions.append({"index": index, "digest": digest, "first": previous, "second": encoded})
            break
        generated += 1

    invalid_values = [
        {1: "alpha"},
        {True: "alpha"},
        {None: "alpha"},
        {1.5: "alpha"},
        {"items": (1, 2)},
        {"items": {1, 2}},
        {"items": ListSubclass([1, 2])},
        DictSubclass({"x": 1}),
        {"value": float("nan")},
        {"value": float("inf")},
        {"value": float("-inf")},
        {"value": "\ud800"},
    ]
    invalid_rejected = 0
    invalid_failures = []
    for index, value in enumerate(invalid_values):
        try:
            canonical_json_digest(value)
        except NARFError:
            invalid_rejected += 1
        except Exception as error:
            invalid_failures.append({"index": index, "unexpected_error": type(error).__name__})
        else:
            invalid_failures.append({"index": index, "accepted": repr(value)})

    receipt_rejected = 0
    receipt_failures = []
    with tempfile.TemporaryDirectory(prefix="narf-canonical-receipt-") as name:
        root = Path(name)
        run_id = str(uuid4())
        store = ReceiptStore(root, os.urandom(32))
        evidence = {
            "evidence_type": "narf.fuzz",
            "evidence_version": 1,
            "run_id": run_id,
            "producer": "host/canonical-fuzz-v1",
            "payload": {"stable": True, "counter": 7},
        }
        store.save(evidence)
        path = root / f"{run_id}.json"
        original_text = path.read_text(encoding="utf-8")
        original = json.loads(original_text)
        if store.load(run_id) != evidence:
            receipt_failures.append({"case": "valid-receipt-did-not-load"})

        for index in range(receipt_mutations):
            mutated = copy.deepcopy(original)
            mode = index % 6
            if mode == 0:
                mutated["mac"] = ("0" if mutated["mac"][0] != "0" else "1") + mutated["mac"][1:]
            elif mode == 1:
                mutated["payload"]["evidence"]["producer"] = f"attacker-{index}"
            elif mode == 2:
                mutated["payload"]["evidence"]["payload"]["counter"] = index + 100
            elif mode == 3:
                mutated["payload"]["evidence"]["extra"] = index
            elif mode == 4:
                mutated["payload"]["receipt_version"] = 2
            else:
                mutated["payload"]["evidence"]["run_id"] = str(uuid4())
            path.write_text(json.dumps(mutated, separators=(",", ":")), encoding="utf-8")
            loaded = store.load(run_id)
            if loaded is None:
                receipt_rejected += 1
            else:
                receipt_failures.append({"index": index, "mode": mode, "loaded": loaded})
                break

        path.write_text(original_text, encoding="utf-8")
        semantic_same = json.dumps(original, indent=2, ensure_ascii=False)
        path.write_text(semantic_same, encoding="utf-8")
        equivalent_serialization_ok = store.load(run_id) == evidence

    after = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, text=True
    )
    source_unchanged = before == after
    passed = (
        generated == iterations
        and not roundtrip_failures
        and not digest_collisions
        and invalid_rejected == len(invalid_values)
        and not invalid_failures
        and receipt_rejected == receipt_mutations
        and not receipt_failures
        and equivalent_serialization_ok
        and source_unchanged
    )
    summary = {
        "seed": SEED,
        "generated_strict_json_values": generated,
        "requested_iterations": iterations,
        "unique_digests_observed": len(digest_map),
        "roundtrip_failures": roundtrip_failures,
        "distinct_canonical_digest_collisions": digest_collisions,
        "invalid_coercion_cases": len(invalid_values),
        "invalid_coercions_rejected": invalid_rejected,
        "invalid_failures": invalid_failures,
        "receipt_mutations_requested": receipt_mutations,
        "receipt_mutations_rejected": receipt_rejected,
        "receipt_failures": receipt_failures,
        "equivalent_receipt_serialization_preserves_authenticated_semantics": equivalent_serialization_ok,
        "source_unchanged": source_unchanged,
        "result": "PASS" if passed else "FAIL",
        "claim": "Security bindings accept only the strict JSON data model; seeded valid-value generation remains deterministic and collision-free in the measured sample, coercion inputs fail closed, and stale-MAC semantic receipt mutations are rejected.",
        "limits": [
            "This is deterministic property/fuzz evidence, not a proof that SHA-256 is collision-free.",
            "Receipt authentication is semantic: equivalent JSON whitespace/key-order serialization is accepted after parsing because the MAC covers canonical payload semantics.",
            "Cross-language JSON canonicalization is not claimed; MgNarf binds the trusted Python host's strict JSON model.",
        ],
    }
    dump(output / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=10000)
    parser.add_argument("--receipt-mutations", type=int, default=256)
    args = parser.parse_args()
    if not args.output.is_absolute() or args.output.resolve().is_relative_to(ROOT):
        parser.error("--output must be absolute and outside the repository")
    if args.iterations < 1 or args.receipt_mutations < 1:
        parser.error("iteration counts must be positive")
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    summary = run(args.output, args.iterations, args.receipt_mutations)
    return 0 if summary["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
