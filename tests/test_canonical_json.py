from __future__ import annotations

from dataclasses import asdict
import json
import math
import os
import random
import tempfile
import unittest

from narf.gate import canonical_json
from narf import (
    EffectBinding,
    FrozenState,
    NARFError,
    NARFGate,
    ReceiptStore,
    Requirement,
    VerifierBinding,
    VerifierResult,
    canonical_json_digest,
    sha256_bytes,
)


class ListSubclass(list):
    pass


class CanonicalJSONTests(unittest.TestCase):
    def test_strict_json_rejects_coercion_collisions(self):
        invalid = [
            {1: "alpha"},
            {True: "alpha"},
            {None: "alpha"},
            {"items": (1, 2)},
            {"items": ListSubclass([1, 2])},
            {"items": {1, 2}},
            {"value": float("nan")},
            {"value": float("inf")},
            {"value": float("-inf")},
            {"value": "\ud800"},
        ]
        for value in invalid:
            with self.subTest(value=repr(value)):
                with self.assertRaises(NARFError):
                    canonical_json_digest(value)

    def test_strict_json_is_deterministic_and_round_trips(self):
        value = {
            "z": [None, True, False, 1, 1.5, "é", {"b": 2, "a": 1}],
            "a": {"nested": ["x", "y"]},
        }
        encoded = canonical_json(value)
        self.assertEqual(encoded, canonical_json(json.loads(encoded)))
        self.assertEqual(encoded, canonical_json({"a": value["a"], "z": value["z"]}))
        self.assertEqual(canonical_json_digest(value), canonical_json_digest(json.loads(encoded)))

    def test_gate_rejects_previous_task_binding_collision_at_freeze(self):
        requirement = Requirement("required", "host-check", "1")
        state = FrozenState(
            candidate_sha256=sha256_bytes(b"candidate"),
            requirements_sha256=canonical_json_digest([asdict(requirement)]),
            policy_sha256=sha256_bytes(b"policy"),
        )
        with tempfile.TemporaryDirectory() as name:
            gate = NARFGate(ReceiptStore(name, os.urandom(32)))
            with self.assertRaises(NARFError):
                gate.freeze_contract(
                    {1: "alpha"},
                    task_id="strict-json",
                    requirements=[requirement],
                    effect_id="publish",
                    effect_version="1",
                    state=state,
                )

    def test_gate_rejects_previous_task_binding_collision_at_open(self):
        requirement = Requirement("required", "host-check", "1")
        state = FrozenState(
            candidate_sha256=sha256_bytes(b"candidate"),
            requirements_sha256=canonical_json_digest([asdict(requirement)]),
            policy_sha256=sha256_bytes(b"policy"),
        )
        with tempfile.TemporaryDirectory() as name:
            gate = NARFGate(ReceiptStore(name, os.urandom(32)))
            contract_id = gate.freeze_contract(
                {"1": "alpha"},
                task_id="strict-json",
                requirements=[requirement],
                effect_id="publish",
                effect_version="1",
                state=state,
            )
            with self.assertRaises(NARFError):
                gate.open_session(
                    contract_id,
                    {1: "alpha"},
                    verifier_bindings=[VerifierBinding("host-check", "1", lambda: VerifierResult("PASS", b"proof"))],
                    effect_binding=EffectBinding("publish", "1", lambda: "effect"),
                    state_probe=lambda: state,
                )

    def test_seeded_property_sample_has_no_distinct_canonical_digest_collision(self):
        rng = random.Random(0x4E415246)
        seen: dict[str, str] = {}

        def text() -> str:
            alphabet = "abcXYZ09_- äöé中"
            return "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 12)))

        def value(depth: int = 0):
            choices = ["null", "bool", "int", "float", "str"]
            if depth < 3:
                choices += ["list", "dict"]
            kind = rng.choice(choices)
            if kind == "null":
                return None
            if kind == "bool":
                return bool(rng.getrandbits(1))
            if kind == "int":
                return rng.randrange(-(10**12), 10**12)
            if kind == "float":
                return rng.uniform(-1e9, 1e9)
            if kind == "str":
                return text()
            if kind == "list":
                return [value(depth + 1) for _ in range(rng.randrange(0, 5))]
            result = {}
            for _ in range(rng.randrange(0, 5)):
                result[text()] = value(depth + 1)
            return result

        for _ in range(2000):
            item = value()
            encoded = canonical_json(item)
            self.assertEqual(encoded, canonical_json(json.loads(encoded)))
            digest = canonical_json_digest(item)
            previous = seen.setdefault(digest, encoded)
            self.assertEqual(previous, encoded)


if __name__ == "__main__":
    unittest.main()
