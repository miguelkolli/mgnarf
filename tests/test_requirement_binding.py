from dataclasses import asdict
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from narf import (
    EffectBinding,
    FrozenState,
    NARFGate,
    ReceiptStore,
    Requirement,
    VerifierBinding,
    VerifierResult,
    canonical_json_digest,
    sha256_bytes,
)


class RequirementBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="narf-requirement-binding-")
        self.addCleanup(self.tmp.cleanup)
        self.store = ReceiptStore(Path(self.tmp.name) / "receipts", b"r" * 32)
        self.gate = NARFGate(self.store)
        self.task = {"description": "bind exact verifier requirement set"}
        self.requirements = [Requirement("unit", "host-check", "1")]
        self.state = FrozenState(
            candidate_sha256=sha256_bytes(b"candidate-v1"),
            requirements_sha256=sha256_bytes(b"external-goalpost-v1"),
            policy_sha256=sha256_bytes(b"policy-v1"),
        )

    def freeze(self):
        return self.gate.freeze_contract(
            self.task,
            task_id="requirement-binding",
            requirements=self.requirements,
            effect_id="publish",
            effect_version="1",
            state=self.state,
        )

    def test_gate_computes_exact_requirement_set_digest(self):
        contract_id = self.freeze()
        contract = self.store.load(contract_id)
        expected = canonical_json_digest([asdict(item) for item in self.requirements])
        self.assertEqual(contract["requirements_set_sha256"], expected)
        self.assertNotEqual(contract["requirements_set_sha256"], self.state.requirements_sha256)

    def test_authenticated_contract_with_mismatched_requirement_set_digest_is_blocked(self):
        contract = self.store.load(self.freeze())
        inconsistent = dict(contract)
        inconsistent["run_id"] = str(uuid4())
        inconsistent["requirements"] = [
            asdict(Requirement("unit", "host-check", "1")),
            asdict(Requirement("policy", "policy-check", "1")),
        ]
        self.store.save(inconsistent)

        session = self.gate.open_session(
            inconsistent["run_id"],
            self.task,
            verifier_bindings=[
                VerifierBinding("host-check", "1", lambda: VerifierResult("PASS", b"unit")),
                VerifierBinding("policy-check", "1", lambda: VerifierResult("PASS", b"policy")),
            ],
            effect_binding=EffectBinding("publish", "1", lambda: "published"),
            state_probe=lambda: self.state,
        )
        verdict = session.verdict()
        self.assertEqual(verdict["result"], "BLOCKED")
        self.assertEqual(verdict["reason"], "INVALID_CONTRACT")


if __name__ == "__main__":
    unittest.main()
