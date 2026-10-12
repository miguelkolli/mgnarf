"""Regression tests for mandatory executor routing in the composed operation path."""

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from narf import (
    AuthoritySnapshot,
    EffectBinding,
    FrozenState,
    NARFError,
    OperationBoundEffectExecutor,
    OperationBoundGate,
    ReceiptStore,
    Requirement,
    VerifierBinding,
    VerifierResult,
    FileConsumptionAuthority,
    sha256_bytes,
)


class OperationExecutorRequiredTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="narf-operation-executor-required-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.store = ReceiptStore(self.root / "receipts", b"x" * 32)
        self.task = {"description": "executor required"}
        self.state = FrozenState(
            sha256_bytes(b"candidate"),
            sha256_bytes(b"requirements"),
            sha256_bytes(b"policy"),
        )
        self.effects = []
        self.requirement = Requirement("review", "security-review", "1")
        self.policy = {
            "actors": {
                "builder": {
                    "principal_id": "agent:builder",
                    "trust_domain": "build-plane",
                },
                "verifier:security-review": {
                    "principal_id": "reviewer:independent",
                    "trust_domain": "review-plane",
                },
            },
            "separation": [
                ["builder", "verifier:security-review", "principal_id"],
                ["builder", "verifier:security-review", "trust_domain"],
            ],
        }
        self.snapshot = AuthoritySnapshot(3, deepcopy(self.policy["actors"]))

    def binding(self):
        actor = self.policy["actors"]["verifier:security-review"]
        return VerifierBinding(
            "security-review",
            "1",
            lambda: VerifierResult("PASS", b"review"),
            principal_id=actor["principal_id"],
            trust_domain=actor["trust_domain"],
        )

    def test_composed_session_cannot_bypass_operation_executor(self):
        gate = OperationBoundGate(self.store, authority_probe=lambda: self.snapshot)
        operation_id = str(uuid4())
        contract_id = gate.freeze_contract(
            self.task,
            operation_id=operation_id,
            task_id="composed-executor-required",
            requirements=(self.requirement,),
            effect_id="deploy",
            effect_version="1",
            state=self.state,
            identity_policy=self.policy,
        )
        session = gate.open_session(
            contract_id,
            self.task,
            verifier_bindings=(self.binding(),),
            effect_binding=EffectBinding(
                "deploy", "1", lambda: self.effects.append("direct-bypass")
            ),
            state_probe=lambda: self.state,
        )
        session.execute("review")
        self.assertEqual(session.finalize()["result"], "PASS")

        with self.assertRaisesRegex(NARFError, "OperationBoundEffectExecutor required"):
            session.execute_effect()
        self.assertEqual(self.effects, [])

        authority = FileConsumptionAuthority(self.root / "authority")
        OperationBoundEffectExecutor(authority).execute(session)
        self.assertTrue(authority.is_reserved(operation_id))
        self.assertEqual(self.effects, ["direct-bypass"])

    def test_legacy_operation_session_keeps_direct_effect_compatibility(self):
        gate = OperationBoundGate(self.store)
        operation_id = str(uuid4())
        contract_id = gate.freeze_contract(
            self.task,
            operation_id=operation_id,
            task_id="legacy-direct-effect",
            requirements=(self.requirement,),
            effect_id="deploy",
            effect_version="1",
            state=self.state,
        )
        session = gate.open_session(
            contract_id,
            self.task,
            verifier_bindings=(
                VerifierBinding(
                    "security-review",
                    "1",
                    lambda: VerifierResult("PASS", b"review"),
                ),
            ),
            effect_binding=EffectBinding(
                "deploy", "1", lambda: self.effects.append("legacy-direct")
            ),
            state_probe=lambda: self.state,
        )
        session.execute("review")
        self.assertEqual(session.finalize()["result"], "PASS")
        session.execute_effect()
        self.assertEqual(self.effects, ["legacy-direct"])


if __name__ == "__main__":
    unittest.main()
