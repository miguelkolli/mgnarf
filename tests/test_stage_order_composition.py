"""Composition tests for ordered evidence through hardened host wrappers."""

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from narf import (
    AuthorityRevisionGate,
    AuthoritySnapshot,
    EffectBinding,
    FencedEffectBinding,
    FencedOperationGate,
    FrozenState,
    NARFError,
    OperationBoundGate,
    ReceiptStore,
    Requirement,
    VerifierBinding,
    VerifierResult,
    sha256_bytes,
)


class MutableAuthority:
    def __init__(self, actors):
        self.revision = 1
        self.actors = deepcopy(actors)

    def __call__(self):
        return AuthoritySnapshot(self.revision, deepcopy(self.actors))


class StageOrderCompositionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="narf-stage-order-composition-")
        self.addCleanup(tmp.cleanup)
        self.store = ReceiptStore(Path(tmp.name), b"c" * 32)
        self.task = {"description": "ordered hardened path"}
        self.state = FrozenState(
            sha256_bytes(b"candidate"),
            sha256_bytes(b"requirements"),
            sha256_bytes(b"policy"),
        )
        self.requirements = [
            Requirement("check", "check", "1"),
            Requirement("approval", "approve", "1"),
        ]
        self.stage_order = ["check", "approval"]
        self.policy = {
            "actors": {
                "builder": {
                    "principal_id": "agent:builder",
                    "trust_domain": "build-plane",
                },
                "verifier:check": {
                    "principal_id": "agent:reviewer",
                    "trust_domain": "review-plane",
                },
                "authority": {
                    "principal_id": "human:approver",
                    "trust_domain": "approval-plane",
                },
            },
            "separation": [
                ["builder", "verifier:check", "principal_id"],
                ["verifier:check", "authority", "principal_id"],
            ],
            "authority_verifier_id": "approve",
        }
        self.authority = MutableAuthority(self.policy["actors"])

    def bindings(self):
        result = []
        for requirement in self.requirements:
            role = "authority" if requirement.verifier_id == "approve" else "verifier:check"
            actor = self.policy["actors"][role]
            result.append(
                VerifierBinding(
                    requirement.verifier_id,
                    requirement.verifier_version,
                    lambda name=requirement.requirement_id: VerifierResult(
                        "PASS", ("evidence:" + name).encode()
                    ),
                    principal_id=actor["principal_id"],
                    trust_domain=actor["trust_domain"],
                )
            )
        return result

    def assert_ordered_session(self, session):
        with self.assertRaises(NARFError):
            session.execute("approval")
        self.assertEqual(session.execute("check")["status"], "PASS")
        self.assertEqual(session.execute("approval")["status"], "PASS")
        self.assertEqual(session.finalize()["result"], "PASS")

    def test_authority_revision_gate_preserves_stage_order(self):
        gate = AuthorityRevisionGate(self.store, self.authority)
        contract_id = gate.freeze_contract(
            self.task,
            task_id="ordered-authority",
            requirements=self.requirements,
            effect_id="publish",
            effect_version="1",
            state=self.state,
            identity_policy=self.policy,
            stage_order=self.stage_order,
        )
        contract = self.store.load(contract_id)
        self.assertEqual(contract["evidence_version"], 3)
        self.assertEqual(contract["stage_order"], self.stage_order)
        session = gate.open_session(
            contract_id,
            self.task,
            verifier_bindings=self.bindings(),
            effect_binding=EffectBinding("publish", "1", lambda: None),
            state_probe=lambda: self.state,
        )
        self.assert_ordered_session(session)

    def test_operation_bound_authority_path_preserves_stage_order(self):
        gate = OperationBoundGate(self.store, authority_probe=self.authority)
        contract_id = gate.freeze_contract(
            self.task,
            operation_id=str(uuid4()),
            task_id="ordered-operation",
            requirements=self.requirements,
            effect_id="publish",
            effect_version="1",
            state=self.state,
            identity_policy=self.policy,
            stage_order=self.stage_order,
        )
        contract = self.store.load(contract_id)
        self.assertEqual(contract["evidence_version"], 3)
        session = gate.open_session(
            contract_id,
            self.task,
            verifier_bindings=self.bindings(),
            effect_binding=EffectBinding("publish", "1", lambda: None),
            state_probe=lambda: self.state,
        )
        self.assert_ordered_session(session)

    def test_fenced_operation_path_preserves_stage_order(self):
        gate = FencedOperationGate(self.store, self.authority)
        contract_id = gate.freeze_contract(
            self.task,
            operation_id=str(uuid4()),
            fence_scope_id="test-scope",
            fencing_authority_id="test-authority",
            task_id="ordered-fenced",
            requirements=self.requirements,
            effect_id="publish",
            effect_version="1",
            state=self.state,
            identity_policy=self.policy,
            stage_order=self.stage_order,
        )
        contract = self.store.load(contract_id)
        self.assertEqual(contract["evidence_version"], 3)
        session = gate.open_session(
            contract_id,
            self.task,
            verifier_bindings=self.bindings(),
            effect_binding=FencedEffectBinding(
                "publish", "1", "test-scope", lambda _token: None
            ),
            state_probe=lambda: self.state,
        )
        self.assert_ordered_session(session)


if __name__ == "__main__":
    unittest.main()
