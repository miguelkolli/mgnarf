"""Composition tests for ordered evidence through hardened host wrappers."""

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from uuid import NAMESPACE_URL, uuid4, uuid5

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
from narf.gate import NARFGate as LegacyNARFGate


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

    def authority_binding_id(self, contract_id):
        return str(
            uuid5(
                NAMESPACE_URL,
                "narf.authority-revision-binding.v1:" + contract_id,
            )
        )

    def reauthenticate_receipt(self, run_id, mutate):
        path = self.store.directory / f"{run_id}.json"
        envelope = json.loads(path.read_text())
        mutate(envelope["payload"]["evidence"])
        envelope["mac"] = self.store._mac(envelope["payload"])
        path.write_text(json.dumps(envelope))

    def freeze_authority_contract(self):
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
        return gate, contract_id

    def open_authority_session(self, gate, contract_id):
        return gate.open_session(
            contract_id,
            self.task,
            verifier_bindings=self.bindings(),
            effect_binding=EffectBinding("publish", "1", lambda: None),
            state_probe=lambda: self.state,
        )

    def test_authority_revision_gate_preserves_stage_order(self):
        gate, contract_id = self.freeze_authority_contract()
        contract = self.store.load(contract_id)
        self.assertEqual(contract["evidence_version"], 3)
        self.assertEqual(contract["stage_order"], self.stage_order)
        session = self.open_authority_session(gate, contract_id)
        self.assert_ordered_session(session)

    def test_authority_binding_authenticates_stage_order_digest(self):
        _gate, contract_id = self.freeze_authority_contract()
        contract = self.store.load(contract_id)
        binding = self.store.load(self.authority_binding_id(contract_id))
        self.assertEqual(binding["evidence_version"], 2)
        self.assertEqual(binding["producer"], "host/narf-authority-revision-binding-v2")
        self.assertEqual(binding["stage_order_sha256"], contract["stage_order_sha256"])

    def test_authenticated_authority_stage_order_digest_tamper_fails_closed(self):
        gate, contract_id = self.freeze_authority_contract()
        binding_id = self.authority_binding_id(contract_id)
        self.reauthenticate_receipt(
            binding_id,
            lambda evidence: evidence.__setitem__("stage_order_sha256", "0" * 64),
        )
        with self.assertRaises(NARFError):
            self.open_authority_session(gate, contract_id)

    def test_authenticated_authority_binding_downgrade_to_v1_fails_closed(self):
        gate, contract_id = self.freeze_authority_contract()
        binding_id = self.authority_binding_id(contract_id)

        def downgrade(evidence):
            evidence["evidence_version"] = 1
            evidence["producer"] = "host/narf-authority-revision-binding-v1"
            evidence.pop("stage_order_sha256", None)

        self.reauthenticate_receipt(binding_id, downgrade)
        with self.assertRaises(NARFError):
            self.open_authority_session(gate, contract_id)

    def test_legacy_core_gate_rejects_ordered_v3_contract(self):
        _gate, contract_id = self.freeze_authority_contract()
        legacy = LegacyNARFGate(self.store)
        with self.assertRaises(NARFError):
            legacy.open_session(
                contract_id,
                self.task,
                verifier_bindings=self.bindings(),
                effect_binding=EffectBinding("publish", "1", lambda: None),
                state_probe=lambda: self.state,
                identity_probe=lambda: deepcopy(self.policy["actors"]),
            )

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
