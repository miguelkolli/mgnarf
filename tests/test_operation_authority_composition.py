"""Composition tests for identity revision + stable operation + effect authority."""

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from narf import (
    AuthoritySnapshot,
    ConsumptionAuthority,
    EffectBinding,
    FrozenState,
    NARFError,
    OperationBoundEffectExecutor,
    OperationBoundGate,
    ReceiptStore,
    Requirement,
    VerifierBinding,
    VerifierResult,
    sha256_bytes,
)


class MemoryConsumptionAuthority(ConsumptionAuthority):
    def __init__(self, on_reserve=None):
        self.used = set()
        self.reserve_calls = 0
        self.on_reserve = on_reserve

    def reserve(self, token: str) -> None:
        self.reserve_calls += 1
        if token in self.used:
            raise NARFError("effect: external consumption authority already consumed")
        self.used.add(token)
        if self.on_reserve is not None:
            self.on_reserve()

    def is_reserved(self, token: str) -> bool:
        return token in self.used

    def domain_key(self):
        return ("test-memory", id(self))


class OperationAuthorityCompositionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="narf-operation-authority-")
        self.addCleanup(tmp.cleanup)
        self.store = ReceiptStore(Path(tmp.name), b"o" * 32)
        self.task = {"description": "composed protected operation"}
        self.state = FrozenState(
            sha256_bytes(b"candidate"),
            sha256_bytes(b"requirements"),
            sha256_bytes(b"policy"),
        )
        self.current_state = self.state
        self.effects = []
        self.operation_id = str(uuid4())
        self.requirements = [
            Requirement("review", "security-review", "1"),
            Requirement("approval", "approve", "1"),
        ]
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
                "authority": {
                    "principal_id": "human:approver",
                    "trust_domain": "approval-plane",
                },
            },
            "separation": [
                ["builder", "verifier:security-review", "principal_id"],
                ["builder", "verifier:security-review", "trust_domain"],
                ["builder", "authority", "principal_id"],
                ["verifier:security-review", "authority", "principal_id"],
            ],
            "authority_verifier_id": "approve",
        }
        self.snapshot = AuthoritySnapshot(7, deepcopy(self.policy["actors"]))

    def gate(self):
        return OperationBoundGate(self.store, authority_probe=lambda: self.snapshot)

    def bindings(self):
        values = []
        for requirement in self.requirements:
            role = (
                "authority"
                if requirement.verifier_id == self.policy["authority_verifier_id"]
                else "verifier:" + requirement.verifier_id
            )
            actor = self.policy["actors"][role]
            values.append(
                VerifierBinding(
                    requirement.verifier_id,
                    requirement.verifier_version,
                    lambda name=requirement.requirement_id: VerifierResult(
                        "PASS", ("evidence:" + name).encode()
                    ),
                    principal_id=actor["principal_id"],
                    trust_domain=actor.get("trust_domain"),
                )
            )
        return values

    def freeze(self, gate=None, *, operation_id=None):
        gate = gate or self.gate()
        return gate.freeze_contract(
            self.task,
            operation_id=operation_id or self.operation_id,
            task_id="composed-operation",
            requirements=self.requirements,
            effect_id="deploy",
            effect_version="1",
            state=self.state,
            identity_policy=self.policy,
        )

    def session(self, gate, contract_id):
        return gate.open_session(
            contract_id,
            self.task,
            verifier_bindings=self.bindings(),
            effect_binding=EffectBinding(
                "deploy", "1", lambda: self.effects.append("deployed")
            ),
            state_probe=lambda: self.current_state,
        )

    @staticmethod
    def run_all(session):
        for requirement_id in session.requirements():
            session.execute(requirement_id)

    def test_composed_path_passes_and_exposes_frozen_revision(self):
        gate = self.gate()
        contract_id = self.freeze(gate)
        session = self.session(gate, contract_id)
        self.run_all(session)

        self.assertEqual(session.finalize()["result"], "PASS")
        self.assertEqual(session.operation_id, self.operation_id)
        self.assertEqual(session.authority_revision, 7)

        authority = MemoryConsumptionAuthority()
        OperationBoundEffectExecutor(authority).execute(session)
        self.assertEqual(authority.reserve_calls, 1)
        self.assertTrue(authority.is_reserved(self.operation_id))
        self.assertEqual(self.effects, ["deployed"])

    def test_revision_change_before_effect_blocks_before_operation_reservation(self):
        gate = self.gate()
        contract_id = self.freeze(gate)
        session = self.session(gate, contract_id)
        self.run_all(session)
        self.snapshot = AuthoritySnapshot(8, deepcopy(self.policy["actors"]))

        authority = MemoryConsumptionAuthority()
        with self.assertRaises(NARFError):
            OperationBoundEffectExecutor(authority).execute(session)
        self.assertEqual(authority.reserve_calls, 0)
        self.assertFalse(authority.is_reserved(self.operation_id))
        self.assertEqual(self.effects, [])

    def test_actor_change_with_same_revision_blocks_before_operation_reservation(self):
        gate = self.gate()
        contract_id = self.freeze(gate)
        session = self.session(gate, contract_id)
        self.run_all(session)

        actors = deepcopy(self.policy["actors"])
        actors["verifier:security-review"]["principal_id"] = "reviewer:changed"
        self.snapshot = AuthoritySnapshot(7, actors)

        authority = MemoryConsumptionAuthority()
        with self.assertRaises(NARFError):
            OperationBoundEffectExecutor(authority).execute(session)
        self.assertEqual(authority.reserve_calls, 0)
        self.assertEqual(self.effects, [])

    def test_revision_change_during_reservation_consumes_operation_but_blocks_callback(self):
        gate = self.gate()
        contract_id = self.freeze(gate)
        session = self.session(gate, contract_id)
        self.run_all(session)

        def advance_revision():
            self.snapshot = AuthoritySnapshot(8, deepcopy(self.policy["actors"]))

        authority = MemoryConsumptionAuthority(on_reserve=advance_revision)
        with self.assertRaises(NARFError):
            OperationBoundEffectExecutor(authority).execute(session)

        self.assertEqual(authority.reserve_calls, 1)
        self.assertTrue(authority.is_reserved(self.operation_id))
        self.assertEqual(self.effects, [])

    def test_stable_operation_blocks_new_contract_replay(self):
        gate = self.gate()
        authority = MemoryConsumptionAuthority()
        executor = OperationBoundEffectExecutor(authority)

        first_id = self.freeze(gate)
        first = self.session(gate, first_id)
        self.run_all(first)
        executor.execute(first)
        self.assertEqual(self.effects, ["deployed"])

        second_id = self.freeze(gate)
        self.assertNotEqual(first_id, second_id)
        second = self.session(gate, second_id)
        self.run_all(second)
        self.assertEqual(second.finalize()["result"], "PASS")

        with self.assertRaisesRegex(NARFError, "already consumed"):
            executor.execute(second)
        self.assertEqual(self.effects, ["deployed"])

    def test_identity_policy_on_operation_wrapper_requires_revision_probe(self):
        legacy = OperationBoundGate(self.store)
        with self.assertRaisesRegex(NARFError, "authority probe required"):
            legacy.freeze_contract(
                self.task,
                operation_id=self.operation_id,
                task_id="legacy-rejects-identity-shortcut",
                requirements=self.requirements,
                effect_id="deploy",
                effect_version="1",
                state=self.state,
                identity_policy=self.policy,
            )


if __name__ == "__main__":
    unittest.main()
