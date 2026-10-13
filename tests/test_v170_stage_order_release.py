"""Release-specific ordered-chain regressions for the v1.70 candidate.

These three cases are intentionally exposed to the v1.70 whole-chain workflow
before its frozen protected-case count is raised from 10 to 13. That staged
transition requires a measured count-mismatch RED before the release scope is
refrozen; the product assertions themselves must remain green.
"""

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from narf import (
    AuthoritySnapshot,
    ConsumptionAuthority,
    FenceToken,
    FencedEffectBinding,
    FencedOperationEffectExecutor,
    FencedOperationGate,
    FencingAuthority,
    FrozenState,
    NARFError,
    ReceiptStore,
    Requirement,
    VerifierBinding,
    VerifierResult,
    sha256_bytes,
)


class MemoryOperationAuthority(ConsumptionAuthority):
    def __init__(self):
        self.used = set()

    def reserve(self, token: str) -> None:
        if token in self.used:
            raise NARFError("effect: external consumption authority already consumed")
        self.used.add(token)

    def is_reserved(self, token: str) -> bool:
        return token in self.used

    def domain_key(self):
        return ("v170-stage-order-operation", id(self))


class MemoryFencingAuthority(FencingAuthority):
    def __init__(self, probe, authority_id):
        self.probe = probe
        self._authority_id = authority_id
        self.sequences = {}

    @property
    def authority_id(self) -> str:
        return self._authority_id

    def acquire(
        self,
        *,
        fence_scope_id,
        operation_id,
        expected_authority_revision,
        effect_id,
        effect_version,
    ):
        snapshot = self.probe()
        if snapshot.revision != expected_authority_revision:
            raise NARFError("fence: authority revision changed")
        sequence = self.sequences.get(fence_scope_id, 0) + 1
        self.sequences[fence_scope_id] = sequence
        return FenceToken(
            fence_scope_id=fence_scope_id,
            operation_id=operation_id,
            authority_revision=expected_authority_revision,
            effect_id=effect_id,
            effect_version=effect_version,
            fence_sequence=sequence,
            authority_id=self.authority_id,
        )


class V170StageOrderReleaseTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="mgnarf-v170-stage-order-")
        self.addCleanup(tmp.cleanup)
        self.store = ReceiptStore(Path(tmp.name) / "receipts", b"o" * 32)
        self.task = {"description": "v1.70 ordered whole-chain release candidate"}
        self.state = FrozenState(
            sha256_bytes(b"candidate-v170-ordered"),
            sha256_bytes(b"requirements-v170-ordered"),
            sha256_bytes(b"policy-v170-ordered"),
        )
        self.current_state = self.state
        self.requirements = (
            Requirement("tests", "check-a", "1"),
            Requirement("security", "check-b", "1"),
            Requirement("approval", "approve", "1"),
        )
        self.stage_order = ["tests", "security", "approval"]
        self.policy = {
            "actors": {
                "builder": {
                    "principal_id": "agent:builder",
                    "trust_domain": "build-plane",
                },
                "verifier:check-a": {
                    "principal_id": "reviewer:a",
                    "trust_domain": "review-a",
                },
                "verifier:check-b": {
                    "principal_id": "reviewer:b",
                    "trust_domain": "review-b",
                },
                "authority": {
                    "principal_id": "human:approver",
                    "trust_domain": "approval-plane",
                },
            },
            "separation": [
                ["builder", "verifier:check-a", "principal_id"],
                ["builder", "verifier:check-b", "principal_id"],
                ["verifier:check-a", "verifier:check-b", "principal_id"],
                ["verifier:check-a", "verifier:check-b", "trust_domain"],
                ["builder", "authority", "principal_id"],
            ],
            "authority_verifier_id": "approve",
        }
        self.snapshot = AuthoritySnapshot(23, deepcopy(self.policy["actors"]))
        self.operation_id = str(uuid4())
        self.scope = "release:v1.70:ordered"
        self.fencing_authority_id = "v170-ordered-fence"
        self.calls = []
        self.effects = []

    def authority_probe(self):
        return self.snapshot

    def bindings(self):
        bindings = []
        for requirement in self.requirements:
            role = (
                "authority"
                if requirement.verifier_id == self.policy["authority_verifier_id"]
                else "verifier:" + requirement.verifier_id
            )
            actor = self.policy["actors"][role]

            def producer(name=requirement.requirement_id):
                self.calls.append(name)
                return VerifierResult("PASS", ("evidence:" + name).encode())

            bindings.append(
                VerifierBinding(
                    requirement.verifier_id,
                    requirement.verifier_version,
                    producer,
                    principal_id=actor["principal_id"],
                    trust_domain=actor["trust_domain"],
                )
            )
        return tuple(bindings)

    def gate_and_session(self):
        gate = FencedOperationGate(self.store, self.authority_probe)
        contract_id = gate.freeze_contract(
            self.task,
            operation_id=self.operation_id,
            fence_scope_id=self.scope,
            fencing_authority_id=self.fencing_authority_id,
            task_id="v1.70-ordered-whole-chain",
            requirements=self.requirements,
            effect_id="release",
            effect_version="1.70",
            state=self.state,
            identity_policy=self.policy,
            stage_order=self.stage_order,
        )
        session = gate.open_session(
            contract_id,
            self.task,
            verifier_bindings=self.bindings(),
            effect_binding=FencedEffectBinding(
                "release",
                "1.70",
                self.scope,
                lambda token: self.effects.append(token) or "committed",
            ),
            state_probe=lambda: self.current_state,
        )
        return gate, contract_id, session

    def execute_ordered_chain(self, session):
        for requirement_id in self.stage_order:
            self.assertEqual(session.execute(requirement_id)["status"], "PASS")
        self.assertEqual(session.finalize()["result"], "PASS")

    def test_11_ordered_identity_revision_fenced_chain_executes_once(self):
        _gate, contract_id, session = self.gate_and_session()
        contract = self.store.load(contract_id)
        self.assertEqual(contract["evidence_version"], 3)
        self.assertEqual(contract["stage_order"], self.stage_order)
        self.execute_ordered_chain(session)

        operation_authority = MemoryOperationAuthority()
        fencing_authority = MemoryFencingAuthority(
            self.authority_probe, self.fencing_authority_id
        )
        executor = FencedOperationEffectExecutor(operation_authority, fencing_authority)
        self.assertEqual(executor.execute(session), "committed")
        self.assertTrue(operation_authority.is_reserved(self.operation_id))
        self.assertEqual(self.calls, self.stage_order)
        self.assertEqual(len(self.effects), 1)

    def test_12_future_ordered_stage_is_blocked_before_producer(self):
        _gate, _contract_id, session = self.gate_and_session()
        with self.assertRaises(NARFError):
            session.execute("security")
        self.assertEqual(self.calls, [])
        self.assertEqual(session.execute("tests")["status"], "PASS")
        self.assertEqual(self.calls, ["tests"])
        self.assertEqual(self.effects, [])

    def test_13_authority_drift_after_first_ordered_receipt_blocks_next_stage(self):
        _gate, _contract_id, session = self.gate_and_session()
        self.assertEqual(session.execute("tests")["status"], "PASS")
        self.assertEqual(self.calls, ["tests"])
        self.snapshot = AuthoritySnapshot(24, deepcopy(self.policy["actors"]))

        with self.assertRaises(NARFError):
            session.execute("security")
        self.assertEqual(self.calls, ["tests"])
        self.assertEqual(session.verdict()["result"], "BLOCKED")
        self.assertEqual(self.effects, [])


if __name__ == "__main__":
    unittest.main()
