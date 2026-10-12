"""Fresh whole-chain adversarial regressions for the v1.70 release candidate."""

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from narf import (
    AuthoritySnapshot,
    ConsumptionAuthority,
    EffectBinding,
    FenceToken,
    FencedEffectBinding,
    FencedOperationEffectExecutor,
    FencedOperationGate,
    FencingAuthority,
    FrozenState,
    NARFError,
    OperationBoundGate,
    ReceiptStore,
    Requirement,
    VerifierBinding,
    VerifierResult,
    sha256_bytes,
)


class MemoryOperationAuthority(ConsumptionAuthority):
    def __init__(self):
        self.used = set()
        self.calls = 0

    def reserve(self, token: str) -> None:
        self.calls += 1
        if token in self.used:
            raise NARFError("effect: external consumption authority already consumed")
        self.used.add(token)

    def is_reserved(self, token: str) -> bool:
        return token in self.used

    def domain_key(self):
        return ("v170-memory-operation", id(self))


class MemoryFencingAuthority(FencingAuthority):
    def __init__(self, probe, *, authority_id="v170-fence", mutate=None):
        self.probe = probe
        self._authority_id = authority_id
        self.mutate = mutate
        self.calls = 0
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
        self.calls += 1
        snapshot = self.probe()
        if snapshot.revision != expected_authority_revision:
            raise NARFError("fence: authority revision changed")
        sequence = self.sequences.get(fence_scope_id, 0) + 1
        self.sequences[fence_scope_id] = sequence
        token = FenceToken(
            fence_scope_id=fence_scope_id,
            operation_id=operation_id,
            authority_revision=expected_authority_revision,
            effect_id=effect_id,
            effect_version=effect_version,
            fence_sequence=sequence,
            authority_id=self.authority_id,
        )
        return self.mutate(token) if self.mutate is not None else token


class V170WholeChainTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="mgnarf-v170-whole-chain-")
        self.addCleanup(tmp.cleanup)
        self.store = ReceiptStore(Path(tmp.name) / "receipts", b"w" * 32)
        self.task = {"description": "v1.70 whole-chain release candidate"}
        self.state = FrozenState(
            sha256_bytes(b"candidate-v170"),
            sha256_bytes(b"requirements-v170"),
            sha256_bytes(b"policy-v170"),
        )
        self.current_state = self.state
        profile_a = {
            "model": {"provider": "example", "name": "reviewer-a", "version": "1"},
            "system_prompt_sha256": sha256_bytes(b"system-a"),
            "verifier_prompt_sha256": sha256_bytes(b"verify-a"),
            "toolchain": {"adapter": "v170"},
        }
        profile_b = {
            "model": {"provider": "example", "name": "reviewer-b", "version": "1"},
            "system_prompt_sha256": sha256_bytes(b"system-b"),
            "verifier_prompt_sha256": sha256_bytes(b"verify-b"),
            "toolchain": {"adapter": "v170"},
        }
        self.policy = {
            "actors": {
                "builder": {
                    "principal_id": "agent:builder",
                    "trust_domain": "build-plane",
                },
                "verifier:check-a": {
                    "principal_id": "reviewer:a",
                    "trust_domain": "review-a",
                    "verifier_profile": profile_a,
                },
                "verifier:check-b": {
                    "principal_id": "reviewer:b",
                    "trust_domain": "review-b",
                    "verifier_profile": profile_b,
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
                ["verifier:check-a", "verifier:check-b", "verifier_profile"],
                ["builder", "authority", "principal_id"],
            ],
            "authority_verifier_id": "approve",
        }
        self.snapshot = AuthoritySnapshot(17, deepcopy(self.policy["actors"]))
        self.requirements = (
            Requirement("tests", "check-a", "1"),
            Requirement("security", "check-b", "1"),
            Requirement("approval", "approve", "1"),
        )
        self.operation_id = str(uuid4())
        self.scope = "release:v1.70"
        self.fencing_authority_id = "v170-fence"
        self.effects = []

    def authority_probe(self):
        return self.snapshot

    def bindings(self):
        result = []
        for requirement in self.requirements:
            role = (
                "authority"
                if requirement.verifier_id == self.policy["authority_verifier_id"]
                else "verifier:" + requirement.verifier_id
            )
            actor = self.policy["actors"][role]
            result.append(
                VerifierBinding(
                    requirement.verifier_id,
                    requirement.verifier_version,
                    lambda name=requirement.requirement_id: VerifierResult(
                        "PASS", ("evidence:" + name).encode()
                    ),
                    principal_id=actor["principal_id"],
                    trust_domain=actor.get("trust_domain"),
                    verifier_profile=deepcopy(actor.get("verifier_profile")),
                )
            )
        return tuple(result)

    def gate(self):
        return FencedOperationGate(self.store, self.authority_probe)

    def freeze(self, gate=None, *, operation_id=None):
        gate = gate or self.gate()
        return gate.freeze_contract(
            self.task,
            operation_id=operation_id or self.operation_id,
            fence_scope_id=self.scope,
            fencing_authority_id=self.fencing_authority_id,
            task_id="v1.70-whole-chain",
            requirements=self.requirements,
            effect_id="release",
            effect_version="1.70",
            state=self.state,
            identity_policy=self.policy,
        )

    def open_session(self, gate, contract_id, *, scope=None):
        effect = FencedEffectBinding(
            "release",
            "1.70",
            scope or self.scope,
            lambda token: self.effects.append(token) or "committed",
        )
        return gate.open_session(
            contract_id,
            self.task,
            verifier_bindings=self.bindings(),
            effect_binding=effect,
            state_probe=lambda: self.current_state,
        )

    def verify_all(self, session):
        for requirement_id in session.requirements():
            session.execute(requirement_id)
        self.assertEqual(session.finalize()["result"], "PASS")

    def executor(self, operation_authority=None, fencing_authority=None):
        operation_authority = operation_authority or MemoryOperationAuthority()
        fencing_authority = fencing_authority or MemoryFencingAuthority(
            self.authority_probe,
            authority_id=self.fencing_authority_id,
        )
        return (
            FencedOperationEffectExecutor(operation_authority, fencing_authority),
            operation_authority,
            fencing_authority,
        )

    def test_01_full_chain_current_authority_executes_once(self):
        gate = self.gate()
        session = self.open_session(gate, self.freeze(gate))
        self.verify_all(session)
        executor, operation_authority, fencing_authority = self.executor()

        self.assertEqual(executor.execute(session), "committed")
        self.assertTrue(operation_authority.is_reserved(self.operation_id))
        self.assertEqual(fencing_authority.calls, 1)
        self.assertEqual(len(self.effects), 1)
        self.assertEqual(self.effects[0].authority_revision, 17)

    def test_02_fenced_contract_cannot_downgrade_to_operation_v1(self):
        gate = self.gate()
        contract_id = self.freeze(gate)
        legacy = OperationBoundGate(self.store, authority_probe=self.authority_probe)

        with self.assertRaisesRegex(NARFError, "authenticated binding required"):
            legacy.open_session(
                contract_id,
                self.task,
                verifier_bindings=self.bindings(),
                effect_binding=EffectBinding("release", "1.70", lambda: None),
                state_probe=lambda: self.current_state,
            )
        self.assertEqual(self.effects, [])

    def test_03_fenced_session_blocks_direct_effect_bypass(self):
        gate = self.gate()
        session = self.open_session(gate, self.freeze(gate))
        self.verify_all(session)

        with self.assertRaisesRegex(NARFError, "FencedOperationEffectExecutor required"):
            session.execute_effect()
        self.assertEqual(self.effects, [])

    def test_04_authority_revision_drift_blocks_before_operation_reservation(self):
        gate = self.gate()
        session = self.open_session(gate, self.freeze(gate))
        self.verify_all(session)
        self.snapshot = AuthoritySnapshot(18, deepcopy(self.policy["actors"]))
        executor, operation_authority, fencing_authority = self.executor()

        with self.assertRaises(NARFError):
            executor.execute(session)
        self.assertEqual(operation_authority.calls, 0)
        self.assertEqual(fencing_authority.calls, 0)
        self.assertEqual(self.effects, [])

    def test_05_observed_identity_drift_cannot_resurrect_after_restore(self):
        gate = self.gate()
        session = self.open_session(gate, self.freeze(gate))
        self.verify_all(session)
        changed = deepcopy(self.policy["actors"])
        changed["verifier:check-a"]["principal_id"] = "agent:builder"
        self.snapshot = AuthoritySnapshot(17, changed)
        self.assertEqual(session.verdict()["result"], "BLOCKED")
        self.snapshot = AuthoritySnapshot(17, deepcopy(self.policy["actors"]))
        executor, operation_authority, fencing_authority = self.executor()

        with self.assertRaises(NARFError):
            executor.execute(session)
        self.assertEqual(operation_authority.calls, 0)
        self.assertEqual(fencing_authority.calls, 0)
        self.assertEqual(self.effects, [])

    def test_06_same_operation_replay_on_fresh_contract_is_blocked(self):
        operation_authority = MemoryOperationAuthority()
        fencing_authority = MemoryFencingAuthority(
            self.authority_probe,
            authority_id=self.fencing_authority_id,
        )
        executor = FencedOperationEffectExecutor(operation_authority, fencing_authority)

        first_gate = self.gate()
        first = self.open_session(first_gate, self.freeze(first_gate))
        self.verify_all(first)
        self.assertEqual(executor.execute(first), "committed")

        second_gate = self.gate()
        second = self.open_session(
            second_gate,
            self.freeze(second_gate, operation_id=self.operation_id),
        )
        self.verify_all(second)
        with self.assertRaisesRegex(NARFError, "already consumed"):
            executor.execute(second)

        self.assertEqual(operation_authority.calls, 2)
        self.assertEqual(fencing_authority.calls, 1)
        self.assertEqual(len(self.effects), 1)

    def test_07_wrong_fencing_authority_blocks_before_operation_reservation(self):
        gate = self.gate()
        session = self.open_session(gate, self.freeze(gate))
        self.verify_all(session)
        operation_authority = MemoryOperationAuthority()
        wrong = MemoryFencingAuthority(self.authority_probe, authority_id="wrong-fence")
        executor = FencedOperationEffectExecutor(operation_authority, wrong)

        with self.assertRaisesRegex(NARFError, "authority binding mismatch"):
            executor.execute(session)
        self.assertEqual(operation_authority.calls, 0)
        self.assertEqual(wrong.calls, 0)
        self.assertEqual(self.effects, [])

    def test_08_malformed_fence_after_reservation_consumes_operation_without_effect(self):
        gate = self.gate()
        session = self.open_session(gate, self.freeze(gate))
        self.verify_all(session)
        operation_authority = MemoryOperationAuthority()

        def corrupt(token):
            return FenceToken(
                fence_scope_id=token.fence_scope_id,
                operation_id=token.operation_id,
                authority_revision=token.authority_revision,
                effect_id=token.effect_id,
                effect_version=token.effect_version,
                fence_sequence=0,
                authority_id=token.authority_id,
            )

        fencing_authority = MemoryFencingAuthority(
            self.authority_probe,
            authority_id=self.fencing_authority_id,
            mutate=corrupt,
        )
        executor = FencedOperationEffectExecutor(operation_authority, fencing_authority)

        with self.assertRaisesRegex(NARFError, "invalid sequence"):
            executor.execute(session)
        self.assertTrue(operation_authority.is_reserved(self.operation_id))
        self.assertEqual(fencing_authority.calls, 1)
        self.assertEqual(self.effects, [])

    def test_09_state_drift_after_pass_blocks_before_operation_reservation(self):
        gate = self.gate()
        session = self.open_session(gate, self.freeze(gate))
        self.verify_all(session)
        self.current_state = FrozenState(
            sha256_bytes(b"candidate-v170-changed"),
            self.state.requirements_sha256,
            self.state.policy_sha256,
        )
        executor, operation_authority, fencing_authority = self.executor()

        with self.assertRaises(NARFError):
            executor.execute(session)
        self.assertEqual(operation_authority.calls, 0)
        self.assertEqual(fencing_authority.calls, 0)
        self.assertEqual(self.effects, [])

    def test_10_effect_scope_goalpost_change_is_rejected_before_verification(self):
        gate = self.gate()
        contract_id = self.freeze(gate)

        with self.assertRaisesRegex(NARFError, "effect binding changed"):
            self.open_session(gate, contract_id, scope="release:other")
        self.assertEqual(self.effects, [])


if __name__ == "__main__":
    unittest.main()
