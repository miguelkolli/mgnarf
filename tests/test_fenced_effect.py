"""Layer A/B regressions for the fenced-effect host path."""

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
    OperationBoundEffectExecutor,
    OperationBoundGate,
    ReceiptStore,
    Requirement,
    VerifierBinding,
    VerifierResult,
    sha256_bytes,
)


class MemoryOperationAuthority(ConsumptionAuthority):
    def __init__(self, on_reserve=None):
        self.used = set()
        self.calls = 0
        self.on_reserve = on_reserve

    def reserve(self, token: str) -> None:
        self.calls += 1
        if token in self.used:
            raise NARFError("effect: external consumption authority already consumed")
        self.used.add(token)
        if self.on_reserve is not None:
            self.on_reserve()

    def is_reserved(self, token: str) -> bool:
        return token in self.used

    def domain_key(self):
        return ("memory-operation", id(self))


class MemoryFencingAuthority(FencingAuthority):
    def __init__(self, snapshot_probe, *, authority_id="test-fence-authority", mutate=None):
        self.snapshot_probe = snapshot_probe
        self.sequences = {}
        self.calls = 0
        self._authority_id = authority_id
        self.mutate = mutate

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
        snapshot = self.snapshot_probe()
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
        if self.mutate is not None:
            return self.mutate(token)
        return token


class FencedEffectTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="narf-fenced-effect-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.store = ReceiptStore(self.root / "receipts", b"f" * 32)
        self.task = {"description": "fenced deploy"}
        self.state = FrozenState(
            sha256_bytes(b"candidate"),
            sha256_bytes(b"requirements"),
            sha256_bytes(b"policy"),
        )
        self.current_state = self.state
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
        self.snapshot = AuthoritySnapshot(11, deepcopy(self.policy["actors"]))
        self.operation_id = str(uuid4())
        self.fence_scope_id = "deployment:production-a"
        self.fencing_authority_id = "test-fence-authority"
        self.received = []

    def authority_probe(self):
        return self.snapshot

    def gate(self):
        return FencedOperationGate(self.store, self.authority_probe)

    def binding(self):
        actor = self.policy["actors"]["verifier:security-review"]
        return VerifierBinding(
            "security-review",
            "1",
            lambda: VerifierResult("PASS", b"review-proof"),
            principal_id=actor["principal_id"],
            trust_domain=actor["trust_domain"],
        )

    def freeze(self, gate=None, *, operation_id=None, fence_scope_id=None):
        gate = gate or self.gate()
        return gate.freeze_contract(
            self.task,
            operation_id=operation_id or self.operation_id,
            fence_scope_id=fence_scope_id or self.fence_scope_id,
            fencing_authority_id=self.fencing_authority_id,
            task_id="fenced-effect-test",
            requirements=(self.requirement,),
            effect_id="deploy",
            effect_version="1",
            state=self.state,
            identity_policy=self.policy,
        )

    def session(self, gate, contract_id, *, scope=None):
        effect = FencedEffectBinding(
            "deploy",
            "1",
            scope or self.fence_scope_id,
            lambda token: self.received.append(token) or "committed",
        )
        session = gate.open_session(
            contract_id,
            self.task,
            verifier_bindings=(self.binding(),),
            effect_binding=effect,
            state_probe=lambda: self.current_state,
        )
        session.execute("review")
        return session

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

    def test_current_fence_is_bound_persisted_and_transported(self):
        gate = self.gate()
        session = self.session(gate, self.freeze(gate))
        executor, operation_authority, fencing_authority = self.executor()

        result = executor.execute(session)

        self.assertEqual(result, "committed")
        self.assertTrue(operation_authority.is_reserved(self.operation_id))
        self.assertEqual(fencing_authority.calls, 1)
        self.assertEqual(len(self.received), 1)
        token = self.received[0]
        self.assertEqual(token.fence_scope_id, self.fence_scope_id)
        self.assertEqual(token.operation_id, self.operation_id)
        self.assertEqual(token.authority_revision, 11)
        self.assertEqual(token.effect_id, "deploy")
        self.assertEqual(token.effect_version, "1")
        self.assertEqual(token.fence_sequence, 1)
        self.assertEqual(token.authority_id, self.fencing_authority_id)

        fence_rows = []
        for path in self.store.directory.glob("*.json"):
            row = self.store.load(path.stem)
            if isinstance(row, dict) and row.get("evidence_type") == "narf.fence":
                fence_rows.append(row)
        self.assertEqual(len(fence_rows), 1)
        self.assertEqual(fence_rows[0]["operation_id"], self.operation_id)
        self.assertEqual(fence_rows[0]["fence_scope_id"], self.fence_scope_id)
        self.assertEqual(fence_rows[0]["fence_sequence"], 1)
        self.assertEqual(fence_rows[0]["authority_id"], self.fencing_authority_id)

    def test_wrong_fencing_authority_is_rejected_before_operation_reservation(self):
        gate = self.gate()
        session = self.session(gate, self.freeze(gate))
        operation_authority = MemoryOperationAuthority()
        wrong_authority = MemoryFencingAuthority(
            self.authority_probe,
            authority_id="other-fence-authority",
        )
        executor = FencedOperationEffectExecutor(operation_authority, wrong_authority)

        with self.assertRaisesRegex(NARFError, "authority binding mismatch"):
            executor.execute(session)

        self.assertEqual(operation_authority.calls, 0)
        self.assertEqual(wrong_authority.calls, 0)
        self.assertEqual(self.received, [])

    def test_revision_change_before_executor_does_not_reserve_operation(self):
        gate = self.gate()
        session = self.session(gate, self.freeze(gate))
        self.snapshot = AuthoritySnapshot(12, deepcopy(self.policy["actors"]))
        executor, operation_authority, fencing_authority = self.executor()

        with self.assertRaises(NARFError):
            executor.execute(session)

        self.assertEqual(operation_authority.calls, 0)
        self.assertEqual(fencing_authority.calls, 0)
        self.assertEqual(self.received, [])

    def test_revision_change_after_operation_reservation_consumes_operation(self):
        gate = self.gate()
        session = self.session(gate, self.freeze(gate))

        def advance_revision():
            self.snapshot = AuthoritySnapshot(12, deepcopy(self.policy["actors"]))

        operation_authority = MemoryOperationAuthority(on_reserve=advance_revision)
        fencing_authority = MemoryFencingAuthority(
            self.authority_probe,
            authority_id=self.fencing_authority_id,
        )
        executor, _, _ = self.executor(operation_authority, fencing_authority)

        with self.assertRaisesRegex(NARFError, "authority revision changed"):
            executor.execute(session)

        self.assertTrue(operation_authority.is_reserved(self.operation_id))
        self.assertEqual(fencing_authority.calls, 1)
        self.assertEqual(self.received, [])

    def test_malformed_or_mismatched_fence_keeps_operation_consumed(self):
        gate = self.gate()
        session = self.session(gate, self.freeze(gate))

        def wrong_scope(token):
            return FenceToken(
                fence_scope_id="deployment:other",
                operation_id=token.operation_id,
                authority_revision=token.authority_revision,
                effect_id=token.effect_id,
                effect_version=token.effect_version,
                fence_sequence=token.fence_sequence,
                authority_id=token.authority_id,
            )

        operation_authority = MemoryOperationAuthority()
        fencing_authority = MemoryFencingAuthority(
            self.authority_probe,
            authority_id=self.fencing_authority_id,
            mutate=wrong_scope,
        )
        executor, _, _ = self.executor(operation_authority, fencing_authority)

        with self.assertRaisesRegex(NARFError, "token binding mismatch"):
            executor.execute(session)

        self.assertTrue(operation_authority.is_reserved(self.operation_id))
        self.assertEqual(self.received, [])

    def test_invalid_fence_sequence_is_rejected_after_operation_reservation(self):
        gate = self.gate()
        session = self.session(gate, self.freeze(gate))

        def negative_sequence(token):
            return FenceToken(
                fence_scope_id=token.fence_scope_id,
                operation_id=token.operation_id,
                authority_revision=token.authority_revision,
                effect_id=token.effect_id,
                effect_version=token.effect_version,
                fence_sequence=-1,
                authority_id=token.authority_id,
            )

        operation_authority = MemoryOperationAuthority()
        fencing_authority = MemoryFencingAuthority(
            self.authority_probe,
            authority_id=self.fencing_authority_id,
            mutate=negative_sequence,
        )
        executor, _, _ = self.executor(operation_authority, fencing_authority)

        with self.assertRaisesRegex(NARFError, "invalid sequence"):
            executor.execute(session)

        self.assertTrue(operation_authority.is_reserved(self.operation_id))
        self.assertEqual(self.received, [])

    def test_direct_and_non_fenced_effect_routes_are_blocked(self):
        gate = self.gate()
        session = self.session(gate, self.freeze(gate))
        self.assertEqual(session.finalize()["result"], "PASS")

        with self.assertRaisesRegex(NARFError, "FencedOperationEffectExecutor required"):
            session.execute_effect()

        normal = OperationBoundEffectExecutor(MemoryOperationAuthority())
        with self.assertRaisesRegex(NARFError, "OperationBoundSession required"):
            normal.execute(session)
        self.assertEqual(self.received, [])

    def test_legacy_operation_gate_cannot_downgrade_fenced_binding(self):
        gate = self.gate()
        contract_id = self.freeze(gate)
        legacy = OperationBoundGate(self.store, authority_probe=self.authority_probe)

        with self.assertRaisesRegex(NARFError, "authenticated binding required"):
            legacy.open_session(
                contract_id,
                self.task,
                verifier_bindings=(self.binding(),),
                effect_binding=EffectBinding("deploy", "1", lambda: "bad"),
                state_probe=lambda: self.current_state,
            )
        self.assertEqual(self.received, [])

    def test_effect_scope_mismatch_is_rejected_before_verification(self):
        gate = self.gate()
        contract_id = self.freeze(gate)
        with self.assertRaisesRegex(NARFError, "effect binding changed"):
            self.session(gate, contract_id, scope="deployment:other")

    def test_same_operation_on_fresh_contract_cannot_acquire_second_fence(self):
        gate = self.gate()
        operation_authority = MemoryOperationAuthority()
        fencing_authority = MemoryFencingAuthority(
            self.authority_probe,
            authority_id=self.fencing_authority_id,
        )
        executor, _, _ = self.executor(operation_authority, fencing_authority)

        first = self.session(gate, self.freeze(gate))
        self.assertEqual(executor.execute(first), "committed")

        second = self.session(gate, self.freeze(gate))
        with self.assertRaisesRegex(NARFError, "already consumed"):
            executor.execute(second)

        self.assertEqual(fencing_authority.calls, 1)
        self.assertEqual(len(self.received), 1)

    def test_different_operations_same_scope_receive_comparable_sequences(self):
        gate = self.gate()
        operation_authority = MemoryOperationAuthority()
        fencing_authority = MemoryFencingAuthority(
            self.authority_probe,
            authority_id=self.fencing_authority_id,
        )
        executor, _, _ = self.executor(operation_authority, fencing_authority)

        first_op = str(uuid4())
        second_op = str(uuid4())
        first = self.session(gate, self.freeze(gate, operation_id=first_op))
        second = self.session(gate, self.freeze(gate, operation_id=second_op))

        executor.execute(first)
        executor.execute(second)

        self.assertEqual([row.fence_sequence for row in self.received], [1, 2])
        self.assertEqual(
            {row.fence_scope_id for row in self.received},
            {self.fence_scope_id},
        )


if __name__ == "__main__":
    unittest.main()
