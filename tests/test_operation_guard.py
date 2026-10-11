import json
from dataclasses import asdict
from pathlib import Path
import tempfile
import unittest
from uuid import NAMESPACE_URL, uuid4, uuid5

from narf import (
    EffectBinding,
    FileConsumptionAuthority,
    FrozenState,
    NARFError,
    NARFGate,
    OperationBoundEffectExecutor,
    OperationBoundGate,
    ReceiptStore,
    Requirement,
    VerifierBinding,
    VerifierResult,
    canonical_json_digest,
    sha256_bytes,
)


class OperationFixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="narf-operation-guard-")
        self.root = Path(self.tmp.name)
        self.key = b"o" * 32
        self.store = ReceiptStore(self.root / "receipts", self.key)
        self.gate = OperationBoundGate(self.store)
        self.authority = FileConsumptionAuthority(self.root / "authority")
        self.executor = OperationBoundEffectExecutor(self.authority)
        self.task = {"description": "publish one external operation"}
        self.requirement = Requirement("required", "host-check", "1")
        self.requirements = (self.requirement,)
        self.state = FrozenState(
            candidate_sha256=sha256_bytes(b"candidate-v1"),
            requirements_sha256=canonical_json_digest([asdict(self.requirement)]),
            policy_sha256=sha256_bytes(b"policy-v1"),
        )
        self.effects = []

    def close(self):
        self.tmp.cleanup()

    def freeze(self, operation_id):
        return self.gate.freeze_contract(
            self.task,
            operation_id=operation_id,
            task_id="operation-guard-test",
            requirements=self.requirements,
            effect_id="publish",
            effect_version="1",
            state=self.state,
        )

    def open(self, contract_id, label):
        def callback():
            self.effects.append(label)
            return label

        session = self.gate.open_session(
            contract_id,
            self.task,
            verifier_bindings=(
                VerifierBinding("host-check", "1", lambda: VerifierResult("PASS", b"proof")),
            ),
            effect_binding=EffectBinding("publish", "1", callback),
            state_probe=lambda: self.state,
        )
        session.execute("required")
        self.assert_pass(session)
        return session

    @staticmethod
    def assert_pass(session):
        if session.finalize()["result"] != "PASS":
            raise AssertionError("fixture failed to obtain PASS")


class OperationGuardTests(unittest.TestCase):
    def setUp(self):
        self.fixture = OperationFixture()
        self.addCleanup(self.fixture.close)

    def test_same_operation_across_fresh_contracts_is_single_use(self):
        operation_id = str(uuid4())
        first_id = self.fixture.freeze(operation_id)
        second_id = self.fixture.freeze(operation_id)
        self.assertNotEqual(first_id, second_id)

        first = self.fixture.open(first_id, "first")
        second = self.fixture.open(second_id, "second")

        self.assertEqual(first.operation_id, operation_id)
        self.assertEqual(second.operation_id, operation_id)
        self.assertEqual(self.fixture.executor.execute(first), "first")
        with self.assertRaisesRegex(NARFError, "already consumed"):
            self.fixture.executor.execute(second)
        self.assertEqual(self.fixture.effects, ["first"])
        self.assertTrue(self.fixture.authority.is_reserved(operation_id))

    def test_distinct_operations_may_each_execute(self):
        first_operation = str(uuid4())
        second_operation = str(uuid4())
        first = self.fixture.open(self.fixture.freeze(first_operation), "first")
        second = self.fixture.open(self.fixture.freeze(second_operation), "second")

        self.assertEqual(self.fixture.executor.execute(first), "first")
        self.assertEqual(self.fixture.executor.execute(second), "second")
        self.assertEqual(self.fixture.effects, ["first", "second"])

    def test_missing_operation_binding_fails_closed(self):
        base_gate = NARFGate(self.fixture.store)
        contract_id = base_gate.freeze_contract(
            self.fixture.task,
            task_id="operation-guard-test",
            requirements=self.fixture.requirements,
            effect_id="publish",
            effect_version="1",
            state=self.fixture.state,
        )
        with self.assertRaisesRegex(NARFError, "authenticated binding required"):
            self.fixture.gate.open_session(
                contract_id,
                self.fixture.task,
                verifier_bindings=(
                    VerifierBinding("host-check", "1", lambda: VerifierResult("PASS", b"proof")),
                ),
                effect_binding=EffectBinding("publish", "1", lambda: None),
                state_probe=lambda: self.fixture.state,
            )

    def test_tampered_operation_binding_fails_closed(self):
        operation_id = str(uuid4())
        contract_id = self.fixture.freeze(operation_id)
        binding_id = str(uuid5(NAMESPACE_URL, "narf.operation-binding.v1:" + contract_id))
        path = self.fixture.store.directory / f"{binding_id}.json"
        envelope = json.loads(path.read_text())
        envelope["payload"]["evidence"]["operation_id"] = str(uuid4())
        path.write_text(json.dumps(envelope))

        with self.assertRaisesRegex(NARFError, "authenticated binding required"):
            self.fixture.gate.open_session(
                contract_id,
                self.fixture.task,
                verifier_bindings=(
                    VerifierBinding("host-check", "1", lambda: VerifierResult("PASS", b"proof")),
                ),
                effect_binding=EffectBinding("publish", "1", lambda: None),
                state_probe=lambda: self.fixture.state,
            )

    def test_binding_can_be_recovered_by_fresh_gate_instance(self):
        operation_id = str(uuid4())
        contract_id = self.fixture.freeze(operation_id)
        fresh_store = ReceiptStore(self.fixture.store.directory, self.fixture.key)
        fresh_gate = OperationBoundGate(fresh_store)
        session = fresh_gate.open_session(
            contract_id,
            self.fixture.task,
            verifier_bindings=(
                VerifierBinding("host-check", "1", lambda: VerifierResult("PASS", b"proof")),
            ),
            effect_binding=EffectBinding("publish", "1", lambda: "fresh"),
            state_probe=lambda: self.fixture.state,
        )
        self.assertEqual(session.operation_id, operation_id)
        session.execute("required")
        self.assertEqual(session.finalize()["result"], "PASS")

    def test_invalid_operation_id_is_rejected_before_contract_creation(self):
        before = list(self.fixture.store.directory.glob("*.json"))
        with self.assertRaisesRegex(NARFError, "operation_id: invalid UUID"):
            self.fixture.freeze("candidate-chosen-new-id")
        self.assertEqual(list(self.fixture.store.directory.glob("*.json")), before)

    def test_non_pass_does_not_consume_operation_authority(self):
        operation_id = str(uuid4())
        contract_id = self.fixture.freeze(operation_id)
        session = self.fixture.gate.open_session(
            contract_id,
            self.fixture.task,
            verifier_bindings=(
                VerifierBinding("host-check", "1", lambda: VerifierResult("BLOCKED", b"blocked")),
            ),
            effect_binding=EffectBinding("publish", "1", lambda: self.fixture.effects.append("bad")),
            state_probe=lambda: self.fixture.state,
        )
        session.execute("required")
        with self.assertRaisesRegex(NARFError, "authenticated PASS required"):
            self.fixture.executor.execute(session)
        self.assertFalse(self.fixture.authority.is_reserved(operation_id))
        self.assertEqual(self.fixture.effects, [])


if __name__ == "__main__":
    unittest.main()
