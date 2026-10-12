from pathlib import Path
import tempfile
import threading
import unittest

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


class StageOrderFixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="narf-stage-order-")
        self.root = Path(self.tmp.name)
        self.store = ReceiptStore(self.root / "receipts", b"s" * 32)
        self.gate = NARFGate(self.store)
        self.task = {"description": "ordered verification chain", "project": "mgnarf"}
        self.state = FrozenState(
            candidate_sha256=sha256_bytes(b"stage-order-candidate"),
            requirements_sha256=sha256_bytes(b"stage-order-requirements"),
            policy_sha256=sha256_bytes(b"stage-order-policy"),
        )
        self.current = self.state
        self.calls = []
        self.effects = []
        self.requirements = (
            Requirement("tests", "check-a", "1"),
            Requirement("security", "check-b", "1"),
            Requirement("approval", "approve", "1"),
        )
        self.stage_order = ["tests", "security", "approval"]

    def close(self):
        self.tmp.cleanup()

    def state_probe(self):
        return self.current

    def producer(self, name, status="PASS"):
        def run():
            self.calls.append(name)
            return VerifierResult(status, ("artifact:" + name).encode())
        return run

    def bindings(self):
        return [
            VerifierBinding("check-a", "1", self.producer("tests")),
            VerifierBinding("check-b", "1", self.producer("security")),
            VerifierBinding("approve", "1", self.producer("approval")),
        ]

    def effect(self):
        def run():
            self.effects.append("published")
            return "published"
        return EffectBinding("publish", "1", run)

    def freeze(self, *, order=None, requirements=None, identity_policy=None):
        return self.gate.freeze_contract(
            self.task,
            task_id="stage-order",
            requirements=self.requirements if requirements is None else requirements,
            effect_id="publish",
            effect_version="1",
            state=self.state,
            identity_policy=identity_policy,
            stage_order=self.stage_order if order is None else order,
        )

    def session(self, contract_id, *, bindings=None, identity_probe=None):
        return self.gate.open_session(
            contract_id,
            self.task,
            verifier_bindings=self.bindings() if bindings is None else bindings,
            effect_binding=self.effect(),
            state_probe=self.state_probe,
            identity_probe=identity_probe,
        )


class StageOrderTests(unittest.TestCase):
    def setUp(self):
        self.fx = StageOrderFixture()
        self.addCleanup(self.fx.close)

    def test_contract_freezes_exact_requirement_order(self):
        contract_id = self.fx.freeze()
        contract = self.fx.store.load(contract_id)
        self.assertEqual(contract["stage_order"], self.fx.stage_order)
        self.assertEqual(contract["stage_order_sha256"], canonical_json_digest(self.fx.stage_order))
        self.assertGreaterEqual(contract["evidence_version"], 3)

    def test_stage_order_must_be_exact_requirement_permutation(self):
        invalid_orders = (
            ["tests", "security"],
            ["tests", "security", "security"],
            ["tests", "security", "approval", "extra"],
        )
        for order in invalid_orders:
            with self.subTest(order=order):
                with self.assertRaises(NARFError):
                    self.fx.freeze(order=order)

    def test_future_stage_is_rejected_before_producer_and_valid_retry_can_follow(self):
        contract_id = self.fx.freeze()
        session = self.fx.session(contract_id)

        with self.assertRaises(NARFError):
            session.execute("security")
        self.assertEqual(self.fx.calls, [])

        self.assertEqual(session.execute("tests")["status"], "PASS")
        self.assertEqual(session.execute("security")["status"], "PASS")
        self.assertEqual(session.execute("approval")["status"], "PASS")
        self.assertEqual(self.fx.calls, ["tests", "security", "approval"])
        self.assertEqual(session.finalize()["result"], "PASS")
        self.assertEqual(session.execute_effect(), "published")

    def test_order_uses_requirement_id_even_when_verifier_id_is_shared(self):
        requirements = (
            Requirement("lint", "ci", "1"),
            Requirement("unit", "ci", "1"),
        )
        contract_id = self.fx.gate.freeze_contract(
            self.fx.task,
            task_id="shared-verifier-stage-order",
            requirements=requirements,
            effect_id="publish",
            effect_version="1",
            state=self.fx.state,
            stage_order=["lint", "unit"],
        )
        shared = VerifierBinding("ci", "1", self.fx.producer("ci"))
        session = self.fx.gate.open_session(
            contract_id,
            self.fx.task,
            verifier_bindings=[shared],
            effect_binding=self.fx.effect(),
            state_probe=self.fx.state_probe,
        )
        with self.assertRaises(NARFError):
            session.execute("unit")
        session.execute("lint")
        session.execute("unit")
        self.assertEqual(session.finalize()["result"], "PASS")

    def test_identity_separation_and_order_are_both_required(self):
        actors = {
            "builder": {"principal_id": "agent:builder", "trust_domain": "builder"},
            "verifier:check-a": {"principal_id": "agent:a", "trust_domain": "ci"},
            "verifier:check-b": {"principal_id": "agent:b", "trust_domain": "review"},
            "authority": {"principal_id": "human:approver", "trust_domain": "human"},
        }
        policy = {
            "actors": actors,
            "separation": [
                ["builder", "verifier:check-b", "principal_id"],
                ["verifier:check-a", "verifier:check-b", "principal_id"],
                ["verifier:check-b", "authority", "principal_id"],
            ],
            "authority_verifier_id": "approve",
        }
        bindings = [
            VerifierBinding("check-a", "1", self.fx.producer("tests"), principal_id="agent:a", trust_domain="ci"),
            VerifierBinding("check-b", "1", self.fx.producer("security"), principal_id="agent:b", trust_domain="review"),
            VerifierBinding("approve", "1", self.fx.producer("approval"), principal_id="human:approver", trust_domain="human"),
        ]
        contract_id = self.fx.freeze(identity_policy=policy)
        session = self.fx.session(contract_id, bindings=bindings, identity_probe=lambda: actors)
        with self.assertRaises(NARFError):
            session.execute("approval")
        for requirement_id in self.fx.stage_order:
            session.execute(requirement_id)
        self.assertEqual(session.finalize()["result"], "PASS")

    def test_concurrent_same_stage_invokes_at_most_one_producer(self):
        contract_id = self.fx.freeze()
        entered = threading.Event()
        release = threading.Event()
        calls = []

        def slow_first():
            calls.append("tests")
            entered.set()
            release.wait(timeout=2)
            return VerifierResult("PASS", b"tests")

        bindings = [
            VerifierBinding("check-a", "1", slow_first),
            VerifierBinding("check-b", "1", self.fx.producer("security")),
            VerifierBinding("approve", "1", self.fx.producer("approval")),
        ]
        session = self.fx.session(contract_id, bindings=bindings)
        errors = []

        def invoke():
            try:
                session.execute("tests")
            except Exception as error:
                errors.append(type(error).__name__)

        first = threading.Thread(target=invoke)
        second = threading.Thread(target=invoke)
        first.start()
        entered.wait(timeout=2)
        second.start()
        release.set()
        first.join(timeout=2)
        second.join(timeout=2)

        self.assertEqual(calls, ["tests"])
        self.assertEqual(len(errors), 1)
        self.assertIn("NARFError", errors)


if __name__ == "__main__":
    unittest.main()
