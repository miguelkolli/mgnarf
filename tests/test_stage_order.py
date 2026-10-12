from pathlib import Path
import json
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

    def reauthenticate_receipt(self, run_id, mutate):
        path = self.store.directory / f"{run_id}.json"
        envelope = json.loads(path.read_text())
        mutate(envelope["payload"]["evidence"])
        envelope["mac"] = self.store._mac(envelope["payload"])
        path.write_text(json.dumps(envelope))


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

    def test_verification_receipts_bind_seed_stage_and_authenticated_predecessor(self):
        contract_id = self.fx.freeze()
        session = self.fx.session(contract_id)
        first = session.execute("tests")
        second = session.execute("security")
        first_receipt = self.fx.store.load(first["evidence_id"])
        second_receipt = self.fx.store.load(second["evidence_id"])

        self.assertEqual(first_receipt["stage_index"], 0)
        self.assertIsNone(first_receipt["predecessor_evidence_id"])
        self.assertIsNone(first_receipt["predecessor_evidence_sha256"])
        self.assertEqual(second_receipt["stage_index"], 1)
        self.assertEqual(second_receipt["predecessor_evidence_id"], first["evidence_id"])
        self.assertEqual(
            second_receipt["predecessor_evidence_sha256"],
            canonical_json_digest(first_receipt),
        )
        self.assertEqual(first_receipt["chain_seed_sha256"], second_receipt["chain_seed_sha256"])

    def test_authenticated_predecessor_change_breaks_dependent_chain(self):
        contract_id = self.fx.freeze()
        session = self.fx.session(contract_id)
        first = session.execute("tests")
        session.execute("security")
        session.execute("approval")

        self.fx.reauthenticate_receipt(
            first["evidence_id"],
            lambda evidence: evidence.__setitem__("artifact_sha256", "0" * 64),
        )
        verdict = session.verdict()
        self.assertEqual(verdict["result"], "BLOCKED")
        self.assertEqual(verdict["reason"], "INVALID_EVIDENCE")

    def test_authenticated_dependent_predecessor_digest_tamper_is_blocked(self):
        contract_id = self.fx.freeze()
        session = self.fx.session(contract_id)
        session.execute("tests")
        second = session.execute("security")
        session.execute("approval")

        self.fx.reauthenticate_receipt(
            second["evidence_id"],
            lambda evidence: evidence.__setitem__("predecessor_evidence_sha256", "0" * 64),
        )
        verdict = session.verdict()
        self.assertEqual(verdict["result"], "BLOCKED")
        self.assertEqual(verdict["reason"], "INVALID_EVIDENCE")

    def test_decision_binds_final_chain_head(self):
        contract_id = self.fx.freeze()
        session = self.fx.session(contract_id)
        last = None
        for requirement_id in self.fx.stage_order:
            last = session.execute(requirement_id)
        decision = session.finalize()
        receipt = self.fx.store.load(decision["decision_id"])
        final_receipt = self.fx.store.load(last["evidence_id"])
        self.assertEqual(receipt["chain_head_evidence_id"], last["evidence_id"])
        self.assertEqual(receipt["chain_head_evidence_sha256"], canonical_json_digest(final_receipt))

        self.fx.reauthenticate_receipt(
            decision["decision_id"],
            lambda evidence: evidence.__setitem__("chain_head_evidence_sha256", "0" * 64),
        )
        with self.assertRaises(NARFError):
            session.execute_effect()

    def test_chain_seed_is_session_bound(self):
        contract_id = self.fx.freeze()
        first_session = self.fx.session(contract_id)
        second_session = self.fx.session(contract_id)
        first = first_session.execute("tests")
        second = second_session.execute("tests")
        first_receipt = self.fx.store.load(first["evidence_id"])
        second_receipt = self.fx.store.load(second["evidence_id"])
        self.assertNotEqual(first_receipt["session_id"], second_receipt["session_id"])
        self.assertNotEqual(first_receipt["chain_seed_sha256"], second_receipt["chain_seed_sha256"])

    def test_failed_predecessor_blocks_later_producer_entry(self):
        contract_id = self.fx.freeze()
        bindings = [
            VerifierBinding("check-a", "1", self.fx.producer("tests", "FAIL")),
            VerifierBinding("check-b", "1", self.fx.producer("security")),
            VerifierBinding("approve", "1", self.fx.producer("approval")),
        ]
        session = self.fx.session(contract_id, bindings=bindings)
        self.assertEqual(session.execute("tests")["status"], "FAIL")
        with self.assertRaises(NARFError):
            session.execute("security")
        self.assertEqual(self.fx.calls, ["tests"])

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

    def test_a_b_race_never_enters_b_before_a_receipt_is_chain_head(self):
        contract_id = self.fx.freeze()
        entered = threading.Event()
        release = threading.Event()
        observed = []

        def slow_first():
            observed.append("tests-enter")
            entered.set()
            release.wait(timeout=2)
            observed.append("tests-exit")
            return VerifierResult("PASS", b"tests")

        def second():
            observed.append("security-enter")
            return VerifierResult("PASS", b"security")

        bindings = [
            VerifierBinding("check-a", "1", slow_first),
            VerifierBinding("check-b", "1", second),
            VerifierBinding("approve", "1", self.fx.producer("approval")),
        ]
        session = self.fx.session(contract_id, bindings=bindings)
        errors = []

        def invoke(requirement_id):
            try:
                session.execute(requirement_id)
            except Exception as error:
                errors.append(type(error).__name__)

        a = threading.Thread(target=invoke, args=("tests",))
        b = threading.Thread(target=invoke, args=("security",))
        a.start()
        entered.wait(timeout=2)
        b.start()
        release.set()
        a.join(timeout=2)
        b.join(timeout=2)

        self.assertEqual(errors, [])
        self.assertEqual(observed, ["tests-enter", "tests-exit", "security-enter"])


if __name__ == "__main__":
    unittest.main()
