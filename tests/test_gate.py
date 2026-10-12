import json
from pathlib import Path
import tempfile
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
    sha256_bytes,
)


class Fixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="narf-test-")
        self.root = Path(self.tmp.name)
        self.store = ReceiptStore(self.root / "receipts", b"k" * 32)
        self.gate = NARFGate(self.store)
        self.task = {"description": "bounded change", "project": "fixture"}
        self.state = FrozenState(
            candidate_sha256=sha256_bytes(b"candidate-v1"),
            requirements_sha256=sha256_bytes(b"requirements-v1"),
            policy_sha256=sha256_bytes(b"policy-v1"),
        )
        self.current = self.state
        self.revoked = False
        self.effects = []
        self.requirements = (
            Requirement("unit", "host-tests", "1"),
            Requirement("policy", "policy-check", "1"),
        )
        self.contract_id = self.gate.freeze_contract(
            self.task,
            task_id="narf-test",
            requirements=self.requirements,
            effect_id="publish",
            effect_version="1",
            state=self.state,
        )

    def state_probe(self):
        return self.current

    def revocation_probe(self, _contract_id, _candidate_sha256):
        return self.revoked

    def bindings(self, statuses=("PASS", "PASS")):
        out = []
        for requirement, status in zip(self.requirements, statuses):
            def produce(selected=status, name=requirement.requirement_id):
                return VerifierResult(selected, ("artifact:" + name).encode())
            out.append(VerifierBinding(requirement.verifier_id, requirement.verifier_version, produce))
        return out

    def effect(self):
        def execute():
            self.effects.append("published")
            return "published"
        return EffectBinding("publish", "1", execute)

    def session(self, *, task=None, bindings=None, statuses=("PASS", "PASS")):
        return self.gate.open_session(
            self.contract_id,
            self.task if task is None else task,
            verifier_bindings=self.bindings(statuses) if bindings is None else bindings,
            effect_binding=self.effect(),
            state_probe=self.state_probe,
            revocation_probe=self.revocation_probe,
        )

    def close(self):
        self.tmp.cleanup()


class NARFGateTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()
        self.addCleanup(self.fixture.close)

    def execute_all(self, session):
        return [session.execute(item) for item in session.requirements()]

    def test_happy_path_passes_and_effect_is_single_use(self):
        session = self.fixture.session()
        self.execute_all(session)
        self.assertEqual(session.verdict()["result"], "PASS")
        self.assertEqual(session.verdict()["coverage"], "2/2")
        self.assertEqual(session.finalize()["result"], "PASS")
        self.assertEqual(session.execute_effect(), "published")
        self.assertEqual(self.fixture.effects, ["published"])
        with self.assertRaises(NARFError):
            session.execute_effect()

    def test_missing_evidence_is_blocked(self):
        session = self.fixture.session()
        session.execute("unit")
        self.assertEqual(session.verdict()["result"], "BLOCKED")
        self.assertEqual(session.verdict()["reason"], "INCOMPLETE_EVIDENCE")

    def test_fail_and_blocked_verifier_outcomes_are_preserved(self):
        for status, expected in (("FAIL", "FAIL"), ("BLOCKED", "BLOCKED")):
            fixture = Fixture()
            self.addCleanup(fixture.close)
            session = fixture.session(statuses=(status, "PASS"))
            self.execute_all(session)
            self.assertEqual(session.verdict()["result"], expected)

    def test_changed_task_is_blocked(self):
        wrong = dict(self.fixture.task, description="changed")
        session = self.fixture.session(task=wrong)
        self.assertEqual(session.verdict()["result"], "BLOCKED")
        self.assertEqual(session.verdict()["reason"], "TASK_CHANGED")

    def test_missing_or_wrong_verifier_binding_is_blocked(self):
        missing = self.fixture.session(bindings=self.fixture.bindings()[:1])
        self.assertEqual(missing.verdict()["reason"], "VERIFIER_UNAVAILABLE")
        wrong = self.fixture.bindings()
        wrong[0] = VerifierBinding("host-tests", "2", wrong[0].producer)
        session = self.fixture.session(bindings=wrong)
        self.assertEqual(session.verdict()["reason"], "VERIFIER_VERSION_CHANGED")

    def test_candidate_change_is_blocked(self):
        session = self.fixture.session()
        self.fixture.current = FrozenState(
            sha256_bytes(b"candidate-v2"),
            self.fixture.state.requirements_sha256,
            self.fixture.state.policy_sha256,
        )
        self.assertEqual(session.verdict()["reason"], "CANDIDATE_CHANGED")

    def test_goalpost_change_is_blocked(self):
        session = self.fixture.session()
        self.fixture.current = FrozenState(
            self.fixture.state.candidate_sha256,
            sha256_bytes(b"requirements-v2"),
            self.fixture.state.policy_sha256,
        )
        self.assertEqual(session.verdict()["reason"], "GOALPOST_CHANGED")

    def test_policy_change_is_blocked(self):
        session = self.fixture.session()
        self.fixture.current = FrozenState(
            self.fixture.state.candidate_sha256,
            self.fixture.state.requirements_sha256,
            sha256_bytes(b"policy-v2"),
        )
        self.assertEqual(session.verdict()["reason"], "POLICY_CHANGED")

    def test_inhibitor_blocks_even_when_verifiers_pass(self):
        session = self.fixture.session()
        self.execute_all(session)
        session.inhibit("authority_missing")
        self.assertEqual(session.finalize()["result"], "BLOCKED")

    def test_inhibitor_after_pass_invalidates_effect(self):
        session = self.fixture.session()
        self.execute_all(session)
        self.assertEqual(session.finalize()["result"], "PASS")
        session.inhibit("human_stop")
        with self.assertRaisesRegex(NARFError, "invalid or stale"):
            session.execute_effect()
        self.assertEqual(self.fixture.effects, [])

    def test_revocation_blocks_and_fails_closed_on_probe_error(self):
        self.fixture.revoked = True
        session = self.fixture.session()
        self.assertEqual(session.verdict()["reason"], "REVOKED")

        fixture = Fixture()
        self.addCleanup(fixture.close)

        def broken_probe(_contract_id, _candidate):
            raise RuntimeError("probe unavailable")

        session = fixture.gate.open_session(
            fixture.contract_id,
            fixture.task,
            verifier_bindings=fixture.bindings(),
            effect_binding=fixture.effect(),
            state_probe=fixture.state_probe,
            revocation_probe=broken_probe,
        )
        self.assertEqual(session.verdict()["reason"], "REVOKED")

    def test_non_boolean_revocation_probe_fails_closed(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)

        def unavailable_probe(_contract_id, _candidate):
            return None

        session = fixture.gate.open_session(
            fixture.contract_id,
            fixture.task,
            verifier_bindings=fixture.bindings(),
            effect_binding=fixture.effect(),
            state_probe=fixture.state_probe,
            revocation_probe=unavailable_probe,
        )
        self.assertEqual(session.verdict()["result"], "BLOCKED")
        self.assertEqual(session.verdict()["reason"], "REVOKED")

    def test_tampered_verification_receipt_is_rejected(self):
        session = self.fixture.session()
        first = session.execute("unit")
        path = self.fixture.store.directory / f"{first['evidence_id']}.json"
        envelope = json.loads(path.read_text())
        envelope["payload"]["evidence"]["task_id"] = "wrong-task"
        path.write_text(json.dumps(envelope))
        session.execute("policy")
        self.assertEqual(session.verdict()["result"], "BLOCKED")
        self.assertEqual(session.verdict()["reason"], "INVALID_EVIDENCE")

    def test_state_change_after_pass_blocks_effect(self):
        session = self.fixture.session()
        self.execute_all(session)
        self.assertEqual(session.finalize()["result"], "PASS")
        self.fixture.current = FrozenState(
            sha256_bytes(b"candidate-v2"),
            self.fixture.state.requirements_sha256,
            self.fixture.state.policy_sha256,
        )
        with self.assertRaises(NARFError):
            session.execute_effect()

    def test_revocation_after_pass_blocks_effect(self):
        session = self.fixture.session()
        self.execute_all(session)
        self.assertEqual(session.finalize()["result"], "PASS")
        self.fixture.revoked = True
        with self.assertRaises(NARFError):
            session.execute_effect()

    def test_tampered_decision_blocks_effect(self):
        session = self.fixture.session()
        self.execute_all(session)
        decision = session.finalize()
        path = self.fixture.store.directory / f"{decision['decision_id']}.json"
        envelope = json.loads(path.read_text())
        envelope["payload"]["evidence"]["result"] = "FAIL"
        path.write_text(json.dumps(envelope))
        with self.assertRaises(NARFError):
            session.execute_effect()

    def test_effect_replay_is_blocked_across_sessions(self):
        first = self.fixture.session()
        self.execute_all(first)
        first.finalize()
        self.assertEqual(first.execute_effect(), "published")

        second = self.fixture.session()
        self.execute_all(second)
        second.finalize()
        with self.assertRaises(NARFError):
            second.execute_effect()

    def test_invalid_verifier_result_fails_closed(self):
        bindings = self.fixture.bindings()
        bindings[0] = VerifierBinding("host-tests", "1", lambda: "PASS")
        session = self.fixture.session(bindings=bindings)
        self.assertEqual(session.execute("unit")["status"], "BLOCKED")
        session.execute("policy")
        self.assertEqual(session.verdict()["result"], "BLOCKED")

    def test_duplicate_requirement_execution_is_rejected(self):
        session = self.fixture.session()
        session.execute("unit")
        with self.assertRaises(NARFError):
            session.execute("unit")


if __name__ == "__main__":
    unittest.main()
