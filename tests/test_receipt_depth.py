import json
import unittest

from narf import NARFError
from test_gate import Fixture


class ReceiptDepthTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()

    def tearDown(self):
        self.fixture.tmp.cleanup()

    def corrupt(self, receipt_id, shape="array"):
        depth = 20_000
        if shape == "array":
            nested = b"[" * depth + b"0" + b"]" * depth
        else:
            nested = b'{"x":' * depth + b"0" + b"}" * depth
        raw = b'{"payload":' + nested + b',"mac":"bad"}'
        self.assertLess(len(raw), 1_048_576)
        (self.fixture.store.directory / (receipt_id + ".json")).write_bytes(raw)

    def completed_session(self):
        session = self.fixture.session()
        evidence = [session.execute(r.requirement_id) for r in self.fixture.requirements]
        decision = session.finalize()
        self.assertEqual(decision["result"], "PASS")
        return session, evidence, decision

    def test_direct_load_rejects_deep_array_and_object(self):
        for shape in ("array", "object"):
            with self.subTest(shape=shape):
                self.corrupt(self.fixture.contract_id, shape)
                self.assertIsNone(self.fixture.store.load(self.fixture.contract_id))

    def test_deep_contract_blocks_verdict_and_effect(self):
        session, _, _ = self.completed_session()
        self.corrupt(self.fixture.contract_id)
        verdict = session.verdict()
        self.assertEqual((verdict["result"], verdict["reason"]), ("BLOCKED", "CONTRACT_INVALID"))
        with self.assertRaises(NARFError):
            session.execute_effect()
        self.assertEqual(self.fixture.effects, [])

    def test_deep_verification_blocks_verdict_and_effect(self):
        session, evidence, _ = self.completed_session()
        self.corrupt(evidence[0]["evidence_id"], "object")
        verdict = session.verdict()
        self.assertEqual((verdict["result"], verdict["reason"]), ("BLOCKED", "INVALID_EVIDENCE"))
        with self.assertRaises(NARFError):
            session.execute_effect()
        self.assertEqual(self.fixture.effects, [])

    def test_deep_decision_blocks_finalization_and_effect(self):
        session, _, decision = self.completed_session()
        self.corrupt(decision["decision_id"])
        # Verifier evidence remains valid; the damaged decision cannot authorize an effect.
        self.assertEqual(session.verdict()["result"], "PASS")
        with self.assertRaises(NARFError):
            session.finalize()
        with self.assertRaises(NARFError):
            session.execute_effect()
        self.assertEqual(self.fixture.effects, [])

    def test_deep_consumption_receipt_rejects_load_and_preserves_replay_denial(self):
        session, _, _ = self.completed_session()
        session.execute_effect()
        consumed = next(
            p.stem for p in self.fixture.store.directory.glob("*.json")
            if json.loads(p.read_bytes())["payload"]["evidence"]["evidence_type"] == "narf.effect"
        )
        self.corrupt(consumed, "object")
        self.assertIsNone(self.fixture.store.load(consumed))
        replay, _, _ = self.completed_session()
        with self.assertRaisesRegex(NARFError, "already consumed"):
            replay.execute_effect()
        self.assertEqual(self.fixture.effects, ["published"])
