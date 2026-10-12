"""Independent adversarial coverage for the stage-order design freeze.

This file is intentionally test-only. It exercises Revision 3 cases that were
not explicit in the implementation PR's first acceptance set. No runtime code
is modified by this review branch.
"""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import threading
import unittest

from narf import (
    AuthorityRevisionGate,
    AuthoritySnapshot,
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


class MutableAuthority:
    def __init__(self, actors):
        self.revision = 1
        self.actors = deepcopy(actors)

    def __call__(self):
        return AuthoritySnapshot(self.revision, deepcopy(self.actors))


class ReviewFixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="narf-stage-order-review-")
        self.root = Path(self.tmp.name)
        self.store = ReceiptStore(self.root / "receipts", b"v" * 32)
        self.gate = NARFGate(self.store)
        self.task = {"description": "independent ordered-chain review"}
        self.state = FrozenState(
            sha256_bytes(b"candidate-a"),
            sha256_bytes(b"requirements-a"),
            sha256_bytes(b"policy-a"),
        )
        self.requirements = (
            Requirement("tests", "check-a", "1"),
            Requirement("security", "check-b", "1"),
            Requirement("approval", "approve", "1"),
        )
        self.order = ["tests", "security", "approval"]
        self.calls = []
        self.effects = []

    def close(self):
        self.tmp.cleanup()

    def producer(self, label, status="PASS"):
        def run():
            self.calls.append(label)
            return VerifierResult(status, ("artifact:" + label).encode())
        return run

    def bindings(self, *, first_status="PASS"):
        return [
            VerifierBinding("check-a", "1", self.producer("tests", first_status)),
            VerifierBinding("check-b", "1", self.producer("security")),
            VerifierBinding("approve", "1", self.producer("approval")),
        ]

    def effect(self):
        def run():
            self.effects.append("published")
            return "published"
        return EffectBinding("publish", "1", run)

    def freeze(self, *, state=None, order=None, identity_policy=None):
        return self.gate.freeze_contract(
            self.task,
            task_id="stage-order-review",
            requirements=self.requirements,
            effect_id="publish",
            effect_version="1",
            state=self.state if state is None else state,
            identity_policy=identity_policy,
            stage_order=self.order if order is None else order,
        )

    def open(self, contract_id, *, state=None, order_bindings=None, identity_probe=None):
        current = self.state if state is None else state
        return self.gate.open_session(
            contract_id,
            self.task,
            verifier_bindings=self.bindings() if order_bindings is None else order_bindings,
            effect_binding=self.effect(),
            state_probe=lambda: current,
            identity_probe=identity_probe,
        )

    def reauthenticate(self, run_id, mutate):
        path = self.store.directory / f"{run_id}.json"
        envelope = json.loads(path.read_text())
        mutate(envelope["payload"]["evidence"])
        envelope["mac"] = self.store._mac(envelope["payload"])
        path.write_text(json.dumps(envelope))

    def complete(self, session):
        rows = []
        for requirement_id in self.order:
            rows.append(session.execute(requirement_id))
        return rows


class StageOrderIndependentCoverageTests(unittest.TestCase):
    def setUp(self):
        self.fx = ReviewFixture()
        self.addCleanup(self.fx.close)

    def test_cross_session_predecessor_replay_is_blocked(self):
        contract_id = self.fx.freeze()
        source = self.fx.open(contract_id)
        target = self.fx.open(contract_id)
        source_a = source.execute("tests")
        target_a = target.execute("tests")
        target_b = target.execute("security")
        target.execute("approval")
        source_a_receipt = self.fx.store.load(source_a["evidence_id"])

        self.fx.reauthenticate(
            target_b["evidence_id"],
            lambda evidence: evidence.update(
                predecessor_evidence_id=source_a["evidence_id"],
                predecessor_evidence_sha256=canonical_json_digest(source_a_receipt),
            ),
        )
        verdict = target.verdict()
        self.assertEqual(verdict["result"], "BLOCKED")
        self.assertEqual(verdict["reason"], "INVALID_EVIDENCE")
        self.assertNotEqual(source_a["evidence_id"], target_a["evidence_id"])

    def test_cross_contract_predecessor_replay_is_blocked(self):
        source_contract = self.fx.freeze()
        target_contract = self.fx.freeze()
        source = self.fx.open(source_contract)
        target = self.fx.open(target_contract)
        source_a = source.execute("tests")
        target.execute("tests")
        target_b = target.execute("security")
        target.execute("approval")
        source_receipt = self.fx.store.load(source_a["evidence_id"])

        self.fx.reauthenticate(
            target_b["evidence_id"],
            lambda evidence: evidence.update(
                predecessor_evidence_id=source_a["evidence_id"],
                predecessor_evidence_sha256=canonical_json_digest(source_receipt),
            ),
        )
        self.assertEqual(target.verdict()["result"], "BLOCKED")

    def test_cross_candidate_predecessor_replay_is_blocked(self):
        other_state = FrozenState(
            sha256_bytes(b"candidate-b"),
            self.fx.state.requirements_sha256,
            self.fx.state.policy_sha256,
        )
        source_contract = self.fx.freeze(state=other_state)
        target_contract = self.fx.freeze()
        source = self.fx.open(source_contract, state=other_state)
        target = self.fx.open(target_contract)
        source_a = source.execute("tests")
        target.execute("tests")
        target_b = target.execute("security")
        target.execute("approval")
        source_receipt = self.fx.store.load(source_a["evidence_id"])

        self.fx.reauthenticate(
            target_b["evidence_id"],
            lambda evidence: evidence.update(
                predecessor_evidence_id=source_a["evidence_id"],
                predecessor_evidence_sha256=canonical_json_digest(source_receipt),
            ),
        )
        self.assertEqual(target.verdict()["result"], "BLOCKED")

    def test_cross_order_policy_predecessor_replay_is_blocked(self):
        alternate_order = ["tests", "approval", "security"]
        source_contract = self.fx.freeze(order=alternate_order)
        target_contract = self.fx.freeze()
        source = self.fx.open(source_contract)
        target = self.fx.open(target_contract)
        source_a = source.execute("tests")
        target.execute("tests")
        target_b = target.execute("security")
        target.execute("approval")
        source_receipt = self.fx.store.load(source_a["evidence_id"])

        self.fx.reauthenticate(
            target_b["evidence_id"],
            lambda evidence: evidence.update(
                predecessor_evidence_id=source_a["evidence_id"],
                predecessor_evidence_sha256=canonical_json_digest(source_receipt),
            ),
        )
        self.assertEqual(target.verdict()["result"], "BLOCKED")

    def test_blocked_predecessor_cannot_enter_next_producer(self):
        contract_id = self.fx.freeze()
        session = self.fx.open(contract_id, order_bindings=self.fx.bindings(first_status="BLOCKED"))
        self.assertEqual(session.execute("tests")["status"], "BLOCKED")
        with self.assertRaises(NARFError):
            session.execute("security")
        self.assertEqual(self.fx.calls, ["tests"])

    def test_v3_identity_separation_violation_blocks_before_producer(self):
        actors = {
            "builder": {"principal_id": "agent:same", "trust_domain": "builder"},
            "verifier:check-a": {"principal_id": "agent:same", "trust_domain": "ci"},
            "verifier:check-b": {"principal_id": "agent:b", "trust_domain": "review"},
            "authority": {"principal_id": "human:approver", "trust_domain": "human"},
        }
        policy = {
            "actors": actors,
            "separation": [["builder", "verifier:check-a", "principal_id"]],
            "authority_verifier_id": "approve",
        }
        bindings = [
            VerifierBinding("check-a", "1", self.fx.producer("tests"), principal_id="agent:same", trust_domain="ci"),
            VerifierBinding("check-b", "1", self.fx.producer("security"), principal_id="agent:b", trust_domain="review"),
            VerifierBinding("approve", "1", self.fx.producer("approval"), principal_id="human:approver", trust_domain="human"),
        ]
        contract_id = self.fx.freeze(identity_policy=policy)
        session = self.fx.open(
            contract_id,
            order_bindings=bindings,
            identity_probe=lambda: deepcopy(actors),
        )
        with self.assertRaises(NARFError):
            session.execute("tests")
        self.assertEqual(self.fx.calls, [])

    def test_ordered_authority_revision_drift_after_partial_chain_blocks(self):
        actors = {
            "builder": {"principal_id": "agent:builder", "trust_domain": "builder"},
            "verifier:check-a": {"principal_id": "agent:a", "trust_domain": "ci"},
            "verifier:check-b": {"principal_id": "agent:b", "trust_domain": "review"},
            "authority": {"principal_id": "human:approver", "trust_domain": "human"},
        }
        policy = {
            "actors": actors,
            "separation": [["verifier:check-a", "verifier:check-b", "principal_id"]],
            "authority_verifier_id": "approve",
        }
        authority = MutableAuthority(actors)
        gate = AuthorityRevisionGate(self.fx.store, authority)
        contract_id = gate.freeze_contract(
            self.fx.task,
            task_id="ordered-authority-drift",
            requirements=self.fx.requirements,
            effect_id="publish",
            effect_version="1",
            state=self.fx.state,
            identity_policy=policy,
            stage_order=self.fx.order,
        )
        bindings = [
            VerifierBinding("check-a", "1", self.fx.producer("tests"), principal_id="agent:a", trust_domain="ci"),
            VerifierBinding("check-b", "1", self.fx.producer("security"), principal_id="agent:b", trust_domain="review"),
            VerifierBinding("approve", "1", self.fx.producer("approval"), principal_id="human:approver", trust_domain="human"),
        ]
        session = gate.open_session(
            contract_id,
            self.fx.task,
            verifier_bindings=bindings,
            effect_binding=self.fx.effect(),
            state_probe=lambda: self.fx.state,
        )
        self.assertEqual(session.execute("tests")["status"], "PASS")
        authority.revision += 1
        with self.assertRaises(NARFError):
            session.execute("security")
        self.assertEqual(self.fx.calls, ["tests"])

    def test_concurrent_future_stage_probes_never_enter_producer(self):
        contract_id = self.fx.freeze()
        session = self.fx.open(contract_id)
        errors = []

        def probe():
            try:
                session.execute("security")
            except Exception as error:
                errors.append(type(error).__name__)

        threads = [threading.Thread(target=probe) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)

        self.assertEqual(len(errors), 12)
        self.assertEqual(set(errors), {"NARFError"})
        self.assertEqual(self.fx.calls, [])
        self.assertEqual(session.execute("tests")["status"], "PASS")

    def test_foreign_session_chain_seed_cannot_replace_first_stage_seed(self):
        contract_id = self.fx.freeze()
        source = self.fx.open(contract_id)
        target = self.fx.open(contract_id)
        source_first = source.execute("tests")
        source_seed = self.fx.store.load(source_first["evidence_id"])["chain_seed_sha256"]
        rows = self.fx.complete(target)
        target_first = rows[0]

        self.fx.reauthenticate(
            target_first["evidence_id"],
            lambda evidence: evidence.__setitem__("chain_seed_sha256", source_seed),
        )
        verdict = target.verdict()
        self.assertEqual(verdict["result"], "BLOCKED")
        self.assertEqual(verdict["reason"], "INVALID_EVIDENCE")

    def test_non_final_chain_head_cannot_authorize_effect(self):
        contract_id = self.fx.freeze()
        session = self.fx.open(contract_id)
        rows = self.fx.complete(session)
        decision = session.finalize()
        first_receipt = self.fx.store.load(rows[0]["evidence_id"])

        self.fx.reauthenticate(
            decision["decision_id"],
            lambda evidence: evidence.update(
                chain_head_evidence_id=rows[0]["evidence_id"],
                chain_head_evidence_sha256=canonical_json_digest(first_receipt),
            ),
        )
        with self.assertRaises(NARFError):
            session.execute_effect()
        self.assertEqual(self.fx.effects, [])

    def test_ordered_v3_effect_is_single_use(self):
        contract_id = self.fx.freeze()
        session = self.fx.open(contract_id)
        self.fx.complete(session)
        self.assertEqual(session.finalize()["result"], "PASS")
        self.assertEqual(session.execute_effect(), "published")
        with self.assertRaises(NARFError):
            session.execute_effect()
        self.assertEqual(self.fx.effects, ["published"])

    def test_old_future_stage_evidence_cannot_make_late_predecessor_valid(self):
        source_contract = self.fx.freeze()
        source = self.fx.open(source_contract)
        source.execute("tests")
        old_b = source.execute("security")
        old_b_receipt = self.fx.store.load(old_b["evidence_id"])
        self.fx.reauthenticate(
            old_b["evidence_id"],
            lambda evidence: evidence.__setitem__("timestamp", 0),
        )

        target_contract = self.fx.freeze()
        target = self.fx.open(target_contract)
        # Simulate pre-existing/fabricated future-stage evidence in host session
        # state. There is intentionally no public evidence-submission API.
        target._NARFSession__runs["security"] = old_b["evidence_id"]
        with self.assertRaises(NARFError):
            target.execute("tests")
        verdict = target.verdict()
        self.assertEqual(verdict["result"], "BLOCKED")
        self.assertNotEqual(old_b_receipt.get("session_id"), target.session_id)


if __name__ == "__main__":
    unittest.main()
