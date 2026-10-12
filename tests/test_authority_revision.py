"""Adversarial tests for monotonic authority-revision identity binding."""

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from narf import (
    AuthorityRevisionGate,
    AuthoritySnapshot,
    EffectBinding,
    FrozenState,
    NARFError,
    ReceiptStore,
    Requirement,
    VerifierBinding,
    VerifierResult,
    sha256_bytes,
)


class MutableAuthority:
    def __init__(self, actors):
        self.revision = 1
        self.actors = deepcopy(actors)
        self.calls = 0
        self.bump_on_call = None

    def __call__(self):
        self.calls += 1
        if self.bump_on_call == self.calls:
            self.revision += 1
        return AuthoritySnapshot(self.revision, deepcopy(self.actors))


class AuthorityRevisionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="narf-authority-revision-")
        self.addCleanup(tmp.cleanup)
        self.store = ReceiptStore(Path(tmp.name), b"r" * 32)
        self.task = {"description": "monotonic authority revision"}
        self.state = FrozenState(
            sha256_bytes(b"candidate"),
            sha256_bytes(b"requirements"),
            sha256_bytes(b"policy"),
        )
        self.current_state = self.state
        self.effects = []
        self.requirements = [
            Requirement("check", "check", "1"),
            Requirement("approval", "approve", "1"),
        ]
        self.policy = {
            "actors": {
                "builder": {
                    "principal_id": "agent:builder",
                    "trust_domain": "build-plane",
                },
                "verifier:check": {
                    "principal_id": "reviewer:independent",
                    "trust_domain": "review-plane",
                },
                "authority": {
                    "principal_id": "human:approver",
                    "trust_domain": "approval-plane",
                },
            },
            "separation": [
                ["builder", "verifier:check", "principal_id"],
                ["builder", "authority", "principal_id"],
            ],
            "authority_verifier_id": "approve",
        }
        self.authority = MutableAuthority(self.policy["actors"])
        self.gate = AuthorityRevisionGate(self.store, self.authority)
        self.contract_id = self.freeze()

    def freeze(self):
        return self.gate.freeze_contract(
            self.task,
            task_id="authority-revision",
            requirements=self.requirements,
            effect_id="publish",
            effect_version="1",
            state=self.state,
            identity_policy=self.policy,
        )

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
                    trust_domain=actor["trust_domain"],
                )
            )
        return result

    def session(self, contract_id=None):
        return self.gate.open_session(
            contract_id or self.contract_id,
            self.task,
            verifier_bindings=self.bindings(),
            effect_binding=EffectBinding(
                "publish", "1", lambda: self.effects.append("published")
            ),
            state_probe=lambda: self.current_state,
        )

    def run_all(self, session):
        for requirement in session.requirements():
            session.execute(requirement)

    def test_baseline_pass_binds_frozen_revision(self):
        session = self.session()
        self.assertEqual(session.authority_revision, 1)
        self.run_all(session)
        self.assertEqual(session.finalize()["result"], "PASS")
        session.execute_effect()
        self.assertEqual(self.effects, ["published"])

    def test_change_and_restore_between_probes_is_exposed_by_revision(self):
        session = self.session()
        self.run_all(session)
        self.assertEqual(session.finalize()["result"], "PASS")

        original = deepcopy(self.authority.actors)
        self.authority.actors["verifier:check"]["principal_id"] = "agent:builder"
        self.authority.actors = original
        self.authority.revision += 1

        self.assertEqual(session.verdict()["result"], "BLOCKED")
        with self.assertRaises(NARFError):
            session.execute_effect()
        self.assertEqual(self.effects, [])

    def test_actor_drift_without_revision_change_still_blocks(self):
        session = self.session()
        self.run_all(session)
        self.assertEqual(session.finalize()["result"], "PASS")

        self.authority.actors["verifier:check"]["principal_id"] = "agent:builder"
        self.assertEqual(session.verdict()["result"], "BLOCKED")
        with self.assertRaises(NARFError):
            session.execute_effect()
        self.assertEqual(self.effects, [])

    def test_old_contract_cannot_reopen_after_revision_change(self):
        self.authority.revision += 1
        with self.assertRaisesRegex(NARFError, "revision changed"):
            self.session()

        new_contract = self.freeze()
        session = self.session(new_contract)
        self.assertEqual(session.authority_revision, 2)
        self.run_all(session)
        self.assertEqual(session.finalize()["result"], "PASS")
        session.execute_effect()
        self.assertEqual(self.effects, ["published"])

    def test_missing_binding_receipt_fails_closed(self):
        for path in self.store.directory.glob("*.json"):
            if path.stem != self.contract_id:
                path.unlink()
        with self.assertRaisesRegex(NARFError, "authenticated revision binding required"):
            self.session()
        self.assertEqual(self.effects, [])

    def test_negative_revision_is_rejected(self):
        self.authority.revision = -1
        with self.assertRaisesRegex(NARFError, "non-negative integer revision required"):
            self.freeze()

    def test_snapshot_must_match_frozen_identity_policy(self):
        self.authority.actors["verifier:check"]["principal_id"] = "reviewer:other"
        with self.assertRaisesRegex(NARFError, "snapshot does not match identity policy"):
            self.freeze()

    def test_callback_entry_rechecks_revision_after_core_prechecks(self):
        session = self.session()
        self.run_all(session)
        self.assertEqual(session.finalize()["result"], "PASS")

        # execute_effect performs two core identity revalidations before the
        # guarded callback entry. Change the monotonic revision on the next
        # authority probe so only the callback-entry guard can observe it.
        self.authority.bump_on_call = self.authority.calls + 3
        with self.assertRaisesRegex(NARFError, "revision changed"):
            session.execute_effect()
        self.assertEqual(self.effects, [])

        # The core consumption receipt is intentionally written before callback
        # entry. Once the late guard blocks, the effect remains consumed rather
        # than risking a duplicate retry under uncertain authority state.
        with self.assertRaisesRegex(NARFError, "already consumed"):
            session.execute_effect()


if __name__ == "__main__":
    unittest.main()
