"""Regression tests for observed identity/profile drift invalidating old authorization."""

from copy import deepcopy
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


class IdentityStaleLatchTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="narf-identity-stale-")
        self.addCleanup(tmp.cleanup)
        self.store = ReceiptStore(Path(tmp.name), b"s" * 32)
        self.gate = NARFGate(self.store)
        self.task = {"description": "sticky identity invalidation"}
        self.state = FrozenState(
            sha256_bytes(b"candidate"),
            sha256_bytes(b"requirements"),
            sha256_bytes(b"policy"),
        )
        self.current_state = self.state
        self.effects = []
        self.requirements = [
            Requirement("tests", "check-a", "1"),
            Requirement("security", "check-b", "1"),
            Requirement("approval", "approve", "1"),
        ]
        profile_a = {
            "model": {"provider": "example", "name": "reviewer-a", "version": "1"},
            "system_prompt_sha256": sha256_bytes(b"system-a"),
            "verifier_prompt_sha256": sha256_bytes(b"verify-a"),
            "toolchain": {"adapter": "1"},
        }
        profile_b = {
            "model": {"provider": "example", "name": "reviewer-b", "version": "1"},
            "system_prompt_sha256": sha256_bytes(b"system-b"),
            "verifier_prompt_sha256": sha256_bytes(b"verify-b"),
            "toolchain": {"adapter": "1"},
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
        self.current_identities = deepcopy(self.policy["actors"])
        self.contract_id = self.gate.freeze_contract(
            self.task,
            task_id="identity-stale",
            requirements=self.requirements,
            effect_id="publish",
            effect_version="1",
            state=self.state,
            identity_policy=self.policy,
        )

    def bindings(self):
        bindings = []
        for requirement in self.requirements:
            role = (
                "authority"
                if requirement.verifier_id == self.policy["authority_verifier_id"]
                else "verifier:" + requirement.verifier_id
            )
            actor = self.policy["actors"][role]
            bindings.append(
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
        return bindings

    def session(self):
        return self.gate.open_session(
            self.contract_id,
            self.task,
            verifier_bindings=self.bindings(),
            effect_binding=EffectBinding(
                "publish", "1", lambda: self.effects.append("published")
            ),
            state_probe=lambda: self.current_state,
            identity_probe=lambda: self.current_identities,
        )

    def run_all(self, session):
        for requirement in session.requirements():
            session.execute(requirement)

    def test_observed_principal_drift_after_pass_is_sticky(self):
        session = self.session()
        self.run_all(session)
        decision = session.finalize()
        self.assertEqual(decision["result"], "PASS")

        self.current_identities["verifier:check-a"]["principal_id"] = "agent:builder"
        self.assertEqual(session.verdict()["result"], "BLOCKED")

        self.current_identities = deepcopy(self.policy["actors"])
        self.assertEqual(session.verdict()["result"], "BLOCKED")
        with self.assertRaisesRegex(NARFError, "invalid or stale"):
            session.finalize()
        with self.assertRaises(NARFError):
            session.execute_effect()
        self.assertEqual(self.effects, [])

    def test_observed_profile_drift_after_pass_is_sticky(self):
        session = self.session()
        self.run_all(session)
        self.assertEqual(session.finalize()["result"], "PASS")

        self.current_identities["verifier:check-a"]["verifier_profile"] = deepcopy(
            self.policy["actors"]["verifier:check-b"]["verifier_profile"]
        )
        self.assertEqual(session.verdict()["result"], "BLOCKED")

        self.current_identities = deepcopy(self.policy["actors"])
        self.assertEqual(session.verdict()["result"], "BLOCKED")
        with self.assertRaises(NARFError):
            session.execute_effect()
        self.assertEqual(self.effects, [])

    def test_observed_drift_after_partial_evidence_invalidates_session(self):
        session = self.session()
        session.execute("tests")

        self.current_identities["verifier:check-b"]["principal_id"] = "agent:builder"
        self.assertEqual(session.verdict()["result"], "BLOCKED")

        self.current_identities = deepcopy(self.policy["actors"])
        with self.assertRaises(NARFError):
            session.execute("security")
        self.assertEqual(session.verdict()["result"], "BLOCKED")
        self.assertEqual(session.finalize()["result"], "BLOCKED")
        self.assertEqual(self.effects, [])

    def test_fresh_session_after_restore_can_verify_again(self):
        first = self.session()
        self.run_all(first)
        self.assertEqual(first.finalize()["result"], "PASS")

        self.current_identities["verifier:check-a"]["principal_id"] = "agent:builder"
        self.assertEqual(first.verdict()["result"], "BLOCKED")
        self.current_identities = deepcopy(self.policy["actors"])

        second = self.session()
        self.run_all(second)
        self.assertEqual(second.finalize()["result"], "PASS")
        second.execute_effect()
        self.assertEqual(self.effects, ["published"])

    def test_drift_observed_before_any_evidence_is_not_sticky(self):
        session = self.session()
        self.current_identities["verifier:check-a"]["principal_id"] = "agent:builder"
        self.assertEqual(session.verdict()["result"], "BLOCKED")

        self.current_identities = deepcopy(self.policy["actors"])
        self.run_all(session)
        self.assertEqual(session.finalize()["result"], "PASS")
        session.execute_effect()
        self.assertEqual(self.effects, ["published"])


if __name__ == "__main__":
    unittest.main()
