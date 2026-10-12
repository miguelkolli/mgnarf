"""Regression tests for identity drift hidden behind another host-state error."""

from copy import deepcopy
from dataclasses import replace
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


class IdentityMaskingTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="narf-identity-mask-")
        self.addCleanup(tmp.cleanup)
        self.store = ReceiptStore(Path(tmp.name), b"m" * 32)
        self.gate = NARFGate(self.store)
        self.task = {"description": "identity masking regression"}
        self.state = FrozenState(
            sha256_bytes(b"candidate"),
            sha256_bytes(b"requirements"),
            sha256_bytes(b"policy"),
        )
        self.current_state = self.state
        self.revoked = False
        self.effects = []
        self.requirements = [Requirement("tests", "check", "1")]
        self.policy = {
            "actors": {
                "builder": {"principal_id": "agent:builder"},
                "verifier:check": {"principal_id": "reviewer:check"},
            },
            "separation": [
                ["builder", "verifier:check", "principal_id"],
            ],
        }
        self.current_identities = deepcopy(self.policy["actors"])
        self.contract_id = self.gate.freeze_contract(
            self.task,
            task_id="identity-mask",
            requirements=self.requirements,
            effect_id="publish",
            effect_version="1",
            state=self.state,
            identity_policy=self.policy,
        )

    def session(self):
        actor = self.policy["actors"]["verifier:check"]
        return self.gate.open_session(
            self.contract_id,
            self.task,
            verifier_bindings=[
                VerifierBinding(
                    "check",
                    "1",
                    lambda: VerifierResult("PASS", b"evidence"),
                    principal_id=actor["principal_id"],
                )
            ],
            effect_binding=EffectBinding(
                "publish", "1", lambda: self.effects.append("published")
            ),
            state_probe=lambda: self.current_state,
            revocation_probe=lambda _contract, _candidate: self.revoked,
            identity_probe=lambda: self.current_identities,
        )

    def test_other_state_errors_cannot_mask_observed_identity_drift(self):
        for masker, expected_reason in (
            ("candidate", "CANDIDATE_CHANGED"),
            ("revocation", "REVOKED"),
            ("unavailable", "STATE_UNAVAILABLE"),
        ):
            with self.subTest(masker=masker):
                self.current_state = self.state
                self.revoked = False
                self.current_identities = deepcopy(self.policy["actors"])
                session = self.session()
                session.execute("tests")
                self.assertEqual(session.finalize()["result"], "PASS")

                self.current_identities["verifier:check"]["principal_id"] = "other-reviewer"
                if masker == "candidate":
                    self.current_state = replace(
                        self.state, candidate_sha256=sha256_bytes(b"changed")
                    )
                elif masker == "revocation":
                    self.revoked = True
                else:
                    self.current_state = None

                verdict = session.verdict()
                self.assertEqual(verdict["result"], "BLOCKED")
                self.assertEqual(verdict["reason"], expected_reason)

                self.current_state = self.state
                self.revoked = False
                self.current_identities = deepcopy(self.policy["actors"])
                verdict = session.verdict()
                self.assertEqual(verdict["result"], "BLOCKED")
                self.assertEqual(verdict["reason"], "IDENTITY_CHANGED")
                with self.assertRaisesRegex(NARFError, "invalid or stale"):
                    session.finalize()
                with self.assertRaises(NARFError):
                    session.execute_effect()

        self.assertEqual(self.effects, [])


if __name__ == "__main__":
    unittest.main()
