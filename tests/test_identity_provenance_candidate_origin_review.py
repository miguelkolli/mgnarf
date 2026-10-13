"""Verifier-only RED probe for frozen candidate-origin attestation semantics.

Frozen design #62 requires B to come from the actual builder execution/output
relationship through a trusted attestation path. A caller-selected actor
instance string must not be enough to manufacture authenticated builder-origin
evidence after the candidate already exists.
"""

from pathlib import Path
import tempfile
import unittest

from narf import (
    FrozenState,
    NARFError,
    NARFGate,
    ReceiptStore,
    Requirement,
    sha256_bytes,
)


class CandidateOriginAttestationReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="narf-origin-review-")
        self.addCleanup(self.tmp.cleanup)
        self.store = ReceiptStore(Path(self.tmp.name) / "receipts", b"o" * 32)
        self.gate = NARFGate(self.store)
        self.task = {"description": "candidate-origin attestation review"}
        self.state = FrozenState(
            candidate_sha256=sha256_bytes(b"already-built-candidate"),
            requirements_sha256=sha256_bytes(b"origin-review-requirements"),
            policy_sha256=sha256_bytes(b"origin-review-policy"),
        )
        self.requirements = [Requirement("tests", "check-a", "1")]
        self.identity_policy = {
            "actors": {
                "builder": {
                    "principal_id": "builder:trusted",
                    "trust_domain": "build",
                },
                "verifier:check-a": {
                    "principal_id": "ci:tests",
                    "trust_domain": "ci",
                },
            },
            "separation": [
                ["builder", "verifier:check-a", "principal_id"],
            ],
        }
        self.snapshot = {
            "authority_id": "host-provenance",
            "trust_root_id": "host-root-v1",
            "revision": 17,
            "actors": {
                "builder": {
                    "principal_id": "builder:trusted",
                    "trust_domain": "build",
                    "credential_equivalence_id": "cred:builder",
                    "execution_security_domain_id": "exec:builder",
                    "control_security_domain_id": "control:builder",
                },
                "verifier:check-a": {
                    "principal_id": "ci:tests",
                    "trust_domain": "ci",
                    "credential_equivalence_id": "cred:tests",
                    "execution_security_domain_id": "exec:tests",
                    "control_security_domain_id": "control:tests",
                },
            },
        }
        self.provenance_policy = {
            "separation": [
                ["builder", "verifier:check-a", "credential_equivalence_id"],
            ]
        }

    def test_caller_selected_builder_instance_cannot_create_b_without_attester(self):
        forged_origin = {
            "candidate_sha256": self.state.candidate_sha256,
            "actor_role": "builder",
            "actor_instance_id": "caller-selected-builder-instance",
        }

        # No builder execution attester, build receipt, or trusted
        # candidate-output relationship is supplied here. Frozen design B says a
        # later/caller assertion must not retroactively prove candidate origin.
        with self.assertRaises(NARFError):
            self.gate.freeze_contract(
                self.task,
                task_id="origin-review",
                requirements=self.requirements,
                effect_id="publish",
                effect_version="1",
                state=self.state,
                identity_policy=self.identity_policy,
                stage_order=["tests"],
                provenance_policy=self.provenance_policy,
                provenance_snapshot=self.snapshot,
                candidate_origin=forged_origin,
            )


if __name__ == "__main__":
    unittest.main()
