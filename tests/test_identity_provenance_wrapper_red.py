"""RED tests: legacy wrappers must reject provenance requests explicitly."""

from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from narf import (
    AuthorityRevisionGate,
    AuthoritySnapshot,
    FencedOperationGate,
    FrozenState,
    NARFError,
    OperationBoundGate,
    ReceiptStore,
    Requirement,
    sha256_bytes,
)


class ProvenanceWrapperNoDowngradeRedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="narf-provenance-wrapper-red-")
        self.addCleanup(self.tmp.cleanup)
        self.store = ReceiptStore(Path(self.tmp.name) / "receipts", b"w" * 32)
        self.task = {"description": "wrapper provenance no downgrade"}
        self.state = FrozenState(
            candidate_sha256=sha256_bytes(b"wrapper-candidate"),
            requirements_sha256=sha256_bytes(b"wrapper-requirements"),
            policy_sha256=sha256_bytes(b"wrapper-policy"),
        )
        self.requirements = (
            Requirement("tests", "check-a", "1"),
            Requirement("security", "check-b", "1"),
        )
        self.identity_actors = {
            "builder": {"principal_id": "agent:builder", "trust_domain": "build"},
            "verifier:check-a": {"principal_id": "ci:tests", "trust_domain": "ci"},
            "verifier:check-b": {"principal_id": "review:security", "trust_domain": "review"},
        }
        self.identity_policy = {
            "actors": self.identity_actors,
            "separation": [["verifier:check-a", "verifier:check-b", "principal_id"]],
        }
        self.provenance_snapshot = {
            "authority_id": "host-provenance",
            "trust_root_id": "host-root-v1",
            "revision": 31,
            "actors": {
                "builder": {
                    "principal_id": "agent:builder",
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
                "verifier:check-b": {
                    "principal_id": "review:security",
                    "trust_domain": "review",
                    "credential_equivalence_id": "cred:security",
                    "execution_security_domain_id": "exec:security",
                    "control_security_domain_id": "control:security",
                },
            },
        }
        self.provenance_policy = {
            "separation": [
                ["verifier:check-a", "verifier:check-b", "credential_equivalence_id"],
                ["verifier:check-a", "verifier:check-b", "execution_security_domain_id"],
            ]
        }

    def authority_probe(self):
        return AuthoritySnapshot(7, self.identity_actors)

    def assert_no_receipts(self):
        self.assertEqual(list(self.store.directory.glob("*.json")), [])

    def test_authority_revision_wrapper_rejects_provenance_request_explicitly(self):
        gate = AuthorityRevisionGate(self.store, self.authority_probe)
        with self.assertRaisesRegex(NARFError, "provenance.*unsupported"):
            gate.freeze_contract(
                self.task,
                task_id="authority-wrapper",
                requirements=self.requirements,
                effect_id="publish",
                effect_version="1",
                state=self.state,
                identity_policy=self.identity_policy,
                stage_order=["tests", "security"],
                provenance_policy=self.provenance_policy,
                provenance_snapshot=self.provenance_snapshot,
            )
        self.assert_no_receipts()

    def test_operation_wrapper_rejects_provenance_request_explicitly(self):
        gate = OperationBoundGate(self.store, authority_probe=self.authority_probe)
        with self.assertRaisesRegex(NARFError, "provenance.*unsupported"):
            gate.freeze_contract(
                self.task,
                operation_id=str(uuid4()),
                task_id="operation-wrapper",
                requirements=self.requirements,
                effect_id="publish",
                effect_version="1",
                state=self.state,
                identity_policy=self.identity_policy,
                stage_order=["tests", "security"],
                provenance_policy=self.provenance_policy,
                provenance_snapshot=self.provenance_snapshot,
            )
        self.assert_no_receipts()

    def test_fenced_wrapper_rejects_provenance_request_explicitly(self):
        gate = FencedOperationGate(self.store, self.authority_probe)
        with self.assertRaisesRegex(NARFError, "provenance.*unsupported"):
            gate.freeze_contract(
                self.task,
                operation_id=str(uuid4()),
                fence_scope_id="deploy:prod",
                fencing_authority_id="fence-host-v1",
                task_id="fenced-wrapper",
                requirements=self.requirements,
                effect_id="publish",
                effect_version="1",
                state=self.state,
                identity_policy=self.identity_policy,
                stage_order=["tests", "security"],
                provenance_policy=self.provenance_policy,
                provenance_snapshot=self.provenance_snapshot,
            )
        self.assert_no_receipts()


if __name__ == "__main__":
    unittest.main()
