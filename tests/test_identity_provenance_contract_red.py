"""RED acceptance tests for the frozen identity-provenance contract foundation.

These tests intentionally describe the first runtime slice only: A/B/P/C contract
activation and fail-closed binding. D1/R/D2/E stage execution provenance is a
later slice after this foundation is green.
"""

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
    canonical_json_digest,
    sha256_bytes,
)


class IdentityProvenanceContractRedTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="narf-provenance-red-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.store = ReceiptStore(self.root, b"p" * 32)
        self.gate = NARFGate(self.store)
        self.task = {"description": "freeze provenance-enabled authorization"}
        self.state = FrozenState(*(sha256_bytes(v) for v in (b"candidate", b"req", b"policy")))
        self.requirements = [
            Requirement("tests", "check-a", "1"),
            Requirement("security", "check-b", "1"),
        ]
        self.order = ["tests", "security"]
        self.identity_policy = {
            "actors": {
                "builder": {
                    "principal_id": "agent:builder",
                    "trust_domain": "build-plane",
                },
                "verifier:check-a": {
                    "principal_id": "ci:tests",
                    "trust_domain": "test-plane",
                },
                "verifier:check-b": {
                    "principal_id": "review:security",
                    "trust_domain": "review-plane",
                },
            },
            "separation": [
                ["verifier:check-a", "verifier:check-b", "principal_id"],
            ],
        }
        self.provenance_policy = {
            "separation": [
                ["verifier:check-a", "verifier:check-b", "execution_security_domain_id"],
            ]
        }
        self.provenance_snapshot = {
            "authority_id": "host-provenance",
            "trust_root_id": "host-root-v1",
            "revision": 7,
            "actors": {
                "builder": {
                    "principal_id": "agent:builder",
                    "trust_domain": "build-plane",
                    "credential_equivalence_id": "cred:builder",
                    "execution_security_domain_id": "exec:builder",
                    "control_security_domain_id": "control:build",
                },
                "verifier:check-a": {
                    "principal_id": "ci:tests",
                    "trust_domain": "test-plane",
                    "credential_equivalence_id": "cred:tests",
                    "execution_security_domain_id": "exec:tests",
                    "control_security_domain_id": "control:tests",
                },
                "verifier:check-b": {
                    "principal_id": "review:security",
                    "trust_domain": "review-plane",
                    "credential_equivalence_id": "cred:security",
                    "execution_security_domain_id": "exec:security",
                    "control_security_domain_id": "control:security",
                },
            },
        }

    def _freeze(self, *, policy=None, snapshot=None, candidate_origin=None):
        return self.gate.freeze_contract(
            self.task,
            task_id="provenance",
            requirements=self.requirements,
            effect_id="publish",
            effect_version="1",
            state=self.state,
            identity_policy=self.identity_policy,
            stage_order=self.order,
            provenance_policy=self.provenance_policy if policy is None else policy,
            provenance_snapshot=self.provenance_snapshot if snapshot is None else snapshot,
            candidate_origin=candidate_origin,
        )

    def _all_evidence(self):
        evidence = []
        for path in sorted(self.root.glob("*.json")):
            loaded = self.store.load(path.stem)
            if isinstance(loaded, dict):
                evidence.append(loaded)
        return evidence

    def _binding_for(self, contract_id):
        bindings = [
            item for item in self._all_evidence()
            if item.get("evidence_type") == "narf.provenance-binding"
            and item.get("contract_id") == contract_id
        ]
        self.assertEqual(len(bindings), 1, bindings)
        return bindings[0]

    def _verifier_bindings(self):
        values = []
        for requirement in self.requirements:
            role = "verifier:" + requirement.verifier_id
            actor = self.identity_policy["actors"][role]
            values.append(
                VerifierBinding(
                    requirement.verifier_id,
                    requirement.verifier_version,
                    lambda: VerifierResult("PASS", b"ok"),
                    principal_id=actor["principal_id"],
                    trust_domain=actor["trust_domain"],
                )
            )
        return values

    def test_provenance_opt_in_freezes_stronger_contract_and_exact_binding(self):
        contract_id = self._freeze()
        contract = self.store.load(contract_id)
        self.assertEqual(contract["evidence_type"], "narf.contract")
        self.assertEqual(contract["evidence_version"], 4)
        self.assertEqual(contract["producer"], "host/narf-contract-v4")
        self.assertIs(contract["provenance_required"], True)
        self.assertEqual(
            contract["provenance_policy_sha256"],
            canonical_json_digest(self.provenance_policy),
        )
        self.assertEqual(
            contract["provenance_snapshot_sha256"],
            canonical_json_digest(self.provenance_snapshot),
        )

        binding = self._binding_for(contract_id)
        self.assertEqual(binding["contract_id"], contract_id)
        self.assertEqual(binding["provenance_policy_sha256"], contract["provenance_policy_sha256"])
        self.assertEqual(binding["provenance_snapshot_sha256"], contract["provenance_snapshot_sha256"])
        self.assertEqual(binding["provenance_authority_id"], "host-provenance")
        self.assertEqual(binding["provenance_trust_root_id"], "host-root-v1")
        self.assertEqual(binding["provenance_revision"], 7)

    def test_legacy_ordered_contract_remains_v3_without_provenance_receipts(self):
        contract_id = self.gate.freeze_contract(
            self.task,
            task_id="legacy-ordered",
            requirements=self.requirements,
            effect_id="publish",
            effect_version="1",
            state=self.state,
            identity_policy=self.identity_policy,
            stage_order=self.order,
        )
        contract = self.store.load(contract_id)
        self.assertEqual(contract["evidence_version"], 3)
        self.assertNotIn("provenance_required", contract)
        self.assertFalse(any(
            item.get("evidence_type") == "narf.provenance-binding"
            for item in self._all_evidence()
        ))

    def test_identity_and_provenance_same_role_mismatch_is_rejected(self):
        snapshot = deepcopy(self.provenance_snapshot)
        snapshot["actors"]["verifier:check-b"]["principal_id"] = "someone-else"
        with self.assertRaises(NARFError):
            self._freeze(snapshot=snapshot)

    def test_equal_required_execution_security_domain_is_rejected(self):
        snapshot = deepcopy(self.provenance_snapshot)
        snapshot["actors"]["verifier:check-b"]["execution_security_domain_id"] = "exec:tests"
        with self.assertRaises(NARFError):
            self._freeze(snapshot=snapshot)

    def test_missing_required_provenance_dimension_is_rejected(self):
        snapshot = deepcopy(self.provenance_snapshot)
        del snapshot["actors"]["verifier:check-b"]["execution_security_domain_id"]
        with self.assertRaises(NARFError):
            self._freeze(snapshot=snapshot)

    def test_builder_provenance_separation_requires_candidate_origin(self):
        policy = deepcopy(self.provenance_policy)
        policy["separation"].append([
            "builder", "verifier:check-a", "credential_equivalence_id"
        ])
        with self.assertRaises(NARFError):
            self._freeze(policy=policy)

    def test_candidate_origin_must_bind_exact_candidate(self):
        policy = deepcopy(self.provenance_policy)
        policy["separation"].append([
            "builder", "verifier:check-a", "credential_equivalence_id"
        ])
        origin = {
            "candidate_sha256": sha256_bytes(b"different-candidate"),
            "actor_role": "builder",
            "actor_instance_id": "build-run-1",
        }
        with self.assertRaises(NARFError):
            self._freeze(policy=policy, candidate_origin=origin)

    def test_valid_candidate_origin_is_committed_by_contract_and_binding(self):
        policy = deepcopy(self.provenance_policy)
        policy["separation"].append([
            "builder", "verifier:check-a", "credential_equivalence_id"
        ])
        origin = {
            "candidate_sha256": self.state.candidate_sha256,
            "actor_role": "builder",
            "actor_instance_id": "build-run-1",
        }
        contract_id = self._freeze(policy=policy, candidate_origin=origin)
        contract = self.store.load(contract_id)
        binding = self._binding_for(contract_id)
        expected = canonical_json_digest(origin)
        self.assertEqual(contract["candidate_origin_sha256"], expected)
        self.assertEqual(binding["candidate_origin_sha256"], expected)

    def test_provenance_contract_without_currentness_probe_fails_closed_on_open(self):
        contract_id = self._freeze()
        with self.assertRaises(NARFError):
            self.gate.open_session(
                contract_id,
                self.task,
                verifier_bindings=self._verifier_bindings(),
                effect_binding=EffectBinding("publish", "1", lambda: None),
                state_probe=lambda: self.state,
                identity_probe=lambda: deepcopy(self.identity_policy["actors"]),
            )

    def test_missing_authenticated_c_binding_blocks_before_session(self):
        contract_id = self._freeze()
        binding = self._binding_for(contract_id)
        (self.root / f"{binding['run_id']}.json").unlink()
        with self.assertRaises(NARFError):
            self.gate.open_session(
                contract_id,
                self.task,
                verifier_bindings=self._verifier_bindings(),
                effect_binding=EffectBinding("publish", "1", lambda: None),
                state_probe=lambda: self.state,
                identity_probe=lambda: deepcopy(self.identity_policy["actors"]),
                provenance_probe=lambda: deepcopy(self.provenance_snapshot),
            )


if __name__ == "__main__":
    unittest.main()
