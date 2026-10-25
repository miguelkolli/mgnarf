"""Acceptance tests for full actor-instance provenance at the D1 linearization point."""

from copy import deepcopy
from pathlib import Path
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


class StrictProvenanceAdmissionAuthority:
    """Trusted-host authority that resolves full execution provenance atomically."""

    def __init__(self, fixture):
        self.fixture = fixture
        self.stage_tokens = set()
        self.effect_tokens = set()
        self.stage_before_check = None
        self.lock = threading.Lock()

    def _require_current(self, expected_snapshot_sha256, expected_revision):
        current = deepcopy(self.fixture.current_snapshot)
        if (
            canonical_json_digest(current) != expected_snapshot_sha256
            or current.get("revision") != expected_revision
        ):
            raise NARFError("provenance: admission authority state changed")
        return current

    def reserve_stage(
        self,
        token,
        *,
        expected_snapshot_sha256,
        expected_revision,
        actor_role,
        actor_instance_id,
    ):
        with self.lock:
            if self.stage_before_check is not None:
                hook = self.stage_before_check
                self.stage_before_check = None
                hook()

            current = self._require_current(
                expected_snapshot_sha256, expected_revision
            )
            expected_actor = current.get("actors", {}).get(actor_role)
            current_execution = deepcopy(self.fixture.execution.get(actor_role))
            if not isinstance(expected_actor, dict) or not isinstance(current_execution, dict):
                raise NARFError("provenance: admission execution binding unavailable")

            expected_keys = {"actor_role", "actor_instance_id"} | set(expected_actor)
            actual_actor = {
                field: current_execution.get(field)
                for field in expected_actor
            }
            if (
                set(current_execution) != expected_keys
                or current_execution.get("actor_role") != actor_role
                or current_execution.get("actor_instance_id") != actor_instance_id
                or canonical_json_digest(actual_actor)
                != canonical_json_digest(expected_actor)
            ):
                raise NARFError("provenance: admission execution binding changed")
            if token in self.stage_tokens:
                raise NARFError("provenance: stage admission already consumed")
            self.stage_tokens.add(token)

    def reserve_effect(
        self,
        token,
        *,
        expected_snapshot_sha256,
        expected_revision,
    ):
        with self.lock:
            self._require_current(expected_snapshot_sha256, expected_revision)
            if token in self.effect_tokens:
                raise NARFError("provenance: effect admission already consumed")
            self.effect_tokens.add(token)


class StageAdmissionFixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="narf-provenance-stage-admission-")
        self.store = ReceiptStore(Path(self.tmp.name) / "receipts", b"s" * 32)
        self.gate = NARFGate(self.store)
        self.task = {"description": "full execution provenance admission"}
        self.state = FrozenState(
            candidate_sha256=sha256_bytes(b"stage-admission-candidate"),
            requirements_sha256=sha256_bytes(b"stage-admission-requirements"),
            policy_sha256=sha256_bytes(b"stage-admission-policy"),
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
            "actors": deepcopy(self.identity_actors),
            "separation": [["verifier:check-a", "verifier:check-b", "principal_id"]],
        }
        self.snapshot = {
            "authority_id": "host-provenance",
            "trust_root_id": "host-root-v1",
            "revision": 21,
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
        self.current_snapshot = deepcopy(self.snapshot)
        self.execution = {
            "verifier:check-a": {
                "actor_role": "verifier:check-a",
                "actor_instance_id": "runner:tests:1",
                **deepcopy(self.snapshot["actors"]["verifier:check-a"]),
            },
            "verifier:check-b": {
                "actor_role": "verifier:check-b",
                "actor_instance_id": "runner:security:1",
                **deepcopy(self.snapshot["actors"]["verifier:check-b"]),
            },
        }
        self.calls = []
        self.authority = StrictProvenanceAdmissionAuthority(self)

    def close(self):
        self.tmp.cleanup()

    def bindings(self):
        def producer(name):
            def run():
                self.calls.append(name)
                return VerifierResult("PASS", name.encode())
            return run

        return [
            VerifierBinding(
                "check-a", "1", producer("tests"),
                principal_id="ci:tests", trust_domain="ci",
            ),
            VerifierBinding(
                "check-b", "1", producer("security"),
                principal_id="review:security", trust_domain="review",
            ),
        ]

    def session(self):
        contract_id = self.gate.freeze_contract(
            self.task,
            task_id="stage-admission",
            requirements=self.requirements,
            effect_id="publish",
            effect_version="1",
            state=self.state,
            identity_policy=self.identity_policy,
            stage_order=["tests", "security"],
            provenance_policy={
                "separation": [
                    ["verifier:check-a", "verifier:check-b", "credential_equivalence_id"],
                    ["verifier:check-a", "verifier:check-b", "execution_security_domain_id"],
                ]
            },
            provenance_snapshot=self.snapshot,
        )
        return self.gate.open_session(
            contract_id,
            self.task,
            verifier_bindings=self.bindings(),
            effect_binding=EffectBinding("publish", "1", lambda: None),
            state_probe=lambda: self.state,
            identity_probe=lambda: deepcopy(self.identity_actors),
            provenance_probe=lambda: deepcopy(self.current_snapshot),
            execution_probe=lambda role, requirement_id: deepcopy(self.execution[role]),
            provenance_admission_authority=self.authority,
        )

    def d1_receipts(self):
        rows = []
        for path in self.store.directory.glob("*.json"):
            row = self.store.load(path.stem)
            if isinstance(row, dict) and row.get("evidence_type") == "narf.provenance-stage-admission":
                rows.append(row)
        return rows


class FullExecutionProvenanceAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.fx = StageAdmissionFixture()
        self.addCleanup(self.fx.close)

    def test_unchanged_full_execution_binding_is_admitted(self):
        session = self.fx.session()
        result = session.execute("tests")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(self.fx.calls, ["tests"])
        self.assertEqual(len(self.fx.authority.stage_tokens), 1)

    def test_same_instance_credential_drift_blocks_before_d1_and_producer(self):
        def drift_same_instance():
            self.fx.execution["verifier:check-a"]["credential_equivalence_id"] = "cred:swapped"
            self.fx.execution["verifier:check-a"]["execution_security_domain_id"] = "exec:swapped"

        self.fx.authority.stage_before_check = drift_same_instance
        session = self.fx.session()
        with self.assertRaisesRegex(NARFError, "provenance"):
            session.execute("tests")
        self.assertEqual(self.fx.calls, [])
        self.assertEqual(self.fx.d1_receipts(), [])
        self.assertEqual(self.fx.authority.stage_tokens, set())


if __name__ == "__main__":
    unittest.main()
