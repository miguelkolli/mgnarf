"""RED acceptance tests for provenance-current effect admission.

This slice starts after provenance A/B/P/C and D1/R/D2/E are GREEN. It
specifies the final session-level effect admission boundary from the frozen
identity-provenance design. Stable-operation/fencing wrapper composition stays
separate and must preserve these stronger semantics rather than downgrade them.
"""

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


class MemoryProvenanceAdmissionAuthority:
    """Trusted-host test authority with atomic currentness + reservation."""

    def __init__(self, fixture):
        self.fixture = fixture
        self.stage_tokens = set()
        self.effect_tokens = set()
        self.lock = threading.Lock()

    def _require_current(self, expected_snapshot_sha256, expected_revision):
        current = deepcopy(self.fixture.current_snapshot)
        if (
            canonical_json_digest(current) != expected_snapshot_sha256
            or current.get("revision") != expected_revision
        ):
            raise NARFError("provenance: admission authority state changed")

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
            self._require_current(expected_snapshot_sha256, expected_revision)
            execution = self.fixture.execution.get(actor_role)
            if (
                not isinstance(execution, dict)
                or execution.get("actor_instance_id") != actor_instance_id
            ):
                raise NARFError("provenance: admission actor changed")
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


class ProvenanceEffectFixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="narf-provenance-effect-red-")
        self.root = Path(self.tmp.name)
        self.store = ReceiptStore(self.root / "receipts", b"x" * 32)
        self.gate = NARFGate(self.store)
        self.task = {"description": "provenance-current effect"}
        self.state = FrozenState(
            candidate_sha256=sha256_bytes(b"provenance-effect-candidate"),
            requirements_sha256=sha256_bytes(b"provenance-effect-requirements"),
            policy_sha256=sha256_bytes(b"provenance-effect-policy"),
        )
        self.current_state = self.state
        self.requirements = (
            Requirement("tests", "check-a", "1"),
            Requirement("security", "check-b", "1"),
        )
        self.order = ["tests", "security"]
        self.effects = []
        self.probe_error = False
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
            "revision": 11,
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
            role: {
                "actor_role": role,
                "actor_instance_id": "runner:" + role.split(":")[-1] + ":1",
                **deepcopy(actor),
            }
            for role, actor in self.snapshot["actors"].items()
            if role.startswith("verifier:")
        }
        self.admission_authority = MemoryProvenanceAdmissionAuthority(self)

    def close(self):
        self.tmp.cleanup()

    def provenance_probe(self):
        if self.probe_error:
            raise RuntimeError("provenance unavailable")
        return deepcopy(self.current_snapshot)

    def execution_probe(self, actor_role, requirement_id):
        del requirement_id
        return deepcopy(self.execution[actor_role])

    def bindings(self):
        return [
            VerifierBinding(
                "check-a",
                "1",
                lambda: VerifierResult("PASS", b"tests"),
                principal_id="ci:tests",
                trust_domain="ci",
            ),
            VerifierBinding(
                "check-b",
                "1",
                lambda: VerifierResult("PASS", b"security"),
                principal_id="review:security",
                trust_domain="review",
            ),
        ]

    def effect(self):
        def run():
            self.effects.append("published")
            return "published"
        return EffectBinding("publish", "1", run)

    def ready_session(self):
        contract_id = self.gate.freeze_contract(
            self.task,
            task_id="provenance-effect",
            requirements=self.requirements,
            effect_id="publish",
            effect_version="1",
            state=self.state,
            identity_policy=self.identity_policy,
            stage_order=self.order,
            provenance_policy={
                "separation": [
                    ["verifier:check-a", "verifier:check-b", "execution_security_domain_id"],
                    ["verifier:check-a", "verifier:check-b", "credential_equivalence_id"],
                ]
            },
            provenance_snapshot=self.snapshot,
        )
        session = self.gate.open_session(
            contract_id,
            self.task,
            verifier_bindings=self.bindings(),
            effect_binding=self.effect(),
            state_probe=lambda: self.current_state,
            identity_probe=lambda: deepcopy(self.identity_actors),
            provenance_probe=self.provenance_probe,
            execution_probe=self.execution_probe,
            provenance_admission_authority=self.admission_authority,
        )
        self.assert_pass(session.execute("tests"))
        self.assert_pass(session.execute("security"))
        self.assert_pass(session.finalize())
        return session

    @staticmethod
    def assert_pass(result):
        if result.get("status", result.get("result")) != "PASS":
            raise AssertionError(result)

    def evidence(self, evidence_type):
        rows = []
        for path in sorted(self.store.directory.glob("*.json")):
            item = self.store.load(path.stem)
            if isinstance(item, dict) and item.get("evidence_type") == evidence_type:
                rows.append(item)
        return rows


class ProvenanceEffectRedTests(unittest.TestCase):
    def setUp(self):
        self.fx = ProvenanceEffectFixture()
        self.addCleanup(self.fx.close)

    def test_valid_current_provenance_admits_exactly_one_effect(self):
        session = self.fx.ready_session()
        self.assertEqual(session.execute_effect(), "published")
        self.assertEqual(self.fx.effects, ["published"])
        receipts = self.fx.evidence("narf.effect")
        self.assertEqual(len(receipts), 1)
        receipt = receipts[0]
        self.assertEqual(receipt["evidence_version"], 4)
        self.assertEqual(receipt["provenance_revision"], 11)
        self.assertEqual(receipt["provenance_authority_id"], "host-provenance")
        self.assertEqual(receipt["provenance_trust_root_id"], "host-root-v1")
        with self.assertRaises(NARFError):
            session.execute_effect()
        self.assertEqual(self.fx.effects, ["published"])

    def test_revision_change_after_final_decision_blocks_before_effect(self):
        session = self.fx.ready_session()
        self.fx.current_snapshot["revision"] += 1
        with self.assertRaisesRegex(NARFError, "provenance"):
            session.execute_effect()
        self.assertEqual(self.fx.effects, [])

    def test_observed_drift_then_restore_does_not_heal_old_authorization(self):
        session = self.fx.ready_session()
        self.fx.current_snapshot["revision"] += 1
        self.assertEqual(session.verdict()["result"], "BLOCKED")
        self.fx.current_snapshot = deepcopy(self.fx.snapshot)
        with self.assertRaisesRegex(NARFError, "provenance"):
            session.execute_effect()
        self.assertEqual(self.fx.effects, [])

    def test_trust_root_replacement_before_effect_blocks(self):
        session = self.fx.ready_session()
        self.fx.current_snapshot["trust_root_id"] = "host-root-v2"
        with self.assertRaisesRegex(NARFError, "provenance"):
            session.execute_effect()
        self.assertEqual(self.fx.effects, [])

    def test_currentness_probe_unavailable_at_effect_blocks(self):
        session = self.fx.ready_session()
        self.fx.probe_error = True
        with self.assertRaisesRegex(NARFError, "provenance"):
            session.execute_effect()
        self.assertEqual(self.fx.effects, [])

    def test_concurrent_duplicate_effect_attempts_admit_at_most_one(self):
        session = self.fx.ready_session()
        start = threading.Barrier(3)
        results = []
        errors = []
        guard = threading.Lock()

        def worker():
            start.wait()
            try:
                value = session.execute_effect()
                with guard:
                    results.append(value)
            except NARFError as exc:
                with guard:
                    errors.append(str(exc))

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        start.wait()
        for thread in threads:
            thread.join(timeout=5)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(results, ["published"])
        self.assertEqual(len(errors), 1)
        self.assertEqual(self.fx.effects, ["published"])
        self.assertEqual(len(self.fx.evidence("narf.effect")), 1)


if __name__ == "__main__":
    unittest.main()
