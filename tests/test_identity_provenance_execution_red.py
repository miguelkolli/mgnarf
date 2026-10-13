"""RED acceptance tests for provenance-aware ordered stage execution.

This slice starts only after the A/B/P/C foundation is GREEN. It specifies
D1 admission -> raw producer result R -> D2 effective completion -> final E
verification evidence and a provenance-bound final decision. External effect
admission remains deliberately fail-closed for a later slice.
"""

from copy import deepcopy
import json
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


class ProvenanceExecutionFixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="narf-provenance-exec-red-")
        self.root = Path(self.tmp.name)
        self.store = ReceiptStore(self.root / "receipts", b"x" * 32)
        self.gate = NARFGate(self.store)
        self.task = {"description": "provenance-aware ordered chain"}
        self.state = FrozenState(
            candidate_sha256=sha256_bytes(b"provenance-exec-candidate"),
            requirements_sha256=sha256_bytes(b"provenance-exec-requirements"),
            policy_sha256=sha256_bytes(b"provenance-exec-policy"),
        )
        self.current_state = self.state
        self.requirements = (
            Requirement("tests", "check-a", "1"),
            Requirement("security", "check-b", "1"),
        )
        self.order = ["tests", "security"]
        self.calls = []
        self.effects = []
        self.identity_actors = {
            "builder": {"principal_id": "agent:builder", "trust_domain": "build"},
            "verifier:check-a": {"principal_id": "ci:tests", "trust_domain": "ci"},
            "verifier:check-b": {"principal_id": "review:security", "trust_domain": "review"},
        }
        self.identity_policy = {
            "actors": deepcopy(self.identity_actors),
            "separation": [
                ["verifier:check-a", "verifier:check-b", "principal_id"],
            ],
        }
        self.provenance_policy = {
            "separation": [
                ["verifier:check-a", "verifier:check-b", "execution_security_domain_id"],
                ["verifier:check-a", "verifier:check-b", "credential_equivalence_id"],
            ]
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

    def close(self):
        self.tmp.cleanup()

    def state_probe(self):
        return self.current_state

    def provenance_probe(self):
        return deepcopy(self.current_snapshot)

    def execution_probe(self, actor_role, requirement_id):
        del requirement_id
        return deepcopy(self.execution[actor_role])

    def producer(self, name, status="PASS", hook=None):
        def run():
            self.calls.append(name)
            if hook is not None:
                hook()
            return VerifierResult(status, ("artifact:" + name).encode())
        return run

    def bindings(self, *, first_status="PASS", first_hook=None, second_hook=None):
        return [
            VerifierBinding(
                "check-a", "1", self.producer("tests", first_status, first_hook),
                principal_id="ci:tests", trust_domain="ci",
            ),
            VerifierBinding(
                "check-b", "1", self.producer("security", "PASS", second_hook),
                principal_id="review:security", trust_domain="review",
            ),
        ]

    def effect(self):
        def run():
            self.effects.append("published")
            return "published"
        return EffectBinding("publish", "1", run)

    def freeze(self):
        return self.gate.freeze_contract(
            self.task,
            task_id="provenance-exec",
            requirements=self.requirements,
            effect_id="publish",
            effect_version="1",
            state=self.state,
            identity_policy=self.identity_policy,
            stage_order=self.order,
            provenance_policy=self.provenance_policy,
            provenance_snapshot=self.snapshot,
        )

    def session(self, contract_id, *, bindings=None):
        return self.gate.open_session(
            contract_id,
            self.task,
            verifier_bindings=self.bindings() if bindings is None else bindings,
            effect_binding=self.effect(),
            state_probe=self.state_probe,
            identity_probe=lambda: deepcopy(self.identity_actors),
            provenance_probe=self.provenance_probe,
            execution_probe=self.execution_probe,
        )

    def evidence(self, evidence_type=None):
        rows = []
        for path in sorted(self.store.directory.glob("*.json")):
            item = self.store.load(path.stem)
            if isinstance(item, dict) and (evidence_type is None or item.get("evidence_type") == evidence_type):
                rows.append(item)
        return rows

    def reauthenticate(self, run_id, mutate):
        path = self.store.directory / f"{run_id}.json"
        envelope = json.loads(path.read_text())
        mutate(envelope["payload"]["evidence"])
        envelope["mac"] = self.store._mac(envelope["payload"])
        path.write_text(json.dumps(envelope))


class ProvenanceExecutionRedTests(unittest.TestCase):
    def setUp(self):
        self.fx = ProvenanceExecutionFixture()
        self.addCleanup(self.fx.close)

    def test_pass_stage_creates_d1_d2_and_final_e_receipt(self):
        contract_id = self.fx.freeze()
        session = self.fx.session(contract_id)
        result = session.execute("tests")
        self.assertEqual(result["status"], "PASS")

        e = self.fx.store.load(result["evidence_id"])
        self.assertEqual(e["evidence_type"], "narf.verification")
        self.assertEqual(e["evidence_version"], 4)
        self.assertEqual(e["status"], "PASS")
        self.assertEqual(e["reason"], "VERIFIER_PASS")
        self.assertEqual(e["identity_role"], "verifier:check-a")
        self.assertEqual(e["actor_instance_id"], "runner:tests:1")
        self.assertEqual(e["provenance_revision"], 11)

        d1 = self.fx.store.load(e["provenance_admission_id"])
        d2 = self.fx.store.load(e["provenance_completion_id"])
        self.assertEqual(d1["evidence_type"], "narf.provenance-stage-admission")
        self.assertEqual(d1["contract_id"], contract_id)
        self.assertEqual(d1["session_id"], session.session_id)
        self.assertEqual(d1["requirement_id"], "tests")
        self.assertEqual(d1["actor_instance_id"], "runner:tests:1")
        self.assertEqual(d2["evidence_type"], "narf.provenance-stage-completion")
        self.assertEqual(d2["provenance_admission_id"], d1["run_id"])
        self.assertEqual(d2["producer_status"], "PASS")
        self.assertEqual(d2["effective_status"], "PASS")
        self.assertEqual(e["provenance_admission_sha256"], canonical_json_digest(d1))
        self.assertEqual(e["provenance_completion_sha256"], canonical_json_digest(d2))
        self.assertEqual(e["producer_result_sha256"], d2["producer_result_sha256"])

    def test_future_stage_blocks_before_producer_and_before_d1(self):
        contract_id = self.fx.freeze()
        session = self.fx.session(contract_id)
        with self.assertRaises(NARFError):
            session.execute("security")
        self.assertEqual(self.fx.calls, [])
        self.assertEqual(self.fx.evidence("narf.provenance-stage-admission"), [])

        self.assertEqual(session.execute("tests")["status"], "PASS")
        self.assertEqual(self.fx.calls, ["tests"])

    def test_second_stage_d1_binds_first_final_e_as_predecessor(self):
        contract_id = self.fx.freeze()
        session = self.fx.session(contract_id)
        first = session.execute("tests")
        second = session.execute("security")
        first_e = self.fx.store.load(first["evidence_id"])
        second_e = self.fx.store.load(second["evidence_id"])
        second_d1 = self.fx.store.load(second_e["provenance_admission_id"])
        self.assertEqual(second_d1["predecessor_evidence_id"], first["evidence_id"])
        self.assertEqual(
            second_d1["predecessor_evidence_sha256"],
            canonical_json_digest(first_e),
        )

    def test_raw_pass_becomes_effective_blocked_when_provenance_changes_during_producer(self):
        def drift():
            self.fx.current_snapshot["revision"] += 1

        contract_id = self.fx.freeze()
        session = self.fx.session(contract_id, bindings=self.fx.bindings(first_hook=drift))
        result = session.execute("tests")
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["reason"], "PROVENANCE_CHANGED_DURING_VERIFICATION")
        e = self.fx.store.load(result["evidence_id"])
        d2 = self.fx.store.load(e["provenance_completion_id"])
        self.assertEqual(d2["producer_status"], "PASS")
        self.assertEqual(d2["effective_status"], "BLOCKED")
        self.assertEqual(e["status"], "BLOCKED")
        with self.assertRaises(NARFError):
            session.execute("security")

    def test_raw_pass_becomes_effective_blocked_when_execution_instance_changes(self):
        def drift():
            self.fx.execution["verifier:check-a"]["actor_instance_id"] = "runner:tests:2"

        contract_id = self.fx.freeze()
        session = self.fx.session(contract_id, bindings=self.fx.bindings(first_hook=drift))
        result = session.execute("tests")
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["reason"], "PROVENANCE_EXECUTION_CHANGED_DURING_VERIFICATION")
        e = self.fx.store.load(result["evidence_id"])
        d2 = self.fx.store.load(e["provenance_completion_id"])
        self.assertEqual(d2["producer_status"], "PASS")
        self.assertEqual(d2["effective_status"], "BLOCKED")

    def test_failed_predecessor_consumes_stage_and_blocks_next_before_d1(self):
        contract_id = self.fx.freeze()
        session = self.fx.session(contract_id, bindings=self.fx.bindings(first_status="FAIL"))
        first = session.execute("tests")
        self.assertEqual(first["status"], "FAIL")
        with self.assertRaises(NARFError):
            session.execute("tests")
        before = len(self.fx.evidence("narf.provenance-stage-admission"))
        with self.assertRaises(NARFError):
            session.execute("security")
        after = len(self.fx.evidence("narf.provenance-stage-admission"))
        self.assertEqual(before, 1)
        self.assertEqual(after, 1)
        self.assertEqual(self.fx.calls, ["tests"])

    def test_reauthenticated_d2_tamper_breaks_stage_evidence(self):
        contract_id = self.fx.freeze()
        session = self.fx.session(contract_id)
        first = session.execute("tests")
        e = self.fx.store.load(first["evidence_id"])
        d2_id = e["provenance_completion_id"]
        self.fx.reauthenticate(
            d2_id,
            lambda row: row.__setitem__("effective_status", "FAIL"),
        )
        verdict = session.verdict()
        self.assertEqual(verdict["result"], "BLOCKED")
        self.assertEqual(verdict["reason"], "INVALID_EVIDENCE")

    def test_complete_chain_finalizes_v4_decision_bound_to_final_e_and_c(self):
        contract_id = self.fx.freeze()
        session = self.fx.session(contract_id)
        first = session.execute("tests")
        last = session.execute("security")
        self.assertEqual(first["status"], "PASS")
        self.assertEqual(last["status"], "PASS")
        decision = session.finalize()
        self.assertEqual(decision["result"], "PASS")
        receipt = self.fx.store.load(decision["decision_id"])
        self.assertEqual(receipt["evidence_version"], 4)
        self.assertEqual(receipt["chain_head_evidence_id"], last["evidence_id"])
        self.assertEqual(receipt["provenance_binding_id"], self.fx.store.load(contract_id)["provenance_binding_id"])
        self.assertEqual(receipt["provenance_revision"], 11)

    def test_effect_remains_fail_closed_after_provenance_stage_slice(self):
        contract_id = self.fx.freeze()
        session = self.fx.session(contract_id)
        session.execute("tests")
        session.execute("security")
        self.assertEqual(session.finalize()["result"], "PASS")
        with self.assertRaises(NARFError):
            session.execute_effect()
        self.assertEqual(self.fx.effects, [])


if __name__ == "__main__":
    unittest.main()
