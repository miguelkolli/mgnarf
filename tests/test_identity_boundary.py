"""Host-owned identity and separation adversaries; no external IdP assumed."""

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from narf import (
    EffectBinding, FrozenState, NARFError, NARFGate, ReceiptStore,
    Requirement, VerifierBinding, VerifierResult, canonical_json_digest,
    sha256_bytes,
)


class IdentityBoundaryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="narf-identity-")
        self.addCleanup(tmp.cleanup)
        self.store = ReceiptStore(Path(tmp.name), b"i" * 32)
        self.gate = NARFGate(self.store)
        self.task = {"description": "independently approve a candidate"}
        self.state = FrozenState(*(sha256_bytes(v) for v in (b"candidate", b"req", b"policy")))
        self.current_state = self.state
        self.requirements = [
            Requirement("tests", "check-a", "1"),
            Requirement("security", "check-b", "1"),
            Requirement("approval", "approve", "1"),
        ]
        self.policy = {
            "actors": {
                role: {"principal_id": principal, "trust_domain": domain}
                for role, principal, domain in (
                    ("builder", "agent:builder", "build-plane"),
                    ("verifier:check-a", "ci:tests", "test-plane"),
                    ("verifier:check-b", "review:security", "review-plane"),
                    ("authority", "human:approver", "approval-plane"),
                )
            },
            "separation": [
                ["builder", "verifier:check-a", "principal_id"],
                ["builder", "verifier:check-b", "principal_id"],
                ["verifier:check-a", "verifier:check-b", "principal_id"],
                ["verifier:check-a", "verifier:check-b", "trust_domain"],
                ["builder", "verifier:check-b", "trust_domain"],
                ["builder", "authority", "principal_id"],
            ],
            "authority_verifier_id": "approve",
        }
        self.current_identities = deepcopy(self.policy["actors"])
        self.effects = []
        self.calls = []

    def freeze(self, **overrides):
        options = dict(task_id="identity", requirements=self.requirements,
                       effect_id="publish", effect_version="1", state=self.state,
                       identity_policy=self.policy)
        options.update(overrides)
        return self.gate.freeze_contract(self.task, **options)

    def bindings(self):
        bindings = []
        for req in self.requirements:
            role = "authority" if req.verifier_id == "approve" else "verifier:" + req.verifier_id
            actor = self.policy["actors"].get(role, {})

            def produce(name=req.requirement_id):
                self.calls.append(name)
                return VerifierResult("PASS", ("evidence:" + name).encode())

            bindings.append(VerifierBinding(req.verifier_id, req.verifier_version, produce,
                                            principal_id=actor.get("principal_id"),
                                            trust_domain=actor.get("trust_domain"),
                                            verifier_profile=deepcopy(actor.get("verifier_profile"))))
        return bindings

    def configure_profiles(self, *, same=False, separate=False):
        profile = {
            "model": {"provider": "example", "name": "reviewer", "version": "1"},
            "system_prompt_sha256": sha256_bytes(b"system prompt"),
            "verifier_prompt_sha256": sha256_bytes(b"verifier prompt"),
            "toolchain": {"adapter": "1"},
        }
        self.policy["actors"]["verifier:check-a"]["verifier_profile"] = deepcopy(profile)
        if not same:
            profile["model"]["name"] = "independent-reviewer"
        self.policy["actors"]["verifier:check-b"]["verifier_profile"] = profile
        if separate:
            self.policy["separation"].append(["verifier:check-a", "verifier:check-b", "verifier_profile"])
        self.current_identities = deepcopy(self.policy["actors"])

    def session(self, contract_id=None, **overrides):
        options = dict(verifier_bindings=self.bindings(),
                       effect_binding=EffectBinding("publish", "1", lambda: self.effects.append("effect")),
                       state_probe=lambda: self.current_state,
                       identity_probe=lambda: self.current_identities)
        options.update(overrides)
        return self.gate.open_session(contract_id or self.freeze(), self.task, **options)

    def run_all(self, session):
        return {req: session.execute(req)["evidence_id"] for req in session.requirements()}

    def assert_blocked(self, session, reason=None):
        verdict = session.verdict()
        self.assertEqual(verdict["result"], "BLOCKED", verdict)
        if reason:
            self.assertEqual(verdict["reason"], reason)
        self.assertEqual(session.finalize()["result"], "BLOCKED")
        with self.assertRaises(NARFError):
            session.execute_effect()
        self.assertEqual(self.effects, [])

    def test_independent_chain_passes_and_effect_is_single_use(self):
        session = self.session()
        self.run_all(session)
        self.assertEqual(session.finalize()["result"], "PASS")
        self.assertEqual(session.verdict()["coverage"], "3/3")
        session.execute_effect()
        with self.assertRaises(NARFError):
            session.execute_effect()
        self.assertEqual(self.effects, ["effect"])

    def test_builder_cannot_verify_under_either_logical_verifier_id(self):
        for role in ("verifier:check-a", "verifier:check-b"):
            with self.subTest(role=role):
                original = deepcopy(self.policy)
                self.policy["actors"][role]["principal_id"] = self.policy["actors"]["builder"]["principal_id"]
                self.current_identities = deepcopy(self.policy["actors"])
                self.assert_blocked(self.session(), "IDENTITY_SEPARATION_VIOLATED")
                self.policy = original
        self.assertEqual(self.calls, [])

    def test_distinct_verifier_ids_do_not_make_one_principal_independent(self):
        self.policy["actors"]["verifier:check-b"]["principal_id"] = "ci:tests"
        self.current_identities = deepcopy(self.policy["actors"])
        self.assert_blocked(self.session(), "IDENTITY_SEPARATION_VIOLATED")

    def test_distinct_principals_in_same_required_domain_are_blocked(self):
        for left, right in (("verifier:check-a", "verifier:check-b"), ("builder", "verifier:check-b")):
            with self.subTest(left=left):
                original = deepcopy(self.policy)
                self.policy["actors"][right]["trust_domain"] = self.policy["actors"][left]["trust_domain"]
                self.current_identities = deepcopy(self.policy["actors"])
                self.assert_blocked(self.session(), "IDENTITY_SEPARATION_VIOLATED")
                self.policy = original

    def test_domain_separation_is_only_enforced_when_requested(self):
        self.policy["separation"] = [r for r in self.policy["separation"] if r[2] != "trust_domain"]
        for actor in self.policy["actors"].values():
            actor["trust_domain"] = "shared"
        self.current_identities = deepcopy(self.policy["actors"])
        session = self.session()
        self.run_all(session)
        self.assertEqual(session.finalize()["result"], "PASS")

    def test_optional_domains_may_be_omitted(self):
        self.policy["separation"] = [r for r in self.policy["separation"] if r[2] != "trust_domain"]
        for actor in self.policy["actors"].values():
            del actor["trust_domain"]
        self.current_identities = deepcopy(self.policy["actors"])
        session = self.session()
        self.run_all(session)
        self.assertEqual(session.finalize()["result"], "PASS")

    def test_missing_required_principal_for_every_role_is_blocked(self):
        for role in self.policy["actors"]:
            for missing in (None, "", "   ", False, 7):
                with self.subTest(role=role, missing=missing):
                    original = deepcopy(self.policy)
                    self.policy["actors"][role]["principal_id"] = missing
                    self.current_identities = deepcopy(self.policy["actors"])
                    self.assert_blocked(self.session(), "IDENTITY_UNAVAILABLE")
                    self.policy = original

    def test_missing_required_actor_is_blocked(self):
        del self.policy["actors"]["builder"]
        self.current_identities = deepcopy(self.policy["actors"])
        self.assert_blocked(self.session(), "IDENTITY_UNAVAILABLE")

    def test_missing_required_domain_is_blocked(self):
        del self.policy["actors"]["verifier:check-b"]["trust_domain"]
        self.current_identities = deepcopy(self.policy["actors"])
        self.assert_blocked(self.session(), "IDENTITY_UNAVAILABLE")

    def test_authority_identity_alone_is_not_approval_evidence(self):
        session = self.session()
        session.execute("tests")
        session.execute("security")
        self.assert_blocked(session, "INCOMPLETE_EVIDENCE")

    def test_authority_must_be_a_required_route(self):
        self.requirements = self.requirements[:2]
        self.assert_blocked(self.session(), "AUTHORITY_UNAVAILABLE")

    def test_authority_role_without_approval_route_is_blocked(self):
        del self.policy["authority_verifier_id"]
        # A labeled actor cannot silently count as an approval producer.
        self.policy["actors"]["verifier:approve"] = deepcopy(self.policy["actors"]["authority"])
        self.current_identities = deepcopy(self.policy["actors"])
        self.assert_blocked(self.session(), "AUTHORITY_UNAVAILABLE")

    def test_missing_authority_binding_is_blocked(self):
        self.assert_blocked(self.session(verifier_bindings=self.bindings()[:2]))

    def test_authority_cannot_be_builder_when_forbidden(self):
        self.policy["actors"]["authority"]["principal_id"] = "agent:builder"
        self.current_identities = deepcopy(self.policy["actors"])
        self.assert_blocked(self.session(), "IDENTITY_SEPARATION_VIOLATED")

    def test_wrong_or_missing_binding_identity_is_blocked(self):
        for index in range(3):
            for field, value in (("principal_id", "imposter"), ("principal_id", None),
                                 ("trust_domain", "wrong-domain"), ("trust_domain", None)):
                with self.subTest(index=index, field=field, value=value):
                    bindings = self.bindings()
                    bindings[index] = replace(bindings[index], **{field: value})
                    self.assert_blocked(self.session(verifier_bindings=bindings), "IDENTITY_BINDING_CHANGED")

    def test_missing_failing_or_malformed_identity_probe_is_blocked(self):
        def unavailable():
            raise RuntimeError("identity provider unavailable")
        for probe in (None, unavailable, lambda: None, lambda: {}, lambda: True, lambda: {"builder": []}):
            with self.subTest(probe=probe):
                self.assert_blocked(self.session(identity_probe=probe))

    def test_identity_change_before_verification_prevents_producer_entry(self):
        session = self.session()
        self.current_identities["builder"]["principal_id"] = "other-builder"
        with self.assertRaises(NARFError):
            session.execute("tests")
        self.assertEqual(self.calls, [])
        self.assert_blocked(session, "IDENTITY_CHANGED")

    def test_identity_change_during_verification_remains_blocked_after_restore(self):
        bindings = self.bindings()
        def change_identity():
            self.current_identities["verifier:check-a"]["principal_id"] = "other"
            return VerifierResult("PASS", b"apparently valid")
        bindings[0] = replace(bindings[0], producer=change_identity)
        session = self.session(verifier_bindings=bindings)
        self.assertEqual(session.execute("tests")["status"], "BLOCKED")
        self.current_identities = deepcopy(self.policy["actors"])
        session.execute("security")
        session.execute("approval")
        self.assert_blocked(session, "VERIFIER_BLOCKED")

    def test_each_identity_field_change_after_pass_blocks_effect(self):
        for role in self.policy["actors"]:
            for field in ("principal_id", "trust_domain"):
                with self.subTest(role=role, field=field):
                    self.current_identities = deepcopy(self.policy["actors"])
                    session = self.session()
                    self.run_all(session)
                    self.assertEqual(session.finalize()["result"], "PASS")
                    self.current_identities[role][field] = "changed"
                    self.assertEqual(session.verdict()["result"], "BLOCKED")
                    with self.assertRaises(NARFError):
                        session.execute_effect()
                    with self.assertRaises(NARFError):
                        session.finalize()
        self.assertEqual(self.effects, [])

    def test_identity_unavailable_after_pass_blocks_effect(self):
        session = self.session()
        self.run_all(session)
        session.finalize()
        self.current_identities = None
        with self.assertRaises(NARFError):
            session.execute_effect()
        self.assertEqual(self.effects, [])

    def test_state_changes_after_pass_still_block_effect(self):
        for field in ("candidate_sha256", "requirements_sha256", "policy_sha256"):
            with self.subTest(field=field):
                self.current_state = self.state
                session = self.session()
                self.run_all(session)
                session.finalize()
                self.current_state = replace(self.state, **{field: sha256_bytes(b"changed")})
                with self.assertRaises(NARFError):
                    session.execute_effect()
        self.assertEqual(self.effects, [])

    def test_self_asserted_candidate_and_artifact_identity_cannot_supply_identity(self):
        self.task["actors"] = deepcopy(self.policy["actors"])
        bindings = [replace(b, principal_id=None, trust_domain=None,
                            producer=lambda: VerifierResult("PASS", json.dumps(self.task).encode()))
                    for b in self.bindings()]
        self.assert_blocked(self.session(verifier_bindings=bindings))
        self.assert_blocked(self.session(identity_probe=None))

    def test_artifact_identity_never_overrides_authenticated_identity(self):
        bindings = [replace(b, producer=lambda: VerifierResult("PASS", b'{"principal_id":"imposter","trust_domain":"other"}'))
                    for b in self.bindings()]
        session = self.session(verifier_bindings=bindings)
        runs = self.run_all(session)
        self.assertEqual(session.finalize()["result"], "PASS")
        self.assertEqual(self.store.load(runs["tests"])["principal_id"], "ci:tests")

    def test_frozen_policy_is_snapshotted_and_authenticated(self):
        expected = deepcopy(self.policy)
        contract_id = self.freeze()
        self.policy["separation"].clear()
        contract = self.store.load(contract_id)
        self.assertEqual(contract["identity_policy"], expected)
        self.assertEqual(contract["identity_policy_sha256"], canonical_json_digest(expected))
        self.assertEqual(contract["evidence_version"], 2)
        self.assertEqual(contract["producer"], "host/narf-contract-v2")

    def test_authenticated_policy_digest_mismatch_is_blocked(self):
        contract = self.store.load(self.freeze())
        contract["run_id"] = str(uuid4())
        contract["identity_policy"]["separation"].clear()
        self.store.save(contract)
        self.assert_blocked(self.session(contract["run_id"]), "INVALID_CONTRACT")

    def test_identity_contract_cannot_be_downgraded_or_omit_policy(self):
        for downgrade in (True, False):
            with self.subTest(downgrade=downgrade):
                contract = self.store.load(self.freeze())
                contract["run_id"] = str(uuid4())
                if downgrade:
                    contract.update(evidence_version=1, producer="host/narf-contract-v1")
                else:
                    del contract["identity_policy"]
                self.store.save(contract)
                with self.assertRaises(NARFError):
                    self.session(contract["run_id"])

    def test_verifier_and_authority_receipts_bind_identity_and_effect(self):
        contract_id = self.freeze()
        session = self.session(contract_id)
        runs = self.run_all(session)
        for req in self.requirements:
            with self.subTest(req=req.requirement_id):
                receipt = self.store.load(runs[req.requirement_id])
                role = "authority" if req.verifier_id == "approve" else "verifier:" + req.verifier_id
                self.assertEqual(receipt["principal_id"], self.policy["actors"][role]["principal_id"])
                self.assertEqual(receipt["trust_domain"], self.policy["actors"][role]["trust_domain"])
                self.assertEqual(receipt["identity_role"], role)
                self.assertEqual(receipt["identity_policy_sha256"], canonical_json_digest(self.policy))
                self.assertEqual(receipt["contract_id"], contract_id)
                self.assertEqual(receipt["session_id"], session.session_id)
                self.assertEqual(receipt["effect_id"], "publish")
                self.assertEqual(receipt["effect_version"], "1")
                self.assertEqual(receipt["evidence_version"], 2)

    def test_authenticated_wrong_evidence_fields_are_rejected(self):
        # Re-sign to test semantic binding separately from HMAC integrity.
        for requirement in ("tests", "approval"):
            for field in ("contract_id", "session_id", "task_sha256", "state", "requirement_id",
                          "verifier_id", "verifier_version", "principal_id", "trust_domain",
                          "identity_role", "identity_policy_sha256", "effect_id", "effect_version"):
                with self.subTest(requirement=requirement, field=field):
                    session = self.session()
                    runs = self.run_all(session)
                    receipt = self.store.load(runs[requirement])
                    receipt["run_id"] = str(uuid4())
                    receipt[field] = "replayed-or-wrong"
                    self.store.save(receipt)
                    session._NARFSession__runs[requirement] = receipt["run_id"]
                    self.assert_blocked(session, "INVALID_EVIDENCE")

    def test_identity_and_authority_evidence_cannot_replay_across_boundaries(self):
        self.configure_profiles(separate=True)
        source_contract = self.freeze()
        first = self.session(source_contract)
        old_runs = self.run_all(first)
        first.finalize()
        for boundary in ("session", "contract", "candidate", "effect"):
            for requirement in ("tests", "approval"):
                with self.subTest(boundary=boundary, requirement=requirement):
                    options = {}
                    if boundary == "candidate":
                        options["state"] = replace(self.state, candidate_sha256=sha256_bytes(b"other"))
                    if boundary == "effect":
                        options["effect_id"] = "other-effect"
                    target = source_contract if boundary == "session" else self.freeze(**options)
                    self.current_state = options.get("state", self.state)
                    effect = EffectBinding(options.get("effect_id", "publish"), "1", lambda: self.effects.append("effect"))
                    second = self.session(target, effect_binding=effect)
                    self.run_all(second)
                    second._NARFSession__runs[requirement] = old_runs[requirement]
                    self.assert_blocked(second, "INVALID_EVIDENCE")

    def test_identity_enabled_effect_is_single_use_across_sessions(self):
        contract_id = self.freeze()
        for index in range(2):
            session = self.session(contract_id)
            self.run_all(session)
            session.finalize()
            if index == 0:
                session.execute_effect()
            else:
                with self.assertRaises(NARFError):
                    session.execute_effect()
        self.assertEqual(self.effects, ["effect"])

    def test_authority_fail_blocked_and_invalid_results_never_authorize(self):
        for produced, expected in ((VerifierResult("FAIL", b"denied"), "FAIL"),
                                   (VerifierResult("BLOCKED", b"pending"), "BLOCKED"),
                                   ("PASS", "BLOCKED")):
            with self.subTest(produced=produced):
                bindings = self.bindings()
                bindings[-1] = replace(bindings[-1], producer=lambda p=produced: p)
                session = self.session(verifier_bindings=bindings)
                self.run_all(session)
                self.assertEqual(session.finalize()["result"], expected)
                with self.assertRaises(NARFError):
                    session.execute_effect()
        self.assertEqual(self.effects, [])

    def test_malformed_policy_is_rejected_instead_of_ignored(self):
        for policy in ({}, {"actors": [], "separation": []},
                       dict(self.policy, unexpected=True),
                       dict(self.policy, separation=[["builder", "typo", "principal_id"]]),
                       dict(self.policy, separation=[["builder", "authority", "typo"]]),
                       dict(self.policy, separation=[["builder"]])):
            with self.subTest(policy=policy):
                with self.assertRaises(NARFError):
                    self.freeze(identity_policy=policy)

    def test_legacy_contracts_and_receipts_do_not_require_identity(self):
        contract_id = self.freeze(identity_policy=None)
        bindings = [VerifierBinding(b.verifier_id, b.verifier_version, b.producer) for b in self.bindings()]
        session = self.session(contract_id, verifier_bindings=bindings, identity_probe=None)
        runs = self.run_all(session)
        self.assertEqual(session.finalize()["result"], "PASS")
        self.assertEqual(self.store.load(contract_id)["evidence_version"], 1)
        self.assertNotIn("identity_policy", self.store.load(contract_id))
        self.assertNotIn("principal_id", self.store.load(runs["tests"]))

    def test_different_principals_may_share_profile_without_separation_rule(self):
        self.configure_profiles(same=True)
        session = self.session()
        self.run_all(session)
        self.assertEqual(session.finalize()["result"], "PASS")
        session.execute_effect()
        self.assertEqual(self.effects, ["effect"])

    def test_same_model_and_prompts_under_distinct_agent_ids_violate_profile_separation(self):
        self.configure_profiles(same=True, separate=True)
        self.policy["actors"]["verifier:check-a"]["principal_id"] = "agent:one"
        self.policy["actors"]["verifier:check-b"]["principal_id"] = "agent:two"
        self.current_identities = deepcopy(self.policy["actors"])
        self.assert_blocked(self.session(), "IDENTITY_SEPARATION_VIOLATED")

    def test_distinct_profiles_pass_when_required_and_are_bound_in_receipts(self):
        self.configure_profiles(separate=True)
        session = self.session()
        runs = self.run_all(session)
        self.assertEqual(session.finalize()["result"], "PASS")
        receipt = self.store.load(runs["tests"])
        self.assertEqual(receipt["verifier_profile"], self.policy["actors"]["verifier:check-a"]["verifier_profile"])

    def test_profile_diversity_does_not_replace_principal_separation(self):
        self.configure_profiles(separate=True)
        self.policy["actors"]["verifier:check-b"]["principal_id"] = "ci:tests"
        self.current_identities = deepcopy(self.policy["actors"])
        self.assert_blocked(self.session(), "IDENTITY_SEPARATION_VIOLATED")

    def test_missing_profile_required_by_separation_is_blocked(self):
        self.configure_profiles(separate=True)
        del self.policy["actors"]["verifier:check-b"]["verifier_profile"]
        self.current_identities = deepcopy(self.policy["actors"])
        self.assert_blocked(self.session(), "IDENTITY_UNAVAILABLE")

    def test_incomplete_model_profile_provenance_is_blocked(self):
        self.configure_profiles()
        original = deepcopy(self.policy)
        for field in ("model", "system_prompt_sha256", "verifier_prompt_sha256", "toolchain"):
            with self.subTest(field=field):
                self.policy = deepcopy(original)
                del self.policy["actors"]["verifier:check-a"]["verifier_profile"][field]
                self.current_identities = deepcopy(self.policy["actors"])
                self.assert_blocked(self.session(), "IDENTITY_UNAVAILABLE")

    def test_invalid_profile_provenance_is_blocked(self):
        self.configure_profiles()
        original = deepcopy(self.policy["actors"]["verifier:check-a"]["verifier_profile"])
        invalid = [None, {}, [], {"toolchain": {}}, {"toolchain": {"runner": ""}},
                   dict(original, agent_id="arbitrary-diversity"),
                   dict(original, system_prompt_sha256="not-a-digest"),
                   dict(original, model={"provider": "example", "name": "model"}),
                   dict(original, model={"provider": "", "name": "model", "version": "1"})]
        for profile in invalid:
            with self.subTest(profile=profile):
                self.policy["actors"]["verifier:check-a"]["verifier_profile"] = profile
                self.current_identities = deepcopy(self.policy["actors"])
                self.assert_blocked(self.session(), "IDENTITY_UNAVAILABLE")

    def test_tool_only_profiles_are_supported(self):
        self.configure_profiles(separate=True)
        self.policy["actors"]["verifier:check-a"]["verifier_profile"] = {"toolchain": {"unit-runner": "3"}}
        self.current_identities = deepcopy(self.policy["actors"])
        session = self.session()
        self.run_all(session)
        self.assertEqual(session.finalize()["result"], "PASS")

    def test_wrong_or_missing_binding_profile_is_blocked(self):
        self.configure_profiles()
        for profile in (None, {"toolchain": {"other": "1"}}):
            with self.subTest(profile=profile):
                bindings = self.bindings()
                bindings[0] = replace(bindings[0], verifier_profile=profile)
                self.assert_blocked(self.session(verifier_bindings=bindings), "IDENTITY_BINDING_CHANGED")

    def test_profile_change_after_freeze_blocks_producer_entry(self):
        self.configure_profiles()
        contract = self.freeze()
        self.current_identities["verifier:check-a"]["verifier_profile"]["model"]["version"] = "2"
        session = self.session(contract)
        with self.assertRaises(NARFError):
            session.execute("tests")
        self.assert_blocked(session, "IDENTITY_CHANGED")
        self.assertEqual(self.calls, [])

    def test_profile_change_during_verification_is_blocked(self):
        self.configure_profiles()
        bindings = self.bindings()
        def change_profile():
            self.current_identities["verifier:check-a"]["verifier_profile"]["system_prompt_sha256"] = sha256_bytes(b"changed")
            return VerifierResult("PASS", b"apparently valid")
        bindings[0] = replace(bindings[0], producer=change_profile)
        session = self.session(verifier_bindings=bindings)
        self.assertEqual(session.execute("tests")["status"], "BLOCKED")
        self.current_identities = deepcopy(self.policy["actors"])
        session.execute("security")
        session.execute("approval")
        self.assert_blocked(session, "VERIFIER_BLOCKED")

    def test_each_profile_component_change_after_pass_blocks_effect(self):
        self.configure_profiles()
        for field, value in (("model", {"provider": "example", "name": "reviewer", "version": "2"}),
                             ("system_prompt_sha256", sha256_bytes(b"changed")),
                             ("verifier_prompt_sha256", sha256_bytes(b"changed")),
                             ("toolchain", {"adapter": "2"})):
            with self.subTest(field=field):
                self.current_identities = deepcopy(self.policy["actors"])
                session = self.session()
                self.run_all(session)
                session.finalize()
                self.current_identities["verifier:check-a"]["verifier_profile"][field] = value
                self.assertEqual(session.verdict()["result"], "BLOCKED")
                with self.assertRaises(NARFError):
                    session.execute_effect()
        self.assertEqual(self.effects, [])

    def test_binding_profile_mutation_after_pass_is_blocked(self):
        self.configure_profiles()
        bindings = self.bindings()
        session = self.session(verifier_bindings=bindings)
        self.run_all(session)
        session.finalize()
        bindings[0].verifier_profile["toolchain"]["adapter"] = "changed"
        with self.assertRaises(NARFError):
            session.execute_effect()
        self.assertEqual(self.effects, [])

    def test_authenticated_wrong_profile_receipt_is_blocked(self):
        self.configure_profiles()
        session = self.session()
        runs = self.run_all(session)
        receipt = self.store.load(runs["tests"])
        receipt["run_id"] = str(uuid4())
        receipt["verifier_profile"]["toolchain"]["adapter"] = "changed"
        self.store.save(receipt)
        session._NARFSession__runs["tests"] = receipt["run_id"]
        self.assert_blocked(session, "INVALID_EVIDENCE")

    def test_candidate_claimed_profile_cannot_supply_host_provenance(self):
        self.configure_profiles(separate=True)
        claimed = deepcopy(self.policy["actors"]["verifier:check-a"]["verifier_profile"])
        self.task["verifier_profile"] = claimed
        bindings = self.bindings()
        bindings[0] = replace(bindings[0], verifier_profile=None,
                              producer=lambda: VerifierResult("PASS", json.dumps(claimed).encode()))
        self.assert_blocked(self.session(verifier_bindings=bindings), "IDENTITY_BINDING_CHANGED")

    def test_missing_current_profile_after_pass_blocks_effect(self):
        self.configure_profiles()
        session = self.session()
        self.run_all(session)
        session.finalize()
        del self.current_identities["verifier:check-a"]["verifier_profile"]
        with self.assertRaises(NARFError):
            session.execute_effect()
        self.assertEqual(self.effects, [])

    def test_profile_key_order_cannot_manufacture_diversity(self):
        self.configure_profiles(same=True, separate=True)
        actor = self.policy["actors"]["verifier:check-b"]
        actor["verifier_profile"] = dict(reversed(list(actor["verifier_profile"].items())))
        self.current_identities = deepcopy(self.policy["actors"])
        self.assert_blocked(self.session(), "IDENTITY_SEPARATION_VIOLATED")

    def test_tampered_identity_contract_and_profile_receipt_are_unauthentic(self):
        self.configure_profiles()
        for target in ("contract", "verification"):
            with self.subTest(target=target):
                contract_id = self.freeze()
                session = self.session(contract_id)
                runs = self.run_all(session)
                run_id = contract_id if target == "contract" else runs["tests"]
                path = self.store.directory / f"{run_id}.json"
                envelope = json.loads(path.read_text())
                receipt = envelope["payload"]["evidence"]
                if target == "contract":
                    receipt["identity_policy"]["separation"].clear()
                else:
                    receipt["verifier_profile"]["model"]["version"] = "forged"
                path.write_text(json.dumps(envelope))
                self.assert_blocked(session)

    def test_authority_and_profiles_are_optional_without_policy_requirements(self):
        self.requirements = self.requirements[:2]
        del self.policy["authority_verifier_id"]
        del self.policy["actors"]["authority"]
        self.policy["separation"] = [r for r in self.policy["separation"] if "authority" not in r]
        self.current_identities = deepcopy(self.policy["actors"])
        session = self.session()
        self.run_all(session)
        self.assertEqual(session.finalize()["result"], "PASS")
        session.execute_effect()
        self.assertEqual(self.effects, ["effect"])


if __name__ == "__main__":
    unittest.main()
