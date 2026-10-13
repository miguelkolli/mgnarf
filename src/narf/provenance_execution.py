"""Provenance-aware ordered stage execution for NARF evidence v4.

This layer extends the A/B/P/C provenance foundation with D1 admission,
raw producer result R, D2 host-finalized completion and E verification
receipts. External effect admission remains fail-closed for the next slice.
"""
from __future__ import annotations

import threading
from dataclasses import asdict
from typing import Callable
from uuid import uuid4

from .gate import (
    EffectBinding,
    FrozenState,
    NARFError,
    Requirement,
    VerifierBinding,
    VerifierResult,
    _freeze_identity_policy,
    _identity_role,
    _requirements_digest,
    _SHA256_RE,
    _validate_state,
    canonical_json,
    canonical_json_digest,
    sha256_bytes,
)
from .provenance import (
    NARFGate as _FoundationNARFGate,
    _CANDIDATE_ORIGIN_VERSION,
    _PROVENANCE_BINDING_VERSION,
    _PROVENANCE_CONTRACT_VERSION,
    _PROVENANCE_STATE_VERSION,
    _builder_origin_required,
    _freeze_candidate_origin,
    _freeze_provenance_policy,
    _freeze_provenance_snapshot,
    _freeze_requirements,
    _provenance_binding_id,
    _require_actor_coherence,
)
from .stage_order import StageOrderedNARFSession, _freeze_stage_order

_STAGE_ADMISSION_VERSION = 1
_STAGE_COMPLETION_VERSION = 1


def _same_json(left: object, right: object) -> bool:
    return canonical_json(left) == canonical_json(right)


def _nonempty_string(value: object) -> bool:
    return type(value) is str and bool(value.strip())


class NARFGate(_FoundationNARFGate):
    """Public evidence-v4 gate with provenance-aware ordered execution."""

    def freeze_contract(
        self,
        task: dict,
        *,
        task_id: str,
        requirements: tuple[Requirement, ...] | list[Requirement],
        effect_id: str,
        effect_version: str,
        state: FrozenState,
        identity_policy: dict | None = None,
        stage_order: list[str] | None = None,
        provenance_policy: dict | None = None,
        provenance_snapshot: dict | None = None,
        candidate_origin: dict | None = None,
    ) -> str:
        if provenance_policy is None:
            return super().freeze_contract(
                task,
                task_id=task_id,
                requirements=requirements,
                effect_id=effect_id,
                effect_version=effect_version,
                state=state,
                identity_policy=identity_policy,
                stage_order=stage_order,
                provenance_policy=provenance_policy,
                provenance_snapshot=provenance_snapshot,
                candidate_origin=candidate_origin,
            )
        if provenance_snapshot is None:
            raise NARFError("provenance: authority snapshot required")

        from .gate import _identifier

        _identifier(task_id, "task_id")
        _identifier(effect_id, "effect_id")
        _identifier(effect_version, "effect_version")
        _validate_state(state)
        if not isinstance(task, dict):
            raise NARFError("task: object required")

        frozen_requirements = _freeze_requirements(requirements)
        requirements_set_sha256 = _requirements_digest(frozen_requirements)
        frozen_identity = None
        if identity_policy is not None:
            frozen_identity = _freeze_identity_policy(identity_policy, frozen_requirements)
        frozen_snapshot = _freeze_provenance_snapshot(provenance_snapshot, frozen_requirements)
        frozen_policy = _freeze_provenance_policy(provenance_policy, frozen_snapshot)
        coherence_sha256 = _require_actor_coherence(frozen_identity, frozen_snapshot)

        frozen_origin = None
        if candidate_origin is not None:
            frozen_origin = _freeze_candidate_origin(candidate_origin, state, frozen_snapshot)
        elif _builder_origin_required(frozen_policy):
            raise NARFError("provenance: candidate origin required")

        frozen_order = None
        if stage_order is not None:
            frozen_order = _freeze_stage_order(stage_order, frozen_requirements)

        store = self._NARFGate__store
        state_id = str(uuid4())
        snapshot_sha256 = canonical_json_digest(frozen_snapshot)
        store.save(
            {
                "evidence_type": "narf.provenance-state",
                "evidence_version": _PROVENANCE_STATE_VERSION,
                "producer": "host/narf-provenance-state-v1",
                "run_id": state_id,
                "provenance_authority_id": frozen_snapshot["authority_id"],
                "provenance_trust_root_id": frozen_snapshot["trust_root_id"],
                "provenance_revision": frozen_snapshot["revision"],
                "actors": frozen_snapshot["actors"],
                "provenance_snapshot_sha256": snapshot_sha256,
            }
        )

        origin_id = None
        origin_sha256 = None
        if frozen_origin is not None:
            origin_id = str(uuid4())
            origin_sha256 = canonical_json_digest(frozen_origin)
            store.save(
                {
                    "evidence_type": "narf.candidate-origin",
                    "evidence_version": _CANDIDATE_ORIGIN_VERSION,
                    "producer": "host/narf-candidate-origin-v1",
                    "run_id": origin_id,
                    "candidate_sha256": state.candidate_sha256,
                    "actor_role": "builder",
                    "actor_instance_id": frozen_origin["actor_instance_id"],
                    "builder_actor_sha256": canonical_json_digest(frozen_snapshot["actors"]["builder"]),
                    "provenance_state_id": state_id,
                    "provenance_snapshot_sha256": snapshot_sha256,
                    "provenance_authority_id": frozen_snapshot["authority_id"],
                    "provenance_trust_root_id": frozen_snapshot["trust_root_id"],
                    "provenance_revision": frozen_snapshot["revision"],
                    "candidate_origin_sha256": origin_sha256,
                }
            )

        contract_id = str(uuid4())
        binding_id = _provenance_binding_id(contract_id)
        policy_sha256 = canonical_json_digest(frozen_policy)
        evidence = {
            "evidence_type": "narf.contract",
            "evidence_version": _PROVENANCE_CONTRACT_VERSION,
            "producer": "host/narf-contract-v4",
            "run_id": contract_id,
            "task_id": task_id,
            "task_sha256": canonical_json_digest(task),
            "requirements": frozen_requirements,
            "requirements_set_sha256": requirements_set_sha256,
            "effect_id": effect_id,
            "effect_version": effect_version,
            "state": asdict(state),
            "provenance_required": True,
            "provenance_policy": frozen_policy,
            "provenance_policy_sha256": policy_sha256,
            "provenance_snapshot_sha256": snapshot_sha256,
            "provenance_state_id": state_id,
            "provenance_binding_id": binding_id,
            "provenance_authority_id": frozen_snapshot["authority_id"],
            "provenance_trust_root_id": frozen_snapshot["trust_root_id"],
            "provenance_revision": frozen_snapshot["revision"],
            "actor_role_coherence_sha256": coherence_sha256,
        }
        if frozen_identity is not None:
            evidence.update(
                identity_policy=frozen_identity,
                identity_policy_sha256=canonical_json_digest(frozen_identity),
            )
        if frozen_order is not None:
            evidence.update(
                stage_order=frozen_order,
                stage_order_sha256=canonical_json_digest(frozen_order),
            )
        if origin_id is not None and origin_sha256 is not None:
            evidence.update(
                candidate_origin_id=origin_id,
                candidate_origin_sha256=origin_sha256,
            )
        store.save(evidence)

        binding = {
            "evidence_type": "narf.provenance-binding",
            "evidence_version": _PROVENANCE_BINDING_VERSION,
            "producer": "host/narf-provenance-binding-v1",
            "run_id": binding_id,
            "contract_id": contract_id,
            "contract_sha256": canonical_json_digest(evidence),
            "provenance_policy_sha256": policy_sha256,
            "provenance_snapshot_sha256": snapshot_sha256,
            "provenance_state_id": state_id,
            "provenance_authority_id": frozen_snapshot["authority_id"],
            "provenance_trust_root_id": frozen_snapshot["trust_root_id"],
            "provenance_revision": frozen_snapshot["revision"],
            "actor_role_coherence_sha256": coherence_sha256,
        }
        if "stage_order_sha256" in evidence:
            binding["stage_order_sha256"] = evidence["stage_order_sha256"]
        if origin_sha256 is not None:
            binding["candidate_origin_sha256"] = origin_sha256
        store.save(binding)
        return contract_id

    def open_session(
        self,
        contract_id: str,
        task: dict,
        *,
        verifier_bindings: tuple[VerifierBinding, ...] | list[VerifierBinding],
        effect_binding: EffectBinding,
        state_probe: Callable[[], FrozenState],
        revocation_probe: Callable[[str, str], object] | None = None,
        identity_probe: Callable[[], dict] | None = None,
        provenance_probe: Callable[[], dict] | None = None,
        execution_probe: Callable[[str, str], dict] | None = None,
    ):
        store = self._NARFGate__store
        contract = store.load(contract_id)
        if not isinstance(contract, dict) or contract.get("evidence_version") != _PROVENANCE_CONTRACT_VERSION:
            if execution_probe is not None:
                raise NARFError("provenance: legacy contract cannot be upgraded")
            return super().open_session(
                contract_id,
                task,
                verifier_bindings=verifier_bindings,
                effect_binding=effect_binding,
                state_probe=state_probe,
                revocation_probe=revocation_probe,
                identity_probe=identity_probe,
                provenance_probe=provenance_probe,
            )

        if (
            contract.get("evidence_type") != "narf.contract"
            or contract.get("producer") != "host/narf-contract-v4"
            or contract.get("provenance_required") is not True
            or type(contract.get("provenance_policy")) is not dict
            or type(contract.get("provenance_snapshot_sha256")) is not str
            or contract.get("provenance_binding_id") != _provenance_binding_id(contract_id)
            or type(contract.get("stage_order")) is not list
            or type(contract.get("stage_order_sha256")) is not str
        ):
            raise NARFError("contract: authenticated provenance NARF contract required")
        if provenance_probe is None or not callable(provenance_probe):
            raise NARFError("provenance: currentness probe required")
        if execution_probe is None or not callable(execution_probe):
            raise NARFError("provenance: execution probe required")
        if not isinstance(task, dict):
            raise NARFError("task: object required")
        if not callable(state_probe):
            raise NARFError("state: host probe must be callable")
        if revocation_probe is not None and not callable(revocation_probe):
            raise NARFError("revocation: host probe must be callable")

        binding = store.load(contract["provenance_binding_id"])
        if (
            not isinstance(binding, dict)
            or binding.get("evidence_type") != "narf.provenance-binding"
            or binding.get("evidence_version") != _PROVENANCE_BINDING_VERSION
            or binding.get("producer") != "host/narf-provenance-binding-v1"
            or binding.get("run_id") != contract["provenance_binding_id"]
            or binding.get("contract_id") != contract_id
            or binding.get("contract_sha256") != canonical_json_digest(contract)
            or binding.get("provenance_policy_sha256") != contract.get("provenance_policy_sha256")
            or binding.get("provenance_snapshot_sha256") != contract.get("provenance_snapshot_sha256")
            or binding.get("provenance_authority_id") != contract.get("provenance_authority_id")
            or binding.get("provenance_trust_root_id") != contract.get("provenance_trust_root_id")
            or binding.get("provenance_revision") != contract.get("provenance_revision")
            or binding.get("actor_role_coherence_sha256") != contract.get("actor_role_coherence_sha256")
            or binding.get("stage_order_sha256") != contract.get("stage_order_sha256")
            or binding.get("candidate_origin_sha256") != contract.get("candidate_origin_sha256")
        ):
            raise NARFError("provenance: authenticated contract binding required")

        requirements = contract.get("requirements")
        if not isinstance(requirements, list) or not requirements:
            raise NARFError("provenance: invalid contract requirements")
        try:
            if contract.get("requirements_set_sha256") != _requirements_digest(requirements):
                raise NARFError("provenance: invalid contract requirements")
            frozen_order = _freeze_stage_order(contract["stage_order"], requirements)
            if canonical_json_digest(frozen_order) != contract["stage_order_sha256"]:
                raise NARFError("provenance: invalid stage order")
            frozen_policy = _freeze_provenance_policy(contract["provenance_policy"], _snapshot_from_state(store, contract))
            if canonical_json_digest(frozen_policy) != contract.get("provenance_policy_sha256"):
                raise NARFError("provenance: invalid policy binding")
        except (KeyError, TypeError):
            raise NARFError("provenance: invalid contract") from None

        state_evidence = store.load(contract["provenance_state_id"])
        snapshot = _validated_state_snapshot(state_evidence, contract, requirements)
        _require_actor_coherence(contract.get("identity_policy"), snapshot)

        current = _freeze_provenance_snapshot(provenance_probe(), requirements)
        if canonical_json_digest(current) != contract["provenance_snapshot_sha256"]:
            raise NARFError("provenance: authority state changed")

        errors: list[str] = []
        if canonical_json_digest(task) != contract.get("task_sha256"):
            errors.append("TASK_CHANGED")

        bindings: dict[str, VerifierBinding] = {}
        if not isinstance(verifier_bindings, (list, tuple)):
            verifier_bindings = []
            errors.append("VERIFIER_UNAVAILABLE")
        for verifier_binding in verifier_bindings:
            if (
                type(verifier_binding) is not VerifierBinding
                or not callable(verifier_binding.producer)
                or verifier_binding.verifier_id in bindings
            ):
                errors.append("VERIFIER_UNAVAILABLE")
                continue
            bindings[verifier_binding.verifier_id] = verifier_binding

        expected = {item.get("verifier_id") for item in requirements if isinstance(item, dict)}
        if set(bindings) != expected:
            errors.append("VERIFIER_UNAVAILABLE")
        for item in requirements:
            selected = bindings.get(item.get("verifier_id")) if isinstance(item, dict) else None
            if selected is None or selected.verifier_version != item.get("verifier_version"):
                errors.append("VERIFIER_VERSION_CHANGED")

        if "identity_policy" in contract:
            try:
                identity = _freeze_identity_policy(contract["identity_policy"], requirements)
                if canonical_json_digest(identity) != contract.get("identity_policy_sha256"):
                    errors.append("INVALID_CONTRACT")
            except Exception:
                errors.append("INVALID_CONTRACT")

        if (
            type(effect_binding) is not EffectBinding
            or not callable(effect_binding.execute)
            or effect_binding.effect_id != contract.get("effect_id")
            or effect_binding.effect_version != contract.get("effect_version")
        ):
            errors.append("EFFECT_BINDING_CHANGED")

        return ProvenanceNARFSession(
            store,
            contract,
            str(uuid4()),
            bindings,
            effect_binding,
            state_probe,
            revocation_probe,
            sorted(set(errors)),
            identity_probe,
            provenance_probe,
            execution_probe,
            binding,
            snapshot,
        )


def _snapshot_from_state(store, contract: dict) -> dict:
    state = store.load(contract.get("provenance_state_id"))
    if not isinstance(state, dict):
        raise NARFError("provenance: authenticated authority state required")
    return {
        "authority_id": state.get("provenance_authority_id"),
        "trust_root_id": state.get("provenance_trust_root_id"),
        "revision": state.get("provenance_revision"),
        "actors": state.get("actors"),
    }


def _validated_state_snapshot(state: object, contract: dict, requirements: list[dict]) -> dict:
    if not isinstance(state, dict):
        raise NARFError("provenance: authenticated authority state required")
    snapshot = _freeze_provenance_snapshot(
        {
            "authority_id": state.get("provenance_authority_id"),
            "trust_root_id": state.get("provenance_trust_root_id"),
            "revision": state.get("provenance_revision"),
            "actors": state.get("actors"),
        },
        requirements,
    )
    if (
        state.get("evidence_type") != "narf.provenance-state"
        or state.get("evidence_version") != _PROVENANCE_STATE_VERSION
        or state.get("producer") != "host/narf-provenance-state-v1"
        or state.get("run_id") != contract.get("provenance_state_id")
        or state.get("provenance_snapshot_sha256") != canonical_json_digest(snapshot)
        or canonical_json_digest(snapshot) != contract.get("provenance_snapshot_sha256")
        or snapshot.get("authority_id") != contract.get("provenance_authority_id")
        or snapshot.get("trust_root_id") != contract.get("provenance_trust_root_id")
        or snapshot.get("revision") != contract.get("provenance_revision")
    ):
        raise NARFError("provenance: invalid authority state binding")
    return snapshot


class ProvenanceNARFSession(StageOrderedNARFSession):
    """Evidence-v4 ordered session with provenance stage attribution."""

    def __init__(
        self,
        store,
        contract,
        session_id,
        bindings,
        effect_binding,
        state_probe,
        revocation_probe,
        errors,
        identity_probe,
        provenance_probe,
        execution_probe,
        provenance_binding,
        provenance_snapshot,
    ):
        super().__init__(
            store,
            contract,
            session_id,
            bindings,
            effect_binding,
            state_probe,
            revocation_probe,
            errors,
            identity_probe,
        )
        self.__provenance_probe = provenance_probe
        self.__execution_probe = execution_probe
        self.__provenance_binding = provenance_binding
        self.__snapshot = provenance_snapshot
        self.__provenance_stale: str | None = None
        self.__stage_lock = threading.RLock()
        self.__stage_inflight: set[str] = set()

    def _provenance_error(self) -> str | None:
        if self.__provenance_stale is not None:
            return self.__provenance_stale
        contract = self._NARFSession__contract
        try:
            current = _freeze_provenance_snapshot(
                self.__provenance_probe(), contract["requirements"]
            )
        except Exception:
            self.__provenance_stale = "PROVENANCE_UNAVAILABLE"
            return self.__provenance_stale
        if (
            canonical_json_digest(current) != contract["provenance_snapshot_sha256"]
            or current.get("authority_id") != contract["provenance_authority_id"]
            or current.get("trust_root_id") != contract["provenance_trust_root_id"]
            or current.get("revision") != contract["provenance_revision"]
        ):
            self.__provenance_stale = "PROVENANCE_CHANGED"
        return self.__provenance_stale

    def _execution_record(self, role: str, requirement_id: str) -> dict:
        expected_actor = self.__snapshot["actors"].get(role)
        if not isinstance(expected_actor, dict):
            raise NARFError("provenance: actor unavailable")
        try:
            record = self.__execution_probe(role, requirement_id)
        except Exception:
            raise NARFError("provenance: execution identity unavailable") from None
        if type(record) is not dict:
            raise NARFError("provenance: execution identity unavailable")
        expected_keys = {"actor_role", "actor_instance_id"} | set(expected_actor)
        if set(record) != expected_keys:
            raise NARFError("provenance: execution identity mismatch")
        if record.get("actor_role") != role or not _nonempty_string(record.get("actor_instance_id")):
            raise NARFError("provenance: execution identity mismatch")
        for field, value in expected_actor.items():
            if not _same_json(record.get(field), value):
                raise NARFError("provenance: execution identity mismatch")
        return record

    def _provenance_context(self) -> dict:
        contract = self._NARFSession__contract
        return {
            "provenance_binding_id": contract["provenance_binding_id"],
            "provenance_binding_sha256": canonical_json_digest(self.__provenance_binding),
            "provenance_snapshot_sha256": contract["provenance_snapshot_sha256"],
            "provenance_authority_id": contract["provenance_authority_id"],
            "provenance_trust_root_id": contract["provenance_trust_root_id"],
            "provenance_revision": contract["provenance_revision"],
            "actor_role_coherence_sha256": contract["actor_role_coherence_sha256"],
        }

    def _stage_base_expected(self, requirement: dict, run_id: str) -> dict:
        return super()._expected_evidence(requirement, run_id)

    def _admission_evidence(
        self, requirement: dict, role: str, execution: dict, run_id: str
    ) -> dict:
        contract = self._NARFSession__contract
        stage_index, _ = self._ordered_requirement(requirement["requirement_id"])
        return {
            "evidence_type": "narf.provenance-stage-admission",
            "evidence_version": _STAGE_ADMISSION_VERSION,
            "producer": "host/narf-provenance-admission-v1",
            "run_id": run_id,
            "contract_id": contract["run_id"],
            "session_id": self._NARFSession__session_id,
            "requirement_id": requirement["requirement_id"],
            "identity_role": role,
            "actor_instance_id": execution["actor_instance_id"],
            "actor_sha256": canonical_json_digest(self.__snapshot["actors"][role]),
            **self._provenance_context(),
            "stage_index": stage_index,
            "stage_order_sha256": contract["stage_order_sha256"],
            "chain_seed_sha256": self._chain_seed_sha256(),
            **self._predecessor_fields(stage_index),
        }

    def _valid_stage_evidence(self, requirement: dict, run_id: str, require_pass: bool = False) -> bool:
        store = self._NARFSession__store
        raw = store.load(run_id)
        if not isinstance(raw, dict):
            return False
        try:
            expected_base = self._stage_base_expected(requirement, run_id)
        except NARFError:
            return False
        fixed = {
            **self._provenance_context(),
            "actor_instance_id": raw.get("actor_instance_id"),
            "provenance_admission_id": raw.get("provenance_admission_id"),
            "provenance_admission_sha256": raw.get("provenance_admission_sha256"),
            "provenance_completion_id": raw.get("provenance_completion_id"),
            "provenance_completion_sha256": raw.get("provenance_completion_sha256"),
            "producer_result_sha256": raw.get("producer_result_sha256"),
        }
        expected_fields = {
            **expected_base,
            **fixed,
            "status": raw.get("status"),
            "reason": raw.get("reason"),
            "artifact_sha256": raw.get("artifact_sha256"),
        }
        if set(raw) != set(expected_fields) or any(raw.get(k) != v for k, v in expected_fields.items()):
            return False
        if (
            not _nonempty_string(raw.get("actor_instance_id"))
            or type(raw.get("provenance_admission_id")) is not str
            or type(raw.get("provenance_completion_id")) is not str
            or type(raw.get("provenance_admission_sha256")) is not str
            or type(raw.get("provenance_completion_sha256")) is not str
            or type(raw.get("producer_result_sha256")) is not str
        ):
            return False
        admission = store.load(raw["provenance_admission_id"])
        completion = store.load(raw["provenance_completion_id"])
        if not isinstance(admission, dict) or not isinstance(completion, dict):
            return False
        if canonical_json_digest(admission) != raw["provenance_admission_sha256"]:
            return False
        if canonical_json_digest(completion) != raw["provenance_completion_sha256"]:
            return False
        if (
            admission.get("evidence_type") != "narf.provenance-stage-admission"
            or admission.get("contract_id") != self._NARFSession__contract["run_id"]
            or admission.get("session_id") != self._NARFSession__session_id
            or admission.get("requirement_id") != requirement["requirement_id"]
            or admission.get("actor_instance_id") != raw["actor_instance_id"]
            or completion.get("evidence_type") != "narf.provenance-stage-completion"
            or completion.get("provenance_admission_id") != admission.get("run_id")
            or completion.get("provenance_admission_sha256") != canonical_json_digest(admission)
            or completion.get("producer_result_sha256") != raw["producer_result_sha256"]
            or completion.get("effective_status") != raw["status"]
            or completion.get("effective_reason") != raw["reason"]
            or completion.get("effective_artifact_sha256") != raw["artifact_sha256"]
        ):
            return False
        if raw.get("status") not in ("PASS", "FAIL", "BLOCKED"):
            return False
        if type(raw.get("artifact_sha256")) is not str or _SHA256_RE.fullmatch(raw["artifact_sha256"]) is None:
            return False
        valid_reason = raw.get("reason") == "VERIFIER_" + str(raw.get("status")) or (
            raw.get("status") == "BLOCKED"
            and raw.get("reason") in (
                "VERIFIER_UNAVAILABLE",
                "STATE_CHANGED_DURING_VERIFICATION",
                "PROVENANCE_CHANGED_DURING_VERIFICATION",
                "PROVENANCE_EXECUTION_CHANGED_DURING_VERIFICATION",
            )
        )
        if not valid_reason:
            return False
        if require_pass and (raw["status"] != "PASS" or raw["reason"] != "VERIFIER_PASS"):
            return False
        return True

    def _valid_pass_prefix(self, length: int) -> bool:
        contract = self._NARFSession__contract
        for requirement_id in contract["stage_order"][:length]:
            run_id = self._NARFSession__runs.get(requirement_id)
            if run_id is None:
                return False
            _, requirement = self._ordered_requirement(requirement_id)
            if not self._valid_stage_evidence(requirement, run_id, require_pass=True):
                return False
        return True

    def execute(self, requirement_id: str) -> dict:
        with self.__stage_lock:
            contract = self._NARFSession__contract
            runs = self._NARFSession__runs
            if self._NARFSession__closed:
                raise NARFError("session: finalized")
            if self._NARFSession__errors:
                raise NARFError("session: blocked host binding")
            if requirement_id in self.__stage_inflight:
                raise NARFError("stage_order: stage already in flight")
            if requirement_id in runs:
                raise NARFError("evidence: duplicate requirement execution")
            if requirement_id not in contract["stage_order"]:
                raise NARFError("requirement: not in frozen stage order")
            next_index = len(runs)
            if next_index >= len(contract["stage_order"]):
                raise NARFError("stage_order: complete")
            if contract["stage_order"][next_index] != requirement_id:
                raise NARFError("stage_order: predecessor stage required")
            if not self._valid_pass_prefix(next_index):
                raise NARFError("stage_order: authenticated PASS predecessor required")

            base_error = super()._current_state_error()
            if base_error:
                raise NARFError(f"session: {base_error.lower()}")
            provenance_error = self._provenance_error()
            if provenance_error:
                raise NARFError(f"session: {provenance_error.lower()}")

            _, requirement = self._ordered_requirement(requirement_id)
            binding = self._NARFSession__bindings[requirement["verifier_id"]]
            role = _identity_role(contract["identity_policy"], binding.verifier_id) if "identity_policy" in contract else "verifier:" + binding.verifier_id
            execution_before = self._execution_record(role, requirement_id)

            self.__stage_inflight.add(requirement_id)
            try:
                admission_id = str(uuid4())
                admission = self._admission_evidence(
                    requirement, role, execution_before, admission_id
                )
                self._NARFSession__store.save(admission)

                try:
                    produced = binding.producer()
                    if (
                        type(produced) is not VerifierResult
                        or produced.status not in ("PASS", "FAIL", "BLOCKED")
                        or type(produced.artifact) is not bytes
                        or len(produced.artifact) > 1_048_576
                    ):
                        raise ValueError("invalid verifier result")
                    producer_status = produced.status
                    producer_artifact_sha256 = sha256_bytes(produced.artifact)
                    producer_reason = "VERIFIER_" + producer_status
                except Exception:
                    producer_status = "BLOCKED"
                    producer_artifact_sha256 = sha256_bytes(b"")
                    producer_reason = "VERIFIER_UNAVAILABLE"

                producer_result = {
                    "producer_status": producer_status,
                    "producer_reason": producer_reason,
                    "producer_artifact_sha256": producer_artifact_sha256,
                }
                producer_result_sha256 = canonical_json_digest(producer_result)

                effective_status = producer_status
                effective_reason = producer_reason
                effective_artifact_sha256 = producer_artifact_sha256
                continuity_result = "PASS"

                state_error = super()._current_state_error()
                if state_error is not None:
                    continuity_result = "BLOCKED"
                    effective_status = "BLOCKED"
                    effective_reason = "STATE_CHANGED_DURING_VERIFICATION"

                provenance_after = self._provenance_error()
                if provenance_after is not None:
                    continuity_result = "BLOCKED"
                    effective_status = "BLOCKED"
                    effective_reason = "PROVENANCE_CHANGED_DURING_VERIFICATION"

                try:
                    execution_after = self._execution_record(role, requirement_id)
                except NARFError:
                    execution_after = None
                if execution_after is None or not _same_json(execution_after, execution_before):
                    continuity_result = "BLOCKED"
                    effective_status = "BLOCKED"
                    effective_reason = "PROVENANCE_EXECUTION_CHANGED_DURING_VERIFICATION"

                completion_id = str(uuid4())
                completion = {
                    "evidence_type": "narf.provenance-stage-completion",
                    "evidence_version": _STAGE_COMPLETION_VERSION,
                    "producer": "host/narf-provenance-completion-v1",
                    "run_id": completion_id,
                    "contract_id": contract["run_id"],
                    "session_id": self._NARFSession__session_id,
                    "requirement_id": requirement_id,
                    "identity_role": role,
                    "actor_instance_id": execution_before["actor_instance_id"],
                    "provenance_admission_id": admission_id,
                    "provenance_admission_sha256": canonical_json_digest(admission),
                    "producer_result_sha256": producer_result_sha256,
                    **producer_result,
                    "execution_continuity": continuity_result,
                    "effective_status": effective_status,
                    "effective_reason": effective_reason,
                    "effective_artifact_sha256": effective_artifact_sha256,
                }
                self._NARFSession__store.save(completion)

                evidence_id = str(uuid4())
                evidence = {
                    **self._stage_base_expected(requirement, evidence_id),
                    **self._provenance_context(),
                    "actor_instance_id": execution_before["actor_instance_id"],
                    "provenance_admission_id": admission_id,
                    "provenance_admission_sha256": canonical_json_digest(admission),
                    "provenance_completion_id": completion_id,
                    "provenance_completion_sha256": canonical_json_digest(completion),
                    "producer_result_sha256": producer_result_sha256,
                    "status": effective_status,
                    "reason": effective_reason,
                    "artifact_sha256": effective_artifact_sha256,
                }
                self._NARFSession__store.save(evidence)
                runs[requirement_id] = evidence_id
                return {
                    "requirement_id": requirement_id,
                    "status": effective_status,
                    "reason": effective_reason,
                    "evidence_id": evidence_id,
                }
            finally:
                self.__stage_inflight.discard(requirement_id)

    def _evaluate(self) -> dict:
        if self._NARFSession__errors:
            return {"result": "BLOCKED", "reason": self._NARFSession__errors[0]}
        state_error = super()._current_state_error()
        if state_error:
            return {"result": "BLOCKED", "reason": state_error}
        provenance_error = self._provenance_error()
        if provenance_error:
            return {"result": "BLOCKED", "reason": provenance_error}
        missing = [item for item in self.requirements() if item not in self._NARFSession__runs]
        if missing:
            return {"result": "BLOCKED", "reason": "INCOMPLETE_EVIDENCE"}
        if len(set(self._NARFSession__runs.values())) != len(self._NARFSession__runs):
            return {"result": "BLOCKED", "reason": "REPLAYED_EVIDENCE"}

        statuses = []
        for requirement in self._NARFSession__contract["requirements"]:
            run_id = self._NARFSession__runs[requirement["requirement_id"]]
            if not self._valid_stage_evidence(requirement, run_id):
                return {"result": "BLOCKED", "reason": "INVALID_EVIDENCE"}
            raw = self._NARFSession__store.load(run_id)
            statuses.append(raw["status"])

        if "FAIL" in statuses:
            return {"result": "FAIL", "reason": "VERIFIER_FAIL"}
        if "BLOCKED" in statuses:
            return {"result": "BLOCKED", "reason": "VERIFIER_BLOCKED"}
        if self._NARFSession__inhibitors:
            return {"result": "BLOCKED", "reason": self._NARFSession__inhibitors[0]}
        return {"result": "PASS", "reason": "EXTERNAL_EVIDENCE_ACCEPTED"}

    def _decision_expected(self, decision_state: dict) -> dict:
        contract = self._NARFSession__contract
        return {
            "evidence_type": "narf.decision",
            "evidence_version": _PROVENANCE_CONTRACT_VERSION,
            "producer": "host/narf-gate-v4",
            **self._identity_context(),
            **self._decision_order_context(),
            **self._provenance_context(),
            "run_id": decision_state["decision_id"],
            "contract_id": contract["run_id"],
            "session_id": self._NARFSession__session_id,
            "task_id": contract["task_id"],
            "task_sha256": contract["task_sha256"],
            "requirements_set_sha256": contract["requirements_set_sha256"],
            "state": contract["state"],
            "result": decision_state["result"],
            "reason": decision_state["reason"],
            "coverage": decision_state["coverage"],
        }

    def _authenticated_decision(self) -> bool:
        decision_state = self._NARFSession__decision
        if decision_state is None:
            return False
        decision = self._NARFSession__store.load(decision_state["decision_id"])
        return (
            isinstance(decision, dict)
            and decision == self._decision_expected(decision_state)
            and (decision_state["result"] != "PASS" or self._evaluate().get("result") == "PASS")
        )

    def finalize(self) -> dict:
        if self._NARFSession__decision is not None:
            if not self._authenticated_decision():
                raise NARFError("decision: invalid or stale")
            return dict(self._NARFSession__decision)
        self._NARFSession__closed = True
        verdict = self.verdict()
        decision_id = str(uuid4())
        decision_state = {**verdict, "decision_id": decision_id}
        self._NARFSession__store.save(self._decision_expected(decision_state))
        self._NARFSession__decision = decision_state
        return dict(decision_state)

    def execute_effect(self):
        raise NARFError("provenance: effect admission not implemented")
