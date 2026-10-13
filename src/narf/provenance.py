"""Opt-in authenticated identity provenance for the public NARF gate.

This first runtime slice freezes the stronger provenance contract foundation
(A/B/P/C). Provenance-enabled stage execution remains deliberately fail-closed
until the D1/R/D2/E slice is implemented.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from typing import Callable
from uuid import NAMESPACE_URL, uuid4, uuid5

from .gate import (
    EffectBinding,
    FrozenState,
    NARFError,
    NARFSession as _BaseNARFSession,
    Requirement,
    VerifierBinding,
    _freeze_identity_policy,
    _identifier,
    _requirements_digest,
    _validate_state,
    canonical_json,
    canonical_json_digest,
)
from .stage_order import NARFGate as _StageOrderNARFGate, _freeze_stage_order

_PROVENANCE_CONTRACT_VERSION = 4
_PROVENANCE_STATE_VERSION = 1
_PROVENANCE_BINDING_VERSION = 1
_CANDIDATE_ORIGIN_VERSION = 1
_PROVENANCE_DIMENSIONS = {
    "principal_id",
    "trust_domain",
    "verifier_profile",
    "credential_equivalence_id",
    "execution_security_domain_id",
    "control_security_domain_id",
}
_ACTOR_FIELDS = set(_PROVENANCE_DIMENSIONS)
_COHERENCE_FIELDS = {"principal_id", "trust_domain", "verifier_profile"}


def _canonical_copy(value: object) -> object:
    return json.loads(canonical_json(value))


def _identity_string(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def _provenance_binding_id(contract_id: str) -> str:
    return str(uuid5(NAMESPACE_URL, "narf:provenance-binding:" + contract_id))


def _freeze_requirements(requirements: object) -> list[dict]:
    if not isinstance(requirements, (list, tuple)) or not requirements:
        raise NARFError("requirements: non-empty frozen set required")
    frozen: list[dict] = []
    seen: set[str] = set()
    for requirement in requirements:
        if type(requirement) is not Requirement:
            raise NARFError("requirements: Requirement values required")
        _identifier(requirement.requirement_id, "requirement_id")
        _identifier(requirement.verifier_id, "verifier_id")
        _identifier(requirement.verifier_version, "verifier_version")
        if requirement.requirement_id in seen:
            raise NARFError("requirements: duplicate requirement")
        seen.add(requirement.requirement_id)
        frozen.append(asdict(requirement))
    return frozen


def _allowed_roles(requirements: list[dict]) -> set[str]:
    return {"builder", "authority"} | {
        "verifier:" + item["verifier_id"] for item in requirements
    }


def _freeze_provenance_snapshot(snapshot: object, requirements: list[dict]) -> dict:
    if type(snapshot) is not dict or set(snapshot) != {
        "authority_id", "trust_root_id", "revision", "actors"
    }:
        raise NARFError("provenance: exact authority snapshot required")
    if not _identity_string(snapshot.get("authority_id")):
        raise NARFError("provenance: authority id required")
    if not _identity_string(snapshot.get("trust_root_id")):
        raise NARFError("provenance: trust root id required")
    if type(snapshot.get("revision")) is not int or snapshot["revision"] < 0:
        raise NARFError("provenance: non-negative revision required")
    actors = snapshot.get("actors")
    if type(actors) is not dict or not actors:
        raise NARFError("provenance: actor map required")
    roles = _allowed_roles(requirements)
    for role, actor in actors.items():
        if role not in roles or type(actor) is not dict or not actor:
            raise NARFError("provenance: invalid actor map")
        if set(actor) - _ACTOR_FIELDS:
            raise NARFError("provenance: invalid actor field")
        for field, value in actor.items():
            if field == "verifier_profile":
                if type(value) is not dict:
                    raise NARFError("provenance: invalid verifier profile")
                canonical_json(value)
            elif not _identity_string(value):
                raise NARFError("provenance: non-empty canonical actor value required")
    return _canonical_copy(snapshot)  # type: ignore[return-value]


def _freeze_provenance_policy(policy: object, snapshot: dict) -> dict:
    if type(policy) is not dict or set(policy) != {"separation"}:
        raise NARFError("provenance: separation policy required")
    rules = policy.get("separation")
    if type(rules) is not list or not rules:
        raise NARFError("provenance: non-empty separation policy required")
    actors = snapshot["actors"]
    for rule in rules:
        if (
            type(rule) is not list
            or len(rule) != 3
            or any(type(part) is not str for part in rule)
            or rule[0] not in actors
            or rule[1] not in actors
            or rule[2] not in _PROVENANCE_DIMENSIONS
        ):
            raise NARFError("provenance: invalid separation rule")
        left = actors[rule[0]].get(rule[2])
        right = actors[rule[1]].get(rule[2])
        if left is None or right is None:
            raise NARFError("provenance: required dimension unavailable")
        if canonical_json(left) == canonical_json(right):
            raise NARFError("provenance: separation violated")
    return _canonical_copy(policy)  # type: ignore[return-value]


def _require_actor_coherence(identity_policy: dict | None, snapshot: dict) -> str:
    identity_sha = None
    coherent: dict[str, dict] = {}
    if identity_policy is not None:
        identity_sha = canonical_json_digest(identity_policy)
        identity_actors = identity_policy["actors"]
        for role in sorted(set(identity_actors).intersection(snapshot["actors"])):
            identity_actor = identity_actors[role]
            provenance_actor = snapshot["actors"][role]
            overlap: dict[str, object] = {}
            for field in _COHERENCE_FIELDS:
                if field in identity_actor:
                    if field not in provenance_actor:
                        raise NARFError("provenance: identity actor field unavailable")
                    if canonical_json(identity_actor[field]) != canonical_json(provenance_actor[field]):
                        raise NARFError("provenance: identity actor mismatch")
                    overlap[field] = identity_actor[field]
            coherent[role] = overlap
    return canonical_json_digest(
        {
            "identity_policy_sha256": identity_sha,
            "provenance_snapshot_sha256": canonical_json_digest(snapshot),
            "roles": coherent,
        }
    )


def _builder_origin_required(policy: dict) -> bool:
    return any(rule[0] == "builder" or rule[1] == "builder" for rule in policy["separation"])


def _freeze_candidate_origin(origin: object, state: FrozenState, snapshot: dict) -> dict:
    if type(origin) is not dict or set(origin) != {
        "candidate_sha256", "actor_role", "actor_instance_id"
    }:
        raise NARFError("provenance: exact candidate origin required")
    if origin.get("candidate_sha256") != state.candidate_sha256:
        raise NARFError("provenance: candidate origin changed")
    if origin.get("actor_role") != "builder" or "builder" not in snapshot["actors"]:
        raise NARFError("provenance: builder origin required")
    if not _identity_string(origin.get("actor_instance_id")):
        raise NARFError("provenance: builder instance required")
    return _canonical_copy(origin)  # type: ignore[return-value]


class NARFGate(_StageOrderNARFGate):
    """Public gate with opt-in evidence-v4 provenance contract semantics."""

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
            if provenance_snapshot is not None or candidate_origin is not None:
                raise NARFError("provenance: policy required")
            return super().freeze_contract(
                task,
                task_id=task_id,
                requirements=requirements,
                effect_id=effect_id,
                effect_version=effect_version,
                state=state,
                identity_policy=identity_policy,
                stage_order=stage_order,
            )
        if provenance_snapshot is None:
            raise NARFError("provenance: authority snapshot required")

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

        binding_id = _provenance_binding_id(contract_id)
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
    ) -> _BaseNARFSession:
        store = self._NARFGate__store
        contract = store.load(contract_id)
        if not isinstance(contract, dict) or contract.get("evidence_version") != _PROVENANCE_CONTRACT_VERSION:
            if provenance_probe is not None:
                raise NARFError("provenance: legacy contract cannot be upgraded")
            return super().open_session(
                contract_id,
                task,
                verifier_bindings=verifier_bindings,
                effect_binding=effect_binding,
                state_probe=state_probe,
                revocation_probe=revocation_probe,
                identity_probe=identity_probe,
            )

        if (
            contract.get("evidence_type") != "narf.contract"
            or contract.get("producer") != "host/narf-contract-v4"
            or contract.get("provenance_required") is not True
            or type(contract.get("provenance_policy")) is not dict
            or type(contract.get("provenance_snapshot_sha256")) is not str
        ):
            raise NARFError("contract: authenticated provenance NARF contract required")
        if provenance_probe is None or not callable(provenance_probe):
            raise NARFError("provenance: currentness probe required")

        binding = store.load(_provenance_binding_id(contract_id))
        if (
            not isinstance(binding, dict)
            or binding.get("evidence_type") != "narf.provenance-binding"
            or binding.get("evidence_version") != _PROVENANCE_BINDING_VERSION
            or binding.get("producer") != "host/narf-provenance-binding-v1"
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

        current = provenance_probe()
        requirements = contract.get("requirements")
        if not isinstance(requirements, list):
            raise NARFError("provenance: invalid contract requirements")
        frozen_current = _freeze_provenance_snapshot(current, requirements)
        if (
            canonical_json_digest(frozen_current) != contract.get("provenance_snapshot_sha256")
            or frozen_current.get("authority_id") != contract.get("provenance_authority_id")
            or frozen_current.get("trust_root_id") != contract.get("provenance_trust_root_id")
            or frozen_current.get("revision") != contract.get("provenance_revision")
        ):
            raise NARFError("provenance: authority state changed")

        # Foundation slice only. Until D1/R/D2/E exists, a provenance-enabled
        # contract can be frozen and authenticated but never execute a producer.
        raise NARFError("provenance: stage execution not implemented")
