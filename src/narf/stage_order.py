"""Opt-in authenticated stage ordering for the public NARF gate.

The existing v1/v2 gate semantics are delegated unchanged. Ordering-enabled
contracts use evidence version 3 and bind every verifier receipt to one complete
frozen requirement order and to the authenticated predecessor receipt.
"""
from __future__ import annotations

import json
import threading
from dataclasses import asdict
from typing import Callable
from uuid import uuid4

from .gate import (
    EffectBinding,
    FrozenState,
    NARFError,
    NARFGate as _BaseNARFGate,
    NARFSession as _BaseNARFSession,
    ReceiptStore,
    Requirement,
    VerifierBinding,
    _freeze_identity_policy,
    _identifier,
    _identity_role,
    _requirements_digest,
    _SHA256_RE,
    _validate_state,
    canonical_json,
    canonical_json_digest,
)

_ORDER_VERSION = 3


def _freeze_stage_order(stage_order: object, requirements: list[dict]) -> list[str]:
    """Return a canonical complete linear requirement order or fail closed."""
    if type(stage_order) is not list or not stage_order:
        raise NARFError("stage_order: non-empty requirement order required")
    if any(type(item) is not str for item in stage_order):
        raise NARFError("stage_order: requirement identifiers required")
    for item in stage_order:
        _identifier(item, "stage_order")
    required = [item["requirement_id"] for item in requirements]
    if len(stage_order) != len(required) or len(set(stage_order)) != len(stage_order):
        raise NARFError("stage_order: exact requirement permutation required")
    if set(stage_order) != set(required):
        raise NARFError("stage_order: exact requirement permutation required")
    return json.loads(canonical_json(stage_order))


class NARFGate(_BaseNARFGate):
    """NARF gate with optional evidence-v3 stage-order semantics."""

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
    ) -> str:
        if stage_order is None:
            return super().freeze_contract(
                task,
                task_id=task_id,
                requirements=requirements,
                effect_id=effect_id,
                effect_version=effect_version,
                state=state,
                identity_policy=identity_policy,
            )

        _identifier(task_id, "task_id")
        _identifier(effect_id, "effect_id")
        _identifier(effect_version, "effect_version")
        _validate_state(state)
        if not isinstance(task, dict):
            raise NARFError("task: object required")
        task_sha256 = canonical_json_digest(task)
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

        frozen_order = _freeze_stage_order(stage_order, frozen)
        requirements_set_sha256 = _requirements_digest(frozen)
        if identity_policy is not None:
            identity_policy = _freeze_identity_policy(identity_policy, frozen)

        contract_id = str(uuid4())
        evidence = {
            "evidence_type": "narf.contract",
            "evidence_version": _ORDER_VERSION,
            "producer": "host/narf-contract-v3",
            "run_id": contract_id,
            "task_id": task_id,
            "task_sha256": task_sha256,
            "requirements": frozen,
            "requirements_set_sha256": requirements_set_sha256,
            "effect_id": effect_id,
            "effect_version": effect_version,
            "state": asdict(state),
            "stage_order": frozen_order,
            "stage_order_sha256": canonical_json_digest(frozen_order),
        }
        if identity_policy is not None:
            evidence.update(
                identity_policy=identity_policy,
                identity_policy_sha256=canonical_json_digest(identity_policy),
            )
        self._NARFGate__store.save(evidence)
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
    ) -> _BaseNARFSession:
        contract = self._NARFGate__store.load(contract_id)
        if not isinstance(contract, dict) or contract.get("evidence_version") != _ORDER_VERSION:
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
            or contract.get("producer") != "host/narf-contract-v3"
            or "stage_order" not in contract
            or "stage_order_sha256" not in contract
        ):
            raise NARFError("contract: authenticated ordered NARF contract required")
        identity_fields = {"identity_policy", "identity_policy_sha256"}
        present_identity = identity_fields.intersection(contract)
        if present_identity and present_identity != identity_fields:
            raise NARFError("contract: invalid identity version binding")
        if not isinstance(task, dict):
            raise NARFError("task: object required")
        if not callable(state_probe):
            raise NARFError("state: host probe must be callable")
        if revocation_probe is not None and not callable(revocation_probe):
            raise NARFError("revocation: host probe must be callable")

        errors: list[str] = []
        if canonical_json_digest(task) != contract.get("task_sha256"):
            errors.append("TASK_CHANGED")

        bindings: dict[str, VerifierBinding] = {}
        if not isinstance(verifier_bindings, (list, tuple)):
            verifier_bindings = []
            errors.append("VERIFIER_UNAVAILABLE")
        for binding in verifier_bindings:
            if (
                type(binding) is not VerifierBinding
                or not callable(binding.producer)
                or binding.verifier_id in bindings
            ):
                errors.append("VERIFIER_UNAVAILABLE")
                continue
            bindings[binding.verifier_id] = binding

        requirements = contract.get("requirements")
        if not isinstance(requirements, list) or not requirements:
            requirements = []
            errors.append("INVALID_CONTRACT")
        try:
            if contract.get("requirements_set_sha256") != _requirements_digest(requirements):
                errors.append("INVALID_CONTRACT")
            frozen_order = _freeze_stage_order(contract["stage_order"], requirements)
            if canonical_json_digest(frozen_order) != contract.get("stage_order_sha256"):
                errors.append("INVALID_CONTRACT")
        except (NARFError, KeyError, TypeError):
            errors.append("INVALID_CONTRACT")

        if present_identity == identity_fields:
            try:
                policy = _freeze_identity_policy(contract["identity_policy"], requirements)
                if canonical_json_digest(policy) != contract["identity_policy_sha256"]:
                    errors.append("INVALID_CONTRACT")
            except (NARFError, KeyError, TypeError):
                errors.append("INVALID_CONTRACT")

        expected = {item.get("verifier_id") for item in requirements if isinstance(item, dict)}
        if set(bindings) != expected:
            errors.append("VERIFIER_UNAVAILABLE")
        for item in requirements:
            selected = bindings.get(item.get("verifier_id")) if isinstance(item, dict) else None
            if selected is None or selected.verifier_version != item.get("verifier_version"):
                errors.append("VERIFIER_VERSION_CHANGED")

        if (
            type(effect_binding) is not EffectBinding
            or not callable(effect_binding.execute)
            or effect_binding.effect_id != contract.get("effect_id")
            or effect_binding.effect_version != contract.get("effect_version")
        ):
            errors.append("EFFECT_BINDING_CHANGED")

        return StageOrderedNARFSession(
            self._NARFGate__store,
            contract,
            str(uuid4()),
            bindings,
            effect_binding,
            state_probe,
            revocation_probe,
            sorted(set(errors)),
            identity_probe,
        )


class StageOrderedNARFSession(_BaseNARFSession):
    """Linear causal chain over every frozen requirement in one session."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__stage_lock = threading.RLock()

    def _identity_context(self) -> dict:
        contract = self._NARFSession__contract
        if "identity_policy" not in contract:
            return {}
        return {"identity_policy_sha256": contract["identity_policy_sha256"]}

    def _identity_error(self) -> str | None:
        if "identity_policy" not in self._NARFSession__contract:
            return None
        return super()._identity_error()

    def _chain_seed_sha256(self) -> str:
        contract = self._NARFSession__contract
        return canonical_json_digest(
            {
                "domain": "narf.stage-order.seed.v1",
                "contract_id": contract["run_id"],
                "session_id": self._NARFSession__session_id,
                "task_id": contract["task_id"],
                "task_sha256": contract["task_sha256"],
                "requirements_set_sha256": contract["requirements_set_sha256"],
                "state": contract["state"],
                "stage_order_sha256": contract["stage_order_sha256"],
                "identity_policy_sha256": contract.get("identity_policy_sha256"),
            }
        )

    def _ordered_requirement(self, requirement_id: str) -> tuple[int, dict]:
        contract = self._NARFSession__contract
        try:
            index = contract["stage_order"].index(requirement_id)
        except ValueError:
            raise NARFError("requirement: not in frozen stage order") from None
        requirement = next(
            item for item in contract["requirements"] if item["requirement_id"] == requirement_id
        )
        return index, requirement

    def _predecessor_fields(self, stage_index: int) -> dict:
        if stage_index == 0:
            return {
                "predecessor_evidence_id": None,
                "predecessor_evidence_sha256": None,
            }
        contract = self._NARFSession__contract
        predecessor_requirement_id = contract["stage_order"][stage_index - 1]
        predecessor_run_id = self._NARFSession__runs.get(predecessor_requirement_id)
        if predecessor_run_id is None:
            raise NARFError("stage_order: predecessor evidence required")
        predecessor = self._NARFSession__store.load(predecessor_run_id)
        if not isinstance(predecessor, dict):
            raise NARFError("stage_order: authenticated predecessor required")
        return {
            "predecessor_evidence_id": predecessor_run_id,
            "predecessor_evidence_sha256": canonical_json_digest(predecessor),
        }

    def _expected_evidence(self, requirement: dict, run_id: str) -> dict:
        expected = super()._expected_evidence(requirement, run_id)
        contract = self._NARFSession__contract
        binding = self._NARFSession__bindings[requirement["verifier_id"]]
        stage_index, _ = self._ordered_requirement(requirement["requirement_id"])
        expected.update(
            stage_index=stage_index,
            stage_order_sha256=contract["stage_order_sha256"],
            chain_seed_sha256=self._chain_seed_sha256(),
            effect_id=contract["effect_id"],
            effect_version=contract["effect_version"],
            **self._predecessor_fields(stage_index),
        )
        if "identity_policy" in contract:
            policy = contract["identity_policy"]
            role = _identity_role(policy, binding.verifier_id)
            actor = policy["actors"][role]
            expected.update(
                **self._identity_context(),
                identity_role=role,
                principal_id=actor["principal_id"],
                trust_domain=actor.get("trust_domain"),
                verifier_profile=actor.get("verifier_profile"),
            )
        return expected

    def _valid_pass_prefix(self, length: int) -> bool:
        contract = self._NARFSession__contract
        for requirement_id in contract["stage_order"][:length]:
            run_id = self._NARFSession__runs.get(requirement_id)
            if run_id is None:
                return False
            _, requirement = self._ordered_requirement(requirement_id)
            raw = self._NARFSession__store.load(run_id)
            try:
                expected = self._expected_evidence(requirement, run_id)
            except NARFError:
                return False
            if not isinstance(raw, dict) or any(raw.get(k) != v for k, v in expected.items()):
                return False
            if set(raw) != set(expected).union({"status", "reason", "artifact_sha256"}):
                return False
            if (
                raw.get("status") != "PASS"
                or raw.get("reason") != "VERIFIER_PASS"
                or type(raw.get("artifact_sha256")) is not str
                or _SHA256_RE.fullmatch(raw["artifact_sha256"]) is None
            ):
                return False
        return True

    def execute(self, requirement_id: str) -> dict:
        with self.__stage_lock:
            contract = self._NARFSession__contract
            runs = self._NARFSession__runs
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
            return super().execute(requirement_id)

    def _decision_order_context(self) -> dict:
        contract = self._NARFSession__contract
        runs = self._NARFSession__runs
        head_id = None
        head_sha256 = None
        if runs:
            completed = [item for item in contract["stage_order"] if item in runs]
            if completed:
                head_id = runs[completed[-1]]
                head = self._NARFSession__store.load(head_id)
                if isinstance(head, dict):
                    head_sha256 = canonical_json_digest(head)
        return {
            "stage_order_sha256": contract["stage_order_sha256"],
            "chain_seed_sha256": self._chain_seed_sha256(),
            "chain_head_evidence_id": head_id,
            "chain_head_evidence_sha256": head_sha256,
        }

    def _authenticated_decision(self) -> bool:
        decision_state = self._NARFSession__decision
        if decision_state is None:
            return False
        decision = self._NARFSession__store.load(decision_state["decision_id"])
        contract = self._NARFSession__contract
        expected = {
            "evidence_type": "narf.decision",
            "evidence_version": _ORDER_VERSION,
            "producer": "host/narf-gate-v3",
            **self._identity_context(),
            **self._decision_order_context(),
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
        return (
            isinstance(decision, dict)
            and decision == expected
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
        contract = self._NARFSession__contract
        evidence = {
            "evidence_type": "narf.decision",
            "evidence_version": _ORDER_VERSION,
            "producer": "host/narf-gate-v3",
            **self._identity_context(),
            **self._decision_order_context(),
            "run_id": decision_id,
            "contract_id": contract["run_id"],
            "session_id": self._NARFSession__session_id,
            "task_id": contract["task_id"],
            "task_sha256": contract["task_sha256"],
            "requirements_set_sha256": contract["requirements_set_sha256"],
            "state": contract["state"],
            "result": verdict["result"],
            "reason": verdict["reason"],
            "coverage": verdict["coverage"],
        }
        self._NARFSession__store.save(evidence)
        self._NARFSession__decision = {**verdict, "decision_id": decision_id}
        return dict(self._NARFSession__decision)
