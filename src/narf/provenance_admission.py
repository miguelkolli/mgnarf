"""Linearized provenance admission for NARF evidence v4.

This layer composes the provenance D1/R/D2/E execution path with a trusted
host authority that atomically compares current provenance and reserves stage
and effect admission tokens. It deliberately does not weaken the existing
stable-operation, authority-revision or fencing wrappers; those composed paths
must preserve this stronger boundary end-to-end.
"""
from __future__ import annotations

from typing import Callable
from uuid import NAMESPACE_URL, uuid4, uuid5

from .gate import (
    EffectBinding,
    FrozenState,
    NARFError,
    VerifierBinding,
    VerifierResult,
    _identity_role,
    canonical_json_digest,
    sha256_bytes,
)
from .provenance import _PROVENANCE_CONTRACT_VERSION
from .provenance_execution import (
    NARFGate as _ExecutionNARFGate,
    ProvenanceNARFSession as _ExecutionProvenanceNARFSession,
    _same_json,
)


class NARFGate(_ExecutionNARFGate):
    """Evidence-v4 gate requiring a linearized provenance admission authority."""

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
        provenance_admission_authority: object | None = None,
    ):
        store = self._NARFGate__store
        contract = store.load(contract_id)
        provenance_v4 = (
            isinstance(contract, dict)
            and contract.get("evidence_version") == _PROVENANCE_CONTRACT_VERSION
            and contract.get("provenance_required") is True
        )

        if not provenance_v4:
            if provenance_admission_authority is not None:
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
                execution_probe=execution_probe,
            )

        if (
            provenance_admission_authority is None
            or not callable(getattr(provenance_admission_authority, "reserve_stage", None))
            or not callable(getattr(provenance_admission_authority, "reserve_effect", None))
        ):
            raise NARFError("provenance: admission authority required")

        base = super().open_session(
            contract_id,
            task,
            verifier_bindings=verifier_bindings,
            effect_binding=effect_binding,
            state_probe=state_probe,
            revocation_probe=revocation_probe,
            identity_probe=identity_probe,
            provenance_probe=provenance_probe,
            execution_probe=execution_probe,
        )
        if not isinstance(base, _ExecutionProvenanceNARFSession):
            raise NARFError("provenance: admission session unavailable")

        return ProvenanceAdmissionSession(
            base._NARFSession__store,
            base._NARFSession__contract,
            base._NARFSession__session_id,
            base._NARFSession__bindings,
            base._NARFSession__effect,
            base._NARFSession__state_probe,
            base._NARFSession__revocation_probe,
            base._NARFSession__errors,
            base._NARFSession__identity_probe,
            base._ProvenanceNARFSession__provenance_probe,
            base._ProvenanceNARFSession__execution_probe,
            base._ProvenanceNARFSession__provenance_binding,
            base._ProvenanceNARFSession__snapshot,
            provenance_admission_authority,
        )


class ProvenanceAdmissionSession(_ExecutionProvenanceNARFSession):
    """Provenance session whose D1/effect admissions are authority-reserved."""

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
        provenance_admission_authority,
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
            provenance_probe,
            execution_probe,
            provenance_binding,
            provenance_snapshot,
        )
        self.__admission_authority = provenance_admission_authority

    def _reserve_stage(
        self,
        admission_id: str,
        *,
        role: str,
        actor_instance_id: str,
    ) -> None:
        contract = self._NARFSession__contract
        try:
            self.__admission_authority.reserve_stage(
                admission_id,
                expected_snapshot_sha256=contract["provenance_snapshot_sha256"],
                expected_revision=contract["provenance_revision"],
                actor_role=role,
                actor_instance_id=actor_instance_id,
            )
        except NARFError:
            raise
        except Exception:
            raise NARFError("provenance: stage admission authority unavailable") from None

    def _reserve_effect(self, effect_run_id: str) -> None:
        contract = self._NARFSession__contract
        try:
            self.__admission_authority.reserve_effect(
                effect_run_id,
                expected_snapshot_sha256=contract["provenance_snapshot_sha256"],
                expected_revision=contract["provenance_revision"],
            )
        except NARFError:
            raise
        except Exception:
            raise NARFError("provenance: effect admission authority unavailable") from None

    def execute(self, requirement_id: str) -> dict:
        with self._ProvenanceNARFSession__stage_lock:
            contract = self._NARFSession__contract
            runs = self._NARFSession__runs
            if self._NARFSession__closed:
                raise NARFError("session: finalized")
            if self._NARFSession__errors:
                raise NARFError("session: blocked host binding")
            if requirement_id in self._ProvenanceNARFSession__stage_inflight:
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
            role = (
                _identity_role(contract["identity_policy"], binding.verifier_id)
                if "identity_policy" in contract
                else "verifier:" + binding.verifier_id
            )
            execution_before = self._execution_record(role, requirement_id)

            self._ProvenanceNARFSession__stage_inflight.add(requirement_id)
            try:
                admission_id = str(
                    uuid5(
                        NAMESPACE_URL,
                        "narf.provenance-stage-admission.v1:"
                        + contract["run_id"]
                        + ":"
                        + self._NARFSession__session_id
                        + ":"
                        + requirement_id,
                    )
                )
                admission = self._admission_evidence(
                    requirement, role, execution_before, admission_id
                )
                self._reserve_stage(
                    admission_id,
                    role=role,
                    actor_instance_id=execution_before["actor_instance_id"],
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
                    "evidence_version": 1,
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
                self._ProvenanceNARFSession__stage_inflight.discard(requirement_id)

    def execute_effect(self):
        decision = self._NARFSession__decision
        if decision is None or decision.get("result") != "PASS":
            raise NARFError("effect: authenticated PASS required")
        if self._NARFSession__effect_used:
            raise NARFError("effect: already consumed")

        state_error = super()._current_state_error()
        if state_error:
            raise NARFError(f"effect: {state_error.lower()}")
        provenance_error = self._provenance_error()
        if provenance_error:
            raise NARFError(f"effect: {provenance_error.lower()}")
        if not self._authenticated_decision():
            raise NARFError("effect: PASS is invalid or stale")

        contract = self._NARFSession__contract
        effect = self._NARFSession__effect
        effect_run_id = str(
            uuid5(
                NAMESPACE_URL,
                "narf.provenance-effect.v4:"
                + contract["run_id"]
                + ":"
                + contract["state"]["candidate_sha256"]
                + ":"
                + effect.effect_id
                + ":"
                + effect.effect_version,
            )
        )

        # This call is the provenance-current linearization point. Do not
        # reclassify an admitted effect if provenance changes after it returns.
        self._reserve_effect(effect_run_id)

        consumed = {
            "evidence_type": "narf.effect",
            "evidence_version": _PROVENANCE_CONTRACT_VERSION,
            "producer": "host/narf-gate-v4",
            **self._identity_context(),
            **self._decision_order_context(),
            **self._provenance_context(),
            "run_id": effect_run_id,
            "contract_id": contract["run_id"],
            "session_id": self._NARFSession__session_id,
            "task_id": contract["task_id"],
            "task_sha256": contract["task_sha256"],
            "requirements_set_sha256": contract["requirements_set_sha256"],
            "state": contract["state"],
            "effect_id": effect.effect_id,
            "effect_version": effect.effect_version,
            "decision_id": decision["decision_id"],
        }
        try:
            self._NARFSession__store.save(consumed)
        except FileExistsError:
            raise NARFError("effect: already consumed") from None
        self._NARFSession__effect_used = True
        return effect.execute()
