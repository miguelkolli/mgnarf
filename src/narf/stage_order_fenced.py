"""Stage-order-capable public fenced-operation gate.

This thin extension preserves the existing fenced-effect transport and executor
semantics while propagating optional authenticated stage ordering into the
underlying authority-revision gate. The lower-level fenced implementation stays
unchanged; only contract creation gains the ordered v3 option.

Provenance-v4 composition requires a stronger cross-authority/fence admission
contract. Until that contract exists, explicit provenance requests fail closed
before any legacy v2/v3 contract or operation binding can be created.
"""
from __future__ import annotations

from .fenced_effect import (
    FencedOperationGate as _BaseFencedOperationGate,
    _canonical_uuid,
    _identifier,
    _operation_binding_id,
    _scope,
)
from .gate import NARFError


class FencedOperationGate(_BaseFencedOperationGate):
    """Fenced operation gate that preserves optional authenticated stage order."""

    def freeze_contract(
        self,
        task: dict,
        *,
        operation_id: str,
        fence_scope_id: str,
        fencing_authority_id: str,
        task_id: str,
        requirements,
        effect_id: str,
        effect_version: str,
        state,
        identity_policy: dict,
        stage_order: list[str] | None = None,
        provenance_policy: dict | None = None,
        provenance_snapshot: dict | None = None,
    ) -> str:
        if provenance_policy is not None or provenance_snapshot is not None:
            raise NARFError("provenance: fenced wrapper unsupported")

        operation_id = _canonical_uuid(operation_id, "operation_id")
        fence_scope_id = _scope(fence_scope_id)
        fencing_authority_id = _identifier(
            fencing_authority_id, "fencing_authority_id"
        )
        effect_id = _identifier(effect_id, "effect_id")
        effect_version = _identifier(effect_version, "effect_version")

        contract_id = self._FencedOperationGate__gate.freeze_contract(
            task,
            task_id=task_id,
            requirements=requirements,
            effect_id=effect_id,
            effect_version=effect_version,
            state=state,
            identity_policy=identity_policy,
            stage_order=stage_order,
        )
        binding_id = _operation_binding_id(contract_id)
        self._FencedOperationGate__store.save(
            {
                "evidence_type": "narf.operation-binding",
                "evidence_version": 2,
                "producer": "host/narf-operation-binding-v2",
                "run_id": binding_id,
                "contract_id": contract_id,
                "operation_id": operation_id,
                "effect_mode": "fenced",
                "fence_scope_id": fence_scope_id,
                "fencing_authority_id": fencing_authority_id,
                "effect_id": effect_id,
                "effect_version": effect_version,
            }
        )
        return contract_id

    def open_session(
        self,
        contract_id: str,
        task: dict,
        *,
        verifier_bindings,
        effect_binding,
        state_probe,
        revocation_probe=None,
        provenance_probe=None,
        execution_probe=None,
        provenance_admission_authority=None,
    ):
        if (
            provenance_probe is not None
            or execution_probe is not None
            or provenance_admission_authority is not None
        ):
            raise NARFError("provenance: fenced wrapper unsupported")
        return super().open_session(
            contract_id,
            task,
            verifier_bindings=verifier_bindings,
            effect_binding=effect_binding,
            state_probe=state_probe,
            revocation_probe=revocation_probe,
        )
