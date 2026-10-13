"""Stage-order-capable public fenced-operation gate.

This thin extension preserves the existing fenced-effect transport and executor
semantics while propagating optional authenticated stage ordering into the
underlying authority-revision gate. The lower-level fenced implementation stays
unchanged; only contract creation gains the ordered v3 option.
"""
from __future__ import annotations

from .fenced_effect import (
    FencedOperationGate as _BaseFencedOperationGate,
    _canonical_uuid,
    _identifier,
    _operation_binding_id,
    _scope,
)


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
    ) -> str:
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
