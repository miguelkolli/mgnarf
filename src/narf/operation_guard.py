"""Operation-bound authorization for cross-contract idempotency.

The core NARF gate intentionally remains contract-scoped for compatibility.
This module adds a stronger trusted-host path: a stable host-owned operation
UUID is HMAC-bound to each contract, recovered from authenticated receipt
history, and used as the external consumption-authority token.
"""
from __future__ import annotations

from uuid import NAMESPACE_URL, UUID, uuid5

from .gate import NARFError, NARFGate, ReceiptStore
from .rollback_guard import ConsumptionAuthority


def _canonical_uuid(value: str, label: str) -> str:
    try:
        parsed = UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise NARFError(f"{label}: invalid UUID") from None
    if str(parsed) != value:
        raise NARFError(f"{label}: invalid UUID")
    return value


def _binding_id(contract_id: str) -> str:
    contract_id = _canonical_uuid(contract_id, "contract_id")
    return str(uuid5(NAMESPACE_URL, "narf.operation-binding.v1:" + contract_id))


class OperationBoundSession:
    """Session wrapper carrying an authenticated host-owned operation identity."""

    __slots__ = ("__session", "__contract_id", "__operation_id")

    def __init__(self, session, contract_id: str, operation_id: str):
        self.__session = session
        self.__contract_id = _canonical_uuid(contract_id, "contract_id")
        self.__operation_id = _canonical_uuid(operation_id, "operation_id")

    @property
    def contract_id(self) -> str:
        return self.__contract_id

    @property
    def operation_id(self) -> str:
        return self.__operation_id

    @property
    def session_id(self) -> str:
        return self.__session.session_id

    def requirements(self) -> list[str]:
        return self.__session.requirements()

    def inhibit(self, reason: str) -> None:
        self.__session.inhibit(reason)

    def execute(self, requirement_id: str) -> dict:
        return self.__session.execute(requirement_id)

    def verdict(self) -> dict:
        return self.__session.verdict()

    def finalize(self) -> dict:
        return self.__session.finalize()

    def execute_effect(self):
        return self.__session.execute_effect()


class OperationBoundGate:
    """Bind a trusted-host stable operation UUID to a NARF contract.

    `operation_id` is semantic authority supplied by the trusted host. It must
    remain stable for retries or newly frozen contracts representing the same
    real external operation. Candidate-controlled operation IDs are outside the
    intended trust model.

    The operation binding is stored as a separate HMAC-authenticated receipt.
    If the binding receipt is missing, tampered, rolled back, or otherwise
    invalid, `open_session()` fails closed before verifier evidence can run.
    """

    def __init__(self, receipt_store: ReceiptStore):
        if type(receipt_store) is not ReceiptStore:
            raise NARFError("store: existing ReceiptStore required")
        self.__store = receipt_store
        self.__gate = NARFGate(receipt_store)

    def freeze_contract(
        self,
        task: dict,
        *,
        operation_id: str,
        task_id: str,
        requirements,
        effect_id: str,
        effect_version: str,
        state,
    ) -> str:
        operation_id = _canonical_uuid(operation_id, "operation_id")
        contract_id = self.__gate.freeze_contract(
            task,
            task_id=task_id,
            requirements=requirements,
            effect_id=effect_id,
            effect_version=effect_version,
            state=state,
        )
        binding_id = _binding_id(contract_id)
        self.__store.save(
            {
                "evidence_type": "narf.operation-binding",
                "evidence_version": 1,
                "producer": "host/narf-operation-binding-v1",
                "run_id": binding_id,
                "contract_id": contract_id,
                "operation_id": operation_id,
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
    ) -> OperationBoundSession:
        contract_id = _canonical_uuid(contract_id, "contract_id")
        binding_id = _binding_id(contract_id)
        binding = self.__store.load(binding_id)
        if (
            not isinstance(binding, dict)
            or set(binding)
            != {
                "evidence_type",
                "evidence_version",
                "producer",
                "run_id",
                "contract_id",
                "operation_id",
            }
            or binding.get("evidence_type") != "narf.operation-binding"
            or binding.get("evidence_version") != 1
            or binding.get("producer") != "host/narf-operation-binding-v1"
            or binding.get("run_id") != binding_id
            or binding.get("contract_id") != contract_id
        ):
            raise NARFError("operation: authenticated binding required")
        operation_id = _canonical_uuid(binding.get("operation_id"), "operation_id")

        session = self.__gate.open_session(
            contract_id,
            task,
            verifier_bindings=verifier_bindings,
            effect_binding=effect_binding,
            state_probe=state_probe,
            revocation_probe=revocation_probe,
        )
        return OperationBoundSession(session, contract_id, operation_id)


class OperationBoundEffectExecutor:
    """Consume stable operation authority before entering the NARF effect.

    The caller does not supply a consumption token. The token comes only from
    the authenticated operation binding recovered by `OperationBoundGate`.
    """

    def __init__(self, authority: ConsumptionAuthority):
        if not isinstance(authority, ConsumptionAuthority):
            raise NARFError("effect: ConsumptionAuthority required")
        self.authority = authority

    def execute(self, session: OperationBoundSession):
        if type(session) is not OperationBoundSession:
            raise NARFError("effect: OperationBoundSession required")
        try:
            decision = session.finalize()
        except Exception as error:
            if isinstance(error, NARFError):
                raise
            raise NARFError("effect: decision revalidation unavailable") from error
        if not isinstance(decision, dict) or decision.get("result") != "PASS":
            raise NARFError("effect: authenticated PASS required")

        # The stable operation identity, not the fresh contract UUID, is the
        # external single-use token. Never release an uncertain reservation.
        self.authority.reserve(session.operation_id)
        return session.execute_effect()
