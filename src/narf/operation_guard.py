"""Operation-bound authorization for cross-contract idempotency.

The core NARF gate intentionally remains contract-scoped for compatibility.
This module adds a stronger trusted-host path: a stable host-owned operation
UUID is HMAC-bound to each contract, recovered from authenticated receipt
history, and used as the external consumption-authority token.

When ``authority_probe`` is configured, ``OperationBoundGate`` composes this
stable operation binding with ``AuthorityRevisionGate``. That opt-in path
therefore requires identity-bound NARF evidence plus a monotonic authority
revision before the same stable operation token may reach the external effect.
"""
from __future__ import annotations

from uuid import NAMESPACE_URL, UUID, uuid5

from .authority_revision import AuthorityRevisionGate
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

    __slots__ = ("__session", "__contract_id", "__operation_id", "__executor_required")

    def __init__(
        self,
        session,
        contract_id: str,
        operation_id: str,
        *,
        executor_required: bool = False,
    ):
        self.__session = session
        self.__contract_id = _canonical_uuid(contract_id, "contract_id")
        self.__operation_id = _canonical_uuid(operation_id, "operation_id")
        if type(executor_required) is not bool:
            raise NARFError("operation: invalid executor requirement")
        self.__executor_required = executor_required

    @property
    def contract_id(self) -> str:
        return self.__contract_id

    @property
    def operation_id(self) -> str:
        return self.__operation_id

    @property
    def authority_revision(self) -> int | None:
        """Return the composed frozen revision when revision hardening is enabled."""
        value = getattr(self.__session, "authority_revision", None)
        return value if type(value) is int else None

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
        if self.__executor_required:
            raise NARFError("effect: OperationBoundEffectExecutor required")
        return self.__session.execute_effect()

    def _execute_effect_via_executor(self):
        """Trusted package route used after stable operation reservation."""
        return self.__session.execute_effect()


class OperationBoundGate:
    """Bind a trusted-host stable operation UUID to a NARF contract.

    ``operation_id`` is semantic authority supplied by the trusted host. It must
    remain stable for retries or newly frozen contracts representing the same
    real external operation. Candidate-controlled operation IDs are outside the
    intended trust model.

    By default the class retains its historical version-1 behavior. Supplying an
    ``authority_probe`` opts into the stronger composed path: contract creation
    must also supply ``identity_policy`` and the underlying contract/session is
    created through ``AuthorityRevisionGate``. This intentionally avoids adding
    a snapshot-only identity mode to the convenience wrapper; callers wanting
    that weaker opt-in path can use ``NARFGate`` directly.

    Composed sessions also require ``OperationBoundEffectExecutor`` for effect
    entry. This prevents accidental bypass of the stable operation reservation.
    Legacy sessions keep their historical direct ``execute_effect()`` behavior
    for compatibility.

    The operation binding is stored as a separate HMAC-authenticated receipt.
    If the binding receipt is missing, tampered, rolled back, or otherwise
    invalid, ``open_session()`` fails closed before verifier evidence can run.
    """

    def __init__(self, receipt_store: ReceiptStore, *, authority_probe=None):
        if type(receipt_store) is not ReceiptStore:
            raise NARFError("store: existing ReceiptStore required")
        self.__store = receipt_store
        self.__authority_revision_enabled = authority_probe is not None
        if self.__authority_revision_enabled:
            self.__gate = AuthorityRevisionGate(receipt_store, authority_probe)
        else:
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
        identity_policy: dict | None = None,
    ) -> str:
        operation_id = _canonical_uuid(operation_id, "operation_id")
        if self.__authority_revision_enabled:
            if type(identity_policy) is not dict:
                raise NARFError("operation: identity policy required with authority probe")
            contract_id = self.__gate.freeze_contract(
                task,
                task_id=task_id,
                requirements=requirements,
                effect_id=effect_id,
                effect_version=effect_version,
                state=state,
                identity_policy=identity_policy,
            )
        else:
            if identity_policy is not None:
                raise NARFError("operation: authority probe required for identity policy")
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
        return OperationBoundSession(
            session,
            contract_id,
            operation_id,
            executor_required=self.__authority_revision_enabled,
        )


class OperationBoundEffectExecutor:
    """Consume stable operation authority before entering the NARF effect.

    The caller does not supply a consumption token. The token comes only from
    the authenticated operation binding recovered by ``OperationBoundGate``.

    In the composed authority-revision mode this ordering deliberately remains:

    decision revalidation -> stable operation reservation -> NARF effect entry.

    If the authority revision changes while the reservation is being made, the
    revision-guarded NARF effect blocks the real callback and the external
    operation reservation remains consumed. Availability is sacrificed instead
    of retrying under uncertain authority state.
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
        return session._execute_effect_via_executor()
