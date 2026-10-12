"""Opt-in fenced-effect transport for the composed MGnarf host path.

This module implements the Layer A/B contract from FENCED-EFFECT-BOUNDARY.md:
MGnarf binds a fence scope, reserves the stable semantic operation before fence
issuance, validates a trusted fencing-authority token, persists authenticated
fence evidence, and transports that exact token into a fenced effect adapter.

It does not by itself prove that an arbitrary external target rejects stale
fences at commit. That stronger claim requires a target/authority integration
that enforces the fence at the external commit boundary.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Callable
from uuid import NAMESPACE_URL, UUID, uuid5

from .authority_revision import AuthorityRevisionGate
from .gate import EffectBinding, NARFError, ReceiptStore
from .rollback_guard import ConsumptionAuthority

_SCOPE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}")
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}")


def _canonical_uuid(value: str, label: str) -> str:
    try:
        parsed = UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise NARFError(f"{label}: invalid UUID") from None
    if str(parsed) != value:
        raise NARFError(f"{label}: invalid UUID")
    return value


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or _IDENTIFIER_RE.fullmatch(value) is None:
        raise NARFError(f"{label}: invalid identifier")
    return value


def _scope(value: object) -> str:
    if type(value) is not str or _SCOPE_RE.fullmatch(value) is None:
        raise NARFError("fence_scope_id: invalid identifier")
    return value


def _operation_binding_id(contract_id: str) -> str:
    contract_id = _canonical_uuid(contract_id, "contract_id")
    return str(uuid5(NAMESPACE_URL, "narf.operation-binding.v1:" + contract_id))


def _fence_receipt_id(session_id: str) -> str:
    session_id = _canonical_uuid(session_id, "session_id")
    return str(uuid5(NAMESPACE_URL, "narf.fence-evidence.v1:" + session_id))


@dataclass(frozen=True)
class FenceToken:
    """Trusted fencing-authority result transported to the external adapter."""

    fence_scope_id: str
    operation_id: str
    authority_revision: int
    effect_id: str
    effect_version: str
    fence_sequence: int
    authority_id: str
    authenticator: str | None = None


@dataclass(frozen=True)
class FencedEffectBinding:
    """Effect adapter that must pass the fence to an enforcing target."""

    effect_id: str
    effect_version: str
    fence_scope_id: str
    execute: Callable[[FenceToken], object]


class FencingAuthority:
    """Trusted-host fence issuance interface.

    Implementations own monotonic ordering and the relationship between fence
    issuance and the authority revision. A returned token is still validated by
    the executor before it is persisted or transported.
    """

    @property
    def authority_id(self) -> str:
        raise NotImplementedError

    def acquire(
        self,
        *,
        fence_scope_id: str,
        operation_id: str,
        expected_authority_revision: int,
        effect_id: str,
        effect_version: str,
    ) -> FenceToken:
        raise NotImplementedError

    def domain_key(self):
        return (type(self).__module__, type(self).__qualname__, id(self))


def _validate_token(token: object) -> FenceToken:
    if type(token) is not FenceToken:
        raise NARFError("fence: FenceToken required")
    _scope(token.fence_scope_id)
    _canonical_uuid(token.operation_id, "fence_operation_id")
    if type(token.authority_revision) is not int or token.authority_revision < 0:
        raise NARFError("fence: invalid authority revision")
    _identifier(token.effect_id, "fence_effect_id")
    _identifier(token.effect_version, "fence_effect_version")
    if type(token.fence_sequence) is not int or token.fence_sequence < 0:
        raise NARFError("fence: invalid sequence")
    _identifier(token.authority_id, "fence_authority_id")
    if token.authenticator is not None and (
        type(token.authenticator) is not str
        or not token.authenticator
        or len(token.authenticator) > 1024
    ):
        raise NARFError("fence: invalid authenticator")
    return token


class _FencedEffectBridge:
    """One-shot bridge from NARF's zero-arg effect callback to a fence adapter."""

    __slots__ = ("binding", "token", "used")

    def __init__(self, binding: FencedEffectBinding):
        self.binding = binding
        self.token: FenceToken | None = None
        self.used = False

    def arm(self, token: FenceToken) -> None:
        if self.token is not None or self.used:
            raise NARFError("fence: effect bridge already armed")
        self.token = token

    def execute(self):
        if self.token is None or self.used:
            raise NARFError("fence: authenticated token required")
        self.used = True
        return self.binding.execute(self.token)


class FencedOperationSession:
    """Identity/revision-bound session that requires fenced effect execution."""

    __slots__ = (
        "__session",
        "__store",
        "__operation_id",
        "__fence_scope_id",
        "__effect_id",
        "__effect_version",
        "__bridge",
    )

    def __init__(
        self,
        session,
        store: ReceiptStore,
        *,
        operation_id: str,
        fence_scope_id: str,
        effect_id: str,
        effect_version: str,
        bridge: _FencedEffectBridge,
    ):
        self.__session = session
        self.__store = store
        self.__operation_id = _canonical_uuid(operation_id, "operation_id")
        self.__fence_scope_id = _scope(fence_scope_id)
        self.__effect_id = _identifier(effect_id, "effect_id")
        self.__effect_version = _identifier(effect_version, "effect_version")
        self.__bridge = bridge

    @property
    def contract_id(self) -> str:
        return self.__session.contract_id

    @property
    def session_id(self) -> str:
        return self.__session.session_id

    @property
    def operation_id(self) -> str:
        return self.__operation_id

    @property
    def fence_scope_id(self) -> str:
        return self.__fence_scope_id

    @property
    def authority_revision(self) -> int:
        return self.__session.authority_revision

    @property
    def effect_id(self) -> str:
        return self.__effect_id

    @property
    def effect_version(self) -> str:
        return self.__effect_version

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
        raise NARFError("effect: FencedOperationEffectExecutor required")

    def _execute_with_fence(self, token: FenceToken):
        token = _validate_token(token)
        if (
            token.fence_scope_id != self.__fence_scope_id
            or token.operation_id != self.__operation_id
            or token.authority_revision != self.authority_revision
            or token.effect_id != self.__effect_id
            or token.effect_version != self.__effect_version
        ):
            raise NARFError("fence: token binding mismatch")

        receipt_id = _fence_receipt_id(self.session_id)
        evidence = {
            "evidence_type": "narf.fence",
            "evidence_version": 1,
            "producer": "host/narf-fenced-effect-v1",
            "run_id": receipt_id,
            "contract_id": self.contract_id,
            "session_id": self.session_id,
            **asdict(token),
        }
        try:
            self.__store.save(evidence)
        except FileExistsError:
            raise NARFError("fence: session token already recorded") from None
        self.__bridge.arm(token)
        return self.__session.execute_effect()


class FencedOperationGate:
    """Freeze identity/revision + stable operation + explicit fence-scope binding.

    The operation binding uses evidence version 2. The legacy OperationBoundGate
    accepts only its version-1 binding, so a fenced contract cannot accidentally
    be reopened through that convenience wrapper and lose its fence requirement.
    """

    def __init__(self, receipt_store: ReceiptStore, authority_probe):
        if type(receipt_store) is not ReceiptStore:
            raise NARFError("store: existing ReceiptStore required")
        self.__store = receipt_store
        self.__gate = AuthorityRevisionGate(receipt_store, authority_probe)

    def freeze_contract(
        self,
        task: dict,
        *,
        operation_id: str,
        fence_scope_id: str,
        task_id: str,
        requirements,
        effect_id: str,
        effect_version: str,
        state,
        identity_policy: dict,
    ) -> str:
        operation_id = _canonical_uuid(operation_id, "operation_id")
        fence_scope_id = _scope(fence_scope_id)
        effect_id = _identifier(effect_id, "effect_id")
        effect_version = _identifier(effect_version, "effect_version")

        contract_id = self.__gate.freeze_contract(
            task,
            task_id=task_id,
            requirements=requirements,
            effect_id=effect_id,
            effect_version=effect_version,
            state=state,
            identity_policy=identity_policy,
        )
        binding_id = _operation_binding_id(contract_id)
        self.__store.save(
            {
                "evidence_type": "narf.operation-binding",
                "evidence_version": 2,
                "producer": "host/narf-operation-binding-v2",
                "run_id": binding_id,
                "contract_id": contract_id,
                "operation_id": operation_id,
                "effect_mode": "fenced",
                "fence_scope_id": fence_scope_id,
                "effect_id": effect_id,
                "effect_version": effect_version,
            }
        )
        return contract_id

    def _load_binding(self, contract_id: str) -> dict:
        contract_id = _canonical_uuid(contract_id, "contract_id")
        binding_id = _operation_binding_id(contract_id)
        binding = self.__store.load(binding_id)
        expected_fields = {
            "evidence_type",
            "evidence_version",
            "producer",
            "run_id",
            "contract_id",
            "operation_id",
            "effect_mode",
            "fence_scope_id",
            "effect_id",
            "effect_version",
        }
        if (
            not isinstance(binding, dict)
            or set(binding) != expected_fields
            or binding.get("evidence_type") != "narf.operation-binding"
            or binding.get("evidence_version") != 2
            or binding.get("producer") != "host/narf-operation-binding-v2"
            or binding.get("run_id") != binding_id
            or binding.get("contract_id") != contract_id
            or binding.get("effect_mode") != "fenced"
        ):
            raise NARFError("fence: authenticated operation binding required")
        _canonical_uuid(binding.get("operation_id"), "operation_id")
        _scope(binding.get("fence_scope_id"))
        _identifier(binding.get("effect_id"), "effect_id")
        _identifier(binding.get("effect_version"), "effect_version")
        return binding

    def open_session(
        self,
        contract_id: str,
        task: dict,
        *,
        verifier_bindings,
        effect_binding: FencedEffectBinding,
        state_probe,
        revocation_probe=None,
    ) -> FencedOperationSession:
        binding = self._load_binding(contract_id)
        if (
            type(effect_binding) is not FencedEffectBinding
            or not callable(effect_binding.execute)
            or effect_binding.effect_id != binding["effect_id"]
            or effect_binding.effect_version != binding["effect_version"]
            or effect_binding.fence_scope_id != binding["fence_scope_id"]
        ):
            raise NARFError("fence: effect binding changed")

        bridge = _FencedEffectBridge(effect_binding)
        standard_binding = EffectBinding(
            binding["effect_id"],
            binding["effect_version"],
            bridge.execute,
        )
        session = self.__gate.open_session(
            contract_id,
            task,
            verifier_bindings=verifier_bindings,
            effect_binding=standard_binding,
            state_probe=state_probe,
            revocation_probe=revocation_probe,
        )
        return FencedOperationSession(
            session,
            self.__store,
            operation_id=binding["operation_id"],
            fence_scope_id=binding["fence_scope_id"],
            effect_id=binding["effect_id"],
            effect_version=binding["effect_version"],
            bridge=bridge,
        )


class FencedOperationEffectExecutor:
    """Reserve one stable operation, acquire a bound fence, then enter NARF.

    Stable operation authority is consumed before fence acquisition. Any fence
    failure, malformed result, local persistence failure, callback exception, or
    ambiguous outcome therefore leaves the semantic operation consumed rather
    than available for a blind retry.
    """

    def __init__(
        self,
        operation_authority: ConsumptionAuthority,
        fencing_authority: FencingAuthority,
    ):
        if not isinstance(operation_authority, ConsumptionAuthority):
            raise NARFError("fence: ConsumptionAuthority required")
        if not isinstance(fencing_authority, FencingAuthority):
            raise NARFError("fence: FencingAuthority required")
        self.operation_authority = operation_authority
        self.fencing_authority = fencing_authority

    def execute(self, session: FencedOperationSession):
        if type(session) is not FencedOperationSession:
            raise NARFError("fence: FencedOperationSession required")

        try:
            decision = session.finalize()
        except Exception as error:
            if isinstance(error, NARFError):
                raise
            raise NARFError("fence: decision revalidation unavailable") from error
        if not isinstance(decision, dict) or decision.get("result") != "PASS":
            raise NARFError("fence: authenticated PASS required")

        # Consume the stable real-world operation before attempting fence
        # issuance. Never release this reservation on any later uncertainty.
        self.operation_authority.reserve(session.operation_id)

        try:
            authority_id = _identifier(
                self.fencing_authority.authority_id,
                "fence_authority_id",
            )
            token = self.fencing_authority.acquire(
                fence_scope_id=session.fence_scope_id,
                operation_id=session.operation_id,
                expected_authority_revision=session.authority_revision,
                effect_id=session.effect_id,
                effect_version=session.effect_version,
            )
        except Exception as error:
            if isinstance(error, NARFError):
                raise
            raise NARFError("fence: authority unavailable") from error

        token = _validate_token(token)
        if token.authority_id != authority_id:
            raise NARFError("fence: authority binding mismatch")
        if (
            token.fence_scope_id != session.fence_scope_id
            or token.operation_id != session.operation_id
            or token.authority_revision != session.authority_revision
            or token.effect_id != session.effect_id
            or token.effect_version != session.effect_version
        ):
            raise NARFError("fence: token binding mismatch")

        return session._execute_with_fence(token)
