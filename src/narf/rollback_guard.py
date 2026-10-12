"""Rollback-protected trusted-host effect execution.

The filesystem receipt store alone is not rollback resistant. This module adds
single-use consumption authorities that must live outside the receipt-store
rollback domain. A multi-domain authority can require every independent domain
to reserve the same token before NARF is allowed to enter the external effect
callback.
"""
from __future__ import annotations

import os
from pathlib import Path
from uuid import UUID

from .gate import NARFError


def _canonical_uuid(value: str, label: str) -> str:
    try:
        parsed = UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise NARFError(f"{label}: invalid UUID") from None
    if str(parsed) != value:
        raise NARFError(f"{label}: invalid UUID")
    return value


def _session_bound_contract_id(session, supplied_contract_id: str) -> str:
    """Return the contract bound inside a real NARFSession.

    NARFSession intentionally keeps its frozen contract private. The rollback
    compatibility executor lives in the same trusted package and must not let a
    caller-selected UUID choose the external single-use token. Test doubles and
    legacy structural sessions that do not expose NARFSession's frozen contract
    keep the historical supplied-token behavior; real NARF sessions are bound.
    """
    contract = getattr(session, "_NARFSession__contract", None)
    if contract is None:
        return supplied_contract_id
    if not isinstance(contract, dict):
        raise NARFError("effect: session contract binding unavailable")
    bound = _canonical_uuid(contract.get("run_id"), "session_contract_id")
    if bound != supplied_contract_id:
        raise NARFError("effect: contract/session mismatch")
    return bound


class ConsumptionAuthority:
    """Trusted-host single-use authority interface."""

    def reserve(self, token: str) -> None:
        raise NotImplementedError

    def is_reserved(self, token: str) -> bool:
        raise NotImplementedError

    def domain_key(self):
        """Best-effort identity used to reject duplicate configured domains."""
        return (type(self).__module__, type(self).__qualname__, id(self))


class FileConsumptionAuthority(ConsumptionAuthority):
    """Single-use authority stored outside the receipt rollback domain.

    The directory itself is trusted host state. Rollback resistance is obtained
    only when this directory cannot be rewound or deleted together with the
    receipt store. A second file inside the same snapshot domain is insufficient.
    """

    def __init__(self, directory: str | Path):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)

    def domain_key(self):
        return ("file", str(self.directory))

    def _path(self, token: str) -> Path:
        token = _canonical_uuid(token, "consumption_token")
        return self.directory / f"{token}.used"

    def reserve(self, token: str) -> None:
        path = self._path(token)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            raise NARFError("effect: external consumption authority already consumed") from None
        except OSError:
            raise NARFError("effect: external consumption authority unavailable") from None

        # Never delete a partially persisted reservation on failure. Losing
        # availability is safer than freeing a token whose state is uncertain.
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(b"narf.consumption-authority.v1\n" + token.encode("ascii") + b"\n")
                output.flush()
                os.fsync(output.fileno())
            try:
                dfd = os.open(self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            except OSError:
                raise NARFError("effect: external consumption authority sync unavailable") from None
            try:
                os.fsync(dfd)
            except OSError:
                raise NARFError("effect: external consumption authority sync failed") from None
            finally:
                os.close(dfd)
        except NARFError:
            raise
        except OSError:
            raise NARFError("effect: external consumption authority persistence failed") from None

    def is_reserved(self, token: str) -> bool:
        path = self._path(token)
        return os.path.lexists(path)


class AllOfConsumptionAuthority(ConsumptionAuthority):
    """Require every configured authority domain to reserve the token.

    This is deliberately all-of rather than a majority quorum. On first use all
    domains must durably reserve the token. On replay, any one preserved domain
    can veto the operation by reporting the token already consumed.

    Partial reservation is never rolled back if a later authority rejects or
    fails. This intentionally sacrifices availability to keep replay fail-closed.
    """

    def __init__(self, authorities):
        if not isinstance(authorities, (tuple, list)) or len(authorities) < 2:
            raise NARFError("effect: at least two consumption authorities required")
        frozen = tuple(authorities)
        if any(not isinstance(authority, ConsumptionAuthority) for authority in frozen):
            raise NARFError("effect: ConsumptionAuthority values required")
        if len({id(authority) for authority in frozen}) != len(frozen):
            raise NARFError("effect: duplicate consumption authority")
        try:
            domain_keys = tuple(authority.domain_key() for authority in frozen)
        except Exception:
            raise NARFError("effect: consumption authority domain identity unavailable") from None
        if len(set(domain_keys)) != len(domain_keys):
            raise NARFError("effect: duplicate consumption authority domain")
        self.authorities = frozen

    def domain_key(self):
        return ("all-of", tuple(authority.domain_key() for authority in self.authorities))

    def reserve(self, token: str) -> None:
        token = _canonical_uuid(token, "consumption_token")
        for authority in self.authorities:
            authority.reserve(token)

    def is_reserved(self, token: str) -> bool:
        token = _canonical_uuid(token, "consumption_token")
        return any(authority.is_reserved(token) for authority in self.authorities)

    def reservation_states(self, token: str) -> tuple[bool, ...]:
        token = _canonical_uuid(token, "consumption_token")
        return tuple(authority.is_reserved(token) for authority in self.authorities)


class RollbackProtectedEffectExecutor:
    """Reserve external single-use authority before entering NARF's effect."""

    def __init__(self, authority: ConsumptionAuthority):
        if not isinstance(authority, ConsumptionAuthority):
            raise NARFError("effect: ConsumptionAuthority required")
        self.authority = authority

    def execute(self, contract_id: str, session):
        supplied_contract_id = _canonical_uuid(contract_id, "contract_id")
        contract_id = _session_bound_contract_id(session, supplied_contract_id)
        try:
            decision = session.finalize()
        except Exception as error:
            if isinstance(error, NARFError):
                raise
            raise NARFError("effect: decision revalidation unavailable") from error
        if not isinstance(decision, dict) or decision.get("result") != "PASS":
            raise NARFError("effect: authenticated PASS required")

        # Reserve outside the receipt rollback domain before session.execute_effect().
        # If the following local receipt persistence or callback fails, the token
        # remains consumed: fail closed and sacrifice availability rather than replay.
        self.authority.reserve(contract_id)
        return session.execute_effect()
