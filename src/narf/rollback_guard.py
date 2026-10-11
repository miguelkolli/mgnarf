"""Rollback-protected trusted-host effect execution.

The filesystem receipt store alone is not rollback resistant. This module adds a
second single-use authority that must live outside the receipt-store rollback
domain. The authority is reserved before NARF is allowed to enter the external
effect callback.
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


class FileConsumptionAuthority:
    """Single-use authority stored outside the receipt rollback domain.

    The directory itself is trusted host state. Rollback resistance is obtained
    only when this directory cannot be rewound or deleted together with the
    receipt store. A second file inside the same snapshot domain is insufficient.
    """

    def __init__(self, directory: str | Path):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)

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


class RollbackProtectedEffectExecutor:
    """Reserve external single-use authority before entering NARF's effect."""

    def __init__(self, authority: FileConsumptionAuthority):
        if type(authority) is not FileConsumptionAuthority:
            raise NARFError("effect: FileConsumptionAuthority required")
        self.authority = authority

    def execute(self, contract_id: str, session):
        contract_id = _canonical_uuid(contract_id, "contract_id")
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
