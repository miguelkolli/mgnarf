"""Database-enforced PostgreSQL fencing reference adapters.

Layer C moves the security-critical serialization into SECURITY DEFINER database
functions. Runtime roles receive only EXECUTE on their intended function; they
do not need direct DML authority over fencing or effect state.

The stronger guarantee remains deployment-specific: the supplied SQL functions,
role grants, PostgreSQL transaction semantics, and protection of the function
owner are all part of the measured trust boundary.
"""
from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

from .fenced_effect import FenceToken, FencingAuthority
from .gate import NARFError

_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}")
_SCOPE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}")


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or _IDENTIFIER_RE.fullmatch(value) is None:
        raise NARFError(f"{label}: invalid identifier")
    return value


def _scope(value: object) -> str:
    if type(value) is not str or _SCOPE_RE.fullmatch(value) is None:
        raise NARFError("fence_scope_id: invalid identifier")
    return value


def _postgres_domain_identity(dsn: str) -> tuple[str, str, int, str]:
    if not isinstance(dsn, str) or not dsn:
        raise NARFError("fence: PostgreSQL DSN required")
    try:
        parsed = urlsplit(dsn)
        port = parsed.port or 5432
    except ValueError:
        raise NARFError("fence: invalid PostgreSQL DSN") from None
    if parsed.scheme not in {"postgres", "postgresql"} or not parsed.hostname:
        raise NARFError("fence: PostgreSQL URL DSN required")
    database = unquote(parsed.path.lstrip("/"))
    if not database or "/" in database:
        raise NARFError("fence: PostgreSQL database required")
    return ("postgresql", parsed.hostname.lower(), port, database)


def _connect(dsn: str, timeout: int):
    try:
        import psycopg
    except Exception:
        raise NARFError("fence: PostgreSQL driver unavailable") from None
    try:
        return psycopg.connect(dsn, connect_timeout=timeout)
    except Exception:
        raise NARFError("fence: PostgreSQL service unavailable") from None


def _validate_timeout(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 30:
        raise NARFError("fence: invalid PostgreSQL connect timeout")
    return value


def _validate_token(token: object) -> FenceToken:
    if type(token) is not FenceToken:
        raise NARFError("fence target: FenceToken required")
    _scope(token.fence_scope_id)
    _identifier(token.effect_id, "fence_effect_id")
    _identifier(token.effect_version, "fence_effect_version")
    _identifier(token.authority_id, "fence_authority_id")
    if type(token.authority_revision) is not int or token.authority_revision < 0:
        raise NARFError("fence target: invalid authority revision")
    if type(token.fence_sequence) is not int or token.fence_sequence < 1:
        raise NARFError("fence target: invalid sequence")
    if type(token.operation_id) is not str or not token.operation_id:
        raise NARFError("fence target: invalid operation id")
    return token


def _known_database_error(error: Exception, *, target: bool = False) -> NARFError | None:
    text = str(error)
    if "narf: unknown scope" in text:
        return NARFError("fence target: unknown scope" if target else "fence: unknown scope")
    if "narf: authority revision changed" in text:
        return NARFError("fence: authority revision changed")
    if "narf: stale authority revision" in text:
        return NARFError("fence target: stale authority revision")
    if "narf: stale fence sequence" in text:
        return NARFError("fence target: stale fence sequence")
    if "narf: issuance evidence mismatch" in text:
        return NARFError("fence target: issuance evidence mismatch")
    if "narf: operation already committed" in text:
        return NARFError("fence target: operation already committed")
    if "narf: invalid fence request" in text:
        return NARFError("fence: invalid fence request")
    if "narf: invalid authority transition" in text:
        return NARFError("fence: invalid authority transition")
    if "narf: invalid commit request" in text:
        return NARFError("fence target: invalid commit request")
    return None


class PostgresFencingAuthority(FencingAuthority):
    """Issue a fence through ``public.narf_acquire_fence``.

    The database function owns advisory locking, revision validation, sequence
    advancement, and issuance persistence. The runtime issuer credential should
    have EXECUTE on that function, not direct UPDATE/INSERT authority over the
    fencing tables.
    """

    def __init__(
        self,
        dsn: str,
        *,
        authority_id: str = "postgres-fencing-authority.v1",
        connect_timeout_seconds: int = 3,
    ):
        self._domain_identity = _postgres_domain_identity(dsn)
        self._dsn = dsn
        self._authority_id = _identifier(authority_id, "fencing_authority_id")
        self.connect_timeout_seconds = _validate_timeout(connect_timeout_seconds)

    @property
    def authority_id(self) -> str:
        return self._authority_id

    def domain_key(self):
        return self._domain_identity

    def acquire(
        self,
        *,
        fence_scope_id: str,
        operation_id: str,
        expected_authority_revision: int,
        effect_id: str,
        effect_version: str,
    ) -> FenceToken:
        scope = _scope(fence_scope_id)
        _identifier(effect_id, "effect_id")
        _identifier(effect_version, "effect_version")
        if type(operation_id) is not str or not operation_id:
            raise NARFError("fence: invalid operation id")
        if type(expected_authority_revision) is not int or expected_authority_revision < 0:
            raise NARFError("fence: invalid expected authority revision")

        connection = _connect(self._dsn, self.connect_timeout_seconds)
        row = None
        try:
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT public.narf_acquire_fence(%s, %s::uuid, %s, %s, %s, %s)",
                        (
                            scope,
                            operation_id,
                            expected_authority_revision,
                            effect_id,
                            effect_version,
                            self.authority_id,
                        ),
                    )
                    row = cursor.fetchone()
        except Exception as error:
            known = _known_database_error(error)
            if known is not None:
                raise known from None
            raise NARFError("fence: PostgreSQL issuance transaction failed") from None
        finally:
            try:
                connection.close()
            except Exception:
                pass

        if row is None or type(row[0]) is not int or row[0] < 1:
            raise NARFError("fence: PostgreSQL issuance returned invalid sequence")
        return FenceToken(
            fence_scope_id=scope,
            operation_id=operation_id,
            authority_revision=expected_authority_revision,
            effect_id=effect_id,
            effect_version=effect_version,
            fence_sequence=row[0],
            authority_id=self.authority_id,
        )


class PostgresFenceControlPlane:
    """Read/advance the authority generation through database-owned functions."""

    def __init__(self, dsn: str, *, connect_timeout_seconds: int = 3):
        self._domain_identity = _postgres_domain_identity(dsn)
        self._dsn = dsn
        self.connect_timeout_seconds = _validate_timeout(connect_timeout_seconds)

    def domain_key(self):
        return self._domain_identity

    def current_revision(self, fence_scope_id: str) -> int:
        scope = _scope(fence_scope_id)
        connection = _connect(self._dsn, self.connect_timeout_seconds)
        row = None
        try:
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT public.narf_current_fence_revision(%s)",
                        (scope,),
                    )
                    row = cursor.fetchone()
        except Exception as error:
            known = _known_database_error(error)
            if known is not None:
                raise known from None
            raise NARFError("fence: PostgreSQL control-plane query failed") from None
        finally:
            try:
                connection.close()
            except Exception:
                pass
        if row is None or type(row[0]) is not int or row[0] < 0:
            raise NARFError("fence: PostgreSQL control-plane returned invalid revision")
        return row[0]

    def advance(
        self,
        fence_scope_id: str,
        *,
        expected_revision: int,
        new_revision: int,
    ) -> int:
        scope = _scope(fence_scope_id)
        if type(expected_revision) is not int or expected_revision < 0:
            raise NARFError("fence: invalid expected authority revision")
        if type(new_revision) is not int or new_revision <= expected_revision:
            raise NARFError("fence: authority revision must advance")
        connection = _connect(self._dsn, self.connect_timeout_seconds)
        row = None
        try:
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT public.narf_advance_fence_revision(%s, %s, %s)",
                        (scope, expected_revision, new_revision),
                    )
                    row = cursor.fetchone()
        except Exception as error:
            known = _known_database_error(error)
            if known is not None:
                raise known from None
            raise NARFError("fence: PostgreSQL authority transition failed") from None
        finally:
            try:
                connection.close()
            except Exception:
                pass
        if row is None or row[0] != new_revision:
            raise NARFError("fence: PostgreSQL authority transition returned invalid revision")
        return new_revision


class PostgresFencedTarget:
    """Commit through ``public.narf_commit_fenced_effect``.

    The target runtime credential should have EXECUTE only on the commit
    function. The SECURITY DEFINER function validates current revision, current
    fence sequence, and exact issuance evidence under the same transaction-scoped
    advisory lock used by issuance and authority transitions, then inserts the
    measured external effect before the transaction commits.
    """

    def __init__(
        self,
        dsn: str,
        *,
        fence_scope_id: str,
        authority_id: str,
        effect_id: str,
        effect_version: str,
        connect_timeout_seconds: int = 3,
    ):
        self._domain_identity = _postgres_domain_identity(dsn)
        self._dsn = dsn
        self.fence_scope_id = _scope(fence_scope_id)
        self.authority_id = _identifier(authority_id, "fencing_authority_id")
        self.effect_id = _identifier(effect_id, "effect_id")
        self.effect_version = _identifier(effect_version, "effect_version")
        self.connect_timeout_seconds = _validate_timeout(connect_timeout_seconds)

    def domain_key(self):
        return self._domain_identity

    def commit(self, token: FenceToken, payload: str = "effect") -> str:
        token = _validate_token(token)
        if type(payload) is not str or len(payload) > 10000:
            raise NARFError("fence target: invalid payload")
        if (
            token.fence_scope_id != self.fence_scope_id
            or token.authority_id != self.authority_id
            or token.effect_id != self.effect_id
            or token.effect_version != self.effect_version
        ):
            raise NARFError("fence target: token binding mismatch")

        connection = _connect(self._dsn, self.connect_timeout_seconds)
        row = None
        try:
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT public.narf_commit_fenced_effect("
                        "%s, %s::uuid, %s, %s, %s, %s, %s, %s)",
                        (
                            self.fence_scope_id,
                            token.operation_id,
                            token.authority_revision,
                            token.fence_sequence,
                            token.effect_id,
                            token.effect_version,
                            token.authority_id,
                            payload,
                        ),
                    )
                    row = cursor.fetchone()
        except Exception as error:
            known = _known_database_error(error, target=True)
            if known is not None:
                raise known from None
            raise NARFError("fence target: PostgreSQL commit transaction failed") from None
        finally:
            try:
                connection.close()
            except Exception:
                pass

        if row is None or str(row[0]) != token.operation_id:
            raise NARFError("fence target: invalid commit result")
        return "committed"
