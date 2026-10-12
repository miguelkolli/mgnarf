"""PostgreSQL-backed fencing authority and enforcing reference target.

This module is Layer C for the fenced-effect design. It demonstrates one
concrete deployment class where fence issuance, authority transitions, and the
external effect commit share one PostgreSQL serialization domain.

The stronger guarantee is intentionally narrow: it applies only when the
configured PostgreSQL target validates the current authority generation and
fence sequence in the same transaction that commits the effect.
"""
from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

from .fenced_effect import FenceToken, FencingAuthority
from .gate import NARFError

_TABLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}")
_SCOPE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}")


def _table(value: object, label: str) -> str:
    if type(value) is not str or _TABLE_RE.fullmatch(value) is None:
        raise NARFError(f"{label}: invalid PostgreSQL table")
    return value


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


class PostgresFencingAuthority(FencingAuthority):
    """Issue monotonic fences from one PostgreSQL scope row.

    Runtime schema creation is deliberately out of scope. The issuer role should
    have SELECT on the scope row, UPDATE only on ``fence_sequence``, and
    INSERT/SELECT on the issuance ledger. It should not be able to change
    ``authority_revision``.
    """

    def __init__(
        self,
        dsn: str,
        *,
        authority_id: str = "postgres-fencing-authority.v1",
        scope_table: str = "narf_fence_scopes",
        issuance_table: str = "narf_fence_issuance",
        connect_timeout_seconds: int = 3,
    ):
        self._domain_identity = _postgres_domain_identity(dsn)
        self._dsn = dsn
        self._authority_id = _identifier(authority_id, "fencing_authority_id")
        self.scope_table = _table(scope_table, "scope_table")
        self.issuance_table = _table(issuance_table, "issuance_table")
        if type(connect_timeout_seconds) is not int or not 1 <= connect_timeout_seconds <= 30:
            raise NARFError("fence: invalid PostgreSQL connect timeout")
        self.connect_timeout_seconds = connect_timeout_seconds

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
        try:
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"SELECT authority_revision, fence_sequence "
                        f"FROM {self.scope_table} WHERE scope_id = %s FOR UPDATE",
                        (scope,),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        raise NARFError("fence: unknown scope")
                    current_revision = int(row[0])
                    current_sequence = int(row[1])
                    if current_revision != expected_authority_revision:
                        raise NARFError("fence: authority revision changed")
                    next_sequence = current_sequence + 1
                    cursor.execute(
                        f"UPDATE {self.scope_table} SET fence_sequence = %s "
                        "WHERE scope_id = %s RETURNING fence_sequence",
                        (next_sequence, scope),
                    )
                    updated = cursor.fetchone()
                    if updated is None or int(updated[0]) != next_sequence:
                        raise NARFError("fence: sequence update failed")
                    cursor.execute(
                        f"INSERT INTO {self.issuance_table} "
                        "(scope_id, fence_sequence, operation_id, authority_revision, "
                        "effect_id, effect_version, authority_id) "
                        "VALUES (%s, %s, %s::uuid, %s, %s, %s, %s)",
                        (
                            scope,
                            next_sequence,
                            operation_id,
                            expected_authority_revision,
                            effect_id,
                            effect_version,
                            self.authority_id,
                        ),
                    )
        except NARFError:
            raise
        except Exception:
            raise NARFError("fence: PostgreSQL issuance transaction failed") from None
        finally:
            try:
                connection.close()
            except Exception:
                pass

        return FenceToken(
            fence_scope_id=scope,
            operation_id=operation_id,
            authority_revision=expected_authority_revision,
            effect_id=effect_id,
            effect_version=effect_version,
            fence_sequence=next_sequence,
            authority_id=self.authority_id,
        )


class PostgresFenceControlPlane:
    """Advance the authority generation independently from effect issuance.

    The control-plane role should be allowed to UPDATE ``authority_revision`` but
    not ``fence_sequence`` or effect rows. Advancing the revision serializes on
    the same scope row used by issuance and target commit.
    """

    def __init__(
        self,
        dsn: str,
        *,
        scope_table: str = "narf_fence_scopes",
        connect_timeout_seconds: int = 3,
    ):
        self._domain_identity = _postgres_domain_identity(dsn)
        self._dsn = dsn
        self.scope_table = _table(scope_table, "scope_table")
        if type(connect_timeout_seconds) is not int or not 1 <= connect_timeout_seconds <= 30:
            raise NARFError("fence: invalid PostgreSQL connect timeout")
        self.connect_timeout_seconds = connect_timeout_seconds

    def domain_key(self):
        return self._domain_identity

    def current_revision(self, fence_scope_id: str) -> int:
        scope = _scope(fence_scope_id)
        connection = _connect(self._dsn, self.connect_timeout_seconds)
        try:
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"SELECT authority_revision FROM {self.scope_table} WHERE scope_id = %s",
                        (scope,),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        raise NARFError("fence: unknown scope")
                    return int(row[0])
        except NARFError:
            raise
        except Exception:
            raise NARFError("fence: PostgreSQL control-plane query failed") from None
        finally:
            try:
                connection.close()
            except Exception:
                pass

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
        try:
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"SELECT authority_revision FROM {self.scope_table} "
                        "WHERE scope_id = %s FOR UPDATE",
                        (scope,),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        raise NARFError("fence: unknown scope")
                    if int(row[0]) != expected_revision:
                        raise NARFError("fence: authority revision changed")
                    cursor.execute(
                        f"UPDATE {self.scope_table} SET authority_revision = %s "
                        "WHERE scope_id = %s RETURNING authority_revision",
                        (new_revision, scope),
                    )
                    updated = cursor.fetchone()
                    if updated is None or int(updated[0]) != new_revision:
                        raise NARFError("fence: authority revision update failed")
                    return new_revision
        except NARFError:
            raise
        except Exception:
            raise NARFError("fence: PostgreSQL authority transition failed") from None
        finally:
            try:
                connection.close()
            except Exception:
                pass


class PostgresFencedTarget:
    """Reference target that enforces fence validity at PostgreSQL commit time.

    The target takes a SHARE row lock on the same scope row that issuance and
    authority transitions update. It then validates current revision, latest
    sequence, and the exact issuance record before inserting the external effect
    row in the same transaction.
    """

    def __init__(
        self,
        dsn: str,
        *,
        fence_scope_id: str,
        authority_id: str,
        effect_id: str,
        effect_version: str,
        scope_table: str = "narf_fence_scopes",
        issuance_table: str = "narf_fence_issuance",
        effect_table: str = "narf_fenced_effects",
        connect_timeout_seconds: int = 3,
    ):
        self._domain_identity = _postgres_domain_identity(dsn)
        self._dsn = dsn
        self.fence_scope_id = _scope(fence_scope_id)
        self.authority_id = _identifier(authority_id, "fencing_authority_id")
        self.effect_id = _identifier(effect_id, "effect_id")
        self.effect_version = _identifier(effect_version, "effect_version")
        self.scope_table = _table(scope_table, "scope_table")
        self.issuance_table = _table(issuance_table, "issuance_table")
        self.effect_table = _table(effect_table, "effect_table")
        if type(connect_timeout_seconds) is not int or not 1 <= connect_timeout_seconds <= 30:
            raise NARFError("fence: invalid PostgreSQL connect timeout")
        self.connect_timeout_seconds = connect_timeout_seconds

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
        try:
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"SELECT authority_revision, fence_sequence "
                        f"FROM {self.scope_table} WHERE scope_id = %s FOR SHARE",
                        (self.fence_scope_id,),
                    )
                    scope_row = cursor.fetchone()
                    if scope_row is None:
                        raise NARFError("fence target: unknown scope")
                    current_revision = int(scope_row[0])
                    current_sequence = int(scope_row[1])
                    if current_revision != token.authority_revision:
                        raise NARFError("fence target: stale authority revision")
                    if current_sequence != token.fence_sequence:
                        raise NARFError("fence target: stale fence sequence")

                    cursor.execute(
                        f"SELECT operation_id::text, authority_revision, effect_id, "
                        f"effect_version, authority_id FROM {self.issuance_table} "
                        "WHERE scope_id = %s AND fence_sequence = %s",
                        (self.fence_scope_id, token.fence_sequence),
                    )
                    issuance = cursor.fetchone()
                    expected = (
                        token.operation_id,
                        token.authority_revision,
                        token.effect_id,
                        token.effect_version,
                        token.authority_id,
                    )
                    if issuance is None or tuple(issuance) != expected:
                        raise NARFError("fence target: issuance evidence mismatch")

                    cursor.execute(
                        f"INSERT INTO {self.effect_table} "
                        "(operation_id, scope_id, fence_sequence, authority_revision, "
                        "effect_id, effect_version, payload) "
                        "VALUES (%s::uuid, %s, %s, %s, %s, %s, %s) "
                        "ON CONFLICT (operation_id) DO NOTHING RETURNING operation_id::text",
                        (
                            token.operation_id,
                            self.fence_scope_id,
                            token.fence_sequence,
                            token.authority_revision,
                            token.effect_id,
                            token.effect_version,
                            payload,
                        ),
                    )
                    inserted = cursor.fetchone()
                    if inserted is None:
                        raise NARFError("fence target: operation already committed")
                    if inserted[0] != token.operation_id:
                        raise NARFError("fence target: invalid commit result")
        except NARFError:
            raise
        except Exception:
            raise NARFError("fence target: PostgreSQL commit transaction failed") from None
        finally:
            try:
                connection.close()
            except Exception:
                pass
        return "committed"
