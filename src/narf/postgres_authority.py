"""PostgreSQL-backed single-use consumption authority.

This adapter intentionally keeps schema bootstrap and destructive administration
outside the runtime authority. The application role should have only INSERT and
SELECT on the ledger table. A privileged administrator is required to create,
truncate, drop or otherwise rewrite the ledger.
"""
from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

from .gate import NARFError
from .rollback_guard import ConsumptionAuthority, _canonical_uuid

_TABLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def _postgres_domain_identity(dsn: str) -> tuple[str, str, int, str]:
    if not isinstance(dsn, str) or not dsn:
        raise NARFError("effect: PostgreSQL DSN required")
    try:
        parsed = urlsplit(dsn)
        port = parsed.port or 5432
    except ValueError:
        raise NARFError("effect: invalid PostgreSQL DSN") from None
    if parsed.scheme not in {"postgres", "postgresql"} or not parsed.hostname:
        raise NARFError("effect: PostgreSQL URL DSN required")
    database = unquote(parsed.path.lstrip("/"))
    if not database or "/" in database:
        raise NARFError("effect: PostgreSQL database required")
    return ("postgresql", parsed.hostname.lower(), port, database)


class PostgresConsumptionAuthority(ConsumptionAuthority):
    """Single-use authority backed by a PostgreSQL UNIQUE/PRIMARY KEY row.

    Runtime credentials should be least-privilege: INSERT and SELECT only. The
    adapter never creates, truncates, deletes from or drops its table.
    """

    def __init__(
        self,
        dsn: str,
        *,
        table: str = "narf_consumption_ledger",
        connect_timeout_seconds: int = 3,
    ):
        self._domain_identity = _postgres_domain_identity(dsn)
        if not isinstance(table, str) or not _TABLE_RE.fullmatch(table):
            raise NARFError("effect: invalid PostgreSQL ledger table")
        if type(connect_timeout_seconds) is not int or connect_timeout_seconds < 1 or connect_timeout_seconds > 30:
            raise NARFError("effect: invalid PostgreSQL connect timeout")
        self._dsn = dsn
        self.table = table
        self.connect_timeout_seconds = connect_timeout_seconds

    def domain_key(self):
        # Deliberately ignore username, password and table name. Different
        # credentials or tables in the same database are not independent
        # rollback domains.
        return self._domain_identity

    def _connect(self):
        try:
            import psycopg
        except Exception:
            raise NARFError("effect: PostgreSQL authority driver unavailable") from None
        try:
            return psycopg.connect(
                self._dsn,
                connect_timeout=self.connect_timeout_seconds,
            )
        except Exception:
            raise NARFError("effect: PostgreSQL consumption authority unavailable") from None

    def reserve(self, token: str) -> None:
        token = _canonical_uuid(token, "consumption_token")
        connection = self._connect()
        row = None
        try:
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"INSERT INTO {self.table} (token, authority_version) "
                        "VALUES (%s::uuid, %s) "
                        "ON CONFLICT (token) DO NOTHING "
                        "RETURNING token::text",
                        (token, "narf.postgres-authority.v1"),
                    )
                    row = cursor.fetchone()
        except Exception:
            raise NARFError("effect: PostgreSQL consumption authority transaction failed") from None
        finally:
            try:
                connection.close()
            except Exception:
                pass
        if row is None:
            raise NARFError("effect: external consumption authority already consumed")
        if row[0] != token:
            raise NARFError("effect: PostgreSQL consumption authority returned invalid token")

    def is_reserved(self, token: str) -> bool:
        token = _canonical_uuid(token, "consumption_token")
        connection = self._connect()
        try:
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"SELECT 1 FROM {self.table} WHERE token = %s::uuid",
                        (token,),
                    )
                    return cursor.fetchone() is not None
        except Exception:
            raise NARFError("effect: PostgreSQL consumption authority query failed") from None
        finally:
            try:
                connection.close()
            except Exception:
                pass
