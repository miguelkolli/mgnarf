"""Unit boundary tests for PostgreSQL fencing adapters (no live DB required)."""
import unittest

from narf import NARFError, PostgresFenceControlPlane, PostgresFencedTarget, PostgresFencingAuthority


class PostgresFencingValidationTests(unittest.TestCase):
    def test_authority_rejects_non_postgres_dsn(self):
        with self.assertRaisesRegex(NARFError, "PostgreSQL URL DSN"):
            PostgresFencingAuthority("sqlite:///tmp/test.db")

    def test_authority_rejects_invalid_authority_id(self):
        with self.assertRaisesRegex(NARFError, "invalid identifier"):
            PostgresFencingAuthority("postgresql://u:p@localhost/db", authority_id="bad id")

    def test_authority_rejects_invalid_timeout(self):
        with self.assertRaisesRegex(NARFError, "invalid PostgreSQL connect timeout"):
            PostgresFencingAuthority("postgresql://u:p@localhost/db", connect_timeout_seconds=31)

    def test_control_plane_rejects_invalid_timeout(self):
        with self.assertRaisesRegex(NARFError, "invalid PostgreSQL connect timeout"):
            PostgresFenceControlPlane("postgresql://u:p@localhost/db", connect_timeout_seconds=0)

    def test_target_rejects_invalid_scope(self):
        with self.assertRaisesRegex(NARFError, "invalid identifier"):
            PostgresFencedTarget(
                "postgresql://u:p@localhost/db",
                fence_scope_id="bad scope",
                authority_id="authority.v1",
                effect_id="deploy",
                effect_version="1",
            )

    def test_target_rejects_invalid_effect_id(self):
        with self.assertRaisesRegex(NARFError, "invalid identifier"):
            PostgresFencedTarget(
                "postgresql://u:p@localhost/db",
                fence_scope_id="scope:a",
                authority_id="authority.v1",
                effect_id="bad effect",
                effect_version="1",
            )

    def test_domains_ignore_credentials_in_same_database(self):
        a = PostgresFencingAuthority("postgresql://a:one@LOCALHOST:5432/db")
        b = PostgresFenceControlPlane("postgresql://b:two@localhost/db")
        c = PostgresFencedTarget(
            "postgresql://c:three@localhost/db",
            fence_scope_id="scope:a",
            authority_id="authority.v1",
            effect_id="deploy",
            effect_version="1",
        )
        self.assertEqual(a.domain_key(), b.domain_key())
        self.assertEqual(b.domain_key(), c.domain_key())


if __name__ == "__main__":
    unittest.main()
