import unittest

from narf import AllOfConsumptionAuthority, NARFError, PostgresConsumptionAuthority


class PostgresAuthorityConfigTests(unittest.TestCase):
    def test_requires_postgresql_url_dsn(self):
        with self.assertRaisesRegex(NARFError, "PostgreSQL URL DSN required"):
            PostgresConsumptionAuthority("host=localhost dbname=narf")

    def test_rejects_invalid_table_identifier(self):
        with self.assertRaisesRegex(NARFError, "invalid PostgreSQL ledger table"):
            PostgresConsumptionAuthority(
                "postgresql://user:secret@db.example:5432/narf",
                table="ledger;drop table x",
            )

    def test_domain_identity_ignores_credentials_and_table(self):
        first = PostgresConsumptionAuthority(
            "postgresql://first:secret-a@db.example:5432/narf",
            table="ledger_a",
        )
        second = PostgresConsumptionAuthority(
            "postgresql://second:secret-b@db.example:5432/narf",
            table="ledger_b",
        )
        self.assertEqual(first.domain_key(), second.domain_key())
        with self.assertRaisesRegex(NARFError, "duplicate consumption authority domain"):
            AllOfConsumptionAuthority([first, second])

    def test_different_databases_are_distinct_logical_domains(self):
        first = PostgresConsumptionAuthority("postgresql://user:secret@db.example/narf_a")
        second = PostgresConsumptionAuthority("postgresql://user:secret@db.example/narf_b")
        self.assertNotEqual(first.domain_key(), second.domain_key())


if __name__ == "__main__":
    unittest.main()
