import tempfile
from pathlib import Path
import unittest
from uuid import uuid4

from narf import NARFError
from narf.rollback_guard import (
    AllOfConsumptionAuthority,
    FileConsumptionAuthority,
    RollbackProtectedEffectExecutor,
)


class FakeSession:
    def __init__(self, decision="PASS", effect_error=None):
        self.decision = decision
        self.effect_error = effect_error
        self.effect_calls = 0

    def finalize(self):
        return {"result": self.decision}

    def execute_effect(self):
        self.effect_calls += 1
        if self.effect_error is not None:
            raise self.effect_error
        return "effect"


class RollbackGuardTests(unittest.TestCase):
    def test_authority_is_single_use_across_instances(self):
        with tempfile.TemporaryDirectory() as name:
            token = str(uuid4())
            first = FileConsumptionAuthority(Path(name))
            first.reserve(token)
            second = FileConsumptionAuthority(Path(name))
            self.assertTrue(second.is_reserved(token))
            with self.assertRaisesRegex(NARFError, "already consumed"):
                second.reserve(token)

    def test_executor_blocks_before_second_session_effect(self):
        with tempfile.TemporaryDirectory() as name:
            token = str(uuid4())
            authority = FileConsumptionAuthority(Path(name))
            first = FakeSession()
            second = FakeSession()
            executor = RollbackProtectedEffectExecutor(authority)

            self.assertEqual(executor.execute(token, first), "effect")
            self.assertEqual(first.effect_calls, 1)
            with self.assertRaisesRegex(NARFError, "already consumed"):
                executor.execute(token, second)
            self.assertEqual(second.effect_calls, 0)

    def test_non_pass_does_not_consume_external_authority(self):
        with tempfile.TemporaryDirectory() as name:
            token = str(uuid4())
            authority = FileConsumptionAuthority(Path(name))
            executor = RollbackProtectedEffectExecutor(authority)
            session = FakeSession(decision="BLOCKED")

            with self.assertRaisesRegex(NARFError, "authenticated PASS required"):
                executor.execute(token, session)
            self.assertFalse(authority.is_reserved(token))
            self.assertEqual(session.effect_calls, 0)

    def test_effect_failure_does_not_release_reservation(self):
        with tempfile.TemporaryDirectory() as name:
            token = str(uuid4())
            authority = FileConsumptionAuthority(Path(name))
            executor = RollbackProtectedEffectExecutor(authority)
            first = FakeSession(effect_error=RuntimeError("target failed"))

            with self.assertRaisesRegex(RuntimeError, "target failed"):
                executor.execute(token, first)
            self.assertTrue(authority.is_reserved(token))

            second = FakeSession()
            with self.assertRaisesRegex(NARFError, "already consumed"):
                executor.execute(token, second)
            self.assertEqual(second.effect_calls, 0)

    def test_all_of_requires_at_least_two_distinct_authorities(self):
        with tempfile.TemporaryDirectory() as name:
            first = FileConsumptionAuthority(Path(name) / "a")
            with self.assertRaisesRegex(NARFError, "at least two"):
                AllOfConsumptionAuthority([first])
            with self.assertRaisesRegex(NARFError, "duplicate consumption authority$"):
                AllOfConsumptionAuthority([first, first])

    def test_all_of_rejects_same_file_domain_through_distinct_instances(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "same"
            first = FileConsumptionAuthority(path)
            second = FileConsumptionAuthority(path)
            with self.assertRaisesRegex(NARFError, "duplicate consumption authority domain"):
                AllOfConsumptionAuthority([first, second])

    def test_all_of_first_use_reserves_every_domain(self):
        with tempfile.TemporaryDirectory() as name:
            token = str(uuid4())
            authorities = [
                FileConsumptionAuthority(Path(name) / label)
                for label in ("a", "b", "c")
            ]
            combined = AllOfConsumptionAuthority(authorities)
            combined.reserve(token)
            self.assertEqual(combined.reservation_states(token), (True, True, True))

    def test_all_of_one_domain_rollback_still_blocks(self):
        with tempfile.TemporaryDirectory() as name:
            token = str(uuid4())
            authorities = [
                FileConsumptionAuthority(Path(name) / label)
                for label in ("a", "b", "c")
            ]
            combined = AllOfConsumptionAuthority(authorities)
            combined.reserve(token)
            authorities[0]._path(token).unlink()
            with self.assertRaisesRegex(NARFError, "already consumed"):
                combined.reserve(token)
            self.assertTrue(combined.is_reserved(token))

    def test_all_of_two_domain_rollback_still_blocks(self):
        with tempfile.TemporaryDirectory() as name:
            token = str(uuid4())
            authorities = [
                FileConsumptionAuthority(Path(name) / label)
                for label in ("a", "b", "c")
            ]
            combined = AllOfConsumptionAuthority(authorities)
            combined.reserve(token)
            authorities[0]._path(token).unlink()
            authorities[1]._path(token).unlink()
            with self.assertRaisesRegex(NARFError, "already consumed"):
                combined.reserve(token)
            self.assertEqual(combined.reservation_states(token), (True, True, True))

    def test_all_of_all_domain_rollback_exposes_remaining_boundary(self):
        with tempfile.TemporaryDirectory() as name:
            token = str(uuid4())
            authorities = [
                FileConsumptionAuthority(Path(name) / label)
                for label in ("a", "b", "c")
            ]
            combined = AllOfConsumptionAuthority(authorities)
            combined.reserve(token)
            for authority in authorities:
                authority._path(token).unlink()
            combined.reserve(token)
            self.assertEqual(combined.reservation_states(token), (True, True, True))

    def test_executor_accepts_all_of_authority_and_blocks_replay(self):
        with tempfile.TemporaryDirectory() as name:
            token = str(uuid4())
            authorities = [
                FileConsumptionAuthority(Path(name) / label)
                for label in ("a", "b", "c")
            ]
            executor = RollbackProtectedEffectExecutor(AllOfConsumptionAuthority(authorities))
            first = FakeSession()
            second = FakeSession()

            self.assertEqual(executor.execute(token, first), "effect")
            authorities[0]._path(token).unlink()
            with self.assertRaisesRegex(NARFError, "already consumed"):
                executor.execute(token, second)
            self.assertEqual(second.effect_calls, 0)


if __name__ == "__main__":
    unittest.main()
