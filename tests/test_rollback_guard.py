import tempfile
from pathlib import Path
import unittest
from uuid import uuid4

from narf import NARFError
from narf.rollback_guard import FileConsumptionAuthority, RollbackProtectedEffectExecutor


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


if __name__ == "__main__":
    unittest.main()
