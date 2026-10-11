import errno
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import patch
from uuid import uuid4

from narf import NARFError
from test_gate import Fixture


ERRORS = (errno.EACCES, errno.EMFILE, errno.ENFILE, errno.ENOENT,
          errno.ENOSPC, errno.EIO, errno.EINVAL, errno.ENOTSUP)


class StoreDurabilityTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()

    def tearDown(self):
        self.fixture.tmp.cleanup()

    def fresh_fixture(self):
        self.fixture.tmp.cleanup()
        self.fixture = Fixture()

    def completed_session(self):
        session = self.fixture.session()
        for requirement in self.fixture.requirements:
            session.execute(requirement.requirement_id)
        self.assertEqual(session.finalize()["result"], "PASS")
        return session

    def directory_open_failure(self, error):
        real_open = os.open
        directory = self.fixture.store.directory

        def injected(path, flags, *args, **kwargs):
            if Path(path) == directory:
                raise OSError(error, "injected directory-open failure")
            return real_open(path, flags, *args, **kwargs)

        return patch("narf.gate.os.open", side_effect=injected)

    def sync_failure(self, error, directory):
        real_sync = os.fsync

        def injected(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode) == directory:
                raise OSError(error, "injected fsync failure")
            return real_sync(fd)

        return patch("narf.gate.os.fsync", side_effect=injected)

    def assert_burned_consumption(self, session):
        self.assertEqual(self.fixture.effects, [])
        with self.assertRaisesRegex(NARFError, "already consumed"):
            session.execute_effect()
        replay = self.completed_session()
        with self.assertRaisesRegex(NARFError, "already consumed"):
            replay.execute_effect()
        self.assertEqual(self.fixture.effects, [])

    def test_directory_open_failure_is_not_successful_save(self):
        for error in ERRORS:
            with self.subTest(errno=error):
                with self.directory_open_failure(error):
                    with self.assertRaises(NARFError):
                        self.fixture.store.save({"run_id": str(uuid4())})

    def test_directory_open_failure_blocks_effect_and_replay(self):
        for error in ERRORS:
            with self.subTest(errno=error):
                self.fresh_fixture()
                session = self.completed_session()
                with self.directory_open_failure(error):
                    with self.assertRaises(NARFError):
                        session.execute_effect()
                self.assert_burned_consumption(session)

    def test_directory_sync_failure_blocks_effect_and_replay(self):
        for error in ERRORS:
            with self.subTest(errno=error):
                self.fresh_fixture()
                session = self.completed_session()
                with self.sync_failure(error, directory=True):
                    with self.assertRaises(NARFError):
                        session.execute_effect()
                self.assert_burned_consumption(session)

    def test_file_sync_failure_blocks_effect_and_replay(self):
        for error in ERRORS:
            with self.subTest(errno=error):
                self.fresh_fixture()
                session = self.completed_session()
                with self.sync_failure(error, directory=False):
                    with self.assertRaises(OSError):
                        session.execute_effect()
                self.assert_burned_consumption(session)

    def test_failed_verifier_receipt_cannot_supply_coverage(self):
        session = self.fixture.session()
        with self.directory_open_failure(errno.EACCES):
            with self.assertRaises(NARFError):
                session.execute(self.fixture.requirements[0].requirement_id)
        verdict = session.verdict()
        self.assertEqual((verdict["result"], verdict["reason"], verdict["coverage"]),
                         ("BLOCKED", "INCOMPLETE_EVIDENCE", "0/2"))
        self.assertEqual(self.fixture.effects, [])

    def test_failed_decision_receipt_does_not_authorize_effect(self):
        session = self.fixture.session()
        for requirement in self.fixture.requirements:
            session.execute(requirement.requirement_id)
        with self.directory_open_failure(errno.EIO):
            with self.assertRaises(NARFError):
                session.finalize()
        with self.assertRaisesRegex(NARFError, "authenticated PASS required"):
            session.execute_effect()
        self.assertEqual(self.fixture.effects, [])
        self.assertEqual(session.finalize()["result"], "PASS")
        session.execute_effect()
        self.assertEqual(self.fixture.effects, ["published"])
