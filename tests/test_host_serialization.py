from dataclasses import replace
import threading
import unittest

from narf import EffectBinding, NARFError, sha256_bytes
from test_gate import Fixture


class HostSerializationTests(unittest.TestCase):
    def changed(self, fixture, axis):
        if axis == "revoked":
            fixture.revoked = True
        else:
            fixture.current = replace(fixture.current, **{axis: sha256_bytes(b"changed")})

    def completed(self, fixture, callback):
        session = fixture.gate.open_session(
            fixture.contract_id,
            fixture.task,
            verifier_bindings=fixture.bindings(),
            effect_binding=EffectBinding("publish", "1", callback),
            state_probe=fixture.state_probe,
            revocation_probe=fixture.revocation_probe,
        )
        for requirement in fixture.requirements:
            session.execute(requirement.requirement_id)
        self.assertEqual(session.finalize()["result"], "PASS")
        return session

    def test_changes_committed_before_guarded_effect_are_denied(self):
        for axis in ("revoked", "candidate_sha256", "requirements_sha256", "policy_sha256"):
            with self.subTest(axis=axis):
                fixture = Fixture()
                try:
                    lock = threading.RLock()
                    session = self.completed(fixture, lambda: fixture.effects.append("published"))
                    with lock:
                        self.changed(fixture, axis)
                    with lock:
                        with self.assertRaises(NARFError):
                            session.execute_effect()
                    self.assertEqual(fixture.effects, [])
                finally:
                    fixture.tmp.cleanup()

    def test_cooperating_mutator_waits_until_effect_finishes(self):
        for axis in ("revoked", "candidate_sha256", "requirements_sha256", "policy_sha256"):
            with self.subTest(axis=axis):
                fixture = Fixture()
                lock = threading.RLock()
                entered = threading.Event()
                checked = threading.Event()
                resume = threading.Event()
                errors = []
                observations = []

                def callback():
                    # BRAIN: Pause while the host still owns the authority lock.
                    entered.set()
                    if not resume.wait(5):
                        raise RuntimeError("test callback resume timeout")
                    observations.append((fixture.current, fixture.revoked))
                    fixture.effects.append("published")

                session = self.completed(fixture, callback)

                def execute():
                    try:
                        with lock:
                            session.execute_effect()
                    except Exception as error:
                        errors.append(error)

                def mutate():
                    try:
                        acquired = lock.acquire(blocking=False)
                        if acquired:
                            lock.release()
                            raise AssertionError("authority lock was not held")
                        checked.set()
                        with lock:
                            self.changed(fixture, axis)
                    except Exception as error:
                        errors.append(error)

                effect_thread = threading.Thread(target=execute, daemon=True)
                actor_thread = threading.Thread(target=mutate, daemon=True)
                try:
                    effect_thread.start()
                    self.assertTrue(entered.wait(5))
                    actor_thread.start()
                    self.assertTrue(checked.wait(5))
                    self.assertEqual(fixture.current, fixture.state)
                    self.assertFalse(fixture.revoked)
                    resume.set()
                    effect_thread.join(5)
                    actor_thread.join(5)
                    self.assertFalse(effect_thread.is_alive())
                    self.assertFalse(actor_thread.is_alive())
                    self.assertEqual(errors, [])
                    self.assertEqual(observations, [(fixture.state, False)])
                    self.assertEqual(fixture.effects, ["published"])
                    self.assertEqual(session.verdict()["result"], "BLOCKED")
                finally:
                    resume.set()
                    effect_thread.join(5)
                    if actor_thread.ident is not None:
                        actor_thread.join(5)
                    fixture.tmp.cleanup()
