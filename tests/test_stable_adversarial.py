"""Fresh post-RC2 adversarial probes for the v1.60 stable candidate.

These tests intentionally target the post-hardening merged code path rather than
RC1/RC2 history. They are self-adversarial evidence, not an independent external
security review or certification.
"""

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from narf import (
    EffectBinding,
    FrozenState,
    NARFError,
    NARFGate,
    ReceiptStore,
    Requirement,
    VerifierBinding,
    VerifierResult,
    sha256_bytes,
)
from narf.reference_host import TrustedFileHost


class StableGateAdversarialTests(unittest.TestCase):
    def _fixture(self, revocation_probe):
        tmp = tempfile.TemporaryDirectory(prefix="narf-stable-adversarial-")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        store = ReceiptStore(root / "receipts", b"a" * 32)
        gate = NARFGate(store)
        task = {"description": "stable adversarial action", "project": "mgnarf"}
        requirements = (Requirement("unit", "stable-unit", "1"),)
        state = FrozenState(
            candidate_sha256=sha256_bytes(b"stable-candidate"),
            requirements_sha256=sha256_bytes(b"stable-requirements"),
            policy_sha256=sha256_bytes(b"stable-policy"),
        )
        effects = []
        contract_id = gate.freeze_contract(
            task,
            task_id="stable-adversarial",
            requirements=requirements,
            effect_id="stable-effect",
            effect_version="1",
            state=state,
        )
        session = gate.open_session(
            contract_id,
            task,
            verifier_bindings=(
                VerifierBinding(
                    "stable-unit",
                    "1",
                    lambda: VerifierResult("PASS", b"stable-artifact"),
                ),
            ),
            effect_binding=EffectBinding(
                "stable-effect", "1", lambda: effects.append("entered") or "entered"
            ),
            state_probe=lambda: state,
            revocation_probe=revocation_probe,
        )
        return session, effects

    def test_post_pass_revocation_uncertainty_blocks_effect_entry(self):
        authority = {"value": False}
        session, effects = self._fixture(lambda _contract, _candidate: authority["value"])
        session.execute("unit")
        self.assertEqual(session.finalize()["result"], "PASS")

        authority["value"] = None
        with self.assertRaisesRegex(NARFError, "revoked"):
            session.execute_effect()
        self.assertEqual(effects, [])

    def test_every_falsey_non_boolean_revocation_value_fails_closed(self):
        for value in (None, 0, "", [], {}):
            with self.subTest(value=value):
                session, effects = self._fixture(lambda _contract, _candidate, v=value: v)
                verdict = session.verdict()
                self.assertEqual(verdict["result"], "BLOCKED")
                self.assertEqual(verdict["reason"], "REVOKED")
                self.assertEqual(effects, [])

    def test_post_pass_inhibitor_stales_decision_and_blocks_callback(self):
        session, effects = self._fixture(lambda _contract, _candidate: False)
        session.execute("unit")
        self.assertEqual(session.finalize()["result"], "PASS")

        session.inhibit("human_stop")
        with self.assertRaisesRegex(NARFError, "invalid or stale"):
            session.finalize()
        with self.assertRaisesRegex(NARFError, "invalid or stale"):
            session.execute_effect()
        self.assertEqual(effects, [])

    def test_inhibitor_cannot_retroactively_follow_consumed_effect(self):
        session, effects = self._fixture(lambda _contract, _candidate: False)
        session.execute("unit")
        self.assertEqual(session.finalize()["result"], "PASS")
        self.assertEqual(session.execute_effect(), "entered")
        with self.assertRaisesRegex(NARFError, "already consumed"):
            session.inhibit("too_late")
        self.assertEqual(effects, ["entered"])


class StableReferenceHostAdversarialTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="narf-stable-host-adversarial-")
        self.addCleanup(self.tmp.cleanup)
        self.host = TrustedFileHost(Path(self.tmp.name), b"h" * 32)
        self.requirements = (Requirement("unit", "host-unit", "1"),)

    def _prepare_pass(self, payload=b"complete approved payload"):
        self.host.prepare(
            {"description": "publish stable payload", "project": "mgnarf"},
            task_id="stable-host",
            candidate=b"stable-candidate",
            policy=b"stable-policy",
            requirements=self.requirements,
            verifier_bindings=(
                VerifierBinding(
                    "host-unit", "1", lambda: VerifierResult("PASS", b"host-artifact")
                ),
            ),
            effect_name="stable.bin",
            payload=payload,
        )
        self.assertEqual(self.host.verify()["result"], "PASS")

    def test_publish_boundary_sees_complete_temp_bytes_before_target_exists(self):
        payload = b"complete approved payload"
        self._prepare_pass(payload)
        real_link = os.link
        observations = []

        def inspect_then_link(source, target, *args, **kwargs):
            source_path = Path(source)
            target_path = Path(target)
            observations.append((source_path.read_bytes(), target_path.exists()))
            return real_link(source, target, *args, **kwargs)

        with patch("narf.reference_host.os.link", side_effect=inspect_then_link):
            target = Path(self.host.commit())

        self.assertEqual(observations, [(payload, False)])
        self.assertEqual(target.read_bytes(), payload)
        self.assertEqual(list(self.host.effects_dir.glob(".*.tmp")), [])

    def test_publish_failure_exposes_no_target_and_retry_is_consumed(self):
        self._prepare_pass()
        with patch("narf.reference_host.os.link", side_effect=OSError("publish fault")):
            with self.assertRaisesRegex(OSError, "publish fault"):
                self.host.commit()

        self.assertFalse(self.host.target.exists())
        self.assertEqual(list(self.host.effects_dir.glob(".*.tmp")), [])
        with self.assertRaisesRegex(NARFError, "already consumed"):
            self.host.commit()

    def test_preexisting_target_is_never_overwritten(self):
        self._prepare_pass()
        self.host.target.write_bytes(b"sentinel")

        with self.assertRaises(FileExistsError):
            self.host.commit()

        self.assertEqual(self.host.target.read_bytes(), b"sentinel")
        self.assertEqual(list(self.host.effects_dir.glob(".*.tmp")), [])
        with self.assertRaisesRegex(NARFError, "already consumed"):
            self.host.commit()

    def test_post_publish_directory_sync_fault_never_leaves_partial_target(self):
        payload = b"complete approved payload"
        self._prepare_pass(payload)
        real_open = os.open

        def fail_effects_directory_open(path, flags, *args, **kwargs):
            if Path(path) == self.host.effects_dir:
                raise OSError("directory sync unavailable")
            return real_open(path, flags, *args, **kwargs)

        with patch("narf.reference_host.os.open", side_effect=fail_effects_directory_open):
            with self.assertRaisesRegex(OSError, "directory sync unavailable"):
                self.host.commit()

        # Publication happened before the directory-sync acknowledgement failed.
        # The outcome is deliberately characterized as ambiguous completion, but
        # the externally visible target is complete rather than partial.
        self.assertEqual(self.host.target.read_bytes(), payload)
        self.assertEqual(list(self.host.effects_dir.glob(".*.tmp")), [])
        with self.assertRaisesRegex(NARFError, "already consumed"):
            self.host.commit()


if __name__ == "__main__":
    unittest.main()
