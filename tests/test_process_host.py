import tempfile
from pathlib import Path
import unittest

from narf import NARFError, Requirement, VerifierResult
from narf.process_host import CandidateFileHost, CandidateVerifier


class CandidateFileHostTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="narf-process-host-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.candidate = self.root / "candidate.bin"
        self.candidate.write_bytes(b"approved:v1")
        self.host = CandidateFileHost(self.root / "authority", self.candidate, b"h" * 32)
        self.requirements = (
            Requirement("shape", "shape-check", "1"),
            Requirement("policy", "policy-check", "1"),
        )
        self.verifiers = (
            CandidateVerifier("shape-check", "1", self.shape_check),
            CandidateVerifier("policy-check", "1", self.policy_check),
        )

    def shape_check(self, candidate):
        return VerifierResult("PASS" if candidate.startswith(b"approved:") else "FAIL", candidate)

    def policy_check(self, candidate):
        return VerifierResult("FAIL" if b"DENY" in candidate else "PASS", b"policy:" + candidate)

    def prepare(self, effect_name="published.bin"):
        return self.host.prepare(
            {"description": "worker candidate publish"},
            task_id="worker-candidate",
            policy=b"policy-v1",
            requirements=self.requirements,
            verifiers=self.verifiers,
            effect_name=effect_name,
        )

    def test_worker_candidate_passes_and_frozen_bytes_are_written(self):
        self.prepare()
        self.assertEqual(self.host.verify()["result"], "PASS")
        self.assertEqual(Path(self.host.commit()).read_bytes(), b"approved:v1")
        self.assertEqual(self.host.target.read_bytes(), b"approved:v1")

    def test_candidate_drift_after_pass_blocks_effect(self):
        self.prepare()
        self.assertEqual(self.host.verify()["result"], "PASS")
        self.candidate.write_bytes(b"approved:v2")
        with self.assertRaisesRegex(NARFError, "candidate_changed"):
            self.host.commit()
        self.assertFalse(self.host.target.exists())

    def test_candidate_change_during_verification_fails_closed(self):
        def mutating_check(candidate):
            self.candidate.write_bytes(b"approved:changed")
            return VerifierResult("PASS", candidate)

        verifiers = (
            CandidateVerifier("shape-check", "1", mutating_check),
            CandidateVerifier("policy-check", "1", self.policy_check),
        )
        self.host.prepare(
            {"description": "worker candidate publish"}, task_id="worker-candidate",
            policy=b"policy-v1", requirements=self.requirements, verifiers=verifiers,
            effect_name="published.bin",
        )
        with self.assertRaises(NARFError):
            self.host.verify()
        self.assertFalse(self.host.target.exists())

    def test_failed_host_verifier_never_writes_effect(self):
        self.candidate.write_bytes(b"DENY")
        self.prepare()
        self.assertEqual(self.host.verify()["result"], "FAIL")
        with self.assertRaises(NARFError):
            self.host.commit()
        self.assertFalse(self.host.target.exists())

    def test_symlink_candidate_is_rejected(self):
        actual = self.root / "actual.bin"
        actual.write_bytes(b"approved:v1")
        link = self.root / "candidate-link.bin"
        link.symlink_to(actual)
        host = CandidateFileHost(self.root / "authority-2", link, b"j" * 32)
        with self.assertRaisesRegex(NARFError, "candidate"):
            host.prepare(
                {"description": "symlink"}, task_id="symlink",
                policy=b"policy-v1", requirements=self.requirements,
                verifiers=self.verifiers, effect_name="published.bin",
            )


if __name__ == "__main__":
    unittest.main()
