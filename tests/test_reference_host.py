import tempfile
import unittest
from pathlib import Path

from narf import NARFError, Requirement, VerifierBinding, VerifierResult
from narf.reference_host import TrustedFileHost


class ReferenceHostIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="narf-reference-host-")
        self.addCleanup(self.tmp.cleanup)
        self.host = TrustedFileHost(Path(self.tmp.name), b"h" * 32)
        self.requirements = (
            Requirement("unit", "host-unit", "1"),
            Requirement("policy", "host-policy", "1"),
        )

    def bindings(self, statuses=("PASS", "PASS")):
        out = []
        for requirement, status in zip(self.requirements, statuses):
            def produce(selected=status, name=requirement.requirement_id):
                return VerifierResult(selected, ("artifact:" + name).encode())
            out.append(VerifierBinding(requirement.verifier_id, requirement.verifier_version, produce))
        return tuple(out)

    def prepare(self, payload=b"approved payload", statuses=("PASS", "PASS")):
        self.host.prepare(
            {"description": "publish approved payload", "project": "reference-host"},
            task_id="reference-host",
            candidate=b"candidate-v1",
            policy=b"policy-v1",
            requirements=self.requirements,
            verifier_bindings=self.bindings(statuses),
            effect_name="published.bin",
            payload=payload,
        )

    def test_verified_effect_writes_frozen_payload_once(self):
        payload = bytearray(b"approved payload")
        self.prepare(payload=payload)
        payload[:] = b"mutated payload!"
        self.assertEqual(self.host.verify()["result"], "PASS")
        target = Path(self.host.commit())
        self.assertEqual(target.read_bytes(), b"approved payload")
        with self.assertRaises(NARFError):
            self.host.commit()

    def test_revocation_after_pass_blocks_file_effect(self):
        self.prepare()
        self.assertEqual(self.host.verify()["result"], "PASS")
        self.host.revoke()
        with self.assertRaises(NARFError):
            self.host.commit()
        self.assertFalse(self.host.target.exists())

    def test_candidate_change_after_pass_blocks_file_effect(self):
        self.prepare()
        self.assertEqual(self.host.verify()["result"], "PASS")
        self.host.replace_candidate(b"candidate-v2")
        with self.assertRaises(NARFError):
            self.host.commit()
        self.assertFalse(self.host.target.exists())

    def test_failed_verifier_never_writes_file(self):
        self.prepare(statuses=("FAIL", "PASS"))
        self.assertEqual(self.host.verify()["result"], "FAIL")
        with self.assertRaises(NARFError):
            self.host.commit()
        self.assertFalse(self.host.target.exists())


if __name__ == "__main__":
    unittest.main()
