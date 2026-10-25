"""RED fault-injection test for durable one-attempt D1 admission semantics."""

import unittest
from unittest.mock import patch

from narf import NARFError, ReceiptStore
from test_identity_provenance_execution_red import ProvenanceExecutionFixture


class ProvenanceAdmissionDurabilityRedTests(unittest.TestCase):
    def setUp(self):
        self.fx = ProvenanceExecutionFixture()
        self.addCleanup(self.fx.close)

    def test_reserved_d1_cannot_be_reissued_after_local_receipt_save_failure(self):
        contract_id = self.fx.freeze()
        session = self.fx.session(contract_id)
        real_save = ReceiptStore.save
        failed = False

        def fail_first_d1(store, evidence):
            nonlocal failed
            if (
                not failed
                and isinstance(evidence, dict)
                and evidence.get("evidence_type") == "narf.provenance-stage-admission"
            ):
                failed = True
                raise OSError("simulated D1 persistence failure after authority reservation")
            return real_save(store, evidence)

        with patch.object(ReceiptStore, "save", new=fail_first_d1):
            with self.assertRaises(OSError):
                session.execute("tests")

        self.assertTrue(failed)
        self.assertEqual(self.fx.calls, [])
        self.assertEqual(self.fx.evidence("narf.provenance-stage-admission"), [])
        self.assertEqual(len(self.fx.admission_authority.stage_tokens), 1)
        first_token = next(iter(self.fx.admission_authority.stage_tokens))

        # The same session/requirement is already externally admitted even
        # though the local D1 receipt could not be durably recorded. A retry
        # must reuse the same reservation token and fail closed before producer.
        with self.assertRaisesRegex(NARFError, "admission already consumed"):
            session.execute("tests")

        self.assertEqual(self.fx.calls, [])
        self.assertEqual(self.fx.admission_authority.stage_tokens, {first_token})
        self.assertEqual(self.fx.evidence("narf.provenance-stage-admission"), [])


if __name__ == "__main__":
    unittest.main()
