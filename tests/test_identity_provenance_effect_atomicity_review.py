"""Verifier-only RED test for frozen effect-admission atomicity.

This file intentionally changes no runtime. It checks the Revision 11 frozen
boundary requirement that existing MGnarf state conditions and provenance
currentness are validated at the same linearized effect-admission point as the
single-use reservation.
"""

import unittest

from narf import FrozenState, NARFError, sha256_bytes
from test_identity_provenance_execution_red import ProvenanceExecutionFixture


class ProvenanceEffectAdmissionAtomicityReviewTests(unittest.TestCase):
    def setUp(self):
        self.fx = ProvenanceExecutionFixture()
        self.addCleanup(self.fx.close)

    def test_state_transition_winning_effect_admission_blocks_callback(self):
        _contract_id, session = self.fx.complete_pass_chain()

        def state_transition_first():
            self.fx.current_state = FrozenState(
                candidate_sha256=sha256_bytes(b"review-state-race-candidate"),
                requirements_sha256=self.fx.state.requirements_sha256,
                policy_sha256=self.fx.state.policy_sha256,
            )

        # This hook executes inside the trusted admission authority immediately
        # before its provenance currentness check/reservation. The frozen design
        # requires existing MGnarf state conditions to be part of the same
        # admission linearization. If this transition wins, the callback must
        # never be entered and no effect authorization may be consumed.
        self.fx.admission_authority.effect_before_check = state_transition_first

        with self.assertRaises(NARFError):
            session.execute_effect()

        self.assertEqual(self.fx.effects, [])
        self.assertEqual(self.fx.admission_authority.effect_tokens, set())
        self.assertEqual(self.fx.evidence("narf.effect"), [])


if __name__ == "__main__":
    unittest.main()
