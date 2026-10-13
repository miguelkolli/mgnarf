"""Verifier-only RED probe for the effect admission post-check race.

The frozen v4 design requires ordinary MGnarf state/currentness and the
single-use effect authorization reservation to share one linearized admission
boundary. This test forces a state transition after the runtime-supplied
admission_check returns but before the trusted authority consumes the effect
token. If that transition wins first, the callback must not run.
"""

import unittest

from narf import FrozenState, NARFError, sha256_bytes
from test_identity_provenance_execution_red import (
    MemoryProvenanceAdmissionAuthority,
    ProvenanceExecutionFixture,
)


class PostCheckStateTransitionAuthority(MemoryProvenanceAdmissionAuthority):
    """Authority that deterministically opens the post-check/pre-reserve window."""

    def reserve_effect(
        self,
        token,
        *,
        expected_snapshot_sha256,
        expected_revision,
        admission_check,
    ):
        with self.lock:
            self._require_current(expected_snapshot_sha256, expected_revision)
            admission_check()

            # Ordinary MGnarf state changes after the callback-based state check
            # but before the effect token is reserved. Under frozen design §15,
            # this transition has won the admission race and must block effect.
            self.fixture.current_state = FrozenState(
                candidate_sha256=sha256_bytes(b"post-check-race-candidate"),
                requirements_sha256=self.fixture.state.requirements_sha256,
                policy_sha256=self.fixture.state.policy_sha256,
            )

            if token in self.effect_tokens:
                raise NARFError("provenance: effect admission already consumed")
            self.effect_tokens.add(token)


class ProvenanceEffectPostCheckRaceReviewTests(unittest.TestCase):
    def setUp(self):
        self.fx = ProvenanceExecutionFixture()
        self.addCleanup(self.fx.close)

    def test_state_transition_after_admission_check_before_reservation_blocks_callback(self):
        authority = PostCheckStateTransitionAuthority(self.fx)
        contract_id = self.fx.freeze()
        session = self.fx.session(contract_id, admission_authority=authority)
        session.execute("tests")
        session.execute("security")
        self.assertEqual(session.finalize()["result"], "PASS")

        with self.assertRaises(NARFError):
            session.execute_effect()

        self.assertEqual(self.fx.effects, [])
        self.assertEqual(authority.effect_tokens, set())
        self.assertEqual(self.fx.evidence("narf.effect"), [])


if __name__ == "__main__":
    unittest.main()
