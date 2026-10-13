"""Adversarial same-thread reentrancy checks for ordered stage admission."""

from pathlib import Path
import tempfile
import unittest

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


class StageOrderReentrancyTests(unittest.TestCase):
    def test_same_stage_reentrant_call_is_blocked_before_second_producer_entry(self):
        tmp = tempfile.TemporaryDirectory(prefix="narf-stage-order-reentrant-")
        self.addCleanup(tmp.cleanup)
        store = ReceiptStore(Path(tmp.name), b"r" * 32)
        gate = NARFGate(store)
        task = {"description": "reentrant ordered stage"}
        state = FrozenState(
            sha256_bytes(b"candidate"),
            sha256_bytes(b"requirements"),
            sha256_bytes(b"policy"),
        )
        contract_id = gate.freeze_contract(
            task,
            task_id="reentrant-stage",
            requirements=[Requirement("tests", "check", "1")],
            effect_id="publish",
            effect_version="1",
            state=state,
            stage_order=["tests"],
        )

        calls = []
        nested_errors = []
        holder = {}

        def producer():
            calls.append("tests")
            if len(calls) == 1:
                try:
                    holder["session"].execute("tests")
                except Exception as error:
                    nested_errors.append(type(error).__name__)
            return VerifierResult("PASS", b"tests")

        session = gate.open_session(
            contract_id,
            task,
            verifier_bindings=[VerifierBinding("check", "1", producer)],
            effect_binding=EffectBinding("publish", "1", lambda: None),
            state_probe=lambda: state,
        )
        holder["session"] = session

        result = session.execute("tests")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(calls, ["tests"])
        self.assertEqual(nested_errors, ["NARFError"])
        self.assertEqual(session.finalize()["result"], "PASS")


if __name__ == "__main__":
    unittest.main()
