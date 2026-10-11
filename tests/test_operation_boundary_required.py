import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class OperationBoundaryRequiredGateTests(unittest.TestCase):
    def test_exact_operation_boundary_is_part_of_required_core_regression(self):
        with tempfile.TemporaryDirectory(prefix="narf-required-operation-bound-") as name:
            output = Path(name) / "evidence"
            env = dict(os.environ)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            process = subprocess.run(
                [
                    sys.executable,
                    "tools/test_operation_bound_authority.py",
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stdout)
            summary = json.loads((output / "summary.json").read_text())
            self.assertEqual(summary["result"], "BOUNDARY_CONFIRMED")
            self.assertEqual(summary["planned_cases"], 5)
            self.assertEqual(
                summary["counts"],
                {
                    "PASS": 4,
                    "LIMITATION_CONFIRMED": 1,
                    "FAIL": 0,
                    "UNEXPECTED": 0,
                },
            )
            self.assertTrue(summary["source_unchanged"])
            stable = next(
                row
                for row in summary["cases"]
                if row["case"] == "stable-operation-id-blocks-fresh-contract"
            )
            self.assertTrue(stable["distinct_contract_ids"])
            self.assertEqual(stable["callback_invocations"], 1)
            self.assertTrue(stable["second_blocked"])


if __name__ == "__main__":
    unittest.main()
