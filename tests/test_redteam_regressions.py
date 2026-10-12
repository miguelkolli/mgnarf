from __future__ import annotations

import base64
from dataclasses import asdict
import multiprocessing
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import tempfile
import threading
import time
import unittest
from uuid import uuid4

from narf import (
    EffectBinding,
    FrozenState,
    NARFError,
    NARFGate,
    ReceiptStore,
    Requirement,
    SignedWitnessAuthority,
    VerifierBinding,
    VerifierResult,
    canonical_json_digest,
    sha256_bytes,
)
from narf.process_host import CandidateFileHost
from narf.rollback_guard import FileConsumptionAuthority, RollbackProtectedEffectExecutor


def _fifo_probe(authority_root: str, fifo_path: str, result_queue) -> None:
    try:
        host = CandidateFileHost(authority_root, fifo_path, b"f" * 32)
        host._read_candidate()
    except NARFError:
        result_queue.put("blocked")
    except BaseException as error:  # pragma: no cover - diagnostic path
        result_queue.put(f"unexpected:{type(error).__name__}:{error}")
    else:
        result_queue.put("accepted")


class _DripHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        body = b"xxxxxxxxxxxx"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        for byte in body:
            try:
                self.wfile.write(bytes([byte]))
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                break
            time.sleep(0.30)

    def log_message(self, _format, *_args):
        return


class RedTeamRegressionTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"), "POSIX FIFO required")
    def test_fifo_candidate_rejected_without_blocking_host(self):
        with tempfile.TemporaryDirectory(prefix="narf-redteam-fifo-") as name:
            root = Path(name)
            fifo = root / "candidate.fifo"
            os.mkfifo(fifo)
            queue = multiprocessing.Queue()
            process = multiprocessing.Process(
                target=_fifo_probe,
                args=(str(root / "authority"), str(fifo), queue),
            )
            process.start()
            process.join(2.0)
            if process.is_alive():
                process.terminate()
                process.join(2.0)
                self.fail("candidate FIFO blocked the host open path")
            self.assertEqual(process.exitcode, 0)
            self.assertEqual(queue.get(timeout=1.0), "blocked")

    def test_signed_witness_timeout_is_wall_clock_bounded_for_drip_body(self):
        class Server(ThreadingHTTPServer):
            daemon_threads = True

        server = Server(("127.0.0.1", 0), _DripHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        public_key = base64.b64encode(b"\x00" * 32).decode("ascii")
        authority = SignedWitnessAuthority(
            f"http://127.0.0.1:{server.server_port}",
            public_key,
            timeout_seconds=1,
            allow_insecure_http=True,
        )
        started = time.monotonic()
        with self.assertRaisesRegex(NARFError, "signed witness unavailable"):
            authority.reserve(str(uuid4()))
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 2.0, f"witness deadline exceeded wall-clock bound: {elapsed:.3f}s")

    def test_rollback_executor_rejects_caller_contract_id_not_bound_to_session(self):
        with tempfile.TemporaryDirectory(prefix="narf-redteam-contract-") as name:
            root = Path(name)
            store = ReceiptStore(root / "receipts", b"r" * 32)
            gate = NARFGate(store)
            requirement = Requirement("required", "host-check", "1")
            state = FrozenState(
                candidate_sha256=sha256_bytes(b"candidate"),
                requirements_sha256=canonical_json_digest([asdict(requirement)]),
                policy_sha256=sha256_bytes(b"policy"),
            )
            task = {"description": "contract binding regression"}
            contract_id = gate.freeze_contract(
                task,
                task_id="contract-binding",
                requirements=[requirement],
                effect_id="publish",
                effect_version="1",
                state=state,
            )
            effects = []
            session = gate.open_session(
                contract_id,
                task,
                verifier_bindings=[
                    VerifierBinding("host-check", "1", lambda: VerifierResult("PASS", b"proof"))
                ],
                effect_binding=EffectBinding("publish", "1", lambda: effects.append("effect") or "effect"),
                state_probe=lambda: state,
            )
            session.execute("required")
            authority = FileConsumptionAuthority(root / "authority")
            executor = RollbackProtectedEffectExecutor(authority)
            attacker_id = str(uuid4())

            with self.assertRaisesRegex(NARFError, "contract/session mismatch"):
                executor.execute(attacker_id, session)
            self.assertFalse(authority.is_reserved(attacker_id))
            self.assertFalse(authority.is_reserved(contract_id))
            self.assertEqual(effects, [])

            self.assertEqual(executor.execute(contract_id, session), "effect")
            self.assertTrue(authority.is_reserved(contract_id))
            self.assertEqual(effects, ["effect"])

    def test_reported_canonical_json_collisions_remain_rejected(self):
        invalid = [
            {1: "alpha"},
            {"items": (1, 2)},
            {"value": "\ud800"},
        ]
        for value in invalid:
            with self.subTest(value=repr(value)):
                with self.assertRaises(NARFError):
                    canonical_json_digest(value)


if __name__ == "__main__":
    unittest.main()
