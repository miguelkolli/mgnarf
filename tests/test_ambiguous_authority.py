from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

from narf import (
    AllOfConsumptionAuthority,
    ConsumptionAuthority,
    NARFError,
    PostgresConsumptionAuthority,
    RollbackProtectedEffectExecutor,
    SignedWitnessAuthority,
)


class FakeSession:
    def __init__(self):
        self.effect_calls = 0

    def finalize(self):
        return {"result": "PASS"}

    def execute_effect(self):
        self.effect_calls += 1
        return "effect"


class AmbiguousAuthority(ConsumptionAuthority):
    def __init__(self):
        self.reserved = set()
        self.calls = 0

    def domain_key(self):
        return ("ambiguous-test", id(self))

    def reserve(self, token: str) -> None:
        self.calls += 1
        if token in self.reserved:
            raise NARFError("effect: external consumption authority already consumed")
        self.reserved.add(token)
        raise NARFError("effect: injected ambiguous reservation outcome")

    def is_reserved(self, token: str) -> bool:
        return token in self.reserved


class CountingAuthority(ConsumptionAuthority):
    def __init__(self):
        self.reserved = set()
        self.calls = 0

    def domain_key(self):
        return ("counting-test", id(self))

    def reserve(self, token: str) -> None:
        self.calls += 1
        if token in self.reserved:
            raise NARFError("effect: external consumption authority already consumed")
        self.reserved.add(token)

    def is_reserved(self, token: str) -> bool:
        return token in self.reserved


class DropAfterReserveHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "NARFFaultFixture/1"
    sys_version = ""

    def log_message(self, format, *args):
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length).decode("utf-8"))
        token = request["token"]
        nonce = request["nonce"]
        operation = self.path.lstrip("/")

        if operation == "reserve" and token not in self.server.tokens:
            self.server.tokens.add(token)
            self.close_connection = True
            return

        if operation == "reserve":
            result, status = "ALREADY_CONSUMED", 409
        elif operation == "status":
            result, status = ("RESERVED", 200) if token in self.server.tokens else ("AVAILABLE", 200)
        else:
            self.send_error(404)
            return

        payload = {
            "version": "narf.signed-witness.response.v1",
            "operation": operation,
            "token": token,
            "nonce": nonce,
            "domain": f"ed25519:{self.server.fingerprint}",
            "result": result,
            "head_sequence": len(self.server.tokens),
            "head_sha256": "0" * 64,
            "token_sequence": 1 if token in self.server.tokens else None,
            "token_checkpoint_sha256": "0" * 64 if token in self.server.tokens else None,
        }
        raw = json.dumps({"payload": payload, "signature": "ignored"}, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class FakeCursor:
    def __init__(self, ledger: set[str]):
        self.ledger = ledger
        self.row = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, _sql, params):
        token = params[0]
        if token in self.ledger:
            self.row = None
        else:
            self.ledger.add(token)
            self.row = (token,)

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self, ledger: set[str], lose_commit_ack: bool):
        self.ledger = ledger
        self.lose_commit_ack = lose_commit_ack

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None and self.lose_commit_ack:
            self.lose_commit_ack = False
            raise OSError("injected commit acknowledgement loss")
        return False

    def cursor(self):
        return FakeCursor(self.ledger)

    def close(self):
        return None


class AmbiguousAuthorityTests(unittest.TestCase):
    def test_all_of_never_rolls_back_uncertain_first_reservation(self):
        first = AmbiguousAuthority()
        second = CountingAuthority()
        authority = AllOfConsumptionAuthority([first, second])
        session = FakeSession()
        token = str(uuid4())

        with self.assertRaises(NARFError):
            RollbackProtectedEffectExecutor(authority).execute(token, session)
        self.assertTrue(first.is_reserved(token))
        self.assertEqual(second.calls, 0)
        self.assertEqual(session.effect_calls, 0)

        with self.assertRaises(NARFError):
            RollbackProtectedEffectExecutor(authority).execute(token, session)
        self.assertEqual(session.effect_calls, 0)
        self.assertEqual(second.calls, 0)

    def test_signed_witness_response_loss_after_reserve_fails_closed_on_retry(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), DropAfterReserveHandler)
        server.tokens = set()
        server.fingerprint = "1" * 64
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            authority = SignedWitnessAuthority(
                f"http://127.0.0.1:{server.server_address[1]}",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                timeout_seconds=1,
                allow_insecure_http=True,
            )
            authority.public_key_fingerprint = server.fingerprint
            authority._verify_signature = lambda payload, signature: None
            session = FakeSession()
            token = str(uuid4())

            with self.assertRaises(NARFError):
                RollbackProtectedEffectExecutor(authority).execute(token, session)
            self.assertIn(token, server.tokens)
            self.assertEqual(session.effect_calls, 0)

            with self.assertRaisesRegex(NARFError, "already consumed"):
                RollbackProtectedEffectExecutor(authority).execute(token, session)
            self.assertEqual(session.effect_calls, 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_postgres_commit_ack_loss_does_not_free_committed_token(self):
        ledger: set[str] = set()
        authority = PostgresConsumptionAuthority("postgresql://user:pass@localhost/narf")
        calls = 0

        def connect():
            nonlocal calls
            calls += 1
            return FakeConnection(ledger, lose_commit_ack=(calls == 1))

        authority._connect = connect
        token = str(uuid4())

        with self.assertRaisesRegex(NARFError, "transaction failed"):
            authority.reserve(token)
        self.assertIn(token, ledger)

        with self.assertRaisesRegex(NARFError, "already consumed"):
            authority.reserve(token)
        self.assertIn(token, ledger)


if __name__ == "__main__":
    unittest.main()
