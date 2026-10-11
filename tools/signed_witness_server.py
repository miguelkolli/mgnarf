#!/usr/bin/env python3
"""Reference Ed25519-signed append-only witness service for CI fixtures."""
from __future__ import annotations

import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import threading
from uuid import UUID

_MAX_REQUEST_BYTES = 65536
_NONCE_RE = re.compile(r"[0-9a-f]{64}")
_SHA256_ZERO = "0" * 64


def canonical_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical_uuid(value: str) -> str:
    parsed = UUID(value)
    if str(parsed) != value:
        raise ValueError("non-canonical UUID")
    return value


def checkpoint_hash(core: dict) -> str:
    return hashlib.sha256(canonical_bytes(core)).hexdigest()


def fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class AppendOnlyLedger:
    def __init__(self, directory: Path):
        self.directory = directory.resolve()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.directory / "ledger.jsonl"
        self.lock = threading.Lock()
        self.tokens: dict[str, dict] = {}
        self.head_sequence = 0
        self.head_sha256 = _SHA256_ZERO
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        previous = _SHA256_ZERO
        expected_sequence = 1
        tokens = {}
        for line in self.path.read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            core = {
                "version": record["version"],
                "sequence": record["sequence"],
                "token": record["token"],
                "previous_checkpoint_sha256": record["previous_checkpoint_sha256"],
            }
            if core["version"] != "narf.signed-witness.checkpoint.v1":
                raise RuntimeError("invalid witness ledger version")
            if core["sequence"] != expected_sequence:
                raise RuntimeError("invalid witness ledger sequence")
            canonical_uuid(core["token"])
            if core["token"] in tokens:
                raise RuntimeError("duplicate witness token")
            if core["previous_checkpoint_sha256"] != previous:
                raise RuntimeError("invalid witness ledger chain")
            expected_hash = checkpoint_hash(core)
            if record.get("checkpoint_sha256") != expected_hash:
                raise RuntimeError("invalid witness ledger checkpoint")
            full = dict(core)
            full["checkpoint_sha256"] = expected_hash
            tokens[core["token"]] = full
            previous = expected_hash
            expected_sequence += 1
        self.tokens = tokens
        self.head_sequence = expected_sequence - 1
        self.head_sha256 = previous

    def reserve(self, token: str) -> tuple[bool, dict | None]:
        token = canonical_uuid(token)
        with self.lock:
            existing = self.tokens.get(token)
            if existing is not None:
                return False, existing
            core = {
                "version": "narf.signed-witness.checkpoint.v1",
                "sequence": self.head_sequence + 1,
                "token": token,
                "previous_checkpoint_sha256": self.head_sha256,
            }
            record = dict(core)
            record["checkpoint_sha256"] = checkpoint_hash(core)
            raw = canonical_bytes(record) + b"\n"
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(self.path, flags, 0o600)
            try:
                if os.write(fd, raw) != len(raw):
                    raise RuntimeError("short witness ledger write")
                os.fsync(fd)
            finally:
                os.close(fd)
            fsync_directory(self.directory)
            self.tokens[token] = record
            self.head_sequence = record["sequence"]
            self.head_sha256 = record["checkpoint_sha256"]
            return True, record

    def status(self, token: str) -> dict | None:
        token = canonical_uuid(token)
        with self.lock:
            return self.tokens.get(token)


class WitnessServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, ledger: AppendOnlyLedger, private_key, domain: str):
        super().__init__(address, WitnessHandler)
        self.ledger = ledger
        self.private_key = private_key
        self.domain = domain

    def envelope(self, operation: str, token: str, nonce: str, result: str, record: dict | None):
        payload = {
            "version": "narf.signed-witness.response.v1",
            "operation": operation,
            "token": token,
            "nonce": nonce,
            "domain": self.domain,
            "result": result,
            "head_sequence": self.ledger.head_sequence,
            "head_sha256": self.ledger.head_sha256,
            "token_sequence": record["sequence"] if record else None,
            "token_checkpoint_sha256": record["checkpoint_sha256"] if record else None,
        }
        signature = self.private_key.sign(canonical_bytes(payload))
        return {"payload": payload, "signature": base64.b64encode(signature).decode("ascii")}


class WitnessHandler(BaseHTTPRequestHandler):
    server_version = "NARFSignedWitness/1"
    sys_version = ""

    def log_message(self, format, *args):
        return

    def _write_json(self, status: int, value) -> None:
        raw = canonical_bytes(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path != "/health":
            self.send_error(404)
            return
        self._write_json(200, {"status": "ok", "head_sequence": self.server.ledger.head_sequence})

    def do_POST(self):
        operation = self.path.lstrip("/")
        if operation not in {"reserve", "status"}:
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if length < 1 or length > _MAX_REQUEST_BYTES:
            self.send_error(400)
            return
        try:
            request = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(request, dict):
                raise ValueError
            token = canonical_uuid(request["token"])
            nonce = request["nonce"]
            if request.get("version") != "narf.signed-witness.request.v1" or request.get("operation") != operation or not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce):
                raise ValueError
        except Exception:
            self.send_error(400)
            return

        if operation == "reserve":
            try:
                created, record = self.server.ledger.reserve(token)
            except Exception:
                self.send_error(500)
                return
            if created:
                self._write_json(201, self.server.envelope(operation, token, nonce, "RESERVED", record))
            else:
                self._write_json(409, self.server.envelope(operation, token, nonce, "ALREADY_CONSUMED", record))
            return

        record = self.server.ledger.status(token)
        result = "RESERVED" if record is not None else "AVAILABLE"
        self._write_json(200, self.server.envelope(operation, token, nonce, result, record))


def load_private_key(path: Path):
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except Exception:
        raise RuntimeError("cryptography is required for signed witness service") from None
    raw = base64.b64decode(path.read_text(encoding="ascii").strip().encode("ascii"), validate=True)
    if len(raw) != 32:
        raise RuntimeError("invalid witness private key")
    return Ed25519PrivateKey.from_private_bytes(raw)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--ledger-directory", type=Path, required=True)
    parser.add_argument("--private-key-file", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    args = parser.parse_args()

    private_key = load_private_key(args.private_key_file)
    from cryptography.hazmat.primitives import serialization
    public_raw = private_key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    fingerprint = hashlib.sha256(public_raw).hexdigest()
    ledger = AppendOnlyLedger(args.ledger_directory)
    server = WitnessServer((args.host, args.port), ledger, private_key, f"ed25519:{fingerprint}")

    ready = {
        "host": args.host,
        "port": server.server_address[1],
        "public_key_base64": base64.b64encode(public_raw).decode("ascii"),
        "public_key_fingerprint": fingerprint,
    }
    args.ready_file.write_text(json.dumps(ready, sort_keys=True) + "\n", encoding="utf-8")
    args.ready_file.chmod(0o600)
    fsync_directory(args.ready_file.parent)
    server.serve_forever(poll_interval=0.1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
