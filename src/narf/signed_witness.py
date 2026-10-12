"""Ed25519-authenticated external single-use witness authority.

The witness is a separate consumption authority. Its signing key authenticates
responses but does not make witness storage monotonic: rollback of the witness's
own ledger remains a separate deployment threat.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import io
import json
import re
import secrets
import time
from urllib.parse import urlsplit

from .gate import NARFError
from .rollback_guard import ConsumptionAuthority, _canonical_uuid

_NONCE_RE = re.compile(r"[0-9a-f]{64}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_MAX_RESPONSE_BYTES = 65536
_READ_CHUNK_BYTES = 4096


def _canonical_bytes(value) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise NARFError("effect: signed witness payload is not canonical JSON") from None


def _decode_public_key(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise NARFError("effect: signed witness public key required")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception:
        raise NARFError("effect: invalid signed witness public key") from None
    if len(raw) != 32:
        raise NARFError("effect: invalid signed witness public key")
    return raw


def _normalize_base_url(value: str, allow_insecure_http: bool) -> tuple[str, tuple]:
    if not isinstance(value, str) or not value:
        raise NARFError("effect: signed witness URL required")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise NARFError("effect: invalid signed witness URL") from None
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise NARFError("effect: signed witness HTTP(S) URL required")
    if parsed.username is not None or parsed.password is not None:
        raise NARFError("effect: signed witness URL credentials forbidden")
    if parsed.query or parsed.fragment:
        raise NARFError("effect: signed witness URL query/fragment forbidden")
    if parsed.scheme == "http":
        loopback = parsed.hostname.lower() in {"127.0.0.1", "::1", "localhost"}
        if not (allow_insecure_http and loopback):
            raise NARFError("effect: signed witness HTTPS required")
    effective_port = port or (443 if parsed.scheme == "https" else 80)
    base = value.rstrip("/")
    return base, (parsed.scheme, parsed.hostname.lower(), effective_port)


def _remaining_seconds(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("signed witness deadline exceeded")
    return remaining


class _DeadlineRawReader(io.RawIOBase):
    """Raw socket reader that reapplies an absolute deadline before every recv."""

    def __init__(self, sock, deadline: float):
        super().__init__()
        self._sock = sock
        self._deadline = deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        self._sock.settimeout(_remaining_seconds(self._deadline))
        try:
            return self._sock.recv_into(buffer)
        except TimeoutError:
            raise TimeoutError("signed witness deadline exceeded") from None

    def close(self) -> None:
        if not self.closed:
            try:
                self._sock.close()
            finally:
                super().close()


class _DeadlineSocket:
    """Socket facade whose HTTP read file enforces one monotonic deadline."""

    def __init__(self, sock, deadline: float):
        self._sock = sock
        self._deadline = deadline

    def makefile(self, mode="r", buffering=None, *args, **kwargs):
        if mode != "rb":
            raise ValueError("signed witness socket only supports binary reads")
        return io.BufferedReader(_DeadlineRawReader(self._sock, self._deadline))

    def __getattr__(self, name):
        return getattr(self._sock, name)


def _read_with_deadline(stream, deadline: float) -> bytes:
    data = bytearray()
    read_once = getattr(stream, "read1", None)
    if not callable(read_once):
        read_once = stream.read
    while len(data) <= _MAX_RESPONSE_BYTES:
        _remaining_seconds(deadline)
        size = min(_READ_CHUNK_BYTES, _MAX_RESPONSE_BYTES + 1 - len(data))
        chunk = read_once(size)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


class SignedWitnessAuthority(ConsumptionAuthority):
    """Single-use authority backed by an Ed25519-authenticated remote witness.

    Only the public key is held by this client. Every request carries a fresh
    nonce and the signed response must echo that nonce and the requested token,
    preventing replay of an older valid success response.

    Signatures authenticate the witness. They do not make its ledger monotonic:
    if a privileged operator can roll back the witness ledger and all other
    authority histories, replay can become possible again.
    """

    def __init__(
        self,
        base_url: str,
        public_key_base64: str,
        *,
        timeout_seconds: int = 3,
        allow_insecure_http: bool = False,
    ):
        if type(timeout_seconds) is not int or timeout_seconds < 1 or timeout_seconds > 30:
            raise NARFError("effect: invalid signed witness timeout")
        self.base_url, self._endpoint_identity = _normalize_base_url(
            base_url, allow_insecure_http
        )
        self._public_key_raw = _decode_public_key(public_key_base64)
        self.public_key_fingerprint = hashlib.sha256(self._public_key_raw).hexdigest()
        self.timeout_seconds = timeout_seconds

    def domain_key(self):
        return ("signed-witness-ed25519", self.public_key_fingerprint)

    def _verify_signature(self, payload: dict, signature_base64: str) -> None:
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except Exception:
            raise NARFError("effect: signed witness crypto driver unavailable") from None
        try:
            signature = base64.b64decode(signature_base64.encode("ascii"), validate=True)
            public_key = Ed25519PublicKey.from_public_bytes(self._public_key_raw)
            public_key.verify(signature, _canonical_bytes(payload))
        except InvalidSignature:
            raise NARFError("effect: signed witness authentication failed") from None
        except NARFError:
            raise
        except Exception:
            raise NARFError("effect: signed witness response invalid") from None

    def _request(self, operation: str, token: str) -> dict:
        token = _canonical_uuid(token, "consumption_token")
        if operation not in {"reserve", "status"}:
            raise NARFError("effect: invalid signed witness operation")
        nonce = secrets.token_hex(32)
        request_payload = {
            "version": "narf.signed-witness.request.v1",
            "operation": operation,
            "token": token,
            "nonce": nonce,
        }
        request_body = _canonical_bytes(request_payload)
        parsed = urlsplit(self.base_url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path_prefix = parsed.path.rstrip("/")
        request_target = f"{path_prefix}/{operation}" if path_prefix else f"/{operation}"
        connection_class = (
            http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        )
        deadline = time.monotonic() + self.timeout_seconds
        connection = connection_class(
            parsed.hostname,
            port,
            timeout=_remaining_seconds(deadline),
        )
        response = None
        try:
            connection.connect()
            if connection.sock is None:
                raise OSError("signed witness connection unavailable")
            connection.sock.settimeout(_remaining_seconds(deadline))
            connection.request(
                "POST",
                request_target,
                body=request_body,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
            if connection.sock is None:
                raise OSError("signed witness connection unavailable")
            connection.sock = _DeadlineSocket(connection.sock, deadline)
            response = connection.getresponse()
            status = response.status
            raw = _read_with_deadline(response, deadline)
        except Exception:
            raise NARFError("effect: signed witness unavailable") from None
        finally:
            if response is not None:
                response.close()
            connection.close()

        if len(raw) > _MAX_RESPONSE_BYTES:
            raise NARFError("effect: signed witness response too large")
        if status not in {200, 201, 409}:
            raise NARFError("effect: signed witness unavailable")
        try:
            envelope = json.loads(raw.decode("utf-8"))
        except Exception:
            raise NARFError("effect: signed witness response invalid") from None
        if not isinstance(envelope, dict):
            raise NARFError("effect: signed witness response invalid")
        payload = envelope.get("payload")
        signature = envelope.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature, str):
            raise NARFError("effect: signed witness response invalid")
        self._verify_signature(payload, signature)

        expected_domain = f"ed25519:{self.public_key_fingerprint}"
        if (
            payload.get("version") != "narf.signed-witness.response.v1"
            or payload.get("operation") != operation
            or payload.get("token") != token
            or payload.get("nonce") != nonce
            or payload.get("domain") != expected_domain
        ):
            raise NARFError("effect: signed witness response binding mismatch")
        head_sequence = payload.get("head_sequence")
        head_sha256 = payload.get("head_sha256")
        if type(head_sequence) is not int or head_sequence < 0:
            raise NARFError("effect: signed witness response invalid")
        if not isinstance(head_sha256, str) or not _SHA256_RE.fullmatch(head_sha256):
            raise NARFError("effect: signed witness response invalid")
        return payload

    def reserve(self, token: str) -> None:
        payload = self._request("reserve", token)
        result = payload.get("result")
        if result == "RESERVED":
            return
        if result == "ALREADY_CONSUMED":
            raise NARFError("effect: external consumption authority already consumed")
        raise NARFError("effect: signed witness response invalid")

    def is_reserved(self, token: str) -> bool:
        payload = self._request("status", token)
        result = payload.get("result")
        if result == "RESERVED":
            return True
        if result == "AVAILABLE":
            return False
        raise NARFError("effect: signed witness response invalid")
