"""Reference trusted-host integration for a real file effect."""
from __future__ import annotations
import json, os, threading
from dataclasses import asdict, replace
from pathlib import Path
from .gate import EffectBinding, FrozenState, NARFError, NARFGate, ReceiptStore, canonical_json_digest, sha256_bytes

class TrustedFileHost:
    def __init__(self, root: str | Path, key: bytes):
        self.root = Path(root).resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.effects_dir = self.root / "effects"
        self.effects_dir.mkdir(mode=0o700, exist_ok=True)
        self.receipts = ReceiptStore(self.root / "receipts", key)
        self.gate = NARFGate(self.receipts)
        self._authority_lock = threading.RLock()
        self._state = None
        self._revoked = False
        self._session = None
        self._target = None

    def _state_probe(self):
        if self._state is None:
            raise NARFError("host: no frozen state")
        return self._state

    def _revocation_probe(self, _contract_id, _candidate_sha256):
        return self._revoked

    def prepare(self, task: dict, *, task_id: str, candidate: bytes, policy: bytes,
                requirements, verifier_bindings, effect_name: str, payload: bytes | bytearray) -> str:
        if self._session is not None:
            raise NARFError("host: effect already prepared")
        if not isinstance(candidate, bytes) or not isinstance(policy, bytes):
            raise NARFError("host: candidate and policy bytes required")
        if not isinstance(payload, (bytes, bytearray)):
            raise NARFError("host: payload bytes required")
        if not isinstance(effect_name, str) or not effect_name or "/" in effect_name or "\\" in effect_name:
            raise NARFError("host: invalid effect name")

        frozen_task = json.loads(json.dumps(task, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False))
        frozen_payload = bytes(payload)
        frozen_requirements = tuple(requirements)
        state = FrozenState(
            candidate_sha256=sha256_bytes(candidate),
            requirements_sha256=canonical_json_digest([asdict(r) for r in frozen_requirements]),
            policy_sha256=sha256_bytes(policy),
        )
        target = self.effects_dir / effect_name

        def write_effect():
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(target, flags, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(frozen_payload)
                output.flush()
                os.fsync(output.fileno())
            dfd = os.open(self.effects_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
            return str(target)

        with self._authority_lock:
            self._state = state
            self._revoked = False
            contract_id = self.gate.freeze_contract(
                frozen_task, task_id=task_id, requirements=frozen_requirements,
                effect_id="file-write", effect_version="1", state=state,
            )
            self._session = self.gate.open_session(
                contract_id, frozen_task, verifier_bindings=tuple(verifier_bindings),
                effect_binding=EffectBinding("file-write", "1", write_effect),
                state_probe=self._state_probe, revocation_probe=self._revocation_probe,
            )
            self._target = target
            return contract_id

    def verify(self):
        if self._session is None:
            raise NARFError("host: no prepared effect")
        for requirement_id in self._session.requirements():
            self._session.execute(requirement_id)
        return self._session.finalize()

    def commit(self):
        if self._session is None:
            raise NARFError("host: no prepared effect")
        with self._authority_lock:
            return self._session.execute_effect()

    def revoke(self):
        with self._authority_lock:
            self._revoked = True

    def replace_candidate(self, candidate: bytes):
        if not isinstance(candidate, bytes):
            raise NARFError("host: candidate bytes required")
        with self._authority_lock:
            if self._state is None:
                raise NARFError("host: no frozen state")
            self._state = replace(self._state, candidate_sha256=sha256_bytes(candidate))

    @property
    def target(self):
        if self._target is None:
            raise NARFError("host: no prepared effect")
        return self._target
