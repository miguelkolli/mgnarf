"""Reference boundary for a host-owned NARF gate over a worker-owned candidate file."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import stat
import threading
from typing import Callable

from .gate import (
    EffectBinding,
    FrozenState,
    NARFError,
    NARFGate,
    ReceiptStore,
    Requirement,
    VerifierBinding,
    VerifierResult,
    canonical_json,
    canonical_json_digest,
    sha256_bytes,
)

_MAX_CANDIDATE_BYTES = 1_048_576


@dataclass(frozen=True)
class CandidateVerifier:
    """Trusted-host verifier that receives the frozen candidate bytes."""

    verifier_id: str
    verifier_version: str
    producer: Callable[[bytes], VerifierResult]


class CandidateFileHost:
    """Trusted host for a candidate file writable by an untrusted worker.

    The worker owns only the candidate file. The host owns the receipt key,
    receipt store, verifier selection, frozen effect bytes and effect target.
    """

    def __init__(self, authority_root: str | Path, candidate_path: str | Path, key: bytes):
        self.authority_root = Path(authority_root).resolve()
        self.authority_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.effects_dir = self.authority_root / "effects"
        self.effects_dir.mkdir(mode=0o700, exist_ok=True)
        self.receipts = ReceiptStore(self.authority_root / "receipts", key)
        self.gate = NARFGate(self.receipts)
        self.candidate_path = Path(os.path.abspath(os.fspath(candidate_path)))
        self._authority_lock = threading.RLock()
        self._state: FrozenState | None = None
        self._revoked = False
        self._session = None
        self._target: Path | None = None

    def _read_candidate(self) -> bytes:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        elif self.candidate_path.is_symlink():
            raise NARFError("candidate: symlink not allowed")
        try:
            fd = os.open(self.candidate_path, flags)
        except OSError as error:
            raise NARFError("candidate: unavailable") from error
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise NARFError("candidate: regular file required")
            with os.fdopen(fd, "rb", closefd=False) as source:
                raw = source.read(_MAX_CANDIDATE_BYTES + 1)
            if len(raw) > _MAX_CANDIDATE_BYTES:
                raise NARFError("candidate: file too large")
            return raw
        finally:
            os.close(fd)

    def _state_probe(self) -> FrozenState:
        if self._state is None:
            raise NARFError("host: no frozen state")
        current = self._read_candidate()
        return FrozenState(
            candidate_sha256=sha256_bytes(current),
            requirements_sha256=self._state.requirements_sha256,
            policy_sha256=self._state.policy_sha256,
        )

    def _revocation_probe(self, _contract_id: str, _candidate_sha256: str):
        return self._revoked

    def prepare(
        self,
        task: dict,
        *,
        task_id: str,
        policy: bytes,
        requirements: tuple[Requirement, ...] | list[Requirement],
        verifiers: tuple[CandidateVerifier, ...] | list[CandidateVerifier],
        effect_name: str,
    ) -> str:
        if self._session is not None:
            raise NARFError("host: effect already prepared")
        if not isinstance(policy, bytes):
            raise NARFError("host: policy bytes required")
        if not isinstance(effect_name, str) or not effect_name or "/" in effect_name or "\\" in effect_name:
            raise NARFError("host: invalid effect name")
        if not isinstance(requirements, (tuple, list)) or not requirements:
            raise NARFError("host: requirements required")
        if not isinstance(verifiers, (tuple, list)) or not verifiers:
            raise NARFError("host: verifiers required")

        frozen_task = json.loads(canonical_json(task))
        frozen_candidate = self._read_candidate()
        frozen_requirements = tuple(requirements)
        state = FrozenState(
            candidate_sha256=sha256_bytes(frozen_candidate),
            requirements_sha256=canonical_json_digest([asdict(item) for item in frozen_requirements]),
            policy_sha256=sha256_bytes(policy),
        )
        bindings = []
        for verifier in verifiers:
            if type(verifier) is not CandidateVerifier or not callable(verifier.producer):
                raise NARFError("host: CandidateVerifier values required")

            def produce(selected=verifier.producer, candidate=frozen_candidate):
                return selected(candidate)

            bindings.append(VerifierBinding(verifier.verifier_id, verifier.verifier_version, produce))

        target = self.effects_dir / effect_name

        def write_effect():
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(target, flags, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(frozen_candidate)
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
                frozen_task,
                task_id=task_id,
                requirements=frozen_requirements,
                effect_id="candidate-file-write",
                effect_version="1",
                state=state,
            )
            self._session = self.gate.open_session(
                contract_id,
                frozen_task,
                verifier_bindings=tuple(bindings),
                effect_binding=EffectBinding("candidate-file-write", "1", write_effect),
                state_probe=self._state_probe,
                revocation_probe=self._revocation_probe,
            )
            self._target = target
            return contract_id

    def verify(self) -> dict:
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

    def revoke(self) -> None:
        with self._authority_lock:
            self._revoked = True

    @property
    def target(self) -> Path:
        if self._target is None:
            raise NARFError("host: no prepared effect")
        return self._target
