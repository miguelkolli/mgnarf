"""Standalone NARF fail-closed acceptance gate.

This reference implementation preserves the core NARF trust model without
importing MGSystem runtime internals. The trusted host freezes task/state/bindings,
runs verifier producers itself, authenticates evidence, and owns the gated effect.
Workers do not receive a PASS override or evidence-submission API.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
import re
from typing import Callable
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5


_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
_RECEIPT_DOMAIN = b"narf.receipt.v1\0"


class NARFError(ValueError):
    """Invalid host configuration or use; never evidence of task PASS."""


@dataclass(frozen=True)
class FrozenState:
    candidate_sha256: str
    requirements_sha256: str
    policy_sha256: str


@dataclass(frozen=True)
class Requirement:
    requirement_id: str
    verifier_id: str
    verifier_version: str


@dataclass(frozen=True)
class VerifierResult:
    status: str
    artifact: bytes


@dataclass(frozen=True)
class VerifierBinding:
    verifier_id: str
    verifier_version: str
    producer: Callable[[], VerifierResult]


@dataclass(frozen=True)
class EffectBinding:
    effect_id: str
    effect_version: str
    execute: Callable[[], object]


def canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError):
        raise NARFError("value: canonical JSON required") from None


def sha256_bytes(value: bytes) -> str:
    if not isinstance(value, bytes):
        raise NARFError("digest: bytes required")
    return hashlib.sha256(value).hexdigest()


def canonical_json_digest(value: object) -> str:
    return sha256_bytes(canonical_json(value).encode("utf-8"))


def _identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise NARFError(f"{label}: invalid identifier")
    return value


def _sha256(value: str, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise NARFError(f"{label}: invalid sha256")
    return value


def _uuid(value: str, label: str) -> str:
    try:
        parsed = UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise NARFError(f"{label}: invalid UUID") from None
    if str(parsed) != value:
        raise NARFError(f"{label}: invalid UUID")
    return value


def _validate_state(state: FrozenState) -> FrozenState:
    if type(state) is not FrozenState:
        raise NARFError("state: FrozenState required")
    _sha256(state.candidate_sha256, "candidate_sha256")
    _sha256(state.requirements_sha256, "requirements_sha256")
    _sha256(state.policy_sha256, "policy_sha256")
    return state


class ReceiptStore:
    """HMAC-authenticated, append-only receipt persistence.

    The host key and this store must remain outside candidate/worker control.
    Receipt files are untrusted until MAC verification succeeds.
    """

    def __init__(self, directory: str | Path, key: bytes):
        self.directory = Path(directory).resolve()
        if not isinstance(key, bytes) or len(key) < 32:
            raise NARFError("store: host key must contain at least 32 bytes")
        self.__key = key
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)

    def _path(self, run_id: str) -> Path:
        _uuid(run_id, "run_id")
        return self.directory / f"{run_id}.json"

    def _mac(self, payload: dict) -> str:
        body = canonical_json(payload).encode("utf-8")
        return hmac.new(self.__key, _RECEIPT_DOMAIN + body, hashlib.sha256).hexdigest()

    def save(self, evidence: dict) -> None:
        if not isinstance(evidence, dict) or "run_id" not in evidence:
            raise NARFError("receipt: evidence with run_id required")
        path = self._path(evidence["run_id"])
        payload = {"receipt_type": "narf.receipt", "receipt_version": 1, "evidence": evidence}
        envelope = {"payload": payload, "mac": self._mac(payload)}
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(canonical_json(envelope))
            output.flush()
            os.fsync(output.fileno())
        try:
            dfd = os.open(self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except OSError:
            return
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    def load(self, run_id: str) -> dict | None:
        try:
            path = self._path(run_id)
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags)
            with os.fdopen(fd, "r", encoding="utf-8") as source:
                text = source.read(1_048_577)
            if len(text) > 1_048_576:
                return None
            envelope = json.loads(text)
            if not isinstance(envelope, dict) or set(envelope) != {"payload", "mac"}:
                return None
            payload = envelope["payload"]
            if not isinstance(payload, dict):
                return None
            if not isinstance(envelope["mac"], str) or not hmac.compare_digest(
                envelope["mac"], self._mac(payload)
            ):
                return None
            if (
                set(payload) != {"receipt_type", "receipt_version", "evidence"}
                or payload["receipt_type"] != "narf.receipt"
                or payload["receipt_version"] != 1
                or not isinstance(payload["evidence"], dict)
                or payload["evidence"].get("run_id") != run_id
            ):
                return None
            return payload["evidence"]
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, NARFError):
            return None


class NARFGate:
    """Trusted-host factory for frozen contracts and candidate-bound sessions."""

    def __init__(self, receipt_store: ReceiptStore):
        if type(receipt_store) is not ReceiptStore:
            raise NARFError("store: existing ReceiptStore required")
        self.__store = receipt_store

    def freeze_contract(
        self,
        task: dict,
        *,
        task_id: str,
        requirements: tuple[Requirement, ...] | list[Requirement],
        effect_id: str,
        effect_version: str,
        state: FrozenState,
    ) -> str:
        _identifier(task_id, "task_id")
        _identifier(effect_id, "effect_id")
        _identifier(effect_version, "effect_version")
        _validate_state(state)
        if not isinstance(task, dict):
            raise NARFError("task: object required")
        task_sha256 = canonical_json_digest(task)
        if not isinstance(requirements, (list, tuple)) or not requirements:
            raise NARFError("requirements: non-empty frozen set required")

        frozen = []
        seen = set()
        for requirement in requirements:
            if type(requirement) is not Requirement:
                raise NARFError("requirements: Requirement values required")
            _identifier(requirement.requirement_id, "requirement_id")
            _identifier(requirement.verifier_id, "verifier_id")
            _identifier(requirement.verifier_version, "verifier_version")
            if requirement.requirement_id in seen:
                raise NARFError("requirements: duplicate requirement")
            seen.add(requirement.requirement_id)
            frozen.append(asdict(requirement))

        contract_id = str(uuid4())
        evidence = {
            "evidence_type": "narf.contract",
            "evidence_version": 1,
            "producer": "host/narf-contract-v1",
            "run_id": contract_id,
            "task_id": task_id,
            "task_sha256": task_sha256,
            "requirements": frozen,
            "effect_id": effect_id,
            "effect_version": effect_version,
            "state": asdict(state),
        }
        self.__store.save(evidence)
        return contract_id

    def open_session(
        self,
        contract_id: str,
        task: dict,
        *,
        verifier_bindings: tuple[VerifierBinding, ...] | list[VerifierBinding],
        effect_binding: EffectBinding,
        state_probe: Callable[[], FrozenState],
        revocation_probe: Callable[[str, str], object] | None = None,
    ) -> "NARFSession":
        contract = self.__store.load(contract_id)
        if (
            not isinstance(contract, dict)
            or contract.get("evidence_type") != "narf.contract"
            or contract.get("evidence_version") != 1
            or contract.get("producer") != "host/narf-contract-v1"
        ):
            raise NARFError("contract: authenticated NARF contract required")
        if not isinstance(task, dict):
            raise NARFError("task: object required")
        if not callable(state_probe):
            raise NARFError("state: host probe must be callable")
        if revocation_probe is not None and not callable(revocation_probe):
            raise NARFError("revocation: host probe must be callable")

        errors = []
        if canonical_json_digest(task) != contract.get("task_sha256"):
            errors.append("TASK_CHANGED")

        bindings = {}
        if not isinstance(verifier_bindings, (list, tuple)):
            verifier_bindings = []
            errors.append("VERIFIER_UNAVAILABLE")
        for binding in verifier_bindings:
            if (
                type(binding) is not VerifierBinding
                or not callable(binding.producer)
                or binding.verifier_id in bindings
            ):
                errors.append("VERIFIER_UNAVAILABLE")
                continue
            bindings[binding.verifier_id] = binding

        requirements = contract.get("requirements")
        if not isinstance(requirements, list) or not requirements:
            requirements = []
            errors.append("INVALID_CONTRACT")
        expected = {item.get("verifier_id") for item in requirements if isinstance(item, dict)}
        if set(bindings) != expected:
            errors.append("VERIFIER_UNAVAILABLE")
        for item in requirements:
            selected = bindings.get(item.get("verifier_id")) if isinstance(item, dict) else None
            if selected is None or selected.verifier_version != item.get("verifier_version"):
                errors.append("VERIFIER_VERSION_CHANGED")

        if (
            type(effect_binding) is not EffectBinding
            or not callable(effect_binding.execute)
            or effect_binding.effect_id != contract.get("effect_id")
            or effect_binding.effect_version != contract.get("effect_version")
        ):
            errors.append("EFFECT_BINDING_CHANGED")

        session_id = str(uuid4())
        return NARFSession(
            self.__store,
            contract,
            session_id,
            bindings,
            effect_binding,
            state_probe,
            revocation_probe,
            sorted(set(errors)),
        )


class NARFSession:
    """One candidate-bound run; only host-invoked verifier evidence can enter."""

    def __init__(
        self,
        store: ReceiptStore,
        contract: dict,
        session_id: str,
        bindings: dict[str, VerifierBinding],
        effect: EffectBinding,
        state_probe: Callable[[], FrozenState],
        revocation_probe: Callable[[str, str], object] | None,
        errors: list[str],
    ):
        self.__store = store
        self.__contract = json.loads(canonical_json(contract))
        self.__session_id = session_id
        self.__bindings = bindings
        self.__effect = effect
        self.__state_probe = state_probe
        self.__revocation_probe = revocation_probe
        self.__errors = list(errors)
        self.__runs: dict[str, str] = {}
        self.__decision: dict | None = None
        self.__closed = False
        self.__effect_used = False
        self.__inhibitors: list[str] = []

    @property
    def session_id(self) -> str:
        return self.__session_id

    def requirements(self) -> list[str]:
        return [item["requirement_id"] for item in self.__contract["requirements"]]

    def inhibit(self, reason: str) -> None:
        if self.__closed:
            raise NARFError("session: finalized")
        _identifier(reason, "inhibitor")
        if reason not in self.__inhibitors:
            self.__inhibitors.append(reason)

    def _revoked(self) -> bool:
        if self.__revocation_probe is None:
            return False
        try:
            value = self.__revocation_probe(
                self.__contract["run_id"], self.__contract["state"]["candidate_sha256"]
            )
        except Exception:
            return True
        return value is not None and value is not False

    def _current_state_error(self) -> str | None:
        if self._revoked():
            return "REVOKED"
        if self.__store.load(self.__contract["run_id"]) != self.__contract:
            return "CONTRACT_INVALID"
        try:
            current = _validate_state(self.__state_probe())
        except Exception:
            return "STATE_UNAVAILABLE"
        frozen = self.__contract["state"]
        if current.candidate_sha256 != frozen["candidate_sha256"]:
            return "CANDIDATE_CHANGED"
        if current.requirements_sha256 != frozen["requirements_sha256"]:
            return "GOALPOST_CHANGED"
        if current.policy_sha256 != frozen["policy_sha256"]:
            return "POLICY_CHANGED"
        return None

    def execute(self, requirement_id: str) -> dict:
        if self.__closed:
            raise NARFError("session: finalized")
        if self.__errors:
            raise NARFError("session: blocked host binding")
        if requirement_id in self.__runs:
            raise NARFError("evidence: duplicate requirement execution")
        requirement = next(
            (item for item in self.__contract["requirements"] if item["requirement_id"] == requirement_id),
            None,
        )
        if requirement is None:
            raise NARFError("requirement: not in frozen contract")
        state_error = self._current_state_error()
        if state_error:
            raise NARFError(f"session: {state_error.lower()}")

        binding = self.__bindings[requirement["verifier_id"]]
        try:
            produced = binding.producer()
            if (
                type(produced) is not VerifierResult
                or produced.status not in ("PASS", "FAIL", "BLOCKED")
                or type(produced.artifact) is not bytes
                or len(produced.artifact) > 1_048_576
            ):
                raise ValueError("invalid verifier result")
            status = produced.status
            artifact_sha256 = sha256_bytes(produced.artifact)
            reason = "VERIFIER_" + status
        except Exception:
            status = "BLOCKED"
            artifact_sha256 = sha256_bytes(b"")
            reason = "VERIFIER_UNAVAILABLE"

        if self._current_state_error() is not None:
            status = "BLOCKED"
            reason = "STATE_CHANGED_DURING_VERIFICATION"

        run_id = str(uuid4())
        evidence = {
            "evidence_type": "narf.verification",
            "evidence_version": 1,
            "producer": "host/narf-verifier-v1",
            "run_id": run_id,
            "contract_id": self.__contract["run_id"],
            "session_id": self.__session_id,
            "task_id": self.__contract["task_id"],
            "task_sha256": self.__contract["task_sha256"],
            "requirement_id": requirement_id,
            "verifier_id": binding.verifier_id,
            "verifier_version": binding.verifier_version,
            "state": self.__contract["state"],
            "status": status,
            "reason": reason,
            "artifact_sha256": artifact_sha256,
        }
        self.__store.save(evidence)
        self.__runs[requirement_id] = run_id
        return {
            "requirement_id": requirement_id,
            "status": status,
            "reason": reason,
            "evidence_id": run_id,
        }

    def _expected_evidence(self, requirement: dict, run_id: str) -> dict:
        binding = self.__bindings[requirement["verifier_id"]]
        return {
            "evidence_type": "narf.verification",
            "evidence_version": 1,
            "producer": "host/narf-verifier-v1",
            "run_id": run_id,
            "contract_id": self.__contract["run_id"],
            "session_id": self.__session_id,
            "task_id": self.__contract["task_id"],
            "task_sha256": self.__contract["task_sha256"],
            "requirement_id": requirement["requirement_id"],
            "verifier_id": binding.verifier_id,
            "verifier_version": binding.verifier_version,
            "state": self.__contract["state"],
        }

    def _evaluate(self) -> dict:
        if self.__errors:
            return {"result": "BLOCKED", "reason": self.__errors[0]}
        state_error = self._current_state_error()
        if state_error:
            return {"result": "BLOCKED", "reason": state_error}
        missing = [item for item in self.requirements() if item not in self.__runs]
        if missing:
            return {"result": "BLOCKED", "reason": "INCOMPLETE_EVIDENCE"}
        if len(set(self.__runs.values())) != len(self.__runs):
            return {"result": "BLOCKED", "reason": "REPLAYED_EVIDENCE"}

        statuses = []
        for requirement in self.__contract["requirements"]:
            run_id = self.__runs[requirement["requirement_id"]]
            raw = self.__store.load(run_id)
            expected = self._expected_evidence(requirement, run_id)
            if not isinstance(raw, dict) or any(raw.get(k) != v for k, v in expected.items()):
                return {"result": "BLOCKED", "reason": "INVALID_EVIDENCE"}
            extra = {"status", "reason", "artifact_sha256"}
            if set(raw) != set(expected).union(extra):
                return {"result": "BLOCKED", "reason": "INVALID_EVIDENCE"}
            valid_reason = raw.get("reason") == "VERIFIER_" + str(raw.get("status")) or (
                raw.get("status") == "BLOCKED"
                and raw.get("reason") in ("VERIFIER_UNAVAILABLE", "STATE_CHANGED_DURING_VERIFICATION")
            )
            if (
                raw.get("status") not in ("PASS", "FAIL", "BLOCKED")
                or not isinstance(raw.get("artifact_sha256"), str)
                or _SHA256_RE.fullmatch(raw["artifact_sha256"]) is None
                or not valid_reason
            ):
                return {"result": "BLOCKED", "reason": "INVALID_EVIDENCE"}
            statuses.append(raw["status"])

        if "FAIL" in statuses:
            return {"result": "FAIL", "reason": "VERIFIER_FAIL"}
        if "BLOCKED" in statuses:
            return {"result": "BLOCKED", "reason": "VERIFIER_BLOCKED"}
        if self.__inhibitors:
            return {"result": "BLOCKED", "reason": self.__inhibitors[0]}
        return {"result": "PASS", "reason": "EXTERNAL_EVIDENCE_ACCEPTED"}

    def verdict(self) -> dict:
        verdict = self._evaluate()
        return {
            **verdict,
            "coverage": f"{len(self.__runs)}/{len(self.requirements())}",
            "session_id": self.__session_id,
            "verdict_scope": "narf",
        }

    def _authenticated_decision(self) -> bool:
        if self.__decision is None:
            return False
        decision = self.__store.load(self.__decision["decision_id"])
        expected = {
            "evidence_type": "narf.decision",
            "evidence_version": 1,
            "producer": "host/narf-gate-v1",
            "run_id": self.__decision["decision_id"],
            "contract_id": self.__contract["run_id"],
            "session_id": self.__session_id,
            "task_id": self.__contract["task_id"],
            "task_sha256": self.__contract["task_sha256"],
            "state": self.__contract["state"],
            "result": self.__decision["result"],
            "reason": self.__decision["reason"],
            "coverage": self.__decision["coverage"],
        }
        return (
            isinstance(decision, dict)
            and decision == expected
            and (self.__decision["result"] != "PASS" or self._evaluate().get("result") == "PASS")
        )

    def finalize(self) -> dict:
        if self.__decision is not None:
            if not self._authenticated_decision():
                raise NARFError("decision: invalid or stale")
            return dict(self.__decision)
        self.__closed = True
        verdict = self.verdict()
        decision_id = str(uuid4())
        evidence = {
            "evidence_type": "narf.decision",
            "evidence_version": 1,
            "producer": "host/narf-gate-v1",
            "run_id": decision_id,
            "contract_id": self.__contract["run_id"],
            "session_id": self.__session_id,
            "task_id": self.__contract["task_id"],
            "task_sha256": self.__contract["task_sha256"],
            "state": self.__contract["state"],
            "result": verdict["result"],
            "reason": verdict["reason"],
            "coverage": verdict["coverage"],
        }
        self.__store.save(evidence)
        self.__decision = {**verdict, "decision_id": decision_id}
        return dict(self.__decision)

    def execute_effect(self) -> object:
        if self.__decision is None or self.__decision["result"] != "PASS":
            raise NARFError("effect: authenticated PASS required")
        if self.__effect_used:
            raise NARFError("effect: already consumed")
        # 🧠 BRAIN: A prior PASS is intentionally insufficient. The host must
        # revalidate revocation, frozen state, and the authenticated decision
        # immediately before the durable effect-consumption record is created.
        state_error = self._current_state_error()
        if state_error:
            raise NARFError(f"effect: {state_error.lower()}")
        if not self._authenticated_decision():
            raise NARFError("effect: PASS is invalid or stale")

        effect_run_id = str(
            uuid5(
                NAMESPACE_URL,
                "narf.effect.v1:"
                + self.__contract["run_id"]
                + ":"
                + self.__contract["state"]["candidate_sha256"]
                + ":"
                + self.__effect.effect_id
                + ":"
                + self.__effect.effect_version,
            )
        )
        consumed = {
            "evidence_type": "narf.effect",
            "evidence_version": 1,
            "producer": "host/narf-gate-v1",
            "run_id": effect_run_id,
            "contract_id": self.__contract["run_id"],
            "session_id": self.__session_id,
            "task_id": self.__contract["task_id"],
            "task_sha256": self.__contract["task_sha256"],
            "state": self.__contract["state"],
            "effect_id": self.__effect.effect_id,
            "effect_version": self.__effect.effect_version,
            "decision_id": self.__decision["decision_id"],
        }
        try:
            self.__store.save(consumed)
        except FileExistsError:
            raise NARFError("effect: already consumed") from None
        self.__effect_used = True
        return self.__effect.execute()
