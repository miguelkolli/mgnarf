"""Monotonic authority-revision binding for identity-enabled NARF.

Snapshot identity checks cannot detect a change that happens and is restored
entirely between two trusted-host probes. This opt-in host wrapper binds a
rollback-resistant monotonic authority revision to the NARF contract using a
separate HMAC-authenticated receipt and rechecks it throughout the session.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Callable
from uuid import NAMESPACE_URL, UUID, uuid5

from .gate import (
    EffectBinding,
    NARFError,
    NARFGate,
    ReceiptStore,
    canonical_json,
    canonical_json_digest,
)


@dataclass(frozen=True)
class AuthoritySnapshot:
    """Trusted-host view of the current identity authority state."""

    revision: int
    actors: dict


def _canonical_uuid(value: str, label: str) -> str:
    try:
        parsed = UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise NARFError(f"{label}: invalid UUID") from None
    if str(parsed) != value:
        raise NARFError(f"{label}: invalid UUID")
    return value


def _binding_id(contract_id: str) -> str:
    contract_id = _canonical_uuid(contract_id, "contract_id")
    return str(uuid5(NAMESPACE_URL, "narf.authority-revision-binding.v1:" + contract_id))


def _freeze_snapshot(value: object) -> AuthoritySnapshot:
    if type(value) is not AuthoritySnapshot:
        raise NARFError("authority: AuthoritySnapshot required")
    if type(value.revision) is not int or value.revision < 0:
        raise NARFError("authority: non-negative integer revision required")
    if type(value.actors) is not dict:
        raise NARFError("authority: actor map required")
    actors = json.loads(canonical_json(value.actors))
    return AuthoritySnapshot(value.revision, actors)


class AuthorityRevisionSession:
    """NARF session carrying the frozen authority revision for audit/use."""

    __slots__ = ("__session", "__contract_id", "__authority_revision")

    def __init__(self, session, contract_id: str, authority_revision: int):
        self.__session = session
        self.__contract_id = _canonical_uuid(contract_id, "contract_id")
        if type(authority_revision) is not int or authority_revision < 0:
            raise NARFError("authority: invalid frozen revision")
        self.__authority_revision = authority_revision

    @property
    def contract_id(self) -> str:
        return self.__contract_id

    @property
    def authority_revision(self) -> int:
        return self.__authority_revision

    @property
    def session_id(self) -> str:
        return self.__session.session_id

    def requirements(self) -> list[str]:
        return self.__session.requirements()

    def inhibit(self, reason: str) -> None:
        self.__session.inhibit(reason)

    def execute(self, requirement_id: str) -> dict:
        return self.__session.execute(requirement_id)

    def verdict(self) -> dict:
        return self.__session.verdict()

    def finalize(self) -> dict:
        return self.__session.finalize()

    def execute_effect(self):
        return self.__session.execute_effect()


class AuthorityRevisionGate:
    """Bind an identity-enabled contract to a monotonic host authority revision.

    The supplied authority probe is trusted-host infrastructure. Its revision
    must increase whenever any identity-authority fact can change, must never be
    reused for a different authority state, and must itself resist rollback.

    The wrapper keeps the core NARF v2 identity contract unchanged. A separate
    authenticated binding receipt ties the core contract to the revision,
    actor-map digest, and identity-policy digest. Missing or invalid binding
    evidence fails closed before verifier evidence can run.
    """

    def __init__(self, receipt_store: ReceiptStore, authority_probe: Callable[[], AuthoritySnapshot]):
        if type(receipt_store) is not ReceiptStore:
            raise NARFError("store: existing ReceiptStore required")
        if not callable(authority_probe):
            raise NARFError("authority: trusted probe must be callable")
        self.__store = receipt_store
        self.__gate = NARFGate(receipt_store)
        self.__authority_probe = authority_probe

    def _probe(self) -> AuthoritySnapshot:
        try:
            value = self.__authority_probe()
        except Exception:
            raise NARFError("authority: snapshot unavailable") from None
        try:
            return _freeze_snapshot(value)
        except NARFError:
            raise
        except Exception:
            raise NARFError("authority: invalid snapshot") from None

    def freeze_contract(
        self,
        task: dict,
        *,
        task_id: str,
        requirements,
        effect_id: str,
        effect_version: str,
        state,
        identity_policy: dict,
    ) -> str:
        if type(identity_policy) is not dict or type(identity_policy.get("actors")) is not dict:
            raise NARFError("authority: identity policy with actors required")

        snapshot = self._probe()
        frozen_policy_actors = json.loads(canonical_json(identity_policy["actors"]))
        if canonical_json(snapshot.actors) != canonical_json(frozen_policy_actors):
            raise NARFError("authority: snapshot does not match identity policy")

        policy_sha256 = canonical_json_digest(identity_policy)
        actors_sha256 = canonical_json_digest(snapshot.actors)
        contract_id = self.__gate.freeze_contract(
            task,
            task_id=task_id,
            requirements=requirements,
            effect_id=effect_id,
            effect_version=effect_version,
            state=state,
            identity_policy=identity_policy,
        )

        contract = self.__store.load(contract_id)
        if (
            not isinstance(contract, dict)
            or contract.get("evidence_type") != "narf.contract"
            or contract.get("evidence_version") != 2
            or contract.get("identity_policy_sha256") != policy_sha256
        ):
            raise NARFError("authority: identity-enabled contract required")

        binding_id = _binding_id(contract_id)
        self.__store.save(
            {
                "evidence_type": "narf.authority-revision-binding",
                "evidence_version": 1,
                "producer": "host/narf-authority-revision-binding-v1",
                "run_id": binding_id,
                "contract_id": contract_id,
                "authority_revision": snapshot.revision,
                "actors_sha256": actors_sha256,
                "identity_policy_sha256": policy_sha256,
            }
        )
        return contract_id

    def _load_binding(self, contract_id: str) -> tuple[dict, dict]:
        contract_id = _canonical_uuid(contract_id, "contract_id")
        binding_id = _binding_id(contract_id)
        binding = self.__store.load(binding_id)
        expected_fields = {
            "evidence_type",
            "evidence_version",
            "producer",
            "run_id",
            "contract_id",
            "authority_revision",
            "actors_sha256",
            "identity_policy_sha256",
        }
        if (
            not isinstance(binding, dict)
            or set(binding) != expected_fields
            or binding.get("evidence_type") != "narf.authority-revision-binding"
            or binding.get("evidence_version") != 1
            or binding.get("producer") != "host/narf-authority-revision-binding-v1"
            or binding.get("run_id") != binding_id
            or binding.get("contract_id") != contract_id
            or type(binding.get("authority_revision")) is not int
            or binding["authority_revision"] < 0
        ):
            raise NARFError("authority: authenticated revision binding required")

        contract = self.__store.load(contract_id)
        if (
            not isinstance(contract, dict)
            or contract.get("evidence_type") != "narf.contract"
            or contract.get("evidence_version") != 2
            or contract.get("producer") != "host/narf-contract-v2"
            or type(contract.get("identity_policy")) is not dict
            or type(contract["identity_policy"].get("actors")) is not dict
            or contract.get("identity_policy_sha256") != binding.get("identity_policy_sha256")
            or canonical_json_digest(contract["identity_policy"]["actors"])
            != binding.get("actors_sha256")
        ):
            raise NARFError("authority: revision binding does not match contract")
        return binding, contract

    def _require_current(self, binding: dict) -> AuthoritySnapshot:
        snapshot = self._probe()
        if snapshot.revision != binding["authority_revision"]:
            raise NARFError("authority: revision changed")
        if canonical_json_digest(snapshot.actors) != binding["actors_sha256"]:
            raise NARFError("authority: actors changed")
        return snapshot

    def open_session(
        self,
        contract_id: str,
        task: dict,
        *,
        verifier_bindings,
        effect_binding,
        state_probe,
        revocation_probe=None,
    ) -> AuthorityRevisionSession:
        binding, _contract = self._load_binding(contract_id)
        self._require_current(binding)

        def identity_probe() -> dict:
            return self._require_current(binding).actors

        guarded_effect_binding = effect_binding
        if type(effect_binding) is EffectBinding and callable(effect_binding.execute):
            def guarded_effect():
                self._require_current(binding)
                return effect_binding.execute()

            guarded_effect_binding = EffectBinding(
                effect_binding.effect_id,
                effect_binding.effect_version,
                guarded_effect,
            )

        session = self.__gate.open_session(
            contract_id,
            task,
            verifier_bindings=verifier_bindings,
            effect_binding=guarded_effect_binding,
            state_probe=state_probe,
            revocation_probe=revocation_probe,
            identity_probe=identity_probe,
        )
        return AuthorityRevisionSession(session, contract_id, binding["authority_revision"])
