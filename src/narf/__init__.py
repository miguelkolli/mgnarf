"""Public NARF reference implementation."""
# 🧠 BRAIN: Public exports route callers to the ordered gate and fenced wrapper;
# 🧠 BRAIN: do not accidentally downgrade v3 contracts through legacy APIs.
# 🐭 PINKY: An exported hardened adapter still needs a real trusted-host path;
# 🐭 PINKY: the worker must never own approval or effect credentials.

from .authority_revision import AuthorityRevisionGate, AuthorityRevisionSession, AuthoritySnapshot
from .fenced_effect import (
    FenceToken,
    FencedEffectBinding,
    FencedOperationEffectExecutor,
    FencedOperationSession,
    FencingAuthority,
)
from .gate import (
    EffectBinding,
    FrozenState,
    NARFError,
    ReceiptStore,
    Requirement,
    VerifierBinding,
    VerifierResult,
    canonical_json_digest,
    sha256_bytes,
)
from .stage_order import NARFGate
from .stage_order_fenced import FencedOperationGate
from .operation_guard import OperationBoundEffectExecutor, OperationBoundGate
from .postgres_authority import PostgresConsumptionAuthority
from .postgres_fencing import (
    PostgresFenceControlPlane,
    PostgresFencedTarget,
    PostgresFencingAuthority,
)
from .rollback_guard import (
    AllOfConsumptionAuthority,
    ConsumptionAuthority,
    FileConsumptionAuthority,
    RollbackProtectedEffectExecutor,
)
from .signed_witness import SignedWitnessAuthority

__all__ = [
    "AllOfConsumptionAuthority",
    "AuthorityRevisionGate",
    "AuthorityRevisionSession",
    "AuthoritySnapshot",
    "ConsumptionAuthority",
    "EffectBinding",
    "FenceToken",
    "FencedEffectBinding",
    "FencedOperationEffectExecutor",
    "FencedOperationGate",
    "FencedOperationSession",
    "FencingAuthority",
    "FileConsumptionAuthority",
    "FrozenState",
    "NARFError",
    "NARFGate",
    "OperationBoundEffectExecutor",
    "OperationBoundGate",
    "PostgresConsumptionAuthority",
    "PostgresFenceControlPlane",
    "PostgresFencedTarget",
    "PostgresFencingAuthority",
    "ReceiptStore",
    "Requirement",
    "RollbackProtectedEffectExecutor",
    "SignedWitnessAuthority",
    "VerifierBinding",
    "VerifierResult",
    "canonical_json_digest",
    "sha256_bytes",
]
