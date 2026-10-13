# Effect-admission authority v2 boundary

Status: **DESIGN CANDIDATE — NO RUNTIME CLAIM**

Related: #62, #64, #65, #66, #67.

## 1. Why this boundary exists

Frozen identity-provenance design #62 §15 requires one effect-admission linearization boundary that covers both currentness and the single-use effect authorization.

The current provenance-v4 implementation calls a trusted authority with a runtime callback:

```text
provenance currentness
-> admission_check() for ordinary MGnarf state / decision
-> effect-token reservation
```

PR #67 proved that this is still a check-then-reserve protocol. Ordinary MGnarf state can change after `admission_check()` returns but before the token is consumed. In that ordering the current implementation can still enter the external callback.

Therefore a callback invocation inside `reserve_effect()` is not by itself proof of atomic/equivalent effect admission.

## 2. Security invariant

A provenance-v4 effect MUST NOT be admitted unless the trusted effect-admission authority can establish that all policy-required mutable admission state was current at the same linearization boundary that consumed the exact single-use effect authorization.

The authority may use one transaction, one linearizable service, or an equivalent fenced multi-domain protocol. A plain sequence of independent reads followed by reservation is not sufficient.

## 3. Admission inputs

The authority operation must bind the exact effect token to the admission context required by the deployment claim. At minimum this includes:

```text
contract_id / exact contract commitment
final decision id / exact authenticated decision commitment
ordinary frozen MGnarf state commitment
ordinary revocation/currentness authority commitment
identity/authority commitment when enabled
provenance authority id
provenance trust root id
provenance revision/currentness commitment
stable operation id / fence commitment when enabled
single-use effect token
admission semantic version
```

A deployment that cannot produce a required commitment returns BLOCKED. Missing data is not inferred from friendly names, caller assertions, timestamps, or previous PASS output.

## 4. Authority models

### 4.1 Single-domain transaction

A deployment may keep all admission-relevant mutable authority state and the token ledger in one trusted linearizable domain.

The successful operation is conceptually:

```text
compare exact expected admission state
AND reserve exact effect token
COMMIT
```

No admission-relevant mutation may bypass the ordering primitive used by that transaction.

### 4.2 Fenced multi-domain admission

When the state cannot live in one domain, each required authority domain must contribute rollback-resistant monotonic revision/fence state.

The final effect path must compare the exact expected commitments and establish a single winning authorization through fencing/reservation. Partial or ambiguous reservation is never rolled back merely to regain availability.

A preserved reservation in any required domain may veto replay. Availability may be sacrificed instead of allowing a second effect under uncertain authority state.

## 5. Required ordering semantics

For every admission-relevant transition T and effect reservation E:

```text
T linearizes first -> effect BLOCKED; callback not entered
E linearizes first under valid expected state -> at most one callback may enter
```

A later authority change does not retroactively undo an effect already admitted unless the external target provides its own authenticated cancellation/rollback protocol.

Concurrent duplicate effect attempts must produce at most one successful admission.

## 6. Fail-closed requirements

The v2 authority path must fail closed when:

- any required currentness/revocation source is unavailable or ambiguous;
- expected contract/decision/state/provenance commitments do not match;
- a required monotonic authority revision/fence cannot be verified;
- the exact effect token is already reserved;
- a partial multi-domain reservation has occurred;
- the configured authority only implements the older callback-style contract;
- a wrapper cannot preserve the stronger admission semantics end-to-end.

Unknown or unsupported authority semantic versions are BLOCKED.

## 7. Callback rule

A callback may still be used as defense-in-depth for deterministic local validation, but its return MUST NOT be treated as the atomic currentness proof for independently mutable authority state.

In particular this is insufficient:

```text
lock provenance authority
check provenance
call ordinary_state_check()
reserve token
```

unless every authority state observed by `ordinary_state_check()` is itself ordered by the same linearization domain or represented by a rollback-resistant monotonic commitment atomically compared by the reservation operation.

## 8. Receipt and audit binding

Successful effect evidence must bind the authority semantic version and enough authenticated admission context to audit which exact reservation authorized the callback.

No local receipt may upgrade an authority failure into PASS. A missing effect receipt after an externally consumed reservation is an availability/recovery problem, not permission to replay the effect.

## 9. Required RED coverage before implementation

Runtime work must not resume until tests exist for at least:

1. ordinary candidate/state transition at the last pre-reservation boundary;
2. revocation transition at the last pre-reservation boundary;
3. identity/authority transition at the last pre-reservation boundary when enabled;
4. provenance transition winning before reservation;
5. reservation winning before a later provenance transition;
6. concurrent duplicate reservation;
7. authority unavailable and malformed/ambiguous authority result;
8. partial multi-domain reservation with fail-closed replay behavior;
9. exact contract/decision/effect-token mismatch;
10. legacy authority semantic version rejected rather than silently downgraded.

PR #67 is a frozen RED witness for item 1 and must not be weakened to obtain GREEN.

## 10. Composition boundary

This document does not claim that `AuthorityRevisionGate`, `OperationBoundGate`, or `FencedOperationGate` already compose with provenance-v4. Until explicit v4 composition exists and is verified, those wrapper paths must continue to reject provenance requests fail closed.

## 11. Release gate

A new implementation candidate may be offered to independent review only after:

```text
#67 unchanged -> GREEN
new authority-v2 RED suite -> GREEN
full repository regression -> PASS at exact SHA
v1.70 protected whole-chain -> PASS at exact SHA
hardened workflow matrix -> PASS at exact SHA
source/evidence hygiene -> PASS
```

Only then may #65 be refrozen to a new exact review head.
