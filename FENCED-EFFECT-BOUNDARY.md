# Fenced effect boundary

Status: design freeze for the next opt-in hardened effect path. No runtime
implementation is claimed by this document.

## 1. Problem

The current composed protected-operation path verifies:

```text
identity / separation
-> monotonic authority revision
-> NARF PASS
-> stable operation reservation
-> guarded effect entry
-> external effect callback
```

That closes stale evidence, identity change-and-restore between probes, and
cross-contract replay of one stable real-world operation.

One boundary remains: authority can still change after the final trusted-host
check but before or while the external system commits the side effect.

A second snapshot check cannot solve that race. The external resource must
participate in the authorization boundary.

## 2. Goal

The fenced path must make a stale authority generation unusable at the external
resource itself.

Conceptually:

```text
NARF PASS
  -> acquire fence for operation X at authority revision R
  -> local NARF effect consumption
  -> send fence F to external resource
  -> external resource validates F at commit
  -> effect commits only if F is still current/acceptable
```

If a newer authority transition makes fence `F` stale before commit, the
external resource must reject `F`.

## 3. A fence token is not just a nonce

A random UUID, timestamp, session ID, contract ID, or incrementing integer does
not become a fencing token merely because it is named `fence`.

A valid fencing design requires all of these properties:

1. **monotonic ordering** — newer valid fences are ordered after older ones;
2. **operation binding** — the fence is for one trusted-host stable operation;
3. **authority binding** — the fence is issued only for the expected authority
   revision/generation;
4. **effect binding** — the fence is tied to the intended effect ID/version;
5. **external enforcement** — the target resource rejects stale or mismatched
   fences when it commits the effect;
6. **host provenance** — candidate/verifier output cannot mint or choose trusted
   fence facts;
7. **replay resistance** — a fence for one operation/effect cannot authorize a
   different operation/effect;
8. **fail-closed uncertainty** — ambiguous issuance/commit outcomes do not free
   the old authorization for a blind retry.

Without external enforcement, MGnarf may transport a token but cannot claim the
final TOCTOU boundary is closed.

## 4. Separation from existing concepts

These values answer different questions and must remain distinct:

```text
contract_id          which frozen NARF contract?
session_id           which verification run?
operation_id         which real semantic side effect?
authority_revision   which identity-authority generation?
fence_sequence       which effect-admission generation/order?
```

None of them should be silently reinterpreted as another.

A stable `operation_id` prevents the same real operation from being admitted
again through a fresh contract. A fence prevents an older admitted authority
generation from committing after a newer generation supersedes it.

Both may be required.

## 5. Reference API shape

The first implementation should introduce an explicit interface rather than
silently extending `ConsumptionAuthority`.

Conceptually:

```python
@dataclass(frozen=True)
class FenceToken:
    operation_id: str
    authority_revision: int
    effect_id: str
    effect_version: str
    fence_sequence: int
    authority_id: str
    authenticator: str | None = None

class FencingAuthority:
    def acquire(
        self,
        *,
        operation_id: str,
        expected_authority_revision: int,
        effect_id: str,
        effect_version: str,
    ) -> FenceToken:
        ...
```

Exact public names may differ, but fence acquisition must not degrade to the
existing `reserve(token)` semantics. The expected authority revision and effect
binding are part of the security contract.

## 6. External effect contract

The external effect adapter must receive the fence explicitly.

Conceptually:

```python
@dataclass(frozen=True)
class FencedEffectBinding:
    effect_id: str
    effect_version: str
    execute: Callable[[FenceToken], object]
```

The adapter is responsible for ensuring the target resource validates the fence
at the commit boundary.

Calling an ordinary zero-argument callback after fence issuance and merely
logging the fence is **not** sufficient.

For a database effect this may mean a transaction/CAS/advisory-lock check. For a
remote service it may mean the service persists and compares the latest accepted
sequence for the protected resource. For another target it may require a
resource-native generation/version check.

## 7. Fence authority requirements

A fencing authority used for a PASS claim must provide a documented trust model.
At minimum:

- `fence_sequence` is a non-negative integer and strictly advances according to
  the authority's ordering rule;
- one authority identity/domain cannot present two incomparable sequences as if
  both were latest;
- acquisition checks the expected authority revision atomically with issuance,
  or under a serialization mechanism that prevents an authority transition from
  being hidden during issuance;
- returned fence fields are authenticated or obtained directly from trusted host
  state rather than candidate/verifier output;
- operation/effect bindings cannot be rewritten after issuance;
- rollback of the fencing ledger is either prevented or explicitly documented as
  a limitation.

A local in-memory counter is acceptable only for reference/unit testing. It is
not evidence of process-, host-, crash-, or rollback-resistant fencing.

## 8. External resource requirements

The final guarantee exists only if the external target enforces it.

For a resource `Y`, the commit rule must be equivalent to:

```text
accept effect for Y only if supplied fence is valid for Y/operation/effect
and is not older than the target's currently accepted fence generation
```

When the target records a newer generation, an older fence must not later
succeed.

The target's comparison state must itself meet the deployment's persistence and
rollback threat model.

If the external API offers no place to validate or persist a fence, MGnarf must
label that integration `UNVERIFIED` for the final TOCTOU guarantee rather than
pretend a client-side check is equivalent.

## 9. Execution ordering

The reference hardened executor should preserve this fail-closed ordering:

```text
1. revalidate authenticated NARF PASS
2. acquire fence bound to operation + expected authority revision + effect
3. keep operation authorization consumed/uncertain after successful or ambiguous acquisition
4. persist NARF's local effect-consumption evidence
5. invoke the fenced external adapter with that exact fence
6. external resource validates fence at commit
```

No step after fence acquisition may release the operation for an automatic blind
retry merely because the callback raised or the network response was ambiguous.

Availability is sacrificed when the system cannot prove that a previously issued
fence/effect attempt was harmless.

## 10. Binding evidence

The fenced path should preserve auditable host evidence tying at minimum:

```text
contract_id
session_id
operation_id
authority_revision
effect_id
effect_version
fence_sequence
fence authority identity/domain
```

If a signed remote fencing authority is used, the authenticated response should
also bind a fresh request nonce and the exact request fields to prevent replay of
an older valid issuance response.

A fence receipt must not be accepted for another contract/session when policy
requires exact session binding, nor for another operation/effect under any mode.

## 11. Direct-effect bypass

A session configured for fenced execution must not expose a normal public route
that invokes the real external effect without a fence.

The API must fail closed if:

- a fenced session is passed to the non-fenced operation executor;
- a caller invokes the session's ordinary direct effect method;
- a `FencedEffectBinding` is replaced by an ordinary zero-argument effect binding
  after freeze/session creation;
- the fence authority is missing or unavailable.

Legacy non-fenced APIs may remain for backward compatibility, but they must be
visibly separate and must not be presented as providing the fenced guarantee.

## 12. Required adversarial tests

Before runtime implementation can claim PASS, tests must cover at least:

1. valid current fence -> external effect commits once;
2. authority revision changes before fence acquisition -> no fence/effect;
3. fence acquisition races an authority transition -> fail closed or serialize;
4. newer fence is issued before older fence reaches commit -> older fence rejected;
5. same fence replayed for the same operation -> rejected/idempotently non-duplicating;
6. fence replayed for another operation -> rejected;
7. fence replayed for another effect ID/version -> rejected;
8. fence fields tampered -> rejected;
9. missing/invalid authority identity -> rejected;
10. equal or decreasing fence sequence where strict advance is required -> rejected;
11. fencing ledger rollback -> BLOCKED or documented LIMITATION_CONFIRMED, never
    silently PASS;
12. direct session effect bypass -> BLOCKED;
13. non-fenced `OperationBoundEffectExecutor` used on fenced session -> BLOCKED;
14. callback/network failure after fence issuance -> authorization remains
    consumed/uncertain, no blind retry;
15. crash after fence issuance but before local callback -> fail closed on retry;
16. external resource that merely receives/logs a token but does not enforce it ->
    UNVERIFIED for final TOCTOU protection;
17. two concurrent fences for one protected operation/resource -> deterministic
    ordering with at most the newest/currently valid fence able to commit;
18. legacy non-fenced path remains behaviorally compatible and is not relabeled
    as fenced.

## 13. Reference implementation strategy

Implementation should proceed in three layers:

### Layer A — contracts and negative tests

Add `FenceToken`, `FencingAuthority`, and `FencedEffectBinding` semantics with
focused tests that initially demonstrate the missing API/boundary.

### Layer B — host orchestration

Add a fenced executor that composes with the current authority-revision + stable
operation session. It must prevent direct/non-fenced execution routes for fenced
sessions.

### Layer C — independently enforcing example target

Provide at least one reference target/adapter that actually validates fence order
at commit. A test-only in-memory target can establish API semantics; a stronger
PostgreSQL or remote-witness example is needed before claiming process/rollback
resistance for a deployment class.

The generic interface alone is not evidence that a real target enforces fences.

## 14. Acceptance language

Allowed claim after Layer A/B only:

> MGnarf can bind and transport a fence through the hardened effect path and
> fails closed when required fencing evidence is unavailable or mismatched.

Stronger claim allowed only after an enforcing target has been verified:

> For the tested target/authority configuration, stale fences are rejected at the
> external commit boundary under the measured threat model.

Do not claim that MGnarf universally eliminates TOCTOU for arbitrary external
systems.
