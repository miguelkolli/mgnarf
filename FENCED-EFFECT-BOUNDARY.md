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
  -> acquire fence for operation X / fence scope Y at authority revision R
  -> local NARF effect consumption
  -> send fence F to external resource Y
  -> external resource validates F against current authoritative generation at commit
  -> effect commits only if F is still current/acceptable
```

If an authority transition makes fence `F` stale before commit, the external
resource must reject `F` even when no newer MGnarf effect is ever attempted.

That last requirement is important. Merely issuing a newer token somewhere else
is not enough unless the target can observe the newer authoritative generation
at commit.

## 3. A fence token is not just a nonce

A random UUID, timestamp, session ID, contract ID, or incrementing integer does
not become a fencing token merely because it is named `fence`.

A valid fencing design requires all of these properties:

1. **monotonic ordering** — newer valid fences are ordered after older ones
   within an explicit fencing scope;
2. **fence-scope binding** — the ordering namespace / protected resource is
   explicit and stable;
3. **operation binding** — the fence is for one trusted-host stable operation;
4. **authority binding** — the fence is issued only for the expected authority
   revision/generation;
5. **effect binding** — the fence is tied to the intended effect ID/version;
6. **external enforcement** — the target resource rejects stale or mismatched
   fences when it commits the effect;
7. **host provenance** — candidate/verifier output cannot mint or choose trusted
   fence facts;
8. **replay resistance** — a fence for one scope/operation/effect cannot
   authorize another;
9. **fail-closed uncertainty** — ambiguous issuance/commit outcomes do not free
   the old authorization for a blind retry.

Without external enforcement, MGnarf may transport a token but cannot claim the
final TOCTOU boundary is closed.

## 4. Separation from existing concepts

These values answer different questions and must remain distinct:

```text
contract_id          which frozen NARF contract?
session_id           which verification run?
operation_id         which one real semantic side effect?
fence_scope_id       which resource / ordering namespace is fenced?
authority_revision   which identity-authority generation?
fence_sequence       which admission generation inside that fence scope?
```

None of them should be silently reinterpreted as another.

`operation_id` and `fence_scope_id` are deliberately different. Two separate
legitimate operations can target the same resource and therefore share one fence
scope while retaining different operation IDs.

Example:

```text
operation A = update deployment config
operation B = restart deployment
fence scope = production-deployment-X
```

If `operation_id` were used as the ordering namespace, fences from A and B would
not be comparable even though both can race on the same protected resource.

A stable `operation_id` prevents the same real operation from being admitted
again through a fresh contract. A fence prevents an older admitted generation
from committing against the same protected scope after a newer authority
state/generation supersedes it.

Both may be required.

## 5. Reference API shape

The first implementation should introduce an explicit interface rather than
silently extending `ConsumptionAuthority`.

Conceptually:

```python
@dataclass(frozen=True)
class FenceToken:
    fence_scope_id: str
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
        fence_scope_id: str,
        operation_id: str,
        expected_authority_revision: int,
        effect_id: str,
        effect_version: str,
    ) -> FenceToken:
        ...
```

Exact public names may differ, but fence acquisition must not degrade to the
existing `reserve(token)` semantics. The fence scope, expected authority
revision, stable operation and effect binding are part of the security contract.

Fence sequence ordering is defined within an explicit authority/scope namespace,
for example:

```text
(authority_id, fence_scope_id)
```

An implementation may use a globally increasing sequence, but it must still bind
and validate the intended scope so unrelated resources do not accidentally gain
or lose authority from one another.

## 6. External effect contract

The external effect adapter must receive the fence explicitly.

Conceptually:

```python
@dataclass(frozen=True)
class FencedEffectBinding:
    effect_id: str
    effect_version: str
    fence_scope_id: str
    execute: Callable[[FenceToken], object]
```

The adapter is responsible for ensuring the target resource validates the fence
at the commit boundary.

Calling an ordinary zero-argument callback after fence issuance and merely
logging the fence is **not** sufficient.

For a database effect this may mean one transaction that compares the target's
current fencing/authority generation and performs the effect atomically. For a
remote service it may mean the service validates the supplied generation against
an authoritative fencing state at commit. For another target it may require a
resource-native generation/version check.

## 7. Fence authority requirements

A fencing authority used for a PASS claim must provide a documented trust model.
At minimum:

- `fence_sequence` is a non-negative integer and strictly advances according to
  the authority's ordering rule within its declared scope;
- the scope namespace is unambiguous and stable;
- one authority identity/domain cannot present two incomparable sequences for
  the same scope as if both were latest;
- acquisition checks the expected authority revision atomically with issuance,
  or under a serialization mechanism that prevents an authority transition from
  being hidden during issuance;
- returned fence fields are authenticated or obtained directly from trusted host
  state rather than candidate/verifier output;
- scope/operation/effect bindings cannot be rewritten after issuance;
- rollback of the fencing ledger is either prevented or explicitly documented as
  a limitation.

A local in-memory counter is acceptable only for reference/unit testing. It is
not evidence of process-, host-, crash-, or rollback-resistant fencing.

## 8. Commit-time invalidation requirement

The final authority-transition guarantee requires more than the common
"resource remembers the largest fence token it has seen" pattern.

That simpler pattern protects this case:

```text
resource has already observed fence 42
worker later presents fence 41
-> reject 41
```

It does **not by itself** protect this case:

```text
worker holds fence 41
authority changes to a newer generation
no newer effect/fence has reached the resource
worker presents 41
```

If the resource only compares against `max_seen == 41`, it may still accept the
old worker. That would leave the authority-transition TOCTOU open.

Therefore a configuration claiming that authority transitions invalidate old
fences must provide one of these equivalent boundaries:

1. authority transition and target effect commit serialize through the same
   transactional/locking/fencing state;
2. authority transition advances authoritative fence-generation state that the
   target reads and validates atomically at effect commit;
3. the target validates the fence against a remote fencing authority whose
   current generation includes the authority transition, with commit semantics
   strong enough for the claimed threat model;
4. another mechanism with equivalent proof that an authority transition that
   precedes commit invalidates the old fence at that commit.

A newer MGnarf effect does not need to occur for the old fence to become stale.

## 9. External resource requirements

The final guarantee exists only if the external target enforces it.

For a fence scope `Y`, the commit rule must be equivalent to:

```text
accept effect only if:
- fence.scope == Y
- operation/effect bindings match
- fence is authenticated/host-trusted
- fence's authority generation is still current for Y
- fence sequence is acceptable for Y under the configured ordering rule
```

When authoritative generation advances, an older fence must not later succeed,
even if the target has never received a newer effect request.

The target's comparison/generation state must itself meet the deployment's
persistence and rollback threat model.

If the external API offers no place to validate or persist/query authoritative
fence state at commit, MGnarf must label that integration `UNVERIFIED` for the
final TOCTOU guarantee rather than pretend a client-side check is equivalent.

## 10. Execution ordering

The reference hardened executor should preserve this fail-closed ordering:

```text
1. revalidate authenticated NARF PASS
2. acquire fence bound to scope + operation + expected authority revision + effect
3. keep operation authorization consumed/uncertain after successful or ambiguous acquisition
4. persist NARF's local effect-consumption evidence
5. invoke the fenced external adapter with that exact fence
6. external resource validates current authoritative generation and fence at commit
```

No step after fence acquisition may release the operation for an automatic blind
retry merely because the callback raised or the network response was ambiguous.

Availability is sacrificed when the system cannot prove that a previously issued
fence/effect attempt was harmless.

## 11. Binding evidence

The fenced path should preserve auditable host evidence tying at minimum:

```text
contract_id
session_id
fence_scope_id
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
requires exact session binding, nor for another scope/operation/effect under any
mode.

## 12. Direct-effect bypass

A session configured for fenced execution must not expose a normal public route
that invokes the real external effect without a fence.

The API must fail closed if:

- a fenced session is passed to the non-fenced operation executor;
- a caller invokes the session's ordinary direct effect method;
- a `FencedEffectBinding` is replaced by an ordinary zero-argument effect binding
  after freeze/session creation;
- the fence authority is missing or unavailable;
- the fence scope in the binding differs from the acquired fence.

Legacy non-fenced APIs may remain for backward compatibility, but they must be
visibly separate and must not be presented as providing the fenced guarantee.

## 13. Required adversarial tests

Before runtime implementation can claim PASS, tests must cover at least:

1. valid current fence -> external effect commits once;
2. authority revision changes before fence acquisition -> no fence/effect;
3. fence acquisition races an authority transition -> fail closed or serialize;
4. authority transition occurs after fence acquisition but before commit, with
   **no newer effect request** -> old fence rejected at external commit;
5. newer authoritative fence generation is registered/committed before older
   fence reaches commit -> older fence rejected;
6. same fence replayed for the same operation -> rejected/idempotently
   non-duplicating;
7. fence replayed for another operation in the same scope -> rejected;
8. fence replayed for another effect ID/version -> rejected;
9. fence replayed for another fence scope -> rejected;
10. two different legitimate operations in the same fence scope produce
    comparable fence generations;
11. activity in a different fence scope does not accidentally authorize or
    invalidate this scope unless the authority explicitly uses a global ordering
    model;
12. fence fields tampered -> rejected;
13. missing/invalid authority identity -> rejected;
14. equal or decreasing fence sequence where strict advance is required ->
    rejected;
15. fencing ledger rollback -> BLOCKED or documented LIMITATION_CONFIRMED, never
    silently PASS;
16. direct session effect bypass -> BLOCKED;
17. non-fenced `OperationBoundEffectExecutor` used on fenced session -> BLOCKED;
18. callback/network failure after fence issuance -> authorization remains
    consumed/uncertain, no blind retry;
19. crash after fence issuance but before local callback -> fail closed on retry;
20. external resource that merely receives/logs a token or only tracks the
    largest previously seen token without authority-transition invalidation ->
    UNVERIFIED for the stronger final TOCTOU claim;
21. concurrent fences in one scope -> deterministic ordering and commit behavior
    consistent with the authority/target protocol;
22. legacy non-fenced path remains behaviorally compatible and is not relabeled
    as fenced.

## 14. Reference implementation strategy

Implementation should proceed in three layers:

### Layer A — contracts and negative tests

Add `FenceToken`, `FencingAuthority`, `FencedEffectBinding`, and explicit
`fence_scope_id` semantics with focused tests that initially demonstrate the
missing API/boundary.

### Layer B — host orchestration

Add a fenced executor that composes with the current authority-revision + stable
operation session. It must prevent direct/non-fenced execution routes for fenced
sessions.

Layer B may demonstrate correct binding/transport and fail-closed routing, but
cannot establish authority-transition invalidation at external commit by itself.

### Layer C — independently enforcing example target

Provide at least one reference target/adapter that actually validates current
authoritative generation and fence order at commit.

A test-only in-memory target can establish API semantics. A stronger PostgreSQL
or remote target is needed before claiming process/rollback resistance for a
deployment class.

For the stronger authority-transition claim, the target/authority arrangement
must also demonstrate that a transition occurring after fence acquisition and
before commit invalidates the old fence **without requiring a newer effect to
arrive first**.

The generic interface alone is not evidence that a real target enforces fences.

## 15. Acceptance language

Allowed claim after Layer A/B only:

> MGnarf can bind and transport a fence through the hardened effect path and
> fails closed when required fencing evidence is unavailable or mismatched.

Allowed claim for a target that only rejects tokens older than ones it has
already observed:

> For the tested target, previously superseded/observed fence generations are
> rejected at commit. Authority-transition invalidation before a newer target
> observation remains UNVERIFIED.

Stronger claim allowed only after an enforcing target/authority configuration
has verified commit-time authority-transition invalidation:

> For the tested target/authority configuration, an authority transition that
> precedes commit invalidates the older fence at the external commit boundary
> under the measured threat model.

Do not claim that MGnarf universally eliminates TOCTOU for arbitrary external
systems.
