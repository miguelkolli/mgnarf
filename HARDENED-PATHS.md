# MGnarf hardened execution paths

This page answers one practical question:

> **Which MGnarf path do I need for the effect I am protecting?**

The answer depends on the threat model. MGnarf deliberately exposes stronger
opt-in layers instead of pretending that one local `PASS` automatically proves
all remote execution properties.

## Status

The paths on this page describe current `main` development after the immutable
v1.61 release tag. They do not silently rewrite the historical v1.61 release
scope or evidence.

The current stable release remains documented in
[RELEASE-v1.61.md](RELEASE-v1.61.md) and
[TEST-REPORT-v1.61.md](TEST-REPORT-v1.61.md).

## Choose the protection level

| Need | Reference path | What it adds | Important retained boundary |
| --- | --- | --- | --- |
| Bind verification to the exact candidate/task/policy and make one local effect single-use | `NARFGate` | frozen contract, N/N evidence, state/revocation revalidation, authenticated receipts | trusted host still owns correct effect serialization |
| Require builder/verifier/authority separation | identity-enabled `NARFGate` | `principal_id`, `trust_domain`, optional `verifier_profile`, separation policy | host authenticates identity provenance |
| Detect identity authority change-and-restore between ordinary snapshots | `AuthorityRevisionGate` | rollback-resistant monotonic authority revision bound to the identity-enabled contract | final external commit is still a separate boundary |
| Keep one real-world operation single-use across fresh contracts/retries | `OperationBoundGate(..., authority_probe=...)` + external consumption authority | stable host-owned `operation_id` combined with identity/revision checks | consumption authority must meet the rollback threat model |
| Carry a bound monotonic fence into the effect adapter | `FencedOperationGate` + `FencedOperationEffectExecutor` | `fence_scope_id`, frozen fencing authority, fence evidence, downgrade/direct-route guards | token transport alone does not prove the target enforces the fence |
| Make authority/fence validity part of the external commit itself | PostgreSQL Layer C reference | DB-owned fence issuance, authority transition and effect commit serialized in one measured PostgreSQL boundary | guarantee is specific to the tested DB/functions/role model; privileged owner/admin rollback remains outside it |

These are cumulative ideas, not marketing tiers. Use only the stronger path when
its additional trust assumptions match the system you can actually enforce.

## 1. Core gate — exact evidence before action

Use the core `NARFGate` when the trusted host can already serialize the relevant
state and effect path and you primarily need to prove:

```text
exact frozen candidate/task/policy
        +
all required host-owned verifier evidence
        +
current state/revocation still valid
        +
authenticated PASS
        ->
one local effect admission
```

The key property is not merely "tests passed". The evidence is bound to the
exact frozen thing that is being authorized. If the candidate or relevant state
changes, the old evidence cannot silently authorize the changed effect.

Start with:

- [NARF-SPEC.md](NARF-SPEC.md)
- [HOST-CONTRACT.md](HOST-CONTRACT.md)
- [INTEGRATION-GUIDE.md](INTEGRATION-GUIDE.md)

## 2. Identity separation — who produced the evidence?

Different verifier names are not proof of independent review. Two logical
checks may still be controlled by the same actor or failure domain.

The identity-enabled path keeps these concepts separate:

```text
verifier_id       which logical check?
principal_id      who controls/authenticates the actor?
trust_domain      which actors may fail or be compromised together?
verifier_profile  how was the verification produced?
```

The trusted host, not the candidate or worker, owns identity provenance.
Separation policy can require, for example, that the builder and an independent
security verifier have different principals and trust domains.

Observed identity/profile drift is sticky for the existing authorization: once
an existing evidence set is observed stale, restoring the old values does not
resurrect the old PASS. Fresh verification requires a fresh authorization run.

See [IDENTITY-BOUNDARY.md](IDENTITY-BOUNDARY.md).

## 3. Monotonic authority revision — make hidden transitions visible

Snapshot comparison cannot detect this by itself:

```text
check identity at revision 11
   -> authority changes
   -> authority is restored to the same visible values
check identity again
```

`AuthorityRevisionGate` binds the contract to a trusted-host monotonic authority
revision. A relevant authority transition must advance that revision and must
not roll it back.

This closes the measured change-and-restore gap **before effect admission**. It
does not by itself prove that an unrelated external service cannot change state
between the final local check and its own commit.

See [AUTHORITY-REVISION.md](AUTHORITY-REVISION.md).

## 4. Stable operation identity — protect the real-world operation, not one contract UUID

A fresh NARF contract intentionally gets a fresh contract identity. That means a
contract UUID is not enough to identify one semantic real-world operation across
retries or newly frozen contracts.

The operation-bound path adds a trusted-host-owned stable `operation_id`:

```text
contract A / operation X -> consumed
contract B / operation X -> external authority rejects replay
```

This matters for operations such as:

- deploy this exact release once;
- publish this artifact once;
- apply this migration once;
- submit this external request once.

Use an external consumption authority appropriate to the rollback threat model.
The repository includes filesystem, PostgreSQL and signed-witness examples with
explicitly measured limits.

See:

- [OPERATION-IDEMPOTENCY.md](OPERATION-IDEMPOTENCY.md)
- [COMPOSED-OPERATION-PATH.md](COMPOSED-OPERATION-PATH.md)
- [ROLLBACK-HARDENING.md](ROLLBACK-HARDENING.md)

## 5. Fence transport — bind effect admission to a resource generation

A stable operation ID prevents replay of one semantic operation, but it does not
solve the final race where authority changes after local admission while an old
worker is still able to reach the external resource.

The fenced path adds distinct concepts:

```text
operation_id         which semantic operation?
fence_scope_id       which protected resource / ordering namespace?
authority_revision   which authority generation?
fence_sequence       which fence generation/order inside that scope?
fencing_authority_id which trusted authority issued the fence?
```

`FencedOperationGate` freezes the scope and fencing-authority identity before
verification. `FencedOperationEffectExecutor` reserves the stable operation
before fence issuance, validates the returned fence, persists authenticated
fence evidence and transports the exact `FenceToken` into a
`FencedEffectBinding`.

The ordering is intentionally fail-closed:

```text
NARF PASS
  -> durable stable operation reservation
  -> acquire bound fence
  -> authenticated fence evidence
  -> local NARF effect consumption
  -> fenced adapter(token)
```

If uncertainty appears after the stable operation has been reserved, MGnarf
sacrifices availability instead of automatically freeing the operation for a
blind retry.

But an important distinction remains:

> **Receiving a fence token is not the same as enforcing a fence token.**

If the target only logs the token, or the client merely checks it one more time
before an ordinary remote write, the final external commit boundary is still
unverified.

See [FENCED-EFFECT-BOUNDARY.md](FENCED-EFFECT-BOUNDARY.md).

## 6. PostgreSQL Layer C — enforce the fence at the measured commit boundary

The PostgreSQL Layer C reference is the repository's concrete example of a
target that participates in the security boundary.

The reference installs DB-owned functions from:

```text
sql/postgres_fencing_v1.sql
```

The public adapters are:

```text
PostgresFencingAuthority
PostgresFenceControlPlane
PostgresFencedTarget
```

The security-critical flow is:

```text
MGnarf PASS
   -> stable operation reservation
   -> PostgreSQL narf_acquire_fence(...)
   -> FenceToken
   -> MGnarf local consumption/evidence
   -> PostgresFencedTarget.commit(token)
   -> PostgreSQL narf_commit_fenced_effect(...)
   -> validate current authority revision
   -> validate current fence sequence
   -> validate exact issuance binding
   -> insert effect
   -> COMMIT
```

Fence issuance, authority transitions and fenced effect commit use the same
per-`fence_scope_id` transaction advisory-lock namespace inside PostgreSQL.
Therefore the database determines the order rather than relying on two
client-side snapshots.

### The important race

The measured reference demonstrates this case:

```text
fence issued at authority revision 11
   -> MGnarf reaches protected callback entry
   -> authority advances 11 -> 12
   -> no revision-12 effect or fence is required
   -> old revision-11 token reaches target commit
   -> PostgreSQL rejects the stale token
   -> 0 external effect rows committed
```

It also measures the inverse ordering: if target commit obtains the serialized
scope authority first and commits successfully, a later authority transition is
ordered after that committed effect.

### Runtime role model

The hardened reference reduces runtime DB roles to narrow function authority:

| Role | Intended database authority |
| --- | --- |
| fence issuer | execute `narf_acquire_fence`; use the separate stable-operation consumption ledger |
| control plane | execute current-revision and advance-revision functions |
| target | execute `narf_commit_fenced_effect` |
| function/schema owner | privileged bootstrap/administrative boundary; not a runtime role |

Direct DML on fencing/effect tables is revoked from the runtime roles. The CI
harness actively attempts direct bypasses and verifies the function EXECUTE
matrix instead of trusting the GRANT statements on paper.

### What was measured

The dedicated PostgreSQL fenced-target workflow requires:

```text
5 PASS
1 LIMITATION_CONFIRMED
0 FAIL
```

The protected cases include:

- current fence commits once;
- authority transition before target commit invalidates the old fence without a
  newer effect;
- newer fence supersedes older fence in the same scope;
- authority transition serializes with concurrent fence acquisition;
- authority transition serializes with concurrent target commit.

The limitation witness deliberately shows that a privileged PostgreSQL
owner/administrator that rewrites the authoritative fencing state can restore an
old generation and allow the old token again. That is **not** relabeled as a
protected case.

See [POSTGRES-FENCED-TARGET.md](POSTGRES-FENCED-TARGET.md).

## 7. What the PostgreSQL claim actually means

Allowed claim:

> For the tested PostgreSQL function-enforced transaction/role configuration,
> authority transitions and fence ordering are validated at the external effect
> commit boundary; a transition that commits before the effect commit invalidates
> the older fence.

Not allowed:

> MGnarf universally eliminates TOCTOU for every database, API, cloud provider
> or external system.

The measured guarantee depends on the exact PostgreSQL functions, role grants,
transaction semantics, function owner and target adapter. If those change, the
stronger claim must be re-verified.

## 8. Deployment checklist for the hardened PostgreSQL reference

Before using the Layer C claim, verify at minimum:

- [ ] the supplied SQL/functions were installed from the revision you reviewed;
- [ ] runtime issuer/control/target credentials do not have direct DML authority
      over the fencing/effect tables beyond the documented stable-operation
      ledger permission;
- [ ] PUBLIC cannot execute the security-definer fencing functions;
- [ ] each runtime role has only the function EXECUTE rights it needs;
- [ ] `fence_scope_id` identifies the actual resource ordering domain;
- [ ] the authority revision advances for every relevant authority transition;
- [ ] the real external effect is performed inside the enforcing commit function
      or an equivalently measured target boundary;
- [ ] the privileged schema/function owner is handled according to the deployment
      threat model;
- [ ] database backup/restore, failover and administrative rollback are either
      excluded from the threat model or independently protected and tested;
- [ ] the stable `operation_id` remains the same across retries/new contracts for
      the same semantic real-world operation;
- [ ] ambiguous post-reservation failures do not automatically free authority for
      blind retry;
- [ ] you have reproduced at least one stale-fence rejection against the actual
      deployment class.

If any required part is unknown, label that part **UNVERIFIED**.

## 9. Recommended reading order

For the strongest reference path:

1. [OVERVIEW.md](OVERVIEW.md)
2. [INTEGRATION-GUIDE.md](INTEGRATION-GUIDE.md)
3. [IDENTITY-BOUNDARY.md](IDENTITY-BOUNDARY.md)
4. [AUTHORITY-REVISION.md](AUTHORITY-REVISION.md)
5. [COMPOSED-OPERATION-PATH.md](COMPOSED-OPERATION-PATH.md)
6. [FENCED-EFFECT-BOUNDARY.md](FENCED-EFFECT-BOUNDARY.md)
7. [POSTGRES-FENCED-TARGET.md](POSTGRES-FENCED-TARGET.md)
8. [HOST-CONTRACT.md](HOST-CONTRACT.md)

The stronger path is useful precisely because each layer states what it proves
and what remains outside its boundary.
