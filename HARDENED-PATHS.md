# MGnarf hardened execution paths

This page answers one practical question:

> **Which MGnarf path do I need for the effect I am protecting?**

The answer depends on the threat model. MGnarf deliberately exposes stronger opt-in layers instead of pretending that one local `PASS` automatically proves all remote execution properties.

## Status

The current published stable release remains **v1.61**. The repository also contains the **v1.70 candidate** hardened line described in [RELEASE-v1.70.md](RELEASE-v1.70.md) and [TEST-REPORT-v1.70.md](TEST-REPORT-v1.70.md). Candidate functionality is not a published stable guarantee until the final release gate completes.

## Choose the protection level

| Need | Reference path | What it adds | Important retained boundary |
| --- | --- | --- | --- |
| Bind verification to exact candidate/task/policy and make one local effect single-use | `NARFGate` | frozen contract, N/N evidence, state/revocation revalidation, authenticated receipts | trusted host still owns correct effect serialization |
| Require builder/verifier/authority separation | identity-enabled `NARFGate` | `principal_id`, `trust_domain`, optional `verifier_profile`, separation policy | host authenticates identity provenance |
| Require required checks/authority in authenticated causal order | `NARFGate` + `freeze_contract(..., stage_order=...)` | evidence-v3 requirement chain, authenticated predecessor binding, final chain-head binding | not physical wall-clock chronology or verifier epistemic independence |
| Detect identity authority change-and-restore | `AuthorityRevisionGate` | rollback-resistant monotonic authority revision | final external commit is still a separate boundary |
| Keep one real-world operation single-use across fresh contracts/retries | `OperationBoundGate(..., authority_probe=...)` + external consumption authority | stable host-owned `operation_id` | authority must meet rollback threat model |
| Carry a bound monotonic fence into the effect adapter | `FencedOperationGate` + `FencedOperationEffectExecutor` | `fence_scope_id`, frozen fencing authority, fence evidence, downgrade/direct-route guards | token transport alone does not prove target enforcement |
| Make authority/fence validity part of external commit | PostgreSQL Layer C reference | DB-owned fence issuance, authority transition and effect commit serialized in one measured PostgreSQL boundary | guarantee is specific to tested DB/functions/role model; privileged owner/admin rollback remains outside it |

These are cumulative ideas. A stronger path adds conditions; it does not replace the obligations below it.

## 1. Core gate — exact evidence before action

Use core `NARFGate` when the trusted host can serialize relevant state/effect paths and you need to prove:

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

The evidence is bound to the exact frozen thing being authorized. If relevant state changes, old evidence cannot silently authorize the changed effect.

Start with [NARF-SPEC.md](NARF-SPEC.md), [HOST-CONTRACT.md](HOST-CONTRACT.md) and [INTEGRATION-GUIDE.md](INTEGRATION-GUIDE.md).

## 2. Identity separation — who produced the evidence?

Different verifier names are not proof of independent review. Identity-enabled MGnarf keeps logical verifier ID, authenticated principal, trust domain and optional verifier profile separate.

```text
verifier_id       which logical check?
principal_id      who controls/authenticates the actor?
trust_domain      which actors may fail together?
verifier_profile  how was verification produced?
```

The trusted host owns provenance. Observed identity/profile drift is sticky for the existing authorization: restoring old values does not resurrect old evidence.

See [IDENTITY-BOUNDARY.md](IDENTITY-BOUNDARY.md).

## 3. Authenticated stage ordering — what had to exist first?

Identity independence does not prove causal order. If a policy requires:

```text
tests -> independent security review -> authority approval
```

then ordinary unordered N/N evidence is insufficient to prove that sequence.

The optional stage-order path freezes one complete linear permutation of exact `requirement_id` values. Ordered contracts use evidence v3.

```text
frozen builder/candidate context
  -> requirement A PASS
  -> requirement B PASS bound to A receipt
  -> authority PASS bound to B receipt
  -> decision bound to final chain head
  -> existing guarded effect path
```

Security properties:

- first stage binds to a deterministic session/contract chain seed;
- later stage binds to authenticated predecessor receipt ID + canonical digest;
- a future stage fails before its producer runs;
- `FAIL`/`BLOCKED` predecessor cannot admit the next stage;
- same-stage concurrency and same-thread re-entrancy admit at most one producer;
- predecessor evidence from another session/contract/candidate/order cannot satisfy the chain;
- identity separation and stage order remain independent conditions;
- final PASS binds the final authenticated chain head;
- authority/stable-operation/fenced wrappers preserve ordering or fail closed.

Do **not** interpret this as physical wall-clock proof. The first implementation does not provide distributed consensus, cross-process shared-session ordering, parallel/DAG workflow semantics, or verifier epistemic independence.

See [STAGE-ORDER-BOUNDARY.md](STAGE-ORDER-BOUNDARY.md).

## 4. Monotonic authority revision — make hidden transitions visible

Snapshot comparison alone cannot detect change-and-restore between reads. `AuthorityRevisionGate` binds a trusted-host monotonic revision to the authorization. Relevant transitions must advance it and must not roll it back.

For ordered contracts, the authority binding covers the exact ordered contract/stage-order digest. Downgrading an ordered authority binding to an unordered form fails closed.

See [AUTHORITY-REVISION.md](AUTHORITY-REVISION.md).

## 5. Stable operation identity — protect the real-world operation

A fresh NARF contract gets a fresh contract identity. Stable operation binding adds a host-owned semantic `operation_id` across retries/new contracts:

```text
contract A / operation X -> consumed
contract B / operation X -> external authority rejects replay
```

Use an external consumption authority appropriate to the rollback threat model. The repository includes filesystem, PostgreSQL and signed-witness examples.

See [OPERATION-IDEMPOTENCY.md](OPERATION-IDEMPOTENCY.md), [COMPOSED-OPERATION-PATH.md](COMPOSED-OPERATION-PATH.md) and [ROLLBACK-HARDENING.md](ROLLBACK-HARDENING.md).

## 6. Fence transport — bind effect admission to a resource generation

A stable operation ID prevents replay but does not solve the final race where authority changes while an old worker can still reach an external resource.

The fenced path adds:

```text
operation_id
fence_scope_id
authority_revision
fence_sequence
fencing_authority_id
```

The fail-closed ordering is:

```text
MGnarf PASS
  -> durable stable-operation reservation
  -> acquire bound fence
  -> authenticated fence evidence
  -> local NARF consumption
  -> fenced adapter(token)
```

For ordered v3 contracts, that exact ordered authorization is preserved through the same path. Stage ordering does not substitute for fence enforcement.

> **Receiving a fence token is not the same as enforcing it.**

If the target only logs or client-checks a token, the final external commit boundary remains unverified.

See [FENCED-EFFECT-BOUNDARY.md](FENCED-EFFECT-BOUNDARY.md).

## 7. PostgreSQL Layer C — enforce the fence at commit

The PostgreSQL Layer C reference is the repository's concrete example of a target that participates in the security boundary.

Public adapters:

```text
PostgresFencingAuthority
PostgresFenceControlPlane
PostgresFencedTarget
```

Measured flow:

```text
MGnarf PASS
   -> stable operation reservation
   -> PostgreSQL narf_acquire_fence(...)
   -> FenceToken
   -> MGnarf consumption/evidence
   -> PostgresFencedTarget.commit(token)
   -> PostgreSQL narf_commit_fenced_effect(...)
   -> validate current authority revision + fence + issuance binding
   -> insert effect
   -> COMMIT
```

Fence issuance, authority transitions and fenced effect commit use the same per-`fence_scope_id` transaction advisory-lock namespace. The database determines order rather than relying on two client-side snapshots.

The measured PostgreSQL workflow requires protected PASS cases plus an explicit privileged rollback limitation. Runtime roles have narrow function authority; direct critical-table DML is denied in the tested role model.

Allowed claim:

> For the tested PostgreSQL function-enforced transaction/role configuration, authority transitions and fence ordering are validated at the external effect commit boundary; a transition that commits before the effect commit invalidates the older fence.

Not allowed claim:

> MGnarf universally eliminates TOCTOU for every database, API, cloud provider or external system.

See [POSTGRES-FENCED-TARGET.md](POSTGRES-FENCED-TARGET.md).

## 8. Deployment checklist

Before calling a hardened path protected, verify at minimum:

- [ ] the real effect credential is unavailable to candidate/worker code;
- [ ] the exact task/candidate/effect payload is frozen;
- [ ] required verifiers are selected and executed by trusted host authority;
- [ ] configured identity facts come from authenticated host provenance;
- [ ] if `stage_order` is used, it is the exact complete required `requirement_id` sequence and no wrapper drops it;
- [ ] relevant identity/state/revocation changes use the same authority protocol as the effect path;
- [ ] stable `operation_id` remains the same across retries/new contracts for the same real-world operation;
- [ ] ambiguous post-reservation failure does not automatically free authority;
- [ ] when fencing is claimed, the target actually enforces the fence at the measured boundary;
- [ ] rollback/backup/failover/admin threats are explicitly inside or outside the deployment threat model;
- [ ] at least one stale/revoked/replayed/incorrectly ordered effect has been tested against the real deployment class.

If a required part is unknown, label that part **UNVERIFIED**.

## 9. Recommended reading order

For the strongest current candidate path:

1. [OVERVIEW.md](OVERVIEW.md)
2. [INTEGRATION-GUIDE.md](INTEGRATION-GUIDE.md)
3. [IDENTITY-BOUNDARY.md](IDENTITY-BOUNDARY.md)
4. [STAGE-ORDER-BOUNDARY.md](STAGE-ORDER-BOUNDARY.md)
5. [AUTHORITY-REVISION.md](AUTHORITY-REVISION.md)
6. [COMPOSED-OPERATION-PATH.md](COMPOSED-OPERATION-PATH.md)
7. [FENCED-EFFECT-BOUNDARY.md](FENCED-EFFECT-BOUNDARY.md)
8. [POSTGRES-FENCED-TARGET.md](POSTGRES-FENCED-TARGET.md)
9. [HOST-CONTRACT.md](HOST-CONTRACT.md)

The stronger path is useful precisely because each layer states what it proves and what remains outside its boundary.
