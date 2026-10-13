# Trusted-host integration contract

This document explains the host obligations behind the NARF trust boundary. It does not turn an unavailable deployment property into PASS; stronger optional paths add obligations that the integrating host must actually enforce.

## Serialize authority and effects

Revocation and frozen-state probes are separate reads. The reference API does not lock an integrating host's mutable state. Another probe cannot eliminate the interval between the final read and an external write.

The host must use the same authority lock or transaction for relevant state changes, revocation changes, and the complete guarded effect call:

```python
with authority_lock:
    session.execute_effect()

with authority_lock:
    host_state.revoked = True
```

The probes and callback must read authority protected by that lock. Hold the lock until the synchronous callback finishes. An asynchronous callback that merely queues an unprotected later write needs a separate target-side transaction or conditional execution protocol.

Use a shared lock across processes when authority is shared across processes; an in-process threading lock is insufficient in that case. Across machines, the host must provide a corresponding transaction or fencing mechanism. All mutators must cooperate. NARF cannot synchronize an actor that bypasses the host's authority protocol.

A change committed before the guarded effect prevents execution. A mutator waiting for an effect already holding the lock commits after that effect finishes. The later revocation does not undo the completed effect.

## Freeze the effect input

The callback must use the approved input snapshot or a target operation conditionally bound to the frozen state. Copy and serialize the task before opening the session and capture that immutable serialization in the callback.

Do not let the callback select its target from an unrelated mutable caller object. The host's state probe must report relevant input changes.

## Authenticate identity and verifier-profile provenance

For the optional [identity policy](IDENTITY-BOUNDARY.md), the host authenticates builder, verifier and authority principals and defines their trust domains. It must bind each producer to those facts outside candidate control, and supply the same current actor map through `identity_probe`. A probe that merely echoes the frozen policy cannot detect changes in underlying authority.

The host also attests any configured verifier profile: actual model/provider/version, exact system and verifier prompt digests, and relevant toolchain versions. Candidate output, producer result payloads and self-reported agent labels must never populate trusted identity or profile fields.

An authority producer must validate a current approval for the exact frozen task, candidate and effect before returning PASS. NARF wraps that result in contract/session-bound evidence; it cannot authenticate a human or detect a host adapter that blindly reuses an old external approval. Authority withdrawal must reach the host's revocation probe or inhibitor path.

Once an identity-enabled session already contains verifier evidence or a decision, any identity/profile/binding error that NARF observes permanently stales that session's existing authorization. Restoring old values does not make its old evidence or decision usable again; the host must open a fresh session and produce fresh verification evidence.

Identity/profile changes must participate in the same authority lock or transaction as state/revocation changes and the complete effect path. Snapshot comparisons cannot detect change-and-restore entirely between reads; hosts needing that guarantee must bind a monotonic authority revision and serialize changes.

Distinct profiles prove different declared methods, not independent reasoning or distinct physical infrastructure.

## Own authenticated stage ordering

For optional [authenticated stage ordering](STAGE-ORDER-BOUNDARY.md), the trusted host owns the exact `stage_order` policy. Candidate, worker and verifier output must not choose or rewrite the ordering, stage index, chain seed, predecessor fields or final chain head.

The first implementation requires one complete linear permutation of all frozen `requirement_id` values. Do not derive the security order only from verifier names: multiple requirements may legitimately share one verifier route.

The public ordered gate creates host-owned chain metadata:

```text
session/contract chain seed
  -> first requirement receipt
  -> next receipt bound to predecessor ID + canonical digest
  -> ...
  -> final decision bound to final authenticated chain head
```

The host must not expose an alternate evidence-submission path that lets untrusted code manufacture these fields. A wrapper or convenience integration that cannot preserve ordered semantics must reject the ordered request rather than silently rebuild an unordered contract.

Stage ordering is not a physical clock service. It proves the accepted authenticated predecessor relation observed by the gate. It does **not** prove:

- wall-clock chronology across unrelated systems;
- cross-process shared-session ordering without external serialization;
- distributed consensus;
- verifier epistemic independence;
- ordering of external side effects beyond the configured guarded/fenced effect boundary.

Inside one `NARFSession`, the reference ordered gate provides atomic admission so a future stage cannot enter before its accepted predecessor and same-stage/re-entrant calls cannot obtain duplicate producer admission. If a deployment reconstructs one logical session across processes or machines, it needs an external serialized session authority with equivalent semantics before claiming the same property.

## Preserve stronger composition

If an ordered contract is composed with authority revision, stable operation identity or fencing, every layer must reference/preserve the exact ordered contract.

Do not:

- strip `stage_order` when constructing an authority/stable/fenced wrapper;
- reinterpret an evidence-v3 contract as legacy v1/v2;
- create a fresh unordered contract for the same requested authorization;
- let direct effect entry bypass a fenced ordered session.

The measured public wrappers fail closed on these downgrade routes. Host adapters must preserve the same rule.

## Protect receipt history and keys

The receipt key, store, store parent, backups, frozen bindings, verifier selection, probes and effect callback must remain outside candidate/worker control, as required by NARF-SPEC section 10. Directory permissions only separate principals; they do not isolate a worker running as the store owner. Use separate OS accounts, an enforced sandbox, or equivalent host controls.

HMAC authenticates contents. It does not prevent deletion or rollback. Single-use consumption also depends on preserving the deterministic consumed receipt filename. Invalid contents, an empty file, a symlink or a directory at that name do not free it for a new exclusive create. Removing or renaming the file does free it. A trusted owner restoring an old store can likewise restore old authority.

Keep consumption receipts and do not restore an older store as current authority. If privileged-owner deletion or rollback is in the threat model, the host needs a monotonic checkpoint or ledger outside the same rollback domain. The filesystem reference alone does not provide that guarantee.

## Persistence failure is not permission

Receipt file synchronization and receipt-directory synchronization must complete before a save succeeds. A failure prevents the gated callback. An uncertain consumption file remains reserved; do not delete it to retry. This sacrifices availability to preserve at-most-once invocation.

A callback failure also consumes its authorization. NARF provides at-most-once invocation, not guaranteed delivery or exactly-once remote completion. Remote acknowledgements and target-side recovery belong to the host.

## Fencing and external commit enforcement

A fence token transported to a callback is not automatically an enforced external fence. If the threat model includes authority changes racing the external commit, the target must participate in the ordering boundary.

The repository's PostgreSQL Layer C reference demonstrates one measured pattern: fence issuance, authority transition and target commit serialize in the same database scope-lock domain. That claim is specific to the tested functions, transactions and role grants; it is not a universal guarantee for arbitrary APIs or devices.

See [FENCED-EFFECT-BOUNDARY.md](FENCED-EFFECT-BOUNDARY.md) and [POSTGRES-FENCED-TARGET.md](POSTGRES-FENCED-TARGET.md).

## Verification scope

Repository tests demonstrate the reference in-process session/host semantics plus focused process, rollback, operation, fencing, signed-witness and PostgreSQL boundaries. The v1.70 candidate additionally measures authenticated stage ordering and its composition with authority revision and fenced execution.

These results do not certify an arbitrary host, OS sandbox, physical-power-loss recovery, production control plane or remote target. A protected-host demonstration does not relabel documented limitations as PASS.
