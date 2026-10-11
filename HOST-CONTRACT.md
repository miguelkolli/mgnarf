# Trusted-host integration contract

This document explains the host obligations behind the existing NARF trust
boundary. It does not change PASS criteria or add a new acceptance gate.

## Serialize authority and effects

Revocation and frozen-state probes are separate reads. The reference API does
not lock an integrating host's mutable state. Another probe cannot eliminate
the interval between the final read and an external write.

The host must use the same authority lock or transaction for relevant state
changes, revocation changes, and the complete `execute_effect()` call:

```python
# The lock belongs to the trusted host, outside candidate control.
with authority_lock:
    session.execute_effect()  # revalidation, receipt persistence, callback

# Every host actor changing relevant authority must use the same lock.
with authority_lock:
    host_state.revoked = True
```

The probes and callback must read the authority protected by that lock. Hold
the lock until the synchronous callback finishes. An asynchronous callback
that merely queues an unprotected later write needs a separate target-side
transaction or conditional execution protocol.

Use a shared lock across processes when authority is shared across processes;
an in-process threading lock is insufficient in that case. Across machines,
the host must provide a corresponding transaction or fencing mechanism. All
mutators must cooperate. NARF cannot synchronize an actor that bypasses the
host's authority protocol.

A change committed before the guarded effect prevents execution. A mutator
waiting for an effect already holding the lock commits after that effect
finishes. The later revocation does not undo the completed effect.

## Freeze the effect's input

The callback must use the approved input snapshot or a target operation
conditionally bound to the frozen state. Copy and serialize the task before
opening the session and capture that immutable serialization in the callback.
Do not let the callback select its target from an unrelated mutable caller
object. The host's state probe must report relevant input changes.

## Protect receipt history and keys

The receipt key, store, store parent, backups, frozen bindings, verifier
selection, probes and effect callback must remain outside candidate/worker
control, as required by NARF-SPEC section 10. Directory permissions only
separate principals; they do not isolate a worker running as the store owner.
Use separate OS accounts, an enforced sandbox, or equivalent host controls.

HMAC authenticates contents. It does not prevent deletion or rollback.
Single-use consumption also depends on preserving the deterministic consumed
receipt filename. Invalid contents, an empty file, a symlink or a directory
at that name do not free it for a new exclusive create. Removing or renaming
the file does free it. A trusted owner restoring an old store can likewise
restore old authority.

Keep consumption receipts and do not restore an older store as current
authority. If privileged-owner deletion or rollback is in the threat model,
the host needs a monotonic checkpoint or ledger outside the same rollback
domain. The filesystem reference alone does not provide that guarantee.

## Persistence failure is not permission

Receipt file synchronization and receipt-directory synchronization must
complete before a save succeeds. A failure prevents the gated callback.
An uncertain consumption file remains reserved; do not delete it to retry.
This sacrifices availability to preserve at-most-once invocation.

A callback failure also consumes its authorization. NARF provides
at-most-once invocation, not guaranteed delivery or exactly-once completion.
Remote acknowledgements and target-side recovery belong to the host.

## Verification scope

The repository's host-serialization tests demonstrate the cooperating
in-process pattern. Additional subprocess experiments have exercised a
shared filesystem lock. These results do not certify an arbitrary host,
an OS sandbox, physical power-loss recovery, or production readiness.

The original unguarded revocation and host-history intervention results
remain limitations of those configurations. A protected-host demonstration
does not relabel them as PASS.
