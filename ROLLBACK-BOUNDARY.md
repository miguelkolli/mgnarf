# Rollback restoration boundary

## Status

This document records a **known limitation witness**, not a NARF security PASS.

The filesystem reference store authenticates receipt contents and uses a
deterministic exclusive-create consumption receipt to provide single-use effect
authorization while that history is preserved. It does not provide a monotonic
history outside its own rollback domain.

`tools/test_rollback_boundary.py` intentionally exercises the privileged
host/storage-owner case described in `HOST-CONTRACT.md`.

## Measured cases

### 1. Restore a pre-consumption snapshot

The harness:

1. freezes a contract and obtains authenticated PASS evidence,
2. snapshots the receipt directory before effect consumption,
3. executes the effect once,
4. restores the older authenticated snapshot,
5. opens a fresh session for the same frozen contract and state, and
6. attempts the same effect again.

The expected witness is `LIMITATION_CONFIRMED`: the restored snapshot no longer
contains the deterministic consumption receipt, so the same authorization can
be consumed again and the external effect is invoked a second time.

The harness records that the restored contract is still authenticated and that
the first and resurrected consumption receipts use the same deterministic
effect receipt ID.

### 2. Delete only the consumption receipt

A privileged owner deletes the deterministic `narf.effect` receipt after the
first effect and synchronizes the receipt directory. A fresh session then
reuses the same contract and state.

The expected witness is again `LIMITATION_CONFIRMED`: removal frees the
exclusive-create filename and the callback can be invoked a second time.

## How to interpret a green CI job

The CI job is named **Rollback restoration witness (expects
LIMITATION_CONFIRMED)**.

A green job means the repository reproduced the documented limitation exactly.
It does **not** mean rollback resistance passed. The harness summary itself must
say `LIMITATION_CONFIRMED`; it never labels this condition `PASS`.

If a future implementation adds rollback-resistant authority, this witness
should stop reproducing the limitation and the CI expectation must be replaced
by a hardening test.

## Required hardening when rollback is in the threat model

The host needs an authority source outside the receipt-store rollback domain,
for example a monotonic checkpoint, ledger, fencing epoch, or target-side
conditional transaction that cannot be rewound together with the filesystem
snapshot.

That mechanism must be independently protected and checked before the gated
effect. Merely adding another file beside the receipts does not solve the
problem if the same snapshot/restore operation can rewind both.

## Scope limits

This witness models a privileged trusted-host or storage operator that can
restore/delete receipt history. It does not weaken the distinct-UID worker
boundary already measured elsewhere: a normal untrusted worker still must not
have this authority.

The witness does not claim production deployment security, physical power-loss
durability, rollback-resistant history, distributed fencing, or exactly-once
remote completion.
