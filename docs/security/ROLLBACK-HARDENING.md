# Rollback hardening reference

## Status

This document describes a **hardened trusted-host configuration** for the rollback limitation recorded in `ROLLBACK-BOUNDARY.md`.

The original filesystem-only witness remains in the repository on purpose. It proves that authenticated receipts alone are not rollback resistant. The hardened path adds a second single-use consumption authority that must live outside the receipt-store rollback domain.

## Execution order

`RollbackProtectedEffectExecutor` performs the effect path in this order:

1. revalidate the authenticated NARF decision,
2. reserve the frozen contract ID in `FileConsumptionAuthority`,
3. persist and revalidate NARF's normal deterministic effect-consumption receipt,
4. enter the external effect callback.

The external authority reservation is intentionally earlier than `session.execute_effect()`.

If receipt persistence, candidate/state revalidation, process execution or the external target fails after the external reservation, the reservation is **not released**. This can sacrifice availability, but it does not reopen the authorization for replay.

## Measured hardening cases

`tools/test_rollback_hardening.py` measures the same two privileged receipt-history interventions as the limitation witness, while preserving the external authority domain:

### 1. Restore a pre-consumption receipt snapshot

The test obtains PASS, snapshots the receipt domain, executes the effect once, restores the old receipt snapshot, opens a fresh NARF session, obtains PASS again, and tries the same contract again.

Expected result: **PASS for the hardening test**. The external authority already contains the contract token, so replay is blocked before `session.execute_effect()` and the external effect count stays at one.

### 2. Delete the deterministic consumption receipt

The test executes the effect once, deletes only the local `narf.effect` receipt, opens a fresh session, and retries the same contract.

Expected result: **PASS for the hardening test**. The external authority still contains the contract token, so deletion of local receipt history does not resurrect the external effect.

## Why the old limitation witness remains green

`.github/workflows/rollback-witness.yml` intentionally exercises the **unprotected filesystem-only configuration** and must continue to report `LIMITATION_CONFIRMED`.

`.github/workflows/rollback-hardening.yml` exercises the **protected configuration** and must report `PASS` for both replay attempts being blocked.

These are not contradictory results. Together they bind the claim boundary:

- filesystem receipts only: rollback limitation confirmed,
- receipts plus independent consumption authority: tested receipt-domain rollback replay blocked.

## Deployment obligation

`FileConsumptionAuthority` is a reference primitive. A separate directory is a different rollback domain only if the operator, storage system or deployment architecture actually prevents it from being rewound or deleted together with the receipt store.

For production, the authority should be backed by an independently protected monotonic mechanism such as:

- a database or service with a unique single-use row outside the application snapshot domain,
- an append-only remote ledger,
- a fencing epoch maintained by separate authority,
- TPM/HSM-backed monotonic state where appropriate, or
- a target-side conditional/idempotency transaction with equivalent non-rewindable semantics.

Putting the authority file beside the receipts and snapshotting both together does **not** close the hole.

## Remaining limits

This hardening does not establish:

- resistance if the external authority itself can be rolled back or deleted,
- physical power-loss guarantees beyond the underlying storage semantics,
- distributed linearizability across arbitrary hosts,
- exactly-once remote completion, or
- production deployment certification.

The claim is narrower: **when the consumption authority remains outside the receipt rollback domain, restoring or deleting receipt history does not re-enable the same external effect authorization.**
