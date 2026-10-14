# Multi-domain fencing boundary

## Status

This document records the next rollback-hardening boundary after `ROLLBACK-HARDENING.md`.

A single external consumption authority blocks receipt-domain rollback only while that authority itself cannot be rewound or deleted. This layer adds an **all-of multi-domain consumption authority** so that replay remains blocked while at least one configured authority domain preserves the consumed token.

This is intentionally **not** a majority quorum.

## Why all-of instead of majority

For first use, every configured authority must durably reserve the same contract token before NARF may enter the effect path.

For replay, any one preserved authority can veto the operation by reporting that token already consumed.

That asymmetry is deliberate:

- first execution requires all authorities,
- replay is blocked by any preserved authority.

A conventional majority quorum can be unsafe for this specific rollback problem. If two of three authorities are rewound, those two could form a fresh majority even though the third still remembers the prior consumption. All-of avoids that acceptance path at the cost of availability.

## Fail-closed partial reservation

`AllOfConsumptionAuthority` reserves authorities sequentially.

If one authority reserves successfully and a later authority rejects or becomes unavailable, earlier reservations are **not** released. The operation fails, but the partial reservations remain consumed.

This can reduce availability. It is intentional: uncertain or partial consumption must not be converted back into reusable authorization.

## Measured fault-injection cases

`tools/test_multidomain_fencing.py` uses three logical authority domains and the normal NARF receipt domain.

### 1. Roll back one of three authority domains

The receipt domain and authority A are restored to their pre-consumption snapshots. Authorities B and C retain the consumed token.

Expected result: **PASS for the hardening case**. Replay is blocked before the external effect because at least one preserved authority rejects the token.

### 2. Roll back two of three authority domains

The receipt domain plus authorities A and B are restored. Authority C retains the consumed token.

Expected result: **PASS for the hardening case**. A and B may be reserved again during the retry, but C rejects the already-consumed token before NARF enters the external effect.

### 3. Delete one authority token

The local NARF effect receipt and one external authority token are deleted. The other two authority domains retain the token.

Expected result: **PASS for the hardening case**. One preserved domain is sufficient to veto replay.

### 4. Roll back all three authority domains

The receipt domain and all three external authority domains are restored to their pre-consumption state.

Expected result: **LIMITATION_CONFIRMED**. With every history domain rewound together, the same authorization can be resurrected and the external effect can run again.

The CI workflow therefore requires exactly:

- 3 × `PASS`,
- 1 × `LIMITATION_CONFIRMED`,
- 0 × `FAIL`,
- overall `BOUNDARY_CONFIRMED`.

A green workflow does not mean universal rollback resistance. It means the measured boundary was reproduced exactly.

## Deployment obligation

The three directories used in CI are logical fault-injection domains, not proof of real operational independence.

A production deployment must make the authorities genuinely independent in the threat model. Examples include separately administered databases/services, independent append-only ledgers, separate fencing authorities, or hardware-backed monotonic state.

If one administrator, snapshot system, root credential, storage controller or disaster-recovery operation can rewind every authority together, the all-of model does not create monotonicity by itself.

## Remaining limits

This layer does not establish:

- safety when every configured authority domain can be rolled back or deleted together,
- Byzantine-authority tolerance,
- cross-machine distributed linearizability,
- physical power-loss guarantees beyond the underlying authorities,
- exactly-once remote completion, or
- production deployment certification.

The narrower claim is: **when at least one all-of consumption-authority domain preserves the consumed token, rollback or deletion of the other measured domains does not re-enable the same external effect authorization.**
