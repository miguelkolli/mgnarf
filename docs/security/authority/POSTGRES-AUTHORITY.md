# PostgreSQL authority boundary

## Status

This document records the next authority boundary after `MULTIDOMAIN-FENCING.md`.

The previous layer used multiple logical file-backed authority domains. That blocks replay while at least one domain preserves history, but logical directories do not by themselves prove operational separation.

This layer adds a **PostgreSQL-backed single-use consumption authority** running as a separate database service. The runtime application role is intentionally least-privilege and may only `INSERT` and `SELECT` ledger rows.

## Runtime model

`PostgresConsumptionAuthority` reserves the frozen contract UUID with one database statement:

- `INSERT ... ON CONFLICT DO NOTHING RETURNING token`

The ledger token is a PostgreSQL primary key. Concurrent attempts for the same token therefore have one database winner; later attempts observe the existing token and are rejected before NARF enters the external effect callback.

The adapter does **not** create, truncate, delete from or drop its ledger table. Schema/bootstrap and destructive administration are deliberately outside the runtime authority.

## Domain identity

For all-of composition, PostgreSQL authority identity is bound to:

- host,
- port,
- database.

Username, password and table name are deliberately ignored. Two credentials or two tables in the same database must not masquerade as independent rollback domains.

This identity is still best-effort. DNS aliases, proxies, replication topologies or shared administrative control can make apparently different endpoints part of one real failure domain. Deployment architecture remains responsible for actual independence.

## Measured cases

`.github/workflows/postgres-authority.yml` starts a separate PostgreSQL service container and provisions:

- an admin role used only for bootstrap and the explicit limitation witness,
- an application role with only `SELECT` and `INSERT` on `narf_consumption_ledger`.

`tools/test_postgres_authority.py` requires exactly five outcomes.

### 1. Runtime app role cannot truncate the ledger

The application role attempts `TRUNCATE` and must be rejected by PostgreSQL permissions.

Expected result: **PASS**.

### 2. Complete local rollback while PostgreSQL history survives

The NARF receipt domain and both local file-backed authority tokens are rewound/deleted after one successful effect. The PostgreSQL ledger row is preserved.

Expected result: **PASS**. The replay obtains a fresh local PASS decision but PostgreSQL rejects the already-consumed contract before the external effect runs again.

### 3. PostgreSQL authority unavailable

The effect path points one authority at an unavailable PostgreSQL endpoint after an earlier file authority has already reserved the token.

Expected result: **PASS** for fail-closed behavior. The external effect is not called and the earlier reservation is not released.

### 4. Four-process concurrent reservation

Four separate processes race to reserve the same fresh contract token in PostgreSQL.

Expected result: **PASS**. Exactly one process reserves the row, three are rejected as already consumed, and exactly one ledger row exists.

### 5. Privileged database-history reset

After one successful external effect, all local history is rewound and the privileged PostgreSQL administrator truncates the ledger table. The same contract is then replayed.

Expected result: **LIMITATION_CONFIRMED**. With the remote fencing history intentionally destroyed by its privileged administrator, the same authorization can be resurrected and the external effect can run again.

The CI workflow therefore requires exactly:

- 4 × `PASS`,
- 1 × `LIMITATION_CONFIRMED`,
- 0 × `FAIL`,
- overall `BOUNDARY_CONFIRMED`.

A green workflow means the measured service boundary and its remaining limitation were reproduced exactly. It does not mean universal rollback resistance.

## What this closes

Within the measured model, compromise or rollback of the application filesystem is no longer enough to resurrect an effect when the PostgreSQL ledger preserves its row.

The runtime app credential also cannot erase the PostgreSQL history because it lacks destructive table privileges.

## What remains open

This layer does not establish safety if the privileged database control plane can itself restore, truncate or replace the ledger together with every other authority history.

It also does not establish:

- independent administration merely because PostgreSQL runs in another process/container,
- cross-region or multi-primary linearizability,
- Byzantine database tolerance,
- physical power-loss semantics beyond PostgreSQL and its storage stack,
- rollback resistance against database backups restored by privileged operators,
- exactly-once completion of arbitrary remote side effects, or
- production deployment certification.

The narrower claim is: **when the PostgreSQL ledger history is preserved and the runtime credential remains least-privilege, complete rollback of the measured local NARF and file-authority history does not re-enable the same external effect authorization.**

## Next boundary

The next deeper boundary is the database control plane itself: independent administration, append-only or externally witnessed ledger history, fencing epochs, hardware-backed monotonic state, or another mechanism that a single privileged database restore cannot silently rewind.
