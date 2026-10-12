# PostgreSQL fenced target reference boundary

Status: Layer C reference integration for the fenced-effect design.

## What this adds

The generic fenced host path can bind and transport a fence, but that alone does
not prove that an external target rejects a stale worker at commit time. This
reference integration uses one PostgreSQL serialization domain for:

- authority revision state;
- per-scope monotonic fence sequence;
- fence issuance evidence;
- and the external effect commit.

The runtime pieces are:

- `PostgresFencingAuthority` — obtains a transaction-scoped advisory lock for
  the `fence_scope_id`, then issues a new fence only if the expected authority
  revision is still current;
- `PostgresFenceControlPlane` — obtains the same advisory lock before advancing
  the authority revision;
- `PostgresFencedTarget` — obtains that same advisory lock, validates the current
  authority revision and latest fence sequence, validates the exact issuance row,
  and inserts the effect in that same transaction.

## Why advisory locking

The target is intentionally a read-mostly runtime role. PostgreSQL locking clauses
such as `SELECT ... FOR SHARE` require privileges that would force the target role
to receive UPDATE authority on the protected scope table. The reference model
instead uses `pg_advisory_xact_lock` with a stable signed 64-bit key derived from
`fence_scope_id`.

Issuer, control-plane, and target all take that same transaction-scoped advisory
lock before touching the authoritative scope state. The target therefore needs
only SELECT on scope/issuance state and INSERT on the measured effect table.

## Serialization rule

For one `fence_scope_id`, PostgreSQL determines one order through the common
transaction-scoped advisory lock:

```text
target gets scope advisory lock first
  -> target validates and may commit old generation
  -> transaction ends and releases lock
  -> later authority transition occurs after that commit
```

or:

```text
authority transition gets scope advisory lock first
  -> revision advances and transaction commits
  -> target acquires lock afterwards
  -> target sees newer revision
  -> old fence is rejected
```

Fence issuance uses the same lock, so transition and issuance cannot pass each
other invisibly inside the measured database boundary.

This is stronger than a second client-side snapshot because the validation is
inside the transaction that commits the measured external effect.

## No newer effect is required

An authority transition from revision 11 to revision 12 invalidates a revision-11
fence even when no revision-12 effect or fence is ever issued. The target compares
the token against the authoritative scope revision at commit.

## Fence ordering

A newer issued fence in the same scope increments `fence_sequence`. The reference
target accepts only the currently latest sequence. An older token is rejected even
if its authority revision still matches.

This is deliberately scope-based. `operation_id` remains the stable semantic
operation identity and is not reused as the fence namespace.

## Split runtime roles

The CI reference uses separate PostgreSQL roles:

- issuer: SELECT scope state, UPDATE only `fence_sequence`, INSERT issuance,
  and use the stable-operation consumption ledger;
- target: SELECT scope/issuance and INSERT the external effect row;
- control plane: SELECT scope state and UPDATE only `authority_revision`.

The common advisory lock does not require granting the target UPDATE permission on
the scope row. Schema creation and destructive administration remain outside those
runtime roles.

## Measured cases

The dedicated CI harness requires:

1. current valid fence commits exactly one effect;
2. authority transition after MGnarf's local final check but before target commit
   rejects the old fence with zero effect rows and without requiring a newer
   effect;
3. a newer fence in the same scope makes the older fence stale;
4. an in-progress authority transition holds the shared scope advisory lock and
   serializes fence acquisition;
5. an in-progress authority transition holds that same advisory lock and
   serializes target commit; the old token is rejected after transition commit;
6. privileged rollback of the authoritative PostgreSQL state is reproduced as a
   `LIMITATION_CONFIRMED`, not relabeled as protected.

## Claim boundary

Allowed claim for the measured configuration:

> For the tested PostgreSQL advisory-lock transaction/role configuration,
> authority transitions and fence ordering are validated at the external effect
> commit boundary; a transition that commits before the effect commit invalidates
> the older fence.

Not claimed:

- universal TOCTOU elimination for arbitrary external services;
- protection against a privileged PostgreSQL administrator who can roll back or
  rewrite the authoritative fencing state;
- availability after ambiguous failures;
- protection when an integration bypasses the fenced target and writes directly
  with more powerful credentials;
- safety if different participants derive different advisory-lock keys for the
  same logical scope.

The database, scope-to-lock-key derivation, schema privileges, transaction
behavior, and target adapter are all part of the measured trust boundary.
