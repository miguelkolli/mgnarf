# PostgreSQL fenced target reference boundary

Status: Layer C reference integration for the fenced-effect design.

## What this adds

The generic fenced host path can bind and transport a fence, but that alone does
not prove that an external target rejects a stale worker at commit time. This
reference integration moves the security-critical serialization into PostgreSQL
`SECURITY DEFINER` functions installed from `sql/postgres_fencing_v1.sql`.

The runtime pieces are:

- `PostgresFencingAuthority` calls `public.narf_acquire_fence(...)`;
- `PostgresFenceControlPlane` calls the DB-owned revision read/advance functions;
- `PostgresFencedTarget` calls `public.narf_commit_fenced_effect(...)`.

The database functions own the transaction-scoped advisory lock, authoritative
revision/sequence validation, issuance persistence, and final effect insert.

## Function-only runtime roles

The hardened reference does not require runtime roles to write fencing/effect
state directly.

- issuer: EXECUTE `narf_acquire_fence` plus SELECT/INSERT on the separate stable
  operation consumption ledger;
- control plane: EXECUTE `narf_current_fence_revision` and
  `narf_advance_fence_revision`;
- target: EXECUTE `narf_commit_fenced_effect`;
- schema/function owner: outside the runtime roles.

Direct DML on `narf_fence_scopes`, `narf_fence_issuance`, and
`narf_fenced_effects` is revoked from those runtime roles. The CI harness probes
that boundary rather than trusting the GRANT statements on paper.

## Serialization rule

All security-critical DB functions derive the same PostgreSQL advisory-lock key
from `fence_scope_id` with `hashtextextended(scope, 0)` and acquire a
transaction-scoped advisory lock before changing or committing scope state.

For one scope PostgreSQL therefore determines one order:

```text
target commit obtains lock first
  -> validates current generation/fence
  -> effect commits
  -> a later authority transition occurs after that effect
```

or:

```text
authority transition obtains lock first
  -> revision advances and commits
  -> target obtains lock afterwards
  -> old fence sees newer revision and is rejected
```

Fence issuance uses the same lock, so transition and issuance cannot pass each
other invisibly inside the measured database boundary.

## No newer effect is required

An authority transition from revision 11 to revision 12 invalidates a revision-11
fence even when no revision-12 effect or fence is ever issued. The commit
function compares the token against authoritative scope state inside the same
transaction that would insert the external effect.

## Fence ordering

A newer issued fence in the same scope increments `fence_sequence`. The commit
function accepts only the current sequence and exact issuance binding. An older
token is rejected even if its authority revision still matches.

`operation_id` remains the stable semantic operation identity and is not reused
as the fencing namespace.

## Measured cases

The dedicated CI harness requires:

1. current valid fence commits exactly one effect;
2. authority transition after MGnarf's local final check but before target commit
   rejects the old fence with zero effect rows and without requiring a newer
   effect;
3. a newer fence in the same scope makes the older fence stale;
4. an in-progress authority transition serializes fence acquisition;
5. an in-progress authority transition serializes target commit and the old
   token is rejected after transition commit;
6. privileged rollback of authoritative PostgreSQL state is reproduced as
   `LIMITATION_CONFIRMED`.

The harness also actively probes direct-DML denial and the exact function EXECUTE
matrix for issuer/control/target roles.

## Claim boundary

Allowed claim for the measured configuration:

> For the tested PostgreSQL function-enforced transaction/role configuration,
> authority transitions and fence ordering are validated at the external effect
> commit boundary; a transition that commits before the effect commit invalidates
> the older fence.

Not claimed:

- universal TOCTOU elimination for arbitrary external services;
- protection against the privileged PostgreSQL function/schema owner or an
  administrator who can rewrite authoritative fencing state;
- availability after ambiguous failures or deliberate advisory-lock denial of
  service;
- safety if a deployment changes the supplied SQL functions, role grants, or
  transaction semantics without re-verification.

The database, installed SQL functions, function owner, role grants, and target
adapter are all part of the measured trust boundary.
