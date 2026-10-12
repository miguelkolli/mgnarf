# Monotonic authority revision boundary

Status: opt-in trusted-host hardening for identity-enabled NARF contracts.

## Problem

Identity-enabled NARF compares the current trusted-host actor map with the actor
map frozen into the authenticated contract. That detects identity drift that is
present when NARF probes the host.

Snapshot comparison alone cannot detect this sequence:

```text
probe sees revision 41 / expected actors
identity authority changes
identity authority is restored to the same actor values
next probe sees the same actors again
```

If no trusted state records that the authority changed, the two actor snapshots
are indistinguishable.

## Stronger host contract

`AuthorityRevisionGate` adds a separate trusted-host binding:

```text
contract_id
+ monotonic authority_revision
+ actors_sha256
+ identity_policy_sha256
-> HMAC-authenticated authority-revision binding receipt
```

The host supplies an `AuthoritySnapshot(revision, actors)` through a trusted
probe. The revision source must obey all of these rules:

1. increment whenever an identity-authority fact relevant to the actor map can change;
2. never reuse one revision for a different authority state;
3. never move backwards;
4. remain outside candidate, worker, builder, and verifier control;
5. resist rollback strongly enough for the deployment's threat model.

The actor map in the snapshot must match the identity policy at contract freeze.
The binding receipt is stored with the same authenticated `ReceiptStore` used by
NARF. Missing, invalid, mismatched, or stale binding evidence fails closed.

## Runtime behavior

The wrapper rechecks the authority binding:

- before opening a session;
- every time the core identity probe is evaluated;
- during normal pre-effect NARF revalidation;
- once more at the protected callback entry.

If the revision differs from the frozen value, the old contract is stale. A new
session is not enough: the trusted host must freeze a new contract under the new
revision.

If actor values drift without the revision changing, the actor digest comparison
still blocks the session. This does not make a broken revision source safe; it
only preserves the existing actor-snapshot defense.

## What this closes

With a rollback-resistant monotonic revision source, a change followed by actor
restoration between NARF actor probes remains visible because the revision does
not return to its previous value.

Conceptually:

```text
actors A, revision 41
        |
        | authority changes and restores actors A
        v
actors A, revision 42
```

The second actor snapshot looks identical, but the contract is still blocked
because `42 != 41`.

## Remaining boundary

This is stronger detection, not full serialization of authority and side effect.
There is always a final check-to-use interval unless the identity authority and
the external effect participate in the same lock, transaction, fencing token,
or equivalent serialized authority mechanism.

`AuthorityRevisionGate` adds an additional probe at callback entry to narrow that
interval. If this late check detects a changed revision after the core effect
consumption receipt has already been persisted, the real callback is blocked and
the authorization remains consumed. That is an intentional fail-closed choice:
availability is sacrificed rather than retrying under uncertain authority state.

Deployments requiring a proof that no authority transition can occur between the
last check and the side effect must combine NARF with a serialized/fenced effect
authority. A PostgreSQL transaction, remote witness, lease/fencing service, or
another deployment-specific mechanism may provide that boundary.

## Compatibility

The core identity contract remains evidence version 2. Existing `NARFGate`
callers are unchanged. The stronger revision binding is opt-in through:

```python
from narf import AuthorityRevisionGate, AuthoritySnapshot
```

The revision binding is a separate authenticated host receipt, following the
same architectural pattern as other stronger host-side NARF bindings.
