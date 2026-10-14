# Composed protected-operation path

Status: opt-in trusted-host hardening built from existing MGnarf primitives.

## Goal

The repository already contains three separate protections:

1. identity/separation-of-duties checks on an exact frozen NARF contract;
2. a monotonic authority revision that keeps identity change-and-restore visible;
3. a stable operation ID plus an external single-use consumption authority.

A deployment should not have to choose between those protections. The composed
path makes them one convenience flow while keeping the core NARF gate unchanged.

## Reference flow

```text
builder
  -> verifier evidence
  -> independent verifier evidence
  -> authority evidence
  -> identity + separation policy
  -> monotonic authority revision
  -> NARF PASS
  -> stable operation binding
  -> external single-use consumption authority
  -> guarded effect entry
  -> real external effect
```

`OperationBoundGate(receipt_store, authority_probe=...)` is the composition
point. When `authority_probe` is supplied, `freeze_contract()` also requires an
`identity_policy` and uses `AuthorityRevisionGate` underneath.

The resulting contract therefore has both:

- an authenticated authority-revision binding; and
- an authenticated stable-operation binding.

The operation binding remains separate from the NARF contract so an external
consumption authority can use one host-owned operation UUID across retries or
newly frozen contracts representing the same real-world operation.

## Mandatory executor route in composed mode

A composed `OperationBoundSession` does not allow callers to invoke the effect
through its public `execute_effect()` method. Effect entry must go through:

```python
OperationBoundEffectExecutor(authority).execute(session)
```

This is an API-level fail-closed guard against accidentally skipping the stable
operation reservation. The legacy `OperationBoundGate(store)` path retains its
historical direct `session.execute_effect()` behavior for backward compatibility.

The private package route used by the executor is not claimed as a sandbox
against a malicious trusted host running arbitrary Python in the same process.
The trusted host remains inside the NARF trust boundary. The guard prevents a
normal integration from silently selecting the hardened gate and then bypassing
its required external authority step.

## Fail-closed ordering

`OperationBoundEffectExecutor` performs:

```text
session.finalize()
  -> reserve(stable operation_id)
  -> guarded session effect entry
```

In authority-revision mode, guarded effect entry still performs the
revision-guarded NARF pre-effect checks and the additional authority check at
protected callback entry.

This has an intentional failure mode:

```text
PASS
-> stable operation reservation succeeds
-> authority revision changes
-> guarded callback entry rejects the effect
-> operation reservation stays consumed
```

The system sacrifices availability rather than releasing a token after the
security state became uncertain.

## Cross-contract replay

A NARF contract UUID is intentionally fresh. That alone is not a stable identity
for a real external operation. `operation_id` is supplied by the trusted host
and must stay the same across retries/new contracts for the same semantic side
effect.

Therefore:

```text
contract A / operation X -> consumed
contract B / operation X -> external authority rejects replay
```

Even if contract B independently reaches PASS, it cannot repeat operation X
through the composed executor.

## Compatibility

Historical use remains unchanged:

```python
OperationBoundGate(store)
```

continues to create the original version-1 operation-bound NARF path.

The stronger mode is explicit:

```python
OperationBoundGate(store, authority_probe=probe)
```

and requires `identity_policy` at contract freeze.

The convenience wrapper deliberately does not add a snapshot-only identity
mode. Callers that want identity enforcement without a monotonic authority
revision can still use `NARFGate` directly. This keeps the composed convenience
path from looking stronger than it is.

## Remaining TOCTOU boundary

This composition is stronger, but it is not a proof that authority state cannot
change after the final callback-entry check and before/during an external system
commits the side effect.

A deployment requiring that guarantee needs an effect authority that serializes
identity-authority transitions with effect execution, or a fencing token that
the external resource itself validates.

Examples include:

- one PostgreSQL transaction/advisory-lock domain used by both authority changes
  and effect admission;
- a remote fencing service that returns strictly increasing fence tokens and an
  external resource that rejects stale tokens;
- another lock/lease/transaction mechanism whose security boundary includes the
  actual side effect.

A second snapshot check alone does not close that boundary.

## Acceptance cases

The composed reference path must demonstrate at minimum:

1. exact identity/revision + exact operation -> PASS/effect;
2. revision drift before effect -> no operation reservation, no effect;
3. actor drift even without revision increment -> no reservation, no effect;
4. revision drift during reservation -> reservation stays consumed, callback blocked;
5. a new contract with the same stable operation ID cannot replay the effect;
6. the convenience wrapper cannot silently enable identity policy without the
   monotonic authority probe;
7. composed sessions cannot directly bypass `OperationBoundEffectExecutor`;
8. legacy operation-bound direct effect behavior remains compatible;
9. all legacy operation-bound tests continue to pass unchanged.
