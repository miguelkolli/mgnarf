# Operation idempotency boundary

MgNarf has two explicitly different consumption scopes.

## Legacy contract-scoped path

The compatibility path uses `NARFGate` with `RollbackProtectedEffectExecutor`.
Its external consumption token is the random `contract_id` generated when a
contract is frozen.

Two independently frozen contracts can therefore contain the same task,
requirement set, effect identity and frozen state while still receiving two
different consumption tokens. `tools/test_operation_idempotency.py` preserves
this fact as an explicit `LIMITATION_CONFIRMED` witness.

This does **not** invalidate the per-contract at-most-once claim. It means the
legacy path does not infer operation-level idempotency across fresh contracts.

## Operation-bound hardened path

`OperationBoundGate` accepts a trusted-host-owned stable `operation_id` UUID.
After the underlying NARF contract is frozen, the adapter persists a separate
HMAC-authenticated `narf.operation-binding` receipt that binds that contract ID
to the operation ID.

`OperationBoundGate.open_session()` does not accept an operation ID from the
caller. It recovers the value only from the authenticated operation-binding
receipt. A missing, malformed, or tampered binding fails closed before verifier
evidence can execute.

`OperationBoundEffectExecutor` likewise accepts no caller-provided consumption
token. After authenticated PASS it reserves `session.operation_id` in the
configured `ConsumptionAuthority`, then enters the NARF effect. Fresh contracts
that share the same stable operation ID therefore contend on the same external
single-use token.

The measured boundary in `tools/test_operation_bound_authority.py` is:

1. two fresh contracts + one stable operation ID -> first effect executes and
   the second is blocked before callback (`PASS`);
2. two distinct operation IDs -> both independent operations execute (`PASS`);
3. tampered operation binding -> fail closed (`PASS`);
4. missing operation binding -> fail closed (`PASS`);
5. trusted host gives the same real-world operation two fresh operation IDs ->
   both can execute (`LIMITATION_CONFIRMED`).

The exact expected summary is therefore `4 PASS + 1 LIMITATION_CONFIRMED`.

## Trust boundary

Operation identity is semantic authority. MgNarf cannot determine from arbitrary
business fields whether two requests are really the same operation. The trusted
host must assign the same operation UUID to retries, re-verification, or newly
frozen contracts that represent the same external action.

The operation ID must not be selected by untrusted candidate/worker code. A host
that simply generates a fresh operation UUID for every new contract retains the
legacy semantic limitation even when using the operation-bound adapter.

Do not derive a supposedly stable operation identity only from ambiguous mutable
business fields unless the host explicitly defines their canonical semantic
scope. A deterministic hash is only as meaningful as the host-owned identity
contract it represents.

## Persistence and rollback

The operation binding uses the same authenticated receipt store as the NARF
contract. Authentication prevents silent binding modification by a worker that
does not own the receipt key. Receipt rollback by a privileged actor remains
subject to the documented receipt-store limitations.

Cross-contract replay resistance comes from reserving the stable operation UUID
in the configured external consumption authorities. File, all-of, PostgreSQL,
and signed-witness authorities can therefore use the same operation token and
retain their existing rollback boundaries.

The operation-bound adapter does not turn process separation into independent
administration, does not infer business semantics, and does not provide exactly-
once remote completion.
