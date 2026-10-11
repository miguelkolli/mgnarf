# Operation idempotency boundary

MgNarf currently provides single-use effect authorization at the individual
contract/authorization boundary. The consumption token used by the hardened
authority path is the random `contract_id` generated when a contract is frozen.

That means two independently frozen contracts can contain the same task,
requirement set, effect identity and frozen state while still receiving two
different consumption tokens.

`tools/test_operation_idempotency.py` characterizes this boundary without
changing production code. It freezes the same authorization input twice, opens
and verifies both contracts, then executes them through one shared external
consumption authority. The expected result is `LIMITATION_CONFIRMED` when both
contract-scoped authorizations can each invoke the same callback once.

This does **not** invalidate MgNarf's current per-contract at-most-once claim.
It shows that MgNarf does not yet provide operation-level idempotency across
fresh contracts.

A future hardening design should use a trusted-host-owned stable operation or
idempotency identity that is bound into the frozen authorization and reserved by
external consumption authorities. The candidate must not be able to choose a
new identity simply to obtain another authorization. Defining when two requests
represent the same real operation remains a host/domain responsibility.

Do not derive a supposedly stable operation identity only from ambiguous mutable
business fields unless the host has explicitly defined their canonical semantic
scope. A deterministic hash is only as meaningful as the host-owned identity
contract it represents.
