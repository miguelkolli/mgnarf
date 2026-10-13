# NARF architecture

## Purpose

NARF is a standalone fail-closed acceptance gate with a Python reference implementation and adversarial verification tests.

## Independence boundary

NARF has no required parent framework, private repository, external governance runtime, workspace variable, database, service, or project harness.

The reference implementation lives under `src/narf/`. The core and stage-order reference gate use only the Python standard library. Optional authority adapters add dependencies only for their own measured boundary. External systems may integrate NARF through adapters, callbacks and state digests, but NARF does not import or depend on the integrating system.

## Components

`ReceiptStore` owns HMAC-authenticated append-only reference receipts. The integrating trusted host owns the receipt key and storage boundary.

The public `NARFGate` is exported from `src/narf/stage_order.py`. It preserves legacy unordered behavior when `stage_order` is omitted and adds optional evidence-v3 authenticated ordering when an exact requirement order is configured. The legacy core implementation remains underneath this compatibility boundary and must reject ordered evidence it does not understand.

`NARFSession` owns verifier execution, evidence evaluation, final decision, revalidation and single-use effect consumption. For ordered sessions it additionally enforces atomic stage admission, authenticated predecessor-chain validation and final chain-head binding.

The optional [identity boundary](IDENTITY-BOUNDARY.md) extends `NARFGate` and `VerifierBinding` with a frozen host-owned actor/separation policy and a current identity probe. Principal, trust domain and verifier profile are independent facts. Authority approval reuses required verifier evidence. Identity-enabled unordered contracts use evidence version 2; version-1 behavior remains the default when neither identity nor stage ordering is configured.

The optional [authenticated stage-order boundary](STAGE-ORDER-BOUNDARY.md) freezes one exact linear permutation of all required `requirement_id` values. Ordered contracts use evidence version 3. The first accepted stage binds to a deterministic session/contract chain seed; every later stage binds to the authenticated predecessor receipt ID and canonical digest; the final decision binds to the final authenticated chain head. Ordering is causal evidence binding, not timestamp or physical-clock ordering.

`AuthorityRevisionGate` adds a trusted-host monotonic authority generation. Its ordered binding covers the exact stage-order digest so an ordered v3 contract cannot silently downgrade to an unordered authority binding.

`OperationBoundGate` adds stable trusted-host semantic operation identity across fresh contracts. When authority revision is composed, it references the exact ordered contract rather than reconstructing a weaker one.

`FencedOperationGate` and `FencedOperationEffectExecutor` carry the exact ordered contract through stable-operation reservation, fence acquisition and guarded effect entry. Stage ordering is additive; it does not replace fence or external commit enforcement.

The PostgreSQL Layer C reference demonstrates one target-specific commit boundary where authority transition, fence issuance and effect commit are serialized in the same database scope-lock domain.

## Invariants

- Missing, stale, invalid, incomplete, revoked, mismatched or unauthenticated evidence never manufactures PASS.
- PASS evidence is bound to the exact task, candidate, frozen requirements and policy.
- Coverage is dynamic `N/N`; there is no fixed verifier count.
- Candidate or worker self-report is not accepted as host verifier evidence.
- A previous PASS cannot authorize an effect after relevant state changes.
- Immediate pre-effect revalidation is mandatory.
- Effect consumption is single-use and replay-resistant in the measured reference model.
- When identity policy is configured, its principal/domain/profile/separation conditions are independent PASS conditions.
- When stage ordering is configured, every frozen requirement participates exactly once in the frozen linear order.
- Future ordered stages are rejected before producer entry until their authenticated predecessor is the accepted chain head.
- Same-stage concurrency and same-thread re-entrancy cannot create two accepted stage admissions in one session.
- Ordered final decisions bind the authenticated final chain head.
- Stronger wrappers preserve the exact ordered contract or fail closed; silent downgrade is forbidden.
- Stage ordering does not claim physical wall-clock chronology, verifier epistemic independence or distributed consensus.
- Integration dependencies are one-way: consumers may depend on NARF; NARF does not depend on consumers.

## Source and test roots

- source root: `src/`
- package: `src/narf/`
- ordered public gate: `src/narf/stage_order.py`
- ordered fenced wrapper: `src/narf/stage_order_fenced.py`
- test root: `tests/`
- stage-order design boundary: `STAGE-ORDER-BOUNDARY.md`

## Verification

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests tools
```

These are standalone repository commands. No external harness is required. A release claim additionally depends on the exact release workflows and candidate SHA recorded by the applicable release gate.
