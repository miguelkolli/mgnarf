# NARF architecture

## Purpose

NARF is a standalone fail-closed acceptance gate with a Python reference implementation and adversarial verification tests.

## Independence boundary

NARF has no required parent framework, private repository, external governance runtime, workspace variable, database, service, or project harness.

The reference implementation lives under `src/narf/` and uses only the Python standard library. External systems may integrate NARF through adapters, callbacks, and state digests, but NARF does not import or depend on the integrating system.

## Components

`ReceiptStore` owns HMAC-authenticated append-only reference receipts. The integrating trusted host owns the receipt key and storage boundary.

`NARFGate` freezes task, state, requirement, verifier, and effect bindings and opens candidate-bound sessions.

`NARFSession` owns verifier execution, evidence evaluation, final decision, revalidation, and single-use effect consumption.

The optional [identity boundary](IDENTITY-BOUNDARY.md) extends `NARFGate` and
`VerifierBinding` with a frozen host-owned actor/separation policy and a current
identity probe. Principal, trust domain and verifier profile are independent
facts. Authority approval reuses required verifier evidence. Identity-enabled
contracts and receipts use version 2; version-1 behavior remains the default.

## Invariants

- Missing, stale, invalid, incomplete, revoked, mismatched, or unauthenticated evidence never manufactures PASS.
- PASS evidence is bound to the exact task, candidate, frozen requirements, and policy.
- Coverage is dynamic `N/N`; there is no fixed verifier count.
- Candidate or worker self-report is not accepted as host verifier evidence.
- A previous PASS cannot authorize an effect after relevant state changes.
- Immediate pre-effect revalidation is mandatory.
- Effect consumption is single-use and replay-resistant in the reference model.
- Integration dependencies are one-way: consumers may depend on NARF; NARF does not depend on consumers.

## Source and test roots

- source root: `src/`
- package: `src/narf/`
- test root: `tests/`

## Verification

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
```

These are standalone repository commands. No external harness is required.
