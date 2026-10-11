# NARF — ARCHITECTURE

## PURPOSE

NARF is a standalone repository for the NARF acceptance-gate specification,
reference implementation, and verification tests. It is separate from the
private MGSystem runtime and does not become MGSystem governance authority.

## SYSTEM BOUNDARIES

The portable reference implementation lives under `src/narf/` and uses only the
Python standard library. It accepts already-established host bindings and state
digests; it does not import MGSystem Task Freeze, lifecycle, analytics, deployment
or project-specific runtime modules.

`ReceiptStore` owns HMAC-authenticated append-only reference receipts. The host
key and receipt directory are trust-boundary inputs and must remain outside
candidate/worker control.

`NARFGate` freezes task/state/requirement/effect bindings and opens sessions.
`NARFSession` owns verifier execution, evidence evaluation, final decision,
revalidation and single-use effect consumption.

The repository must not contain MGSystem trusted-host receipt keys, production
credentials, private project data, or deployment-owned secret state.

Root MGSystem `LAWS.md` remains ecosystem authority. This repository owns only
NARF-specific implementation, tests and documentation.

## INVARIANTS

- NARF fails closed: missing, stale, invalid, incomplete, revoked, mismatched or
  unauthenticated evidence never manufactures PASS.
- PASS evidence remains bound to the exact task/candidate and frozen requirements
  and policy.
- Coverage is dynamic `N/N`; there is no fixed verifier count.
- Implementation/worker self-report is not accepted as host verifier evidence.
- A previous PASS cannot authorize an effect after relevant state changes.
- Immediate pre-effect revalidation is mandatory.
- Effect consumption is single-use and replay-resistant in the reference model.
- Public/reusable NARF code has no dependency on MGSystem private credentials or
  project-specific state.
- No public-release, deployment, production-readiness or external-E2E PASS claim
  is valid without separate current evidence.

## SOURCE AND TEST ROOTS

- source root: `src/`
- package: `src/narf/`
- test root: `tests/`

## VERIFICATION

Standalone reference verification commands:

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
```

Shared MGSystem verification remains a separate external gate and must be run
from an applicable MGSystem runtime/worktree. Standalone unit success does not
substitute for that gate.

## PROVENANCE

The behavioral model was extracted from MGSystem NARF v3 source at
`817e694fedbae8dc749fbbfcf271cf1fa93f1881`. The standalone implementation is an
intentional dependency-boundary extraction, not a byte-for-byte runtime copy.
