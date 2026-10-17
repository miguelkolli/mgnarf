# TEST REPORT — v1.61 signed-witness deadline hardening

Date: 2026-10-12

## Trigger

A maintainer-supplied Claude adversarial retest of v1.60 reported that six previously identified findings were fixed and one availability finding remained partial: a signed-witness peer dripping HTTP response headers byte-by-byte could keep `reserve()` alive for roughly 35 seconds despite a configured one-second timeout. The same report described 98 repository tests as passing, plus a separate 16-test series and agent PoCs. Those external/private runs are recorded as provenance, not re-labeled as repository-owned evidence.

The retest also reported three smaller hardening observations (store-directory permission validation, acceptance of a 32-byte all-zero HMAC key, and a host-callable same-requirement concurrent `execute()` boundary). They were not conflated with the reproduced slow-header defect and are not silently claimed fixed by v1.61.

## Recon and reproduction

Inspection of v1.60 showed one monotonic deadline created before `urllib.request.urlopen()`, but the explicit deadline-aware loop began only after an HTTP response object had already been returned. The existing regression fixture dripped the response body; it did not drip response headers.

A minimal slow-header reproduction against the old transport exceeded a one-second configured timeout by multiple seconds while the peer continued to make byte-level progress. A deadline-aware raw-reader prototype failed closed at approximately one second. This established a concrete reproducible gap before production code was changed.

## Implementation

The v1.61 patch:

1. moves the signed-witness client onto `http.client`;
2. preserves one monotonic deadline for the request/response socket path;
3. reapplies the remaining deadline before each raw response read used by HTTP status/header/body parsing;
4. keeps the existing fail-closed `NARFError("effect: signed witness unavailable")` behavior;
5. adds a byte-at-a-time slow-header regression alongside the existing slow-body regression;
6. preserves HTTP/1.0 response stream lifetime semantics required by the reference witness server; and
7. makes the ambiguous durable-reservation acknowledgement-loss injection independent of the chosen HTTP transport.

## First CI pass and correction

The first candidate commit exposed compatibility failures in the signed-witness and ambiguous-authority workflows. Investigation found two causes:

- the first custom raw reader closed the underlying socket too early for HTTP/1.0 close-delimited connection semantics; and
- the ambiguous-ack harness monkeypatched `urllib.request.urlopen`, coupling the fault injection to the old transport implementation.

Neither was accepted as a release PASS. The socket reader was changed to preserve the socket's own file-object lifetime, and the fault injection was moved to the authority-response boundary after the witness has processed the request. The safety assertion stayed the same: once reservation durability may have succeeded, the uncertain reservation is never rolled back and retry remains blocked.

## Candidate evidence

PR #38 head `a5d851ab96909460c992dd0edc96eda3da41f3a1` completed all 11 repository workflows successfully.

The aggregate reference suite on the PR merge ref reported:

- tests: **99**
- failures: **0**
- errors: **0**
- skips: **0**
- compile: **PASS**

The 99 tests explicitly included:

- `test_signed_witness_timeout_is_wall_clock_bounded_for_drip_body`
- `test_signed_witness_timeout_is_wall_clock_bounded_for_drip_headers`
- `test_signed_witness_response_loss_after_reserve_fails_closed_on_retry`
- the non-boolean revocation regression
- FIFO non-blocking candidate handling
- session/contract binding
- canonical JSON coercion regressions
- post-PASS inhibitor and revocation checks
- durable store and atomic publication fault paths

The repository workflow set also passed signed-witness, ambiguous-authority, PostgreSQL, multi-domain fencing, operation-bound authority, operation-idempotency, rollback hardening, rollback limitation, canonical fuzz and strict reference-host boundaries.

## Merged-main evidence

PR #38 was merged to `main` as:

`6226b837e163ca47faaa2f2d8ab338735451268a`

The exact merged SHA triggered 11 push workflows. All completed without failure or cancellation, including the aggregate `NARF reference checks` path.

## Result

**PATCH EVIDENCE: PASS** for the reproduced v1.60 slow-header availability finding and its measured regression boundary.

This report does **not** claim independent certification, arbitrary-network total-time guarantees, or exactly-once external completion. The v1.61 stable tag remains subject to the separate release-freeze gate and immutable-release publication procedure.
