# Trusted host / untrusted worker process boundary

This document describes the next reference integration boundary beyond the single-process file host.

## What is being demonstrated

A distinct Unix worker process owns only a candidate workspace. It does **not** receive the NARF receipt key, receipt-store ownership, verifier selection, revocation authority or the effect target.

The trusted host:

1. reads the worker-produced candidate file;
2. freezes the candidate bytes, task, requirements and policy;
3. runs host-selected verifiers against the frozen candidate bytes;
4. requires an authenticated NARF PASS;
5. re-hashes the current worker candidate immediately before the effect; and
6. writes only the frozen, approved bytes to the host-owned effect target.

If the worker changes the candidate after PASS, the effect is blocked. If the worker tries to read or modify the host key, receipts or effect directory, the Unix boundary must deny the operation.

## Reference pieces

- `src/narf/process_host.py` — host-side adapter for a worker-owned candidate file.
- `tests/test_process_host.py` — logic and fail-closed regression tests.
- `tools/test_process_boundary.py` — Linux root harness that drops the worker to UID/GID 65534 with no supplementary groups or effective capabilities.
- `.github/workflows/reference-tests.yml` — runs the boundary harness in CI and preserves its evidence.

## Important boundary detail

The worker can change the candidate file at any time. The host therefore never lets the effect callback re-read that mutable file. The effect is bound to the frozen candidate bytes captured before verification.

This means a mutation after the final state check cannot redirect the effect to different bytes: the effect still contains the exact approved snapshot. A mutation that remains present at revalidation is detected as `CANDIDATE_CHANGED` and blocks execution.

## What this does not prove

This is still a reference Linux fixture. It does not certify a production container, VM, orchestration platform or remote target.

The following remain outside the demonstrated scope:

- rollback-resistant authority history across host restore;
- physical power-loss recovery guarantees;
- remote exactly-once completion;
- multi-machine fencing or distributed transactions;
- arbitrary privileged host compromise.

The result should be described as a measured trusted-host / untrusted-worker process boundary, not as production certification.
