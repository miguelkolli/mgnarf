# MgNarf v1.60 RC1 red-team follow-up

Date: 2026-10-12

## Scope and provenance

A blind red-team pass was reported against historical `main` commit
`d53f19bd79f366bc61598895b22c82887b310741`. That commit predates the immutable
`v1.60-rc1` source commit
`85cd54fd629336d63c10e7ebf6f946084447b3e7`.

The red-team agent did not receive the repository tests or this report before
its review, but it did read source code. The reviewer and the repository-building
assistant are from the same model family. This is therefore **blind self/red-team
evidence, not an independent external security review or certification**.

This follow-up re-audited the reported code paths on the RC1 source before
changing them. Findings #1, #2 and #3 were still structurally present on the
RC1 source. Finding #4 had already been fixed on RC1 and already had strict
canonical-JSON regression coverage.

## Confirmed hardening in this follow-up

### 1. FIFO candidate path can block the trusted host

Severity: medium availability issue.

The candidate reader previously opened a worker-controlled path in blocking
mode and only then used `fstat()` to reject non-regular files. A FIFO swapped in
after verification could therefore block the open while `commit()` held the
host authority lock, preventing `revoke()` from acquiring the same lock.

Hardening: add `O_NONBLOCK` where available before opening the candidate, then
retain the post-open `fstat()` regular-file check. A regression test performs the
FIFO probe in a child process with a hard test timeout so a future regression
cannot hang the entire test runner indefinitely.

### 2. Signed-witness timeout can be extended by a dripping response body

Severity: low-to-medium availability issue.

The witness client passed `timeout_seconds` to `urlopen()`, which is a socket
operation timeout rather than a complete body-read deadline. A peer that keeps
making incremental progress can extend the request well beyond the configured
limit.

Hardening: establish a monotonic deadline at request start, pass the remaining
time into `urlopen()`, tighten the exposed response socket timeout to the
remaining budget, and consume the response with one-read-at-a-time bounded
chunks while recomputing the remaining budget. The regression test uses a real
loopback HTTP server that drips a response body and requires a one-second
configured timeout to fail closed within a bounded wall-clock interval.

Remaining boundary: the standard-library URL opener still owns DNS resolution
and response-header parsing. This change closes the reproduced drip-body path;
it is not a claim that every operating-system resolver or transport failure can
be synchronously interrupted at an exact deadline on every platform.

### 3. Rollback executor accepted a caller-selected contract UUID

Severity: medium replay/rollback-boundary issue in the compatibility executor.

`RollbackProtectedEffectExecutor.execute(contract_id, session)` previously used
the caller-supplied UUID as the external single-use token without checking that
it matched the frozen contract inside a real `NARFSession`. Supplying a fresh
UUID could therefore choose a fresh rollback-protection token for an existing
session.

Hardening: when the executor receives a real NARF session, derive the bound
contract ID from that session's frozen contract, reject any mismatch, and reserve
the session-bound ID. The public compatibility call shape remains unchanged.
Structural test doubles that are not NARF sessions retain the historical token
behavior; they are outside the trusted-host NARF session boundary.

### 4. Canonical task collisions / lone surrogate

Severity in the original report: low.

No new production change was required on the RC1 source. Strict canonical JSON
already rejects non-string object keys, tuples/list subclasses and lone UTF-16
surrogates with `NARFError`. Existing canonical-JSON tests cover the original
coercion-collision classes; this follow-up adds a small red-team regression
witness for the exact reported shapes.

## Reported results that remain useful evidence

The reported attack pass observed no violation in the following areas:

- concurrent duplicate execution, including a reported 16-thread/session case;
- randomized crash and revocation races;
- receipt mutation/truncation attacks;
- external-authority rollback protection and AllOf alias checks;
- candidate replacement by symlink, directory, device and oversized file.

These observations are preserved as reported evidence only. This follow-up does
not relabel them as independent verification.

## Remaining findings / follow-up work

The following reported items were not silently folded into this patch and should
remain visible for separate semantic review:

- `inhibit()` after `finalize()` versus the inhibitor language in spec section 9;
- permissive treatment of a revocation probe returning `None`;
- non-atomic final target write / partial target persistence on write failure;
- whether TrustedFileHost payload identity should be part of the locked task or
  effect binding beyond its current candidate/state binding;
- the intentional availability trade-off where an authority reservation can be
  burned if state changes between decision revalidation and effect entry.

## Evidence limits explicitly retained

The reported `t15` race evidence was inconclusive: one version blocked every
run and another allowed every run, while both avoided wrong-byte output. It does
not establish the interesting middle interleaving.

Not covered by that reported pass:

- a live PostgreSQL authority instance;
- physical power-loss behavior and injected `fsync()` faults;
- bind-mount aliases into the same authority directory;
- independent third-party security review.

## Release interpretation

`v1.60-rc1` is immutable and is not modified by this work. If this hardening
passes the repository gates and is accepted, it belongs in a later release
candidate (for example `v1.60-rc2`) rather than retargeting RC1.
