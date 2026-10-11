# v1.60-beta.1 — standalone reference beta

This is the release note for the first NARF beta pre-release. The tag is valid only when it points to an exact merged `main` commit whose required aggregate reference check completed successfully.

## Scope

NARF is a standalone fail-closed acceptance gate for AI-assisted and automated work. This beta includes:

- authenticated host receipts;
- frozen task and candidate bindings;
- a gate-computed digest of the exact verifier requirement set;
- verifier identity/version binding and N/N coverage;
- revocation, inhibitor and state revalidation;
- single-use effect consumption;
- a trusted file-host reference integration;
- distinct UID/GID and trusted-host/untrusted-worker process fixtures;
- abrupt host-process crash/at-most-once characterization;
- an explicit filesystem rollback limitation witness;
- rollback-protected consumption authority;
- multi-domain all-of fencing;
- a least-privilege PostgreSQL consumption authority boundary.

Beta describes maturity of this reference scope. It does **not** certify an arbitrary production host, sandbox, database control plane or external effect system.

## Required release gate

The release commit must pass the required `Reference tests (no skips)` merge context. That context is an aggregate and fails unless all of these jobs succeed on the same exact revision:

1. repository tests and compile;
2. distinct UID/GID isolation;
3. trusted-host/untrusted-worker process boundary;
4. crash persistence / at-most-once boundary;
5. filesystem rollback limitation witness with its expected `LIMITATION_CONFIRMED` result;
6. rollback hardening;
7. multi-domain fencing with its documented limitation preserved;
8. PostgreSQL authority boundary with its documented privileged-admin limitation preserved.

A green limitation-witness job means the documented limitation was reproduced exactly. It does not relabel that limitation as a security PASS.

## Rollback claim boundary

The filesystem receipt store authenticates receipt contents but is not monotonic storage. Deleting a deterministic consumption record or restoring a valid older filesystem snapshot can resurrect authorization in that baseline model.

The hardened consumption-authority path blocks replay while at least one authority domain retains the consumed token. The PostgreSQL fixture further demonstrates a separately running service, least-privilege application credentials, fail-closed unavailability and a single database winner for concurrent reservations.

A privileged control plane that can rewind **every** authority history remains a documented limitation. This release does not claim Byzantine tolerance, independent administration merely from process separation, cross-region linearizability, physical-power-loss guarantees or rollback resistance against a coordinated privileged restore.

## Other limits

- Python name mangling is not an isolation boundary; host secrets require OS/process/sandbox separation from untrusted workers.
- State and revocation probes are host-owned. Relevant mutators must participate in the same authority lock, transaction or fencing protocol as the complete effect.
- The gate hashes verifier artifacts but does not independently interpret verifier domain logic. Verifier quality remains a trusted-host responsibility.
- Session run state is memory-resident; a crash can require a fresh session and repeated verification.
- Consumption is reserved before callback invocation. A failed callback may burn the authorization; exactly-once remote completion is outside the gate.
- This project has not received an independent security certification.

## License

Apache License 2.0. Preserve the applicable attribution in [NOTICE](NOTICE):

```text
This software includes software originally developed as MGNARF Ändi.
```

See [LICENSE](LICENSE) and [TRADEMARKS.md](TRADEMARKS.md).

> PINKY: Beta means the evidence boundary is clearer, not that the universe is solved.  
> BRAIN: Precisely.
