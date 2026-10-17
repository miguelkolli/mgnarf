# v1.60-rc1 — release candidate

`v1.60-rc1` is the first release candidate for the standalone MgNarf v1.60 reference implementation.

The RC tag is valid only when it points to the exact merged release-freeze `main` commit whose required aggregate reference gate completed successfully. The tag must not be moved after publication.

## Scope

The release candidate includes:

- strict canonical task binding for the trusted Python host;
- frozen task, candidate, policy and external-goalpost bindings;
- a gate-computed digest of the exact verifier requirement set;
- verifier identity/version binding and complete N/N evidence coverage;
- authenticated receipts and stale/invalid decision rejection;
- revocation, inhibitor and immediate pre-effect state revalidation;
- trusted file-host and candidate-file-host reference integrations;
- distinct UID/GID and trusted-host/untrusted-worker process boundaries;
- abrupt host-process crash and at-most-once callback characterization;
- explicit filesystem rollback limitation evidence;
- rollback-protected consumption authorities and multi-domain all-of fencing;
- least-privilege PostgreSQL single-use authority;
- Ed25519 signed witness authority with fresh nonce response binding;
- stable HMAC-authenticated host-owned operation IDs across fresh contracts;
- high-fanout same-operation concurrency: 16 synchronized host processes with exactly one callback winner;
- fail-closed ambiguous durable-reservation behavior when witness or PostgreSQL acknowledgement is lost;
- deterministic canonical/receipt fuzz evidence;
- whole-chain `freeze → verify → decision → authority → effect` trust-boundary audit.

## RC1 acceptance gate

Before the immutable RC1 tag is created, the exact merged release-freeze commit must satisfy all applicable repository workflows. In particular, `Reference tests (no skips)` must succeed on that exact `main` SHA.

RC1 must not be published from a PR merge-ref, candidate branch SHA or a previous historical green run.

The release process records the exact source commit and then verifies that the created tag resolves to that same commit.

## Security boundary

The strong path is fail-closed when required evidence is incomplete, invalid or stale, and when external consumption authority is unavailable or its durable outcome becomes ambiguous.

An ambiguous reservation can intentionally burn authorization without completing the callback. This preserves at-most-once invocation safety at the cost of availability.

The signed witness and PostgreSQL authorities protect replay only while at least one preserving authority history remains trustworthy and monotonic relative to the attempted replay.

## Known limitations

These remain explicit in RC1:

- Python object privacy is not a security boundary; untrusted code requires enforced process/OS/sandbox separation.
- The trusted host defines semantic operation identity. Deliberately assigning a new operation ID to the same real-world action can create new authorization.
- Verifier correctness and selection remain trusted-host responsibilities.
- Session run state is memory-resident and may need to be reconstructed after a crash.
- If privileged operators can roll back every preserving authority history together, replay can return.
- CI process/service separation does not prove independent production administration.
- A consumed authorization does not guarantee exactly-once remote completion; callback/target failure can burn authorization.
- Physical-power-loss guarantees, arbitrary production sandboxing, external database/witness administration and remote-target semantics are not certified by the reference fixtures.
- MgNarf has not received an independent security certification.

See [TRUST-BOUNDARY-AUDIT-v1.60.md](docs/archive/v1.60/TRUST-BOUNDARY-AUDIT-v1.60.md) for the whole-chain RC audit.

## License

Apache License 2.0. Preserve the applicable attribution from [NOTICE](NOTICE):

```text
This software includes software originally developed as MGNARF Ändi.
```

> PINKY: Is RC1 the end of testing?  
> BRAIN: No. It is where the scope freezes and new ideas stop moving the release target.
