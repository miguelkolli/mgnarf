# v1.60 — stable reference release

`v1.60` is the first stable release of the standalone MgNarf reference implementation.

Stable here means that the v1.60 behavioral contract and measured reference boundary have completed the repository's beta → RC1 → red-team → RC2 → stable-hardening lifecycle and are frozen for this release. It does **not** mean that every deployment is secure, that every external effect is exactly-once, or that MgNarf has received an independent security certification.

## What stable v1.60 contains

The release retains the RC2 hardening and adds the final post-RC2 semantic fixes:

- strict frozen task/candidate/policy/goalpost and verifier-requirement binding;
- authenticated complete N/N verifier evidence and immediate pre-effect revalidation;
- revocation and inhibitor enforcement, including a stop condition introduced after finalized PASS but before effect consumption;
- configured revocation probes fail closed unless they return the exact boolean `False`;
- trusted-host/untrusted-worker and distinct UID/GID reference boundaries;
- crash persistence and at-most-once callback characterization;
- rollback-protected authorities, PostgreSQL fencing, signed-witness fencing and multi-domain all-of authority;
- stable host-owned operation IDs across fresh contracts and high-fanout same-operation single-winner races;
- strict canonical JSON task binding and receipt/canonical fuzz coverage;
- FIFO candidate availability hardening and bounded signed-witness drip-body handling;
- session-bound rollback authority;
- `TrustedFileHost` publication through a fully written and fsynced same-directory temporary file followed by atomic no-overwrite publication, preventing partial final target exposure in the measured publication-fault paths;
- fresh post-hardening stable adversarial regression coverage.

## Stable-readiness evidence

The post-RC2 semantic review is recorded in [STABLE-READINESS-v1.60.md](docs/archive/v1.60/STABLE-READINESS-v1.60.md).

The fresh post-hardening adversarial pass is recorded in [TEST-REPORT-v1.60-stable-adversarial.md](TEST-REPORT-v1.60-stable-adversarial.md).

That fresh pass added eight attack/fault-injection probes. On the merged post-adversarial main source it ran as part of a 98-test core suite with 0 failures, 0 errors and 0 skips, followed by a successful `Reference tests (no skips)` aggregate. The evidence is same-project/self-adversarial, not an independent external review.

## Stable acceptance gate

`v1.60` may be published only when all of the following hold:

1. this stable-freeze change is merged to `main` without runtime, verifier, policy or test-semantic changes;
2. the exact merged freeze SHA completes the repository's required reference workflows;
3. `Reference tests (no skips)` is `success` on that exact SHA;
4. a stable release draft named `v1.60` is bound to that exact verified SHA while no `v1.60` tag exists;
5. repository release immutability is confirmed enabled by a repository administrator before first publication;
6. that exact draft is published without retargeting it;
7. the created `v1.60` tag resolves to the exact verified freeze SHA;
8. the published release reports `immutable=true`, `draft=false`, and `prerelease=false`.

The stable tag must never be moved after publication.

## Known boundaries retained in stable v1.60

Stable does not erase the measured limits:

- the filesystem receipt store authenticates contents but is not rollback resistant by itself;
- replay can return if privileged operators roll back every preserving independent authority history together;
- a durable authority reservation can intentionally be burned if relevant state changes later or callback execution fails;
- authorization consumption does not prove exactly-once remote completion;
- if local target publication succeeds but a later durability acknowledgement fails, the outcome can be ambiguous even though the visible target is complete;
- the trusted host defines semantic operation identity; deliberately assigning a new operation ID to the same real-world action can create new authorization;
- effect-payload identity remains a host integration responsibility unless included in the frozen task/state/host contract; v1.60 does not impose a universal external-effect payload schema;
- Python object privacy is not a security boundary; untrusted code requires enforced process/OS/sandbox separation;
- production-host isolation, production control-plane independence, physical-power-loss behavior, arbitrary resolver/transport deadline behavior, bind-mount aliasing and remote-target semantics are outside the certified reference fixtures;
- MgNarf has **not** received an independent external security certification.

A green limitation witness means that a documented limitation was reproduced as expected; it does not convert that limitation into a security PASS.

## License

Apache License 2.0. Preserve the applicable attribution from [NOTICE](NOTICE):

```text
This software includes software originally developed as MGNARF Ändi.
```

> PINKY: Is stable the end of testing?  
> BRAIN: No. Stable freezes the v1.60 contract; new evidence can still produce the next fix or next version.
