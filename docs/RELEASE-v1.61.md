# v1.61 — signed-witness deadline hardening

`v1.61` is a stable patch release of the standalone MgNarf reference implementation.

It preserves the v1.60 behavioral boundary except for one availability hardening discovered by a post-release adversarial retest: a peer could drip HTTP response headers slowly enough that a configured one-second signed-witness timeout could take far longer to return. v1.61 closes that measured slow-header path and adds an exact regression fixture for it.

Stable still does **not** mean that every deployment is secure, every external effect is exactly-once, or that MgNarf has received an independent security certification.

## What changed since v1.60

- **Signed-witness slow-header deadline hardening.** The witness transport now reapplies one monotonic absolute deadline to response status/header/body socket reads instead of relying on a per-I/O timeout while headers are parsed.
- **Exact slow-header regression coverage.** A peer that emits HTTP response headers one byte at a time must fail closed inside the configured wall-clock budget.
- **HTTP/1.0 response lifetime compatibility.** The deadline reader preserves the socket file lifetime expected by `http.client`, including the reference witness server's HTTP/1.0 close behavior.
- **Transport-neutral ambiguous-ack fault injection.** The durable-reservation/ack-loss harness now injects at the signed-authority response boundary rather than depending on `urllib.request.urlopen`; the safety claim is unchanged.

No v1.60 tag or release was moved or rewritten. v1.60 remains immutable historical evidence.

## Evidence

See [TEST-REPORT-v1.61.md](TEST-REPORT-v1.61.md).

The v1.61 candidate PR completed all 11 repository workflows successfully. Its aggregate reference job ran **99 tests with 0 failures, 0 errors and 0 skips**, including both the existing slow-body witness timeout regression and the new slow-header regression. After the runtime change was merged, the exact `main` merge SHA `6226b837e163ca47faaa2f2d8ab338735451268a` again completed all 11 push workflows without failure or cancellation.

The external-agent retest that triggered this patch is useful adversarial evidence, but it is not treated as an independent security certification. Release acceptance relies on repository-owned reproducible gates on the exact release source.

## Stable acceptance gate

`v1.61` may be published only when all of the following hold:

1. this release-freeze change is merged to `main` without runtime, verifier, policy or test-semantic changes;
2. the exact merged freeze SHA completes the repository's required reference workflows;
3. `Reference tests (no skips)` is `success` on that exact SHA;
4. a stable release draft named `v1.61` is bound to that exact verified SHA while no `v1.61` tag exists;
5. repository release immutability is confirmed enabled by a repository administrator before first publication;
6. that exact draft is published without retargeting it;
7. the created `v1.61` tag resolves to the exact verified freeze SHA;
8. the published release reports `immutable=true`, `draft=false`, and `prerelease=false`.

The stable tag must never be moved after publication.

## Known boundaries retained in v1.61

v1.61 keeps the safety-over-availability choices and deployment limits already documented for v1.60:

- a durable authority reservation can intentionally remain consumed when later revalidation, callback failure, or an ambiguous acknowledgement prevents completion;
- authorization consumption does not prove exactly-once remote completion;
- the filesystem receipt store authenticates contents but is not rollback resistant by itself;
- replay can return if every preserving independent authority history is rolled back together;
- the trusted host remains responsible for semantic operation identity and for effect-payload identity unless the host includes it in frozen bindings;
- Python object privacy is not a security boundary; untrusted code requires enforced process/OS/sandbox separation;
- the reference timeout regression covers the reproduced socket-level slow-response paths; arbitrary resolver behavior, hostile network stacks, production control-plane isolation, physical-power-loss behavior, bind-mount aliasing and remote-target semantics remain deployment concerns outside that fixture;
- MgNarf has **not** received an independent external security certification.

A green limitation witness means that a documented limitation was reproduced as expected; it does not convert that limitation into a security PASS.

## License

Apache License 2.0. Preserve the applicable attribution from [NOTICE](NOTICE):

```text
This software includes software originally developed as MGNARF Ändi.
```

> PINKY: What do we do when stable gets attacked again?  
> BRAIN: Keep the old evidence immutable, reproduce the finding, fix the next version, and test again.
