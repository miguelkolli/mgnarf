# NARF

## In plain English

AI systems can write code and take actions quickly, but **“looks good” is not the same as “proved safe to run.”** NARF is a small safety gate between AI-assisted work and the action that work is allowed to trigger.

Before an action is allowed, NARF asks:

- Are we still approving the exact same task and candidate that were checked?
- Is the exact verifier requirement set the one that was frozen?
- Did every required verifier actually run and pass?
- Is the evidence authentic, complete and current?
- Has relevant state changed, been revoked or been inhibited?
- Has this operation already been consumed?

If any required condition is missing, uncertain or invalid, NARF does **not** manufacture PASS.

Think of it as a checkpoint for AI-assisted automation: **evidence first, action second**.

NARF does not make an AI correct, sandbox an entire system or certify a production deployment. It enforces a narrower rule: an automated action should happen only when the required evidence still supports that exact action at the moment it is executed.

## Technical summary

NARF is a standalone fail-closed acceptance gate for AI-assisted and automated work.

It has no required parent framework, private repository, workspace variable, external governance runtime or project harness. The core reference gate uses the Python standard library. Optional authority adapters add dependencies only for their own measured boundary.

## Status: v1.60 RC2 — immutable prerelease

`v1.60-rc2` is published as an immutable prerelease pinned to its verified release commit. It contains the post-RC1 red-team hardening for three reproduced findings and regression coverage for a fourth canonical-task boundary that was already fixed in RC1. **RC2 is not the stable v1.60 release and is not an independent security certification.**

The merge-required reference gate covers repository tests and compilation, strict canonical task binding, distinct UID/GID isolation, trusted-host/untrusted-worker process separation, crash persistence, filesystem rollback characterization, rollback hardening, multi-domain fencing, PostgreSQL consumption authority, Ed25519 signed witness fencing, stable operation-ID binding, high-fanout same-operation races, ambiguous durable-reservation outcomes, and the strict trusted reference-host transition. A required boundary that fails, skips or is cancelled prevents the aggregate required check from succeeding.

Additional focused workflows retain deterministic evidence for canonical/receipt fuzzing and integration fault injection. A green limitation witness means the documented limitation was reproduced exactly; it does not relabel that limitation as a security PASS.

The current release-candidate threat model and measured boundary are summarized in [TRUST-BOUNDARY-AUDIT-v1.60.md](TRUST-BOUNDARY-AUDIT-v1.60.md). RC1 remains documented in [RELEASE-v1.60-rc1.md](RELEASE-v1.60-rc1.md); the post-RC1 adversarial follow-up is in [TEST-REPORT-v1.60-rc1-redteam.md](TEST-REPORT-v1.60-rc1-redteam.md), and RC2 scope is in [RELEASE-v1.60-rc2.md](RELEASE-v1.60-rc2.md).

Rollback claims remain deliberately scoped. The filesystem receipt store is **not** rollback resistant. Hardened paths block replay while at least one independent consumption-authority history survives. If privileged operators can rewind the signed witness, PostgreSQL ledger and every other preserving authority history together, replay can return; that remains an explicit `LIMITATION_CONFIRMED` boundary.

Production-host isolation, production control-plane independence, physical-power-loss behavior, exactly-once remote completion, and privileged whole-authority rollback remain outside the measured guarantee.

## Core rule

```text
PASS only when the exact frozen task/candidate has complete authenticated
verifier evidence for the exact frozen verifier requirement set, every required
verifier passes, relevant state is unchanged, no inhibitor or revocation exists,
and state is revalidated immediately before the gated effect.
```

Equivalently:

```text
PASS = frozen task binding
    AND frozen candidate binding
    AND exact verifier-requirement-set binding
    AND external goalpost binding unchanged
    AND policy binding unchanged
    AND coverage N/N
    AND all verifiers PASS
    AND no inhibitors
    AND not revoked
    AND authenticated evidence
    AND pre-effect revalidation
```

If any required condition is absent or invalid, NARF must not manufacture PASS.

## Measured v1.60 boundary

The RC track includes evidence for:

- a strict Python-host JSON data model for security bindings; coercible non-JSON Python values fail closed;
- deterministic canonical/receipt fuzzing with 10,000 generated strict JSON values and 256 stale-MAC receipt mutations;
- exact task, candidate, policy, external-goalpost and verifier-requirement-set bindings;
- host-owned verifier execution with authenticated N/N evidence;
- revocation, inhibitor and state revalidation before effect;
- Unix UID/GID and trusted-host/untrusted-worker process boundaries;
- crash windows and at-most-once callback invocation characterization;
- rollback-protected single-use authorities and all-of multi-domain fencing;
- least-privilege PostgreSQL reservation with concurrent single-winner behavior;
- Ed25519 signed witness responses with fresh nonce binding;
- stable authenticated host-owned operation IDs across fresh contracts;
- a synchronized 16-host same-operation race requiring exactly one callback and fifteen consumed-token blocks;
- fail-closed ambiguous reservation outcomes when a durable witness or PostgreSQL reservation succeeds but its acknowledgement is lost;
- strict task validation at both the core gate and the trusted reference-host integration boundary.

These are measured reference boundaries, not an independent security certification.

## Repository

- [NARF-SPEC.md](NARF-SPEC.md) — behavioral specification.
- [INDEPENDENCE.md](INDEPENDENCE.md) — standalone/dependency boundary.
- [ARCHITECTURE.md](ARCHITECTURE.md) — reference architecture and trust boundary.
- [HOST-CONTRACT.md](HOST-CONTRACT.md) — host locking, immutable effect input and persistence obligations.
- [REFERENCE-HOST.md](REFERENCE-HOST.md) and [PROCESS-BOUNDARY.md](PROCESS-BOUNDARY.md) — trusted-host examples.
- [ROLLBACK-BOUNDARY.md](ROLLBACK-BOUNDARY.md), [ROLLBACK-HARDENING.md](ROLLBACK-HARDENING.md) and [MULTIDOMAIN-FENCING.md](MULTIDOMAIN-FENCING.md) — measured rollback boundaries.
- [POSTGRES-AUTHORITY.md](POSTGRES-AUTHORITY.md) — PostgreSQL authority boundary and limits.
- [TRUST-BOUNDARY-AUDIT-v1.60.md](TRUST-BOUNDARY-AUDIT-v1.60.md) — RC whole-chain adversarial audit.
- [RELEASE-v1.60-rc1.md](RELEASE-v1.60-rc1.md) — immutable RC1 release scope and known limitations.
- [TEST-REPORT-v1.60-rc1-redteam.md](TEST-REPORT-v1.60-rc1-redteam.md) — blind post-RC1 adversarial findings, fixes and retained evidence limits.
- [RELEASE-v1.60-rc2.md](RELEASE-v1.60-rc2.md) — RC2 hardening scope, acceptance gate and known boundaries.
- [src/narf/](src/narf/) — Python reference implementation and authority adapters.
- [tests/](tests/) and [tools/](tools/) — regression and adversarial fixtures.
- [TEST-REPORT.md](TEST-REPORT.md) — recorded evidence and historical limitations.
- [BETA-ACCEPTANCE.md](BETA-ACCEPTANCE.md) — historical beta promotion gate.
- [RELEASE-v1.60-beta.1.md](RELEASE-v1.60-beta.1.md) — first beta pre-release notes.
- [LICENSE](LICENSE), [NOTICE](NOTICE) and [TRADEMARKS.md](TRADEMARKS.md) — license, attribution and branding.

## Run the tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests tools
```

The process regressions target Unix. A skip is not PASS in the required reference workflow. Fixtures that cannot exercise their intended authority report the missing boundary rather than inventing PASS.

## Trust model

The integrating trusted host owns:

- the HMAC receipt key and receipt-store authority;
- frozen task, candidate, external goalpost, policy and exact verifier-requirement bindings;
- verifier selection and execution;
- revocation and current-state probes;
- semantic operation identity for the operation-bound path;
- any external consumption authority used for rollback hardening;
- the gated effect callback.

Python attribute privacy is not a security boundary. Candidate code and untrusted workers must be separated from host authority by an enforced OS/process/sandbox boundary or equivalent mechanism. There is intentionally no candidate evidence-submission or PASS-override API.

Verifier artifacts are hashed and authenticated as evidence, but the gate does not reinterpret a verifier's domain logic. Verifier correctness and selection remain trusted-host responsibilities.

## Integration limits

- The trusted host defines semantic `operation_id`. If it deliberately assigns a new operation ID to the same real-world operation, the gate cannot infer that the two IDs should be one operation.
- Relevant state and revocation changes must participate in the host's authority lock, transaction or fencing protocol with the complete synchronous effect path.
- The filesystem receipt store authenticates contents but cannot make history monotonic. Use independent consumption authorities when rollback/deletion is in scope.
- If every preserving authority history is rolled back together, replay can return.
- An ambiguous durable reservation is never released automatically. Availability may be sacrificed rather than risk replay.
- A callback exception may leave authorization consumed without completing the external action. NARF does not claim exactly-once remote completion.
- Session execution state is memory-resident. A crash can require a fresh session and repeated verification.
- The reference fixtures do not certify an arbitrary production sandbox, database control plane, witness operator, deployment or remote target.

Read [HOST-CONTRACT.md](HOST-CONTRACT.md) and [TRUST-BOUNDARY-AUDIT-v1.60.md](TRUST-BOUNDARY-AUDIT-v1.60.md) before integrating an effect. NARF PASS applies only to the measured scope.

## License and attribution

The source code is licensed under the Apache License, Version 2.0. See `LICENSE`.

Redistributions and derivative works must preserve the applicable attribution from `NOTICE`:

```text
This software includes software originally developed as MGNARF Ändi.
```

The Apache license does not grant permission to present a modified version as the official NARF, MGNARF, or MGNARF Ändi project. See `TRADEMARKS.md`.

> PINKY: Did the checks actually run?  
> BRAIN: Yes. Keep the evidence, and keep the unverified boundaries visible.
