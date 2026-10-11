# NARF

## In plain English

AI systems can write code and take actions quickly, but **“looks good” is not the same as “proved safe to run.”** NARF is a small safety gate between AI-assisted work and the action that work is allowed to trigger.

Before an action is allowed, NARF asks:

- Are we still approving the exact same task and candidate that were checked?
- Is the exact verifier requirement set the one that was frozen?
- Did every required verifier actually run and pass?
- Is the evidence authentic, complete and current?
- Has relevant state changed, been revoked or been inhibited?
- Has this action already been consumed?

If any required condition is missing, uncertain or invalid, NARF does **not** manufacture PASS.

Think of it as a checkpoint for AI-assisted automation: **evidence first, action second**.

NARF does not make an AI correct, sandbox an entire system or certify a production deployment. It enforces a narrower rule: an automated action should happen only when the required evidence still supports that exact action at the moment it is executed.

## Technical summary

NARF is a standalone fail-closed acceptance gate for AI-assisted and automated work.

It has no required parent framework, private repository, workspace variable, external governance runtime or project harness. The core reference gate uses the Python standard library. Optional authority adapters may add external dependencies for their own measured boundary.

## Status: beta reference implementation

NARF is available for review, host-integration development and pre-production evaluation. **Beta** is a maturity label for the documented reference scope; it is not a production-host security certification.

The required merge gate now aggregates the repository tests, compilation, distinct UID/GID isolation, trusted-host/untrusted-worker process boundary, crash persistence, the filesystem rollback limitation witness, rollback hardening, multi-domain fencing and the PostgreSQL authority boundary. A required boundary that is skipped, cancelled or fails prevents the aggregate required check from succeeding.

Rollback claims are deliberately scoped. The filesystem-only receipt store is **not** rollback resistant. The measured hardened paths block replay while at least one independent consumption-authority history survives; the PostgreSQL fixture also demonstrates least-privilege runtime credentials and a single database winner under concurrent reservation. A privileged common control plane that can rewind every authority history remains an explicit limitation.

Production-host integration, production sandboxing, physical-power-loss behavior, exactly-once remote completion and privileged whole-authority rollback remain **UNVERIFIED** outside the documented fixtures.

The alpha-to-beta rules are defined in [BETA-ACCEPTANCE.md](BETA-ACCEPTANCE.md). The `v1.60-beta.1` pre-release is published only from an exact merged `main` commit after the required aggregate reference check succeeds.

### Historical promotion baseline

The original promotion baseline was observed in [GitHub Actions run 38117123064](https://github.com/miguelkolli/mgnarf/actions/runs/38117123064) on 2026-10-11 for commit [`478c3958beaf699c2db34d255fde764f4f38f596`](https://github.com/miguelkolli/mgnarf/commit/478c3958beaf699c2db34d255fde764f4f38f596).

That baseline recorded 34/34 repository tests PASS, 24/24 Unix isolation cases PASS and compile PASS. It is historical evidence, not a substitute for current exact-revision CI. Check the [current reference workflow](https://github.com/miguelkolli/mgnarf/actions/workflows/reference-tests.yml) for current evidence.

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

## Repository

- [NARF-SPEC.md](NARF-SPEC.md) — behavioral specification.
- [INDEPENDENCE.md](INDEPENDENCE.md) — standalone/dependency boundary.
- [ARCHITECTURE.md](ARCHITECTURE.md) — reference architecture and trust boundary.
- [HOST-CONTRACT.md](HOST-CONTRACT.md) — host locking, immutable effect input, receipt-history protection and persistence obligations.
- [REFERENCE-HOST.md](REFERENCE-HOST.md) and [PROCESS-BOUNDARY.md](PROCESS-BOUNDARY.md) — concrete trusted-host examples.
- [ROLLBACK-BOUNDARY.md](ROLLBACK-BOUNDARY.md), [ROLLBACK-HARDENING.md](ROLLBACK-HARDENING.md) and [MULTIDOMAIN-FENCING.md](MULTIDOMAIN-FENCING.md) — measured rollback boundaries.
- [POSTGRES-AUTHORITY.md](POSTGRES-AUTHORITY.md) — separately running PostgreSQL consumption authority and its limits.
- [src/narf/](src/narf/) — Python reference implementation and authority adapters.
- [tests/](tests/) and [tools/](tools/) — regression and adversarial fixtures.
- [TEST-REPORT.md](TEST-REPORT.md) — recorded evidence and historical limitations.
- [BETA-ACCEPTANCE.md](BETA-ACCEPTANCE.md) — beta promotion/release gate.
- [RELEASE-v1.60-beta.1.md](RELEASE-v1.60-beta.1.md) — beta pre-release notes.
- [LICENSE](LICENSE), [NOTICE](NOTICE) and [TRADEMARKS.md](TRADEMARKS.md) — license, attribution and branding.

## Run the tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests tools
```

The process regressions target Unix. A skip is not PASS in the required reference workflow. The 24-case Unix fixture requires Linux credential-switch authority; if that authority is unavailable, the fixture reports UNVERIFIED rather than inventing PASS.

## Trust model

The integrating trusted host owns:

- the HMAC receipt key and receipt-store authority;
- frozen task, candidate, external goalpost, policy and exact verifier-requirement bindings;
- verifier selection and execution;
- revocation and current-state probes;
- any external consumption authority used for rollback hardening;
- the gated effect callback.

Python attribute privacy is not a security boundary. Candidate code and untrusted workers must be separated from host authority by an enforced OS/process/sandbox boundary or an equivalent mechanism. There is intentionally no candidate evidence-submission or PASS-override API.

Verifier artifacts are hashed and authenticated as evidence, but the gate does not reinterpret a verifier's domain logic. Verifier correctness and selection remain trusted-host responsibilities.

## Integration limits

- Relevant state and revocation changes must share the host's authority lock or transaction with the complete synchronous `execute_effect` call. NARF cannot synchronize an actor that bypasses that protocol.
- The filesystem receipt store authenticates contents but cannot make history monotonic. If rollback/deletion is in scope, use an independent consumption authority such as the documented hardened adapters.
- A callback exception may leave authorization consumed without completing the external action. NARF prefers at-most-once invocation over availability; retry requires a new contract or a target-side idempotency/recovery protocol.
- Session execution state is in memory. A host crash before a durable final decision may require opening a new session and rerunning verifiers.
- The reference fixtures do not certify an arbitrary production sandbox, database control plane, deployment or remote target.

Read [HOST-CONTRACT.md](HOST-CONTRACT.md) before integrating an effect. NARF PASS applies only to the measured scope.

## License and attribution

The source code is licensed under the Apache License, Version 2.0. See `LICENSE`.

Redistributions and derivative works must preserve the applicable attribution from `NOTICE`:

```text
This software includes software originally developed as MGNARF Ändi.
```

The Apache license does not grant permission to present a modified version as the official NARF, MGNARF, or MGNARF Ändi project. See `TRADEMARKS.md`.

> PINKY: Did the checks actually run?  
> BRAIN: Yes. Keep the evidence, and keep the unverified boundaries visible.
