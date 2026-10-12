# MGnarf repository index

This is the navigation map for the MGnarf repository.

Use it when you know **what you want to do**, but not yet **which file to read**.

## Quick routes

| I want to... | Start here |
| --- | --- |
| understand MGnarf in plain English | [README.md](README.md) |
| see where MGnarf belongs in my stack | [INTEGRATION-GUIDE.md](INTEGRATION-GUIDE.md) |
| integrate a real protected effect | [HOST-CONTRACT.md](HOST-CONTRACT.md) |
| understand the trust model and architecture | [ARCHITECTURE.md](ARCHITECTURE.md) |
| read the normative behavior | [NARF-SPEC.md](NARF-SPEC.md) |
| inspect the current stable release | [RELEASE-v1.61.md](RELEASE-v1.61.md) |
| inspect current stable evidence | [TEST-REPORT-v1.61.md](TEST-REPORT-v1.61.md) |
| audit historical adversarial findings | [TRUST-BOUNDARY-AUDIT-v1.60.md](TRUST-BOUNDARY-AUDIT-v1.60.md) |
| understand rollback / replay limits | [ROLLBACK-BOUNDARY.md](ROLLBACK-BOUNDARY.md) |
| inspect the Python implementation | [src/narf/](src/narf/) |
| inspect regression tests | [tests/](tests/) |
| inspect adversarial / boundary harnesses | [tools/](tools/) |
| inspect CI and release gates | [.github/workflows/](.github/workflows/) |

## Contents

- [Start here](#start-here)
- [Integration and trusted-host boundaries](#integration-and-trusted-host-boundaries)
- [Specification and architecture](#specification-and-architecture)
- [Authority, replay and rollback boundaries](#authority-replay-and-rollback-boundaries)
- [Current stable release](#current-stable-release)
- [Historical releases and acceptance evidence](#historical-releases-and-acceptance-evidence)
- [Source code](#source-code)
- [Tests](#tests)
- [Tools and adversarial fixtures](#tools-and-adversarial-fixtures)
- [CI and release workflows](#ci-and-release-workflows)
- [Legal and attribution](#legal-and-attribution)

## Start here

- [README.md](README.md) — plain-English overview, current stable status, core rule, measured boundary and trust model.
- [INTEGRATION-GUIDE.md](INTEGRATION-GUIDE.md) — stack-oriented guide showing where MGnarf goes before deploys, database writes, API mutations, file publication and device commands.
- [HOST-CONTRACT.md](HOST-CONTRACT.md) — obligations of the integrating trusted host: serialization, immutable effect input, receipt/key protection and failure handling.
- [REFERENCE-HOST.md](REFERENCE-HOST.md) — concrete trusted-host filesystem-effect example.
- [PROCESS-BOUNDARY.md](PROCESS-BOUNDARY.md) — trusted-host / untrusted-worker process boundary example and limits.

## Integration and trusted-host boundaries

- [INTEGRATION-GUIDE.md](INTEGRATION-GUIDE.md) — choose-your-stack placement guide and integration checklist.
- [HOST-CONTRACT.md](HOST-CONTRACT.md) — authority-lock / transaction requirements and host responsibilities.
- [REFERENCE-HOST.md](REFERENCE-HOST.md) — single-process trusted-host reference integration.
- [PROCESS-BOUNDARY.md](PROCESS-BOUNDARY.md) — process separation and credential-boundary example.
- [CODEX-UNIX-TESTS.md](CODEX-UNIX-TESTS.md) — Unix isolation test plan/evidence context.
- [CRASH-BOUNDARY.md](CRASH-BOUNDARY.md) — crash-window and persistence boundary.

## Specification and architecture

- [NARF-SPEC.md](NARF-SPEC.md) — behavioral specification.
- [ARCHITECTURE.md](ARCHITECTURE.md) — reference architecture, components and invariants.
- [INDEPENDENCE.md](INDEPENDENCE.md) — standalone/dependency boundary; MGnarf does not require a parent framework.

## Authority, replay and rollback boundaries

- [OPERATION-IDEMPOTENCY.md](OPERATION-IDEMPOTENCY.md) — semantic operation identity and stable operation-bound authority.
- [POSTGRES-AUTHORITY.md](POSTGRES-AUTHORITY.md) — PostgreSQL consumption authority and its measured limits.
- [SIGNED-WITNESS.md](SIGNED-WITNESS.md) — signed-witness authority, response validation and measured network boundary.
- [ROLLBACK-BOUNDARY.md](ROLLBACK-BOUNDARY.md) — what the filesystem receipt history does and does not protect against.
- [ROLLBACK-HARDENING.md](ROLLBACK-HARDENING.md) — stronger single-use consumption authority patterns.
- [MULTIDOMAIN-FENCING.md](MULTIDOMAIN-FENCING.md) — combining independent authority domains and the retained whole-authority rollback limit.

## Current stable release

The current stable release is **v1.61**.

- [RELEASE-v1.61.md](RELEASE-v1.61.md) — immutable v1.61 release scope, acceptance gate and retained boundaries.
- [TEST-REPORT-v1.61.md](TEST-REPORT-v1.61.md) — v1.61 reproduced finding, deadline hardening and exact repository evidence.
- [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) — release preparation / verification checklist.

The GitHub release/tag is the immutable release artifact. `main` may continue to receive documentation or later development without moving an immutable historical tag.

## Historical releases and acceptance evidence

### v1.60 stable line

- [RELEASE-v1.60.md](RELEASE-v1.60.md) — immutable v1.60 stable release scope.
- [STABLE-READINESS-v1.60.md](STABLE-READINESS-v1.60.md) — stable-readiness review and retained limits.
- [TEST-REPORT-v1.60-stable-adversarial.md](TEST-REPORT-v1.60-stable-adversarial.md) — adversarial stable retest evidence.
- [TRUST-BOUNDARY-AUDIT-v1.60.md](TRUST-BOUNDARY-AUDIT-v1.60.md) — whole-chain trust-boundary audit.
- [RELEASE-v1.60-rc2.md](RELEASE-v1.60-rc2.md) — RC2 hardening release evidence.
- [RELEASE-v1.60-rc1.md](RELEASE-v1.60-rc1.md) — RC1 release evidence.
- [TEST-REPORT-v1.60-rc1-redteam.md](TEST-REPORT-v1.60-rc1-redteam.md) — blind red-team findings and regression evidence after RC1.
- [RELEASE-v1.60-beta.1.md](RELEASE-v1.60-beta.1.md) — first v1.60 beta prerelease.
- [BETA-ACCEPTANCE.md](BETA-ACCEPTANCE.md) — historical beta promotion gate.

### Earlier history

- [RELEASE-v1.50.md](RELEASE-v1.50.md) — earlier stable milestone notes.
- [TEST-REPORT.md](TEST-REPORT.md) — accumulated historical test evidence and limitations.

Historical documents are evidence of the state that was measured at that time. They should not be silently rewritten to describe a newer release.

## Source code

The public Python reference implementation lives in [src/narf/](src/narf/).

- [src/narf/gate.py](src/narf/gate.py) — core fail-closed gate, frozen contracts, verifier evidence, decisions, receipts and effect execution.
- [src/narf/operation_guard.py](src/narf/operation_guard.py) — operation-bound execution helpers.
- [src/narf/rollback_guard.py](src/narf/rollback_guard.py) — consumption authorities and rollback-hardened effect execution.
- [src/narf/postgres_authority.py](src/narf/postgres_authority.py) — PostgreSQL-backed consumption authority.
- [src/narf/signed_witness.py](src/narf/signed_witness.py) — signed-witness consumption authority and response deadline handling.
- [src/narf/reference_host.py](src/narf/reference_host.py) — reference trusted-host filesystem effect integration.
- [src/narf/process_host.py](src/narf/process_host.py) — trusted-host / untrusted-worker process integration fixture.
- [src/narf/__init__.py](src/narf/__init__.py) — public reference API exports.

## Tests

The unit/regression suite lives in [tests/](tests/).

Major areas covered there include:

- core gate and requirement binding;
- canonical JSON and receipt validation;
- trusted-host serialization;
- process / worker boundaries;
- reference-host behavior;
- rollback and operation-bound authority;
- PostgreSQL and signed-witness configuration;
- crash/store durability;
- red-team and stable-adversarial regressions.

Run the repository suite with:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests tools
```

## Tools and adversarial fixtures

Boundary and fault-injection harnesses live in [tools/](tools/).

They include fixtures for:

- Unix UID/GID isolation;
- trusted-host process separation;
- crash persistence;
- canonical binding fuzzing;
- rollback and rollback hardening;
- multi-domain fencing;
- PostgreSQL authority;
- signed-witness behavior;
- operation idempotency and concurrent operation races;
- ambiguous durable-reservation outcomes;
- strict reference-host task coercion.

`tools/signed_witness_server.py` is the reference signed-witness service used by the measured witness fixtures.

## CI and release workflows

GitHub Actions live in [.github/workflows/](.github/workflows/).

### Boundary / regression workflows

- `reference-tests.yml` — aggregate required reference checks.
- `canonical-binding-fuzz.yml` — canonical binding / receipt fuzz boundary.
- `reference-host-strict-task.yml` — strict trusted-host task boundary.
- `rollback-witness.yml` — documented rollback limitation witness.
- `rollback-hardening.yml` — rollback-hardening boundary.
- `multidomain-fencing.yml` — multi-domain authority boundary.
- `postgres-authority.yml` — PostgreSQL authority boundary.
- `signed-witness.yml` — signed-witness authority boundary.
- `operation-bound-authority.yml` — operation-bound authority checks.
- `operation-idempotency-witness.yml` — stable operation identity / replay checks.
- `ambiguous-authority.yml` — ambiguous durable-reservation fault boundary.

### Historical / stable release workflows

- `beta-release.yml` — historical beta release workflow.
- `rc-release.yml` — historical RC1 release workflow.
- `rc2-release.yml` — historical RC2 release workflow.
- `stable-release.yml` — v1.60 stable release verification workflow.
- `stable-release-v1.61.yml` — v1.61 stable release verification workflow.

A green workflow only supports the boundary that workflow actually measures. Limitation-witness success means the documented limitation reproduced as expected; it does not turn that limitation into a security guarantee.

## Legal and attribution

- [LICENSE](LICENSE) — Apache License 2.0.
- [NOTICE](NOTICE) — required project attribution.
- [TRADEMARKS.md](TRADEMARKS.md) — naming and official-project branding boundary.

---

If you are new to the repository, the shortest useful reading path is:

**[README](README.md) → [INTEGRATION-GUIDE](INTEGRATION-GUIDE.md) → [HOST-CONTRACT](HOST-CONTRACT.md) → [RELEASE-v1.61](RELEASE-v1.61.md) → [TEST-REPORT-v1.61](TEST-REPORT-v1.61.md)**
