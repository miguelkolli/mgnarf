# Documentation map

The repository root is intentionally small: [README.md](../README.md) is the public front door, [INDEX.md](../INDEX.md) is a compatibility pointer, and the canonical [LICENSE](../LICENSE) and [NOTICE](../NOTICE) stay at root. Project documentation lives here.

## Core documentation

- [OVERVIEW.md](OVERVIEW.md) — plain-English overview and repository map.
- [NARF-SPEC.md](NARF-SPEC.md) — behavioral specification.
- [ARCHITECTURE.md](ARCHITECTURE.md) — architecture and invariants.
- [INTEGRATION-GUIDE.md](INTEGRATION-GUIDE.md) — practical placement in real systems.
- [HOST-CONTRACT.md](HOST-CONTRACT.md) — trusted-host obligations.
- [HARDENED-PATHS.md](HARDENED-PATHS.md) — threat-model-specific execution paths.
- [IDENTITY-BOUNDARY.md](IDENTITY-BOUNDARY.md) — identity and separation-of-duties boundary.
- [STAGE-ORDER-BOUNDARY.md](STAGE-ORDER-BOUNDARY.md) — authenticated causal stage ordering.
- [FENCED-EFFECT-BOUNDARY.md](FENCED-EFFECT-BOUNDARY.md) — fenced-effect boundary.

## Release and evidence documents

- [RELEASE-v1.70.md](RELEASE-v1.70.md) / [TEST-REPORT-v1.70.md](TEST-REPORT-v1.70.md) — current stable release and evidence.
- [RELEASE-v1.61.md](RELEASE-v1.61.md) / [TEST-REPORT-v1.61.md](TEST-REPORT-v1.61.md) — previous immutable stable release and evidence.
- [RELEASE-v1.60.md](RELEASE-v1.60.md), [RELEASE-v1.60-rc2.md](RELEASE-v1.60-rc2.md), [RELEASE-v1.60-rc1.md](RELEASE-v1.60-rc1.md), [RELEASE-v1.60-beta.1.md](RELEASE-v1.60-beta.1.md) — earlier release records.
- [TEST-REPORT-v1.60-stable-adversarial.md](TEST-REPORT-v1.60-stable-adversarial.md) — v1.60 stable adversarial evidence.
- [TEST-REPORT.md](TEST-REPORT.md) — supplemental reference evidence and audits.
- [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) — release acceptance checklist.
- [RELEASE-PUBLICATION-v1.70.md](RELEASE-PUBLICATION-v1.70.md) — v1.70 publication gate record.

## Current security boundaries

- [AUTHORITY-REVISION.md](security/AUTHORITY-REVISION.md)
- [COMPOSED-OPERATION-PATH.md](security/COMPOSED-OPERATION-PATH.md)
- [OPERATION-IDEMPOTENCY.md](security/OPERATION-IDEMPOTENCY.md)
- [POSTGRES-FENCED-TARGET.md](security/POSTGRES-FENCED-TARGET.md)
- [ROLLBACK-BOUNDARY.md](security/ROLLBACK-BOUNDARY.md)
- [ROLLBACK-HARDENING.md](security/ROLLBACK-HARDENING.md)

## Security / authority

- [REFERENCE-HOST.md](security/host/REFERENCE-HOST.md)
- [PROCESS-BOUNDARY.md](security/host/PROCESS-BOUNDARY.md)
- [MULTIDOMAIN-FENCING.md](security/authority/MULTIDOMAIN-FENCING.md)
- [POSTGRES-AUTHORITY.md](security/authority/POSTGRES-AUTHORITY.md)
- [SIGNED-WITNESS.md](security/authority/SIGNED-WITNESS.md)
- [INDEPENDENCE.md](security/legacy/INDEPENDENCE.md)
- [CRASH-BOUNDARY.md](security/legacy/CRASH-BOUNDARY.md)

## Archive

- [BETA-ACCEPTANCE.md](archive/v1.60/BETA-ACCEPTANCE.md)
- [STABLE-READINESS-v1.60.md](archive/v1.60/STABLE-READINESS-v1.60.md)
- [TRUST-BOUNDARY-AUDIT-v1.60.md](archive/v1.60/TRUST-BOUNDARY-AUDIT-v1.60.md)
- [TEST-REPORT-v1.60-rc1-redteam.md](archive/v1.60/TEST-REPORT-v1.60-rc1-redteam.md)
- [RELEASE-v1.50.md](archive/v1.50/RELEASE-v1.50.md)
- [NEXT-RELEASE-READINESS.md](archive/NEXT-RELEASE-READINESS.md)
- [CODEX-UNIX-TESTS.md](archive/manual/CODEX-UNIX-TESTS.md)

## Legal and link compatibility

- [TRADEMARKS.md](TRADEMARKS.md) — project naming and branding policy.
- [LICENSE](../LICENSE) and [NOTICE](../NOTICE) — canonical legal files at repository root.

Exact `docs/LICENSE` and `docs/NOTICE` mirrors are retained only so historical release documents moved from the root keep their original relative legal links without rewriting recorded release evidence.

Historical release and test documents are moved for navigation only; their recorded evidence claims are not upgraded or rewritten by the move.
