# NARF — ARCHITECTURE

## PURPOSE

NARF is a standalone repository for the NARF acceptance-gate specification, reference implementation, and verification tests. It is separate from the private MGSystem repository and does not become MGSystem governance authority.

## SYSTEM BOUNDARIES

Current repository state is foundation-only. No standalone runtime, package, service, deployment, database, or privileged host launcher is established yet.

The repository must not contain MGSystem trusted-host receipt keys, production credentials, private project data, or deployment-owned secret state.

Root MGSystem `LAWS.md` remains ecosystem authority. This repository owns only NARF-specific implementation and documentation once separately authorized.

## INVARIANTS

- NARF must fail closed: missing, stale, invalid, incomplete, revoked, or mismatched evidence must never manufacture PASS.
- PASS evidence must remain bound to the exact task/candidate and the applicable frozen requirements and policy.
- A previous PASS must not authorize an effect after relevant state changes; pre-effect revalidation is required by the NARF model.
- Implementation/worker self-report is not sufficient acceptance evidence.
- Public/reusable NARF code must not depend on MGSystem private credentials or project-specific state.
- No public-release or production-readiness claim is valid without its own current verification evidence.

Application folder/module structure will follow the implementation boundaries established by a separately authorized runtime task.

## VERIFICATION

At foundation stage there are no NARF runtime source roots or project-local test commands yet.

Shared MGSystem foundation verification is expected through the MGSystem harness using the `mgsystem.ref` in `mgsystem.project.json` when that runtime is locally available. Standalone NARF runtime verification commands must be added to this document and projected into `mgsystem.project.json` in the same task that introduces the runtime.

Do not use this file for task history, speculative redesign, or duplicated state.
