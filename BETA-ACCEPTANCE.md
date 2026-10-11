# Beta promotion acceptance gate

This document defines the alpha-to-beta promotion gate for the standalone NARF Python reference implementation.

Beta is a development maturity label for the documented reference scope. It is **not** a production-host security certification and does not convert an explicitly unverified deployment boundary into PASS.

## Promotion candidate

A beta candidate must be based on current `main` and reviewed through a pull request. The candidate may not weaken tests, verifier requirements, fail-closed behavior, receipt authentication, frozen bindings, revalidation, replay protection or documented integration limits merely to obtain a passing result.

## Mandatory conditions

Missing evidence is `UNVERIFIED`, not PASS.

1. Repository tests execute completely with zero failures/errors and no required skips, and source/tests/tools compile.
2. Distinct UID/GID isolation executes all planned protected operations.
3. Trusted-host/untrusted-worker process-boundary checks succeed.
4. Crash-persistence checks preserve the documented at-most-once boundary.
5. The filesystem rollback witness reproduces its documented `LIMITATION_CONFIRMED` result exactly; a missing limitation witness is not promotion PASS.
6. Rollback hardening blocks both measured replay paths.
7. Multi-domain fencing reproduces its exact protected/limitation boundary.
8. The PostgreSQL authority fixture reproduces its exact protected/privileged-admin limitation boundary.
9. The candidate preserves fail-closed semantics: missing, malformed, unauthenticated, stale, revoked, incomplete or mismatched evidence cannot manufacture PASS.
10. The exact verifier requirement list is bound by a gate-computed canonical digest carried through accepted verification, decision and effect evidence.
11. Trusted-host obligations remain explicit: host-owned key authority, verifier quality, state/revocation probes, immutable effect inputs, serialized relevant mutations and protected consumption history.
12. README and release notes keep production limits visible, including production sandboxing, privileged whole-authority rollback, physical power-loss behavior and exactly-once remote completion.
13. LICENSE, NOTICE and TRADEMARKS.md remain present and applicable attribution is preserved.
14. Pull-request checks complete successfully for the exact candidate tree.
15. After merge, the required aggregate `Reference tests (no skips)` context completes successfully on the exact `main` commit intended for the beta tag.

## Required merge context

`Reference tests (no skips)` is an aggregate check. It runs even when a dependency fails and fails unless every required boundary job reports `success`. This prevents the repository ruleset from becoming green merely because only the original core/unit and UID/GID checks passed.

The separate limitation-witness jobs intentionally succeed only when their **expected limitation** is reproduced. Their success is evidence that the boundary is still visible, not that the limited configuration became safe.

## Promotion decision

```text
BETA PASS = exact candidate bindings frozen
         AND aggregate required CI complete
         AND all required protected cases satisfy their stated expectations
         AND all required limitation witnesses remain explicit
         AND no required skips
         AND no weakened acceptance conditions
         AND known unverified boundaries remain explicit
         AND exact merged main commit revalidated
```

If any mandatory condition is false or lacks evidence, promotion is `BLOCKED` or `UNVERIFIED` and no beta tag should be published.

## Release rule

The first beta pre-release is `v1.60-beta.1`.

The release workflow may create that tag only after the `NARF reference checks` workflow completes successfully for a **push to `main`**. It must target the exact `workflow_run.head_sha`, mark the GitHub release as a pre-release, and use `RELEASE-v1.60-beta.1.md` as its notes.

If the tag or release already exists, automation must not silently retarget it.

## Historical baseline

Promotion work originally started from main commit `478c3958beaf699c2db34d255fde764f4f38f596`, where GitHub Actions run `38117123064` recorded 34/34 repository tests PASS, 24/24 Unix isolation cases PASS and compile PASS.

That baseline is historical evidence only. It never replaces exact candidate and exact final-main verification.
