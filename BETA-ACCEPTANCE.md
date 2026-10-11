# Beta promotion acceptance gate

This document defines the alpha-to-beta promotion gate for the standalone NARF Python reference implementation.

Beta is a development maturity label for the documented standalone reference scope. It is **not** a production-host security certification and does not convert any explicitly UNVERIFIED deployment boundary into PASS.

## Promotion candidate

A beta candidate must be based on current `main` and reviewed through a pull request. The candidate may not weaken tests, verifier requirements, fail-closed behavior, receipt authentication, frozen bindings, revalidation, replay protection or documented integration limits merely to obtain a passing result.

## Mandatory PASS conditions

All conditions below are required. Missing evidence is `UNVERIFIED`, not PASS.

1. The repository regression suite executes completely on the candidate and reports zero failures and zero errors. A required test skip is not PASS.
2. The distinct-UID/GID Unix isolation fixture executes successfully and records every expected protected operation.
3. Source, tests and Unix harness compile successfully.
4. Gate source and the frozen Unix test plan remain unchanged during the isolation run.
5. The candidate preserves fail-closed behavior: missing, malformed, unauthenticated, stale, revoked, incomplete or mismatched evidence cannot manufacture PASS.
6. The candidate preserves the trusted-host contract: host-owned key authority, immutable effect bindings, serialized relevant mutations and protected consumption history remain explicit requirements.
7. README and release notes keep the known production boundaries visible as `UNVERIFIED`, including production-host integration, deployment sandboxing, rollback-resistant history, physical power-loss safety and durable remote acknowledgement.
8. LICENSE, NOTICE and TRADEMARKS.md remain present and applicable attribution is preserved.
9. The pull-request checks complete successfully for the exact candidate tree.
10. After merge, the required reference workflow completes successfully on the exact `main` commit intended for the beta tag.

## Promotion decision

```text
BETA PASS = candidate bindings frozen
         AND required CI complete
         AND repository tests PASS
         AND Unix isolation PASS
         AND compile PASS
         AND no required skips
         AND no weakened acceptance conditions
         AND known UNVERIFIED boundaries remain explicit
         AND final main commit revalidated
```

If any mandatory condition is false or lacks evidence, the promotion result is `BLOCKED` or `UNVERIFIED` and no beta tag should be published.

## Release rule

The first planned beta pre-release is `v1.60-beta.1`.

The tag must point to the exact merged `main` commit that has completed the required reference checks successfully. The GitHub release should be marked as a pre-release. The release notes must state that beta does not certify an integrating production host.

## Baseline entering promotion

Before this promotion work, `main` was commit `478c3958beaf699c2db34d255fde764f4f38f596`. GitHub Actions run `38117123064` completed successfully on that commit. The recorded baseline comprised 34/34 repository tests PASS, 24/24 Unix isolation cases PASS and compile PASS.

That baseline permits starting the beta promotion. It does not replace candidate and post-merge verification required above.
