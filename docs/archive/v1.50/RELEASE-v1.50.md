# v1.50 — standalone reference alpha

Prepared release notes for tag `v1.50`. Publishing this document does not
create a tag or GitHub release. The intended release is an **alpha pre-release**.

## Scope

NARF is a standalone fail-closed acceptance gate for AI-assisted and automated
work. This release candidate covers the Python standard-library reference
implementation, authenticated receipts, frozen task/candidate bindings,
pre-effect revalidation and at-most-once callback invocation under the
[trusted-host contract](../../HOST-CONTRACT.md). MGSystem is outside this scope.

Release source: [`45be1f7b7bbe25003a0ecc49c861dc3f653470f9`](https://github.com/miguelkolli/mgnarf/commit/45be1f7b7bbe25003a0ecc49c861dc3f653470f9).
The proposed tag must point to that exact tested commit.

## Changes included

- Reject deeply nested malformed receipts through the existing fail-closed path.
- Block effects when receipt-directory durability checks fail; preserve
  uncertain consumption reservations to prevent replay.
- Document and test trusted-host serialization and immutable effect inputs.
- Add fresh-process regressions and a runnable distinct-UID/GID Unix harness.
- Run reference regressions, compilation and the Unix fixture in GitHub Actions.
- Publish alpha status and evidence limits in README and TEST-REPORT.

## Recorded verification

[GitHub Actions run 38116156257](https://github.com/miguelkolli/mgnarf/actions/runs/38116156257)
completed successfully for the exact release source on 2026-10-11.
The completed job steps and their emitted summaries were checked.

| Check | Result |
| --- | --- |
| Repository tests | 34/34 PASS; 0 failures, 0 errors, 0 skips |
| Distinct UID/GID fixture | 24/24 PASS; 24 protected operations executed |
| Compile source, tests and harness | PASS |
| Unix gate source and frozen plan | Unchanged |

The two test counts describe different suites and are not combined.
The recorded reference environment was Python 3.12.3 on Linux.
See [TEST-REPORT.md](../../TEST-REPORT.md) for earlier supplemental tests and audits.

## Integration requirements and limits

The integrating trusted host owns the receipt key, verifier/effect bindings,
current-state and revocation authority. It must protect receipt storage and
its parents, preserve consumption history, bind immutable effect inputs and
serialize relevant mutations with the complete synchronous effect call.

The Unix results apply to a disposable host-owned fixture. Production
sandboxing, deployment behavior, rollback-resistant history, physical
power-loss safety and durable remote acknowledgement remain UNVERIFIED.
At-most-once callback invocation does not promise exactly-once completion
of an external action. This alpha is not an independent security certification.

## License

Apache License 2.0. Preserve the applicable attribution in [NOTICE](../../../NOTICE):

```text
This software includes software originally developed as MGNARF Ändi.
```

See [LICENSE](../../../LICENSE) and [TRADEMARKS.md](../../TRADEMARKS.md).

> PINKY: What are we publishing, Brain?  
> BRAIN: The tested reference, with its evidence and limits.
