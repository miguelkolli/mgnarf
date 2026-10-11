# v1.60-beta.1 — standalone reference beta

Prepared release notes for tag `v1.60-beta.1`. Publishing this document alone does not create a tag or GitHub release. The intended release is a **beta pre-release**.

## Scope

NARF is a standalone fail-closed acceptance gate for AI-assisted and automated work. This beta covers the Python standard-library reference implementation, authenticated receipts, frozen task/candidate bindings, pre-effect revalidation and at-most-once callback invocation under the documented trusted-host contract.

MGSystem is outside this release scope.

Beta indicates increased maturity of the standalone reference implementation and its recorded verification process. It does **not** certify an integrating production host, deployment sandbox or external effect system.

## Promotion gate

The alpha-to-beta conditions are defined in [BETA-ACCEPTANCE.md](BETA-ACCEPTANCE.md).

The `v1.60-beta.1` tag must point to the exact merged `main` commit whose required NARF reference checks have completed successfully. Do not publish the beta tag from an unverified PR head or from a later untested commit.

## Baseline evidence

The promotion started from main commit
[`478c3958beaf699c2db34d255fde764f4f38f596`](https://github.com/miguelkolli/mgnarf/commit/478c3958beaf699c2db34d255fde764f4f38f596).

[GitHub Actions run 38117123064](https://github.com/miguelkolli/mgnarf/actions/runs/38117123064) completed successfully for that baseline on 2026-10-11.

| Check | Baseline result |
| --- | --- |
| Repository tests | 34/34 PASS; 0 failures, 0 errors, 0 skips |
| Distinct UID/GID fixture | 24/24 PASS; 24 protected operations executed |
| Compile source, tests and harness | PASS |
| Unix gate source and frozen plan | Unchanged |

The beta candidate and final merged main commit must also satisfy the promotion gate. The baseline is not a substitute for that verification.

## What changes with beta

- The public maturity label moves from alpha to beta for the standalone reference implementation.
- Promotion requirements are now explicit and fail closed in `BETA-ACCEPTANCE.md`.
- Release publication is bound to successful verification of the exact final main commit.
- Known production integration limits remain visible rather than being reclassified as PASS.

No production-host certification is claimed by this maturity change.

## Integration requirements and limits

The integrating trusted host owns the receipt key, verifier/effect bindings,
current-state and revocation authority. It must protect receipt storage and
its parents, preserve consumption history, bind immutable effect inputs and
serialize relevant mutations with the complete synchronous effect call.

The Unix results apply to a disposable host-owned fixture. Production-host
integration, production sandboxing, deployment behavior, rollback-resistant
history, physical power-loss safety and durable remote acknowledgement remain
**UNVERIFIED**.

At-most-once callback invocation does not promise exactly-once completion of
an external action. This beta is not an independent security certification.

## License

Apache License 2.0. Preserve the applicable attribution in [NOTICE](NOTICE):

```text
This software includes software originally developed as MGNARF Ändi.
```

See [LICENSE](LICENSE) and [TRADEMARKS.md](TRADEMARKS.md).

> PINKY: Are we calling it finished, Brain?  
> BRAIN: No. We are promoting only what the evidence supports.
