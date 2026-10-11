# NARF

NARF is a standalone fail-closed acceptance gate for AI-assisted and automated work.

It has no required parent framework, workspace variable, private repository, external governance system, or project harness. The reference implementation uses only the Python standard library.

## Status: alpha reference implementation

NARF is available for review, experimentation and host-integration development.
The current development status is **alpha**. This status does not imply that
a versioned release has been published.

The recorded standalone reference checks pass. Production-host integration,
deployment sandboxing, rollback resistance and physical power-loss safety
remain **UNVERIFIED**.

### Recorded verification

The following results were observed in
[GitHub Actions run 38115420983](https://github.com/miguelkolli/mgnarf/actions/runs/38115420983)
on 2026-10-11, for exact commit
[`51182b678ae0b7da2aa1197468cb3e8f74c3ca6d`](https://github.com/miguelkolli/mgnarf/commit/51182b678ae0b7da2aa1197468cb3e8f74c3ca6d).

| Check | Observed result |
| --- | --- |
| Repository regression suite | **34/34 PASS**, 0 failures, 0 errors, 0 skips |
| Unix UID/GID isolation fixture | **24/24 PASS**, 24 protected operations executed |
| Compile source, tests and Unix harness | **PASS** |
| Unix gate source and frozen plan | Unchanged during the run |

The Unix cases use a disposable host-owned fixture and workers under a distinct
UID/GID. They test OS denial of key/receipt tampering, positive access controls,
unchanged host state and rejection of replay. They are separate from the
34 unittest methods.

These are results for the recorded revision. Check the
[latest workflow runs](https://github.com/miguelkolli/mgnarf/actions/workflows/reference-tests.yml)
for later revisions, and see [TEST-REPORT.md](TEST-REPORT.md) for the detailed
evidence, earlier supplemental runs, audit findings and limitations. Earlier
parameterized repetitions are not counted as additional current CI tests.

## Core rule

```text
PASS only when the exact frozen task/candidate has complete authenticated
verifier evidence, every required verifier passes, relevant state is unchanged,
no inhibitor or revocation exists, and state is revalidated immediately before
the gated effect.
```

Equivalently:

```text
PASS = frozen bindings
    AND candidate unchanged
    AND requirements unchanged
    AND policy unchanged
    AND coverage N/N
    AND all verifiers PASS
    AND no inhibitors
    AND not revoked
    AND authenticated evidence
    AND pre-effect revalidation
```

If any required condition is missing or invalid, NARF must not manufacture PASS.

## Repository

- [NARF-SPEC.md](NARF-SPEC.md) — behavioral specification.
- [INDEPENDENCE.md](INDEPENDENCE.md) — standalone/dependency boundary.
- [ARCHITECTURE.md](ARCHITECTURE.md) — reference architecture and trust boundary.
- [HOST-CONTRACT.md](HOST-CONTRACT.md) — host locking, immutable effect input, receipt-history protection and persistence obligations.
- [src/narf/gate.py](src/narf/gate.py) — Python reference implementation.
- [tests/](tests/) — reference and adversarial regression tests.
- [tools/test_unix_isolation.py](tools/test_unix_isolation.py) — distinct-UID/GID isolation harness.
- [CODEX-UNIX-TESTS.md](CODEX-UNIX-TESTS.md) — local Unix harness instructions and required privileges.
- [TEST-REPORT.md](TEST-REPORT.md) — recorded verification and evidence limits.
- [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) — reference-alpha release conditions.
- [LICENSE](LICENSE), [NOTICE](NOTICE) and [TRADEMARKS.md](TRADEMARKS.md) — license, attribution and branding.

## Run the tests

The reference implementation uses Python's standard library. The recorded CI
run used Python 3.12.3 on Linux. Run these commands from the repository root:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests tools
```

The process regressions target Unix. Report skipped tests as skipped; a skip
is not PASS. The CI reference job rejects any skipped test or an empty suite.

The separate 24-case Unix harness requires Linux credential-switch authority.
Follow [CODEX-UNIX-TESTS.md](CODEX-UNIX-TESTS.md) to run it in a disposable fixture.
If credential switching is unavailable, it records **UNVERIFIED** and exits 2.

## Trust model

The integrating trusted host owns:

- the HMAC receipt key;
- frozen task/state/requirement bindings;
- verifier selection and execution;
- revocation and current-state probes;
- the gated effect callback.

Candidate code and implementation workers must not receive those authorities. There is intentionally no evidence-submission or PASS-override API for candidate code.

An integrating host must serialize relevant state/revocation changes with the complete gated effect and preserve receipt history. See [the trusted-host integration contract](HOST-CONTRACT.md) for the tested locking pattern and its limits.

## Integration

Other systems may integrate NARF. That dependency is one-way: an integration may depend on NARF, but NARF does not depend on the integrating system.

## Integration limits

- The trusted host must keep the receipt key, store and relevant parent
  directories outside untrusted-worker authority. HMAC authenticates receipt
  contents; filesystem permissions or another enforced boundary provide
  access control.
- Relevant state and revocation changes must share the host's authority lock
  or transaction with the complete synchronous `execute_effect` call.
  Effect inputs must remain bound to the approved task/candidate.
- The host must preserve consumption history. Receipt authentication alone
  does not prevent deletion or restoration of an older valid store.
- Consumption is reserved before callback invocation. An exception may leave
  the effect consumed without completing the external action. The guarantee
  is at-most-once callback invocation under the documented contract;
  exactly-once external completion requires additional host design.
- The recorded Unix fixture does not certify an integrating application's
  production sandbox, deployment or remote-target durability.

Read [HOST-CONTRACT.md](HOST-CONTRACT.md) before integrating an effect.
NARF's reference-test PASS applies to the measured scope.

## License and attribution

The source code is licensed under the Apache License, Version 2.0. See `LICENSE`.

Redistributions and derivative works must preserve the applicable attribution from `NOTICE` as required by Apache-2.0. The project attribution is:

```text
This software includes software originally developed as MGNARF Ändi.
```

The Apache license does not grant permission to present a modified version as the official NARF, MGNARF, or MGNARF Ändi project. See `TRADEMARKS.md` for the project name and branding policy.

> PINKY: Did the checks actually run?  
> BRAIN: Yes. Keep the evidence, and keep the unverified boundaries visible.
