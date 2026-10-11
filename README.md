# NARF

NARF is a standalone fail-closed acceptance gate for AI-assisted and automated work.

It has no required parent framework, workspace variable, private repository, external governance system, or project harness. The reference implementation uses only the Python standard library.

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

- `NARF-SPEC.md` — behavioral specification.
- `INDEPENDENCE.md` — standalone/dependency boundary.
- `ARCHITECTURE.md` — reference architecture and trust boundary.
- `HOST-CONTRACT.md` — host locking, immutable effect input, receipt-history protection and persistence obligations.
- `src/narf/gate.py` — Python reference implementation.
- `tests/test_gate.py` — positive and adversarial fail-closed tests.
- `LICENSE` — Apache License, Version 2.0.
- `NOTICE` — required project attribution notice.
- `TRADEMARKS.md` — project name and branding policy.

## Run the tests

Python 3 is the only runtime requirement for the reference implementation.

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
```

No external harness is required for these commands.

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

## Status

This repository contains a reference implementation and adversarial unit tests. A standalone unit-test result is not, by itself, a production-readiness or external end-to-end certification claim.

## License and attribution

The source code is licensed under the Apache License, Version 2.0. See `LICENSE`.

Redistributions and derivative works must preserve the applicable attribution from `NOTICE` as required by Apache-2.0. The project attribution is:

```text
This software includes software originally developed as MGNARF Ändi.
```

The Apache license does not grant permission to present a modified version as the official NARF, MGNARF, or MGNARF Ändi project. See `TRADEMARKS.md` for the project name and branding policy.
