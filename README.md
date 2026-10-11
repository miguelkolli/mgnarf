# NARF

NARF is a fail-closed acceptance gate for AI-assisted and automated work.

The core rule is simple:

```text
PASS only when the exact frozen task/candidate has complete authenticated
verifier evidence, every required verifier passes, relevant state is unchanged,
no inhibitor/revocation exists, and the state is revalidated immediately before
the gated effect.
```

A useful shorthand is:

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

## What is here

- `NARF-SPEC.md` — standalone behavioral contract.
- `src/narf/gate.py` — standard-library reference implementation.
- `tests/test_gate.py` — positive and adversarial/fail-closed tests.
- MGSystem repository governance files used while this project is developed.

## Trust model

NARF assumes a trusted host owns:

- the HMAC receipt key;
- the frozen task/state/requirement bindings;
- verifier selection and execution;
- revocation and current-state probes;
- the privileged/gated effect callback.

Candidate code and implementation workers must not receive those authorities.
There is intentionally no `submit_evidence()` or PASS-override API.

## Run the reference tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
```

## Provenance

The standalone model was extracted from the NARF v3 semantics in the private
MGSystem runtime at source commit
`817e694fedbae8dc749fbbfcf271cf1fa93f1881`.

It is not a byte-for-byte copy: MGSystem-specific Task Freeze, lifecycle,
analytics, deployment, host paths, and private runtime dependencies are excluded.
The standalone boundary keeps the fail-closed acceptance and pre-effect
revalidation model while making host integration explicit through callbacks and
digests.

## Status

This repository is still in foundation/reference-implementation stage. Local
standalone tests may verify the code in a working checkout, but that is not the
same claim as MGSystem shared-harness, deployment, production, or external
end-to-end NARF verification.

No public release or production-readiness claim is made yet.

## License

No license has been selected yet. Do not treat repository visibility as a grant
of reuse rights until a license is explicitly added.
