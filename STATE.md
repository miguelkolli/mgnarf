# NARF — STATE

STATE = NOW.

## PROJECT

PROJECT STATUS: FOUNDATION

The repository now contains a standalone NARF specification, Python reference
implementation, and adversarial/fail-closed unit tests.

Local standalone verification during the extraction task observed:

- `PYTHONPATH=src python3 -m unittest discover -s tests -v` → 17 tests OK
- `python3 -m compileall -q src tests` → OK

MGSystem canonical Git-baseline/shared-harness verification was not available in
the remote GitHub execution environment and is therefore UNVERIFIED.

No public release, deployment, production verification, external end-to-end NARF
PASS, or license selection is claimed yet.

## NOT HERE

Do not store secrets, task history, roadmaps, or speculative future design here.
