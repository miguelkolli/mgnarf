# Reference trusted-host integration

This example is the next step after the standalone gate tests: it wires NARF to
a concrete host-owned filesystem effect.

The implementation lives in `src/narf/reference_host.py`. It intentionally keeps
the trust boundary simple:

- the host owns the receipt key and receipt directory;
- the host freezes the task, candidate, requirements, policy and effect payload;
- verifier callbacks are supplied on the trusted-host side;
- the effect target and bytes are captured before verification;
- authority mutations and the complete `execute_effect()` call share the same
  host lock;
- the gated effect is a real exclusive file creation followed by file and
  directory `fsync`;
- revocation or candidate drift after PASS prevents the file write;
- replaying the same effect is rejected.

Run it with the normal repository suite:

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests tools
```

## What this demonstrates

This is stronger than a callback-only toy example because the accepted effect
changes the filesystem and the test asserts that rejected or stale authority
does not create the target file.

It also demonstrates immutable effect input: mutating the caller-owned payload
after `prepare()` does not change the bytes written by the accepted effect.

## What this does not prove

This adapter is deliberately **single-process**. Its `threading.RLock` is not a
multi-process or distributed authority lock.

It does not prove:

- isolation from an attacker running with the trusted host's OS identity;
- a production sandbox;
- multi-process or cross-machine serialization;
- rollback-resistant receipt history;
- physical power-loss recovery;
- exactly-once completion of an external service action.

Those boundaries remain **UNVERIFIED**. See `HOST-CONTRACT.md` before adapting
the pattern to a production host.

The purpose of this integration is evidence-driven progression: first prove a
real host-owned effect under the documented contract, then move the authority
boundary into a separate process / OS identity and test that boundary directly.
