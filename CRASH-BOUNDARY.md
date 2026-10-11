# Crash / persistence boundary

This harness measures one narrow durability property of the NARF reference gate: what happens when the trusted host process exits abruptly after the effect authorization has been durably reserved.

## Why this matters

`execute_effect()` persists the deterministic effect-consumption receipt before invoking the external callback. That ordering intentionally prefers safety over availability.

If the process dies after reservation but before the external action completes, the authorization remains consumed. A later process must not invoke the callback again just because the first process failed to finish.

## Measured cases

`tools/test_crash_boundary.py` runs two fresh-process cases:

1. **Crash before target write** — the child exits at the start of the callback. The consumption receipt exists, the external target does not, and a fresh session is denied replay.
2. **Crash after durable target write** — the child writes and fsyncs the target, then exits before returning. The consumption receipt exists, the target exists once, and a fresh session is denied replay.

In both cases the replay callback has its own marker. PASS requires that marker to remain absent, proving the second process did not enter the external callback.

## Guarantee demonstrated

The measured claim is **at-most-once callback invocation across ordinary host-process exit**, given the reference filesystem persistence path completes before the crash.

This is not an exactly-once guarantee. In the first case the authorization is consumed even though the external effect never completed.

## Still unverified

This harness does not establish:

- physical power-loss durability;
- storage-controller or filesystem behavior outside the measured runner;
- rollback-resistant authority after restoring an older host snapshot;
- exactly-once remote completion or acknowledgement;
- distributed fencing across machines.

Those boundaries must remain visible and must not be relabeled PASS by this harness.
