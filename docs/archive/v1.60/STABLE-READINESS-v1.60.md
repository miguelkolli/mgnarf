# v1.60 stable-readiness review

This document records the post-RC2 semantic review that must complete before a stable `v1.60` release is frozen.

Stable is not inferred from an RC2 publication. The candidate still has to pass the repository's exact-SHA reference gate and a fresh adversarial/stabilization cycle after these changes.

## Review base

The review started from merged `main` commit:

```text
fbbe871461d490aed2e76e8a2c62fe39fc1c59ac
```

That exact commit had a successful `Reference tests (no skips)` aggregate before this hardening work began.

## Post-RC2 findings reviewed

### 1. Inhibitor after finalized PASS

**Finding:** confirmed semantic mismatch.

The specification says an inhibitor prevents PASS or effect, but the RC2 session API rejected `inhibit()` after `finalize()`. That left a window where a host could have a newly established stop condition after PASS finalization but before effect consumption and could not represent it through the inhibitor API.

**Hardening:** `inhibit()` remains available until effect consumption. A post-finalization inhibitor makes the authenticated PASS stale because effect execution reevaluates the current inhibitor state. Adding an inhibitor after effect consumption is rejected because it cannot retroactively undo an executed effect.

**Regression:** a finalized PASS followed by `inhibit("human_stop")` must block effect entry and execute zero callbacks.

### 2. Non-boolean revocation probe result

**Finding:** confirmed fail-closed gap.

RC2 treated a configured revocation probe returning `None` as equivalent to a clear non-revoked result. A configured probe that cannot provide a definite answer is authority uncertainty and must not manufacture permission.

**Hardening:** for a configured revocation probe, only the exact boolean `False` is clear. `True`, exceptions, and non-boolean results fail closed as revoked/unavailable authority.

**Regression:** a configured probe returning `None` must produce `BLOCKED / REVOKED`.

### 3. Reference-host final target publication

**Finding:** confirmed host-integration durability issue.

RC2 `TrustedFileHost` opened the final target name before writing the payload. A write/fsync failure could therefore leave a partial final target even though the gated effect failed.

**Hardening:** the host now writes the complete frozen payload to a unique host-owned temporary file in the same directory, flushes and fsyncs it, and only then publishes the final name with an atomic hard link. The final target therefore does not appear until complete bytes have been prepared. The hard link also preserves the historical no-overwrite behavior because publication fails if the target already exists.

**Regression:** a fault at the atomic publication step must leave no final target and no leaked temporary file.

## Payload identity decision

The RC2 red-team report also asked whether `TrustedFileHost` payload identity should become a new core locked task/effect field.

That is **not silently promoted into the v1.60 core contract in this hardening patch**.

The current reference host detaches the supplied payload into immutable `bytes` before the contract/session is opened, and the gated callback is host-owned. Candidate or worker code is not given a mutation route to that frozen callback input. Promoting an effect-input digest into the authenticated core contract would change the contract/evidence schema rather than merely close the three reproduced semantic gaps above.

For v1.60, this remains an explicit trust-boundary rule: integrations that require independent semantic binding of external effect input must include that identity in their frozen task/state/host contract. The reference implementation does not claim a universal effect-payload schema.

## Boundaries that remain explicit

This review does not convert existing limitations into security guarantees:

- the filesystem receipt store is not rollback resistant by itself;
- replay can return if every preserving external authority history is rolled back together;
- durable reservation may intentionally burn authorization when later state changes or callback execution fails;
- consumed authorization does not prove exactly-once remote completion;
- production-host isolation and control-plane independence are deployment responsibilities;
- physical-power-loss/fsync fault behavior is not certified beyond the measured fixtures;
- arbitrary resolver/transport deadline behavior, bind-mount aliasing, and remote-target semantics remain outside the measured reference boundary;
- the project has not received an independent external security certification.

## Stable gate still required

Before `v1.60` stable may be published:

1. this hardening must be one scoped commit merged through a green exact-head PR gate;
2. the exact merged `main` SHA must complete `Reference tests (no skips)` successfully;
3. a fresh adversarial/stabilization pass must target the post-hardening code, not RC1/RC2 history;
4. any new reproduced stable-blocking finding must be fixed and re-gated, or stable must stop;
5. stable release notes must preserve the remaining known boundaries and evidence provenance;
6. the stable release must be created from the exact verified freeze SHA and must be immutable.

Until those steps complete, the project remains on the `v1.60 RC2` track rather than stable.
