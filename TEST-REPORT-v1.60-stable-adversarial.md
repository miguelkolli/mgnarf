# v1.60 stable adversarial test report

## Scope

This report records the fresh post-hardening adversarial/stabilization pass run before the `v1.60` stable freeze.

The pass targeted the merged post-RC2 hardening code, not historical RC1/RC2 source. It was added as a tests-only change in PR #35.

Evidence provenance remains deliberately limited: this is same-project/self-adversarial evidence produced inside the project workflow. It is **not** an independent third-party security review or certification.

## Bound source

Post-hardening base before the attack-test commit:

```text
047601acac2ceb72eb3af4cb5fa8eaa363dd880b
```

Tests-only adversarial PR head:

```text
450133dc4f63f5a9c1b974adc25e29848777bba8
```

Merged post-adversarial `main`:

```text
56d394f35fb31626063eb41aa1f8b48a24f15c96
```

PR #35 changed only `tests/test_stable_adversarial.py` and contained one commit.

## Fresh adversarial probes

Eight new probes were added without changing runtime, verifier logic, policy or release logic:

1. A revocation authority that changes from exact `False` to `None` after finalized PASS must block effect entry.
2. Falsey non-boolean revocation values (`None`, `0`, empty string, empty list, empty dict) must all fail closed.
3. A post-PASS inhibitor must stale the authenticated decision and prevent callback entry.
4. An inhibitor cannot be added retroactively after an effect has already been consumed.
5. The file-publication boundary must observe the complete frozen temporary payload while the final target is still absent.
6. Atomic publication failure must expose no final target, leak no temporary file, and leave authorization consumed.
7. A pre-existing final target must never be overwritten and retry remains consumed.
8. A directory-sync acknowledgement fault after atomic publication is characterized as ambiguous completion: a visible target may exist, but if present it must contain the complete frozen payload, never partial bytes; retry remains consumed.

## PR-head evidence

On PR head `450133dc4f63f5a9c1b974adc25e29848777bba8`:

- all eight `test_stable_adversarial` cases were discovered and reported `ok` in the core job log;
- core suite: **98 tests, 0 failures, 0 errors, 0 skips**;
- core check: `Core reference tests (no skips)` SUCCESS, job `114770578117`, workflow run `38237167284`;
- aggregate: `Reference tests (no skips)` SUCCESS, check `114770776591`;
- the observed 20-check matrix contained no failure, cancelled or skipped conclusion.

## Merged-main evidence

On exact merged `main` `56d394f35fb31626063eb41aa1f8b48a24f15c96`:

- all eight stable-adversarial cases again reported `ok`;
- core suite: **98 tests, 0 failures, 0 errors, 0 skips**;
- core check: `Core reference tests (no skips)` SUCCESS, job `114770959178`, workflow run `38237283306`;
- core evidence artifact: ID `11740847815`, recorded artifact SHA-256 `248e01c9b63f1f48690b13532a6e0d4fce5c1b3bc7d99f80bfcefeb33e6f4794`;
- aggregate: `Reference tests (no skips)` SUCCESS, check `114771198404`;
- the observed 20-check matrix contained no failure, cancelled or skipped conclusion.

## Result

**No new stable-blocking invariant violation was reproduced inside this eight-probe scope.**

That statement is scoped evidence, not a claim that no vulnerability exists.

The directory-sync fault probe intentionally confirms an existing availability/completion boundary: if atomic target publication succeeds but the subsequent directory-sync acknowledgement fails, the callback can report failure while the complete target already exists. Authorization remains consumed. MgNarf therefore does not claim exactly-once external completion.

## Stable interpretation

Within the measured reference boundary, the three post-RC2 hardening items remained fail-closed under the fresh probes:

- post-PASS inhibition prevents effect entry;
- configured revocation authority uncertainty does not become permission;
- final file publication does not expose partial target bytes in the tested publication-fault paths.

Existing limitations remain limitations. In particular, this pass does not certify arbitrary production sandboxing, independent control planes, physical power-loss behavior, privileged rollback of every preserving authority, arbitrary resolver/transport behavior, bind-mount aliasing or remote-target semantics.

The stable release must preserve these limitations in its release notes and must still be created only from the exact freeze SHA whose required aggregate reference gate succeeds.
