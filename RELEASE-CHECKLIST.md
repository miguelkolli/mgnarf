# MGnarf release checklist

This checklist is the generic release gate for a new MGnarf prerelease or stable release.

It is intentionally version-neutral. Historical release documents remain evidence of the exact versions they describe and must not be rewritten to make a newer release look as if it had always contained later features.

## 1. Freeze the intended scope

Before creating a tag or GitHub release:

- [ ] Choose the release version and whether it is prerelease or stable.
- [ ] Write the release scope in a release-specific document.
- [ ] List the public APIs and security semantics included in the release.
- [ ] List retained limitations and explicitly `UNVERIFIED` boundaries.
- [ ] Confirm the release does not claim certification, universal safety, or production guarantees beyond measured evidence.
- [ ] Record the exact candidate SHA that is being evaluated.

If the release contains new public APIs, new trust assumptions, or changed effect/authority semantics, treat that as a security-relevant release even if the implementation diff is small.

## 2. Candidate SHA is immutable during evaluation

The acceptance evidence belongs to one exact candidate SHA.

- [ ] Record `git rev-parse HEAD`.
- [ ] Confirm the candidate branch/worktree is clean.
- [ ] Do not amend, rebase, force-push or otherwise replace the candidate while evidence is being collected.
- [ ] If any code, test, workflow, release document, or security-relevant configuration changes, assign a new SHA and restart the applicable acceptance gate.

A PASS for SHA A is not evidence for SHA B.

## 3. Required repository tests

Run the full repository suite on the exact candidate SHA:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 -m compileall -q src tests tools
```

Required result:

- [ ] test count is recorded;
- [ ] 0 failures;
- [ ] 0 errors;
- [ ] 0 skips;
- [ ] compileall succeeds;
- [ ] no test or verifier was weakened, removed, bypassed, or relabeled merely to obtain green output.

The release-specific report must state the exact counts rather than only saying "tests passed".

## 4. Required GitHub Actions evidence

For the exact candidate SHA:

- [ ] Every currently configured required boundary/regression workflow applicable to the release has completed.
- [ ] No applicable workflow is queued or in progress when the release decision is made.
- [ ] No applicable workflow concluded failure, cancelled, or unexpectedly skipped.
- [ ] The exact workflow count and names are recorded in the release evidence.
- [ ] Important job-level evidence is inspected where a workflow intentionally mixes protected cases and limitation witnesses.

A limitation-witness workflow succeeding means the documented limitation reproduced as expected. It does **not** convert that limitation into a security guarantee.

## 5. Adversarial and whole-chain review

A release that changes public security behavior must receive an adversarial review of the combined candidate, not only unit tests for each isolated feature.

At minimum:

- [ ] Attempt downgrade to an older/weaker API path.
- [ ] Attempt replay across contract/session/operation boundaries.
- [ ] Attempt state, identity, authority, profile, operation, and effect binding drift where applicable.
- [ ] Attempt direct-effect or convenience-wrapper bypass where stronger paths are meant to be mandatory.
- [ ] Attempt malformed, missing, stale and authenticated-but-mismatched evidence.
- [ ] Exercise concurrency/race boundaries relevant to the changed feature.
- [ ] Exercise persistence/rollback behavior relevant to the claimed threat model.
- [ ] Verify ambiguity and crash outcomes fail closed rather than silently freeing authority for blind retry.
- [ ] Record blocking, non-blocking and unverified findings separately.

If a blocking finding is fixed, the corrected SHA becomes the new candidate and the applicable evidence must be rerun.

## 6. Integration and trust-boundary review

Before stable release, inspect the full protected path from candidate input to real effect.

- [ ] Candidate/worker-controlled data cannot manufacture trusted identity, authority, verifier or fence facts.
- [ ] Protected credentials live on the trusted-host / enforcing-target side.
- [ ] Required serialization/locks/transactions are part of the actual effect path, not merely documentation.
- [ ] Stable operation identity is preserved across retries/new contracts where semantic at-most-once behavior is claimed.
- [ ] External consumption/fencing authorities meet the stated persistence and rollback threat model.
- [ ] Any resource-enforced claim is limited to targets that actually validate the authority/fence at commit.
- [ ] Privileged owner/admin rollback or equivalent out-of-bound authority is documented where it remains a limitation.

A generic client-side recheck is not evidence that an arbitrary external resource enforces a final commit-time boundary.

## 7. Documentation consistency

- [ ] `README.md` describes the release status correctly.
- [ ] `OVERVIEW.md`, `NARF-SPEC.md`, `ARCHITECTURE.md`, `HOST-CONTRACT.md` and applicable boundary documents agree on the security model.
- [ ] `HARDENED-PATHS.md` does not present stronger paths as universal guarantees.
- [ ] Release notes distinguish measured guarantees from retained limitations.
- [ ] Historical release/test documents are not silently rewritten.
- [ ] Public API exports and documentation match the code actually being released.
- [ ] Installation/integration examples use the intended hardened path rather than accidentally demonstrating a weaker bypass route.

## 8. Legal and repository hygiene

- [ ] `LICENSE` is present and unchanged unless the release intentionally changes licensing.
- [ ] `NOTICE` remains accurate.
- [ ] `TRADEMARKS.md` remains consistent with public naming.
- [ ] No secrets, credentials, private customer data or private MGSystem material are included.
- [ ] No generated caches, temporary evidence, local paths or unrelated artifacts are committed.
- [ ] `git status` is clean for the frozen candidate.

## 9. Release-specific evidence document

Create a release-specific report that records at minimum:

```text
version / release type
candidate SHA
previous stable tag + SHA
scope summary
public API/security changes
unit-test count / failures / errors / skips
compile result
required workflow results
adversarial findings and fixes
measured protected cases
LIMITATION_CONFIRMED cases
UNVERIFIED boundaries
final release decision
```

Do not use `PASS` for an unexecuted boundary.

## 10. Freeze merge and exact-main revalidation

When the release candidate is approved for freeze:

- [ ] Merge the release-freeze change with an exact expected-head SHA guard.
- [ ] Record the resulting exact `main` SHA.
- [ ] Wait for the push-triggered workflows on that exact `main` SHA.
- [ ] Require all applicable push workflows to complete successfully again.
- [ ] Reconfirm the release notes/test report point to the exact SHA that will be tagged.

PR-head green status is not a substitute for final exact-main push evidence.

## 11. Tag and GitHub release

Only after the exact-main release gate is green:

- [ ] Create the release tag on the exact verified freeze SHA.
- [ ] Never retarget or reuse an immutable historical tag.
- [ ] Create the GitHub release from that exact tag.
- [ ] For a stable release, ensure it is not marked prerelease.
- [ ] Verify the release/tag is immutable according to the repository's release policy/tooling.
- [ ] Verify title, notes and evidence links identify the same version and SHA.

If the published artifact points to a different SHA than the accepted candidate, the release is not accepted.

## 12. Stable-release decision

A stable release may be called **PASS** only when all required gates above are backed by executed evidence for the exact frozen revision.

Otherwise use one of:

- **FAIL** — a demonstrated release/security requirement is violated;
- **BLOCKED** — required authority, infrastructure or prerequisite is unavailable;
- **UNVERIFIED** — the requested property has not been measured or cannot be established with the available boundary.

A stable MGnarf release is a measured reference implementation and security boundary, not an independent security certification or a promise that every third-party deployment inherits the same guarantees.
