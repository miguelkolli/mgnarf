# Next release readiness

Status: **PRE-RELEASE RECON — NOT YET FROZEN**

This document is a version-neutral readiness snapshot for the development on `main` after the immutable v1.61 stable release. It is not release notes, not a tag decision, and not a PASS for a future release.

## Recon anchors

Previous immutable stable release:

```text
v1.61
30b7d0def802c3e7256e8aca2bbdc025df972721
```

Development recon anchor before this readiness-document update:

```text
aff0b4062b96ad0a7ba285dcc01ab4f9c2feebc9
```

At that anchor, `main` was 11 commits ahead of `v1.61` and 0 commits behind it. The change set is substantial enough that the next version should be chosen deliberately; this document does not assume that it is merely a patch release.

## Current exact-main evidence at recon anchor

For `aff0b4062b96ad0a7ba285dcc01ab4f9c2feebc9`:

- push-triggered workflow collection: **12 completed / 12 success**;
- repository core suite: **191 tests**;
- failures: **0**;
- errors: **0**;
- skips: **0**;
- compileall: **PASS**;
- PostgreSQL fenced-target workflow: **success** on the same main SHA.

This evidence supports the current development state. It does not by itself freeze or publish a new release.

## Major public/security changes since v1.61

The post-v1.61 development line adds materially new security paths and public API surface.

### Identity-bound separation of duties

- principal identity is distinct from logical verifier identity;
- trust domain is modeled separately from principal identity;
- optional verifier profile allows policy to distinguish verification methods/failure modes;
- trusted host owns identity provenance;
- candidate/worker self-asserted identity cannot create trusted identity;
- observed identity/profile drift permanently stales the existing authorization rather than allowing an old PASS to resurrect after values are restored.

### Monotonic authority revision

- identity-enabled contracts can bind to a trusted-host monotonic authority revision;
- identity authority change-and-restore between ordinary snapshots remains visible when the revision advances correctly;
- revision rollback remains part of the authority's deployment threat model.

### Stable operation composition

- a stable host-owned `operation_id` can represent one semantic real-world operation across newly frozen contracts/retries;
- the stronger composed operation path combines identity/revision checks with external single-use consumption authority;
- hardened sessions require the guarded executor path rather than silently bypassing stable-operation reservation.

### Fenced-effect transport

- `fence_scope_id` is distinct from semantic `operation_id`;
- fencing authority identity is frozen before verification;
- stable operation reservation occurs before fence issuance;
- fence evidence binds scope, operation, authority revision, effect and sequence;
- fenced sessions block normal direct/non-fenced effect routes;
- token transport alone is explicitly not called universal external commit enforcement.

### PostgreSQL Layer C commit boundary

A concrete reference target now demonstrates commit-time fencing in one measured PostgreSQL configuration:

- DB-owned `SECURITY DEFINER` functions own fence issuance, authority transition and fenced effect commit;
- issuer/control/target runtime roles are separated by function EXECUTE authority;
- direct DML over critical fencing/effect state is denied to those runtime roles;
- the CI harness actively probes the role/function privilege boundary;
- authority transition that commits before the target commit invalidates the older fence even when no newer effect/fence is issued;
- newer fence sequence supersedes older fence in the same scope;
- privileged function/schema owner or administrator rollback remains `LIMITATION_CONFIRMED` rather than being relabeled as protected.

## Important retained boundaries

The current development line still depends on explicit trust assumptions.

- The trusted host remains inside the trust boundary. Python object privacy is not a sandbox against a malicious trusted host running arbitrary code in-process.
- Identity/profile correctness depends on host-authenticated provenance; names alone do not prove real-world independence.
- Monotonic authority revision is only as rollback-resistant and complete as the host authority that advances it.
- Stable-operation consumption may intentionally sacrifice availability after ambiguous failures rather than automatically retrying a possibly-consumed real-world effect.
- Generic fenced-effect transport does not prove that arbitrary HTTP APIs, cloud providers, databases or devices enforce a fence at their own commit boundary.
- The stronger PostgreSQL Layer C claim applies only to the tested database functions, role grants, transaction/advisory-lock behavior, function owner and adapter model.
- A privileged PostgreSQL function/schema owner or administrator that rewrites authoritative fencing state can defeat the measured Layer C guarantee.
- Backup/restore, failover and administrative rollback require their own deployment threat model if they are meant to be covered.
- Independent third-party security certification has not been performed.

## Why this is not release-ready yet

The development evidence is strong enough to begin a release freeze, but the next stable release has **not** completed the release-specific acceptance process.

Before declaring the next stable candidate ready, complete at minimum:

1. **Choose the release version and scope explicitly.**
   The change set contains new public APIs/security semantics and should not inherit a version number by habit.

2. **Run a fresh whole-chain adversarial review on one exact candidate SHA.**
   The individual features have been attacked during development, but the combined post-v1.61 candidate must be reviewed as one untrusted system: downgrade paths, cross-layer replay, authority/identity/fence drift, convenience-wrapper bypass, crash/ambiguity and concurrency boundaries.

3. **Create release-specific freeze/release notes and a test report.**
   They must bind the selected scope and all evidence to one exact candidate SHA and list every retained `LIMITATION_CONFIRMED` / `UNVERIFIED` boundary.

4. **Freeze the candidate and rerun the complete gate.**
   Full unit suite, compile, all applicable workflows and required adversarial fixtures must pass on the exact freeze SHA. Any correction creates a new candidate SHA.

5. **Merge the freeze with an expected-head guard and verify exact `main` again.**
   Push-triggered workflows on the resulting main SHA must be green before tag creation.

6. **Only then create an immutable tag/release.**
   The tag must point to the exact verified freeze SHA and historical tags must never be retargeted.

## Current readiness verdict

```text
RELEASE SCOPE:       NOT YET SELECTED
VERSION:             NOT YET SELECTED
CANDIDATE SHA:       NOT YET FROZEN
CURRENT DEV CI:      PASS at recon anchor aff0b406...
WHOLE-CHAIN REVIEW:  REQUIRED FOR NEXT RELEASE
RELEASE REPORT:      REQUIRED
FINAL RELEASE GATE:  UNVERIFIED
```

Therefore:

> **NEXT STABLE RELEASE: NOT YET FROZEN / UNVERIFIED**

This is not a failure of the current code. It means the development line has advanced enough that the next release deserves its own exact-SHA acceptance cycle rather than inheriting v1.61 evidence.

## Next gate

The next release task should begin with one explicit candidate scope and version decision, then freeze one exact SHA for a fresh combined adversarial review. Do not tag or publish before that review and its exact-main revalidation are complete.
