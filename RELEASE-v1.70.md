# v1.70 — hardened execution paths candidate

Status: **CANDIDATE SCOPE FREEZE — NOT YET RELEASED**

`v1.70` is the proposed next stable capability release after immutable `v1.61`.
It is intentionally not treated as a patch: the candidate line adds new public
security APIs and new authority/effect semantics.

Previous stable release:

```text
v1.61
30b7d0def802c3e7256e8aca2bbdc025df972721
```

Initial development anchor for this candidate cycle:

```text
0063c66f144dc7eb8031eb235f8072a7982d5db3
```

The exact evaluation SHA for release acceptance must be recorded in the release
PR/test report. Any code, test, workflow or security-relevant documentation
change after that point creates a new candidate SHA and restarts the applicable
gate. Pull-request evidence is candidate evidence only; the final stable release
still requires fresh push-triggered revalidation on the exact resulting `main`
SHA under `RELEASE-CHECKLIST.md`.

## Scope

The proposed v1.70 stable scope is the combined hardened candidate line:

1. **Identity-bound separation of duties**
   - `principal_id`, `trust_domain`, and optional `verifier_profile` remain
     distinct from logical `verifier_id`;
   - trusted host owns provenance;
   - candidate/worker self-asserted identity cannot manufacture trusted facts;
   - observed identity/profile drift permanently stales existing authorization.

2. **Monotonic authority revision**
   - `AuthorityRevisionGate` binds identity-enabled contracts to one trusted-host
     monotonic revision;
   - authority change-and-restore remains visible when the revision advances;
   - rollback resistance of that revision remains part of the authority threat
     model.

3. **Stable operation identity and composed execution**
   - `OperationBoundGate(..., authority_probe=...)` binds one host-owned semantic
     operation across fresh contracts/retries;
   - composed sessions require the guarded executor path;
   - ambiguous reservation outcomes remain consumed rather than automatically
     retried.

4. **Fenced effect transport**
   - `FencedOperationGate`, `FencedOperationEffectExecutor`, `FenceToken`, and
     `FencedEffectBinding` bind fence scope, operation, revision, effect and
     fencing-authority identity;
   - stable operation reservation occurs before fence issuance;
   - direct/non-fenced effect routes are rejected for fenced sessions;
   - token transport alone is not claimed as universal external commit fencing.

5. **PostgreSQL Layer C reference**
   - `PostgresFencingAuthority`, `PostgresFenceControlPlane`, and
     `PostgresFencedTarget` use DB-owned `SECURITY DEFINER` functions;
   - authority transition, fence issuance and target commit serialize in the same
     PostgreSQL scope-lock domain;
   - runtime roles use narrow function `EXECUTE` authority rather than direct DML
     over critical fencing/effect state;
   - the measured claim applies only to the tested PostgreSQL function/role/
     transaction model.

6. **Authenticated stage ordering**
   - ordered contracts use evidence v3 and freeze an exact `requirement_id`
     permutation rather than relying on verifier-role names or timestamps;
   - the first stage binds to a session/contract-owned chain seed and every later
     stage binds to the authenticated predecessor receipt ID and canonical digest;
   - a future stage is rejected before its verifier producer can run;
   - same-stage concurrency and same-thread re-entrancy are admitted at most once;
   - the final PASS decision binds to the final authenticated chain head;
   - authority-revision, stable-operation and fenced-operation wrappers preserve
     the ordered contract without silent downgrade;
   - legacy v1/v2 behavior remains available when stage ordering is not configured.

## Fresh v1.70 whole-chain acceptance gate

The release candidate adds a fresh combined adversarial suite rather than relying
only on the isolated development tests. The whole-chain suite must execute all
13 protected cases on the exact candidate SHA:

1. current identity/revision/state reaches one fenced effect;
2. fenced contract cannot downgrade into the weaker operation-binding v1 path;
3. fenced session cannot call direct effect entry;
4. authority revision drift blocks before stable-operation reservation;
5. observed identity drift cannot resurrect after restoration;
6. one semantic operation cannot execute again through a fresh contract;
7. wrong fencing authority is rejected before operation reservation;
8. malformed fence after reservation leaves operation consumed and effect absent;
9. state drift after PASS blocks before operation reservation;
10. effect/fence-scope goalpost drift is rejected before verification;
11. an ordered v3 identity/revision/fenced chain reaches exactly one effect;
12. a future ordered stage is rejected before its producer until its predecessor exists;
13. authority revision drift after the first ordered receipt blocks the next stage before producer/effect entry.

Required result:

```text
13 tests
0 failures
0 errors
0 skips
13 protected cases
```

This fresh whole-chain gate complements, rather than replaces, the existing
repository workflows. In particular, PostgreSQL commit-time fencing remains
measured by the dedicated live PostgreSQL workflow, and the broader stage-order
Revision 3 adversarial suite remains part of the full repository regression set.

## Required release evidence

Before stable publication, the exact v1.70 candidate must satisfy
`RELEASE-CHECKLIST.md`, including:

- full repository unit suite with exact test count and zero skips;
- compileall success;
- every applicable GitHub Actions workflow completed successfully on the exact
  candidate SHA;
- fresh v1.70 whole-chain adversarial workflow success with all 13 protected cases;
- authenticated stage-order Revision 3 adversarial coverage success;
- live PostgreSQL fenced-target boundary success;
- recorded protected, `LIMITATION_CONFIRMED`, and `UNVERIFIED` cases;
- release-specific test report bound to the exact evaluated SHA;
- final freeze merge with expected-head protection;
- complete push-triggered revalidation on the exact resulting `main` SHA;
- only then immutable tag and stable GitHub release publication.

## Retained limitations / non-claims

v1.70 does **not** claim any of the following:

- independent security certification;
- correctness of verifier domain logic;
- proof that differently named principals/profiles are administratively or
  epistemically independent in the real world;
- protection from a malicious trusted host that deliberately abandons the
  documented hardened API path;
- rollback resistance when every preserving authority domain is rolled back
  together;
- exactly-once remote completion after an ambiguous or failed effect;
- universal fencing/TOCTOU protection for arbitrary HTTP APIs, cloud providers,
  databases or devices;
- PostgreSQL Layer C protection against a privileged function/schema owner or
  administrator that can rewrite authoritative state;
- backup/restore, failover, physical-power-loss or production administration
  guarantees unless separately enforced and tested.

A green limitation witness means that a documented limitation reproduced as
expected. It is not converted into a security PASS.

## Candidate decision

At this scope refreeze:

```text
VERSION:             v1.70
RELEASE TYPE:        proposed stable capability release
SCOPE:               FROZEN FOR CANDIDATE REVIEW
INITIAL ANCHOR:      0063c66f144dc7eb8031eb235f8072a7982d5db3
EXACT CANDIDATE SHA: TO BE RECORDED AFTER THIS FREEZE COMMIT
WHOLE-CHAIN REVIEW:  13 PROTECTED CASES REQUIRED
FINAL RELEASE GATE:  UNVERIFIED
TAG/RELEASE:         NOT CREATED
```

Do not publish `v1.70` until the exact-candidate review, release-specific test
report, freeze merge and exact-main push gate have all completed.
