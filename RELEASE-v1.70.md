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

The pre-documentation release-branch candidate measured for this freeze was:

```text
c4ec748822ca3acacb7ce3fd14ffbc881c55baa0
```

Its evidence is recorded in [TEST-REPORT-v1.70.md](TEST-REPORT-v1.70.md).
The documentation/refreeze change containing this file necessarily receives a
new Git SHA and must be freshly revalidated. No PASS is inherited across that
SHA change. Final stable publication still requires fresh push-triggered
revalidation on the exact resulting `main` SHA under `RELEASE-CHECKLIST.md`.

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

The same exact-head release workflow also requires the complete repository suite
and compilation:

```text
237 tests
0 failures
0 errors
0 skips
compileall src tests tools: PASS
```

This gate complements, rather than replaces, the existing repository workflows.
PostgreSQL commit-time fencing remains measured by the dedicated live PostgreSQL
workflow, and the broader stage-order Revision 3 adversarial suite remains part
of the full repository regression set.

## Measured pre-documentation candidate evidence

Exact candidate:

```text
c4ec748822ca3acacb7ce3fd14ffbc881c55baa0
```

Measured results:

- v1.70 whole-chain: **13 / 13 PASS**;
- full repository regression: **237 / 237 PASS**;
- failures/errors/skips: **0 / 0 / 0**;
- `compileall -q src tests tools`: **PASS**;
- v1.70 signed witness: **4 PASS + 1 LIMITATION_CONFIRMED + 0 FAIL**;
- signed-witness result: **BOUNDARY_CONFIRMED**;
- all **14 / 14** applicable pull-request workflows: **success**.

See [TEST-REPORT-v1.70.md](TEST-REPORT-v1.70.md) for the adversarial history,
protected claims, limitations and workflow evidence.

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
- release-specific test report;
- documentation/security-model consistency;
- final freeze merge with expected-head protection;
- complete push-triggered revalidation on the exact resulting `main` SHA;
- only then immutable tag and stable GitHub release publication.

## Retained limitations / non-claims

v1.70 does **not** claim any of the following:

- independent security certification;
- correctness of verifier domain logic;
- proof that differently named principals/profiles/providers are administratively
  or epistemically independent in the real world;
- physical wall-clock chronology from authenticated stage ordering;
- distributed consensus or cross-process shared-session ordering without an
  external serialized session authority;
- a general DAG, parallel-stage or optional-stage workflow model;
- protection from a malicious trusted host that deliberately abandons the
  documented hardened API path;
- rollback resistance when every preserving authority domain is rolled back
  together;
- exactly-once remote completion after an ambiguous or failed effect;
- ordering of arbitrary external side effects beyond the guarded/fenced effect
  boundary;
- universal fencing/TOCTOU protection for arbitrary HTTP APIs, cloud providers,
  databases or devices;
- PostgreSQL Layer C protection against a privileged function/schema owner or
  administrator that can rewrite authoritative state;
- backup/restore, failover, physical-power-loss or production administration
  guarantees unless separately enforced and tested.

A green limitation witness means that a documented limitation reproduced as
expected. It is not converted into a security PASS.

## Candidate decision

At this documentation/refreeze step:

```text
VERSION:                        v1.70
RELEASE TYPE:                   proposed stable capability release
SCOPE:                          FROZEN FOR CANDIDATE REVIEW
INITIAL ANCHOR:                 0063c66f144dc7eb8031eb235f8072a7982d5db3
MEASURED SOURCE CANDIDATE:      c4ec748822ca3acacb7ce3fd14ffbc881c55baa0
SOURCE WHOLE-CHAIN:             13 / 13 PASS
SOURCE FULL REGRESSION:         237 / 237 PASS
SOURCE SIGNED WITNESS:          4 PASS + 1 LIMITATION_CONFIRMED + 0 FAIL
DOCUMENTATION-REFREEZE GATE:    UNVERIFIED UNTIL ITS NEW SHA RUNS
FINAL EXACT-MAIN RELEASE GATE:  UNVERIFIED
TAG/RELEASE:                    NOT CREATED
```

Do not publish `v1.70` until the documentation/refreeze candidate has completed
fresh exact-head verification, the freeze merge has been accepted into `main`
with expected-head protection, and the exact resulting `main` SHA has completed
the final push-triggered release gate.
