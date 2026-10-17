# TEST REPORT — v1.70 hardened execution candidate

Date: 2026-10-13

Status: **PRE-MAIN CANDIDATE EVIDENCE — FINAL STABLE GATE UNVERIFIED**

## Evidence source candidate

This report records repository-owned evidence measured on the exact release-branch candidate:

```text
c4ec748822ca3acacb7ce3fd14ffbc881c55baa0
```

Previous stable release:

```text
v1.61
30b7d0def802c3e7256e8aca2bbdc025df972721
```

This report is being added in a later documentation/refreeze change. Therefore the commit containing this report necessarily has a different Git SHA from the measured source candidate above. That later SHA must receive its own fresh exact-head gates before any merge to `main`. No PASS in this report is inherited across a SHA change.

## Frozen candidate scope measured

The v1.70 candidate combines the post-v1.61 hardened execution line:

1. identity-bound separation of duties;
2. monotonic authority revision;
3. stable semantic operation identity;
4. fenced effect transport and downgrade/direct-route guards;
5. PostgreSQL Layer C commit-time fencing reference; and
6. authenticated stage ordering using evidence v3.

Authenticated stage ordering freezes an exact linear `requirement_id` permutation, binds the first stage to a session/contract-owned chain seed, binds every later stage to the authenticated predecessor receipt ID and canonical digest, rejects future stages before producer entry, protects same-stage admission against concurrency and same-thread re-entrancy, binds the final PASS decision to the final authenticated chain head, and preserves the ordered contract through authority-revision, stable-operation and fenced-operation wrappers without silent downgrade.

Legacy unordered v1/v2 behavior remains unchanged when stage ordering is not configured.

## Adversarial development history

The stage-order work was deliberately driven through RED -> GREEN cycles rather than added as an unmeasured API:

- the initial ordered API tests were RED because `stage_order` did not exist;
- composition tests were RED because authority/stable-operation/fenced wrappers did not yet propagate ordering;
- whole-chain review found a real same-thread re-entrancy gap: `RLock` alone allowed the same verifier producer to re-enter the same stage before the outer receipt was committed;
- a dedicated RED regression reproduced two producer entries;
- the runtime was corrected with explicit in-flight stage reservation released in `finally`;
- an independent review then found an evidence-coverage gap rather than another runtime break;
- test-only PR #56 added cross-session, cross-contract, cross-candidate and cross-order predecessor replay, BLOCKED predecessor, v3 identity-separation failure, partial-chain authority drift, concurrent future-stage probes, foreign chain seed substitution, non-final chain head and ordered-v3 single-use-effect coverage without modifying runtime code.

The independent verifier route completed 224/224 repository tests at that stage and the hardened workflow set remained green.

## Release integration findings

The v1.70 integration itself exposed governance/harness issues that were not hidden or relabeled as product PASS:

### 1. Exact-head topology failure

The first direct feature -> release-candidate integration PR (#57) used a feature-only PR head. The v1.70 exact-head workflow correctly checked out that head, but the release-only `test_v170_whole_chain.py` fixture existed only on the base branch. Test discovery therefore ran **0 tests** and the gate returned FAIL.

No product-security conclusion was drawn from that run. #57 was closed without merge. The integration topology was rebuilt so the exact head contained both the reviewed feature and the release fixtures.

### 2. Release-candidate push coverage gap

The first v1.70 exact workflows listened for `push` only on `main`. That prevented a release-candidate branch from obtaining exact branch-head push evidence before the final main merge.

The workflows were strengthened, not weakened: they now also run on pushes to `release/v1.70-candidate` and the integration branch. Final exact-main push revalidation remains mandatory.

### 3. Release-specific stage-order scope expansion

The existing v1.70 whole-chain gate contained 10 protected identity/revision/operation/fencing cases. Stage ordering was not accepted into the stable scope merely because feature tests were green.

Three release-specific ordered-chain cases were added and the frozen gate was deliberately refrozen at **13 protected cases**:

11. ordered v3 identity + authority revision + fenced execution reaches exactly one effect;
12. a future ordered stage is rejected before producer entry until its predecessor exists;
13. authority revision drift after the first ordered receipt blocks the next stage before producer/effect entry.

The exact release workflow was also strengthened to run the complete repository regression suite and `compileall -q src tests tools` on the same branch-head SHA.

## Exact release-branch candidate evidence

After the reviewed stage-order integration was merged **only** into `release/v1.70-candidate`, the resulting exact branch head was:

```text
c4ec748822ca3acacb7ce3fd14ffbc881c55baa0
```

### v1.70 whole-chain and full repository gate

The push-triggered exact-head workflow checked out the exact expected SHA and reported:

```text
release whole-chain tests: 13
protected cases:           13
failures:                  0
errors:                    0
skips:                     0
result:                    PASS

full repository tests:     237
failures:                  0
errors:                    0
skips:                     0
result:                    PASS

compileall src tests tools: PASS
```

All three v1.70 stage-order release regressions executed as PASS inside the exact release-candidate gate.

### v1.70 signed-witness exact gate

The separate push-triggered exact-head signed-witness workflow checked out the same exact release-branch SHA and reported:

```text
PASS:                  4
LIMITATION_CONFIRMED:  1
FAIL:                  0
result:                BOUNDARY_CONFIRMED
source_unchanged:      true
```

The high-fanout boundary used 16 fresh contracts/processes sharing one authenticated semantic operation UUID and produced:

```text
successful workers:   1
blocked workers:      15
callback invocations: 1
PostgreSQL rows:      1
witness reserved:     true
```

Resetting local host history and PostgreSQL did not re-enable the operation while the independent signed witness retained its consumed-token history.

The deliberate witness-ledger rollback case remains `LIMITATION_CONFIRMED`: if privileged operators can rewind the witness ledger together with every other preserving authority history, replay can return. That limitation is not converted into PASS.

### Pull-request workflow matrix

For the current release head `c4ec7488...`, all **14 / 14** applicable pull-request workflows completed successfully, including:

- aggregate reference checks;
- canonical binding fuzz;
- strict reference-host boundary;
- rollback limitation witness;
- rollback hardening;
- multi-domain fencing;
- PostgreSQL authority;
- PostgreSQL fenced target;
- signed witness;
- operation-bound authority;
- operation idempotency witness;
- ambiguous durable-reservation boundary;
- v1.70 whole-chain exact candidate; and
- v1.70 signed-witness exact candidate.

## Protected claims supported by this candidate

Within the measured reference boundaries, the candidate supports these claims:

- required evidence is bound to the exact frozen task/candidate/state/requirements/policy/effect context;
- configured identity separation remains an independent PASS condition;
- configured stage ordering is authenticated causal predecessor binding, not a timestamp convention;
- an ordered future stage cannot run its producer before its accepted predecessor exists;
- same-stage concurrency and same-thread re-entrancy cannot create two accepted producer admissions in one session;
- predecessor evidence from another session, contract, candidate, ordering policy or relevant identity/authority context cannot satisfy the chain;
- the ordered final decision binds to the authenticated final chain head;
- authority-revision, stable-operation and fenced-operation wrappers preserve ordered semantics or fail closed;
- stable operation replay remains externally single-use while the configured authority history survives;
- the tested PostgreSQL Layer C function/transaction/role model validates authority/fence state at the measured commit boundary;
- signed-witness and PostgreSQL ambiguity paths prefer fail-closed availability loss over automatically reopening uncertain consumed authority.

## Limitations and UNVERIFIED boundaries

The candidate does **not** prove:

- independent external security certification;
- logical correctness of verifier domain logic;
- epistemic independence merely because principals/profiles/providers differ;
- physical wall-clock chronology from stage ordering;
- distributed consensus or cross-process shared-session ordering without an external serialized session authority;
- ordering of arbitrary external side effects beyond the configured guarded/fenced effect boundary;
- universal TOCTOU elimination for arbitrary APIs, clouds, databases or devices;
- exactly-once remote effect completion after ambiguous acknowledgement or callback failure;
- rollback resistance if every preserving authority history is rolled back together;
- protection against a malicious trusted host that deliberately bypasses the documented hardened path;
- PostgreSQL Layer C protection against privileged function/schema owners or administrators able to rewrite authoritative state;
- backup/restore, failover, bind-mount aliasing, physical-power-loss behavior or production administration guarantees unless separately enforced and tested;
- a general DAG, parallel-stage or optional-stage workflow model.

The stage-order implementation proves authenticated predecessor-chain semantics inside the measured trusted-host/session boundary. It does not claim physical time ordering.

## Documentation audit status

The `c4ec7488...` candidate revealed a documentation-consistency blocker before main merge: the runtime/release scope contained stage ordering while README, hardened-path guidance, behavioral specification and architecture text still described the pre-stage-order public model.

This report is part of the documentation/refreeze correction. The documentation-refreeze SHA must be freshly revalidated and becomes the next candidate only after its own exact-head gates pass.

## Release decision

For measured source candidate `c4ec748822ca3acacb7ce3fd14ffbc881c55baa0`:

```text
FEATURE / PRE-MAIN CANDIDATE EVIDENCE: PASS
STABLE RELEASE DECISION:               UNVERIFIED
MAIN FREEZE MERGE:                     NOT YET PERFORMED
FINAL EXACT-MAIN PUSH GATE:            NOT YET PERFORMED
v1.70 TAG:                             NOT CREATED
GITHUB RELEASE:                        NOT PUBLISHED
```

No tag or stable release may be created from this report alone. The documentation/refreeze candidate must first pass fresh exact-head gates, then the release freeze must merge to `main` with expected-head protection, and the exact resulting `main` SHA must complete the final push-triggered gate before publication.
