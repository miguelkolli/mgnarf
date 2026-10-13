# Identity provenance and independence attestation boundary

Status: **DESIGN FREEZE CANDIDATE — ADVERSARIAL REVISION 5 — NO RUNTIME CLAIM**

Related: #61

This document defines the semantic boundary for authenticated actor provenance and machine-enforced independence claims in MGnarf. It does not claim that the current runtime proves these properties.

Revision 2 closed alias/equivalence and snapshot-mixing gaps. Revision 3 added candidate-origin attribution and per-stage execution/action attestation. Revision 4 removed the candidate/contract bootstrap cycle and carried provenance currentness to the effect path. Revision 5 defines linearized stage/effect admission so concurrent provenance changes have deterministic fail-closed semantics.

## 1. Problem

MGnarf already separates several security questions that must remain distinct:

1. **candidate/state integrity** — acceptance binds to frozen task/state/candidate facts;
2. **identity separation** — policy can require different logical principals, trust domains and verifier profiles;
3. **authenticated stage order** — ordered verifier/authority evidence can bind to its authenticated predecessor;
4. **effect admission** — the final accepted decision is revalidated and the external effect is guarded/single-use/fenced according to the selected host path.

A further question remains:

> What proves that two actors are genuinely separate along the dimensions policy claims, that the attested actors actually produced the candidate/evidence/actions being accepted, and that those provenance facts are current at the exact admission point where a verifier stage or external effect becomes authorized?

A logical identity label is not proof of independence. A static actor registry is not proof of execution attribution. A once-valid provenance decision is not a permanent effect authorization.

## 2. Core invariant

MGnarf MUST NOT claim stronger separation or attribution than authenticated provenance evidence actually proves.

If policy requires two actors to differ on provenance dimension `D`, the configured provenance authority must establish that their canonical security-equivalence classes for `D` are distinct:

```text
canonical_provenance(actor_A, D)
!=
canonical_provenance(actor_B, D)
```

For a required dimension, the authority result has three semantic outcomes:

```text
SAME      -> separation requirement fails
DISTINCT  -> separation requirement may be satisfied
UNKNOWN   -> BLOCKED
```

`UNKNOWN`, unavailable, ambiguous, stale, unauthenticated, or candidate/verifier-controlled provenance MUST never be upgraded to `DISTINCT`.

Every provenance-sensitive artifact/action MUST be attributable to the exact attested actor instance that produced it. Provenance currentness MUST also be valid at the linearized admission point for each provenance-dependent stage and for the final external effect.

## 3. Provenance evidence classes

The design distinguishes four authenticated objects. None may silently substitute for another.

### A. Authority-state snapshot

A pre-contract snapshot of canonical actor provenance under one provenance authority state.

```text
Under authority revision R, what canonical security-equivalence classes are assigned to each actor role?
```

### B. Candidate-origin/build attestation

Created from a builder execution under A and bound to the exact candidate digest.

```text
Which attested builder execution produced this exact candidate digest?
```

### C. Contract-bound provenance binding

Created after the candidate/task/state/policy contract exists. It commits the exact contract to A and B when B is required.

```text
Which pre-contract provenance state and candidate-origin proof govern this authorization contract?
```

### D. Per-stage execution/action attestation

Created for each provenance-dependent verifier or authority invocation and bound to C.

```text
Which attested actor instance actually produced this verifier result or authority action for this contract/stage?
```

The dependency graph is acyclic:

```text
authority-state snapshot A
  -> builder execution
  -> candidate-origin attestation B
  -> candidate/task/state freeze
  -> contract
  -> contract-bound provenance binding C
  -> linearized stage admission
  -> stage execution/action attestations D...
  -> final decision
  -> stable operation / fence
  -> linearized effect admission
  -> effect
```

## 4. Separation of concerns

### Identity separation

```text
Are policy-required actor facts distinct?
```

### Provenance attestation

```text
What canonical security-equivalence classes do actors belong to, and which actor instances produced accepted artifacts/actions?
```

### Stage ordering

```text
Did required authenticated stages execute in the required predecessor order?
```

### Admission currentness

```text
At which single ordered point did current provenance + exact authorization become admitted for this stage/effect?
```

All may be required simultaneously.

## 5. Trust boundary

Provenance facts and actor-instance attribution MUST originate outside candidate/verifier control.

Acceptable sources are host-owned authority mechanisms such as:

- a trusted-host execution registry;
- an authenticated workload/execution attester;
- an authenticated identity/provenance probe;
- a host-owned credential/security-domain mapping;
- an authenticated external authority whose result is frozen or revision-bound by the host.

The following MUST NOT be treated as provenance proof on their own:

- verifier output fields;
- candidate output fields;
- environment variables writable by candidate/verifier code;
- friendly actor names;
- arbitrary provider resource names;
- model-generated identity claims;
- process arguments supplied by untrusted code;
- timestamps alone.

## 6. Canonical provenance dimensions

Candidate dimensions include:

- `principal_id` — authenticated logical actor identity;
- `credential_equivalence_id` — canonical authority-defined class for the underlying credential/signing/service identity relevant to policy;
- `execution_security_domain_id` — canonical authority-defined class for the execution/worker/runtime security boundary;
- `control_security_domain_id` — canonical authority-defined class for the administrative/control-plane authority boundary;
- `trust_domain` — existing logical trust boundary used by MGnarf identity policy;
- `verifier_profile` — frozen verifier/model/toolchain profile where applicable.

A provenance field used for separation MUST NOT be a display label. Its authority must define equality at the security boundary.

If two aliases resolve to the same underlying boundary, they MUST resolve to the same canonical equivalence identifier. If the authority cannot determine equivalence, the result is `UNKNOWN` and a required rule is BLOCKED.

## 7. Policy model

Policy expresses explicit pairwise separation requirements over canonical dimensions.

Conceptually:

```json
{
  "actors": {
    "builder": {
      "principal_id": "builder-A",
      "credential_equivalence_id": "cred-domain-01",
      "execution_security_domain_id": "exec-domain-build",
      "control_security_domain_id": "control-domain-build",
      "trust_domain": "build-domain"
    },
    "verifier:tests": {
      "principal_id": "verify-tests-A",
      "credential_equivalence_id": "cred-domain-02",
      "execution_security_domain_id": "exec-domain-verify-A",
      "control_security_domain_id": "control-domain-verify-A",
      "trust_domain": "verify-domain-A"
    },
    "verifier:security": {
      "principal_id": "verify-sec-B",
      "credential_equivalence_id": "cred-domain-03",
      "execution_security_domain_id": "exec-domain-verify-B",
      "control_security_domain_id": "control-domain-verify-B",
      "trust_domain": "verify-domain-B"
    },
    "authority": {
      "principal_id": "authority-H",
      "credential_equivalence_id": "cred-domain-04",
      "execution_security_domain_id": "exec-domain-authority",
      "control_security_domain_id": "control-domain-human-policy",
      "trust_domain": "authority-domain"
    }
  },
  "separation": [
    ["builder", "verifier:tests", "credential_equivalence_id"],
    ["verifier:tests", "verifier:security", "execution_security_domain_id"],
    ["verifier:tests", "verifier:security", "control_security_domain_id"],
    ["verifier:security", "authority", "principal_id"]
  ]
}
```

The exact serialized schema may evolve before implementation.

## 8. Authority-state snapshot A

A MUST exist independently of any contract so builder attribution can be established before contract freeze.

A MUST bind the semantic equivalent of:

```text
provenance_authority_id
provenance_authority_trust_root_id
provenance_schema_version
provenance_revision
canonical_actor_provenance_map
provenance_map_digest
```

A is authenticated by the configured provenance authority/trust root and MUST have rollback-resistant currentness semantics sufficient for the deployment's claim.

All actor provenance used for one authorization must derive from the exact A selected later by C. Actor fields MUST NOT be mixed across A snapshots/revisions.

## 9. Candidate-origin/build attestation B

If policy requires provenance separation involving `builder`, MGnarf MUST have B for the exact candidate.

B MUST bind the semantic equivalent of:

```text
candidate_sha256
builder_role
builder_actor_instance_id
builder principal/canonical provenance
A digest / provenance_map_digest
provenance_authority_id
provenance_authority_trust_root_id
provenance_revision
build_attestation_id
```

B must be produced by the trusted execution/provenance attestation path from the actual builder execution/output relationship, not from a builder-supplied claim that it produced an arbitrary digest.

A later registry lookup is insufficient. B from another candidate/A/trust root/revision cannot satisfy the current authorization.

## 10. Contract-bound provenance binding C

After the ordinary MGnarf contract is frozen, the trusted host creates C.

C MUST bind the semantic equivalent of:

```text
contract_id
candidate_sha256
task/policy/state contract commitments
identity/provenance policy digest
A digest / provenance_map_digest
provenance_authority_id
provenance_authority_trust_root_id
provenance_revision
B digest when builder provenance is required
stage_order digest when authenticated ordering is enabled
MGnarf authority revision when enabled
```

C is the provenance root for subsequent session/stage authorization.

A stage/wrapper must not choose another A or B after C exists. If A becomes stale/currentness-invalid, C becomes unusable for new stage admission and effect admission.

## 11. Per-stage execution/action attestation D

Every provenance-dependent verifier or authority stage MUST be bound to an authenticated actor instance for that exact invocation.

D MUST bind the semantic equivalent of:

```text
C digest / contract provenance binding id
actor_role
actor_instance_id
principal/canonical provenance from A
contract_id
session_id
requirement_id
stage invocation/admission identity
stage_order/predecessor context when enabled
produced evidence/action digest
```

D MUST come from the trusted execution/provenance authority path, not verifier output.

D from another contract/session/stage/invocation/actor/A/C cannot be replayed into the current stage.

## 12. Linearized provenance-dependent stage admission

Each provenance-dependent stage MUST have exactly one host-owned admission linearization point before producer entry.

At that point, the host must atomically, or through an equivalent single-winner reservation/fencing protocol:

```text
validate exact C
validate current A authority/root/revision/currentness
validate required separation for this actor/stage
validate actor-instance attestation/admission identity
validate stage-order predecessor state when enabled
reserve this stage invocation so it cannot be concurrently/re-entrantly admitted twice
```

Only after successful reservation may the producer run.

Concurrency semantics are defined by the order of the provenance transition and admission reservation:

- provenance/currentness transition linearizes first -> stage admission is BLOCKED and producer is not entered;
- stage admission reservation linearizes first under valid provenance -> producer may run, but later provenance drift makes subsequent stages/final authorization stale according to revision rules;
- duplicate/concurrent stage attempts -> at most one admission for the exact reserved stage invocation.

This MUST compose with the existing authenticated stage-order in-flight reservation rather than create a second contradictory admission order.

## 13. Attestation-to-execution continuity

The host MUST close the gap between stage admission and the artifact/action later accepted.

A deployment must provide one of:

1. attested actor instance and relevant credential/security-domain bindings are immutable for the invocation; or
2. the host revalidates the execution-instance binding at required evidence/finalization boundaries and fails closed on drift.

A stage admitted under one actor instance but completed under another is BLOCKED/stale. Restoring old visible values after drift MUST NOT heal the invocation.

## 14. Revision, revocation and drift

Any semantic change to A's actor/provenance mappings, canonical equivalence resolution, trust root, relevant authority configuration, or accepted actor-instance binding MUST advance/invalidate provenance state in a rollback-resistant way.

If MGnarf monotonic authority revision is also enabled, provenance changes relevant to authorization MUST be bound to that revision so the mechanisms cannot disagree silently.

After a partial chain begins, provenance drift blocks later stages/final authorization unless the authorization is deliberately restarted under fresh bindings.

Required revocation/currentness signals are additional fail-closed conditions. Absence of required currentness data is BLOCKED.

## 15. Final decision provenance binding

The final provenance-enabled MGnarf decision MUST bind, directly or transitively through the authenticated ordered evidence chain, to C and the required B/D attestations.

Stable-operation, authority-revision and fencing paths MUST preserve that exact provenance-enabled decision/binding. None may reconstruct a weaker authorization.

## 16. Linearized effect admission

The external effect boundary has one defined **effect-admission linearization point**.

At that point, the trusted effect path MUST atomically, or with equivalent fencing/compare-and-reserve semantics:

```text
validate exact contract / final decision / C relationship
validate A authority id + trust root
validate A provenance revision/currentness
validate required provenance revocation/currentness state
validate existing MGnarf state/revocation/authority conditions
validate stable-operation/fence relationship
reserve/consume the single-use effect authorization
```

Only after successful effect admission may the protected external effect begin.

Concurrency semantics:

- provenance/currentness transition linearizes before effect admission -> effect is BLOCKED;
- effect admission reservation linearizes first under current valid provenance -> that one effect is admitted; a later provenance change does not retroactively undo an already-started external effect unless the target system provides transactional cancellation/rollback;
- concurrent duplicate effect attempts -> at most one reservation/admission can win;
- an already-issued fence is not a provenance override: the fence participates in the same admission check.

The security claim is therefore precise:

> provenance must be current at the linearized effect-admission point.

MGnarf does not claim to revoke an external side effect after that admission point when the target cannot roll it back.

## 17. Independence claim strength

MGnarf MUST describe only the dimensions it actually verifies.

- Different `principal_id` values prove only principal separation.
- Different canonical credential IDs prove credential-equivalence separation only according to the configured authority model.
- Different canonical execution/control IDs prove those declared security-domain separations only according to that authority model.
- D proves stage attribution only under the configured execution-attestation trust model.

MGnarf MUST NOT translate these into a universal claim of statistical, cognitive, organizational, geographic, vendor, or failure-mode independence.

## 18. No-silent-downgrade rule

Every public/composed path accepting provenance-enabled authorization MUST preserve/enforce it end-to-end or reject fail closed.

It MUST NOT:

- strip provenance fields;
- reinterpret provenance-enabled authorization as identity-only;
- reconstruct a weaker unordered/unattested contract;
- ignore stronger evidence versions;
- substitute verifier-supplied identity facts;
- reduce canonical separation to friendly-name inequality;
- switch provenance authority/trust root;
- mix A snapshots;
- substitute A for required B/D evidence;
- reuse D across unauthorized invocation/session/stage;
- omit C or stage/effect admission currentness checks;
- split provenance currentness and single-use reservation into race-prone independent checks whose order is undefined.

## 19. Versioning

Existing released identity-only contracts retain existing semantics.

Provenance support MUST use distinct, unambiguous versions for stronger contract/binding semantics and for A/B/C/D evidence types as applicable.

Older consumers that do not implement stronger provenance semantics MUST reject those versions, never ignore unknown fields and continue as legacy PASS.

## 20. Required adversarial cases

Before runtime provenance support can be called PASS, tests MUST cover at minimum:

1. same underlying credential under two labels when credential separation is required -> BLOCKED;
2. same execution security domain under two verifier labels -> BLOCKED;
3. same control security domain under two trust-domain labels -> BLOCKED;
4. missing/malformed/UNKNOWN required provenance -> BLOCKED;
5. candidate/verifier self-asserted trusted provenance -> ignored/BLOCKED;
6. provenance evidence from another session/contract/candidate/policy/revision -> BLOCKED;
7. A replaced after partial chain -> stale/BLOCKED;
8. drift then restore -> partial chain remains stale/BLOCKED;
9. distinct logical identities but equal required canonical domains -> BLOCKED;
10. correct provenance but wrong authenticated stage order -> BLOCKED;
11. correct predecessor chain but provenance separation fails -> BLOCKED;
12. wrapper strips provenance -> BLOCKED;
13. legacy gate receives stronger provenance version -> rejected, never legacy PASS;
14. authority-revision/stable-operation/fenced wrappers preserve exact provenance binding;
15. replay under new actor map/policy -> BLOCKED;
16. same underlying security domain under different aliases -> canonicalized SAME/BLOCKED;
17. same map under wrong provenance authority/trust root -> BLOCKED;
18. actor fields mixed from multiple valid A snapshots -> BLOCKED;
19. authority cannot determine equivalence -> UNKNOWN/BLOCKED;
20. correct static verifier-B record but verifier-B executes under verifier-A actor instance -> BLOCKED;
21. D from another invocation/session reused -> BLOCKED;
22. actor/security binding changes between stage admission and result -> stale/BLOCKED;
23. builder map exists but required B is absent -> BLOCKED;
24. B for another candidate -> BLOCKED;
25. authority map is correct but authority action lacks attributable D -> BLOCKED;
26. A -> B -> contract -> C exact bootstrap path -> valid;
27. C references A different from B's A -> BLOCKED;
28. C references B for different candidate -> BLOCKED;
29. post-hoc map without required B cannot prove builder provenance -> BLOCKED;
30. provenance changes after final PASS but before effect admission -> BLOCKED;
31. provenance changes after fence issuance but before effect admission -> BLOCKED;
32. provenance drifts/restores before effect -> old authorization stale/BLOCKED;
33. old decision/fence after authority/trust-root replacement -> BLOCKED;
34. required current provenance/revocation state unavailable at effect admission -> BLOCKED;
35. provenance revision races effect admission and revision change linearizes first -> effect BLOCKED;
36. effect admission linearizes first, then provenance changes -> no second effect; the admitted effect is not retroactively reclassified;
37. provenance revision races stage admission and revision change linearizes first -> producer not entered;
38. stage admission linearizes first, provenance changes during/after producer -> chain stale before later stage/final effect;
39. concurrent duplicate effect attempts around provenance change -> at most one admission and only under valid provenance at its linearization point;
40. concurrent duplicate/re-entrant stage attempts -> at most one stage admission;
41. correct B/D provenance + correct ordering + current provenance at effect admission -> eligible for PASS only with all other MGnarf conditions;
42. full existing regression suite remains green and legacy contracts retain legacy semantics.

## 21. Non-goals

This first boundary does not prove:

- statistical independence of model errors;
- cognitive independence of humans;
- organizational independence merely because company names differ;
- cloud-provider independence merely because provider names differ;
- resistance to compromise of the trusted host/provenance trust root itself;
- correctness of an external provenance/execution authority beyond the configured trust model;
- revocation of an external effect after the defined effect-admission point when the target cannot roll it back;
- that different models/vendors are automatically independent.

## 22. Implementation gate

No runtime change should begin until this boundary is deliberately reviewed and accepted or amended.

Required development order:

```text
recon exact current main
  -> freeze semantic boundary
  -> adversarial design review
  -> tests first / RED
  -> smallest runtime implementation
  -> canonical alias/equivalence tests
  -> provenance authority/trust-root/rollback tests
  -> A snapshot atomicity tests
  -> B candidate-origin tests
  -> C contract-binding/bootstrap tests
  -> D stage actor-instance attribution tests
  -> stage admission linearization/concurrency tests
  -> attestation/execution TOCTOU tests
  -> stage-order composition tests
  -> final-decision provenance-binding tests
  -> effect admission linearization/provenance-race tests
  -> authority/stable-operation/fencing no-downgrade tests
  -> full regression suite
  -> independent whole-chain review
  -> exact-SHA evidence
  -> release freeze only if deliberately included
```

Until all of that exists, MGnarf documentation must say only that released identity separation relies on trusted-host actor facts according to released contract semantics. It must not claim independently attested execution/control provenance, candidate/stage attribution, or provenance-current effect admission unless those properties have actually been implemented and verified.
