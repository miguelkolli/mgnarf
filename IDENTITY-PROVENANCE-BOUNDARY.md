# Identity provenance and independence attestation boundary

Status: **DESIGN FREEZE CANDIDATE — ADVERSARIAL REVISION 4 — NO RUNTIME CLAIM**

Related: #61

This document defines the semantic boundary for authenticated actor provenance and machine-enforced independence claims in MGnarf. It does not claim that the current runtime proves these properties.

Revision 2 closed alias/equivalence and snapshot-mixing gaps. Revision 3 added candidate-origin attribution and per-stage execution/action attestation. Revision 4 removes the candidate/contract bootstrap cycle and extends provenance currentness through the final pre-effect admission boundary.

## 1. Problem

MGnarf already separates several security questions that must remain distinct:

1. **candidate/state integrity** — acceptance binds to frozen task/state/candidate facts;
2. **identity separation** — policy can require different logical principals, trust domains and verifier profiles;
3. **authenticated stage order** — ordered verifier/authority evidence can bind to its authenticated predecessor;
4. **effect admission** — the final accepted decision is revalidated and the external effect is guarded/single-use/fenced according to the selected host path.

A further question remains:

> What proves that two actors are genuinely separate along the dimensions policy claims, that the attested actors actually produced the candidate/evidence/actions being accepted, and that those provenance facts are still current when the external effect is admitted?

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

Every provenance-sensitive artifact/action MUST also be attributable to the exact attested actor instance that produced it, and provenance currentness MUST remain valid through final effect admission.

## 3. Provenance evidence classes

The design distinguishes four authenticated objects. None may silently substitute for another.

### A. Authority-state snapshot

A pre-contract snapshot of canonical actor provenance under one provenance authority state.

Answers:

```text
Under authority revision R, what canonical security-equivalence classes are assigned to each actor role?
```

### B. Candidate-origin/build attestation

Created from a builder execution under authority-state snapshot A and bound to the exact candidate digest.

Answers:

```text
Which attested builder execution produced this exact frozen candidate digest?
```

### C. Contract-bound provenance binding

Created only after the candidate/task/state/policy contract exists. It commits the exact contract to authority-state snapshot A and candidate-origin attestation B when required.

Answers:

```text
Which pre-contract provenance state and candidate-origin proof govern this exact authorization contract?
```

### D. Per-stage execution/action attestation

Created for each provenance-dependent verifier or authority invocation and bound to contract provenance binding C.

Answers:

```text
Which attested actor instance actually produced this exact verifier result or authority action for this contract/stage?
```

The dependency graph is intentionally acyclic:

```text
authority-state snapshot A
  -> builder execution
  -> candidate-origin attestation B
  -> candidate/task/state freeze
  -> contract
  -> contract-bound provenance binding C
  -> stage execution/action attestations D...
  -> final decision
  -> stable operation / fence
  -> pre-effect provenance revalidation
  -> effect
```

## 4. Separation of concerns

### Identity separation answers

```text
Are the actor facts required by policy distinct?
```

### Provenance attestation answers

```text
What authenticated security-equivalence classes do those actors belong to, and which actor instances produced the accepted artifacts/actions?
```

### Stage ordering answers

```text
Did the required authenticated stages execute in the required predecessor order?
```

### Effect currentness answers

```text
Are the provenance authority state, contract binding and required actor/action attestations still valid at the moment the external effect is admitted?
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

The exact provider-specific mechanism is outside this generic boundary.

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
- `credential_equivalence_id` — canonical authority-defined equivalence class for the underlying credential/signing/service identity relevant to policy;
- `execution_security_domain_id` — canonical authority-defined equivalence class for the execution/worker/runtime security boundary;
- `control_security_domain_id` — canonical authority-defined equivalence class for the administrative/control-plane authority boundary;
- `trust_domain` — existing logical trust boundary used by MGnarf identity policy;
- `verifier_profile` — frozen verifier/model/toolchain profile where applicable.

A provenance field used for separation MUST NOT be a display label. Its authority must define equality at the security boundary.

If two aliases resolve to the same underlying security boundary, they MUST resolve to the same canonical equivalence identifier. If the authority cannot determine equivalence, the result is `UNKNOWN` and a required separation rule is BLOCKED.

A deployment MAY implement a smaller authenticated field set, but it MUST reject a policy requiring a dimension it cannot establish canonically.

## 7. Policy model

The policy expresses explicit pairwise separation requirements over canonical dimensions.

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

The frozen semantic rule is: each required separation dimension must be backed by authenticated canonical provenance, each provenance-dependent artifact/action must be attributable to its attested producer, and the relevant provenance authority state must remain current through effect admission.

## 8. Authority-state snapshot A

Authority-state snapshot A MUST exist independently of any specific contract so builder attribution can be established before contract freeze.

A MUST bind the semantic equivalent of:

```text
provenance_authority_id
provenance_authority_trust_root_id
provenance_schema_version
provenance_revision
canonical_actor_provenance_map
provenance_map_digest
```

A is authenticated by the configured provenance authority/trust root and MUST have rollback-resistant currentness semantics sufficient for the deployment's claims.

`provenance_authority_id` identifies the authority namespace. `provenance_authority_trust_root_id` identifies the configured trust root or equivalent host trust anchor. A same-looking map under another authority/trust root is not the same trust statement.

All actor provenance used for one provenance authorization must derive from the exact A selected later by contract binding C. Actor fields MUST NOT be mixed across authority-state snapshots/revisions.

## 9. Candidate-origin/build attestation B

If policy requires any provenance separation involving `builder`, MGnarf MUST have authenticated candidate-origin attestation B for the exact frozen candidate.

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

B must be produced by the trusted execution/provenance attestation path from the actual builder execution/output relationship, not by accepting a builder-supplied statement that it produced an arbitrary digest.

A later registry lookup saying `builder = builder-A` is insufficient. The exact candidate digest must be attributable to the attested builder execution under A.

A B from another candidate digest, authority state, trust root or provenance revision cannot satisfy the current authorization.

## 10. Contract-bound provenance binding C

After the ordinary MGnarf contract is frozen, the trusted host creates authenticated contract provenance binding C.

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

A stage or wrapper must not choose another A or B after C exists. If A becomes stale/currentness-invalid, C becomes unusable for new stage admission and final effect authorization.

The contract MUST NOT silently acquire provenance semantics merely because A/B exist. Stronger provenance behavior requires the unambiguous provenance-enabled contract/binding semantic version.

## 11. Per-stage execution/action attestation D

Every provenance-dependent verifier or authority stage MUST be bound to an authenticated execution/action instance for that exact invocation.

D MUST bind, directly or transitively, the semantic equivalent of:

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

A correct static actor record does not authorize evidence created under another actor instance.

For an authority stage, the accepted authority action/decision MUST be attributable to the attested authority actor/action instance.

D from another contract, session, stage, invocation, actor instance, A revision, or C cannot be replayed into the current stage.

## 12. Attestation-to-execution continuity

MGnarf MUST close the time-of-check/time-of-use gap between actor attestation and the artifact/action being accepted.

A deployment must provide one of these semantic guarantees:

1. the attested actor instance and relevant credential/security-domain bindings are immutable for the whole invocation; or
2. the host revalidates the execution-instance binding at admission and again at required evidence/finalization boundaries, failing closed on drift.

A pre-launch attestation followed by execution under another instance, credential equivalence class, execution security domain, control security domain, provenance revision, or authority is BLOCKED.

Restoring old visible values after drift MUST NOT heal the invocation.

## 13. Revision, revocation and drift

Any semantic change to A's actor/provenance mappings, canonical equivalence resolution, provenance trust root, relevant authority configuration, or accepted actor-instance binding MUST advance/invalidate the relevant provenance state in a rollback-resistant way.

If the host also uses MGnarf monotonic authority revision, provenance changes relevant to authorization MUST be bound to that revision so the mechanisms cannot disagree silently.

After a partial verifier chain begins:

```text
verifier A accepted
  -> A / authority / actor-instance currentness changes
  -> verifier B requested
```

must be BLOCKED unless the authorization is deliberately restarted under fresh bindings.

Revocation/currentness signals required by the configured provenance authority model are additional fail-closed conditions. Absence of required currentness data is BLOCKED.

## 14. Final decision and pre-effect provenance revalidation

The final MGnarf decision for a provenance-enabled authorization MUST bind, directly or transitively through the authenticated ordered evidence chain, to C and the required B/D attestations.

Stable-operation, authority-revision and fencing paths MUST preserve that exact provenance-enabled decision/binding. None may reconstruct a weaker authorization.

Immediately before external effect admission, the trusted effect path MUST revalidate at minimum:

```text
exact contract/decision/fence relationship
C authenticity and exact binding
A authority id + trust root
A provenance revision/currentness
required provenance revocation/currentness state
existing MGnarf state/revocation/authority conditions
single-use / stable-operation / fence conditions
```

If A or any required provenance authority/currentness condition changed after the final PASS decision, the old decision/fence MUST NOT cause the effect.

An already-issued fence is not a provenance override.

A drift-then-restore sequence MUST remain stale when the configured monotonic/rollback-resistant provenance semantics say that a revision transition occurred.

## 15. Independence claim strength

MGnarf MUST describe only the dimensions it actually verifies.

- Different `principal_id` values prove only principal separation.
- Different canonical `credential_equivalence_id` values prove credential-equivalence separation only according to the configured authority model.
- Different canonical `execution_security_domain_id` values prove execution-domain separation only according to that authority model.
- Different canonical `control_security_domain_id` values prove declared control-plane separation only according to that authority model.
- D proves stage attribution only under the configured execution-attestation trust model.

MGnarf MUST NOT translate these into a universal claim that verifiers are statistically, organizationally, cognitively, geographically, vendor, or failure-mode independent.

## 16. No-silent-downgrade rule

Every public/composed path that accepts a provenance-enabled authorization MUST either preserve/enforce it end-to-end or reject fail closed before verifier/effect execution.

It MUST NOT:

- strip required provenance fields;
- reinterpret a provenance-enabled contract as identity-only;
- reconstruct a weaker unordered/unattested contract;
- accept an older receipt schema while ignoring provenance;
- substitute verifier-supplied identity facts;
- reduce canonical credential/execution/control separation to friendly-name inequality;
- switch provenance authority/trust root;
- mix authorization facts from multiple A snapshots;
- substitute static A for required B or D evidence;
- reuse D across an unauthorized invocation/session/stage;
- let stable-operation/fencing/effect wrappers omit C or pre-effect currentness checks.

## 17. Versioning

Existing released identity-only contracts retain existing semantics.

Provenance support MUST use distinct, unambiguous versions for the stronger contract/binding semantics and for A/B/C/D evidence types as applicable.

An older consumer that does not implement stronger provenance semantics MUST reject those stronger versions, never ignore unknown fields and continue as legacy PASS.

## 18. Required adversarial cases

Before runtime provenance support can be called PASS, tests MUST cover at minimum:

1. same underlying credential under two principal labels when credential separation is required -> BLOCKED;
2. same execution security domain under two verifier labels when execution separation is required -> BLOCKED;
3. same control security domain under two trust-domain labels when control separation is required -> BLOCKED;
4. missing/malformed/UNKNOWN required provenance -> BLOCKED;
5. candidate/verifier attempts to self-assert trusted provenance -> ignored/BLOCKED;
6. provenance evidence from another session/contract/candidate/policy/revision -> BLOCKED;
7. A replaced after verifier A but before verifier B -> stale/BLOCKED;
8. provenance values drift then return to original values -> partial chain remains stale/BLOCKED;
9. logical identities distinct but required canonical security-equivalence IDs equal -> BLOCKED;
10. correct provenance but wrong authenticated stage order -> BLOCKED;
11. correct predecessor chain but provenance separation fails -> BLOCKED;
12. wrapper strips provenance requirement -> BLOCKED;
13. legacy gate presented with stronger provenance evidence version -> rejected, never legacy PASS;
14. authority-revision/stable-operation/fenced wrappers preserve exact provenance binding;
15. replay under a new actor map or policy digest -> BLOCKED;
16. concurrency cannot admit a provenance-dependent stage while A/C/currentness is stale/in transition;
17. final effect remains single-use and exact-decision-bound;
18. legacy contracts retain legacy semantics;
19. same underlying credential represented by two aliases -> canonicalized SAME/BLOCKED;
20. same execution security domain represented by two aliases -> SAME/BLOCKED;
21. same control security domain represented by two aliases -> SAME/BLOCKED;
22. same map under wrong/replaced provenance authority or trust root -> BLOCKED;
23. actor fields mixed from multiple individually valid A snapshots -> BLOCKED;
24. authority cannot determine required equivalence -> UNKNOWN/BLOCKED;
25. correct static verifier-B record but verifier-B runs under verifier-A actor instance -> BLOCKED;
26. D from another invocation/session reused for current stage -> BLOCKED;
27. attested actor instance/security binding changes between admission and receipt -> stale/BLOCKED;
28. actor map says builder-A but candidate lacks B -> BLOCKED when builder provenance separation is required;
29. valid B for another candidate digest -> BLOCKED;
30. authority actor map is correct but accepted authority action lacks attributable D -> BLOCKED;
31. correct B/D provenance + correct ordered chain -> eligible for PASS only with all other MGnarf conditions;
32. A is pre-contract and valid, B is produced under A, then C binds exact A+B+candidate+contract -> valid bootstrap path;
33. C references A different from B's A -> BLOCKED;
34. C references B for a different candidate -> BLOCKED;
35. post-hoc actor map with no required candidate-origin B cannot prove builder provenance -> BLOCKED;
36. provenance changes after final PASS but before effect -> effect BLOCKED;
37. provenance changes after fence issuance but before guarded effect entry -> effect BLOCKED;
38. provenance drifts then visible values restore before effect -> old authorization remains stale/BLOCKED;
39. old decision/fence replayed after provenance authority/trust-root replacement -> BLOCKED;
40. effect path cannot obtain required current provenance/revocation state -> BLOCKED;
41. full existing regression suite remains green.

## 19. Non-goals

This first boundary does not prove:

- statistical independence of model errors;
- cognitive independence of humans;
- organizational independence merely because company names differ;
- cloud-provider independence merely because provider names differ;
- resistance to compromise of the trusted host/provenance trust root itself;
- correctness of an external provenance/execution authority beyond the configured trust model;
- that two different models or vendors are automatically independent.

Those claims require separate evidence and must not be implied by this feature.

## 20. Implementation gate

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
  -> attestation/execution TOCTOU tests
  -> stage-order composition tests
  -> final-decision/pre-effect provenance-drift tests
  -> authority/stable-operation/fencing no-downgrade tests
  -> concurrency tests
  -> full regression suite
  -> independent whole-chain review
  -> exact-SHA evidence
  -> release freeze only if deliberately included
```

Until all of that exists, MGnarf documentation must say only that released identity separation relies on trusted-host actor facts according to released contract semantics. It must not claim independently attested execution/control provenance, candidate/stage attribution, or provenance-current effect admission unless those properties have actually been implemented and verified.
