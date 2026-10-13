# Identity provenance and independence attestation boundary

Status: **DESIGN FREEZE CANDIDATE — ADVERSARIAL REVISION 3 — NO RUNTIME CLAIM**

Related: #61

This document defines the semantic boundary for authenticated actor provenance and machine-enforced independence claims in MGnarf. It does not claim that the current runtime proves these properties.

Revision 2 closed alias/equivalence and snapshot-mixing gaps. Revision 3 adds candidate-origin attribution and per-stage execution/action attestation so static actor records cannot be mistaken for proof of who actually produced a candidate, verifier result, or authority decision.

## 1. Problem

MGnarf already separates several security questions that must remain distinct:

1. **candidate/state integrity** — the gate binds acceptance to frozen task/state/candidate facts;
2. **identity separation** — policy can require different logical principals, trust domains and verifier profiles;
3. **authenticated stage order** — ordered verifier/authority evidence can bind to its authenticated predecessor;
4. **effect admission** — the final accepted decision is revalidated and the external effect is guarded/single-use/fenced according to the selected host path.

A further question remains:

> What proves that two actors are genuinely separate along the dimensions the policy claims, and that the attested actors actually produced the candidate/evidence/actions being accepted?

A logical identity label is not, by itself, proof of independence. A static actor registry is not, by itself, proof of execution attribution.

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

In addition, every provenance-sensitive artifact/action MUST be attributable to the exact attested actor instance that produced it. A correct static actor map with incorrect runtime routing is BLOCKED.

## 3. Three provenance evidence classes

The design distinguishes three evidence classes. None may silently substitute for another.

### A. Static canonical provenance snapshot

Answers:

```text
What canonical security-equivalence classes are assigned to each frozen actor role?
```

This is the atomic actor/provenance map described below.

### B. Candidate-origin/build attestation

Answers:

```text
Which attested builder execution produced this exact frozen candidate digest?
```

This is required whenever policy makes a builder-vs-other separation claim based on provenance.

### C. Per-stage execution/action attestation

Answers:

```text
Which attested execution/action instance actually produced this exact verifier result or authority action?
```

This is required for each provenance-dependent verifier/authority stage.

A static snapshot does not prove B or C. B does not prove later stage execution. C for one stage does not prove another stage.

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

All may be required simultaneously.

A correct ordered chain with false independence claims is BLOCKED.
A correct provenance map with wrong execution attribution is BLOCKED.
A correctly attested set of independent actors in the wrong required order is BLOCKED.
A correct identity/provenance/order chain with stale candidate/state/effect bindings is BLOCKED.

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
- environment variables writable by the candidate/verifier;
- friendly actor names;
- arbitrary provider resource names;
- model-generated identity claims;
- process arguments supplied by untrusted code;
- timestamps alone.

## 6. Canonical provenance dimensions

The design uses explicit dimensions instead of one overloaded `independent=true` bit.

Candidate dimensions include:

- `principal_id` — authenticated logical actor identity;
- `credential_equivalence_id` — canonical authority-defined equivalence class for the underlying credential/signing/service identity relevant to policy;
- `execution_security_domain_id` — canonical authority-defined equivalence class for the execution/worker/runtime security boundary;
- `control_security_domain_id` — canonical authority-defined equivalence class for the administrative/control-plane authority boundary;
- `trust_domain` — existing logical trust boundary used by MGnarf identity policy;
- `verifier_profile` — frozen verifier/model/toolchain profile where applicable.

A provenance field used for separation MUST NOT be a mere display label. Its authority must define what equality means at the security boundary.

If two aliases resolve to the same underlying security boundary, they MUST resolve to the same canonical equivalence identifier. If the authority cannot determine equivalence, the result is `UNKNOWN` and a required separation rule is BLOCKED.

A deployment MAY implement a smaller authenticated field set, but it MUST reject any policy that requires a dimension it cannot establish canonically.

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
    ["builder", "verifier:tests", "principal_id"],
    ["builder", "verifier:tests", "credential_equivalence_id"],
    ["verifier:tests", "verifier:security", "execution_security_domain_id"],
    ["verifier:tests", "verifier:security", "control_security_domain_id"],
    ["verifier:security", "authority", "principal_id"]
  ]
}
```

The exact serialized schema may evolve before implementation.

The frozen semantic rule is: each required separation dimension must be backed by authenticated canonical provenance, and each provenance-dependent artifact/action must be attributable to the attested actor instance that produced it.

## 8. Provenance authority and atomic snapshot

Before any provenance-dependent stage is admitted, the trusted host MUST have one authenticated provenance snapshot covering all actor facts needed by the frozen policy.

The authority statement MUST bind, directly or transitively through authenticated host receipts, to the semantic equivalent of:

```text
provenance_authority_id
provenance_authority_trust_root_id
provenance_schema_version
provenance_revision
provenance_map_digest
contract_id
policy_digest
candidate/state binding
```

`provenance_authority_id` identifies the authority namespace. `provenance_authority_trust_root_id` identifies the configured trust root or equivalent host trust anchor. A same-looking actor map from a different authority/trust root is not automatically the same trust statement.

All actor provenance used by one authorization MUST come from one canonical authenticated snapshot/map commitment. The gate MUST NOT synthesize an actor by mixing individually valid fields from different snapshots, revisions, authorities, or sessions.

The snapshot MUST bind the exact:

- actor map;
- canonical provenance map;
- provenance authority and trust root;
- provenance schema/version;
- provenance revision;
- contract ID;
- policy digest;
- candidate/state semantic class;
- authority revision when the separate monotonic MGnarf authority-revision feature is enabled.

If stage ordering is enabled, the provenance requirement is part of the exact ordered contract semantic class and must not be silently dropped by an unordered wrapper.

## 9. Candidate-origin/build attestation

If policy requires any provenance separation involving `builder`, MGnarf MUST have an authenticated candidate-origin/build attestation for the exact frozen candidate.

The attestation MUST bind the semantic equivalent of:

```text
candidate_sha256
builder_role
builder_actor_instance_id
builder principal/canonical provenance
provenance_snapshot_digest
provenance_authority_id
provenance_revision
build_attestation_id
```

It SHOULD also bind the task/project/build semantic identifiers needed by the deployment so a build attestation cannot be transplanted into an unrelated authorization.

A later lookup saying `builder = builder-A` is insufficient. The accepted candidate digest itself must be attributable to the attested builder execution.

A builder attestation for another candidate digest, another provenance snapshot/revision, or another authority cannot satisfy the current contract.

If builder provenance is not required by policy, legacy candidate binding may retain its existing semantics; the system MUST NOT relabel that legacy binding as provenance-attested builder origin.

## 10. Per-stage execution/action attestation

Every provenance-dependent verifier or authority stage MUST be bound to an authenticated execution/action instance for that exact invocation.

The accepted stage evidence MUST bind, directly or transitively, to the semantic equivalent of:

```text
actor_role
actor_instance_id
provenance_snapshot_digest
credential_equivalence_id
execution_security_domain_id
control_security_domain_id
contract_id
session_id
requirement_id
stage_order/predecessor context when enabled
stage invocation/admission identity
```

The actor-instance binding MUST come from the trusted execution/provenance authority path, not from verifier output.

A correct static actor record does not authorize evidence created under a different actor instance.

For an authority stage, the accepted authority action/decision MUST be attributable to the attested authority actor/action instance. A correct authority row in the actor map is not enough by itself.

## 11. Attestation-to-execution continuity

MGnarf MUST close the time-of-check/time-of-use gap between actor attestation and the artifact/action being accepted.

A deployment must provide one of these semantic guarantees:

1. the attested actor instance and relevant security-domain/credential bindings are immutable for the whole invocation; or
2. the host revalidates the execution-instance binding at admission and again at the required evidence/finalization boundaries, failing closed on any drift.

A pre-launch attestation followed by execution under another instance, credential equivalence class, execution security domain, control security domain, provenance revision, or authority is BLOCKED.

Restoring the old values after drift MUST NOT heal that invocation.

## 12. Revision and drift

Provenance is not a one-time startup hint.

Any semantic change to actor/provenance mappings, canonical equivalence-class resolution, provenance authority trust root, relevant authority configuration, or accepted actor-instance binding MUST produce a new revision/attestation or invalidate the prior authorization in a rollback-resistant manner.

If the host also uses MGnarf monotonic authority revision, any provenance-authority change relevant to authorization MUST advance or be bound to that authority revision so the mechanisms cannot disagree silently.

After a partial verifier chain begins:

```text
verifier A accepted
  -> provenance/authority/actor-instance binding changes
  -> verifier B requested
```

must be BLOCKED unless the entire authorization is deliberately restarted under a new frozen contract/revision.

## 13. Independence claim strength

MGnarf MUST describe only the dimensions it actually verifies.

Examples:

- Different `principal_id` values prove only principal separation.
- Different canonical `credential_equivalence_id` values prove credential-equivalence separation only according to the configured provenance authority model.
- Different canonical `execution_security_domain_id` values prove execution-domain separation only according to that authority model.
- Different canonical `control_security_domain_id` values prove declared control-plane separation only according to that authority model.
- A per-stage actor-instance attestation proves attribution only under the configured execution-attestation trust model.

MGnarf MUST NOT translate any one of these into a universal claim that verifiers are statistically, organizationally, cognitively, geographically, vendor, or failure-mode independent.

## 14. Composition with authenticated stage order

The intended composed chain is:

```text
builder execution
  -> candidate-origin attestation bound to candidate digest
  -> frozen candidate/contract
  -> authenticated atomic provenance snapshot
  -> verifier A admission
       actor-instance attested
       identity/provenance checked
       evidence bound to that instance
  -> verifier B admission
       actor-instance attested
       identity/provenance checked
       predecessor A authenticated
       evidence bound to verifier-B instance
  -> authority action
       authority instance/action attested
       predecessor B authenticated
  -> MGnarf decision
       bound to final authenticated chain head
       provenance/currentness revalidated
  -> stable operation / fencing
  -> effect
```

Provenance is an additional acceptance condition, never a replacement for existing requirement, candidate, identity, order, authority, revocation, operation or fencing checks.

## 15. No-silent-downgrade rule

Every public/composed path that accepts a provenance-attested contract MUST do one of exactly two things:

1. preserve and enforce provenance semantics end-to-end; or
2. reject the request fail closed before verifier execution.

It MUST NOT:

- strip required provenance fields;
- reinterpret a provenance-attested contract as identity-only;
- reconstruct a weaker unordered/unattested contract;
- accept an older receipt schema while ignoring required provenance;
- silently substitute verifier-supplied identity facts;
- silently reduce canonical credential/execution/control separation to friendly-name inequality;
- silently switch provenance authority/trust root;
- assemble authorization facts from multiple snapshots;
- substitute a static actor-map record for required candidate-origin or stage-execution attestation;
- reuse an actor-instance attestation across a different invocation/session/stage unless the attestation semantics explicitly authorize exactly that reuse.

## 16. Versioning

Existing released identity-only contracts retain their existing semantics.

Provenance attestation MUST use a distinct evidence/contract semantic version or an equivalently unambiguous versioned binding.

Candidate-origin attestations and per-stage execution/action attestations MUST also be versioned unambiguously and rejected by consumers that do not understand the stronger semantics.

An older gate that does not implement provenance semantics MUST reject the stronger version rather than accept it while ignoring unknown fields.

A provenance-aware wrapper MUST never emit an older identity-only contract for the same authorization request unless policy explicitly requested only legacy semantics.

## 17. Required adversarial cases

Before runtime provenance support can be called PASS, tests MUST cover at minimum:

1. same underlying credential under two principal labels when credential separation is required -> BLOCKED;
2. same execution security domain under two verifier labels when execution-domain separation is required -> BLOCKED;
3. same control security domain under two trust-domain labels when control-domain separation is required -> BLOCKED;
4. missing required provenance field -> BLOCKED;
5. malformed provenance dimension -> BLOCKED;
6. candidate attempts to self-assert provenance -> ignored/BLOCKED;
7. verifier output attempts to replace host provenance -> ignored/BLOCKED;
8. provenance receipt from another session -> BLOCKED;
9. provenance receipt from another contract -> BLOCKED;
10. provenance receipt from another candidate/state -> BLOCKED;
11. provenance receipt from another policy -> BLOCKED;
12. provenance receipt from another provenance revision -> BLOCKED;
13. provenance snapshot replaced after verifier A but before verifier B -> stale/BLOCKED;
14. provenance values drift then return to original values -> existing partial chain remains stale/BLOCKED;
15. logical identities distinct but required credential equivalence IDs equal -> BLOCKED;
16. logical identities distinct but required execution security domains equal -> BLOCKED;
17. provenance dimensions distinct but required principal IDs equal -> BLOCKED;
18. correct provenance but verifier B executes before required verifier A -> BLOCKED when stage order is enabled;
19. correct predecessor chain but provenance separation fails -> BLOCKED;
20. wrapper strips provenance requirement -> BLOCKED;
21. legacy core gate presented with stronger provenance evidence version -> rejected, never legacy PASS;
22. authority-revision wrapper preserves exact provenance binding -> PASS only while current;
23. stable-operation wrapper preserves exact provenance binding -> PASS only for the exact contract;
24. fenced-operation wrapper preserves exact provenance binding -> PASS only for the exact contract/fence;
25. replay of valid provenance under a new actor map -> BLOCKED;
26. replay of valid provenance under a new policy digest -> BLOCKED;
27. concurrency cannot admit a provenance-dependent stage while its authenticated snapshot is stale/in transition;
28. valid independently attested A -> B -> authority chain -> PASS only when all other MGnarf conditions pass;
29. final effect remains single-use and bound to the exact final authenticated decision;
30. full existing regression suite remains green and legacy contracts retain legacy semantics;
31. same underlying credential represented by two aliases -> canonicalized SAME/BLOCKED;
32. same underlying execution security domain represented by two aliases -> canonicalized SAME/BLOCKED;
33. same underlying control security domain represented by two aliases -> canonicalized SAME/BLOCKED;
34. same provenance map presented under a wrong/replaced provenance authority or trust root -> BLOCKED;
35. actor authorization fields mixed from multiple individually valid snapshots -> BLOCKED;
36. provenance authority cannot determine equivalence for a required dimension -> UNKNOWN/BLOCKED;
37. correct static verifier-B record, but verifier-B stage actually executes under verifier-A actor instance -> BLOCKED;
38. actor-instance attestation from another invocation/session reused for current stage -> BLOCKED;
39. attested actor instance or required security binding changes between admission and receipt -> stale/BLOCKED;
40. actor map says builder-A, but frozen candidate lacks builder-A candidate-origin attestation -> BLOCKED when builder provenance separation is required;
41. valid builder attestation for another candidate digest -> BLOCKED;
42. authority actor map is correct but accepted authority action is not attributable to that authority actor/action instance -> BLOCKED;
43. correct candidate-origin binding + correct per-stage actor-instance provenance + correct ordered chain -> eligible for PASS only when all other MGnarf conditions pass.

## 18. Non-goals

This first boundary does not prove:

- statistical independence of model errors;
- cognitive independence of two humans;
- organizational independence merely because companies differ;
- cloud-provider independence merely because provider names differ;
- resistance to compromise of the trusted host itself;
- correctness of an external provenance/execution authority beyond the configured trust model;
- that two different models or vendors are automatically independent.

Those claims require separate evidence and must not be implied by this feature.

## 19. Implementation gate

No runtime change should begin until this boundary is deliberately reviewed and accepted or amended.

The required development order is:

```text
recon exact current main
  -> freeze semantic boundary
  -> adversarial design review
  -> tests first / RED
  -> smallest runtime implementation
  -> provenance alias/tamper/replay/drift tests
  -> provenance authority/trust-root tests
  -> atomic snapshot/mix-and-match tests
  -> candidate-origin/build-attestation tests
  -> per-stage actor-instance attribution tests
  -> attestation/execution TOCTOU tests
  -> stage-order composition tests
  -> authority/stable-operation/fencing no-downgrade tests
  -> concurrency tests
  -> full regression suite
  -> independent whole-chain review
  -> exact-SHA evidence
  -> release freeze only if deliberately included
```

Until all of that exists, MGnarf documentation must say only that released identity separation relies on trusted-host actor facts according to released contract semantics. It must not claim independently attested execution/control provenance or candidate/stage attribution unless those properties have actually been implemented and verified.
