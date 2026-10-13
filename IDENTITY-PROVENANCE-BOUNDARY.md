# Identity provenance and independence attestation boundary

Status: **DESIGN FREEZE CANDIDATE — ADVERSARIAL REVISION 2 — NO RUNTIME CLAIM**

Related: #61

This document defines the semantic boundary for authenticated actor provenance and machine-enforced independence claims in MGnarf. It does not claim that the current runtime proves these properties.

Revision 2 closes the first adversarial-review gaps: provenance values used for separation are canonical authority-defined security-equivalence classes rather than friendly labels; the provenance authority itself is authenticated and revision-bound; all actor provenance is committed atomically in one snapshot; and unknown equivalence fails closed.

## 1. Problem

MGnarf already separates several security questions that must remain distinct:

1. **candidate/state integrity** — the gate binds acceptance to frozen task/state/candidate facts;
2. **identity separation** — policy can require different logical principals, trust domains and verifier profiles;
3. **authenticated stage order** — ordered verifier/authority evidence can bind to its authenticated predecessor;
4. **effect admission** — the final accepted decision is revalidated and the external effect is guarded/single-use/fenced according to the selected host path.

A further question remains:

> What proves that two host-declared actors are genuinely separate along the dimensions the policy claims?

A logical identity label is not, by itself, proof of independence.

For example, two verifier routes may be labeled as different principals while sharing one underlying credential, one execution security domain, or one administrative control plane. If policy requires independence at one of those levels, MGnarf must not infer that independence from different friendly names.

## 2. Core invariant

MGnarf MUST NOT claim stronger separation than authenticated provenance evidence actually proves.

If policy requires two actors to differ on provenance dimension `D`, then the configured provenance authority must establish that their canonical security-equivalence classes for `D` are distinct:

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

Different logical labels are never automatically promoted into stronger provenance claims.

## 3. Separation of concerns

This boundary is separate from existing identity separation and stage ordering.

### Identity separation answers

```text
Are the actor facts required by policy distinct?
```

### Provenance attestation answers

```text
What authenticated security-equivalence classes do those actor facts actually belong to?
```

### Stage ordering answers

```text
Did the required authenticated actor stages execute in the required predecessor order?
```

All three may be required simultaneously.

A correct ordered chain with false independence claims is BLOCKED.
A correctly attested set of independent actors in the wrong required order is BLOCKED.
A correct identity/provenance/order chain with stale candidate/state/effect bindings is BLOCKED.

## 4. Trust boundary

Provenance facts MUST originate outside candidate/verifier control.

Acceptable sources are host-owned authority mechanisms such as:

- a trusted-host execution registry;
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
- model-generated claims such as `I am verifier B`;
- process arguments supplied by untrusted code;
- timestamps alone.

## 5. Canonical provenance dimensions

The design uses explicit dimensions instead of one overloaded `independent=true` bit.

Candidate dimensions include:

- `principal_id` — authenticated logical actor identity;
- `credential_equivalence_id` — canonical authority-defined equivalence class for the underlying credential/signing/service identity relevant to the policy;
- `execution_security_domain_id` — canonical authority-defined equivalence class for the execution/worker/runtime security boundary;
- `control_security_domain_id` — canonical authority-defined equivalence class for the administrative/control-plane authority boundary;
- `trust_domain` — existing logical trust boundary used by MGnarf identity policy;
- `verifier_profile` — frozen verifier/model/toolchain profile where applicable.

A provenance field used for separation MUST NOT be a mere display label. Its authority must define what equality means at the security boundary.

If two aliases resolve to the same underlying security boundary, they MUST resolve to the same canonical equivalence identifier.

If the authority cannot determine whether two aliases share an underlying security boundary, the result is `UNKNOWN` and the required separation is BLOCKED.

Not every policy needs every field. A deployment MAY implement a smaller authenticated field set, but it MUST reject any policy that requires a dimension it cannot establish canonically.

## 6. Policy model

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

The frozen semantic rule is: each required separation dimension must be backed by authenticated canonical provenance, and missing/unknown required provenance fails closed.

## 7. Provenance authority and atomic snapshot

Before any provenance-dependent verifier stage is admitted, the trusted host MUST have one authenticated provenance snapshot covering all actor facts needed by the frozen policy.

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

`provenance_authority_id` identifies the authority namespace. `provenance_authority_trust_root_id` identifies the configured trust root or equivalent host trust anchor for that authority. A same-looking actor map from a different authority/trust root is not automatically the same trust statement.

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

## 8. Revision and drift

Provenance is not a one-time startup hint.

Any semantic change to actor/provenance mappings, canonical equivalence-class resolution, provenance authority trust root, or relevant authority configuration MUST produce a new provenance revision or otherwise invalidate the prior snapshot in a rollback-resistant manner.

If the host also uses MGnarf monotonic authority revision, any provenance-authority change relevant to authorization MUST advance or be bound to that authority revision so the two mechanisms cannot disagree silently.

After a partial verifier chain begins:

```text
verifier A accepted
  -> provenance/authority changes
  -> verifier B requested
```

must be BLOCKED unless the entire authorization is deliberately restarted under a new frozen contract/revision.

Restoring the previous visible values later MUST NOT heal the stale partial chain.

## 9. Actor binding

Runtime verifier producers MUST NOT select or overwrite their own trusted provenance.

A verifier may be launched with host-known identity metadata, but accepted provenance used for policy evaluation must come from the authenticated host authority path, not from producer-returned evidence.

The gate MUST compare the authenticated actor provenance from the exact committed snapshot against the frozen policy expectations before accepting provenance-dependent evidence.

No actor field used for authorization may be substituted from a second otherwise-valid snapshot after this comparison.

## 10. Independence claim strength

MGnarf MUST describe only the dimensions it actually verifies.

Examples:

- Different `principal_id` values prove only principal separation.
- Different canonical `credential_equivalence_id` values prove credential-equivalence separation only according to the configured provenance authority model.
- Different canonical `execution_security_domain_id` values prove execution-domain separation only according to that authority model.
- Different canonical `control_security_domain_id` values prove declared control-plane separation only according to that authority model.

MGnarf MUST NOT translate any one of these into a universal claim that verifiers are statistically, organizationally, cognitively, geographically, vendor, or failure-mode independent.

## 11. Composition with authenticated stage order

The intended composed chain is:

```text
frozen builder/candidate state
  -> authenticated atomic provenance snapshot
  -> verifier A
       identity/provenance checked
       evidence authenticated
  -> verifier B
       identity/provenance checked
       predecessor A authenticated
  -> authority
       identity/provenance checked
       predecessor B authenticated
  -> MGnarf decision
       bound to final authenticated chain head
  -> stable operation / fencing
  -> effect
```

Provenance is an additional acceptance condition, never a replacement for existing requirement, candidate, identity, order, authority, revocation, operation or fencing checks.

## 12. No-silent-downgrade rule

Every public/composed path that accepts a provenance-attested contract MUST do one of exactly two things:

1. preserve and enforce the provenance semantics end-to-end; or
2. reject the request fail closed before verifier execution.

It MUST NOT:

- strip required provenance fields;
- reinterpret a provenance-attested contract as identity-only;
- reconstruct a weaker unordered/unattested contract;
- accept an older receipt schema while ignoring required provenance;
- silently substitute verifier-supplied identity facts;
- silently reduce a required canonical credential/execution/control separation rule to friendly-name inequality;
- silently switch provenance authority/trust root;
- assemble authorization facts from multiple snapshots.

## 13. Versioning

Existing released identity-only contracts retain their existing semantics.

Provenance attestation MUST use a distinct evidence/contract semantic version or an equivalently unambiguous versioned binding.

An older gate that does not implement provenance semantics MUST reject the stronger version rather than accept it while ignoring unknown fields.

A provenance-aware wrapper MUST never emit an older identity-only contract for the same authorization request unless policy explicitly requested only legacy semantics.

## 14. Required adversarial cases

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
31. same underlying credential represented by two different aliases -> canonicalized SAME/BLOCKED;
32. same underlying execution security domain represented by two aliases -> canonicalized SAME/BLOCKED;
33. same underlying control security domain represented by two aliases -> canonicalized SAME/BLOCKED;
34. same provenance map presented under a wrong/replaced provenance authority or trust root -> BLOCKED;
35. actor authorization fields mixed from multiple individually valid snapshots -> BLOCKED;
36. provenance authority cannot determine equivalence for a required dimension -> UNKNOWN/BLOCKED.

## 15. Non-goals

This first boundary does not prove:

- statistical independence of model errors;
- cognitive independence of two humans;
- organizational independence merely because companies differ;
- cloud-provider independence merely because provider names differ;
- resistance to compromise of the trusted host itself;
- correctness of an external provenance authority beyond the configured trust model;
- that two different models or vendors are automatically independent.

Those claims require separate evidence and must not be implied by this feature.

## 16. Implementation gate

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
  -> stage-order composition tests
  -> authority/stable-operation/fencing no-downgrade tests
  -> concurrency tests
  -> full regression suite
  -> independent whole-chain review
  -> exact-SHA evidence
  -> release freeze only if deliberately included
```

Until all of that exists, MGnarf documentation must say only that released identity separation relies on trusted-host actor facts according to the released contract semantics. It must not claim independently attested execution/control provenance unless that evidence has actually been implemented and verified.
