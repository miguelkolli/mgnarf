# Identity provenance and independence attestation boundary

Status: **DESIGN FREEZE CANDIDATE — NO RUNTIME CLAIM**

Related: #61

This document defines the semantic boundary for authenticated actor provenance and machine-enforced independence claims in MGnarf. It does not claim that the current runtime proves these properties.

## 1. Problem

MGnarf already separates several security questions that must remain distinct:

1. **candidate/state integrity** — the gate binds acceptance to frozen task/state/candidate facts;
2. **identity separation** — policy can require different logical principals, trust domains and verifier profiles;
3. **authenticated stage order** — ordered verifier/authority evidence can bind to its authenticated predecessor;
4. **effect admission** — the final accepted decision is revalidated and the external effect is guarded/single-use/fenced according to the selected host path.

A further question remains:

> What proves that two host-declared actors are genuinely separate along the dimensions the policy claims?

A logical identity label is not, by itself, proof of independence.

For example, two verifier routes may be labeled as different principals while sharing one API credential, one execution identity, or one administrative control plane. If a policy requires independence at one of those levels, MGnarf must not infer that independence merely from different friendly names.

## 2. Core invariant

MGnarf MUST NOT claim stronger separation than the authenticated provenance evidence actually proves.

If policy requires two actors to differ on provenance dimension `D`, then:

```text
authenticated_provenance(actor_A, D)
!=
authenticated_provenance(actor_B, D)
```

must hold for the exact frozen contract semantic class.

If either value is missing, unauthenticated, stale, from another contract/session/candidate/policy, or writable by candidate/verifier code, the requirement is BLOCKED.

Different logical IDs are never automatically promoted into stronger provenance claims.

## 3. Separation of concerns

This boundary is separate from existing identity separation and stage ordering.

### Identity separation answers

```text
Are the actor facts required by policy distinct?
```

### Provenance attestation answers

```text
Where did those actor facts come from, and what execution/control boundary do they actually prove?
```

### Stage ordering answers

```text
Did the required authenticated actor stages execute in the required predecessor order?
```

All three may be required simultaneously.

A correct ordered chain with fake independence claims is BLOCKED.
A correctly attested set of independent actors in the wrong required order is BLOCKED.
A correct identity/provenance/order chain with stale candidate/state/effect bindings is BLOCKED.

## 4. Trust boundary

Provenance facts MUST originate outside candidate/verifier control.

Acceptable sources are host-owned authority mechanisms such as:

- a trusted-host execution registry;
- an authenticated identity/provenance probe;
- a host-owned credential mapping;
- an authenticated external authority whose result is frozen or revision-bound by the host.

The exact provider-specific mechanism is outside this generic boundary.

The following MUST NOT be treated as provenance proof on their own:

- verifier output fields;
- candidate output fields;
- environment variables writable by the candidate/verifier;
- friendly actor names;
- model-generated claims such as `I am verifier B`;
- process arguments supplied by untrusted code;
- timestamps alone.

## 5. Provenance dimensions

The first design uses explicit dimensions instead of one overloaded `independent=true` bit.

Candidate dimensions include:

- `principal_id` — logical authenticated actor identity;
- `credential_id` — authenticated credential/key/service identity class used to invoke the actor;
- `execution_domain` — authenticated execution identity or worker/runtime security domain;
- `control_domain` — authenticated administrative/control-plane authority domain;
- `trust_domain` — existing logical trust boundary used by MGnarf identity policy;
- `verifier_profile` — frozen verifier/model/toolchain profile where applicable.

Not every policy needs every field.

A deployment MAY implement a smaller authenticated field set, but it MUST reject any policy that requires a dimension it cannot establish.

## 6. Policy model

The policy continues to express explicit pairwise separation requirements.

Conceptually:

```json
{
  "actors": {
    "builder": {
      "principal_id": "builder-A",
      "credential_id": "cred-build-01",
      "execution_domain": "runner-build",
      "control_domain": "org-build",
      "trust_domain": "build-domain"
    },
    "verifier:tests": {
      "principal_id": "verify-tests-A",
      "credential_id": "cred-tests-02",
      "execution_domain": "runner-verify-A",
      "control_domain": "org-verify-A",
      "trust_domain": "verify-domain-A"
    },
    "verifier:security": {
      "principal_id": "verify-sec-B",
      "credential_id": "cred-sec-03",
      "execution_domain": "runner-verify-B",
      "control_domain": "org-verify-B",
      "trust_domain": "verify-domain-B"
    },
    "authority": {
      "principal_id": "authority-H",
      "credential_id": "cred-auth-04",
      "execution_domain": "authority-host",
      "control_domain": "human-policy-domain",
      "trust_domain": "authority-domain"
    }
  },
  "separation": [
    ["builder", "verifier:tests", "principal_id"],
    ["builder", "verifier:tests", "credential_id"],
    ["verifier:tests", "verifier:security", "execution_domain"],
    ["verifier:tests", "verifier:security", "control_domain"],
    ["verifier:security", "authority", "principal_id"]
  ]
}
```

The exact serialized schema may evolve before implementation.

The semantic rule is frozen here: each required separation dimension must be backed by authenticated provenance, and missing required provenance fails closed.

## 7. Provenance snapshot

Before any provenance-dependent verifier stage is admitted, the trusted host MUST have an authenticated provenance snapshot covering all actor facts needed by the frozen policy.

The snapshot MUST bind, directly or transitively through authenticated host receipts, to the exact:

- contract ID;
- policy digest;
- candidate/state semantic class;
- actor map;
- provenance map;
- provenance schema/version;
- authority revision when monotonic authority revision is enabled.

If stage ordering is enabled, the provenance requirement is part of the exact ordered contract semantic class and must not be silently dropped by an unordered wrapper.

## 8. Revision and drift

Provenance is not a one-time startup hint.

If the host supports monotonic authority revision, any change to actor/provenance authority MUST advance the authority revision.

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

A verifier may be launched with host-known identity metadata, but the accepted provenance used for policy evaluation must come from the authenticated host authority path, not from producer-returned evidence.

The gate MUST compare the host-authenticated actor provenance against the exact frozen policy expectations before accepting provenance-dependent evidence.

## 10. Independence claim strength

MGnarf MUST describe only the dimensions it actually verifies.

Examples:

- Different `principal_id` values prove only principal separation.
- Different `credential_id` values prove credential separation only if the credential IDs are host-authenticated.
- Different `execution_domain` values prove execution-domain separation only according to the trusted host's execution-domain authority model.
- Different `control_domain` values prove declared control-plane separation only according to the configured authority model.

MGnarf MUST NOT translate any one of these into a universal claim that the verifiers are statistically, organizationally, cognitively, or vendor-independent.

## 11. Composition with authenticated stage order

The intended composed chain is:

```text
frozen builder/candidate state
  -> authenticated provenance snapshot
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
- silently reduce a required dimension from credential/execution/control separation to principal-name separation.

## 13. Versioning

Existing released identity-only contracts retain their existing semantics.

Provenance attestation MUST use a distinct evidence/contract semantic version or an equivalently unambiguous versioned binding.

An older gate that does not implement provenance semantics MUST reject the stronger version rather than accept it while ignoring unknown fields.

A provenance-aware wrapper MUST never emit an older identity-only contract for the same authorization request unless policy explicitly requested only legacy semantics.

## 14. Required adversarial cases

Before runtime provenance support can be called PASS, tests MUST cover at minimum:

1. same credential under two principal labels when credential separation is required -> BLOCKED;
2. same execution domain under two verifier labels when execution-domain separation is required -> BLOCKED;
3. same control domain under two trust-domain labels when control-domain separation is required -> BLOCKED;
4. missing required provenance field -> BLOCKED;
5. malformed provenance dimension -> BLOCKED;
6. candidate attempts to self-assert provenance -> ignored/BLOCKED;
7. verifier output attempts to replace host provenance -> ignored/BLOCKED;
8. provenance receipt from another session -> BLOCKED;
9. provenance receipt from another contract -> BLOCKED;
10. provenance receipt from another candidate/state -> BLOCKED;
11. provenance receipt from another policy -> BLOCKED;
12. provenance receipt from another authority revision -> BLOCKED;
13. provenance snapshot replaced after verifier A but before verifier B -> stale/BLOCKED;
14. provenance values drift then return to original values -> existing partial chain remains stale/BLOCKED;
15. logical identities distinct but required credential IDs equal -> BLOCKED;
16. logical identities distinct but required execution domains equal -> BLOCKED;
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
30. full existing regression suite remains green and legacy contracts retain legacy semantics.

## 15. Non-goals

This first boundary does not prove:

- statistical independence of model errors;
- cognitive independence of two humans;
- organizational independence merely because companies differ;
- cloud-provider independence merely because provider names differ;
- resistance to compromise of the trusted host itself;
- correctness of an external identity provider beyond the configured trust model;
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
  -> provenance tamper/replay/drift tests
  -> stage-order composition tests
  -> authority/stable-operation/fencing no-downgrade tests
  -> concurrency tests
  -> full regression suite
  -> independent whole-chain review
  -> exact-SHA evidence
  -> release freeze only if deliberately included
```

Until all of that exists, MGnarf documentation must say only that released identity separation relies on trusted-host actor facts according to the released contract semantics. It must not claim independently attested execution/control provenance unless that evidence has actually been implemented and verified.
