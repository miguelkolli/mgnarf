# Identity provenance and independence attestation boundary

Status: **DESIGN FREEZE CANDIDATE — ADVERSARIAL REVISION 6 — NO RUNTIME CLAIM**

Related: #61

This document defines the semantic boundary for authenticated actor provenance and machine-enforced independence claims in MGnarf. It does not claim that the current runtime proves these properties.

Revision history:

- Revision 2: canonical security-equivalence classes, authenticated provenance authority, atomic actor map, `UNKNOWN -> BLOCKED`.
- Revision 3: candidate-origin attribution and runtime actor-instance attribution.
- Revision 4: acyclic pre-contract/contract provenance graph and pre-effect currentness.
- Revision 5: linearized stage/effect admission under concurrent provenance changes.
- Revision 6: explicit per-stage admission/completion state machine; pre-execution admission evidence is separated from post-execution result attribution.

## 1. Security claim

MGnarf MUST NOT claim stronger separation, attribution, or currentness than authenticated provenance evidence proves.

For a policy-required provenance dimension `D`, the configured provenance authority resolves actor equivalence as:

```text
SAME      -> separation fails
DISTINCT  -> separation may pass
UNKNOWN   -> BLOCKED
```

Friendly names, aliases, timestamps, model claims, verifier-returned identity fields, and candidate-controlled environment/process data are never provenance proof.

Every provenance-sensitive candidate, verifier result, and authority action must be attributable to the exact attested producer instance. Provenance must also be current at the linearized admission point for every provenance-dependent stage and for the final effect.

## 2. Canonical provenance dimensions

A deployment may support any explicit subset, but a required unsupported/unknown dimension is BLOCKED.

Typical dimensions:

- `principal_id` — authenticated logical actor identity;
- `credential_equivalence_id` — canonical security-equivalence class for the relevant credential/service identity;
- `execution_security_domain_id` — canonical worker/runtime security domain;
- `control_security_domain_id` — canonical administrative/control-plane domain;
- `trust_domain` — logical trust domain;
- `verifier_profile` — frozen verifier/model/toolchain profile where applicable.

If two aliases map to the same underlying boundary, they MUST resolve to the same canonical equivalence identifier. If the authority cannot establish equivalence, the result is `UNKNOWN`.

## 3. Policy semantics

Policy expresses pairwise separation over explicit dimensions, for example:

```json
{
  "separation": [
    ["builder", "verifier:tests", "credential_equivalence_id"],
    ["verifier:tests", "verifier:security", "execution_security_domain_id"],
    ["verifier:tests", "verifier:security", "control_security_domain_id"],
    ["verifier:security", "authority", "principal_id"]
  ]
}
```

Different logical IDs never imply stronger separation automatically.

## 4. Trust boundary

Trusted provenance must originate outside candidate/verifier control through a configured host-owned or authenticated external authority path, such as an execution attester, host registry, credential mapping, or identity/provenance probe.

The provenance authority/trust root is itself part of the trust model. MGnarf does not claim correctness beyond that configured trust root.

## 5. Authenticated provenance objects

The model uses five authenticated object classes. None may silently substitute for another.

### A — authority-state snapshot

Pre-contract canonical actor provenance under one authority state.

A binds the semantic equivalent of:

```text
provenance_authority_id
provenance_authority_trust_root_id
provenance_schema_version
provenance_revision
canonical_actor_provenance_map
provenance_map_digest
```

A must have rollback-resistant currentness semantics sufficient for the deployment claim.

### B — candidate-origin/build attestation

Required when policy makes a provenance separation claim involving `builder`.

B binds:

```text
candidate_sha256
builder_role
builder_actor_instance_id
builder canonical provenance from A
A digest / provenance_map_digest
provenance authority/root/revision
build_attestation_id
```

B must be produced from the actual builder execution/output relationship by the trusted attestation path. A later registry lookup cannot retroactively prove candidate origin.

### C — contract-bound provenance binding

Created after the ordinary MGnarf contract is frozen.

C binds:

```text
contract_id
candidate_sha256
task/policy/state commitments
identity/provenance policy digest
A digest / provenance_map_digest
provenance authority/root/revision
B digest when builder provenance is required
stage_order digest when enabled
MGnarf authority revision when enabled
```

C is the provenance root for session/stage/effect authorization. After C exists, no wrapper/stage may silently select another A or B.

### D1 — stage-admission attestation/reservation

Created before producer entry for one exact provenance-dependent verifier/authority invocation.

D1 binds:

```text
C digest / provenance binding id
contract_id
session_id
requirement_id / authority-action id
actor_role
actor_instance_id
canonical actor provenance from A
A provenance revision/currentness observation
stage-order predecessor context when enabled
unique invocation/admission id
```

D1 is created only after the linearized stage-admission checks succeed. It is host/attester owned and is never verifier-generated PASS evidence.

### D2 — stage-completion/result attestation

Created only after the producer/action completes for an admitted D1.

D2 binds:

```text
D1 id/digest
same contract/session/stage/invocation
same actor instance
produced verifier evidence/action digest
execution-continuity result
completion disposition
```

A D2 without its exact prior D1 is invalid. D2 from one D1 cannot satisfy another invocation.

## 6. Acyclic object graph

```text
A authority-state snapshot
  -> builder execution
  -> B candidate-origin attestation
  -> candidate/task/state freeze
  -> contract
  -> C contract provenance binding
  -> D1 stage admission
  -> producer/action
  -> D2 stage completion
  -> next ordered stage D1/D2 ...
  -> final decision
  -> stable operation / fence
  -> effect admission
  -> effect
```

No object is allowed to depend on evidence that can only exist later in the graph.

## 7. Linearized stage admission

Every provenance-dependent stage has one host-owned admission linearization point before producer entry.

At that point the host atomically, or with an equivalent single-winner reservation/fencing protocol:

```text
validates exact C
validates current A authority/root/revision/currentness
validates required separation for this actor/stage
validates actor-instance identity/provenance
validates ordered predecessor state when enabled
reserves one unique D1 invocation
```

Semantics:

- provenance transition linearizes first -> D1 not created; producer not entered;
- D1 reservation linearizes first under valid provenance -> producer may run;
- duplicate/re-entrant attempts -> at most one D1 admission for the exact stage slot/invocation policy;
- later provenance drift makes subsequent/final authorization stale according to currentness rules.

This admission MUST compose with the existing stage-order in-flight reservation, not create a contradictory second ordering mechanism.

## 8. Stage completion, crash and retry

D1 is not PASS evidence by itself. A stage becomes eligible for acceptance only with its valid D2 and all existing MGnarf checks.

If the producer crashes/fails after D1 but before D2:

- that D1 is terminally failed/aborted for the exact invocation;
- retry uses a fresh invocation/admission id and fresh currentness checks;
- late D2 for the abandoned D1 cannot satisfy the retry;
- duplicate completion for one D1 yields at most one accepted completion;
- no D1/D2 combination may be spliced across invocations.

If provenance changes after D1 but before D2, D2 may record that the execution completed, but the resulting chain is stale/BLOCKED for later authorization unless the configured semantics explicitly establish unchanged valid provenance through completion.

## 9. Attestation-to-execution continuity

A deployment must guarantee either:

1. actor instance and relevant credential/security-domain bindings are immutable for the invocation; or
2. they are revalidated at required completion/finalization boundaries.

A stage admitted under one actor/security binding but completed under another is BLOCKED/stale. Drift followed by restoration does not heal the invocation when monotonic revision semantics observed the transition.

## 10. Stage-order composition

When authenticated stage ordering is enabled:

```text
D2(stage n)
  -> authenticated stage evidence/chain head for n
  -> D1(stage n+1) validates that predecessor
```

Identity/provenance separation and predecessor ordering are independent conditions. Correct provenance cannot repair wrong order; correct order cannot repair failed provenance separation.

## 11. Revision, revocation and drift

Changes to actor mappings, canonical equivalence resolution, provenance authority/root, relevant authority configuration, revocation state, or accepted actor-instance binding must advance/invalidate provenance state in a rollback-resistant manner.

If MGnarf monotonic authority revision is enabled, provenance state must be bound so the two authority mechanisms cannot silently disagree.

Required currentness/revocation data unavailable -> BLOCKED.

## 12. Final decision binding

A provenance-enabled final decision MUST bind, directly or transitively through the authenticated stage chain, to:

```text
C
required B
all required accepted D1/D2 stage pairs
final authenticated stage-order chain head when enabled
```

Stable-operation, authority-revision and fencing wrappers must preserve that exact stronger decision. They may not reconstruct a weaker authorization.

## 13. Linearized effect admission

The external effect boundary has one effect-admission linearization point.

At that point the trusted path atomically, or with equivalent compare-and-reserve/fencing semantics:

```text
validates exact contract / final decision / C relationship
validates A authority id + trust root
validates A provenance revision/currentness
validates required provenance revocation/currentness
validates existing MGnarf state/revocation/authority conditions
validates stable-operation/fence relationship
reserves/consumes the single-use effect authorization
```

Semantics:

- provenance transition linearizes first -> effect BLOCKED;
- effect reservation linearizes first under valid provenance -> one effect admitted;
- later provenance change does not retroactively undo an already-started effect unless the target supports rollback/cancellation;
- concurrent duplicate effect attempts -> at most one admission;
- an issued fence is not a provenance override.

The exact claim is:

> provenance is current at the linearized effect-admission point.

## 14. No-silent-downgrade rule

Every provenance-enabled public/composed path must preserve/enforce provenance end-to-end or reject fail closed.

It MUST NOT:

- strip provenance fields;
- reinterpret provenance authorization as legacy identity-only;
- reduce canonical domain separation to label inequality;
- switch authority/trust root;
- mix A snapshots;
- substitute A for required B/D1/D2;
- splice D1/D2 across invocations;
- ignore stronger evidence versions;
- omit C/currentness checks in stable-operation/fencing/effect paths;
- split currentness and admission reservation into unordered race-prone checks.

## 15. Versioning

Existing identity-only contracts retain existing semantics.

A/B/C/D1/D2 and the stronger contract/binding path require unambiguous semantic versions. Older consumers that do not understand them MUST reject them, never ignore unknown fields and continue as legacy PASS.

## 16. Claim strength / non-goals

MGnarf may claim only the dimensions the configured authority model establishes. It does not automatically prove statistical, cognitive, organizational, geographic, vendor, or failure-mode independence.

This boundary also does not prove resistance to compromise of the trusted host/provenance root itself, nor revoke an already-admitted external effect when the target cannot roll it back.

## 17. Required adversarial coverage

Before runtime provenance support can be called PASS, tests must cover at minimum:

1. aliasing of same underlying credential/execution/control boundary -> SAME/BLOCKED;
2. required equivalence UNKNOWN/missing/malformed -> BLOCKED;
3. self-asserted candidate/verifier provenance -> ignored/BLOCKED;
4. replay across session/contract/candidate/policy/revision -> BLOCKED;
5. wrong/replaced provenance authority/root -> BLOCKED;
6. mix actor fields from different A snapshots -> BLOCKED;
7. builder provenance required but B absent -> BLOCKED;
8. B for wrong candidate/A/revision -> BLOCKED;
9. C binds A/B/candidate inconsistently -> BLOCKED;
10. correct static actor record but actual stage actor instance differs -> BLOCKED;
11. D1 absent, D2/evidence appears -> BLOCKED;
12. D2 from invocation X attached to D1 Y -> BLOCKED;
13. producer crash after D1, retry gets new D1, late old D2 arrives -> old D2 BLOCKED;
14. duplicate D2 race for one D1 -> at most one accepted completion;
15. provenance changes after D1 before D2 -> later authorization stale/BLOCKED as required;
16. provenance transition races D1 and transition linearizes first -> producer not entered;
17. D1 linearizes first, provenance changes later -> chain cannot reach later/final authorization under stale provenance;
18. authenticated stage order wrong despite correct provenance -> BLOCKED;
19. provenance separation wrong despite correct stage order -> BLOCKED;
20. wrapper strips/downgrades provenance -> BLOCKED;
21. legacy gate receives stronger evidence version -> reject, never legacy PASS;
22. final decision missing required B/D1/D2/C binding -> BLOCKED;
23. provenance changes after final decision/fence but before effect admission -> BLOCKED;
24. provenance drift/restore before effect -> old authorization remains stale when transition was observed;
25. authority/root replacement before effect -> BLOCKED;
26. currentness/revocation unavailable at effect admission -> BLOCKED;
27. provenance transition races effect admission and transition wins -> BLOCKED;
28. effect admission wins under valid provenance then provenance changes -> no second effect; admitted effect not retroactively reclassified;
29. concurrent duplicate effects -> at most one admission;
30. correct A -> B -> contract -> C -> D1 -> producer -> D2 sequence -> eligible only if all existing MGnarf checks pass;
31. full existing regression suite remains green and legacy semantics remain unchanged.

## 18. Implementation gate

No runtime change should begin until this boundary is deliberately reviewed and accepted or amended.

Required sequence:

```text
recon exact current main
  -> design/adversarial freeze
  -> tests first / RED
  -> smallest implementation
  -> canonical equivalence tests
  -> A authority/root/rollback tests
  -> B candidate-origin tests
  -> C contract-binding/bootstrap tests
  -> D1 admission linearization tests
  -> D2 completion/splice/crash/retry tests
  -> execution continuity tests
  -> stage-order composition tests
  -> final decision provenance-binding tests
  -> effect admission/provenance-race tests
  -> wrapper no-downgrade tests
  -> full regression suite
  -> independent whole-chain review
  -> exact-SHA evidence
  -> release freeze only if deliberately included
```

Until then, released MGnarf documentation must not claim independently attested candidate/stage provenance or provenance-current effect admission.
