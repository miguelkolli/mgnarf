# Identity provenance and independence attestation boundary

Status: **DESIGN FREEZE CANDIDATE — ADVERSARIAL REVISION 11 — NO RUNTIME CLAIM**

Related: #61

This document defines the semantic boundary for authenticated actor provenance and machine-enforced independence claims in MGnarf. It does not claim that the current runtime proves these properties.

Revision history:

- Revision 2: canonical security-equivalence classes, authenticated provenance authority, atomic actor map, `UNKNOWN -> BLOCKED`.
- Revision 3: candidate-origin attribution and runtime actor-instance attribution.
- Revision 4: acyclic pre-contract/contract provenance graph and pre-effect currentness.
- Revision 5: linearized stage/effect admission under concurrent provenance changes.
- Revision 6: split pre-execution stage admission from post-execution completion.
- Revision 7: preserve one-attempt-per-requirement-per-session semantics.
- Revision 8: freeze acyclic `D1 -> producer result R -> D2 -> final NARF stage receipt E` construction.
- Revision 9: make provenance an explicit frozen-contract semantic opt-in.
- Revision 10: unify existing identity-policy roles with provenance roles.
- Revision 11: separate raw producer result R from the host-finalized effective stage disposition in D2/E.

## 1. Security claim

MGnarf MUST NOT claim stronger separation, attribution, or currentness than authenticated provenance evidence proves.

For a policy-required provenance dimension `D`, the configured provenance authority resolves actor equivalence as:

```text
SAME      -> separation fails
DISTINCT  -> separation may pass
UNKNOWN   -> BLOCKED
```

Friendly names, aliases, timestamps, model claims, verifier-returned identity fields, and candidate-controlled environment/process data are never provenance proof.

Every provenance-sensitive candidate, verifier result, and authority action must be attributable to the exact attested producer instance. Provenance must be current at the linearized admission point for every provenance-dependent stage and for the final effect.

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

## 3. Unified actor-role semantics

MGnarf identity-policy roles and provenance roles share one canonical namespace:

```text
builder
verifier:<id>
authority
```

For every overlapping role:

- the canonical role identifier MUST be identical;
- overlapping fields such as `principal_id`, `trust_domain`, and `verifier_profile` MUST match exactly under canonical serialization unless one explicitly frozen derivation rule defines their relation;
- verifier bindings MUST match the same unified actor record;
- authority attribution MUST use the same unified actor record;
- ambiguous or missing role mapping is BLOCKED.

A role alias MUST NOT bypass separation. If aliases canonicalize to the same actor/security identity, a rule requiring separation fails.

P MUST bind one canonical combined identity/provenance actor-role commitment, or both policy digests plus an authenticated coherence commitment that unambiguously joins them.

## 4. Policy semantics

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

## 5. Trust boundary

Trusted provenance must originate outside candidate/verifier control through a configured host-owned or authenticated external authority path, such as an execution attester, host registry, credential mapping, or identity/provenance probe.

The provenance authority/trust root is itself part of the trust model. MGnarf does not claim correctness beyond that configured trust root.

## 6. Authenticated provenance and stage objects

### A — authority-state snapshot

A is the pre-contract canonical actor-provenance state and binds:

```text
provenance_authority_id
provenance_authority_trust_root_id
provenance_schema_version
provenance_revision
canonical_actor_role_map
canonical_actor_provenance_map
provenance_map_digest
```

A MUST use the same canonical role namespace as identity policy where roles overlap and must have rollback-resistant currentness semantics sufficient for the deployment claim.

### B — candidate-origin/build attestation

B is required when policy makes a provenance separation claim involving `builder` and binds:

```text
candidate_sha256
builder canonical role
builder_actor_instance_id
builder canonical identity/provenance from A
A digest / provenance_map_digest
provenance authority/root/revision
build_attestation_id
```

B must come from the actual builder execution/output relationship through the trusted attestation path. A later registry lookup cannot retroactively prove candidate origin.

### P — frozen provenance-enabled MGnarf contract

Provenance is enabled by P itself, never by a later receipt.

P is an unambiguously stronger MGnarf contract semantic version and binds:

```text
provenance semantics/evidence version
provenance_required = true
provenance_policy_sha256
identity_policy_sha256 when identity policy is enabled
actor_role_coherence_sha256 / combined actor-policy commitment
A digest / provenance_map_digest
provenance_authority_id
provenance_authority_trust_root_id
provenance_revision
B digest when builder provenance is required
all ordinary task/candidate/state/requirements/effect commitments
stage_order digest when enabled
```

An older gate that does not understand P MUST reject it. A legacy contract cannot be upgraded to provenance semantics after freeze.

### C — contract-bound provenance binding

C is created only for an already provenance-enabled P and binds:

```text
P contract_id / exact contract digest
provenance_policy_sha256 from P
identity/provenance actor-role coherence commitment from P
A digest / provenance_map_digest exactly matching P
provenance authority/root/revision exactly matching P
B digest exactly matching P when required
stage_order digest exactly matching P when enabled
MGnarf authority revision when enabled
C evidence semantic version
```

C does not activate provenance. P does. Missing, invalid, stale, or inconsistent C blocks before stage admission.

### D1 — stage-admission attestation/reservation

D1 is created before producer entry and binds:

```text
C digest / provenance binding id
P contract_id
session_id
requirement_id / authority-action id
canonical actor_role
actor_instance_id
unified identity/provenance actor commitment
canonical actor provenance from A
A provenance revision/currentness observation
stage-order predecessor context when enabled
unique admission id
```

D1 is host/attester-owned and created only after linearized admission succeeds.

### R — raw canonical producer-result commitment

R is the canonical host representation of what the producer/action itself returned for the admitted invocation, before host post-execution continuity/currentness overrides.

For verifier stages R binds:

```text
producer_status: PASS / FAIL / BLOCKED
producer_artifact_sha256
producer_reason/result fields
result schema/version
```

For producer exception/unavailability/invalid result, R is a canonical unavailable/error result commitment. R does not include D2 or E digests and R alone is never accepted stage evidence.

### D2 — host-finalized stage-completion attestation

D2 is created after R and binds both the raw producer result and the host-finalized terminal disposition:

```text
D1 id/digest
same P/session/requirement/admission
same actor role + actor instance
R digest
execution-continuity result
post-execution state/provenance/currentness result
effective_status: PASS / FAIL / BLOCKED
effective_reason
effective_artifact_sha256
terminal completion metadata
```

Effective disposition rules:

- valid producer result + all required post-execution host/provenance checks pass -> effective disposition mirrors R;
- producer exception/unavailable/invalid result -> effective `BLOCKED` with host-owned unavailable/error reason;
- ordinary candidate/state/identity/provenance continuity failure after producer execution -> effective `BLOCKED` with host-owned reason regardless of producer PASS;
- the effective artifact digest follows the frozen runtime semantic chosen for that host failure class and MUST be deterministic/canonical; it may preserve the producer artifact digest when matching existing MGnarf semantics.

D2 MUST NOT bind E's digest if E binds D2.

### E — final authenticated MGnarf stage receipt

E is the authenticated verification/action evidence consumed by MGnarf evaluation and stage-order predecessor logic.

E binds:

```text
all existing MGnarf requirement/verifier/task/state/effect fields
P provenance semantic version / policy commitment
unified actor-role/identity/provenance commitment
R digest
C id/digest
D1 id/digest
D2 id/digest
effective_status/effective_reason/effective_artifact_sha256 exactly matching D2
stage-order predecessor fields when enabled
```

E MUST NOT expose raw R PASS as stage PASS when D2 effective disposition is BLOCKED. Ordered predecessor logic uses E and requires effective PASS.

## 7. Acyclic construction graph

```text
A authority-state snapshot
  -> builder execution
  -> B candidate-origin attestation
  -> P provenance-enabled contract freeze
  -> C exact P/A/B/coherence binding
  -> D1 stage admission
  -> producer/action
  -> raw canonical producer result R
  -> D2 continuity/currentness + effective terminal disposition
  -> final authenticated stage receipt E
  -> next ordered requirement D1 ... only after effective PASS E predecessor
  -> final decision
  -> stable operation / fence
  -> effect admission
  -> effect
```

No object may depend on evidence that can only exist later in the graph.

## 8. Contract activation and downgrade resistance

The contract is the semantic activation point.

- a provenance-enabled request MUST freeze as P, not as a legacy contract;
- P MUST declare its stronger provenance semantic/evidence version;
- P MUST commit provenance policy, actor-role coherence, and exact pre-contract A/B material required by policy;
- C MUST exactly confirm P's commitments;
- missing C for P is BLOCKED before verifier execution;
- C attached to a legacy contract cannot create a provenance claim;
- an older/legacy gate MUST reject P;
- a wrapper that cannot preserve P semantics MUST reject before producer/effect execution.

## 9. Linearized stage admission

Every provenance-dependent requirement has one host-owned admission linearization point before producer entry.

At that point the host atomically, or with equivalent single-winner reservation/fencing semantics:

```text
validates exact P + C consistency
validates unified actor-role identity/provenance coherence
validates current A authority/root/revision/currentness
validates required separation for the actor/requirement
validates verifier/authority binding against the same actor record
validates actor-instance identity/provenance
validates ordered predecessor E effective PASS when enabled
reserves exactly one D1 for this requirement in this session
```

Semantics:

- provenance transition linearizes first -> D1 not created; producer not entered;
- D1 reservation linearizes first under valid provenance -> producer runs once for that session requirement;
- duplicate/re-entrant execute attempts for the same requirement/session -> rejected;
- later provenance drift can force D2/E effective BLOCKED or make later/final authorization stale.

This MUST compose with existing ordered in-flight reservation and duplicate-requirement semantics.

## 10. Terminal completion and execution cardinality

Provenance MUST preserve the existing one-attempt-per-requirement-per-session model.

```text
producer returns -> raw R -> host continuity/currentness -> D2 effective disposition -> E
producer throws/unavailable/invalid -> unavailable R -> D2 effective BLOCKED -> E BLOCKED
```

After terminal E, that requirement is consumed for the session regardless of effective PASS/FAIL/BLOCKED.

- no second D1 for the same requirement in the same session;
- no second accepted D2/E for one D1;
- FAIL/BLOCKED does not permit same-session retry;
- producer exception does not permit same-session retry;
- a fresh-session retry, where otherwise permitted, uses fresh session+D1/R/D2/E and cannot reuse old evidence;
- provenance introduces no new retry capability.

A hard host/process crash after D1 but before terminal E leaves no PASS evidence. Orphaned D1/R/D2 fragments cannot be promoted after restart absent a separately specified authenticated recovery protocol.

## 11. Attestation-to-execution continuity

A deployment must guarantee either:

1. actor instance and relevant credential/security-domain bindings are immutable for the invocation; or
2. they are revalidated at required completion/finalization boundaries.

A requirement admitted under one actor/security binding but completed under another yields effective BLOCKED/stale. Drift followed by restoration does not heal the invocation when monotonic revision semantics observed the transition.

## 12. Stage-order composition

When authenticated stage ordering is enabled:

```text
E(stage n) with effective PASS
  -> authenticated ordered chain head for n
  -> D1(stage n+1) validates that E predecessor
```

A FAIL/BLOCKED E consumes its requirement for the session and cannot be healed by retrying it inside that session.

Correct provenance cannot repair wrong order; correct order cannot repair failed provenance separation.

## 13. Revision, revocation and drift

Changes to actor mappings, canonical role resolution, canonical equivalence resolution, provenance authority/root, relevant authority configuration, revocation state, or accepted actor-instance binding must advance/invalidate provenance state in a rollback-resistant manner.

If MGnarf monotonic authority revision is enabled, provenance state must be bound so the two mechanisms cannot silently disagree.

Required currentness/revocation data unavailable -> BLOCKED.

## 14. Final decision binding

A provenance-enabled final decision MUST bind, directly or transitively through authenticated E stage receipts, to:

```text
P
C
required B
unified actor-role coherence commitment
all required accepted D1/R/D2/E stage chains
final authenticated ordered E chain head when enabled
```

Only a complete required effective-PASS set is eligible for PASS. Stable-operation, authority-revision and fencing wrappers must preserve that exact stronger decision.

## 15. Linearized effect admission

The external effect boundary has one effect-admission linearization point.

At that point the trusted path atomically, or with equivalent compare-and-reserve/fencing semantics:

```text
validates exact P / final decision / C relationship
validates unified actor-role coherence commitment
validates A authority id + trust root
validates A provenance revision/currentness
validates required provenance revocation/currentness
validates existing MGnarf state/revocation/authority conditions
validates stable-operation/fence relationship
reserves/consumes the single-use effect authorization
```

- provenance transition linearizes first -> effect BLOCKED;
- effect reservation linearizes first under valid provenance -> one effect admitted;
- later provenance change does not retroactively undo an already-started effect unless target rollback/cancellation exists;
- concurrent duplicate effect attempts -> at most one admission;
- issued fence is not a provenance override.

The exact claim is: provenance is current at the linearized effect-admission point.

## 16. No-silent-downgrade rule

Every provenance-enabled path must preserve/enforce provenance end-to-end or reject fail closed.

It MUST NOT:

- freeze a provenance-enabled request as a legacy contract;
- attach C to a legacy contract and advertise it as provenance-attested;
- let identity policy and A resolve the same role to different actor truths;
- use role aliases to bypass separation;
- expose raw R PASS as E PASS when D2 effective disposition is BLOCKED;
- strip provenance fields;
- reinterpret P as legacy identity-only;
- reduce canonical domain separation to label inequality;
- switch authority/trust root;
- mix A snapshots;
- substitute A for required B/D1/D2/E;
- splice D1/R/D2/E across sessions/requirements;
- create a D2/E hash cycle;
- use D2 as ordered predecessor evidence when E is required;
- introduce same-session retry rejected by existing requirement semantics;
- ignore stronger evidence versions;
- omit P/C/currentness checks in stable-operation/fencing/effect paths;
- split currentness and admission reservation into unordered race-prone checks.

## 17. Versioning

Existing identity-only contracts retain existing semantics.

P is an unambiguously stronger contract semantic version. A/B/C/D1/R/D2/E require unambiguous schemas/versions as applicable. Older consumers that do not understand P MUST reject it, never ignore unknown fields and continue as legacy PASS.

## 18. Claim strength / non-goals

MGnarf may claim only the dimensions the configured authority model establishes. It does not automatically prove statistical, cognitive, organizational, geographic, vendor, or failure-mode independence.

This boundary does not prove resistance to compromise of the trusted host/provenance root itself, nor revoke an already-admitted external effect when the target cannot roll it back.

## 19. Required adversarial coverage

Before runtime provenance support can be called PASS, tests must cover at minimum:

1. aliasing of same underlying credential/execution/control boundary -> SAME/BLOCKED;
2. required equivalence UNKNOWN/missing/malformed -> BLOCKED;
3. self-asserted candidate/verifier provenance -> ignored/BLOCKED;
4. replay across session/contract/candidate/policy/revision -> BLOCKED;
5. wrong/replaced provenance authority/root -> BLOCKED;
6. mix actor fields from different A snapshots -> BLOCKED;
7. identity policy and A disagree on same-role actor facts -> BLOCKED;
8. role aliases attempt to bypass separation -> canonicalized and BLOCKED when separation required;
9. verifier binding matches one actor view but not the unified actor record -> BLOCKED;
10. builder provenance required but B absent -> BLOCKED;
11. B for wrong candidate/A/revision -> BLOCKED;
12. provenance-enabled request frozen as legacy contract then C attached -> no provenance claim/BLOCKED;
13. legacy gate receives P -> rejected, never legacy PASS;
14. P commits A1/B1 but C binds A2/B1 or A1/B2 -> BLOCKED;
15. P requires C but C missing -> BLOCKED before stage admission;
16. correct static actor record but actual stage actor instance differs -> BLOCKED;
17. D1 absent, D2/E appears -> BLOCKED;
18. D2 from requirement/session X attached to D1 Y -> BLOCKED;
19. D2 binds R1 but E binds another R -> BLOCKED;
20. raw R=PASS, provenance continuity fails before D2 -> D2 effective BLOCKED and E BLOCKED;
21. raw R=PASS, ordinary candidate/state continuity fails -> D2/E effective BLOCKED;
22. raw R=FAIL with continuity valid -> D2/E effective FAIL;
23. raw R=BLOCKED/unavailable -> D2/E effective BLOCKED;
24. D2 effective status/reason/artifact differs from E -> BLOCKED;
25. continuity passes and raw R=PASS -> D2 effective PASS and matching E eligible for predecessor use;
26. valid D2 from one D1 plus E from another D1 -> BLOCKED;
27. ordered predecessor references D2 instead of required E -> BLOCKED;
28. producer exception after D1 -> unavailable R -> D2/E effective BLOCKED; second same-session D1 rejected;
29. FAIL/BLOCKED E then same-session retry attempt -> rejected;
30. fresh-session retry, where otherwise permitted, uses fresh session+D1/R/D2/E and cannot reuse old evidence;
31. orphaned D1/R/D2 after hard crash -> never PASS and cannot be spliced into fresh session;
32. duplicate D2/E race for one D1 -> at most one accepted terminal stage receipt;
33. provenance transition races D1 and transition linearizes first -> producer not entered;
34. D1 linearizes first, provenance changes during producer -> D2/E effective BLOCKED or later chain stale according to exact currentness rule;
35. authenticated stage order wrong despite correct provenance -> BLOCKED;
36. provenance separation wrong despite correct stage order -> BLOCKED;
37. FAIL/BLOCKED predecessor E cannot be healed by same-session re-execution;
38. wrapper strips/downgrades provenance or actor-role coherence -> BLOCKED;
39. final decision missing required P/B/C/D1/R/D2/E/coherence binding -> BLOCKED;
40. provenance changes after final decision/fence but before effect admission -> BLOCKED;
41. provenance drift/restore before effect -> old authorization stale when transition observed;
42. authority/root replacement before effect -> BLOCKED;
43. currentness/revocation unavailable at effect admission -> BLOCKED;
44. provenance transition races effect admission and transition wins -> BLOCKED;
45. effect admission wins under valid provenance then provenance changes -> no second effect; admitted effect not retroactively reclassified;
46. concurrent duplicate effects -> at most one admission;
47. exact D1 -> R -> D2 -> E construction is acyclic and internally consistent;
48. exact A -> B -> P -> C -> D1 -> R -> D2 -> E sequence -> eligible only if all existing MGnarf checks pass;
49. provenance path preserves existing duplicate-requirement and ordered-PASS-prefix semantics;
50. full existing regression suite remains green and legacy semantics remain unchanged.

## 20. Implementation gate

No runtime change should begin until this boundary is deliberately reviewed and accepted or amended.

Required sequence:

```text
recon exact current main + stage-order candidate semantics
  -> design/adversarial freeze
  -> tests first / RED
  -> smallest implementation
  -> unified actor-role/coherence tests
  -> P contract opt-in / legacy-rejection tests
  -> canonical equivalence tests
  -> A authority/root/rollback tests
  -> B candidate-origin tests
  -> C exact P/A/B/coherence binding tests
  -> D1 admission linearization tests
  -> raw R canonical-result tests
  -> D2 effective-disposition/continuity tests
  -> E final-receipt binding/no-cycle tests
  -> one-attempt/crash/orphan tests
  -> stage-order effective-PASS E-chain composition tests
  -> final decision provenance-binding tests
  -> effect admission/provenance-race tests
  -> wrapper no-downgrade tests
  -> full regression suite
  -> independent whole-chain review
  -> exact-SHA evidence
  -> release freeze only if deliberately included
```

Until then, released MGnarf documentation must not claim independently attested candidate/stage provenance or provenance-current effect admission.
