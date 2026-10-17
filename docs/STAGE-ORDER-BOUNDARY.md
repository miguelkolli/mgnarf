# Authenticated stage-order boundary

Status: **DESIGN FREEZE CANDIDATE — ADVERSARIAL REVISION 3 — NO RUNTIME PASS CLAIM IN THIS DOCUMENT**

This document defines the security boundary for optional authenticated stage ordering in MGnarf. It does not itself claim that any runtime revision has passed the required acceptance gate.

Revision 2 removed verifier-role ambiguity, closed unordered-required-stage bypass, defined the chain root and final chain-head binding, and required atomic stage admission against concurrent execution. Revision 3 adds an explicit no-downgrade composition rule for authority revision, stable operation, fenced-effect and convenience-wrapper paths.

## 1. Problem

Identity separation answers **who** produced required evidence and whether required actors are independent under the frozen policy.

It does not by itself answer **whether required verification stages were accepted in the required causal order**.

The intended chain may be:

```text
builder / frozen candidate state
  -> verifier requirement A
  -> independent verifier requirement B
  -> authority requirement
  -> MGnarf decision
  -> effect
```

Without an explicit ordering primitive, all required verifier and authority evidence can be valid while having been produced in another sequence.

Timestamps are insufficient as the security primitive. Clocks can disagree, move backwards, collide, be absent, or be controlled by a weaker trust domain than the authenticated evidence.

## 2. Stage identity: requirement_id, not verifier role

The first implementation MUST identify ordered stages by frozen `requirement_id`.

It MUST NOT identify stages only by `verifier_id`, `verifier:<id>` role, principal, or authority role.

Reason: a frozen contract may contain distinct requirements that use the same logical verifier route. A verifier role therefore does not uniquely identify the evidence item that the next stage must depend on.

Example:

```text
Requirement("lint",     "ci", "1")
Requirement("unit",     "ci", "1")
Requirement("security", "review", "1")
```

The safe order is expressed as:

```json
{
  "stage_order": ["lint", "unit", "security"]
}
```

not as:

```text
verifier:ci -> verifier:ci -> verifier:review
```

Identity policy remains a separate mapping from each verifier route to its authenticated actor role.

## 3. First-version scope: one complete linear chain

The first implementation supports exactly one linear ordering over the complete frozen requirement set.

When stage ordering is enabled:

```text
set(stage_order) == set(frozen requirement_id values)
len(stage_order) == len(frozen requirements)
```

Therefore `stage_order` MUST be a permutation of every frozen requirement exactly once.

The contract MUST reject:

- unknown requirement IDs;
- duplicate stages;
- omitted frozen requirements;
- extra stages;
- empty ordering when requirements exist;
- malformed ordering syntax;
- ordering policy present but omitted from authenticated contract binding.

This deliberately avoids a first-version ambiguity where some required checks are ordered and other equally required checks can execute anywhere. Partial orders, parallel branches, optional stages, and predecessor graphs are future features with separate security semantics.

## 4. Builder is the authenticated chain seed, not a verifier stage

The builder is not represented as a verifier receipt in the current reference gate. Its output is represented by the frozen contract, task, candidate/state digests, requirements/policy digests, and optional authenticated builder identity facts.

Therefore the ordered verifier chain begins from a deterministic chain seed derived from trusted frozen/session context rather than from a synthetic builder receipt.

Conceptually:

```text
chain_seed = H(
  domain,
  contract_id,
  session_id,
  stage_order_digest,
  frozen task/state/requirements/policy binding
)
```

The exact domain-separated encoding must be canonical and frozen before implementation.

The first stage evidence MUST bind to this chain seed.

This establishes:

```text
frozen builder/candidate context
  -> first required verification evidence
```

without pretending that MGnarf has authenticated a builder execution event it does not actually observe.

## 5. Core causal invariant

For ordered stages `S[0] ... S[n]`:

```text
accepted(S[0])
  requires
chain_seed_binding(S[0]) == expected_chain_seed
```

and for every later stage:

```text
accepted(S[i]) for i > 0
  requires
predecessor_id(S[i]) == evidence_id(S[i-1])
AND
predecessor_digest(S[i]) == canonical_authenticated_digest(S[i-1])
```

The predecessor receipt MUST authenticate successfully before a dependent producer is invoked.

The digest MUST be computed from the canonical authenticated evidence payload selected by the gate, not from candidate-, worker-, or verifier-supplied predecessor bytes.

A later stage never becomes valid merely because a missing predecessor appears afterwards.

Therefore:

```text
produced B-before-A + later A != valid A -> B chain
```

However, an **early rejected invocation** is different from produced evidence: if B is requested before A, the gate should reject before invoking B's producer and create no B verification receipt. A later request for B after a valid A may then execute normally because no earlier B evidence exists.

## 6. Same-chain requirements

Every predecessor used by a dependent stage MUST belong to the exact same authenticated authorization chain.

At minimum it must match the same:

```text
contract_id
session_id
task_id / task digest
candidate/state
requirements set
policy
stage_order digest
identity-policy context when enabled
```

When monotonic authority revision is enabled, the exact ordered contract MUST also be covered by the authenticated authority-revision binding and repeated current-revision checks. The core verifier receipt does not need to duplicate that revision value if the composed host layer authenticates the exact contract/revision relation and fails closed on mismatch or drift.

Evidence from another session, contract, candidate, policy, ordering policy, identity context, or authority generation must never satisfy the predecessor relation.

The existing requirement/verifier/effect bindings remain mandatory. Stage ordering is an additional PASS condition, never a replacement for them.

## 7. Frozen contract binding

The complete canonical `stage_order` MUST be frozen into authenticated contract evidence before any verifier execution begins.

The contract MUST bind a canonical `stage_order_sha256` (or equivalent authenticated canonical digest).

Changing stage order, adding/removing a stage, changing a frozen requirement mapping, or substituting another ordering digest after freeze is a goalpost/policy change and cannot reuse old verification evidence.

The ordering configuration must be a separate explicit opt-in. Omitting it preserves existing semantics.

## 8. Evidence schema

The first stage evidence must bind at minimum to the existing verification evidence fields plus:

```text
stage_index = 0
stage_order_sha256
chain_seed_sha256
predecessor_evidence_id = null (or omitted by one frozen canonical rule)
predecessor_evidence_sha256 = null (or omitted by one frozen canonical rule)
```

Every later ordered stage must bind at minimum to the existing verification evidence fields plus:

```text
stage_index
stage_order_sha256
chain_seed_sha256
predecessor_evidence_id
predecessor_evidence_sha256
```

Only one canonical representation for first-stage predecessor fields may be accepted; implementations must not accept multiple equivalent encodings that widen the parser surface.

The evidence remains bound to its own `requirement_id`, verifier ID/version, state, identity fields when applicable, effect binding, contract, and session.

## 9. Execution semantics

For a stage-order-enabled session:

1. the next executable stage is determined by the frozen `stage_order` and already authenticated accepted chain prefix;
2. requesting a future stage before its predecessor exists MUST fail closed before invoking that stage's producer;
3. a predecessor with `FAIL` or `BLOCKED` status cannot authorize a dependent stage;
4. a dependent stage is invoked only after its predecessor receipt has been loaded, authenticated, schema-validated, and confirmed as the current chain head;
5. state, revocation, identity and authority-revision checks remain required before and after verifier execution as applicable;
6. if drift is observed during dependent verification, the produced stage is `BLOCKED` and cannot extend the chain;
7. once a requirement has produced verification evidence in a session, existing single-execution semantics remain in force; retry requires a fresh session where current semantics require one;
8. a broken/stale chain never heals by restoring old mutable state inside the same already-staled session.

The gate must not expose an external evidence-submission path that lets a worker manufacture predecessor fields.

## 10. Concurrency and atomic stage admission

Stage ordering is a causal security property and therefore the predecessor check and admission of the next stage cannot be a racy check-then-run operation.

For one `NARFSession` instance, the implementation MUST provide atomic stage admission such that:

- at most one invocation can reserve a given requirement;
- a dependent stage cannot reserve until its predecessor has been durably saved and authenticated as the accepted chain head;
- two concurrent calls cannot both pass a stale `not-yet-run` check for the same requirement;
- B racing A cannot invoke B's producer before A's accepted receipt is committed to the receipt store and installed as chain head.

The implementation may use a session lock/reservation mechanism, but the security property is the atomic transition, not a particular Python primitive.

This first feature does **not** claim distributed consensus or cross-process shared-session ordering. A deployment that reconstructs one logical session across independent processes needs an external serialized authority with equivalent semantics before claiming the same property.

## 11. Authority

An authority approval remains a frozen requirement and is ordered by its `requirement_id` like any other stage.

When identity policy designates that requirement's verifier route as `authority`, the existing identity boundary still governs its principal, trust domain and verifier profile.

Ordering does not make an authority independent. A correctly ordered authority requirement that violates identity separation remains BLOCKED.

Likewise, identity independence does not prove ordering. Both policies must pass when both are configured.

## 12. Final MGnarf decision binding

A PASS decision for an ordered session MUST bind to the completed ordered chain, not merely to the unordered set of verification receipt IDs.

At minimum the authenticated decision must bind:

```text
stage_order_sha256
chain_seed_sha256
chain_head_evidence_id
chain_head_evidence_sha256
```

The chain head must be the authenticated PASS evidence for the final `requirement_id` in the frozen `stage_order`.

Because every stage recursively binds its authenticated predecessor, the authenticated final head commits to the complete accepted chain prefix.

Before creating or consuming a PASS decision, the gate must still re-evaluate the chain and current state under existing fail-closed semantics.

## 13. Effect path

Stage ordering must not create a second effect path.

The existing guarded effect mechanisms remain authoritative, including as configured:

- current-state revalidation;
- revocation;
- sticky identity staleness;
- monotonic authority revision;
- stable operation reservation;
- fenced effect transport / commit enforcement where supported;
- single-use effect consumption.

Conceptually:

```text
frozen chain seed
  -> A PASS evidence
  -> B PASS evidence bound to A
  -> authority PASS evidence bound to B
  -> MGnarf PASS decision bound to final chain head
  -> existing guarded effect path
```

## 14. Replay, tamper and stale-chain rules

The following must fail closed:

- predecessor evidence replayed from another session;
- predecessor evidence replayed from another contract;
- predecessor evidence for another candidate/state;
- predecessor evidence from another requirements/policy binding;
- predecessor evidence from another `stage_order` digest;
- predecessor evidence from another identity/authority revision context where applicable;
- dependent evidence naming an unknown predecessor;
- dependent evidence naming the right ID with the wrong canonical predecessor digest;
- dependent evidence whose predecessor receipt is missing, altered, unauthenticated or schema-invalid;
- final decision naming a non-final chain head;
- final decision with a valid evidence set but wrong chain order;
- observed state/identity/authority drift after partial chain followed by restoration;
- candidate/worker/verifier output attempting to self-assert stage index, predecessor, seed or chain head.

## 15. Composition and no-silent-downgrade rule

Stage ordering is not secure if a stronger host wrapper silently reconstructs or forwards the task through an unordered gate.

Therefore every public/composed path that accepts an ordered contract MUST do one of exactly two things:

1. preserve the ordered contract and enforce its authenticated ordering semantics end-to-end; or
2. reject the operation fail closed before verifier execution.

It MUST NOT silently omit `stage_order`, reinterpret ordered evidence as an older unordered evidence version, or create a new unordered contract for the same requested authorization.

For the existing hardened paths this means:

- **authority revision:** its authenticated revision binding must cover the exact ordered contract. If the authority-binding schema has an ordered variant, that variant must bind `stage_order_sha256` (or an equivalent exact ordered-contract commitment). Authenticated downgrade of that binding to an unordered variant must fail closed;
- **stable operation:** the operation binding must reference the exact ordered contract ID. It must not authorize reconstruction of an unordered contract or bypass ordered finalization;
- **fenced operation/effect:** the fencing path must preserve the exact ordered contract through authority revision, stable-operation reservation, fence issuance and guarded effect entry. Existing fence semantics remain additional conditions, not replacements for stage ordering;
- **convenience/public wrappers:** a wrapper that does not implement ordered semantics must reject an ordered request rather than ignore the field;
- **legacy core gate:** an older gate that does not know the ordered evidence version must reject the ordered contract rather than accept it while ignoring unknown ordering fields.

A composed wrapper may bind authority revision or operation identity transitively through the exact authenticated contract rather than duplicating every field in every receipt, but the chain of authenticated bindings must be unambiguous and downgrade-resistant.

## 16. Versioning and backward compatibility

Existing evidence versions MUST NOT silently acquire new ordering semantics.

An ordering-enabled contract that adds ordering fields to authenticated evidence MUST use an evidence version that an older gate rejects rather than ignores.

The implementation must recon all wrappers and composed paths before selecting the exact new evidence version. The version matrix must preserve at least these semantic classes:

```text
base semantics without stage order
identity semantics without stage order
stage-order semantics (with or without identity, as explicitly supported)
```

No current v1/v2 contract may be reinterpreted as ordered merely because a new runtime exists.

Omitting stage-order policy preserves current behavior and receipt schema for that existing semantic class.

## 17. Required adversarial cases

Before runtime stage ordering can be called PASS, tests must cover at minimum:

1. B requested before A -> rejected before B producer invocation, no B receipt;
2. B requested again after valid A -> may execute because the early rejected request produced no evidence;
3. authority requirement requested before its predecessor -> rejected before authority producer invocation;
4. fabricated/old B produced before A does not become valid after later A;
5. B references A from another session -> BLOCKED;
6. B references A from another contract -> BLOCKED;
7. B references A from another candidate/state -> BLOCKED;
8. B references A from another ordering policy -> BLOCKED;
9. right predecessor ID with wrong predecessor digest -> BLOCKED;
10. predecessor receipt missing/tampered/unauthenticated -> dependent chain BLOCKED;
11. predecessor status FAIL -> next stage cannot execute;
12. predecessor status BLOCKED -> next stage cannot execute;
13. stage order omits one frozen requirement -> contract rejected;
14. stage order duplicates a requirement -> contract rejected;
15. stage order contains unknown requirement -> contract rejected;
16. two different requirements using the same verifier_id remain unambiguous because ordering uses requirement_id;
17. identity separation violation remains BLOCKED even with correct stage order;
18. identity/profile/authority drift after partial chain stales the chain;
19. clock rollback, equal timestamps or missing timestamps cannot manufacture ordering;
20. two concurrent calls for the same stage invoke at most one producer;
21. A/B race cannot invoke B before A's authenticated PASS receipt becomes chain head;
22. concurrent future-stage probes cannot skip a required predecessor;
23. chain seed from another session cannot seed the first stage;
24. final decision with wrong/non-final chain head -> BLOCKED;
25. authenticated authority binding with wrong stage-order digest -> BLOCKED;
26. authenticated downgrade of ordered authority binding to unordered binding -> BLOCKED;
27. legacy core gate presented with ordered evidence version -> rejected, never unordered PASS;
28. authority-revision wrapper preserves ordered execution -> PASS only in correct order;
29. stable-operation wrapper preserves ordered execution -> PASS only in correct order;
30. fenced-operation wrapper preserves ordered execution -> PASS only in correct order;
31. correct complete A -> B -> authority chain plus all existing MGnarf conditions -> PASS;
32. effect remains single-use and bound to the final authenticated decision;
33. non-ordering contracts retain their current semantics;
34. existing full regression suite remains green.

## 18. Non-goals

The first stage-order implementation does not prove:

- physical wall-clock chronology;
- epistemic independence of verifier reasoning;
- that distinct providers cannot share a hidden control plane;
- distributed consensus across arbitrary hosts;
- cross-process session ordering without a serialized external session authority;
- ordering of external side effects beyond the existing guarded/fenced effect boundary;
- a general DAG/parallel-stage workflow model.

Those are separate claims and must not be implied by this feature.

## 19. Implementation gate

Runtime work may begin only after this revised design is deliberately accepted or amended.

The implementation sequence is:

```text
recon exact current main and composed wrappers
  -> freeze exact stage-order API/schema/version
  -> adversarial tests first
  -> smallest runtime change
  -> focused concurrency/adversarial tests
  -> composition/no-downgrade tests
  -> full regression suite
  -> whole-chain review
  -> exact-SHA evidence
```

Until the runtime work and evidence complete, MGnarf documentation MUST continue to state that the current released identity chain proves required participation and separation, not authenticated predecessor ordering.
