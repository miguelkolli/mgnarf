# Authenticated stage-order boundary

Status: **DESIGN FREEZE CANDIDATE — NO RUNTIME CLAIM YET**

This document defines the security boundary for optional authenticated stage ordering in MGnarf. It does not claim the runtime currently enforces this property.

## 1. Problem

Identity separation answers **who** produced required evidence and whether required actors are independent under the frozen policy.

It does not by itself answer **whether the required stages happened in the required order**.

The intended chain may be:

```text
builder
  -> verifier A
  -> independent verifier B
  -> human/policy authority
  -> MGnarf decision
  -> effect
```

Without an explicit ordering primitive, all required verifier and authority evidence can be valid while having been produced in another sequence.

Timestamps are insufficient as the security primitive. Clocks can disagree, move backwards, collide, be absent, or be controlled by a weaker trust domain than the evidence itself.

## 2. Core invariant

When stage ordering is enabled, every ordered stage after the first MUST bind to authenticated predecessor evidence from the same frozen authorization chain.

For ordered stages `S[0] ... S[n]`:

```text
accepted(S[i]) for i > 0
  requires
predecessor_binding(S[i]) == authenticated_evidence(S[i-1])
```

A later stage must never become valid merely because the missing predecessor appears afterwards.

Therefore:

```text
B-before-A + later A != valid A -> B chain
```

The dependent evidence must be produced again after the predecessor exists.

## 3. Security meaning

Authenticated ordering means evidence causally references the accepted predecessor evidence identity or digest.

It does **not** mean MGnarf proves real-world wall-clock time.

The order claim is limited to:

```text
this accepted evidence was created as a dependent stage of this exact authenticated predecessor evidence
```

That predecessor evidence is already bound to the same contract, session, task, candidate/state, requirements, policy and verifier identity context.

## 4. Policy model

Ordering is a separate policy axis from identity separation.

A simple linear policy may use:

```json
{
  "stage_order": [
    "verifier:tests",
    "verifier:security",
    "authority"
  ]
}
```

A future graph form may be introduced separately if multiple predecessors or parallel stages are required. The first implementation should prefer one minimal canonical form rather than support multiple equivalent syntaxes.

Identity rules remain independent. For example, a policy may require both:

```text
builder.principal_id != verifier:security.principal_id
```

and:

```text
verifier:tests -> verifier:security -> authority
```

Passing one condition never substitutes for the other.

## 5. Frozen contract binding

If ordering is configured, the complete canonical ordering policy MUST be frozen into authenticated contract evidence before verifier execution begins.

Changing stage order, adding a stage, removing a stage, or changing a stage identity after freeze is a policy/goalpost change.

The contract MUST reject:

- unknown stage roles;
- duplicate stages;
- an authority stage without a frozen authority verifier route;
- a verifier stage not represented by a frozen requirement;
- malformed ordering syntax;
- ordering policy that is present but omitted from authenticated contract binding.

## 6. Evidence binding

For an ordered stage after the first, accepted evidence must bind at minimum to:

```text
contract_id
session_id
requirement_id / stage role
predecessor_evidence_id
predecessor_evidence_digest or equivalent authenticated binding
```

The predecessor must be authenticated before the dependent producer is invoked.

The predecessor must belong to the same:

```text
contract
session
task
candidate/state
requirements set
policy
identity-policy context when enabled
```

Evidence from another session, contract, candidate, policy or chain must never satisfy the predecessor relation.

## 7. Execution semantics

For a linear ordered chain:

1. a stage whose predecessor has not successfully completed cannot execute as an order-valid stage;
2. FAIL or BLOCKED predecessor evidence cannot authorize the next stage;
3. a dependent stage produced before its required predecessor is invalid and is not repaired by later predecessor evidence;
4. replacing, invalidating or staling an accepted predecessor invalidates dependent authorization;
5. a fresh valid chain requires fresh dependent evidence from the first broken point onward.

The implementation should fail closed before invoking a dependent verifier when the predecessor condition is not satisfied.

## 8. Authority

If `authority` is part of the ordered chain, authority evidence must be produced only after its required predecessor evidence is authenticated and accepted.

Authority identity remains governed by the identity boundary. Ordering does not make an authority independent; identity separation must require that independently when needed.

An authority role that is correctly ordered but violates frozen principal/trust-domain/profile separation remains BLOCKED.

## 9. MGnarf decision and effect

The final MGnarf decision must bind to the completed ordered evidence chain.

The effect path remains subject to all existing protections, including current-state revalidation, revocation, identity/authority revision where configured, stable-operation rules, fencing where configured and single-use consumption.

Stage ordering must not create a second effect path or bypass hardened executors.

Conceptually:

```text
A evidence
  -> B evidence bound to A
  -> authority evidence bound to B
  -> MGnarf decision bound to completed chain
  -> existing guarded effect path
```

## 10. Replay and stale-chain rules

The following must fail closed:

- predecessor evidence replayed from another session;
- predecessor evidence replayed from another contract;
- predecessor evidence for another candidate/state;
- predecessor evidence from another ordering policy;
- dependent evidence that names an unknown or unauthenticated predecessor;
- dependent evidence whose predecessor receipt has been altered or removed;
- dependent evidence retained after observed identity, authority or state drift has made the predecessor chain stale.

Existing sticky stale-session behavior remains applicable. Restoring previous identities or state does not resurrect an already-staled ordered chain.

## 11. Versioning and backward compatibility

Existing evidence versions must not silently acquire new ordering semantics.

If authenticated stage ordering changes the evidence schema, an ordering-enabled contract MUST use a new evidence version that older gates reject rather than ignore.

Conceptually:

```text
v1: base MGnarf contract semantics
v2: optional identity-bound semantics
vNext: optional authenticated stage-order semantics
```

The exact version number is an implementation decision, but fail-closed version separation is mandatory.

Omitting stage-order policy must preserve current behavior.

## 12. Required adversarial cases

Before runtime stage ordering can be called PASS, tests must cover at minimum:

1. verifier B executes before verifier A -> BLOCKED;
2. authority executes before verifier B -> BLOCKED;
3. A appears after an already-produced B -> old B remains invalid;
4. B references A from another session -> BLOCKED;
5. B references A from another contract -> BLOCKED;
6. B references A from another candidate/state -> BLOCKED;
7. B references A from another ordering policy -> BLOCKED;
8. predecessor evidence is FAIL -> next stage BLOCKED;
9. predecessor evidence is BLOCKED -> next stage BLOCKED;
10. predecessor receipt is missing/tampered -> dependent chain BLOCKED;
11. identity separation violation remains BLOCKED even with correct stage order;
12. identity/profile/authority drift after partial chain stales the chain;
13. clock rollback, equal timestamps or missing timestamps cannot manufacture ordering;
14. duplicate/replayed dependent evidence remains rejected;
15. correct A -> B -> authority chain plus all existing MGnarf conditions -> PASS;
16. effect remains single-use and bound to the final authenticated decision;
17. non-ordering contracts retain their current semantics.

## 13. Non-goals

The first stage-order implementation does not need to prove:

- physical wall-clock chronology;
- epistemic independence of verifier reasoning;
- that two different providers cannot share a hidden control plane;
- distributed consensus across arbitrary hosts;
- ordering of effects outside the existing guarded/fenced external-effect boundary.

Those are separate claims and must not be implied by this feature.

## 14. Implementation gate

Runtime work may begin only after this design is deliberately accepted or amended.

The implementation must then follow:

```text
recon
  -> freeze exact stage-order semantics
  -> adversarial tests first
  -> smallest runtime change
  -> full regression suite
  -> whole-chain review
  -> exact-SHA evidence
```

Until that happens, MGnarf documentation must continue to state that the existing identity chain proves required participation and separation, not strict predecessor ordering.
