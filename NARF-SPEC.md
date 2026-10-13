# NARF behavioral specification

## 1. Purpose

NARF is a standalone acceptance gate. It does not decide product intent and it does not replace tests. It decides whether a specific frozen candidate has sufficient, authentic, current evidence to receive PASS and whether a gated effect may still be executed.

NARF requires no parent framework, private repository, workspace variable, external harness, or external governance runtime.

## 2. Core invariant

For a frozen contract with `N` requirements:

```text
PASS iff
  task binding is unchanged
  AND candidate binding is unchanged
  AND requirement/goalpost binding is unchanged
  AND policy binding is unchanged
  AND evidence coverage is N/N
  AND every required verifier result is PASS
  AND evidence is authentic and session-bound
  AND any configured identity, domain, profile and separation conditions hold
  AND any configured authenticated stage-order conditions hold
  AND no inhibitor exists
  AND the contract is not revoked
```

For every required condition `x`:

```text
x invalid or absent => NARF != PASS
```

NARF is therefore fail-closed, not fail-open.

## 3. Frozen contract

Before implementation evidence is accepted, the trusted host freezes task identity, candidate state, requirements, policy, verifier identities and versions, and effect identity and version. The reference implementation stores the contract as authenticated host evidence.

Authenticated stage ordering is an optional stronger contract boundary. When configured, `stage_order` is an exact linear permutation of all frozen `requirement_id` values and is authenticated as part of the ordered contract. Partial orders, DAGs, optional stages and parallel branches are not part of the first stage-order model.

Operation-level idempotency is another optional stronger integration boundary. `OperationBoundGate` binds a trusted-host-owned stable operation UUID to a frozen NARF contract in separate authenticated host evidence. The operation identity is semantic authority supplied by the trusted host; candidate or worker code must not choose it.

## 4. Verifier evidence

Only host-bound verifier producers may create accepted verifier evidence. Each verifier result is `PASS`, `FAIL`, or `BLOCKED`.

A developer or worker result outside the bound verifier route is not NARF evidence. Missing, malformed, tampered, replayed, wrong-task, wrong-session, wrong-verifier, wrong-state or wrong-predecessor evidence must not produce PASS.

When explicitly configured, [identity separation](IDENTITY-BOUNDARY.md) adds host-authenticated principal, trust-domain and optional verifier-profile facts. `verifier_id` names a logical check; `principal_id` names its authenticated controller; `trust_domain` describes shared administrative control; `verifier_profile` describes the verification method. They are distinct axes. Required authority approval uses a frozen required verifier route. A principal label or candidate-supplied profile never substitutes for authenticated evidence.

When explicitly configured, [authenticated stage ordering](STAGE-ORDER-BOUNDARY.md) adds causal predecessor binding over the exact frozen `requirement_id` sequence:

- the first ordered stage binds to a deterministic session/contract-owned chain seed;
- every later stage binds to the authenticated predecessor receipt ID and canonical receipt digest;
- a future stage is rejected before its producer is invoked;
- a `FAIL` or `BLOCKED` predecessor cannot authorize the next stage;
- predecessor evidence from another session, contract, candidate/state, ordering policy or applicable identity/authority context cannot satisfy the chain;
- the final decision binds to the authenticated final chain head.

Stage ordering is not based on timestamps and does not prove physical wall-clock chronology.

Evidence-version semantics are intentionally separated:

```text
v1: base semantics without identity policy or stage order
v2: identity-enabled semantics without stage order
v3: stage-order semantics, with identity policy when configured
```

An older gate must reject an ordered v3 contract rather than accept it while ignoring ordering fields. Omitting `stage_order` preserves the existing v1/v2 semantic class.

## 5. Result semantics

`PASS`: all frozen requirements have authentic PASS evidence and all configured identity/order/current-state/inhibitor conditions are clear.

`FAIL`: at least one valid required verifier explicitly returned FAIL.

`BLOCKED`: required evidence, binding, predecessor chain, identity, authority or state is unavailable, incomplete, invalid, changed, revoked, inhibited, stale or otherwise cannot safely support PASS.

## 6. State, identity and ordered-chain changes

The gate rechecks frozen state before each verifier run and after the verifier returns. Candidate, goalpost, policy, contract, revocation or state-probe changes must fail closed.

For identity-enabled contracts, the same checks also revalidate frozen identity and profile facts using the trusted-host probe and verifier bindings, including immediately before effect execution. Profile separation is optional and driven by the frozen policy; a configured profile cannot change after freeze.

For ordered contracts, stage admission is atomic inside one session: at most one invocation may reserve a requirement, and a dependent producer cannot enter until the authenticated PASS receipt for its predecessor is durably available as the accepted chain head. Same-thread re-entrancy and same-stage concurrent calls must not create duplicate producer admission.

A later predecessor never retroactively validates evidence that was already produced out of order. An early request that was rejected before producer entry creates no evidence and may be retried after the required predecessor exists.

When a revocation probe is configured, only the exact boolean value `False` establishes a clear non-revoked state. `True`, probe exceptions, and non-boolean or otherwise unavailable probe results fail closed as revoked/unavailable authority.

## 7. Final decision

Finalization writes an authenticated decision receipt bound to the same contract, session, task and frozen state. A PASS decision is valid only while reevaluation still produces PASS.

For an ordered session, the authenticated decision additionally binds the stage-order digest, chain seed and final authenticated chain-head receipt ID/digest. A decision naming a non-final or invalid chain head cannot authorize effect execution.

## 8. Effect rule

A PASS decision is not permanent permission. Immediately before the gated effect, the host revalidates revocation, frozen state, contract authenticity, inhibitor state, decision freshness and any configured identity/order composition requirements.

Core NARF effect consumption is single-use per frozen contract/authorization. The compatibility `RollbackProtectedEffectExecutor` therefore reserves a contract-scoped token.

For operation-level idempotency across fresh contracts, an integrating trusted host may use `OperationBoundGate` with `OperationBoundEffectExecutor`. That path recovers an authenticated stable operation UUID and reserves that UUID in the configured external consumption authority before entering the callback. Fresh contracts representing the same real external operation must receive the same host-owned operation UUID.

For fenced execution, the ordered contract must survive authority-revision, stable-operation reservation, fence issuance and guarded effect entry without silent downgrade. Stage ordering adds an authorization condition; it does not create a second effect path or replace fencing/commit-time enforcement.

NARF does not infer business equivalence. If the trusted host assigns a fresh operation UUID to the same real-world action, a new authorization remains possible.

## 9. Authority and inhibitors

Human or product authority is outside NARF's product-decision role. An integrating host may represent a stop condition as an inhibitor. An inhibitor prevents PASS or effect even when technical verifiers passed.

An authority approval may itself be a frozen required verifier route. When stage ordering is configured it is ordered by its `requirement_id` like every other required stage. Correct order does not replace identity separation: both conditions must pass when both are configured.

An inhibitor may be added after a PASS decision has been finalized but before the effect has been consumed. That new inhibitor invalidates the previously valid PASS for effect execution. Once the effect has been consumed, adding an inhibitor cannot retroactively undo it and is rejected by the reference session API.

## 10. Trust boundary

Receipt authentication, receipt storage, frozen bindings, verifier selection, state probes, revocation probes, identity provenance, stage-order configuration, semantic operation identity where used, and the gated effect callback remain host-owned and outside candidate or worker control.

Candidate, worker or verifier output must not self-assert trusted chain seed, stage index, predecessor fields or final chain head. There is intentionally no untrusted evidence-submission API for manufacturing those fields.

If the candidate can forge host evidence or replace those bindings, the NARF trust boundary has been broken.

## 11. Integration boundary

Other systems may call or embed NARF through their own adapters. The relationship is one-way: an integrating system may depend on NARF, while NARF remains independent of the integrating system.

A public/composed wrapper that accepts an ordered contract must either preserve ordered semantics end-to-end or reject the request before verifier execution. It must never silently reconstruct an unordered authorization.

The first stage-order implementation provides atomic admission for one in-memory `NARFSession`; it does not claim distributed consensus or cross-process shared-session ordering without an external serialized session authority.

## 12. Non-goals

The standalone reference does not define product intent, host deployment, analytics authority, production readiness, business-level equivalence of operations, a licensing model, physical wall-clock ordering, epistemic independence of verifier reasoning, distributed consensus, a general DAG/parallel workflow model, or exactly-once remote completion.
