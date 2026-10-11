# NARF behavioral specification

## 1. Purpose

NARF is an acceptance gate. It does not decide product intent and it does not
replace tests. It decides whether a specific frozen candidate has sufficient,
authentic, current evidence to receive PASS and whether a gated effect may still
be executed.

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
  AND no inhibitor exists
  AND the contract is not revoked
```

For every required condition `x`:

```text
x invalid or absent => NARF != PASS
```

NARF is therefore fail-closed, not fail-open.

## 3. Frozen contract

Before implementation evidence is accepted, the trusted host freezes:

- task identity and canonical task digest;
- candidate digest;
- requirements/goalpost digest;
- policy digest;
- the complete requirement set;
- verifier identities and versions;
- effect identity and version.

The reference implementation stores the contract as authenticated host evidence.

## 4. Verifier evidence

Only host-bound verifier producers may create accepted verifier evidence.

Each verifier result is one of:

- `PASS`
- `FAIL`
- `BLOCKED`

A developer/worker test result outside the bound verifier route is not NARF
evidence. Missing, malformed, tampered, replayed, wrong-task, wrong-session,
wrong-verifier, or wrong-state evidence must not produce PASS.

## 5. Result semantics

`PASS`
: All frozen requirements have authentic PASS evidence and all current-state and
  inhibitor checks are clear.

`FAIL`
: At least one valid required verifier explicitly returned FAIL.

`BLOCKED`
: Required evidence/binding/state is unavailable, incomplete, invalid, changed,
  revoked, inhibited, or otherwise cannot safely support PASS.

The gate must preserve verifier FAIL/BLOCKED outcomes rather than reinterpret
them into PASS.

## 6. State changes

The gate rechecks frozen state before each verifier run and after the verifier
returns. Relevant changes include:

- candidate change;
- requirements/goalpost change;
- policy change;
- contract invalidation;
- revocation;
- state-probe failure.

A change during verification makes that evidence BLOCKED.

## 7. Final decision

Finalization writes an authenticated decision receipt bound to the same contract,
session, task and frozen state.

A PASS decision is valid only while reevaluation still produces PASS.

## 8. Effect rule

A PASS decision is not permanent permission.

Immediately before the gated effect, the host must revalidate:

- revocation state;
- candidate/requirements/policy state;
- contract authenticity;
- decision authenticity and freshness.

The effect is recorded with deterministic single-use identity before invoking the
callback. A repeated/recovered attempt must fail closed rather than execute the
same privileged effect twice.

## 9. Authority and inhibitors

Human/product authority is outside NARF's product-decision role. A host/lifecycle
may represent missing authority or another stop condition as an inhibitor. An
inhibitor must prevent PASS/effect even when technical verifiers passed.

## 10. Trust boundary

The following must remain host-owned and outside candidate/worker control:

- receipt authentication key;
- authenticated receipt storage;
- frozen bindings;
- verifier binding selection;
- state/revocation probes;
- gated effect callback.

If the candidate can forge host evidence or replace those bindings, the NARF
trust boundary has been broken.

## 11. Non-goals

The standalone reference does not define:

- product intent;
- MGSystem Task Freeze internals;
- an operating-system trusted-host launcher;
- deployment credentials;
- analytics/telemetry authority;
- production readiness;
- a licensing model.

Those are separate boundaries.
