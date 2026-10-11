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

## 4. Verifier evidence

Only host-bound verifier producers may create accepted verifier evidence. Each verifier result is `PASS`, `FAIL`, or `BLOCKED`.

A developer or worker result outside the bound verifier route is not NARF evidence. Missing, malformed, tampered, replayed, wrong-task, wrong-session, wrong-verifier, or wrong-state evidence must not produce PASS.

## 5. Result semantics

`PASS`: all frozen requirements have authentic PASS evidence and all current-state and inhibitor checks are clear.

`FAIL`: at least one valid required verifier explicitly returned FAIL.

`BLOCKED`: required evidence, binding, or state is unavailable, incomplete, invalid, changed, revoked, inhibited, or otherwise cannot safely support PASS.

## 6. State changes

The gate rechecks frozen state before each verifier run and after the verifier returns. Candidate, goalpost, policy, contract, revocation, or state-probe changes must fail closed.

## 7. Final decision

Finalization writes an authenticated decision receipt bound to the same contract, session, task and frozen state. A PASS decision is valid only while reevaluation still produces PASS.

## 8. Effect rule

A PASS decision is not permanent permission. Immediately before the gated effect, the host revalidates revocation, frozen state, contract authenticity, and decision freshness. Effect consumption is single-use and replay-resistant.

## 9. Authority and inhibitors

Human or product authority is outside NARF's product-decision role. An integrating host may represent a stop condition as an inhibitor. An inhibitor prevents PASS or effect even when technical verifiers passed.

## 10. Trust boundary

Receipt authentication, receipt storage, frozen bindings, verifier selection, state probes, revocation probes, and the gated effect callback remain host-owned and outside candidate or worker control.

If the candidate can forge host evidence or replace those bindings, the NARF trust boundary has been broken.

## 11. Integration boundary

Other systems may call or embed NARF through their own adapters. The relationship is one-way: an integrating system may depend on NARF, while NARF remains independent of the integrating system.

## 12. Non-goals

The standalone reference does not define product intent, host deployment, analytics authority, production readiness, or a licensing model.
