# MgNarf v1.60 trust-boundary audit

## Audit status

**Result: BOUNDARY_CONFIRMED for the measured reference scope.**

This document records the whole-chain adversarial review used for the `v1.60-rc1` release freeze. It is a project security review of the reference implementation and its measured fixtures. It is **not** an independent security certification and does not certify an arbitrary production deployment.

The reviewed execution chain is:

```text
freeze → verify → decision → authority → effect
```

The audit found one RC-blocking stage-transition flaw: the public `TrustedFileHost` integration performed a permissive `json.dumps/json.loads` conversion before the hardened core gate could validate the caller's original task. Integer object keys and tuples could therefore be coerced into strict-looking JSON and reach PASS + effect. The finding was reproduced end-to-end before remediation, then fixed so the integration validates the original task with the same strict canonical JSON boundary as the core gate. Required regression and focused integration evidence now cover that transition.

After that remediation, no additional known HIGH/CRITICAL fail-open path was found inside the threat model documented below. Known limits remain explicit and are not counted as PASS.

## 1. Freeze

### Trusted authority

The trusted host owns the task, candidate, policy, external goalposts, exact verifier requirement set and — on the operation-bound path — semantic operation identity.

### Enforced bindings

- security-bound task values must use the strict JSON data model accepted by the trusted Python host;
- object keys must be strings and arrays must be lists;
- non-finite floats, coercible custom/container values and invalid UTF-8 surrogate values fail closed;
- the task is bound by a SHA-256 digest of the strict canonical representation;
- candidate, policy and external goalposts are bound by frozen digests;
- the exact verifier requirement set receives a gate-computed digest distinct from the broader external-goalpost binding.

### Adversarial evidence

The audit independently reproduced pre-hardening task-binding collisions caused by permissive Python-to-JSON coercion. The core gate and trusted reference-host integration were both hardened and regression tested.

Deterministic property/fuzz evidence additionally measures 10,000 generated strict JSON values, invalid coercion cases and authenticated-receipt mutations.

### Remaining limit

The trusted host defines the meaning of the input and operation identity. MgNarf cannot determine that two deliberately different host-provided operation IDs represent the same real-world action.

## 2. Verify

### Trusted authority

Verifier identity, version, selection and execution are host-owned. Candidate/worker code has no evidence-submission or PASS-override API.

### Enforced behavior

- verifier identity and version are checked against the frozen requirement set;
- every requirement must execute exactly once for complete N/N coverage;
- verifier artifacts are hashed and receipt-authenticated;
- relevant state is checked before and after verifier execution;
- candidate bytes used by the candidate-file reference host are frozen and supplied to the trusted verifier producer;
- missing, malformed, unavailable or stale evidence fails closed.

### Remaining limit

MgNarf authenticates that the selected verifier produced the evidence. It does not independently prove that the verifier's domain logic is correct. Verifier correctness remains a trusted-host responsibility.

## 3. Decision

### Enforced behavior

A decision is valid only when the exact authenticated evidence set remains bound to the contract/session and all required statuses support PASS. The gate re-evaluates relevant state, revocation and inhibitor conditions rather than treating an earlier PASS as an eternal capability.

Authenticated decision receipts bind the contract, session, task, exact requirement set and frozen state. Missing or altered receipt history is not converted into PASS.

### Remaining limit

Session execution state is memory-resident. A process crash may require a new session and repeated verification. This is availability/recovery behavior, not a permission to reuse stale PASS evidence.

## 4. Authority

### Strong path

The operation-bound path stores a host-owned stable operation UUID in an HMAC-authenticated binding associated with the contract. The effect executor obtains its consumption token from that authenticated session binding; the caller does not supply an ad-hoc token at effect time.

External single-use authorities include:

- filesystem authority for a distinct trusted rollback domain;
- PostgreSQL primary-key/unique reservation using a least-privilege runtime role;
- Ed25519-authenticated signed witness with a fresh request nonce and signed token/operation/domain binding;
- all-of composition requiring every configured independent authority to reserve on first use.

Partial or ambiguous reservations are deliberately **never rolled back**. MgNarf sacrifices availability rather than freeing a token whose durable state is uncertain.

### Adversarial evidence

Measured evidence includes:

- concurrent PostgreSQL single-winner reservation;
- local-history and PostgreSQL rollback while a signed witness survives;
- signed response forgery/replay and nonce mismatch attempts;
- witness outage fail-closed behavior;
- durable witness reservation followed by lost response acknowledgement;
- durable PostgreSQL commit followed by lost commit acknowledgement;
- retry after ambiguous outcomes remaining blocked;
- 16 synchronized host processes, 16 fresh contracts and one shared authenticated operation ID producing exactly one callback and fifteen consumed-token blocks;
- replay remaining blocked after all host-local histories are discarded and PostgreSQL is reset while signed witness history survives.

### Remaining limits

- The trusted host still defines semantic operation identity.
- If every preserving authority history — including signed witness and PostgreSQL — is rolled back together, replay can return. That boundary remains `LIMITATION_CONFIRMED`.
- CI service/process separation does not by itself prove independent production administration.

## 5. Effect

### Enforced behavior

The strong executor requires an authenticated PASS, reserves external operation authority first, and only then enters the NARF effect path. The session immediately revalidates current state and the authenticated decision before local effect-consumption evidence is persisted and the callback is invoked.

Crash and race fixtures characterize callback invocation as at-most-once inside the measured boundary.

### Remaining limits

- A callback or remote target can fail after authorization is durably consumed. MgNarf does not claim exactly-once remote completion.
- Physical-power-loss guarantees and arbitrary production target semantics are outside the reference fixtures.
- Actors that bypass the trusted host's lock/transaction/fencing protocol are outside the protected path.

## Measured release-candidate evidence

The RC1 freeze is based on the exact repository workflows, not on this document alone. The measured suite includes:

- 83 core repository tests with zero failures, errors or skips on the pre-freeze audited main revision;
- compilation checks;
- strict canonical/receipt fuzzing: 10,000 generated values and 256 stale-MAC receipt mutations;
- 24-case UID/GID isolation;
- trusted-host/untrusted-worker process separation;
- crash persistence and at-most-once characterization;
- filesystem rollback limitation witness;
- rollback hardening and multi-domain fencing;
- PostgreSQL authority and privileged-admin limitation characterization;
- signed witness 4-protected + 1-limitation boundary;
- stable operation-ID hardening and the legacy contract-scoped limitation witness;
- 16-host same-operation race plus post-reset replay check;
- four ambiguous durable-reservation/lost-acknowledgement cases;
- strict trusted reference-host transition: two coercion attacks rejected before freeze plus one valid control.

The final `v1.60-rc1` tag must be created only from the exact merged release-freeze `main` commit after its complete required reference gate succeeds. Candidate or historical evidence is not a substitute for that exact-revision verification.

## Release decision

Within the documented reference threat model:

```text
FINAL: BOUNDARY_CONFIRMED
```

This means the measured boundary is explicit, repeatable and fail-closed under the executed cases. It does **not** mean that MgNarf is unbreakable, formally verified, independently certified or a substitute for secure production isolation and operations.
