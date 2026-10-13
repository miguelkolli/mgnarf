# Candidate-origin attestation v2 boundary

Status: **DESIGN CANDIDATE — NO RUNTIME CLAIM**

Related: #62, #64, #65, #69.

## 1. Why this boundary exists

Frozen identity-provenance design #62 requires candidate-origin object B to prove that the frozen candidate actually came from the claimed builder execution/output relationship.

The current runtime accepts a caller-provided object containing:

```text
candidate_sha256
actor_role = builder
actor_instance_id
```

and, after field validation, emits authenticated `narf.candidate-origin` evidence.

PR #69 proved that this is insufficient: a caller-selected builder instance can be upgraded into host-authenticated B evidence without any trusted proof that the claimed builder instance produced the candidate.

A host signature over an untrusted assertion proves only that the host stored the assertion. It does not prove the asserted build relationship.

## 2. Security invariant

MGnarf MUST NOT credit builder provenance for a candidate unless a trusted attestation path binds the exact candidate output to the exact builder execution instance and the required builder provenance.

Candidate-origin evidence B is derived from authenticated build/output attestation. It is not created from free-form caller fields during contract freeze.

## 3. Required source attestation

A trusted builder/output attestation must exist before a provenance-enabled contract can credit builder origin.

The source attestation must bind at least:

```text
attestation semantic version
attestation id / build-run id
candidate_sha256
builder actor role
builder actor instance id
builder provenance / actor commitment
provenance authority id
provenance trust-root id
provenance revision or equivalent trusted currentness commitment
output relationship / build execution commitment
trusted attester identity or trust domain
```

The exact schema may use digests for canonical nested structures, but the relationship must be authenticated and unambiguous.

## 4. Creation timing

The trusted attestation is produced as part of the builder execution/output boundary, or by an external trusted attester that directly observes that boundary.

A later lookup, registry entry, caller assertion, or retrospective mapping from candidate hash to a builder name MUST NOT by itself create origin proof.

If no qualifying attestation was produced when the relationship was observable, builder provenance is UNVERIFIED/BLOCKED.

## 5. Contract-freeze API boundary

The provenance contract freeze path must no longer accept an arbitrary `candidate_origin` structure as proof.

A compliant path consumes an authenticated attestation reference, for example conceptually:

```text
candidate_origin_attestation_id
```

or an externally signed attestation object verified by a configured trusted attester.

The gate must load/verify the source attestation and derive B from it. Caller-controlled fields cannot override the attested candidate, actor instance, provenance, or authority identity.

## 6. Required validation before B

Before candidate-origin B can be emitted, the trusted host validates at least:

1. source attestation authenticity and semantic version;
2. exact candidate hash equals the frozen candidate;
3. actor role is `builder`;
4. builder actor instance is present and attested, not supplied ad hoc by the contract caller;
5. attested builder provenance matches the builder actor commitment required by the frozen provenance snapshot/policy;
6. attestation authority/trust root is accepted;
7. required authority/provenance currentness is valid under the deployment claim;
8. source attestation is not tampered, ambiguous, or from a different candidate/build relationship.

Any failure is BLOCKED before B/P/C can claim builder provenance.

## 7. B evidence binding

The derived `narf.candidate-origin` evidence must bind the source attestation, not merely repeat its human-readable fields.

At minimum B should include commitments equivalent to:

```text
candidate_sha256
actor_role = builder
actor_instance_id
builder_actor_sha256
source_attestation_id
source_attestation_sha256
attester/trust-domain commitment
provenance authority/root/revision commitment
```

The provenance-enabled contract C then binds the exact B digest/identifier as already required by the frozen design.

## 8. Replay semantics

A valid build attestation may be reusable only when it still proves the exact same candidate/output relationship under the policy being claimed.

It must not be replayable to:

- a different candidate hash;
- a different builder instance;
- a different builder actor/provenance commitment;
- a different trust root when the policy requires exact root binding;
- a different output relationship whose semantics are not covered by the attestation.

Reuse across multiple contracts for the exact same attested candidate may be allowed if the contract explicitly binds the same authenticated source attestation and all required currentness rules still hold.

## 9. Trusted-attester models

Accepted deployment models include:

### 9.1 Host-owned build attester

A trusted build host observes the actual builder process/output and writes an authenticated attestation into a protected evidence store at build completion.

### 9.2 External signed build attester

A separate trusted service signs the exact build/output relationship. MGnarf verifies the signature/trust root and exact attestation semantics before deriving B.

### 9.3 Hardware/workload identity attester

A workload-identity or hardware-backed attester may bind the candidate to an execution instance, provided the resulting evidence proves the exact relationship required by policy rather than only identifying a machine or account.

A plain caller parameter, environment variable, registry lookup, or self-asserted agent identity is not a trusted attester.

## 10. Fail-closed requirements

The candidate-origin path returns BLOCKED when:

- builder provenance is required but no source attestation exists;
- attester is unavailable or untrusted;
- source evidence cannot be authenticated;
- candidate hash differs;
- builder instance differs or is missing;
- builder provenance commitment differs;
- trust root/authority commitment is stale or unsupported where required;
- source attestation semantics are unknown;
- the caller supplies only the legacy free-form `candidate_origin` object.

No fallback may silently downgrade builder-origin provenance to an unsigned or self-asserted claim.

## 11. Required RED coverage before implementation

Keep PR #69 unchanged and add RED coverage for at least:

1. caller-selected builder instance without attester -> BLOCKED;
2. missing attestation -> BLOCKED when builder provenance is required;
3. forged/tampered source attestation -> BLOCKED;
4. attestation for different candidate -> BLOCKED;
5. attestation for different builder instance -> BLOCKED;
6. builder provenance digest mismatch -> BLOCKED;
7. untrusted/changed attester root -> BLOCKED where exact root is required;
8. cross-candidate/source-attestation replay -> BLOCKED;
9. valid trusted build/output attestation -> B created and C binds its exact digest;
10. legacy/free-form origin API cannot silently mint v4 B evidence.

## 12. Composition boundary

This document does not claim that existing authority-revision, stable-operation, or fencing wrappers already support the stronger candidate-origin path. Provenance-v4 wrapper composition remains fail closed until explicitly implemented and verified.

## 13. Release gate

A new v1.70 provenance candidate may return to independent review only after:

```text
#69 unchanged -> GREEN
trusted-origin RED suite -> GREEN
#67 unchanged -> GREEN
replacement effect-admission authority suite -> GREEN
full repository regression -> PASS at exact SHA
v1.70 protected whole-chain -> PASS at exact SHA
hardened workflow matrix -> PASS at exact SHA
```

Only after those gates may #65 be refrozen to a new exact implementation head.
