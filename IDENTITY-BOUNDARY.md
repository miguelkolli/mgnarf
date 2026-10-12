# Identity and separation-of-duties boundary

Status: first opt-in reference implementation. The identity design was frozen
before runtime work; verifier-profile provenance was added to that design before
implementing the API. The original version-1 contract semantics remain available.

## 1. Problem

NARF already binds PASS evidence to the exact frozen task, candidate, requirements, policy, verifier ID/version, session and effect path. That prevents evidence for one artifact or state from silently authorizing another.

A different question remains: who produced the required evidence?

Two verifier IDs are not automatically two independent authorities. The same agent, credential, key, account, process owner or administrative domain can present multiple logical verifier names. A policy that requires independent review therefore needs identity and trust-domain bindings in addition to verifier names.

Independent actors may also share the same verification method. Optional profile
constraints address that separate axis; they do not replace identity constraints.

The target flow is:

```text
builder -> verifier A -> independent verifier B -> human/policy authority -> NARF -> effect
```

NARF must not invent these identities. The trusted host supplies and authenticates them, freezes the relevant bindings, and keeps their provenance outside candidate/worker control.

## 2. Terms

### verifier_id

Logical verifier route, for example `unit-tests`, `security-review`, or `policy-approval`.

This answers: **which check is this?**

### principal_id

Stable host-authenticated identity of the actor or authority producing evidence, for example a workload identity, key fingerprint, CI identity, human account, or separately authenticated agent identity.

This answers: **who produced or controlled this evidence?**

A candidate-supplied string is not a principal identity.

### trust_domain

Host-defined administrative or compromise domain shared by principals that should not be treated as independent for a given policy. Examples can include one service account, one signing key hierarchy, one agent session authority, one CI control plane, or another deployment-specific domain.

This answers: **which principals may still fail together?**

Different `principal_id` values do not prove independence when the policy also requires distinct trust domains.

### verifier_profile

Host-authenticated provenance describing **how verification is produced**. This
is independent of both the controlling `principal_id` and its `trust_domain`.
For model-based verification it records provider, model, model version, system
prompt digest, verifier prompt digest, and relevant toolchain versions. It must
not contain an agent ID or other arbitrary per-run label to manufacture diversity.
`principal_id` must never be redefined as model plus prompt.

Different principals (including differently named agents) may use the same
profile. Policy may optionally require distinct profiles. Without that rule,
sharing a profile alone does not block PASS. When profile provenance is required,
missing or invalid provenance blocks PASS. Any frozen profile change stales the
evidence, even if the replacement would also satisfy separation.

The first implementation compares complete canonical profiles for inequality;
it does not prove epistemic independence or enforce diversity of each individual
model, provider, prompt, or toolchain field. These are host-attested facts, not
facts inferred from candidate output.

### role

The policy-visible function of an actor, such as `builder`, `verifier:<id>`, or `authority`.

## 3. Core identity invariant

Identity requirements are additional PASS conditions, not replacements for existing NARF conditions.

For every frozen identity or separation condition `x`:

```text
x invalid, unavailable, unauthenticated, stale, mismatched, or violated => NARF != PASS
```

A policy may therefore require conditions such as:

```text
builder.principal_id != verifier:security.principal_id
verifier:tests.principal_id != verifier:security.principal_id
builder.trust_domain != verifier:security.trust_domain
authority.principal_id != builder.principal_id
verifier:tests.verifier_profile != verifier:security.verifier_profile
```

The runtime must fail closed when it cannot establish a required identity property.

## 4. Trust boundary

Identity provenance is host-owned.

The candidate, worker, builder output, verifier output payload, or mutable task input must not be able to choose a principal identity or trust domain that NARF later treats as authenticated identity evidence.

The host may derive identity from deployment-specific sources such as an authenticated process boundary, workload credential, signing-key fingerprint, CI/OIDC claim, human authentication session, remote witness key, or another trusted adapter. NARF remains standalone and does not depend on any one identity provider.

NARF evaluates frozen identity facts and rules; it does not authenticate GitHub, OpenAI, an IAM service, a human, or another product directly.

## 5. Frozen binding model

The first implementation should keep identity data explicit and canonical.

Conceptually:

```json
{
  "actors": {
    "builder": {
      "principal_id": "agent:builder:123",
      "trust_domain": "builder-control-plane"
    },
    "verifier:tests": {
      "principal_id": "ci:test-runner:456",
      "trust_domain": "ci-tests"
    },
    "verifier:security": {
      "principal_id": "reviewer:789",
      "trust_domain": "independent-review"
    },
    "authority": {
      "principal_id": "human:approver:abc",
      "trust_domain": "human-approval"
    }
  },
  "separation": [
    ["builder", "verifier:security", "principal_id"],
    ["verifier:tests", "verifier:security", "principal_id"],
    ["builder", "verifier:security", "trust_domain"],
    ["builder", "authority", "principal_id"]
  ]
}
```

Exact public API names may differ, but the semantic data must be frozen and included in authenticated contract evidence before accepted verifier evidence can authorize an effect.

## 6. Verifier evidence binding

When identity constraints are enabled, accepted verifier evidence must bind at minimum to:

```text
contract
session
task
candidate/state
requirement
verifier_id
verifier_version
principal_id
trust_domain when required by policy
status
artifact digest
verifier_profile when required by policy
```

Changing a verifier's required identity after contract freeze is a goalpost/policy change, not a harmless rebinding.

A verifier binding that has the correct logical `verifier_id` but the wrong required `principal_id` must fail closed.

## 7. Authority

Human or policy authority remains a host integration concern. Identity binding must not turn NARF into a product-intent engine.

An authority approval can be represented as required, authenticated evidence whose identity is frozen and whose separation constraints are evaluated like other required actors. A host may use a human, policy service, signed witness, CI approval route, or another authenticated authority.

If authority is required by policy, missing authority evidence prevents PASS.

## 8. Ordering

The security requirement is complete current evidence and valid separation at the effect boundary. The first identity implementation does not need to claim that logical arrows prove wall-clock ordering unless explicit stage-order evidence is added.

Therefore:

```text
builder -> verifier A -> verifier B -> authority -> NARF -> effect
```

initially means that all listed roles are required in the authorization chain. It does not by itself prove a temporal sequence among verifier executions.

If strict ordering becomes a requirement, it needs an explicit authenticated predecessor/stage binding rather than timestamp comparison alone.

## 9. Required adversarial cases

Before the feature can be called PASS, tests must cover at least these cases:

1. builder principal equals required verifier principal -> BLOCKED;
2. builder principal equals independent verifier principal under a distinct-principal rule -> BLOCKED;
3. verifier A principal equals verifier B principal when policy requires separation -> BLOCKED;
4. verifier IDs differ but their required principal is the same -> BLOCKED;
5. principal IDs differ but trust domains are equal when policy requires domain separation -> BLOCKED;
6. required principal identity is missing -> BLOCKED;
7. required trust domain is missing -> BLOCKED;
8. authority is required but absent -> BLOCKED;
9. authority principal equals builder principal when forbidden -> BLOCKED;
10. bound identity changes after verification but before effect -> BLOCKED;
11. old authority/identity evidence is replayed for another contract/session/candidate/effect -> BLOCKED;
12. candidate-controlled output tries to self-assert a different principal/trust domain -> ignored or BLOCKED, never PASS;
13. correct independent identities plus all existing NARF conditions -> PASS;
14. identity-enabled PASS remains single-use and pre-effect revalidation still applies.
15. different principals sharing one verifier profile remain allowed without a profile-separation rule;
16. the same model and prompts under different agent IDs fail a distinct-profile rule;
17. distinct-profile policy requires authenticated, complete profile provenance;
18. a frozen profile change before verification, during verification, or before effect blocks authorization.

## 10. Backward compatibility

The existing reference API and existing contracts must keep their current semantics unless identity enforcement is explicitly configured.

Adding the identity feature must not silently reinterpret current `verifier_id` as a cryptographic or human principal identity.

In particular:

```text
verifier_id != principal_id
```

must remain a documented distinction.

## 11. Implementation gate

Runtime implementation may begin only if the following remain true on the frozen base revision:

- current NARF reference checks are green;
- the existing task/candidate/policy/verifier/effect bindings remain intact;
- identity provenance stays outside candidate/worker control;
- NARF remains standalone and identity-provider agnostic;
- missing identity information fails closed only when the frozen policy requires that information;
- no existing PASS is relabeled merely by documentation.

The implementation should then be introduced with focused unit/adversarial tests first, followed by the smallest runtime change needed to satisfy them.

## 12. Reference API extension

`NARFGate.freeze_contract(..., identity_policy=...)` accepts a strict canonical
JSON policy with `actors`, `separation`, and optional `authority_verifier_id`.
Each actor records `principal_id` and optional `trust_domain` and
`verifier_profile`. Roles are `builder`, `verifier:<verifier_id>`, and `authority`.
An authority route must occur in the frozen requirements; that route uses the
`authority` role instead of `verifier:<id>`. An authority identity alone never
counts as an approval. All configured roles and all required verifier routes
require principal identities. Separation triples select `principal_id`,
`trust_domain`, or `verifier_profile`.

Profiles use one of these canonical shapes:

```json
{"toolchain": {"unit-runner": "3.2"}}
```

```json
{
  "model": {"provider": "example-provider", "name": "review-model", "version": "pinned-version"},
  "system_prompt_sha256": "<64 lowercase hex digits>",
  "verifier_prompt_sha256": "<64 lowercase hex digits>",
  "toolchain": {"review-adapter": "1.0"}
}
```

Tool-only profiles require a nonempty toolchain. Model profiles require all
model fields and both prompt digests; their toolchain may be empty when no tools
are relevant. Toolchain names and versions must be nonempty strings. Unknown
profile fields are invalid. Identity strings are opaque host-defined names;
NARF does not interpret providers, accounts, prompts, or model names.

`VerifierBinding` gains optional `principal_id`, `trust_domain`, and
`verifier_profile` fields, supplied by the host that authenticates the producer.
`open_session(..., identity_probe=...)` requires a trusted callback returning
the current actor map for identity-enabled contracts. The gate checks it before
and after verification and at finalization and effect entry. Frozen fields and
profile provenance must match the producer binding and the current host facts.

Configured profiles are required and frozen even without a separation rule.
Profile separation additionally requires complete profiles on both named roles.
Hosts that do not configure profiles retain principal/domain-only enforcement.

Identity-enabled contracts and their receipts use evidence version 2 so a
version-1 gate rejects them instead of silently ignoring the new conditions.
Omitting `identity_policy` retains version-1 contracts and receipt semantics.
The authenticated contract binds the complete policy and its canonical digest;
verification evidence additionally binds the actor, principal, domain, profile,
policy digest and effect identity/version. Decision and consumption evidence
remain bound to that contract and policy digest.

This API is available directly on `NARFGate`. Existing host examples and the
`OperationBoundGate` convenience wrapper retain their version-1 interfaces;
they do not automatically opt into identity enforcement. Invalid policy syntax
raises `NARFError`; missing, mismatched or insufficient required identity facts
produce a `BLOCKED` session. Attempted execution through a blocked session raises
`NARFError` before invoking the producer or effect.
