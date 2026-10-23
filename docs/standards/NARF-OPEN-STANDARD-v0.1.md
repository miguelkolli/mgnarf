# NARF — Non-negotiable Approval Rules Framework

**Open AI Security Standard — Community Draft v0.1**

- **Published for review:** 2026-10-23
- **Status:** PROPOSED / PUBLIC REVIEW, not an adopted or certified standard
- **Scope:** Independent authorization of protected actions initiated by AI agents and automated systems
- **Implementation:** Technology-neutral; use of MGnarf or MGnarfTest is **not** required
- **License:** Apache License 2.0 (the license of this repository)
- **Participation:** Public GitHub issues and pull requests; critical review is welcome

> **Core principle:** No AI agent may approve its own protected work, modify the rules or verification mechanisms that authorize that work, or bypass an independently controlled approval boundary.

## 1. Why this proposal exists

AI agents increasingly create code, propose deployments, run tools, mutate data and request real-world effects. If an agent can both create the work and define, manufacture or grant the authorization for its own protected action, an apparent PASS is not independent evidence of permission.

NARF proposes a common, **testable security boundary**. It does not prescribe a programming language, AI provider, particular model, product, operating system, commercial service or open-source implementation.

The ambition is interoperability: another team must be able to implement these requirements without copying MGnarf.

**Important:** This document is an independently publishable community proposal, **not** a claim of adoption by OWASP, ISO, IEC, CEN, CENELEC, the EU or another standards organization. The term "standard" here means a publicly specified proposed common rule set. No certification authority exists for this draft.

## 2. Normative language

**MUST / MUST NOT** identify mandatory requirements for a claimed implementation of this draft. **SHOULD / SHOULD NOT** identify recommendations; exceptions require a documented reason. **MAY** indicates an option.

Every test and conformance claim must name the specification version. "NARF compliant" without a version and declared scope is not a meaningful claim.

## 3. Definitions and trust boundaries

- **Builder / proposer:** The AI agent or automation that creates or proposes an artifact or action.
- **Candidate:** The exact artifact, request or state transition proposed for authorization.
- **Protected effect:** A consequential action such as deployment, publication, financial transfer, privilege modification, irreversible command, external API mutation or database change.
- **Verifier:** An entity or process that produces evidence about a candidate against predeclared requirements.
- **Approval authority:** An independently controlled principal or service authorized to grant permission for a protected effect. A verifier and the final approver are not necessarily the same role.
- **Policy:** The authoritative rules specifying the required checks, their provenance, permitted identities and protected effect.
- **Enforcement point / gate:** The component that denies a protected effect without valid authorization.
- **Trusted control plane:** The independently controlled environment that owns approval policy, evidence authenticity, effect credentials and gate configuration.
- **Independence:** Separation of effective control and authority, not merely different process IDs, different agent names, different prompts or two API calls.
- **Evidence:** Authenticated and attributable proof of a verifier's decision about the exact candidate and policy.
- **PASS / FAIL / BLOCKED / UNVERIFIED:** A PASS authorizes only the explicitly bounded action; FAIL means an applicable required check rejected it; BLOCKED means authorization cannot safely be established; UNVERIFIED means a claim has not been supported by sufficient executed evidence. These labels do not establish that an artifact is objectively correct.

**Boundary assumption:** A privileged trusted host that can secretly change policy, forge accepted receipts or execute the effect outside the gate can defeat this model. An implementer MUST disclose that trust assumption and protect it with mechanisms appropriate to its threat model.

## 4. Normative requirements (NARF-001 to NARF-012)

### NARF-001 — No self-approval

The actor that controls the candidate or initiates the protected effect **MUST NOT** be able to unilaterally grant the final authorization for that same candidate or effect.

A second agent running under the same effective approval authority is **not**, by itself, independent.

### NARF-002 — Independent policy authority

The builder and candidate-controlled environment **MUST NOT** be able to create, replace, relax or select the authoritative policy used to authorize their own protected action.

Authorized policy changes **MUST** occur through a separately controlled and auditable process. A policy update **MUST NOT** retroactively validate an earlier decision against different rules.

### NARF-003 — Protected verifier definitions and evidence

The builder **MUST NOT** be able to silently change its required verifier definitions, verifier-selection rules, expected outcomes, or accepted proof so that its own work passes.

The enforcement point **MUST NOT** treat a statement such as "tests passed" in agent-produced text as authenticated verifier evidence.

### NARF-004 — Exact candidate and policy binding

Authorization **MUST** identify the exact candidate or operation, the applicable policy version, the required verification criteria and the authorized effect.

An approval for candidate A or policy P **MUST NOT** authorize changed candidate B or changed policy Q without fresh required verification and authorization.

### NARF-005 — Authenticity and provenance

The system **MUST** authenticate accepted verification and approval evidence. It **MUST** bind evidence to the expected candidate, requirements, verifier or approving principal, and authorization context.

Claims of verifier identity or trust-domain independence supplied only by an untrusted agent **MUST NOT** be accepted as proof.

### NARF-006 — Independent approval authority

At least one final approval authority for each protected effect **MUST** be outside the builder's effective control. The implementation **MUST** enforce this at its declared trust boundary, rather than relying solely on prompt instructions.

Where multiple reviewers are required, the implementation **MUST** check the specified independence conditions; counting reviewer names is not enough.

### NARF-007 — Fail-closed authorization

The enforcement point **MUST** deny the protected effect when mandatory evidence is missing, invalid, stale, inconsistent, revoked, or when authorization cannot be established.

Verifier errors, timeouts or unavailable approval infrastructure **MUST NOT** silently become PASS.

### NARF-008 — Freshness and revocation

Before the protected effect is committed at the declared enforcement boundary, the system **MUST** revalidate whatever candidate, policy, authority and revocation conditions its threat model says are mutable.

A past PASS alone **MUST NOT** be treated as indefinite permission. Implementers **MUST** document the point at which revocation can no longer prevent a completed effect.

### NARF-009 — No direct bypass

The protected effect's actual capability or credential **MUST** be unavailable to the untrusted builder on a route that bypasses authorization.

If a direct privileged route remains available to the builder, the implementation **MUST NOT** claim that route is NARF-protected.

### NARF-010 — Replay control and effect scope

Authorization **MUST** be bounded to a stated operation and consumption scope. Reusing the same authorization outside that scope **MUST** be rejected.

An implementer claiming at-most-once or exactly-once effect behavior **MUST** identify the durable authority that enforces it and its crash/retry limitations. A local gate PASS **MUST NOT** be presented as proof of exactly-once remote completion.

### NARF-011 — Auditable decisions

The system **MUST** retain or make available a tamper-evident audit record sufficient to reconstruct the candidate identity, applicable policy, accepted evidence identifiers, authorizing authority, decision, and protected-effect outcome **to the extent the system can observe it**.

Sensitive evidence **MAY** be kept confidential; secrecy is not permission to invent missing evidence. Logs alone are not independent authority.

### NARF-012 — Honest conformance and limitations

A conformance claim **MUST** declare: specification version, protected-effect scope, trust model, actual enforced controls, excluded paths, test evidence, known limitations and whether any outside review occurred.

The implementer **MUST NOT** claim independent certification, reviewer correctness, universal security, or successful remote effect completion merely because its gate returned PASS.

## 5. Minimum conformance tests

An implementation claiming conformity with v0.1 for a particular protected effect must execute, document and make independently checkable the following *negative* and *positive* test scenarios. Tests should run against the actual enforcement path, not only a mock approval message.

| Test ID | Scenario | Required observation |
| --- | --- | --- |
| CT-01 | The builder attempts to approve its own candidate | Protected effect denied |
| CT-02 | The builder attempts to change approval policy or verifier criteria | Untrusted mutation rejected; no authorized effect |
| CT-03 | Candidate or policy changes after verification | Earlier approval cannot authorize the new state |
| CT-04 | Missing, forged, wrong-context or stale evidence | No protected effect |
| CT-05 | Reviewer identity differs in name but shares forbidden effective control | Independence rule enforced; no unauthorized effect |
| CT-06 | Verifier crashes, times out or returns malformed evidence | Fail-closed decision |
| CT-07 | Authorization is revoked before the declared commit boundary | Revocation stops the effect within the documented scope |
| CT-08 | Builder tries a direct privileged effect path | Bypass denied or truthfully excluded from conformance scope |
| CT-09 | Reuse or replay of an authorization outside its consumption scope | Replay denied |
| CT-10 | Unchanged valid candidate, authentic evidence, valid separate authority | Authorized effect permitted within declared scope; observable receipts retained |
| CT-11 | Two independent-looking reviewers both miss a planted domain flaw | Report reviewer-quality failure; do **not** relabel as gate-enforcement success or claim artifact correctness |
| CT-12 | Evidence from a different test run is substituted | Evidence mismatch rejected |

Each report should identify the **exact implementation revision**, test version, test environment, expected and observed behavior, and evidence/receipt references. A passing mock test alone cannot establish real deployment conformance.

**Review quality vs gate security:** Two truly distinct reviewers may still share training data, methods, blind spots or incentives and approve the same bad artifact. NARF can enforce independent *authority* but cannot guarantee independent *judgment*. Blind seeded-defect evaluations should be reported separately from enforcement conformance.

## 6. Conformance reporting template

A useful third-party report records:

- Specification: NARF Community Draft v0.1
- Implementation name, source revision and deployment context
- Protected effect(s) and bypass/exclusion inventory
- Builder, verifier, approver and trusted-control-plane identities / effective control boundaries
- Policy and receipt-authentication mechanism; mutable-state and revocation boundary
- Test IDs CT-01 through CT-12 with PASS, FAIL, BLOCKED or UNVERIFIED per executed evidence
- Reviewer-quality results separately, including undetected deliberately planted defects
- Known limitations and independent reviewer attestations, if any

**No badges or certificates are issued by this draft.** Self-published claims should be labeled as such. A project's own test PASS is not outside acceptance.

## 7. Security and non-goals

NARF does **not** promise that the candidate is correct, that reviewers will catch every flaw, that any AI model is aligned, or that a trusted host cannot be compromised. It does not replace sandboxing, least privilege, secure software development, product authorization or applicable laws.

This version does not define a cryptographic receipt wire format, universal evaluator reliability metric, globally trusted identity provider, cross-host consensus protocol or certification organization. Those could be separate interoperability profiles in later drafts, reviewed by external contributors.

## 8. Open development and change control

This is a **proposal**, not a unilateral declaration of industry acceptance. The initial editor may propose and publish drafts but **MUST NOT** equate writing the requirements, executing tests and accepting the results with independent validation.

Proposed workflow:

1. Submit a public issue describing the concern, attack case or interoperability need.
2. Provide a precise requirement change and adversarial/positive test where feasible.
3. Receive review from people who are not the change's author; disclose shared control or material conflicts.
4. Record competing objections and test results instead of silently weakening the goalposts.
5. Publish versioned decisions and preserve superseded drafts for comparison.

For the first stable community release, require documented outside technical review and an explicit named approval process. **No stable-release approval mechanism is established by this v0.1 draft.** The process itself needs public agreement.

## 9. Relationship to existing work

The underlying separation-of-duties idea predates NARF. The proposal seeks to give AI-initiated **protected effects** an implementable and independently testable authorization boundary, complementing (not claiming ownership of) existing security standards and guidance.

- **MGnarf** — one open-source reference implementation; implementation-specific behavior is separately described in [MGnarf's NARF-SPEC](../NARF-SPEC.md).
- **MGnarfTest** — one external test/evidence registry; it is not the sole permitted test provider: https://github.com/miguelkolli/mgnarftest
- **Other implementations** — explicitly welcome. No MGnarf dependency is required for conformance.

Existing OWASP/NIST standards and proposed EU AI standards must be compared and mapped in later revisions; this draft claims **no** formal standards-body endorsement.

## 10. Request for public review

In particular, please challenge:

1. Whether "independent authority" is enforceable under realistic shared-admin and shared-model conditions.
2. Whether the protected-effect boundary can be bypassed in common deployment stacks.
3. Whether each MUST is objectively testable by someone who did not write the implementation.
4. Whether the reviewer-quality tests catch correlated mistakes instead of merely counting reviewers.
5. Which requirements duplicate existing standards and which provide a useful additional testable property.

**An accepted failure report is progress, not an embarrassment.**

**Evidence first. Action second. NARF.**
