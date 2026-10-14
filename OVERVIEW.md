# MGnarf overview

## In plain English

AI systems can write code and take actions quickly, but **“looks good” is not the same as “proved safe to run.”** MGnarf is a small fail-closed safety gate between AI-assisted work and the action that work is allowed to trigger.

Before an action is allowed, MGnarf can ask:

- Are we still approving the exact same task and candidate that were checked?
- Is the exact frozen verifier requirement set still the one being used?
- Did every required verifier actually run and pass?
- Is the evidence authentic, complete and current?
- If identity separation is configured, did the required independent actors really satisfy that frozen policy?
- If stage ordering is configured, was each required stage accepted only after its authenticated predecessor?
- Has relevant state, authority, revocation or policy changed?
- Has this real-world operation already been consumed?

If any required condition is missing, uncertain or invalid, MGnarf does **not** manufacture PASS.

Think of it as a checkpoint for AI-assisted automation: **evidence first, action second**.

## Where MGnarf goes

Put MGnarf **between verified work and the real effect** — as close as practical to the deploy, database write, email/API mutation, file publication or device command that changes the outside world.

```text
AI / automation
      |
      v
produces candidate
      |
      v
verification / tests
      |
      v
    MGNARF
      |
      v
real effect
```

The credential that can perform the protected effect must stay on the trusted-host side. If the agent can call the effect path directly, it can bypass the gate.

See [INTEGRATION-GUIDE.md](INTEGRATION-GUIDE.md).

## Current release status

The current published stable release is **v1.70**. Its immutable scope and evidence remain in:

- [RELEASE-v1.70.md](RELEASE-v1.70.md)
- [TEST-REPORT-v1.70.md](TEST-REPORT-v1.70.md)
- [GitHub release v1.70](https://github.com/miguelkolli/mgnarf/releases/tag/v1.70)

The stable release is bound to exact source commit `b811a13eab9cacd9f922b1f15097aa6bf700fc01`. Later documentation cleanup and development on `main` do not change that immutable release evidence.

The previous immutable stable release remains v1.61:

- [RELEASE-v1.61.md](RELEASE-v1.61.md)
- [TEST-REPORT-v1.61.md](TEST-REPORT-v1.61.md)

## Core rule

```text
PASS only when the exact frozen authorization has complete authentic evidence
for every required condition that was configured, current authority still
supports that authorization, and the guarded effect path remains valid.
```

Base MGnarf includes exact task/candidate/requirements/policy/effect binding, N/N verifier coverage, current-state/revocation checks, authenticated receipts and single-use local effect admission.

Optional stronger boundaries add additional conditions rather than replacing the base rule.

## Identity separation

Different verifier names do not prove independence. Identity-enabled MGnarf can bind host-authenticated facts such as:

```text
principal_id
trust_domain
verifier_profile
```

A separation policy may require the builder, independent verifier and authority to differ along selected axes. Candidate/worker self-report cannot populate trusted identity fields.

See [IDENTITY-BOUNDARY.md](IDENTITY-BOUNDARY.md).

## Authenticated stage ordering

Identity answers **who** supplied required evidence. Stage ordering answers **which authenticated predecessor had to exist first**.

When `stage_order` is configured, the first implementation freezes one complete linear permutation of all required `requirement_id` values. Ordered contracts use evidence version 3.

```text
frozen candidate/context
  -> tests PASS
  -> security PASS bound to tests receipt
  -> authority PASS bound to security receipt
  -> MGnarf decision bound to final chain head
  -> existing guarded effect path
```

The first stage binds to a session/contract-owned chain seed. Every later stage binds to the authenticated predecessor receipt ID and canonical digest. A future stage is rejected before its producer runs. Same-stage concurrent and same-thread re-entrant admission is single-winner inside one session.

Stage ordering is a **causal authenticated evidence chain**, not a timestamp convention. It does not prove physical wall-clock chronology, verifier epistemic independence, distributed consensus or cross-process shared-session ordering.

See [STAGE-ORDER-BOUNDARY.md](STAGE-ORDER-BOUNDARY.md).

## Stronger execution boundaries

Depending on threat model, the hardened line can additionally compose:

```text
identity separation
  -> authenticated stage order (optional)
  -> monotonic authority revision
  -> stable semantic operation identity
  -> fence transport
  -> target-side commit enforcement where available
```

- [AUTHORITY-REVISION.md](docs/security/AUTHORITY-REVISION.md) makes relevant authority change-and-restore visible through a trusted-host monotonic revision.
- [OPERATION-IDEMPOTENCY.md](docs/security/OPERATION-IDEMPOTENCY.md) keeps one semantic real-world operation single-use across fresh contracts/retries.
- [FENCED-EFFECT-BOUNDARY.md](FENCED-EFFECT-BOUNDARY.md) transports a bound fence into the effect adapter.
- [POSTGRES-FENCED-TARGET.md](docs/security/POSTGRES-FENCED-TARGET.md) is the measured PostgreSQL Layer C example where authority/fence validity is checked at the database commit boundary.

A stronger wrapper must preserve an ordered v3 contract end-to-end or reject it. Silent downgrade to unordered semantics is not allowed.

## Trust model

The integrating trusted host owns:

- HMAC receipt key and receipt-store authority;
- frozen task/candidate/state/requirements/policy/effect bindings;
- verifier selection and execution;
- identity/profile provenance when configured;
- stage-order configuration and chain admission when configured;
- state/revocation probes;
- semantic operation identity when configured;
- any external consumption/fencing authority;
- the gated effect credential/callback.

Candidate or worker output is not host evidence. There is intentionally no candidate evidence-submission or PASS-override API.

Python attribute privacy is not a security boundary. Untrusted code must be separated from host authority by an enforced OS/process/sandbox/service boundary appropriate to the threat model.

## Important limits

MGnarf does not prove:

- verifier domain logic is correct;
- differently named principals/models/providers are actually independent in the real world;
- physical wall-clock order from stage ordering;
- arbitrary distributed-host consensus;
- exactly-once remote completion after ambiguous acknowledgement or callback failure;
- rollback resistance if every preserving authority history is rewound together;
- universal TOCTOU elimination for arbitrary APIs/clouds/databases/devices;
- safety if the trusted host deliberately bypasses the protected path;
- independent external security certification.

The PostgreSQL Layer C guarantee is specific to its tested functions/transactions/role model. A green limitation witness means the documented limitation reproduced as expected; it is not a security PASS.

## Repository map

- [README.md](README.md) — front door and navigation.
- [NARF-SPEC.md](NARF-SPEC.md) — behavioral specification.
- [ARCHITECTURE.md](ARCHITECTURE.md) — architecture and invariants.
- [INTEGRATION-GUIDE.md](INTEGRATION-GUIDE.md) — practical placement.
- [HOST-CONTRACT.md](HOST-CONTRACT.md) — trusted-host obligations.
- [HARDENED-PATHS.md](HARDENED-PATHS.md) — choose stronger paths by threat model.
- [IDENTITY-BOUNDARY.md](IDENTITY-BOUNDARY.md) — identity separation.
- [STAGE-ORDER-BOUNDARY.md](STAGE-ORDER-BOUNDARY.md) — authenticated causal ordering.
- [AUTHORITY-REVISION.md](docs/security/AUTHORITY-REVISION.md) — monotonic authority revision.
- [COMPOSED-OPERATION-PATH.md](docs/security/COMPOSED-OPERATION-PATH.md) — composed authority/stable-operation path.
- [FENCED-EFFECT-BOUNDARY.md](FENCED-EFFECT-BOUNDARY.md) — fence transport.
- [POSTGRES-FENCED-TARGET.md](docs/security/POSTGRES-FENCED-TARGET.md) — measured commit-time fencing.
- [docs/](docs/) — secondary and historical documentation.
- [RELEASE-v1.70.md](RELEASE-v1.70.md) / [TEST-REPORT-v1.70.md](TEST-REPORT-v1.70.md) — current stable scope/evidence.
- [RELEASE-v1.61.md](RELEASE-v1.61.md) / [TEST-REPORT-v1.61.md](TEST-REPORT-v1.61.md) — previous immutable stable.

## Run the tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests tools
```

A skip is not PASS in the required reference workflow. A boundary that cannot be exercised must remain BLOCKED/UNVERIFIED rather than being guessed green.

> PINKY: Did the checks actually run?  
> BRAIN: Keep the evidence, and keep the unverified boundaries visible.
