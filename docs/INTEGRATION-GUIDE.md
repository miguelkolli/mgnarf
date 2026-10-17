# MGnarf integration guide

This guide answers the practical question: **where does MGnarf go in a real system?**

MGnarf is not a general wrapper around an AI model. It belongs at the boundary between verified work and the real-world effect that work is allowed to trigger.

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
irreversible or security-relevant effect
```

Examples of an effect are a production deploy, database migration, email send, API mutation, file publication, payment request, infrastructure change, or device command.

The most important installation rule is therefore:

> Put MGnarf as close as practical to the effect, and keep the credential or authority for that effect on the trusted-host side of the gate.

If an agent can call the production deploy API, database write credential, email provider, or device API directly, it can bypass MGnarf and the gate does not protect that path.

## 1. Get the reference implementation

MGnarf v1.70 is the current stable Python reference implementation. The core gate uses the Python standard library. Optional authority adapters add dependencies only for their own measured boundary.

```bash
git clone https://github.com/miguelkolli/mgnarf.git
cd mgnarf
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests tools
```

For a first integration, keep the MGnarf source and the host wrapper under your control and import from `src/narf`. The repository does not currently claim a universal one-command production installer for every host stack.

Before production use, read [HOST-CONTRACT.md](HOST-CONTRACT.md), [REFERENCE-HOST.md](security/host/REFERENCE-HOST.md), and [PROCESS-BOUNDARY.md](security/host/PROCESS-BOUNDARY.md).

## 2. Choose your stack

| Your system | Put MGnarf here | Keep trusted | Freeze before verification |
| --- | --- | --- | --- |
| GitHub Actions -> Vercel/Railway/other deploy | after build/test evidence, immediately before the production deploy call | production deploy credential, receipt authority, verifier execution | exact commit/candidate, policy, required checks, deploy target |
| AI coding agent | between agent-produced changes and `git push`, merge, release, or deploy | Git/release/deploy credential and host policy | exact candidate SHA, task, verifier set, target operation |
| PostgreSQL migration or data mutation | immediately before the transaction that changes production data/schema | DB write role, transaction/fencing authority | migration/data payload, schema target, policy, checks |
| Email or external API action | immediately before `send()` / mutation request | provider token/API credential | exact recipient/request payload, policy, checks |
| Generic Python/file workflow | immediately before final write/publish/callback | final target authority and receipt key | exact bytes/task/state/requirements |
| IoT/device command | immediately before the real device control API call | device/cloud credential | exact device, command, value, policy, checks |

The table is a placement guide, not a claim that MGnarf automatically understands every provider. The integrating host supplies the actual verifier callbacks, state probes, revocation logic, and effect callback.

## 3. The integration pattern

A host integration should have four zones:

```text
UNTRUSTED / CANDIDATE SIDE
  agent output, generated code, proposed SQL, proposed email, proposed API payload
                    |
                    v
TRUSTED VERIFICATION SIDE
  freeze exact task/candidate + run required verifiers + authenticate evidence
                    |
                    v
MGNARF GATE
  exact binding + N/N evidence + revocation/state revalidation + single-use effect
                    |
                    v
TRUSTED EFFECT SIDE
  credential + deploy/send/write/migrate/device command
```

The candidate may propose the action. It must not own the final authority that performs the action.

## 4. Minimal host flow

The current public API follows this sequence:

```text
freeze_contract(...)
    -> open_session(...)
        -> execute(each frozen requirement)
            -> finalize()
                -> execute_effect()
```

`execute_effect()` requires an authenticated PASS, rejects a consumed effect, rechecks current state/revocation, revalidates the decision, persists consumption evidence, and only then invokes the host-owned effect callback.

A simplified host skeleton looks like this:

```python
from pathlib import Path

from narf import (
    EffectBinding,
    FrozenState,
    NARFGate,
    ReceiptStore,
    Requirement,
    VerifierBinding,
    VerifierResult,
    sha256_bytes,
)

# Host-owned secret. Do not give this to the agent/worker.
receipt_key = load_host_secret()
store = ReceiptStore(Path("/trusted/narf-receipts"), receipt_key)
gate = NARFGate(store)

# Freeze immutable input before verification.
task = {
    "operation": "deploy",
    "candidate": candidate_sha,
    "target": "production",
}

state = FrozenState(
    candidate_sha256=candidate_sha,
    requirements_sha256=requirements_or_goalpost_sha,
    policy_sha256=policy_sha,
)

requirements = [
    Requirement("tests", "tests", "1"),
    Requirement("policy", "policy", "1"),
]

contract_id = gate.freeze_contract(
    task,
    task_id="prod-deploy",
    requirements=requirements,
    effect_id="deploy-production",
    effect_version="1",
    state=state,
)

session = gate.open_session(
    contract_id,
    task,
    verifier_bindings=[
        VerifierBinding("tests", "1", run_tests),
        VerifierBinding("policy", "1", check_policy),
    ],
    effect_binding=EffectBinding(
        "deploy-production",
        "1",
        deploy_exact_frozen_candidate,
    ),
    state_probe=read_current_frozen_state,
    revocation_probe=is_revoked,
)

for requirement_id in session.requirements():
    session.execute(requirement_id)

decision = session.finalize()
if decision["result"] != "PASS":
    raise RuntimeError(decision)

# In a real host, hold the required authority lock / transaction / fencing
# protocol across the relevant final state and effect path.
result = session.execute_effect()
```

This is an integration pattern, not a drop-in production configuration. Your host still has to define what state is relevant, which verifiers are required, how revocation works, and how the real effect is serialized.

## 5. Pattern A — GitHub Actions -> Vercel / Railway / another deploy target

### Where MGnarf goes

```text
commit / PR
   -> build
   -> tests
   -> security/policy checks
   -> freeze exact deploy candidate
   -> MGnarf
   -> production deploy API/CLI
```

### What stays trusted

- the production deploy token or credential;
- the receipt key and receipt authority;
- the code that selects and runs required verifiers;
- the target environment (`production`, service/project ID, region if relevant);
- the final deploy callback.

### What gets frozen

At minimum, bind the exact candidate being deployed and the target operation. For Git-backed deployments this will usually include an exact commit/candidate digest rather than a moving branch name.

Do not protect `deploy main`; protect the exact candidate that `main` resolved to when the contract was frozen.

### Failure examples that should block

- tests were never run;
- a required security check is missing;
- the commit changed after verification;
- production policy changed after PASS;
- the deploy was revoked;
- the same single-use authority is replayed.

## 6. Pattern B — AI coding agent -> push / merge / deploy

### Where MGnarf goes

```text
coding agent
   -> proposed changes
   -> host freezes candidate
   -> host runs tests/verifiers
   -> MGnarf
   -> host-owned git push / merge / deploy
```

### What stays trusted

The agent must not hold a credential that lets it bypass the protected effect. If MGnarf protects production deploy but the agent also has an unrestricted production token, the integration is bypassable by design.

The trusted host should own the GitHub/release/deploy credential and expose only the gated action the agent is allowed to request.

### What gets frozen

- exact task;
- exact candidate tree/commit/digest;
- exact verifier requirement set;
- policy/goalpost state;
- target operation and environment.

### Good demo

Give the agent a changed candidate after tests have passed. The state probe should detect the change and `execute_effect()` should refuse the deploy. Then repeat with the original frozen candidate and valid evidence.

That demonstrates the difference between ordinary “tests passed earlier” CI and last-moment bound revalidation.

## 7. Pattern C — PostgreSQL migration or production data mutation

### Where MGnarf goes

```text
proposed migration / mutation
   -> validate SQL / schema / policy / backup prerequisites
   -> freeze exact payload and target state
   -> MGnarf
   -> production DB transaction
```

### What stays trusted

- production write credentials;
- transaction/fencing authority;
- migration runner;
- required verifier selection;
- rollback/consumption authority when used.

### What gets frozen

Freeze the exact operation, not merely a filename such as `latest.sql`. Useful bindings can include:

- migration content digest;
- target database/environment;
- expected schema revision;
- policy revision;
- required checks;
- semantic operation ID when using an operation-bound authority.

### Integration note

MGnarf does not replace the database transaction. The trusted host should combine MGnarf's pre-effect checks with the database's own transaction, advisory lock, fencing token, or equivalent concurrency control. Relevant state changes and the effect path must use the same authority protocol.

## 8. Pattern D — email, webhook, ticketing, payment request, or external API mutation

### Where MGnarf goes

```text
agent proposes request
   -> validate recipient/payload/policy
   -> freeze exact request
   -> MGnarf
   -> provider API mutation
```

### What stays trusted

- provider API token;
- final request construction or immutable frozen request bytes;
- recipient/target policy;
- effect callback.

### What gets frozen

The effect payload matters. Bind enough information so a PASS for one message or request cannot silently authorize another.

For an email this can include recipient, subject/body digest, attachments digest, sender identity, and policy revision. For a generic API mutation it can include method, target resource, canonical request payload digest, and semantic operation ID.

### Important limit

Authorization consumption does not prove exactly-once remote completion. A provider may accept the request while the host loses the acknowledgement. Preserve the ambiguous reservation and use provider-side idempotency/transaction semantics where available; do not automatically free authority just because the acknowledgement was uncertain.

## 9. Pattern E — generic Python/file publication

The repository's reference host is the best starting example for this pattern.

```text
producer
   -> candidate bytes
   -> verifier(s)
   -> MGnarf
   -> exclusive final file publication
```

The reference host demonstrates:

- host-owned receipt key and directory;
- frozen task/candidate/policy/effect payload;
- host-owned verifier callbacks;
- immutable effect input;
- authority locking around state changes and `execute_effect()`;
- a real filesystem effect rather than a no-op callback;
- stale/revoked state blocking the write;
- replay rejection.

See [REFERENCE-HOST.md](security/host/REFERENCE-HOST.md).

## 10. Pattern F — IoT / device control

### Where MGnarf goes

```text
agent / automation decides desired command
   -> policy + state checks
   -> freeze exact device command
   -> MGnarf
   -> host-owned device/cloud API call
```

### What stays trusted

- device/cloud token;
- mapping from logical device to real device ID;
- safety policy;
- final device command callback.

### What gets frozen

For example:

```json
{
  "device": "zone-a-lighting",
  "command": "set_brightness",
  "value": 30,
  "policy_revision": "...",
  "operation_id": "..."
}
```

If the desired value, device mapping, safety policy, or relevant state changes after verification, the state probe should make the effect stale and block it.

MGnarf is not a physical safety controller. Device interlocks and vendor/device safety mechanisms remain separate requirements.

## 11. How to decide what belongs in `FrozenState`

Ask: **what could change after verification that would make this PASS no longer valid?**

Anything in that answer needs to be represented by the frozen task/bindings or by the three host-controlled state digests:

- `candidate_sha256` — the exact candidate/effect input identity;
- `requirements_sha256` — external goalpost or requirement state relevant to the decision;
- `policy_sha256` — the policy revision relevant to the decision.

The state probe must recompute the current values from trusted host state. Do not ask the untrusted candidate to tell MGnarf whether it changed.

## 12. Credentials and bypass resistance

A correct-looking MGnarf call is not enough. The architecture has to make bypass materially harder than using the gate.

Bad:

```text
agent -----> MGnarf -----> deploy API
   \---------------------> deploy API   # bypass
```

Better:

```text
agent ---> request to trusted host ---> MGnarf ---> deploy API
                                      [deploy token lives here]
```

For stronger isolation, place the trusted host in a separate process, OS identity, container/sandbox boundary, or service whose credentials are not available to the agent. The appropriate boundary depends on the threat model.

## 13. Host serialization is still required

MGnarf revalidates state immediately before the effect, but the integrating host must still serialize relevant authority changes with the complete synchronous effect path.

For a single-process host this may be a shared lock. Across processes or machines, use a transaction, distributed lock/fencing protocol, database authority, signed witness, or another mechanism appropriate to the deployment.

See [HOST-CONTRACT.md](HOST-CONTRACT.md) for the exact obligation.

## 14. Rollback and stronger single-use authority

The filesystem receipt store authenticates contents but is not rollback resistant by itself. If privileged deletion or rollback is in scope, use an independent preserving authority such as the measured PostgreSQL or signed-witness paths, or combine independent authorities where appropriate.

Relevant documents:

- [ROLLBACK-BOUNDARY.md](security/ROLLBACK-BOUNDARY.md)
- [ROLLBACK-HARDENING.md](security/ROLLBACK-HARDENING.md)
- [POSTGRES-AUTHORITY.md](security/authority/POSTGRES-AUTHORITY.md)
- [MULTIDOMAIN-FENCING.md](security/authority/MULTIDOMAIN-FENCING.md)
- [SIGNED-WITNESS.md](security/authority/SIGNED-WITNESS.md)

## 15. Integration checklist

Before calling an integration protected, answer all of these:

- [ ] What exact effect is MGnarf protecting?
- [ ] Can the agent or worker reach that effect through another credential/path?
- [ ] What exact task/candidate/payload is frozen?
- [ ] Which checks are mandatory, and are they host-selected?
- [ ] Where is the receipt key stored?
- [ ] Who can modify or roll back receipt/authority history?
- [ ] What state changes would make PASS stale?
- [ ] Does the state probe read that state from trusted authority?
- [ ] How is revocation represented?
- [ ] What lock, transaction, or fencing mechanism spans relevant state changes and the effect path?
- [ ] What happens if the external effect succeeds but its acknowledgement is lost?
- [ ] Is replay blocked by a preserved single-use authority appropriate to the threat model?
- [ ] Are production credentials outside candidate/worker control?
- [ ] Have you tested a real blocked stale/revoked/replayed effect, not only a happy path?

If one of these is unknown, treat that part of the integration as **UNVERIFIED**, not as an implicit PASS.

## 16. Recommended first real demo

A useful first public demo is deliberately small:

```text
AI agent proposes deploy of commit A
        |
        v
host freezes commit A
        |
        v
host runs tests -> PASS
        |
        +---- candidate changes to commit B ----+
        |                                       |
        v                                       |
MGnarf revalidates ------------------------------+
        |
        v
BLOCKED: candidate changed
```

Then run the same path without changing the candidate and show exactly one successful deploy effect.

That demonstrates MGnarf's core value in one screen: **verified earlier is not enough; the exact verified authority must still be valid at the moment of effect.**

## 17. Scope reminder

MGnarf proves a narrow property inside the configured trusted-host boundary. It does not prove that a verifier is logically correct, that an arbitrary sandbox is secure, or that a remote service completed an action exactly once.

A good integration makes those boundaries explicit instead of hiding them.
