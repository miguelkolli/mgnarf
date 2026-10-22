# MGnarf

**Evidence first. Action second.**

MGnarf is a fail-closed execution gate for AI-assisted and automated work. It sits between verified work and the real effect that changes the outside world.

If an AI agent writes code, prepares a database change, proposes an API mutation, or asks to deploy something, MGnarf does not treat “the checks looked good earlier” as permanent permission. It binds evidence to the exact frozen candidate and revalidates the authorization before the protected effect.

## Why I built MGnarf

> **I needed it. I couldn't find it. So I made it. Now you can use it. No need to ask.**

I needed a way to stop AI agents from approving their own work or changing the rules used to approve it. I couldn't find a solution that fit my needs, so I built MGnarf and made it open source. Copy it, use it, test it, and improve it under the [Apache 2.0 license](LICENSE). No need to ask me for permission or notify me.

## Start here

| I want to... | Read |
| --- | --- |
| understand MGnarf in plain English | [OVERVIEW.md](docs/OVERVIEW.md) |
| see where it belongs in a real stack | [INTEGRATION-GUIDE.md](docs/INTEGRATION-GUIDE.md) |
| choose a hardened execution path | [HARDENED-PATHS.md](docs/HARDENED-PATHS.md) |
| understand authenticated verifier/authority ordering | [STAGE-ORDER-BOUNDARY.md](docs/STAGE-ORDER-BOUNDARY.md) |
| inspect the measured PostgreSQL commit-time reference | [POSTGRES-FENCED-TARGET.md](docs/security/POSTGRES-FENCED-TARGET.md) |
| integrate a real protected effect | [HOST-CONTRACT.md](docs/HOST-CONTRACT.md) |
| inspect the behavioral specification | [NARF-SPEC.md](docs/NARF-SPEC.md) |
| inspect architecture and trust boundaries | [ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| inspect the current stable release | [RELEASE-v1.70.md](docs/RELEASE-v1.70.md) |
| inspect current stable evidence | [TEST-REPORT-v1.70.md](docs/TEST-REPORT-v1.70.md) |
| inspect the previous immutable stable release | [RELEASE-v1.61.md](docs/RELEASE-v1.61.md) / [TEST-REPORT-v1.61.md](docs/TEST-REPORT-v1.61.md) |

## Where MGnarf sits

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

The credential that can perform the protected effect belongs on the trusted-host side. If an agent can bypass the gate and call the deploy, API, database, publication or device path directly, the gate cannot protect that path.

## The core idea

MGnarf separates **evidence** from **effect authority**.

A typical protected path is:

```text
freeze exact task/candidate/policy
        -> run required host-bound verifiers
        -> authenticate evidence
        -> revalidate current authority/state
        -> authenticated PASS decision
        -> single-use guarded effect
```

For stronger threat models, MGnarf exposes additional opt-in boundaries instead of pretending that one local PASS proves every remote execution property.

## Protection levels

| Need | Reference path | What it adds |
| --- | --- | --- |
| exact task/candidate/policy + required evidence + one local effect admission | `NARFGate` | frozen bindings, N/N evidence, authenticated receipts, revalidation |
| builder/verifier/authority separation | identity-enabled `NARFGate` | host-authenticated principal, trust domain, optional verifier profile |
| require verifier/authority stages in authenticated causal order | `NARFGate` + `freeze_contract(..., stage_order=...)` | evidence-v3 requirement ordering, predecessor receipt chain, final chain-head binding |
| monotonic identity-authority generation | `AuthorityRevisionGate` | trusted-host revision bound to the authorization |
| stable real-world operation identity across fresh contracts | `OperationBoundGate(..., authority_probe=...)` | host-owned semantic operation UUID and external single-use authority |
| transport a bound fence into the effect adapter | `FencedOperationGate` + `FencedOperationEffectExecutor` | scope/revision/fence binding and downgrade/direct-route guards |
| validate authority/fence state at the measured external commit | PostgreSQL Layer C reference | DB-owned serialized authority/fence/effect commit boundary |

These are cumulative security ideas, not marketing tiers. A stronger path adds conditions; it does not erase the obligations of the layers below it.

### Authenticated stage ordering

Stage ordering is separate from identity independence.

Identity answers:

```text
who produced this evidence?
```

Stage ordering answers:

```text
which authenticated predecessor had to exist before this stage could run?
```

An ordered first-version chain can be:

```text
frozen builder/candidate context
  -> tests requirement
  -> independent security requirement
  -> authority requirement
  -> MGnarf PASS decision
  -> guarded effect
```

The order is frozen by exact `requirement_id`. The first stage binds to a session/contract-owned chain seed; each later stage binds to the authenticated predecessor receipt ID and canonical digest. A future stage is rejected before its producer runs. The final decision binds to the final authenticated chain head.

This is **not** a physical wall-clock proof, a claim of verifier epistemic independence, or distributed consensus. See [STAGE-ORDER-BOUNDARY.md](docs/STAGE-ORDER-BOUNDARY.md).

## Current release status

The current published stable release is **v1.70**.

- [RELEASE-v1.70.md](docs/RELEASE-v1.70.md)
- [TEST-REPORT-v1.70.md](docs/TEST-REPORT-v1.70.md)
- [GitHub release v1.70](https://github.com/miguelkolli/mgnarf/releases/tag/v1.70)

The immutable v1.70 release is bound to exact source commit `b811a13eab9cacd9f922b1f15097aa6bf700fc01`. Historical release documents remain evidence of what was measured at their own release points; later `main` cleanup or development does not retroactively change v1.70.

## Trust boundary

The trusted host owns at least:

- receipt key and receipt-store authority;
- frozen task/candidate/state/requirements/policy/effect bindings;
- verifier selection and execution;
- identity/profile provenance when configured;
- `stage_order` and chain admission when configured;
- state and revocation probes;
- semantic `operation_id` when configured;
- external consumption/fencing authority when configured;
- the real effect credential and callback/adapter.

Candidate/worker output is not trusted host evidence. Python attribute privacy is not a security boundary. If untrusted code can access host secrets or call the effect directly, use an enforced process/OS/sandbox/service boundary appropriate to the threat model.

## Important retained limits

MGnarf does not claim:

- that verifier logic is correct;
- that differently named agents/models are genuinely independent in the real world;
- physical wall-clock chronology from stage ordering;
- distributed consensus across arbitrary hosts;
- universal TOCTOU elimination for arbitrary remote systems;
- exactly-once remote completion after ambiguous acknowledgement or callback failure;
- rollback resistance if every preserving authority history is rolled back together;
- protection from a malicious trusted host that deliberately bypasses the hardened path;
- independent external security certification.

The strongest current PostgreSQL claim is specific to the tested function/transaction/role configuration in [POSTGRES-FENCED-TARGET.md](docs/security/POSTGRES-FENCED-TARGET.md). A green limitation witness means the documented limitation reproduced as expected; it does not turn that limitation into a security guarantee.

## Integration and boundary documents

- [INTEGRATION-GUIDE.md](docs/INTEGRATION-GUIDE.md) — placement in real stacks.
- [HOST-CONTRACT.md](docs/HOST-CONTRACT.md) — trusted-host serialization, immutable input and persistence obligations.
- [IDENTITY-BOUNDARY.md](docs/IDENTITY-BOUNDARY.md) — principal/trust-domain/profile separation.
- [STAGE-ORDER-BOUNDARY.md](docs/STAGE-ORDER-BOUNDARY.md) — authenticated causal requirement ordering.
- [AUTHORITY-REVISION.md](docs/security/AUTHORITY-REVISION.md) — monotonic authority generation.
- [OPERATION-IDEMPOTENCY.md](docs/security/OPERATION-IDEMPOTENCY.md) — semantic operation identity.
- [COMPOSED-OPERATION-PATH.md](docs/security/COMPOSED-OPERATION-PATH.md) — identity/revision + stable-operation composition.
- [FENCED-EFFECT-BOUNDARY.md](docs/FENCED-EFFECT-BOUNDARY.md) — fence transport boundary.
- [POSTGRES-FENCED-TARGET.md](docs/security/POSTGRES-FENCED-TARGET.md) — measured PostgreSQL Layer C commit boundary.
- [SIGNED-WITNESS.md](docs/security/authority/SIGNED-WITNESS.md) — signed-witness authority.
- [ROLLBACK-BOUNDARY.md](docs/security/ROLLBACK-BOUNDARY.md), [ROLLBACK-HARDENING.md](docs/security/ROLLBACK-HARDENING.md), [MULTIDOMAIN-FENCING.md](docs/security/authority/MULTIDOMAIN-FENCING.md) — rollback/replay boundaries.

Secondary and historical documentation is organized under [docs/](docs/).

## Source map

The Python reference implementation lives in [src/narf/](src/narf/).

- `gate.py` — legacy core gate/session primitives and receipt/effect mechanics.
- `stage_order.py` — public `NARFGate`, legacy delegation plus ordered evidence-v3 semantics.
- `authority_revision.py` — monotonic authority-revision wrapper.
- `operation_guard.py` — stable operation binding and composed authority path.
- `stage_order_fenced.py` — ordered public fenced-operation gate.
- `fenced_effect.py` — fenced session/token/effect executor primitives.
- `postgres_authority.py` — PostgreSQL single-use consumption authority.
- `postgres_fencing.py` — PostgreSQL Layer C adapters.
- `signed_witness.py` — signed-witness authority and response deadline handling.
- `reference_host.py` / `process_host.py` — trusted-host reference integrations.
- `__init__.py` — public API exports.

## Tests and CI

Run the repository suite with:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests tools
```

Stage-order regressions include core ordering, composition/downgrade, same-thread re-entrancy, independent adversarial replay/tamper coverage, and v1.70 release-specific ordered whole-chain cases.

GitHub Actions live in [.github/workflows/](.github/workflows/). A green workflow supports only the boundary it actually measures. Release claims are tied to explicit candidate SHAs and must be re-run after candidate changes.

## Legal and attribution

- [LICENSE](LICENSE) — Apache License 2.0.
- [NOTICE](NOTICE) — required project attribution.
- [TRADEMARKS.md](docs/TRADEMARKS.md) — naming/official-project boundary.

Redistributions and derivative works must preserve the applicable attribution from `NOTICE`:

```text
This software includes software originally developed as MGNARF Ändi.
```

---

**Shortest useful reading path:** [OVERVIEW](docs/OVERVIEW.md) -> [INTEGRATION-GUIDE](docs/INTEGRATION-GUIDE.md) -> [HARDENED-PATHS](docs/HARDENED-PATHS.md) -> [HOST-CONTRACT](docs/HOST-CONTRACT.md)
