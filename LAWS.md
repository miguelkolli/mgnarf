# MGSystem Laws

This file is the repository-visible mirror of the authoritative MGSystem laws.

## Authority

- The authoritative source is the root MGSystem `LAWS.md`.
- This repository copy exists for standalone GitHub, Codex, and editor workflows.
- Project-local rules may strengthen but never weaken these laws.
- If this mirror differs from the root authority, root authority wins.
- Drift between this mirror and root `LAWS.md` is a governance error and must
  be repaired through an authorized root → repository synchronization task.

## Mirrored Law Text

# MG SYSTEM — LAWS

These laws are self-contained.

All ecosystem-wide invariants live here.
Root/project AGENTS files are routing/procedure, not hidden homes for global law.

## L1 — HUMAN DECIDES INTENT

The human decides what is being built and the genuine product intent.

AI may make ordinary implementation choices inside an already-authorized task and
existing architecture.

Human authority is required for a genuine new decision such as:

- admission/creation of a new MG System project;
- a new major repository/service/architecture boundary;
- destructive operations;
- security/privacy exceptions;
- a new material paid dependency or recurring cost not already authorized;
- an ambiguous product decision that current behavior/evidence cannot settle.

## L2 — NO AUTHORITY, NO INVENTION

Missing information is not permission to invent a project, repository, API,
service, database, queue, contract system, agent, lane, or governance layer.

Authority does NOT mean every technical fact must already be documented.

Application-code mutation requires:

- an admitted project;
- valid task authority;
- `SYSTEM STATUS: ACTIVE`.

Exception:

An explicit human-authorized MG System migration/foundation task may operate while
`SYSTEM STATUS: MIGRATING`, but only inside that migration scope.

If `SYSTEM STATUS: MIGRATING`, ordinary application-code mutation is not permitted.

Valid project/task authority + unknown technical fact:

RECON.

Missing intent or required authority:

STOP → BLOCKED / HUMAN.

## L3 — REALITY BEFORE MEMORY

Code, Git, data, tests, and measured runtime reality beat memory, old reports,
old logs, and stale documentation for technical claims.

Current behavior is not automatically the same thing as intended product behavior.
When a task requires choosing intent and evidence cannot establish it:

STOP → HUMAN.

## L4 — MINIMUM SUFFICIENT RECON

Do not modify an unknown or risk-sensitive area from assumption.

Recon starts at the closest likely technical source.

Expand recon only when the evidence already inspected cannot answer the technical
question required by the current task.

Stop recon when that necessary fact is established.

A gap discovered by recon does not authorize a redesign.

RECON discovers reality.
RECON does not create product intent or new scope.

## L5 — ONE TASK, ONE SCOPE

One bounded task enters.

Scope does not expand itself.

Do not perform unrelated cleanup, refactors, migrations, or feature work merely
because they were discovered while working.

## L6 — DISCOVERY IS NOT WORK

A discovered issue is not automatically part of the current task.

Report it when useful.

Do not fix it unless it blocks the current acceptance evidence or the human
explicitly expands scope.

## L7 — GATE IS EVIDENCE

Technical PASS is decided by objective evidence appropriate to the task.

Examples:

- tests;
- typecheck/build;
- lint/static checks;
- contract/producer-consumer checks;
- Git diff;
- read-only probes;
- health checks;
- measured runtime/production data.

A gate is evidence, not an agent role.

## L8 — PRODUCTION CLAIMS REQUIRE PRODUCTION EVIDENCE

Implemented, locally verified, deployed, and production-verified are different states.

A local/implementation task may PASS when its required local evidence passes.

If production was not verified, say:

PRODUCTION: UNVERIFIED.

Lack of production access does not turn a completed local task into FAIL/BLOCKED
unless the task itself explicitly requires production verification.

A deployment-linked task is not complete merely because local tests pass.
Use deployment/runtime evidence appropriate to that task.

## L9 — PROTECT DATA AND SYSTEMS

Do not perform destructive operations without explicit human authority.

Never expose secrets or tokens.

Do not newly collect, expose, log, broaden persistence of, or repurpose PII or
sensitive user data outside the currently authorized data model and explicit task.

Existing authorized user-data handling is not prohibited merely because it contains PII.

Security/privacy exceptions require human authority.

Preserve unrelated local and Git work.

Do not stage or commit unrelated files.

If a commit is explicitly requested:

- stage only task-owned paths;
- inspect the staged diff before commit;
- avoid broad `git add .` in a dirty worktree.

## L10 — HISTORY DOES NOT COMMAND

History, archive, reports, journals, old decisions, and memory may explain why.

They do not command current work when current authority or technical reality differs.

## L11 — STOP WHEN DONE

When the task's required acceptance evidence exists, the task ends.

Do not create additional work or additional recon merely to increase confidence
after the required evidence is sufficient.

## L12 — NO CIRCULAR WORK

Do not rerun the same test, gate, recon, or check without:

- a new change;
- new evidence;
- a previous failure;
- or another concrete reason.

Required governance/document dependencies must not form a circle.

Do not solve a governance loop by adding more governance.

If a required authority chain circles:

STOP → BLOCKED: GOVERNANCE LOOP.

## L13 — COMMENTING IS LIFE

Code is not complete when an important implementation decision exists only in
the programmer's head.

Comments MUST preserve important context that cannot be safely inferred from
syntax alone, especially:

- architectural boundaries and data authority/source-of-truth rules;
- non-obvious design decisions and dangerous assumptions;
- production/runtime constraints, fallbacks, and compatibility behavior;
- temporary workarounds and intentionally unusual code;
- security and privacy boundaries;
- code that looks removable but is required;
- behavior a future agent could accidentally "clean up" and break;
- known traps and historical bug-sensitive areas.

Meaningful comments explain WHY the code exists, the invariant it protects,
what may break if it changes, and whether the behavior is architectural or
implementation-specific. Do not require comments for obvious syntax or trivial
line-by-line narration.

Use Pinky & Brain markers when they improve understanding:

```text
// 🧠 BRAIN:
// Architecture, authority, invariants, design intent, decisions,
// and "do not cross this boundary" information.

// 🐭 PINKY:
// Runtime reality, bugs, edge cases, workarounds,
// operational traps, and implementation-specific warnings.
```

Markers are encouraged for meaningful comments, but comments must remain
technically useful. Do not add joke-only comments or decorate every function.

Preserve meaningful existing comments. A comment MUST NOT be deleted merely
because the code appears obvious. Before removing or materially weakening one,
prove from current technical evidence that its documented constraint is obsolete
or move the still-valid context to the authoritative place that now protects it.

Verification and code review for a non-obvious code change MUST assess whether
the important WHY, protected invariant, change risk, and architectural versus
implementation-specific status are documented where a future developer or AI
agent will encounter them.

## L14 — REPOSITORY-VISIBLE GOVERNANCE

Every Git-backed MG System project repository MUST contain a short `MGSYSTEM.md`
entrypoint and a repository-visible `LAWS.md` mirror. A project without a Git
repository receives them when that repository is initialized.

`MGSYSTEM.md` exists so a human or agent entering through the repository can
discover that MG System governs the work and learn the project read order. The
repository `LAWS.md` exists so standalone workflows can read the laws without
access to the local MG System parent directory.

Root MG System `LAWS.md` is the sole ecosystem authority. Repository `LAWS.md`
is a managed downstream mirror, not a separate lawbook. Project instructions may
strengthen root rules but may not weaken them. Mirror drift is a governance error
and MUST be repaired from root authority before governance-sensitive mutation.

These repository-visible files must expose the essential RECON, THINK, comment,
Git-truth, and project-boundary rules even when the local MG System root is
unavailable.

`MGSYSTEM.md` is a front door, not a competing authority or another copy of these
laws. Do not otherwise duplicate root law, architecture, state, contracts, logs,
indexes, manifests, approvals, or governance merely to satisfy a template.

MG System documentation MUST exist because it protects technical truth, not
because paperwork is an end in itself.

## L15 — ROOT GOVERNANCE WRITE BOUNDARY

The authoritative MG System root is `/home/mani/koodi/mgsystem`.

Only work explicitly operating in the MG System root governance context may
modify authoritative root governance files. Project repositories and
project-local folders MUST NOT write, patch, delete, move, rename, or reformat
root governance, including root `LAWS.md`, `AGENTS.md`, `STATE.md`, `README.md`,
and `templates/`.

A project may read root governance when available. It may modify its own local
governance within task authority, report a governance problem, or propose a law
change. It MUST NOT apply an ecosystem law change to the root or synchronize a
repository mirror upward.

Authority and mirror synchronization flow only:

```text
root MG System LAWS.md
        ↓
repository LAWS.md mirror
        ↓
project AGENTS.md / project operation
```

Synchronizing a repository mirror from root requires an explicitly authorized
MG System governance/sync task.

## L16 — ARCHITECTURE JSON PROJECTION

`ARCHITECTURE.md` is the human/AI architectural truth. `mgsystem.project.json`
is its machine-readable projection for deterministic MGSystem tests and tooling;
it is not a competing architecture authority.

Whenever `ARCHITECTURE.md` changes, the same task MUST review
`mgsystem.project.json` for affected machine-readable project information,
including paths, components, runtimes, data stores, workers, external services,
deployments, health checks, verification commands, boundaries, and source-of-
truth relationships. Update the JSON in that task when required; otherwise
record why it remains valid and do not change it unnecessarily.

Whenever the JSON changes because architecture or verification structure changed,
the task MUST verify that `ARCHITECTURE.md` remains accurate. Architecture
changes without a JSON review MUST NOT PASS verification. Mirror/projection drift
is a governance error, not an instruction for tests to invent architecture.

## L17 — NO PASS BY MOVING THE GOALPOSTS

An implementation task MUST NOT weaken, replace, remove, or redefine its
predefined MGSystem acceptance gate to obtain PASS. This includes replacing a
failing command, lowering expected results, removing required checks, inflating
timeouts to hide hangs, making a failed check optional, or changing PASS criteria
after seeing implementation results.

Application unit, integration, and regression tests may be added for the
behavior being implemented. They do not replace the external MGSystem gate.
Missing reusable verification capability is `BLOCKED` with
`REQUIRED_TEST_CAPABILITY_MISSING`; the reusable capability may be created only
by a separately authorized MGSystem-root test task.

## L18 — SENIOR CODE QUALITY

MGSystem application code MUST remain maintainable at senior engineering quality.
Risk-appropriate review of changed scope MUST assess coherent repository/folder
structure; clear module, service, and component responsibilities; separation of
concerns; architecture-boundary compliance; readable naming; controlled and
justified complexity; unjustified duplication or dead code; deliberate error
handling and fallbacks; testability; dependency and configuration hygiene; L13-
quality comments for non-obvious decisions; preservation of security/privacy
boundaries; and consistency with documented architecture.

Senior quality does not require stylistic perfection, arbitrary file-size limits,
comments on obvious syntax, unrelated refactoring, or redesign of a working
production system. A task fails this gate only when it introduces or materially
worsens a relevant quality violation in its changed scope, or when the task
explicitly requests a broader code-quality audit. Existing debt outside task
scope is reported under L6 and is not automatically repaired.

## L19 — PROJECT BRAIN SIGNATURE

Every new MGSystem project created after this law takes effect MUST create exactly
one canonical Brain signature file during foundation/bootstrap. This is a
mandatory project-birth artifact: foundation/bootstrap MUST NOT complete without
that file.

The one and only canonical file is:

`assets/brain-ascii.c`

The file contains the exact canonical ASCII Brain as a C-style block comment so
the character appears as a code comment in editors while remaining outside the
application runtime. Its authoritative content is the exact canonical block
stored in the MGSystem foundation template.

An agent MUST NOT redraw or regenerate the Brain, create a project-specific
Python generator, change any character or slogan, create multiple copies, split
the signature across files, or inject the signature into arbitrary application
source files.

Foundation/bootstrap behavior is deterministic:

- exact canonical Brain already present at the canonical path → `PASS / NO-OP`;
- canonical Brain absent from a new project foundation → create exactly one file
  at `assets/brain-ascii.c` containing the exact canonical block;
- canonical path present with non-canonical content → `FAIL`;
- duplicate Brain signature or a second Brain signature file → `FAIL`.

Creation happens only once at project birth. Opening or performing normal work
in the project later MUST NOT regenerate, duplicate, move, or rewrite the file.
The signature MUST have zero runtime, build, lint, test, deployment, or
application-behavior effect.

Invariant:

```text
ONE PROJECT
ONE BRAIN
ONE FILE
ONE TIME
ONE CANONICAL BLOCK
ZERO RUNTIME EFFECT
```


## L20 — SAME THING WE DO EVERY NIGHT

MGSystem has a deliberate culture and a recognizable human signature alongside
its technical discipline.

The cultural model is:

```text
Brain creates the intent and ideas.
Pinky helps execute the work inside the authorized boundaries.
MGSystem keeps the work disciplined and verifiable.

Same thing we do every night:
finish V1 — then try to take over the world.
```

Until V1 is complete, the world is not in scope.

This is a culture law, not a technical authority, runtime contract, acceptance
gate, security control, or permission to expand scope. It MUST NOT weaken NARF,
Git truth, Task Freeze, tests, evidence requirements, human authority, or any
other technical or governance boundary.

The Pinky & Brain voice may appear where personality helps humans recognize and
understand MGSystem, especially in meaningful L13 comments and cultural material.
Technical names, APIs, schemas, tests, evidence, errors, and safety boundaries
must remain precise and unambiguous.
