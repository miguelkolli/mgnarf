# NARF — AGENTS

This file defines project routing and project-boundary procedure.

Standalone startup order:

1. `MGSYSTEM.md`
2. `LAWS.md`
3. `AGENTS.md`
4. `STATE.md`
5. `ARCHITECTURE.md`
6. `mgsystem.project.json`
7. Relevant contracts or documentation only when the task needs them.

The repository `LAWS.md` is a downstream mirror. When the MG System root is
available, root `LAWS.md` is authoritative: compare it with the mirror, report
drift, and do not perform governance-sensitive mutation on known drift.

Do not traverse upward to modify root MG System governance. Mirror synchronization
flows root → repository only and requires an explicitly authorized MG System
governance/sync task. A project may report or propose a governance change but may
not apply it to root law.

Unknown technical fact → RECON.

Missing intent or authority → STOP.

Project instructions may strengthen root MG System rules but may not weaken them.

## DOCUMENTATION SYNC

Documentation sync is required before PASS for every mutation task. Compare the
changed reality with the documents that claim to describe it, and update only
the affected truth sources in the same task:

- `STATE.md` for current status, blockers, deployment state, or verified result;
- `ARCHITECTURE.md` plus the required `mgsystem.project.json` review for
  structure, boundaries, responsibilities, runtimes, integrations, deployment,
  or verification architecture;
- `AGENTS.md`, `MGSYSTEM.md`, `README.md`, contracts, and user documentation
  when their procedures, interfaces, setup, or usage truth changes.

If material documented truth changed and its owner remains stale, do not report
PASS. If no documentation is affected, report
`DOCUMENTATION SYNC: REVIEWED — NO UPDATE REQUIRED`. Git history remains the
complete technical change log; do not create or update narrative files merely to
duplicate routine diffs.

`ARCHITECTURE.md` is human/AI architecture truth. `mgsystem.project.json` is its
machine-readable projection for shared MGSystem tests, never a competing
authority. Whenever architecture changes, review the JSON in the same task and
report whether it must change. When root MGSystem is available locally, use
`$MGSYSTEM_HOME/tests/run.py`; otherwise obtain the configured MGSystem repository
and `mgsystem.ref` in a local checkout before running tests. If neither route is
available, report `BLOCKED` / `MGSYSTEM_RUNTIME_UNAVAILABLE`. Project agents may
run the shared harness but may not modify root test code.

Do not weaken configured MGSystem acceptance commands, expected results, required
checks, timeouts, or PASS criteria to obtain PASS. Application tests may evolve
with application behavior; they do not replace the external MGSystem gate.

During implementation and VERIFY, review changed application scope for coherent
folder/module placement, clear responsibilities and separation, architecture-
boundary compliance, maintainability/readability, justified complexity,
deliberate error/fallback behavior, meaningful L13 comments, security/privacy
boundaries, tests, configured lint/type/build evidence, dependency/configuration
hygiene, and consistency with `ARCHITECTURE.md`. Report unrelated existing debt;
do not refactor it without task authority.

TASK → ROUTE → MINIMUM RECON → CHANGE → VERIFY → DONE
