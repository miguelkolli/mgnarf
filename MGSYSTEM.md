# MGSystem

This repository is managed under MGSystem.

## Authority

The authoritative ecosystem governance lives in the root MGSystem.

This repository's `LAWS.md` is the visible mirror for standalone work. Root
MGSystem `LAWS.md` remains authoritative; known mirror drift must be reported.

Project-level instructions may strengthen root rules but may never weaken them.
The root may not be available when entering through this repository, so follow
the entry rules below before work.

## Read Before Work

1. `MGSYSTEM.md`
2. `LAWS.md`
3. `AGENTS.md`
4. `STATE.md`
5. `ARCHITECTURE.md`
6. `mgsystem.project.json`

Read additional contracts or documentation only when relevant to the task.

## Core Rules

- RECON is mandatory: NO CODE WITHOUT RECON
- NO DECISION WITHOUT THINK
- COMMENTING IS LIFE
- Check Git truth before changing code
- Respect project and repository boundaries; never modify root MGSystem
  governance from project work

## Current Truth

`STATE.md` is the project's current operational truth.

`ARCHITECTURE.md` describes the current system structure and boundaries.

`mgsystem.project.json` is the machine-readable projection used by MGSystem
tests. It is not a competing authority. Whenever `ARCHITECTURE.md` changes,
review the JSON in the same task and report whether a JSON update is required.

## Shared Runtime

Use `MGSYSTEM_HOME` when available and run its `tests/run.py`. Otherwise use the
MGSystem repository and `mgsystem.ref` configured in `mgsystem.project.json`;
obtain that revision in a local checkout before running tests. Never execute
Python directly from a remote URL. If neither route is available, governance is
still readable here but shared verification is `BLOCKED` with
`MGSYSTEM_RUNTIME_UNAVAILABLE`.

## Boundary

Do not modify other MGSystem projects or repositories unless explicitly
authorized.
