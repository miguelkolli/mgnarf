# NARF test report — 2026-10-11

## Result and tested revision

The merged standalone reference implementation passed **34/34 repository
unit tests**, with **0 failures, 0 errors and 0 skips**, on Linux with
Python **3.12.14**. Compileall also completed with exit code **0**.

The tested revision is
[`9d4608770c15774a365ec2cc23c56bf38cd198bc`](https://github.com/miguelkolli/mgnarf/commit/9d4608770c15774a365ec2cc23c56bf38cd198bc).
Its tree is `039271727531323ee7b45c0ce4929d591a934b3c`.
All seven Python source/test files were checked against that tree before
the post-merge test run. The merged tree equals the previously tested PR #4
tree. This report is added in a later documentation-only commit.

**Local reference tests: PASS. Whole host integration and production
readiness: UNVERIFIED. GitHub CI: UNVERIFIED.**

This assessment concerns external standalone `miguelkolli/mgnarf`.
MGSystem is outside its scope.

## Merged changes

| PR | Change |
| --- | --- |
| [#1](https://github.com/miguelkolli/mgnarf/pull/1) | Catch receipt-decoding RecursionError and reject invalid receipts through the existing fail-closed route. |
| [#2](https://github.com/miguelkolli/mgnarf/pull/2) | Reject directory-open/fsync failures before effect invocation; retain uncertain consumption reservations to prevent replay. |
| [#3](https://github.com/miguelkolli/mgnarf/pull/3) | Document and test cooperating trusted-host serialization, immutable inputs and receipt-history obligations. |
| [#4](https://github.com/miguelkolli/mgnarf/pull/4) | Add fresh-process regressions and an alpha release checklist. |

All four PRs were confirmed merged into `main`.

## Repository test coverage

| Test file | Test methods | Post-merge result |
| --- | ---: | --- |
| [test_gate.py](tests/test_gate.py) | 17 | PASS |
| [test_receipt_depth.py](tests/test_receipt_depth.py) | 5 | PASS |
| [test_store_durability.py](tests/test_store_durability.py) | 6 | PASS |
| [test_host_serialization.py](tests/test_host_serialization.py) | 2 | PASS |
| [test_worker_processes.py](tests/test_worker_processes.py) | 4 | PASS |
| **Total** | **34** | **PASS; 0 skips** |

These are unittest method counts. Parameterized subcases are not added to
the method total. The durability tests contain 34 subcases; the two
host-serialization tests contain eight subcases.

The parser regressions reproduced six RecursionError errors before the
parser fix. The isolated durability baseline produced 18 failures and
eight errors before the persistence fix. Corrected code passed the same
expected-denial checks.

## Four fresh-process checks

Each subprocess uses a fresh `python -I` interpreter. The test verifies
the loaded source path, process exit and Unix UID.

| Check | Observed result | Callback / target / consumption |
| --- | --- | --- |
| Wrong host key | ReceiptStore.load rejected authentication. Raw receipt bytes remained readable to the same UID, and their digest matched the host's file. | 0 / 0 / 0 |
| Two synchronized host-capable contenders | Both reached a real PASS decision before barrier release. Exactly one invoked the effect; the loser received NARFError: already consumed. | 1 / 1 / 1 |
| Keyless same-UID contract tampering | A child without the host key changed task_id without recomputing the MAC. Authentication failed and open_session rejected the contract. | 0 / 0 / 0 |
| Real reservation write denial | Directory permissions caused EACCES during effect reservation after a real PASS decision; callback entry was prevented. | 0 / 0 / 0 |

The last column counts callback entries, external **test-target** writes
and authenticated effect-consumption receipts. These are not production
effects.

The Linux root permission-denial worker dropped and verified its effective
CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH capabilities before applying the
permission restriction. This was an actual filesystem denial, not an
injected successful/failed gate result. If that capability operation is
unavailable, the repository test explicitly skips; **a skip is not PASS**.
No such skip occurred in the reported run.

The contenders intentionally possess host authority and share one key and
store. Their result proves contention behavior under that setup, not
isolation of untrusted workers. HMAC authentication does not provide
filesystem confidentiality or access control.

## Earlier supplemental runs

These runs occurred before the final merge and were not repeated as
10,000 new post-merge tests.

| Assessment | Revision / scope | Result |
| --- | --- | --- |
| Parameterized regression | PR #2 code, commit `168f096053ca99485d23dcf095fce077c336fe5f`; 25 families × 400 variants | 10,000/10,000 PASS |
| Storage subprocess checks | Corrected persistence code; normal control, actual permission faults and bounded directory-fsync fault injection | 8/8 PASS |
| Shared host-lock subprocess checks | PR #3 head `0e6caaf6d159310b8b2e9a25f790a5f9f2260fb0`; cooperating mutator and effect use the same lock | 32/32 PASS |
| Distinct-account boundary attempts | Executor rejected credential switching before the planned receipt-store operations | 16 UNVERIFIED; 0 intended account-boundary operations executed |

The final gate blob is
`41137015f2f89cd1ec97b5f63d0a8a8d746de781`, unchanged from PR #2.
Later PRs added documentation and tests. The 10,000-case run retained
47,928 receipt snapshots and observed 1,200 callback entries and 1,200
test-target writes. Repetition of parameterized families is not evidence
of 10,000 independent attack ideas.

## Remaining limits

- Distinct Unix-account ACL/UID isolation remains UNVERIFIED. This executor
  rejected setgroups/setuid operations; same-UID results do not replace them.
- State/revocation updates and the complete synchronous execute_effect call
  require the shared authority lock/transaction described in
  [HOST-CONTRACT.md](HOST-CONTRACT.md). A non-cooperating mutator is outside
  the tested lock guarantee.
- A store owner can remove consumption history or restore an old snapshot.
  HMAC does not make history monotonic. Rollback-resistant host storage was
  not implemented or certified here.
- Physical power loss and durable remote-target acknowledgement were not
  tested. At-most-once callback invocation does not guarantee exactly-once
  completion of an external action.
- No GitHub workflow runs or commit statuses existed for the merged commit
  at the final check. Local PASS is not GitHub CI PASS.
- The assessment and evidence audit were performed by the same assistant.
  This is not an independent security certification.
- The user's external local checkout was unavailable in this environment;
  this report makes no new claim about its local Git status.

## Evidence and harness corrections

Worker evidence retained subprocess exits, PIDs, receipt files and
callback/target events. The previously delivered evidence bundles are
outside this repository; raw bundle contents are not included by this
Markdown commit.

| Bundle | SHA256 |
| --- | --- |
| NARF_worker_4_PASS_ja_julkaisu.zip | `324108df533c51572b3b2b7a3e137d61308b8e757dfba56a2dee9bd44778ed5b` |
| NARF_GitHub_3_PR_ja_jatkovarmennus.zip | `d410c412b62d53e4864b98ac195f77c90cec6cec195061f9fa68db70301d1fd0` |

Earlier harness issues were corrected and disclosed: the initial durability
baseline reused a fixture across some failing subcases; those effect cases
were rerun with isolated fixtures. A local document-name mixup was corrected
before publication. The first host-boundary harness stopped on denied
credential switching; the corrected runner retained stderr and classified
those cases UNVERIFIED. The first four-worker launch attempt used a missing
log-directory path and stopped before executing tests. These were harness
or setup corrections; acceptance expectations were not relaxed to obtain PASS.

## Reproduce and release scope

From the repository root:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
```

Optional worker evidence retention:

```bash
NARF_WORKER_EVIDENCE_DIR=/absolute/new/evidence-directory \
PYTHONPATH=src python3 -m unittest discover -s tests -p test_worker_processes.py -v
```

Use a fresh evidence directory and record the exact revision, Python/OS
versions, exit codes and skips. The process tests target Unix.

See [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) for the scoped reference-alpha
conditions. Merging these changes did not create a tag or publish a release.

> PINKY: Did the checks actually run?  
> BRAIN: Yes. PASS applies to the measured reference tests; the unverified
> boundaries remain visible.
