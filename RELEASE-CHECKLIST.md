# Reference release checklist

The first proposed release is an explicitly scoped alpha of the standalone
Python reference implementation, for example `0.1.0a1`. This document does
not publish a release or certify a host integration.

## Before an alpha tag

- Review and merge the stacked changes in order: PR #1 (receipt parser
  recursion), PR #2 (directory durability failures), PR #3 (trusted-host
  contract), then the worker-process regression tests accompanying this file.
- Run `PYTHONPATH=src python3 -m unittest discover -s tests -v` and
  `python3 -m compileall -q src tests` on the exact merged commit. Record
  the Python/OS versions, exit codes, failures and skips. The new process
  tests target Unix; the real permission-denial test may skip when a root
  runner cannot drop its filesystem bypass capabilities. A skip is not PASS.
- Require the repository's configured GitHub checks to pass on that commit.
  At the time of preparing this checklist there were no recorded GitHub
  workflow runs or status checks; local results do not replace that evidence.
- Preserve the test evidence and state the release scope in the release notes:
  standalone reference API, authenticated receipts, revalidation and
  at-most-once callback invocation under the documented trusted-host contract.
- Preserve LICENSE, NOTICE and TRADEMARKS.md and link HOST-CONTRACT.md.

## What the process tests establish

Four fresh-interpreter regression tests cover wrong-key authentication,
two synchronized host-capable contenders sharing a key/store, keyless
same-UID receipt tampering, and an actual filesystem EACCES while reserving
the effect. They check callback/target events and authenticated consumption
receipts. The wrong-key test also proves raw receipt bytes remain readable
to the same Unix account; HMAC authentication is not a filesystem ACL.

## Before claiming production host isolation

- Exercise the actual host and untrusted worker under distinct Unix accounts
  or an equivalent enforced authority boundary. Verify that workers cannot
  access the key or modify receipts, parent directories or backup history.
  The current executor rejects account-switch operations; this boundary
  remains UNVERIFIED here.
- Test the actual host's shared authority lock/transaction, immutable effect
  input, revocation and candidate updates through its real effect path.
- If receipt deletion, backup rollback or physical power loss are in the host
  threat model, establish the corresponding protected monotonic history and
  crash/persistence guarantees in that deployment.

At-most-once callback invocation does not promise exactly-once completion of
an external action. No release date or production certification follows from
the number of test repetitions alone.
