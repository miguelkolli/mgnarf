# v1.70 — hardened execution paths

`v1.70` is the next stable capability release of the standalone MGnarf reference implementation after immutable `v1.61`.

This release freezes the measured hardened execution line covering identity-bound separation of duties, monotonic authority revision, stable semantic operation identity, fenced effects, the PostgreSQL Layer C reference boundary, and authenticated stage ordering.

Stable means the exact published source completed the repository's release gates and is frozen as historical evidence. It does **not** mean every deployment is secure, every verifier is correct, every external effect is exactly-once, or that MGnarf has received independent security certification.

## What v1.70 adds

- **Identity-bound separation of duties.** Logical verifier identity remains distinct from host-owned principal, trust-domain and optional verifier-profile facts.
- **Monotonic authority revision.** Authority changes remain visible through a trusted revision boundary instead of being hidden by change-and-restore.
- **Stable semantic operation identity.** One host-owned operation identity survives fresh contracts and retries so the guarded path can reject replay while the preserving authority history remains intact.
- **Fenced effect transport.** Fence scope, operation, authority revision, effect and fencing-authority identity are bound together, and fenced sessions reject weaker direct-effect paths.
- **PostgreSQL Layer C reference.** The tested `SECURITY DEFINER` function/role/transaction model serializes authority transition, fence issuance and target commit inside one PostgreSQL scope-lock domain.
- **Authenticated stage ordering.** Ordered evidence v3 freezes the exact requirement order, binds each accepted stage to its authenticated predecessor, blocks future stages before producer entry, protects same-stage admission, and binds final PASS to the final chain head.

Legacy unordered v1/v2 behavior remains available when stage ordering is not configured.

## Release evidence

The v1.70 candidate cycle deliberately did not inherit PASS across SHA changes. The release line was repeatedly revalidated after integration and documentation changes.

The frozen acceptance requirements include:

- v1.70 whole-chain: **13 protected cases**;
- full repository regression: **237 tests**;
- failures/errors/skips: **0 / 0 / 0**;
- `compileall -q src tests tools`: **PASS**;
- signed-witness boundary: **4 PASS + 1 LIMITATION_CONFIRMED + 0 FAIL**;
- all **14** required exact-main push workflows: **success** on the exact publication source.

Historical candidate evidence and the adversarial development record are retained in:

- [RELEASE-v1.70.md](RELEASE-v1.70.md)
- [TEST-REPORT-v1.70.md](TEST-REPORT-v1.70.md)
- [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md)

The stable-release workflow appends the final exact `main` SHA and SHA-pinned evidence links to this publication note only after the complete exact-main workflow matrix is green. The release draft must remain bound to that SHA and must be published without retargeting.

## Retained limits / non-claims

v1.70 does **not** claim:

- independent security certification;
- correctness of verifier domain logic;
- real-world administrative or epistemic independence merely because identities or profiles differ;
- physical wall-clock chronology from authenticated stage ordering;
- distributed consensus or a general DAG/parallel-stage workflow model;
- protection from a malicious trusted host that deliberately abandons the documented hardened path;
- rollback resistance if every preserving authority history is rolled back together;
- exactly-once remote completion after ambiguous acknowledgement or callback failure;
- universal fencing or TOCTOU elimination for arbitrary HTTP APIs, clouds, databases or devices;
- PostgreSQL Layer C protection against privileged function/schema owners or administrators able to rewrite authoritative state;
- backup/restore, failover, physical-power-loss or production-administration guarantees unless separately enforced and tested.

A green limitation witness means a documented limitation reproduced as expected. It is not converted into a security PASS.

## Publication gate

Publication is accepted only if the exact final source revision satisfies the release checklist, the prepared draft is pinned to that same revision, repository release immutability is confirmed enabled, the draft is published without retargeting, and the resulting release verifies as immutable, non-draft and non-prerelease.

If any required boundary is unexecuted or cannot be established, the result is `UNVERIFIED` or `BLOCKED`, not PASS.

## License

Apache License 2.0. Preserve the applicable attribution from [NOTICE](NOTICE):

```text
This software includes software originally developed as MGNARF Ändi.
```
