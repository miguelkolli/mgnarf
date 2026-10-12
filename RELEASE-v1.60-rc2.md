# v1.60-rc2 — hardening release candidate

`v1.60-rc2` is the second release candidate for the standalone MgNarf v1.60 reference implementation.

RC2 preserves the immutable RC1 history and adds the post-RC1 red-team hardening that was confirmed against the RC1 code path. The RC2 tag is valid only when it points to the exact merged `main` commit whose required aggregate reference gate completed successfully. The tag must not move after publication.

## What changed since RC1

RC2 adds hardening for three confirmed findings and locks a fourth already-fixed boundary with an exact regression witness:

1. **FIFO candidate availability hardening.** Candidate paths are opened non-blocking where supported and are rejected after `fstat()` unless they are regular files. This closes the reproduced path where a FIFO could block `commit()` while the host authority lock was held.
2. **Signed-witness wall-clock timeout.** The witness client now enforces a monotonic request/body deadline rather than relying only on per-socket-operation timeout behavior. A drip-body regression fixture must fail closed inside the configured wall-clock budget.
3. **Session-bound rollback authority.** `RollbackProtectedEffectExecutor` derives the real contract identity from a real `NARFSession`, rejects caller-supplied mismatches, and reserves the session-bound contract ID.
4. **Canonical task coercion regressions.** Exact regression coverage preserves strict rejection of non-string object keys, tuples/list subclasses and lone UTF-16 surrogates. No new RC2 production change was required for this item because the RC1 source already contained the strict canonical-JSON fix.

See [TEST-REPORT-v1.60-rc1-redteam.md](TEST-REPORT-v1.60-rc1-redteam.md) for provenance, reproduced findings, hardening details and retained evidence limits.

## Evidence provenance

The attack report that triggered this hardening was a blind red-team/self-review against historical commit `d53f19bd79f366bc61598895b22c82887b310741`. The red-team agent did not receive repository tests or the report in advance, but it did read source code and came from the same model family as the repository-building assistant.

That evidence is useful adversarial coverage, but it is **not an independent external security review or certification**.

The follow-up re-audited the reported code paths against the immutable RC1 source before changing them. Findings 1, 2 and 3 were still structurally present there; finding 4 was already fixed and covered.

## RC2 acceptance gate

Before `v1.60-rc2` is published:

- the release-preparation change must be merged to `main`;
- the exact merged `main` SHA must complete the repository's required reference workflows;
- `Reference tests (no skips)` must be `success` on that exact SHA;
- an RC2 draft must be bound to that exact verified SHA while no `v1.60-rc2` tag exists;
- repository release immutability must be confirmed enabled by a repository administrator before the first publication;
- that exact draft must then be published without changing its target;
- the created tag must resolve to the draft's exact verified SHA;
- the resulting GitHub release must report `immutable=true` and `prerelease=true`.

GitHub's immutable-release settings endpoint requires repository Administration read permission. The standard Actions `GITHUB_TOKEN` used by this repository does not have that permission, so the automated path deliberately stops at a draft instead of weakening the gate or creating a release first and checking immutability afterward. First publication therefore has one explicit admin/UI gate: confirm **Settings > General > Releases > Enable release immutability**, then publish the exact prepared draft. After publication, automation can verify the public release's immutable flag, tag binding and source gate without needing repository-admin permission.

RC2 must not be published from a PR merge-ref, candidate branch SHA, historical green run, manually retargeted tag, or a draft whose target differs from the verified candidate SHA.

## Known boundaries retained in RC2

The red-team follow-up intentionally leaves these items visible rather than silently calling them fixed:

- `inhibit()` after `finalize()` still requires a separate semantic/spec review;
- a revocation probe returning `None` remains a permissive integration behavior requiring explicit contract review;
- a non-atomic final target write can leave partial target output if the target write fails;
- TrustedFileHost payload identity is not promoted here into a new locked task/effect binding;
- a durable authority reservation can be burned if relevant state changes after reservation and before effect entry; this is a deliberate safety-over-availability trade-off;
- the filesystem receipt store remains non-monotonic and is not rollback resistant by itself;
- if every preserving authority history is rolled back together, replay can return;
- callback or remote-target failure can consume authorization without proving exactly-once remote completion;
- production-host isolation, production control-plane independence, physical-power-loss behavior, arbitrary resolver/transport deadline behavior, bind-mount aliasing into an authority directory and remote-target semantics are not certified by the reference fixtures;
- MgNarf has not received an independent security certification.

The reported `t15` race evidence also remains explicitly inconclusive: observed runs hit both all-blocked and all-allowed extremes while preserving correct bytes, but did not establish the interesting middle interleaving.

## Existing measured boundary

RC2 retains the RC1 measured boundary for strict frozen task/candidate/policy/goalpost binding, exact verifier-requirement binding, authenticated complete evidence, revocation/inhibitor/state revalidation, process isolation fixtures, crash characterization, rollback-protected authorities, PostgreSQL fencing, signed-witness fencing, stable operation IDs, multi-domain fencing, high-fanout single-winner races, ambiguous durable-reservation handling and canonical/receipt fuzzing.

A green limitation witness continues to mean that the documented limitation was reproduced as expected; it does not convert the limitation into a security PASS.

## License

Apache License 2.0. Preserve the applicable attribution from [NOTICE](NOTICE):

```text
This software includes software originally developed as MGNARF Ändi.
```

> PINKY: Did red team find something real?  
> BRAIN: Yes. Fix what reproduces, keep what is uncertain visible, and move the candidate only with evidence.
