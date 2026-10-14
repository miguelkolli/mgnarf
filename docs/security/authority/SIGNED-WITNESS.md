# Signed external witness boundary

## Status

This layer follows `POSTGRES-AUTHORITY.md`.

The PostgreSQL authority blocks replay while its ledger history survives, but a privileged database administrator can still truncate or restore that history. An Ed25519-authenticated witness adds another authority domain whose private signing key and append-only token history are outside the PostgreSQL runtime credential and database control plane.

The measured claim is deliberately narrow:

> Resetting the local NARF history and the PostgreSQL ledger does not re-enable the same authorization while the signed witness retains its consumed-token history.

This is not a universal rollback-resistance claim.

## Protocol

`SignedWitnessAuthority` is a `ConsumptionAuthority`.

For every `reserve` or `status` request the client generates a fresh 256-bit nonce. The witness signs a canonical JSON response with Ed25519. The client accepts the response only when all of these bindings match:

- signing public key,
- protocol version,
- operation,
- exact contract token,
- fresh request nonce,
- witness signing-domain fingerprint,
- syntactically valid ledger head metadata.

A captured older valid `RESERVED` response cannot be replayed for a new request because its nonce no longer matches.

The client holds only the public verification key. The witness service owns the private key.

## Append-only checkpoint chain

The reference witness persists one record per first reservation:

- monotonically increasing sequence,
- contract token,
- previous checkpoint SHA-256,
- current checkpoint SHA-256.

The record is appended and fsynced before the witness signs `RESERVED`.

The signature authenticates the witness response. The hash chain makes accidental or partial history corruption visible when the service reloads its ledger.

Neither signatures nor hash chains make storage inherently monotonic. A privileged operator that restores an older internally consistent witness ledger can still make the witness forget a later token.

## Measured cases

`tools/test_signed_witness.py` and `.github/workflows/signed-witness.yml` require exactly five outcomes.

1. **Local + PostgreSQL rollback, witness preserved — PASS**
   - one effect executes,
   - local receipt history is restored to its pre-consumption snapshot,
   - a privileged PostgreSQL administrator truncates the database ledger,
   - the witness history is left intact,
   - replay is rejected by the witness before PostgreSQL is called again.

2. **Wrong Ed25519 public key — PASS**
   - the witness may already have persisted the reservation,
   - the client cannot authenticate the response,
   - the external effect is not entered.

3. **Witness unavailable — PASS**
   - network/service failure is fail-closed,
   - the external effect is not entered.

4. **Captured signed success with a stale nonce — PASS**
   - the signature is cryptographically valid,
   - token and signing identity match,
   - the response is rejected because the request nonce differs.

5. **Privileged witness-history rollback — LIMITATION_CONFIRMED**
   - local history is restored,
   - PostgreSQL is truncated,
   - the witness ledger is restored to its own pre-consumption snapshot while the same signing key remains valid,
   - replay succeeds and the external effect runs a second time.

The workflow therefore requires:

- 4 × `PASS`,
- 1 × `LIMITATION_CONFIRMED`,
- 0 × `FAIL`,
- overall `BOUNDARY_CONFIRMED`.

A green limitation witness means the limitation was reproduced exactly.

## Deployment requirements

A real deployment only gains the measured benefit when the witness is actually outside the database rollback/control domain. Putting the witness ledger on a filesystem, backup set, administrator account or storage snapshot controlled by the same authority as PostgreSQL does not create an independent domain.

Production deployments should also use HTTPS even though the signed protocol authenticates responses. The reference client permits plain HTTP only for an explicit loopback fixture.

Signing-key rotation must not be treated as adding an independent authority. The all-of domain identity is the Ed25519 public-key fingerprint; aliases using the same key are one logical witness domain.

## Remaining boundary

The next deeper problem is coordinated rollback of every authority, including the witness itself.

Closing that requires a genuinely monotonic or externally anchored history such as an independently administered transparency log, hardware-backed monotonic state, a target-side durable idempotency/fencing mechanism, or another system whose history cannot be rewound by the same privileged control plane.

The CI witness runs as a separate process with separate storage on one runner. That validates protocol behavior and the measured failure cases; it does not prove independent production administration, Byzantine tolerance, cross-region linearizability, physical-power-loss safety, or exactly-once remote effect completion.
