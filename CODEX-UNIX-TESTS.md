# Run the distinct-UID tests with local Codex

The runnable harness is [tools/test_unix_isolation.py](tools/test_unix_isolation.py).
It targets the external standalone mgnarf repository. It does not implement
a new gate or involve MGSystem.

## What it checks

Twelve operations are attempted in two host-owned layouts, giving **24 planned
cases**. In one layout the authority/store directories are private (0700).
In the other they permit traversal (0755), while the key and receipt files
remain private (0600) and the directories remain unwritable by the worker.

| Operation | Expected result for UID/GID 65534 |
| --- | --- |
| Read, overwrite or unlink the host key | EACCES or EPERM |
| Read, overwrite, unlink, rename or replace a consumption receipt | EACCES or EPERM |
| Create a symlink inside the store | EACCES or EPERM |
| Change the store mode | EACCES or EPERM |
| Rename the store or its authority parent | EACCES or EPERM |

The child must first prove it can traverse/read a public control and write/read
its own staging directory. The harness verifies its real/effective/saved
UIDs and GIDs, empty supplementary groups and zero effective capabilities.
The child receives paths and an operation name, never the host key.

Each fresh fixture runs the actual NARFGate API to obtain PASS and consume one
test effect before the attack. PASS requires an OS denial, unchanged host
contents/permissions/ownership, authenticated receipts and a denied fresh-session
replay with exactly one total callback and test-target write.

Exit codes: **0 = scoped PASS; 1 = FAIL; 2 = UNVERIFIED**. A credential-switch
failure records all planned cases UNVERIFIED with zero protected operations.
There is no simulated success fallback.

## Requirements

- Linux with Python 3 and permission to switch root children to UID/GID 65534.
- Run only this reviewed harness with sudo in a disposable worktree.
- An absolute, initially nonexistent evidence directory outside the repository.
- No production keys, receipt directories, accounts or effects are used. The
  script creates temporary host/worker fixtures and removes them after each case.

The current gate blob is
`41137015f2f89cd1ec97b5f63d0a8a8d746de781`. The command below checks that expected
blob before any protected operation. The tested gate revision before this
harness was added is `9d4608770c15774a365ec2cc23c56bf38cd198bc`; repository
unit tests for that revision passed 34/34. A new runner commit must be recorded
separately by the person executing this assessment.

## Command in the reviewed disposable worktree

```bash
test_python="$(command -v python3)"
test_evidence="$(mktemp -d /tmp/mgnarf-unix-evidence.XXXXXX)"
sudo -- "$test_python" tools/test_unix_isolation.py \
  --output "$test_evidence/results" \
  --expected-gate-blob 41137015f2f89cd1ec97b5f63d0a8a8d746de781
unix_test_exit=$?
sudo -- cat "$test_evidence/results/summary.json"
printf 'Unix harness exit code: %s\n' "$unix_test_exit"
```

The results directory is root-owned and private; use sudo to inspect or archive
only these test artifacts. Preserve the frozen plan, preflight, all 24 evidence
rows and summary. Receipt snapshots are retained, but ephemeral key contents
are intentionally not archived or printed.

## Copy this task to local Codex

```text
TEHTÄVÄ: suorita ulkoisen mgnarfin aidot Unix UID/GID-eristystestit.

Kohde: miguelkolli/mgnarf. MGSystem ei kuulu tähän tehtävään.
Lue CODEX-UNIX-TESTS.md ja tools/test_unix_isolation.py ennen sudo-ajoa.

1. Ota alkuperäisen checkoutin HEAD- ja Git-status-snapshot. Älä muuta sitä.
2. Fetch origin. Luo kertakäyttöinen detached worktree testikoodin commitista.
   Jos Unix-testikoodin PR ei ole vielä mainissa, käytä origin/codex/unix-isolation-codex-20261011.
   Muuten käytä tuoretta origin/mainia. Kirjaa käytetty täysi commit SHA.
3. Tarkista, että testattava gate-blob vastaa dokumentin odotettua arvoa.
   Jos ei vastaa, raportoi UNVERIFIED; älä muuta odotusta arvaamalla.
4. Aja dokumentin komento oikeassa Linuxissa sudo-oikeuksilla. Sudo koskee
   vain tätä tarkastettua testiharnessia ja sen väliaikaisia fixtureja.
   Jos valtuus tai käyttäjän vaihto estyy, kirjaa UNVERIFIED + täsmällinen syy.
5. Älä muuta gatea, policyä, tuotekoodia tai testin odotuksia saadaksesi PASS.
   Älä tulosta avaimia tai käytä tuotannon tiedostoja/ulkoisia kohteita.
6. PASS vaatii exit 0, summary.result PASS, 24 PASS-riviä ja 24 suoritettua
   suojatun alueen operaatiota. Jokaisessa rivissä pitää olla oikea eri UID,
   onnistuneet worker-kontrollit, EACCES/EPERM, muuttumaton host-alue,
   autentikoidut kuitit ja estetty replay. Tarkista näyttö, älä vain tekstiä.
7. Säilytä suunnitelma, preflight, kaikki evidence-rivit, summary ja exit-koodi.
   Aja normaalit repositoryn yksikkötestit erikseen ja raportoi niiden tulos.
8. Poista vain oma kertakäyttöinen worktree; säilytä testinäyttö. Varmista,
   että alkuperäisen checkoutin HEAD ja Git-status vastaavat alun snapshotia.
   Älä pushaa, yhdistä PR:ää, luo tagia tai julkaise releasea tässä ajossa.

Raportoi PASS/FAIL/UNVERIFIED, commit, Python/Linux-versiot, toteutuneet
UID/GID:t, tapausmäärät, callbackit/kohdekirjoitukset, replay ja näyttöpolku.
Rajaa tulos host-owned fixtureen. Älä väitä tuotannon sandbox-eristystä,
rollback-kestävyyttä, power-loss-turvaa tai koko järjestelmän PASSia.
```

## Validation status when prepared

The authoring executor rejects setgroups with EPERM and UID/GID changes with
EINVAL. A real preflight run therefore yielded **24 UNVERIFIED, 0 protected
operations, exit 2**. This verifies reporting of the unavailable boundary;
it does **not** validate the privileged test path or Unix isolation itself.
The local Codex run above is needed to obtain that evidence.

PINKY: Can the worker write somewhere at all? BRAIN: Its own staging area must
work before a host-area denial can count.
