# Security policy

Server Guard is a security tool. A flaw in it can be worse than its absence: a false hard-reject
can deny legitimate play, and a bypass can give a false sense of protection. Report issues
privately.

## Status of the code today

The in-game runtime does not exist yet. `src/ServerGuard/` holds only directory READMEs, and the
phase ledger is at the Phase 0 exit review ([TODO.md](TODO.md)). The shipped executable code is
the Python tooling under `tools/` plus the CI workflow, so the evidence, archive, and replay
tooling is what can actually be attacked today; the in-game classes below describe the runtime as
designed. [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) ranks the current surface and names the
location of every threat.

## Reporting a vulnerability

- **Contact:** maci (maci.stgn@gmail.com).
- Do **not** open a public issue for an exploitable finding first.
- Include: affected build (target is V3.2.0 b9), the detector or code path, a reproduction or
  proof-of-concept, and the impact (false reject, evidence tampering, bypass, resource abuse).

## Supported versions

There is no released version to support yet. The only executable code is the tooling on the
default branch of this repository, and the in-game runtime has not been built. Fixes land there
and are not backported; there is no older line to patch.

## In scope

Shipped today: the Python tooling under `tools/` (evidence chain verification, evidence
archiving, the restore drill, the backup-age check, config validation, and SBOM rendering) and
the CI workflow. Two areas in particular, because they are where a mistake does damage today:

- Any path an operator supplies that the tooling then creates, copies into, or deletes a
  directory tree at: `tools/evidence_export.py` (`--out`, which is created with
  `mkdir(parents=True)` and swept of stale staging trees), `tools/restore_drill.py` (`--work`,
  which the restore writes into), and `tools/sbom.py` (`--out`, whose parent directories are
  created). `--archive` on the first two and `--root` on `tools/backup_status.py` are read-only
  and are not in this class.
- Anything that weakens or forges an evidence hash chain, or that corrupts an archive so a
  restore cannot be proven.

Path handling that is already covered and would be a regression: the untrusted-name validator
shared by `tools/evidence_check.py` and `tools/evidence_export.py` refuses anything that is not
a plain file name inside the evidence directory, and every manifest-supplied name passes it
before reaching the filesystem.

Planned runtime, not yet built: in-game detectors and the review surface. The classes below
describe that design.

- Bypasses of a Hard invariant that let an impossible action through.
- False hard-rejects that deny legitimate play.
- Induced findings: one player triggering detections attributed to another.
- Evidence tampering, truncation, injection, or hash-chain forgery by a non-keyholder (the
  chain does not claim to prove anything against the evidence keyholder).
- Authentication bypass or privilege escalation in the review dashboard or console commands.
- Interception or spoofing of the optional operator-alert webhook endpoint.
- De-anonymization of pseudonymous evidence, or leakage of secrets/auth material into logs.
- Resource-exhaustion of the game thread through the mod's own code paths.

## Out of scope

- Client-side cheats that Server Guard explicitly does not claim to detect (aimbot/ESP proof from
  a single event; anything requiring client memory inspection).
- Network-level volumetric DoS: that belongs to the host firewall, not the game thread.
- Vulnerabilities in the base game, EAC, or unrelated mods.
- A compromised host, malicious server admin, or a malicious same-process DLL (equal server trust
  cannot be defended against from inside the process).

## Disclosure

Coordinated disclosure. We aim to acknowledge within 7 business days and to agree a fix
and public-disclosure timeline with the reporter. Fixes to Hard invariants ship with a regression
fixture so the bypass cannot silently return.

## Handling of player evidence in reports

Do not include real players' pseudonym-to-identity mappings, auth tickets, or raw packet captures
in a report. De-identified reproductions only.
