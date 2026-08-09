# Security policy

Server Guard is a security tool. A flaw in it can be worse than its absence: a false hard-reject
can deny legitimate play, and a bypass can give a false sense of protection. Report issues
privately.

## Reporting a vulnerability

- **Contact:** maci (maci.stgn@gmail.com).
- Do **not** open a public issue for an exploitable finding first.
- Include: affected build (target is V3.1.0 b14), the detector or code path, a reproduction or
  proof-of-concept, and the impact (false reject, evidence tampering, bypass, resource abuse).

## In scope

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
