# Player monitoring and privacy notice

Server operators running Server Guard must make this notice available to players (for example in
the server rules, MOTD, or Discord). Steamworks guidance requires clear notice that a monitoring
system exists and understandable reasons when a player is excluded.

## What Server Guard is

Server Guard is a **server-side** integrity check. It observes only facts the dedicated server can
already verify from normal gameplay: authenticated identity, network request order, movement,
combat, inventory changes, crafting, loot, world interaction, and privileged actions.

## What it does NOT do

- It does **not** scan your computer, processes, drivers, files, overlays, memory, or input
  devices, and takes no screenshots.
- It does **not** bypass or interact with Easy Anti-Cheat.
- It cannot and does not claim to prove use of any specific cheat program from behavior alone.

## What is recorded

For gameplay events that trigger a detector, the server writes an evidence record containing:
server build, session epoch, a **pseudonymous** player identifier (keyed HMAC), the entity ID,
the detector and version, observed values, expected bounds, contributing event IDs, the action
taken, and a review disposition.

## What is NOT recorded by default

- Authentication tickets, passwords, or encryption material.
- Raw packet payloads.
- Full chat text or private messages (chat *rate* may be used as availability evidence; chat
  *content* moderation is a separate concern, out of scope here).
- IP addresses and other secrets are not retained by default.

## Pseudonymization and access

Exported evidence uses keyed HMAC identifiers. The mapping from pseudonym to platform identity is
kept in a separate, permission-restricted local file and is only resolved during an operator
review or appeal.

## Retention schedule (operator-configurable defaults)

| Data | Default retention | Notes |
|---|---|---|
| Evidence JSONL segments | 30 days | Append-only, hash-chained, rotated by size and day. |
| Sampled position history (review replay) | 7 days | Pseudonymous, bounded per player. |
| Pseudonym → identity map | Lifetime of the ban/appeal window, then purged | Restricted file permissions. |
| Pseudonym HMAC key | Destroyed when the evidence written under it expires | Platform IDs are enumerable, so a purged identity map de-identifies only once its key is destroyed. Key rotation starts a new pseudonym epoch. |
| Confirmed false-positive fixtures | Indefinite (de-identified) | Kept as regression tests, no player identity. |
| Suppressed / raw tuning findings | 30 days | Used only for threshold tuning. |
| Operator audit log (overrides, unbans, purges) | 1 year | Actor, timestamp, reason; no gameplay data. |
| Rate-limit / availability counters | In-memory only, never persisted | Flood evidence records pseudonym and cost class, no IP or source prefix. |
| Evidence exports and webhook alerts | Operator responsibility once exported | Exports are pseudonymous; webhook payloads carry evidence IDs only. Purge does not reach copies already exported. |

Operators may shorten retention. A player may request purge of evidence tied to a resolved appeal;
purge replaces the record payload with a tombstone (the hash chain still verifies) and is
recorded in the audit log.

## Operator review channels

Operator review happens through the server console or an authenticated web dashboard; an
optional webhook (for example Discord) can notify the operator with evidence IDs only. Real
identity is resolved only during a review or appeal and never leaves the server host except to
the reviewing operator.

## Your rights on this server

- You will be told, in game, the rule and evidence ID behind any kick, quarantine, or local ban.
- You may appeal a contested action (see [`docs/POLICY.md`](docs/POLICY.md) → Roles and appeals).
- Detectors default to observe-only; enforcement is opt-in per operator and per detector.

## For operators in the EU/EEA

The server operator, not the mod maintainer, is the data controller for their deployment.
Pseudonymized identifiers remain personal data while the HMAC key exists. The customary legal
basis for cheat detection is legitimate interest in service integrity; operators should note
that basis in their server rules and be prepared to handle access, erasure, and objection
requests. Erasure requests are not limited to the appeal flow above.

Retention owner and contact: maci (maci.stgn@gmail.com). Operators running their own deployment
should substitute their own contact here.

## Operator checklist

Before opening a server with Server Guard:

- Post this notice in the server rules, MOTD, or Discord.
- Replace the retention owner and contact with your own.
- Confirm the retention schedule matches your rules; defaults apply otherwise.
- Enable the alert webhook only if you want it; payloads carry evidence IDs, never identity.
- Restrict the identity-map file and evidence directory permissions on your host.
- Decide how access, erasure, and objection requests are handled (see the EU/EEA section;
  erasure is not limited to the appeal flow).
- Record purge and unban actions in the audit log; if you export evidence, keep those exports
  under the same retention discipline.
