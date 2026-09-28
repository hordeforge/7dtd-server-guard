# Upgrading

What changes for a consumer between two releases, and what to do about it. The changelog
records every entry a release carried; this document records what a reader has to do
before or after the upgrade. A release whose `### Breaking` or `### Removed` entry has no
section here fails `make check` (see "Keeping this current" below).

The version policy is at the head of [CHANGELOG.md](../CHANGELOG.md): this is a 0.x
project, so a minor bump may change tooling contracts and command names, and a patch bump
is expected not to. There is no support window and no backport window, so a patch is the
only upgrade that is expected to need nothing here.

## Before any upgrade

Run the shipped pre-deploy check against the config you are actually deploying. It is the
same code path the server's strict loader runs, so what it rejects, startup rejects:

```bash
make verify-config FILE=/path/to/server-guard.json
```

`SKIP_ENV=1` drops the environment pass, which is the one check that cannot be answered
from the file alone: it fails when a `webhook` or `dashboard` that is `enabled` names an
environment variable that is unset. Leave it on wherever the real environment is
available, because an unset sink variable is the failure mode this check exists to catch.

`SHOW_EFFECTIVE=1` prints the effective (defaulted) config and the `configHash` the
evidence records, the health report, and the hook manifest carry. Read it once before the
upgrade and once after: a hash that changes is the signal that the config on disk is not
the config the running detectors are reporting against.

## 0.4.1 to 0.5.0

Five changes break a consumer, and the first three are checked before the server starts
rather than at runtime.

### Config validation rejects an empty path and a non-uppercase environment variable name

- Before: an empty `evidence.dir`, `identityMap.path`, or `hmacKey.path` loaded, and a
  `webhook.urlEnv` or `dashboard.secretEnv` naming a lower-case or hyphenated environment
  variable loaded too. A misspelled name did not fail, it disabled the sink.
- After: the config is rejected wholesale at startup, before any detector runs.
- What breaks: a server that started cleanly on 0.4.1 and now refuses to start, and it
  names no file to look at if the rejection is only in a startup log line.
- What to do: run `make verify-config FILE=<file>` first. Rename the variable in both the
  config and the environment before upgrading. The pattern is `^[A-Z][A-Z0-9_]*$`, so
  `serverguard-webhook-url` becomes `SERVERGUARD_WEBHOOK_URL`. The values the variables
  hold are unchanged, and a config that never set these keys keeps the shipped defaults
  (`SERVERGUARD_WEBHOOK_URL`, `SERVERGUARD_DASHBOARD_SECRET`), which already match.

### The evidence schema closes its root object

- Before: a record carrying an unrecognized top-level key validated. After: the root is
  `additionalProperties: false`, so it does not.
- What breaks: a consumer that validates records itself, such as a webhook sink or an
  analyst's script. A detector that wants to emit such a key has it named in
  [SCHEMAS.md](SCHEMAS.md) first, which is where the new key is added.
- What to do: no action for an existing evidence directory. Records already on disk
  validate, and `make verify-evidence` and `make verify-archive` are unaffected: both
  verify the hash chain and neither reads the schema.

### A `health` record requires `configHash`

- Before: `configHash` was optional on a health snapshot. After: it is required.
- What breaks: a consumer that validates the health snapshots in an existing evidence
  directory against `config/schemas/evidence.v1.schema.json`. In 0.4.1 a health record
  could not carry the field at all, so every snapshot already on disk lacks it.
- What to do: tolerate a health record without `configHash` in the consumer, or migrate
  the existing directory. The records are unchanged on disk and still verify: the chain
  hashes the record as written, and the schema is not on that path.

### A replay trace requires the `determinism` block

- Before: a trace without `determinism` validated. After: `startUtc`, `startMonotonicMs`,
  and `fingerprint` are required.
- What breaks: `make exercise` and any corpus of traces written by an older harness.
- What to do: regenerate traces with the current harness. A trace edited rather than
  regenerated is resealed with
  `uv run python tools/replay_contract_check.py --fix-fingerprint`, which rewrites the
  recorded `fingerprint` from the trace's own outcome projection.

### The tool CLIs report a usage error as exit 2

- Before: a tool reported a usage error and a verification failure under the same
  nonzero exit code. After: a usage error is 2 and a verification failure is 1, with the
  verdict on stdout and the detail on stderr.
- What breaks: a script that treated any nonzero exit as "the evidence is bad". It now
  sees 2 for its own invocation mistake.
- What to do: read stdout to distinguish a pass from a failure, and treat 2 as a bug in
  the caller, not in the evidence. This applies to `make export-evidence`,
  `make verify-archive`, `make backup`, `make backup-status`, `make drill-restore`, and
  `make verify-config`.

### Records whose free text held an identifier no longer validate

Under `### Changed`: the evidence schema now denies personal data by value as well as by
key, through `personalDataValueDenyList`. A record written before this release whose free
text carried a Steam id in either spelling, the 64-bit or Xbox account form, a dotted-quad
address, a MAC address, or a contact address no longer validates. Nothing in the shipped
sample did, and the records stay on disk and still verify, so this is a consumer-side
validation question rather than an upgrade step.

## Rollback

Rollback is the reverse: restore the previous config, and expect the newer evidence to be
read-only to the older build. The procedure is in
[OPERATIONS.md](OPERATIONS.md) -> Upgrade and rollback.

## Keeping this current

`make check` fails when a dated changelog release carrying a `### Breaking` or `### Removed`
entry has no section in this file, so a breaking change cannot ship with the entry and
nothing else. The rule is one of the release checks in [CONTRIBUTING.md](../CONTRIBUTING.md)
-> Releasing, and it is a minor bump under the 0.x policy, so it goes in a section headed
`## <old> to <new>`.
