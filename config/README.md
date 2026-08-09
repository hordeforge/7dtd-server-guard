# config

Operator-facing configuration.

- `server-guard.example.json`: complete example of config v1, kept in sync with
  [docs/SCHEMAS.md](../docs/SCHEMAS.md) -> Config schema. The doc is canonical; the example
  is illustrative. Every key here must exist in the schema, and the schema must not contain
  keys the example omits without a default.
- `server-guard.local.json`: runtime config; gitignored (may contain the webhook URL and
  operator choices). Never commit it.
