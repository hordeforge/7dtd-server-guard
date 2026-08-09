# Config

Strict versioned config load, validation, and reload (config v1 in
[docs/SCHEMAS.md](../../../docs/SCHEMAS.md)). Rejects unknown keys and invalid ranges;
computes the effective-config hash written into every evidence record. Console reload runs
the same checks.
