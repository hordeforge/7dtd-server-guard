# Evidence

`EvidenceStore`: append-only JSONL segments, per-record hash chain, tombstones, rotation by
size and day, retention, redaction, crash-safe segment close, export. Dedicated writer
thread. Schema: evidence v1 in [docs/SCHEMAS.md](../../../docs/SCHEMAS.md). Never log auth
tickets, passwords, raw packet bodies, or full chat.
