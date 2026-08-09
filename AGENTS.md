# AGENTS.md: 7dtd-server-guard

This repository owns server-side behavioral validation, exploit mitigation, evidence, and
operator response for modded 7DTD dedicated servers.

## Boundaries

- Do not add client scanners, drivers, memory inspection, screenshots, or EAC bypasses.
- Do not claim that a behavioral signal proves use of a particular cheat program.
- Do not automatically permanently ban. Default every new detector to observe-only.
- Hard rejection requires complete authoritative inputs and legal-context tests.
- Keep chat content moderation separate from gameplay-integrity detection.
- Never write network IO or unbounded work on the game thread.
- Never commit game assemblies, authentication material, player evidence, or server data.
- Use full method signatures and build fingerprints for Harmony hooks. Fail open on mismatch.
- Use `7dtd-loadgen` for repeatable scenarios and `7dtd-apm` for overhead/regression evidence.
- Follow the parent workspace naming, EAC, secret, source-distribution, and writing rules.

The documents in `docs/` (indexed in `docs/INDEX.md`) and the phase gates in `TODO.md` are the
design contract. Update them when evidence changes an assumption; record why in
`docs/DECISIONS.md`. Run `make check` before opening a docs change.


## Stock-game research -> 7dtd-research

Anything that studies the **stock** dedicated server belongs in
[`../7dtd-research/`](../7dtd-research/), not here: reverse-engineering
narratives (`docs/`), the Mono.Cecil dump tooling (`tools/`), wire/protocol
analysis, and engine cost/loop RE. This repo owns server-side validation and exploit mitigation;
it does not host stock-game RE docs or dumpers. When RE is needed, add it
under `../7dtd-research/` and link back. How to RE:
[`../7dtd-research/docs/re-methodology.md`](../7dtd-research/docs/re-methodology.md).
