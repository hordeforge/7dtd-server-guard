# surface_inventory

Planned Phase 1 tool: a Mono.Cecil metadata probe that inventories authoritative decision
points in the pinned build and emits hook manifest v1 ([docs/SCHEMAS.md](../../../docs/SCHEMAS.md)).
Runs against the installed assemblies by path; never copies or commits game DLLs
([AGENTS.md](../../../AGENTS.md)). No code yet: this README is the planned contract the
Phase 1 TODO item must satisfy.

## Inputs

- `--assembly-dir <path>`: directory containing the installed `Assembly-CSharp.dll` and
  friends of the pinned build (default: the local dedicated server's managed dir).
- `--registry docs/DETECTORS.md`: the detector registry; the probe targets each detector's
  declared `seam` in `tools/detector_spec.yaml` (consumed via
  `config/detector-config-manifest.json`) and reports any row whose seam cannot be
  resolved on the pinned build.
- `--manifest-out <path>`: where hook manifest v1 is written.
- `--fingerprint-out <path>`: where the build fingerprint (SHA-256 over assembly identity
  plus `Assembly-CSharp.dll` file hash) is written.

## Outputs

1. Hook manifest v1 (SCHEMAS.md -> Hook manifest): one entry per resolved hook with full
   signature, parameter roles, return type, metadata token, hook kind, seam class, thread,
   expected rate, reject capability, compatibility risk, fallback event, and the
   server-derived / client-declared authority class of every input.
2. Unresolved list: registry rows whose seam cannot be resolved on the pinned build, with
   the reason (type missing, signature mismatch, token mismatch). These detectors stay
   observe-only or are deferred.
3. Build fingerprint file used by the metadata-contract tests (TEST_PLAN.md layer 3) and by
   evidence records at runtime.

## Validation rules

- Exit non-zero if the probe cannot read the pinned assembly (wrong path or unexpected
  build), so CI cannot silently pass on an unexamined build.
- Exit non-zero if a registry row that claims a Hard ceiling has no resolved seam with
  complete server-derived inputs; a missing seam demotes the row (Strong or deferred) in
  the registry, it does not ship as Hard.
- The manifest and fingerprint must be byte-identical across repeated runs on the same
  assembly directory.

## Dependencies

Mono.Cecil (netstandard/net48 build), referenced by path or package, never committed.
The probe is a separate console tool, not part of the mod DLL.
