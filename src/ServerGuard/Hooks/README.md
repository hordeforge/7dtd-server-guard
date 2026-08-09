# Hooks

`HookRegistry`: exact type/method/signature/token resolution against the pinned build, hook
manifest v1 consumption, per-hook runtime fault guard with self-disable, build fingerprint
check. Fail open on mismatch ([docs/ARCHITECTURE.md](../../../docs/ARCHITECTURE.md) -> Hook
policy). No transpilers in the initial design.
