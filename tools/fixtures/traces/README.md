# traces

Versioned synthetic replay traces (TEST_PLAN.md Layer 4). Layout: one subdirectory per
detector family (`movement/`, `combat/`, ...) or one `detectors/<id>/` directory per
detector once the corpus grows. Every trace file carries the recording build's hook
manifest hash and schema version; a fingerprint or schema mismatch skips and reports
instead of replaying blindly. Empty until Phase 4.
