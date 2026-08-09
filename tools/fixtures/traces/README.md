# traces

Versioned synthetic replay inputs (TEST_PLAN.md Layer 4), conforming to replay-trace v1.
Layout: one subdirectory per
detector family (`movement/`, `combat/`, ...) or one `detectors/<id>/` directory per
detector once the corpus grows. Every trace file carries the recording build's hook
manifest hash and schema version; a fingerprint or schema mismatch skips and reports
instead of replaying blindly. The inventory stack design vector is exercised before Phase 4;
the full corpus remains Phase 4 work.
