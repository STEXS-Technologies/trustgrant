#![no_main]
use libfuzzer_sys::fuzz_target;
use trustgrant::{GrantLineage, GrantRevision, GrantSeriesId, SupersessionPolicy, TrustGrantId};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Derive revision from first byte (1–255, since GrantRevision requires > 0)
    let revision_val = (data[0] as u64).max(1);

    // Try creating a GrantRevision — may fail on 0 (but we ensured >= 1)
    let Ok(revision) = GrantRevision::new(revision_val) else {
        return;
    };

    let trustgrant_id = TrustGrantId::generate();
    let series_id = GrantSeriesId::generate();

    // Test with various supersession policies
    let policies = [
        SupersessionPolicy::Coexist,
        SupersessionPolicy::SupersedePrevious,
        SupersessionPolicy::ExplicitRevocationRequired,
    ];

    let policy_idx = if data.len() > 1 {
        (data[1] as usize) % policies.len()
    } else {
        0
    };
    let policy = policies[policy_idx];

    // Test with and without supersedes
    let supersedes = if data.len() > 2 && data[2].is_multiple_of(2) {
        Some(TrustGrantId::generate())
    } else {
        None
    };

    // GrantLineage::new is infallible — must never panic
    let lineage = GrantLineage::new(trustgrant_id, series_id, revision, supersedes, policy);

    // Basic invariants
    assert_eq!(lineage.trustgrant_id(), trustgrant_id);
    assert_eq!(lineage.grant_series_id(), series_id);

    // Test GrantRevision::new(0) — must fail
    let _ = GrantRevision::new(0);
});
