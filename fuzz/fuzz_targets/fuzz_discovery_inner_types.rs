#![no_main]
use libfuzzer_sys::fuzz_target;
use trustgrant::{DiscoveryDelegation, DiscoveryRevocationPolicy};

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let s = input.as_ref();

    // DiscoveryDelegation::new() is infallible — must never panic
    let delegation = DiscoveryDelegation::new(s);
    // Debug format must be non-empty
    let debug = format!("{:?}", delegation);
    assert!(!debug.is_empty());

    // DiscoveryRevocationPolicy::new() with fuzzer-derived TTL values
    if data.len() >= 8 {
        let non_revoked = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let max_stale = if data.len() >= 16 {
            u64::from_le_bytes([
                data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
            ])
        } else {
            3600
        };

        // May error on zero TTL — that's fine, we test no panics
        let _ = DiscoveryRevocationPolicy::new(s, non_revoked, max_stale);
    }
});
