#![no_main]
use libfuzzer_sys::fuzz_target;
use trustgrant::document::{RawTrustGrantDocument, ValidatedTrustGrantDocument};

fuzz_target!(|data: &[u8]| {
    if let Ok(raw) = RawTrustGrantDocument::parse_json_bytes(data)
        && let Ok(validated) = ValidatedTrustGrantDocument::try_from(raw)
    {
        // Validated document must have consistent scope
        assert!(validated.target_scope().all() || !validated.target_scope().allow().is_empty());
    }
});
