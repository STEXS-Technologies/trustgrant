#![no_main]
use libfuzzer_sys::fuzz_target;
use trustgrant::document::RawTrustGrantDocument;
use trustgrant::verify::{CanonicalizationProfile, canonicalize_trustgrant};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data)
        && let Ok(raw) = RawTrustGrantDocument::parse_json_str(s)
        && let Ok(bytes) = canonicalize_trustgrant(&raw, CanonicalizationProfile::Rfc8785)
    {
        // Canonical output must be valid UTF-8
        let canonical_str = std::str::from_utf8(bytes.as_slice());
        assert!(canonical_str.is_ok());
        // Canonical output must be valid JSON
        let _: Result<serde_json::Value, _> = serde_json::from_slice(bytes.as_slice());
    }
});
