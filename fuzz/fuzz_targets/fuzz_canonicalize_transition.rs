#![no_main]
use libfuzzer_sys::fuzz_target;
use trustgrant::{
    document::RawOwnershipTransitionDocument,
    ownership::{canonicalize_transition_acceptance, canonicalize_transition_proposal},
    verify::CanonicalizationProfile,
};

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = RawOwnershipTransitionDocument::parse_json_bytes(data) else {
        return;
    };

    // canonicalize_transition_proposal must never panic
    if let Ok(bytes) = canonicalize_transition_proposal(&raw, CanonicalizationProfile::Rfc8785) {
        // Output must be valid UTF-8
        let s = std::str::from_utf8(bytes.as_slice());
        assert!(s.is_ok());
        // Output must be valid JSON
        let _: Result<serde_json::Value, _> = serde_json::from_slice(bytes.as_slice());
    }

    // canonicalize_transition_acceptance must never panic
    if let Ok(bytes) = canonicalize_transition_acceptance(&raw, CanonicalizationProfile::Rfc8785) {
        // Output must be valid UTF-8
        let s = std::str::from_utf8(bytes.as_slice());
        assert!(s.is_ok());
        // Output must be valid JSON
        let _: Result<serde_json::Value, _> = serde_json::from_slice(bytes.as_slice());
    }
});
