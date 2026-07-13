#![no_main]
use libfuzzer_sys::fuzz_target;
use trustgrant::document::RawTrustGrantDocument;

fuzz_target!(|data: &[u8]| {
    // Parser must not panic on any input
    if let Ok(document) = RawTrustGrantDocument::parse_json_bytes(data) {
        // Invariants on parsed output
        assert!(!document.trustgrant_id.is_empty());
        assert!(!document.issuer_authority.is_empty());
        assert!(!document.key_id.is_empty());
    }
});
