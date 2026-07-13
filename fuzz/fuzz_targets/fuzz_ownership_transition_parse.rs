#![no_main]
use libfuzzer_sys::fuzz_target;
use trustgrant::document::RawOwnershipTransitionDocument;

fuzz_target!(|data: &[u8]| {
    if let Ok(document) = RawOwnershipTransitionDocument::parse_json_bytes(data) {
        assert!(!document.transition_id.is_empty());
        assert!(!document.origin_authority.is_empty());
        assert!(!document.from_authority.is_empty());
        assert!(!document.to_authority.is_empty());
        // from and to must differ
        assert_ne!(document.from_authority, document.to_authority);
    }
});
