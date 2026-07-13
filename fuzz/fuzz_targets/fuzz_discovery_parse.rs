#![no_main]
use libfuzzer_sys::fuzz_target;
use trustgrant::discovery::parse_authority_discovery_document;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data)
        && let Ok(doc) = parse_authority_discovery_document(s)
    {
        assert!(!doc.keys().is_empty());
    }
});
