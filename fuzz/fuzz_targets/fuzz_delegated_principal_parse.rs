#![no_main]
use libfuzzer_sys::fuzz_target;
use trustgrant::discovery::parse_delegated_principal_key_document;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_delegated_principal_key_document(s);
    }
});
