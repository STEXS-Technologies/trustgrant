#![no_main]
use libfuzzer_sys::fuzz_target;
use trustgrant::domain::AuthorityId;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    if let Ok(authority) = AuthorityId::new(input.as_ref()) {
        // Roundtrip through Display and re-parse
        let display = authority.to_string();
        assert!(!display.is_empty());
        let reparsed = AuthorityId::new(&display);
        assert!(reparsed.is_ok());
        assert_eq!(reparsed.unwrap(), authority);
    }
});
