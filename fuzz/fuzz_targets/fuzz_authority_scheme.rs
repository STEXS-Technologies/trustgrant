#![no_main]
use libfuzzer_sys::fuzz_target;
use trustgrant::AuthorityId;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let s = input.as_ref();

    if let Ok(authority) = AuthorityId::new(s) {
        // Extract scheme — must never panic
        let scheme = authority.scheme();
        // Debug format must be non-empty
        let debug = format!("{:?}", scheme);
        assert!(!debug.is_empty());

        // Scheme extraction is deterministic
        let scheme2 = authority.scheme();
        assert_eq!(format!("{:?}", scheme), format!("{:?}", scheme2));
    }
});
