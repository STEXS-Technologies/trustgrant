#![no_main]
use libfuzzer_sys::fuzz_target;
use trustgrant::domain::SelectorKind;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    if let Ok(kind) = SelectorKind::new(input.as_ref()) {
        // as_str() must return a non-empty string
        assert!(!kind.as_str().is_empty());
        // same_kind() must be reflexive
        assert!(kind.same_kind(&kind));
    }
});
