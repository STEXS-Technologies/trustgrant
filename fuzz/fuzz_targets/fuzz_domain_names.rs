#![no_main]
use libfuzzer_sys::fuzz_target;
use trustgrant::{
    AlgorithmName, CanonicalizationName, KeyId, OperationName, PrincipalId, PrincipalKind,
    ResourceTypeName,
};

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let s = input.as_ref();

    // Test each domain name validator — none must panic
    if let Ok(name) = OperationName::new(s) {
        let display = name.as_str();
        assert!(!display.is_empty());
    }
    if let Ok(name) = ResourceTypeName::new(s) {
        let display = name.as_str();
        assert!(!display.is_empty());
    }
    if let Ok(name) = PrincipalId::new(s) {
        let display = name.as_str();
        assert!(!display.is_empty());
    }
    if let Ok(name) = PrincipalKind::new(s) {
        let display = name.as_str();
        assert!(!display.is_empty());
    }
    if let Ok(name) = KeyId::new(s) {
        let display = name.as_str();
        assert!(!display.is_empty());
    }
    if let Ok(name) = AlgorithmName::new(s) {
        let display = name.as_str();
        assert!(!display.is_empty());
    }
    if let Ok(name) = CanonicalizationName::new(s) {
        let display = name.as_str();
        assert!(!display.is_empty());
    }
});
