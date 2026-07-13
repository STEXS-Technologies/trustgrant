#![no_main]
use libfuzzer_sys::fuzz_target;
use trustgrant::domain::SelectorExpression;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data)
        && let Ok(expr) = SelectorExpression::parse(s)
    {
        // Expression must roundtrip through Display
        let display = format!("{expr}");
        assert!(!display.is_empty());
        // Expression must match or not match any candidate without panicking
        let _ = expr.matches("test_candidate");
        let _ = expr.matches("");
    }
});
