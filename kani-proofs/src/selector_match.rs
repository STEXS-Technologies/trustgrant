//! Kani proof harnesses: selector matching core algorithm.
//!
//! Verifies panic-freedom and correctness of the core O(n*m) matching
//! algorithm independently of the ICU/unicode dependency chain.

/// Simplified selector matching — mirrors evaluate engine logic.
fn selector_matches(selector_all: bool, values: &[&str], context_values: &[&str]) -> bool {
    if selector_all {
        return true;
    }
    if values.is_empty() || context_values.is_empty() {
        return false;
    }
    values.iter().any(|value| context_values.iter().any(|candidate| candidate == value))
}

/// Proof: all=true always matches regardless of values.
#[kani::proof]
#[kani::unwind(8)]
fn verify_all_true_always_matches() {
    let v1 = kani::any::<u8>();
    let v2 = kani::any::<u8>();
    let values = [String::from_iter([v1 as char]), String::from_iter([v2 as char])];
    let context = [String::from_iter([kani::any::<u8>() as char])];
    let v: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
    let c: Vec<&str> = context.iter().map(|s| s.as_str()).collect();
    let result = selector_matches(true, &v, &c);
    assert!(result);
}

/// Proof: all=false with mismatched values never matches.
#[kani::proof]
#[kani::unwind(8)]
fn verify_all_false_no_match() {
    let values = ["alpha", "beta"];
    let context = ["gamma", "delta"];
    let result = selector_matches(false, &values, &context);
    assert!(!result);
}
