#![no_main]
use libfuzzer_sys::fuzz_target;
use trustgrant::SelectorContext;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let s = input.as_ref();

    let mut ctx = SelectorContext::new();

    // Try to insert various kind/value combinations
    // Use chunks of the input to derive kind and value
    let chunks: Vec<&str> = s.split('\0').collect();

    for chunk in chunks.iter() {
        if chunk.is_empty() {
            continue;
        }
        // Find a safe char boundary for splitting
        let mid = chunk.len() / 2;
        let safe_mid = chunk.floor_char_boundary(mid);

        let kind_str = if safe_mid > 0 && safe_mid < chunk.len() {
            &chunk[..safe_mid]
        } else {
            chunk
        };
        let value_str = if safe_mid > 0 && safe_mid < chunk.len() {
            &chunk[safe_mid..]
        } else {
            "fuzz-value"
        };

        // insert must never panic — Result is fine
        let _ = ctx.insert(kind_str, value_str);

        // Insert the same kind/value again — deduplication must not panic
        let _ = ctx.insert(kind_str, value_str);
    }
});
