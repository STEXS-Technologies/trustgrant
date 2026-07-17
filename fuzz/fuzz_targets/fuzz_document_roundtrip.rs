#![no_main]
use libfuzzer_sys::fuzz_target;
use trustgrant::document::RawTrustGrantDocument;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data)
        && let Ok(raw) = RawTrustGrantDocument::parse_json_str(s)
    {
        // Serialize back to JSON string
        if let Ok(json_str) = raw.to_json_string() {
            // Re-parse the serialized output
            if let Ok(reparsed) = RawTrustGrantDocument::parse_json_str(&json_str) {
                // Roundtrip: the re-parsed document must match the original
                assert_eq!(raw.trustgrant_id, reparsed.trustgrant_id);
                assert_eq!(raw.issuer_authority, reparsed.issuer_authority);
                assert_eq!(raw.key_id, reparsed.key_id);
                assert_eq!(raw.origin_authority, reparsed.origin_authority);
                assert_eq!(
                    raw.active_owning_authority,
                    reparsed.active_owning_authority
                );
            }
            // Serialized output must be valid JSON
            let _: Result<serde_json::Value, _> = serde_json::from_str(&json_str);
        }
    }
});
