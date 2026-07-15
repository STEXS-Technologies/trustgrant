#![no_main]
use libfuzzer_sys::fuzz_target;

use chrono::{TimeZone, Utc};
use std::collections::BTreeMap;

use trustgrant::{
    TrustGrantDraft, TrustGrantDraftAuthorities, document::raw::{
        RawCapabilities, RawResourceScope, RawScope,
    },
};

// Fuzz the TrustGrantDraft builder and serialization paths.
//
// Constructs drafts from raw-parsed components and exercises all builder
// methods to ensure none panic on valid or invalid inputs.
fuzz_target!(|data: &[u8]| {
    let json_str = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Extract a candidate authority string from the data. Use the first
    // non-empty line or a default.
    let authority_str = json_str
        .lines()
        .find(|l| !l.is_empty() && l.len() < 256)
        .unwrap_or("https://fuzz.example.com");

    // 1. Try constructing authorities
    if let Ok(authorities) = TrustGrantDraftAuthorities::self_owned(authority_str) {
        // 2. Draft construction with default scope (all = true)
        if let Ok(draft) = TrustGrantDraft::new(
            authorities,
            "fuzz-key",
            RawScope::all(),
            RawCapabilities::new(true, false),
            RawResourceScope::new(BTreeMap::new()),
            Utc.with_ymd_and_hms(2026, 6, 15, 12, 0, 0)
                .single()
                .unwrap_or(Utc::now()),
        ) {
            // 3. Call builder methods — these should never panic
            let draft = draft.with_default_audience_scope(Vec::new());

            if let Ok(draft) = draft.with_lineage(
                trustgrant::GrantSeriesId::generate(),
                trustgrant::GrantRevision::new(1).unwrap(),
                None,
                trustgrant::SupersessionPolicy::Coexist,
            ) {
                // 4. Serialize to signable document
                if let Ok(signable) = draft.signable_document() {
                    // Invariant: signable document has empty signature
                    assert!(signable.signature.is_empty());
                }

                // 5. Serialize canonical bytes
                let _ = draft.canonical_bytes();

                // 6. Produce signed document
                let _ = draft.into_signed_document("fuzz-signature");
            }
        }
    }
});
