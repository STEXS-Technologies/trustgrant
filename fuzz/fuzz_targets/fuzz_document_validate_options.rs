#![no_main]
use libfuzzer_sys::fuzz_target;
use trustgrant::document::{RawTrustGrantDocument, ValidatedTrustGrantDocument, raw::RawPrincipal};

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = RawTrustGrantDocument::parse_json_bytes(data) else {
        return;
    };

    // Test ValidatedTrustGrantDocument::try_from with all optional fields
    // (revocation, issuer_principal, default_audience_scope, global_constraints,
    //  interoperability_profile) — must never panic
    if let Ok(validated) = ValidatedTrustGrantDocument::try_from(raw.clone()) {
        // Basic invariants on validated document
        assert!(validated.target_scope().all() || !validated.target_scope().allow().is_empty());
    }

    // Also test ValidatedPrincipal::try_from if issuer_principal exists
    if let Some(principal) = raw.issuer_principal {
        let raw_principal = RawPrincipal {
            kind: principal.kind.clone(),
            id: principal.id.clone(),
        };
        // Must never panic — Result is fine
        let _ = trustgrant::ValidatedPrincipal::try_from(raw_principal);
    }
});
