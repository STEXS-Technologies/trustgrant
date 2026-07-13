#![no_main]
use libfuzzer_sys::fuzz_target;

use chrono::{TimeZone, Utc};

use trustgrant::{
    AuthorityDiscoverySource, AuthorityId, AuthorityKeyRecord, KeyId, OwnershipTransitionVerifier,
    RawOwnershipTransitionDocument, ResolvedSignerBinding, SignatureProfile,
    SignatureVerificationRequest, SignatureVerifier, TrustGrantError, ValidatedPrincipal,
    VerificationContext, VerificationPosture,
};

struct FuzzSignatureVerifier;

impl SignatureVerifier for FuzzSignatureVerifier {
    fn verify_signature(
        &self,
        _request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), TrustGrantError> {
        // Accept every signature during fuzzing — we are looking for panics,
        // not semantic correctness.
        Ok(())
    }
}

struct FuzzDiscoverySource;

impl AuthorityDiscoverySource for FuzzDiscoverySource {
    fn resolve_signer_binding(
        &self,
        issuer_authority: &AuthorityId,
        key_id: &KeyId,
        issuer_principal: Option<&ValidatedPrincipal>,
        _context: VerificationContext,
    ) -> Result<ResolvedSignerBinding, TrustGrantError> {
        if issuer_principal.is_some() {
            return Err(TrustGrantError::IssuerPrincipalMismatch);
        }

        // Use a wide validity window that covers any reasonable timestamp.
        let key_record = AuthorityKeyRecord::new(
            key_id.as_str().to_owned(),
            "ed25519",
            "public-key-material",
            fixed_timestamp(2020, 1, 1, 0, 0, 0),
            fixed_timestamp(2030, 1, 1, 0, 0, 0),
        )?;
        let signature_profile = SignatureProfile::new("jcs+ed25519", "RFC8785")?;

        Ok(ResolvedSignerBinding::new(
            issuer_authority.clone(),
            key_record,
            signature_profile,
            None,
        ))
    }
}

fn fixed_timestamp(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
        .single()
        .expect("fixed timestamp should be valid")
}

fuzz_target!(|data: &[u8]| {
    // Parse raw document from fuzzer bytes.
    let Ok(raw) = RawOwnershipTransitionDocument::parse_json_bytes(data) else {
        return;
    };

    // Basic parse invariants (same as fuzz_ownership_transition_parse.rs).
    assert!(!raw.transition_id.is_empty());
    assert!(!raw.origin_authority.is_empty());
    assert!(!raw.from_authority.is_empty());
    assert!(!raw.to_authority.is_empty());
    // from and to must differ
    assert_ne!(raw.from_authority, raw.to_authority);

    // Run full verification pipeline.
    let verifier = OwnershipTransitionVerifier::new();
    let context = VerificationContext::new(
        fixed_timestamp(2026, 4, 7, 12, 30, 0),
        VerificationPosture::Online,
    );

    let result =
        verifier.verify_json_bytes(data, &FuzzSignatureVerifier, &FuzzDiscoverySource, context);

    // On success, check basic invariants of the verified output.
    if let Ok(verified) = result {
        let document = verified.document();
        let record = verified.record();
        let metadata = verified.metadata();

        // Transition id must match between document and record lineage.
        assert_eq!(
            document.lineage().transition_id(),
            record.lineage().transition_id(),
        );

        // Metadata verified_at must match the context timestamp.
        assert_eq!(
            metadata.verified_at(),
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
        );
    }
});
