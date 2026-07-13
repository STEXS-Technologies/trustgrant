#![no_main]
use libfuzzer_sys::fuzz_target;

use chrono::Utc;

use trustgrant::{
    AuthorityId, AuthorityKeyRecord, DelegatedPrincipalRef, OwnershipProofKind,
    OwnershipVerificationRecord, ProofFinality, ResolvedSignerBinding, RevocationRecord,
    RevocationSourceKind, RevocationStatus, SignatureProfile, SignatureVerificationRequest,
    SignatureVerifier, TrustGrantError, VerificationMetadata, VerificationPipeline,
    VerificationPosture, VerifiedRevocationState, document::RawTrustGrantDocument,
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

fn build_metadata(doc: &RawTrustGrantDocument) -> Result<VerificationMetadata, TrustGrantError> {
    let now = Utc::now();

    let issuer_authority = AuthorityId::new(doc.issuer_authority.as_str())?;

    let key_record = AuthorityKeyRecord::new(
        doc.key_id.as_str(),
        "ed25519",
        "base64-fuzz-public-key",
        doc.issued_at,
        // Ensure not_after is strictly greater than not_before.
        doc.issued_at
            .checked_add_signed(chrono::Duration::days(365))
            .ok_or(TrustGrantError::InvalidKeyValidityWindow)?,
    )?;

    let signature_profile = SignatureProfile::new("jcs+ed25519", "RFC8785")?;

    let delegated_principal = match doc.issuer_principal.as_ref() {
        Some(principal) => Some(DelegatedPrincipalRef::new(
            principal.kind.as_str(),
            principal.id.as_str(),
        )?),
        None => None,
    };

    let signer_binding = ResolvedSignerBinding::new(
        issuer_authority,
        key_record,
        signature_profile,
        delegated_principal,
    );

    let origin_authority = AuthorityId::new(doc.origin_authority.as_str())?;
    let active_owning_authority = AuthorityId::new(doc.active_owning_authority.as_str())?;

    let ownership = OwnershipVerificationRecord::new(
        origin_authority,
        active_owning_authority,
        now,
        OwnershipProofKind::StaticOwner,
        None,
    );

    let revocation = if doc
        .revocation
        .as_ref()
        .is_some_and(|revocation| revocation.revocable)
    {
        VerifiedRevocationState::Checked(RevocationRecord::new(
            RevocationStatus::Active,
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            now,
            now,
        )?)
    } else {
        VerifiedRevocationState::NonRevocable
    };

    Ok(VerificationMetadata::new(
        now,
        VerificationPosture::Online,
        signer_binding,
        ownership,
        revocation,
    ))
}

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = RawTrustGrantDocument::parse_json_bytes(data) else {
        return;
    };

    let Ok(metadata) = build_metadata(&raw) else {
        return;
    };

    let pipeline = VerificationPipeline::new();
    let verifier = FuzzSignatureVerifier;

    let result = pipeline.verify_json_bytes(data, &verifier, metadata);

    if let Ok(artifacts) = result {
        let grant_id = artifacts
            .verified_grant()
            .lineage()
            .trustgrant_id()
            .to_string();
        assert!(!grant_id.is_empty(), "trustgrant_id must not be empty");
        assert_eq!(
            grant_id, raw.trustgrant_id,
            "trustgrant_id must match input"
        );
    }
});
