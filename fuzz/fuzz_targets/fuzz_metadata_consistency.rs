#![no_main]
use chrono::{Duration, Utc};
use libfuzzer_sys::fuzz_target;
use trustgrant::{
    AuthorityId, AuthorityKeyRecord, DelegatedPrincipalRef, OwnershipProofKind,
    OwnershipVerificationRecord, ProofFinality, ResolvedSignerBinding, RevocationRecord,
    RevocationSourceKind, RevocationStatus, SignatureProfile, ValidatedTrustGrantDocument,
    VerificationMetadata, VerificationPosture, VerifiedRevocationState,
    document::RawTrustGrantDocument,
    verify::{CanonicalizationProfile, ensure_metadata_matches_document},
};

fuzz_target!(|data: &[u8]| {
    // Step 1: Parse and validate a document from fuzzer bytes.
    let Ok(raw) = RawTrustGrantDocument::parse_json_bytes(data) else {
        return;
    };
    let Ok(validated) = ValidatedTrustGrantDocument::try_from(raw.clone()) else {
        return;
    };

    // Step 2: Build verification metadata from the document's own fields.
    let now = Utc::now();

    let issuer_authority = match AuthorityId::new(raw.issuer_authority.as_str()) {
        Ok(a) => a,
        Err(_) => return,
    };

    let not_after = match raw.issued_at.checked_add_signed(Duration::days(365)) {
        Some(t) => t,
        None => return,
    };

    let key_record = match AuthorityKeyRecord::new(
        raw.key_id.as_str(),
        "ed25519",
        "base64-fuzz-public-key",
        raw.issued_at,
        not_after,
    ) {
        Ok(k) => k,
        Err(_) => return,
    };

    let signature_profile = match SignatureProfile::new("jcs+ed25519", "RFC8785") {
        Ok(p) => p,
        Err(_) => return,
    };

    let delegated_principal = match raw.issuer_principal.as_ref() {
        Some(principal) => {
            match DelegatedPrincipalRef::new(principal.kind.as_str(), principal.id.as_str()) {
                Ok(p) => Some(p),
                Err(_) => return,
            }
        }
        None => None,
    };

    let signer_binding = ResolvedSignerBinding::new(
        issuer_authority,
        key_record,
        signature_profile,
        delegated_principal,
    );

    let origin_authority = match AuthorityId::new(raw.origin_authority.as_str()) {
        Ok(a) => a,
        Err(_) => return,
    };
    let active_owning_authority = match AuthorityId::new(raw.active_owning_authority.as_str()) {
        Ok(a) => a,
        Err(_) => return,
    };

    let ownership = OwnershipVerificationRecord::new(
        origin_authority,
        active_owning_authority,
        now,
        OwnershipProofKind::StaticOwner,
        None,
    );

    let revocation = if raw.revocation.as_ref().is_some_and(|r| r.revocable) {
        let expires_at = match now.checked_add_signed(Duration::minutes(5)) {
            Some(t) => t,
            None => return,
        };
        match RevocationRecord::new(
            RevocationStatus::Active,
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            now,
            expires_at,
        ) {
            Ok(record) => VerifiedRevocationState::Checked(record),
            Err(_) => return,
        }
    } else {
        VerifiedRevocationState::NonRevocable
    };

    let metadata = VerificationMetadata::new(
        now,
        VerificationPosture::Online,
        signer_binding,
        ownership,
        revocation,
    );

    // Step 3: Call ensure_metadata_matches_document — must never panic.
    let _result =
        ensure_metadata_matches_document(&metadata, &validated, CanonicalizationProfile::Rfc8785);
    // Both Ok and Err are valid; the point is no panics.
});
