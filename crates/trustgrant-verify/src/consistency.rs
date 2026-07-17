use trustgrant_document::ValidatedTrustGrantDocument;
use trustgrant_domain::CanonicalizationProfile;
use trustgrant_error::TrustGrantError;
use trustgrant_revocation::VerifiedRevocationState;

use super::policy::VerificationPolicy;
use super::{VerificationMetadata, VerificationPosture, VerifiedTrustGrant};

/// Verifies that verification metadata is consistent with the validated document.
///
/// # Errors
///
/// Returns [`TrustGrantError::SignerAuthorityMismatch`] if the signer's issuer
/// authority does not match the document.
///
/// Returns [`TrustGrantError::KeyIdMismatch`] if the key IDs differ.
///
/// Returns [`TrustGrantError::SignatureProfileMismatch`] if the signature
/// profile's canonicalization name does not match the expected profile.
///
/// Returns [`TrustGrantError::SignerKeyInactive`] if the key record is not
/// active at the verification timestamp.
///
/// Returns [`TrustGrantError::IssuerPrincipalMismatch`] if the delegated
/// principal binding does not match the document's issuer principal.
///
/// Returns [`TrustGrantError::OwnershipOriginMismatch`] if the ownership
/// origin authority differs.
///
/// Returns [`TrustGrantError::ActiveOwningAuthorityMismatch`] if the active
/// owning authority differs.
pub fn ensure_metadata_matches_document(
    metadata: &VerificationMetadata,
    validated_document: &ValidatedTrustGrantDocument,
    canonical_profile: CanonicalizationProfile,
) -> Result<(), TrustGrantError> {
    let signer_binding = metadata.signer_binding();

    if signer_binding.issuer_authority() != validated_document.issuer_authority() {
        return Err(TrustGrantError::SignerAuthorityMismatch);
    }

    if signer_binding.key_record().key_id() != validated_document.key_id() {
        return Err(TrustGrantError::KeyIdMismatch);
    }

    if signer_binding
        .signature_profile()
        .canonicalization()
        .as_str()
        != canonical_profile.discovery_name()
    {
        return Err(TrustGrantError::SignatureProfileMismatch);
    }

    if !signer_binding
        .key_record()
        .is_active_at(metadata.verified_at())
    {
        return Err(TrustGrantError::SignerKeyInactive);
    }

    match (
        signer_binding.delegated_principal(),
        validated_document.issuer_principal(),
    ) {
        (None, None) => {}
        (Some(binding_principal), Some(document_principal))
            if binding_principal.kind() == document_principal.kind()
                && binding_principal.id() == document_principal.id() => {}
        _ => return Err(TrustGrantError::IssuerPrincipalMismatch),
    }

    if metadata.ownership().origin_authority()
        != validated_document
            .ownership_authority_state()
            .origin_authority()
    {
        return Err(TrustGrantError::OwnershipOriginMismatch);
    }

    if metadata.ownership().active_owning_authority()
        != validated_document
            .ownership_authority_state()
            .active_owning_authority()
    {
        return Err(TrustGrantError::ActiveOwningAuthorityMismatch);
    }

    Ok(())
}

pub(crate) fn ensure_verified_grant_consistent(
    verified_grant: &VerifiedTrustGrant,
    canonical_profile: CanonicalizationProfile,
) -> Result<(), TrustGrantError> {
    let validated_document = ValidatedTrustGrantDocument::try_from(
        verified_grant
            .document()
            .clone()
            .into_raw_document_for_consistency_check()?,
    )?;

    ensure_metadata_matches_document(
        verified_grant.metadata(),
        &validated_document,
        canonical_profile,
    )?;
    ensure_revocation_state_matches_document(verified_grant.metadata(), &validated_document)?;
    ensure_revocation_state_is_acceptable(verified_grant.metadata())?;

    Ok(())
}

pub(crate) fn ensure_revocation_state_matches_document(
    metadata: &VerificationMetadata,
    validated_document: &ValidatedTrustGrantDocument,
) -> Result<(), TrustGrantError> {
    match (
        requires_revocation_check(validated_document),
        metadata.revocation(),
    ) {
        (true, VerifiedRevocationState::NonRevocable) => {
            Err(TrustGrantError::MissingRevocationProof)
        }
        (false, VerifiedRevocationState::Checked(_)) => {
            Err(TrustGrantError::UnexpectedRevocationProofForNonRevocableGrant)
        }
        _ => Ok(()),
    }
}

pub(crate) fn ensure_revocation_state_is_acceptable(
    metadata: &VerificationMetadata,
) -> Result<(), TrustGrantError> {
    let Some(record) = metadata.revocation().checked_record() else {
        return Ok(());
    };

    if !record.is_fresh_at(metadata.verified_at()) {
        return Err(TrustGrantError::StaleRevocationRecord);
    }

    let policy = VerificationPolicy::for_posture(metadata.posture());

    if policy.requires_non_live_revocation_source()
        && !policy.accepts_revocation_source_kind(record.source_kind())
    {
        return Err(TrustGrantError::VerificationPostureRequiresNonLiveRevocation);
    }

    if !policy.accepts_revocation_finality(record.finality()) {
        return Err(TrustGrantError::InsufficientRevocationProofFinality);
    }

    Ok(())
}

fn requires_revocation_check(document: &ValidatedTrustGrantDocument) -> bool {
    document
        .revocation()
        .is_some_and(|revocation| revocation.revocable())
}

pub(crate) const fn canonical_profile_for_rehydrate(
    _posture: VerificationPosture,
) -> CanonicalizationProfile {
    CanonicalizationProfile::Rfc8785
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::super::verified_grant::{
        NormalizedTrustGrantDocument, NormalizedTrustGrantDocumentParts, VerificationMetadata,
    };
    use super::{ensure_metadata_matches_document, ensure_revocation_state_matches_document};
    use chrono::{TimeZone, Utc};
    use trustgrant_discovery::{
        AuthorityKeyRecord, DelegatedPrincipalRef, ResolvedSignerBinding, SignatureProfile,
    };
    use trustgrant_document::{RawTrustGrantDocument, ValidatedTrustGrantDocument};
    use trustgrant_domain::{
        AuthorityId, CanonicalizationProfile, OwnershipProofKind, OwnershipVerificationRecord,
    };
    use trustgrant_error::TrustGrantError;
    use trustgrant_ports::VerificationPosture;
    use trustgrant_revocation::{
        ProofFinality, RevocationRecord, RevocationSourceKind, RevocationStatus,
        VerifiedRevocationState,
    };

    /// Round-trip a `RawTrustGrantDocument` through validation → normalization
    /// → raw rehydration → re-validation and return both validated documents.
    fn round_trip(
        raw: &RawTrustGrantDocument,
    ) -> (ValidatedTrustGrantDocument, ValidatedTrustGrantDocument) {
        let validated_first = ValidatedTrustGrantDocument::try_from(raw.clone())
            .unwrap_or_else(|error| panic!("first validation should succeed: {error}"));

        let normalized: NormalizedTrustGrantDocument = validated_first.clone().into();

        let rehydrated_raw = normalized
            .into_raw_document_for_consistency_check()
            .unwrap_or_else(|error| panic!("rehydration should succeed: {error}"));

        let validated_second = ValidatedTrustGrantDocument::try_from(rehydrated_raw)
            .unwrap_or_else(|error| panic!("second validation should succeed: {error}"));

        (validated_first, validated_second)
    }

    // ── minimal document ──────────────────────────────────────────────

    #[test]
    fn round_trip_minimal_document_preserves_all_fields() {
        let json = r#"{
            "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
            "version":0,
            "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
            "revision":1,
            "supersedes":null,
            "supersession_policy":"coexist",
            "issuer_authority":"https://issuer.example.com",
            "origin_authority":"https://issuer.example.com",
            "active_owning_authority":"https://issuer.example.com",
            "key_id":"root-key-1",
            "target_scope":{"all":true,"allow":null,"deny":null},
            "capabilities":{"recognize":true,"mint":false},
            "default_audience_scope":null,
            "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
            "global_constraints":null,
            "revocation":null,
            "issued_at":"2026-04-07T12:00:00Z",
            "signature":"rehydrated-signature",
            "issuer_principal":null
        }"#;
        let raw = RawTrustGrantDocument::parse_json_str(json)
            .unwrap_or_else(|error| panic!("raw document should parse: {error}"));

        let (first, second) = round_trip(&raw);
        assert_eq!(first, second, "minimal document round-trip should be equal");
    }

    // ── document with audience scope ──────────────────────────────────

    #[test]
    fn round_trip_audience_scope_preserves_all_fields() {
        let json = r#"{
            "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
            "version":0,
            "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
            "revision":1,
            "supersedes":null,
            "supersession_policy":"coexist",
            "issuer_authority":"https://issuer.example.com",
            "origin_authority":"https://issuer.example.com",
            "active_owning_authority":"https://issuer.example.com",
            "key_id":"root-key-1",
            "target_scope":{"all":false,"allow":[{"kind":"authority","all":false,"values":["https://target.example.com"],"expressions":null}],"deny":null},
            "capabilities":{"recognize":true,"mint":true},
            "default_audience_scope":[
                {"authority_id":"https://audience1.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":null},
                {"authority_id":"https://audience2.example.com","scope":{"all":false,"allow":[{"kind":"authority","all":false,"values":["https://specific.example.com"],"expressions":null}],"deny":null},"principal_scope":null}
            ],
            "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":[{"kind":"namespace","all":false,"values":["banned"],"expressions":null}],"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":100,"max_per_user":5},"audience_scope":null},"operations":{"all":false,"allow":["recognize","mint"],"deny":null}}}},
            "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-12-31T23:59:59Z"}},
            "revocation":null,
            "issued_at":"2026-04-07T12:00:00Z",
            "signature":"rehydrated-signature",
            "issuer_principal":null
        }"#;
        let raw = RawTrustGrantDocument::parse_json_str(json)
            .unwrap_or_else(|error| panic!("raw document should parse: {error}"));

        let (first, second) = round_trip(&raw);
        assert_eq!(
            first, second,
            "audience-scope document round-trip should be equal"
        );
    }

    // ── document with revocation ──────────────────────────────────────

    #[test]
    fn round_trip_revocation_preserves_all_fields() {
        let json = r#"{
            "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
            "version":0,
            "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
            "revision":1,
            "supersedes":null,
            "supersession_policy":"coexist",
            "issuer_authority":"https://issuer.example.com",
            "origin_authority":"https://issuer.example.com",
            "active_owning_authority":"https://issuer.example.com",
            "key_id":"root-key-1",
            "target_scope":{"all":false,"allow":[{"kind":"authority","all":false,"values":["https://target.example.com"],"expressions":null}],"deny":null},
            "capabilities":{"recognize":true,"mint":false},
            "default_audience_scope":null,
            "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
            "global_constraints":null,
            "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
            "issued_at":"2026-04-07T12:00:00Z",
            "signature":"rehydrated-signature",
            "issuer_principal":null
        }"#;
        let raw = RawTrustGrantDocument::parse_json_str(json)
            .unwrap_or_else(|error| panic!("raw document should parse: {error}"));

        let (first, second) = round_trip(&raw);
        assert_eq!(
            first, second,
            "revocation document round-trip should be equal"
        );
    }

    // ── document with issuer principal ────────────────────────────────

    #[test]
    fn round_trip_issuer_principal_preserves_all_fields() {
        let json = r#"{
            "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
            "version":0,
            "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
            "revision":1,
            "supersedes":null,
            "supersession_policy":"coexist",
            "issuer_authority":"https://issuer.example.com",
            "origin_authority":"https://issuer.example.com",
            "active_owning_authority":"https://issuer.example.com",
            "key_id":"root-key-1",
            "target_scope":{"all":false,"allow":[{"kind":"authority","all":false,"values":["https://target.example.com"],"expressions":null}],"deny":null},
            "capabilities":{"recognize":true,"mint":false},
            "default_audience_scope":null,
            "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
            "global_constraints":null,
            "revocation":null,
            "issued_at":"2026-04-07T12:00:00Z",
            "signature":"rehydrated-signature",
            "issuer_principal":{"kind":"service","id":"issuer-worker"}
        }"#;
        let raw = RawTrustGrantDocument::parse_json_str(json)
            .unwrap_or_else(|error| panic!("raw document should parse: {error}"));

        let (first, second) = round_trip(&raw);
        assert_eq!(
            first, second,
            "issuer-principal document round-trip should be equal"
        );
    }

    // ── full document with all optional fields ────────────────────────

    #[test]
    fn round_trip_full_document_preserves_all_fields() {
        let json = r#"{
            "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174002",
            "version":0,
            "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
            "revision":2,
            "supersedes":"tg_123e4567-e89b-12d3-a456-426614174000",
            "supersession_policy":"supersede_previous",
            "issuer_authority":"https://issuer.example.com",
            "origin_authority":"https://owner.example.com",
            "active_owning_authority":"https://owner.example.com",
            "key_id":"signing-key-42",
            "target_scope":{"all":false,"allow":[{"kind":"authority","all":false,"values":["https://a.example.com","https://b.example.com"],"expressions":null},{"kind":"namespace","all":true,"values":null,"expressions":null}],"deny":[{"kind":"authority","all":false,"values":["https://blocked.example.com"],"expressions":null}]},
            "capabilities":{"recognize":true,"mint":true},
            "default_audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":false,"allow":[{"kind":"authority","all":false,"values":["https://aud-target.example.com"],"expressions":null}],"deny":null},"principal_scope":null}],
            "resource_scope":{"types":{"credential":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["issued"],"expressions":null}],"deny":null,"capabilities":{"recognize":true,"mint":true},"constraints":{"minting":{"max_total":1000,"max_per_user":10},"audience_scope":null},"operations":{"all":false,"allow":["recognize","mint"],"deny":["revoke"]}},"badge":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
            "global_constraints":{"time":{"not_before":"2026-01-01T00:00:00Z","not_after":"2026-12-31T23:59:59Z"}},
            "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/v1/revoke","post_revocation_effect":"block_all"},
            "issued_at":"2026-06-15T09:30:00Z",
            "signature":"rehydrated-signature",
            "issuer_principal":{"kind":"service","id":"grant-issuer"}
        }"#;
        let raw = RawTrustGrantDocument::parse_json_str(json)
            .unwrap_or_else(|error| panic!("raw document should parse: {error}"));

        let (first, second) = round_trip(&raw);
        assert_eq!(first, second, "full document round-trip should be equal");
    }

    // ── rehydration doesn't corrupt specific fields ───────────────────

    #[test]
    fn rehydration_preserves_lineage_fields() {
        let json = r#"{
            "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174002",
            "version":0,
            "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
            "revision":3,
            "supersedes":"tg_123e4567-e89b-12d3-a456-426614174000",
            "supersession_policy":"supersede_previous",
            "issuer_authority":"https://issuer.example.com",
            "origin_authority":"https://issuer.example.com",
            "active_owning_authority":"https://issuer.example.com",
            "key_id":"root-key-1",
            "target_scope":{"all":true,"allow":null,"deny":null},
            "capabilities":{"recognize":true,"mint":false},
            "default_audience_scope":null,
            "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
            "global_constraints":null,
            "revocation":null,
            "issued_at":"2026-04-07T12:00:00Z",
            "signature":"rehydrated-signature",
            "issuer_principal":null
        }"#;
        let raw = RawTrustGrantDocument::parse_json_str(json)
            .unwrap_or_else(|error| panic!("raw document should parse: {error}"));
        let (first, second) = round_trip(&raw);

        assert_eq!(
            first.lineage().trustgrant_id(),
            second.lineage().trustgrant_id(),
            "trustgrant_id should survive round-trip"
        );
        assert_eq!(
            first.lineage().grant_series_id(),
            second.lineage().grant_series_id(),
            "grant_series_id should survive round-trip"
        );
        assert_eq!(
            first.lineage().revision(),
            second.lineage().revision(),
            "revision should survive round-trip"
        );
        assert_eq!(
            first.lineage().supersession_policy(),
            second.lineage().supersession_policy(),
            "supersession_policy should survive round-trip"
        );
    }

    #[test]
    fn rehydration_preserves_ownership_authority_fields() {
        let json = r#"{
            "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
            "version":0,
            "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
            "revision":1,
            "supersedes":null,
            "supersession_policy":"coexist",
            "issuer_authority":"https://issuer.example.com",
            "origin_authority":"https://owner.example.com",
            "active_owning_authority":"https://admin.example.com",
            "key_id":"root-key-1",
            "target_scope":{"all":true,"allow":null,"deny":null},
            "capabilities":{"recognize":true,"mint":false},
            "default_audience_scope":null,
            "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
            "global_constraints":null,
            "revocation":null,
            "issued_at":"2026-04-07T12:00:00Z",
            "signature":"rehydrated-signature",
            "issuer_principal":null
        }"#;
        let raw = RawTrustGrantDocument::parse_json_str(json)
            .unwrap_or_else(|error| panic!("raw document should parse: {error}"));
        let (first, second) = round_trip(&raw);

        assert_eq!(
            first.issuer_authority(),
            second.issuer_authority(),
            "issuer_authority should survive round-trip"
        );
        assert_eq!(
            first.ownership_authority_state().origin_authority(),
            second.ownership_authority_state().origin_authority(),
            "origin_authority should survive round-trip"
        );
        assert_eq!(
            first.ownership_authority_state().active_owning_authority(),
            second.ownership_authority_state().active_owning_authority(),
            "active_owning_authority should survive round-trip"
        );
    }

    #[test]
    fn rehydration_preserves_key_id() {
        let json = r#"{
            "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
            "version":0,
            "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
            "revision":1,
            "supersedes":null,
            "supersession_policy":"coexist",
            "issuer_authority":"https://issuer.example.com",
            "origin_authority":"https://issuer.example.com",
            "active_owning_authority":"https://issuer.example.com",
            "key_id":"signing-key-42",
            "target_scope":{"all":true,"allow":null,"deny":null},
            "capabilities":{"recognize":true,"mint":false},
            "default_audience_scope":null,
            "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
            "global_constraints":null,
            "revocation":null,
            "issued_at":"2026-04-07T12:00:00Z",
            "signature":"rehydrated-signature",
            "issuer_principal":null
        }"#;
        let raw = RawTrustGrantDocument::parse_json_str(json)
            .unwrap_or_else(|error| panic!("raw document should parse: {error}"));
        let (first, second) = round_trip(&raw);

        assert_eq!(
            first.key_id(),
            second.key_id(),
            "key_id should survive round-trip"
        );
    }

    #[test]
    fn rehydration_preserves_target_scope_selectors() {
        let json = r#"{
            "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
            "version":0,
            "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
            "revision":1,
            "supersedes":null,
            "supersession_policy":"coexist",
            "issuer_authority":"https://issuer.example.com",
            "origin_authority":"https://issuer.example.com",
            "active_owning_authority":"https://issuer.example.com",
            "key_id":"root-key-1",
            "target_scope":{"all":false,"allow":[{"kind":"authority","all":false,"values":["https://a.example.com","https://b.example.com"],"expressions":null},{"kind":"namespace","all":true,"values":null,"expressions":null}],"deny":[{"kind":"authority","all":false,"values":["https://blocked.example.com"],"expressions":null}]},
            "capabilities":{"recognize":true,"mint":false},
            "default_audience_scope":null,
            "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
            "global_constraints":null,
            "revocation":null,
            "issued_at":"2026-04-07T12:00:00Z",
            "signature":"rehydrated-signature",
            "issuer_principal":null
        }"#;
        let raw = RawTrustGrantDocument::parse_json_str(json)
            .unwrap_or_else(|error| panic!("raw document should parse: {error}"));
        let (first, second) = round_trip(&raw);

        assert_eq!(
            first.target_scope().all(),
            second.target_scope().all(),
            "target_scope.all should survive round-trip"
        );
        assert_eq!(
            first.target_scope().allow().len(),
            second.target_scope().allow().len(),
            "target_scope allow count should survive round-trip"
        );
        for (i, (a, b)) in first
            .target_scope()
            .allow()
            .iter()
            .zip(second.target_scope().allow().iter())
            .enumerate()
        {
            assert_eq!(
                a.kind(),
                b.kind(),
                "target_scope allow[{i}] kind should survive round-trip"
            );
            assert_eq!(
                a.all(),
                b.all(),
                "target_scope allow[{i}] all should survive round-trip"
            );
            assert_eq!(
                a.values(),
                b.values(),
                "target_scope allow[{i}] values should survive round-trip"
            );
        }
        assert_eq!(
            first.target_scope().deny().len(),
            second.target_scope().deny().len(),
            "target_scope deny count should survive round-trip"
        );
        for (i, (a, b)) in first
            .target_scope()
            .deny()
            .iter()
            .zip(second.target_scope().deny().iter())
            .enumerate()
        {
            assert_eq!(
                a.kind(),
                b.kind(),
                "target_scope deny[{i}] kind should survive round-trip"
            );
            assert_eq!(
                a.values(),
                b.values(),
                "target_scope deny[{i}] values should survive round-trip"
            );
        }
    }

    #[test]
    fn rehydration_preserves_capabilities() {
        let json = r#"{
            "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
            "version":0,
            "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
            "revision":1,
            "supersedes":null,
            "supersession_policy":"coexist",
            "issuer_authority":"https://issuer.example.com",
            "origin_authority":"https://issuer.example.com",
            "active_owning_authority":"https://issuer.example.com",
            "key_id":"root-key-1",
            "target_scope":{"all":true,"allow":null,"deny":null},
            "capabilities":{"recognize":true,"mint":true},
            "default_audience_scope":null,
            "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
            "global_constraints":null,
            "revocation":null,
            "issued_at":"2026-04-07T12:00:00Z",
            "signature":"rehydrated-signature",
            "issuer_principal":null
        }"#;
        let raw = RawTrustGrantDocument::parse_json_str(json)
            .unwrap_or_else(|error| panic!("raw document should parse: {error}"));
        let (first, second) = round_trip(&raw);

        assert_eq!(
            first.capabilities().recognize(),
            second.capabilities().recognize(),
            "recognize capability should survive round-trip"
        );
        assert_eq!(
            first.capabilities().mint(),
            second.capabilities().mint(),
            "mint capability should survive round-trip"
        );
    }

    #[test]
    fn rehydration_preserves_revocation_policy() {
        let json = r#"{
            "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
            "version":0,
            "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
            "revision":1,
            "supersedes":null,
            "supersession_policy":"coexist",
            "issuer_authority":"https://issuer.example.com",
            "origin_authority":"https://issuer.example.com",
            "active_owning_authority":"https://issuer.example.com",
            "key_id":"root-key-1",
            "target_scope":{"all":true,"allow":null,"deny":null},
            "capabilities":{"recognize":true,"mint":false},
            "default_audience_scope":null,
            "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
            "global_constraints":null,
            "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/v1/revoke","post_revocation_effect":"block_all"},
            "issued_at":"2026-04-07T12:00:00Z",
            "signature":"rehydrated-signature",
            "issuer_principal":null
        }"#;
        let raw = RawTrustGrantDocument::parse_json_str(json)
            .unwrap_or_else(|error| panic!("raw document should parse: {error}"));
        let (first, second) = round_trip(&raw);

        assert_eq!(
            first.revocation().map(|r| r.revocable()),
            second.revocation().map(|r| r.revocable()),
            "revocable flag should survive round-trip"
        );
        assert_eq!(
            first.revocation().map(|r| r.revocation_endpoint()),
            second.revocation().map(|r| r.revocation_endpoint()),
            "revocation_endpoint should survive round-trip"
        );
    }

    #[test]
    fn rehydration_preserves_issuer_principal() {
        let json = r#"{
            "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
            "version":0,
            "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
            "revision":1,
            "supersedes":null,
            "supersession_policy":"coexist",
            "issuer_authority":"https://issuer.example.com",
            "origin_authority":"https://issuer.example.com",
            "active_owning_authority":"https://issuer.example.com",
            "key_id":"root-key-1",
            "target_scope":{"all":true,"allow":null,"deny":null},
            "capabilities":{"recognize":true,"mint":false},
            "default_audience_scope":null,
            "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
            "global_constraints":null,
            "revocation":null,
            "issued_at":"2026-04-07T12:00:00Z",
            "signature":"rehydrated-signature",
            "issuer_principal":{"kind":"service","id":"issuer-worker"}
        }"#;
        let raw = RawTrustGrantDocument::parse_json_str(json)
            .unwrap_or_else(|error| panic!("raw document should parse: {error}"));
        let (first, second) = round_trip(&raw);

        assert_eq!(
            first.issuer_principal().map(|p| p.kind().as_str()),
            second.issuer_principal().map(|p| p.kind().as_str()),
            "issuer_principal kind should survive round-trip"
        );
        assert_eq!(
            first.issuer_principal().map(|p| p.id().as_str()),
            second.issuer_principal().map(|p| p.id().as_str()),
            "issuer_principal id should survive round-trip"
        );
    }

    // ── rehydration fails for ExplicitRevocationRequired ──────────────

    // ── ensure_metadata_matches_document error-path tests ──────────

    const MATCHING_DOC_JSON: &str = r#"{
        "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
        "version":0,
        "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
        "revision":1,
        "supersedes":null,
        "supersession_policy":"coexist",
        "issuer_authority":"https://issuer.example.com",
        "origin_authority":"https://issuer.example.com",
        "active_owning_authority":"https://issuer.example.com",
        "key_id":"root-key-1",
        "target_scope":{"all":true,"allow":null,"deny":null},
        "capabilities":{"recognize":true,"mint":false},
        "default_audience_scope":null,
        "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
        "global_constraints":null,
        "revocation":null,
        "issued_at":"2026-04-07T12:00:00Z",
        "signature":"base64-signature",
        "issuer_principal":null
    }"#;

    const MATCHING_DOC_WITH_PRINCIPAL_JSON: &str = r#"{
        "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
        "version":0,
        "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
        "revision":1,
        "supersedes":null,
        "supersession_policy":"coexist",
        "issuer_authority":"https://issuer.example.com",
        "origin_authority":"https://issuer.example.com",
        "active_owning_authority":"https://issuer.example.com",
        "key_id":"root-key-1",
        "target_scope":{"all":true,"allow":null,"deny":null},
        "capabilities":{"recognize":true,"mint":false},
        "default_audience_scope":null,
        "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
        "global_constraints":null,
        "revocation":null,
        "issued_at":"2026-04-07T12:00:00Z",
        "signature":"base64-signature",
        "issuer_principal":{"kind":"service","id":"issuer-worker"}
    }"#;

    const REVOCABLE_DOC_JSON: &str = r#"{
        "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
        "version":0,
        "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
        "revision":1,
        "supersedes":null,
        "supersession_policy":"coexist",
        "issuer_authority":"https://issuer.example.com",
        "origin_authority":"https://issuer.example.com",
        "active_owning_authority":"https://issuer.example.com",
        "key_id":"root-key-1",
        "target_scope":{"all":true,"allow":null,"deny":null},
        "capabilities":{"recognize":true,"mint":false},
        "default_audience_scope":null,
        "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
        "global_constraints":null,
        "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
        "issued_at":"2026-04-07T12:00:00Z",
        "signature":"base64-signature",
        "issuer_principal":null
    }"#;

    fn test_verified_at() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 7, 12, 0, 0)
            .single()
            .unwrap_or_else(|| panic!("fixed timestamp should be valid"))
    }

    fn parse_validated(json: &str) -> ValidatedTrustGrantDocument {
        let raw = RawTrustGrantDocument::parse_json_str(json)
            .unwrap_or_else(|error| panic!("raw document should parse: {error}"));
        ValidatedTrustGrantDocument::try_from(raw)
            .unwrap_or_else(|error| panic!("validated document should succeed: {error}"))
    }

    fn matching_signer_binding() -> ResolvedSignerBinding {
        let authority = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("authority id should be valid: {error}"));
        let key_record = AuthorityKeyRecord::new(
            "root-key-1",
            "ed25519",
            "base64-root-public-key",
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("valid timestamp")),
            Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("valid timestamp")),
        )
        .unwrap_or_else(|e| panic!("authority key record should be valid: {e}"));
        let signature_profile = SignatureProfile::new("jcs+ed25519", "RFC8785")
            .unwrap_or_else(|e| panic!("signature profile should be valid: {e}"));
        ResolvedSignerBinding::new(authority, key_record, signature_profile, None)
    }

    fn matching_ownership() -> OwnershipVerificationRecord {
        let authority = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("authority id should be valid: {error}"));
        OwnershipVerificationRecord::new(
            authority.clone(),
            authority,
            test_verified_at(),
            OwnershipProofKind::StaticOwner,
            None,
        )
    }

    fn active_revocation_record() -> RevocationRecord {
        RevocationRecord::new(
            RevocationStatus::Active,
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            test_verified_at(),
            Utc.with_ymd_and_hms(2026, 4, 7, 14, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("valid timestamp")),
        )
        .unwrap_or_else(|e| panic!("revocation record should be valid: {e}"))
    }

    fn matching_metadata(revocation: VerifiedRevocationState) -> VerificationMetadata {
        VerificationMetadata::new(
            test_verified_at(),
            VerificationPosture::Online,
            matching_signer_binding(),
            matching_ownership(),
            revocation,
        )
    }

    #[test]
    fn metadata_matches_document_on_correct_binding() {
        let doc = parse_validated(MATCHING_DOC_JSON);
        let metadata = matching_metadata(VerifiedRevocationState::NonRevocable);

        let result =
            ensure_metadata_matches_document(&metadata, &doc, CanonicalizationProfile::Rfc8785);

        assert!(
            result.is_ok(),
            "matching metadata should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn metadata_rejects_signature_profile_mismatch() {
        let doc = parse_validated(MATCHING_DOC_JSON);
        let authority = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("authority id should be valid: {error}"));
        let key_record = AuthorityKeyRecord::new(
            "root-key-1",
            "ed25519",
            "base64-root-public-key",
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("valid timestamp")),
            Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("valid timestamp")),
        )
        .unwrap_or_else(|e| panic!("authority key record should be valid: {e}"));
        // Profile says "RFC8785" but we create one with a different canonicalization name
        let mismatched_profile = SignatureProfile::new("jcs+ed25519", "SHA256")
            .unwrap_or_else(|e| panic!("signature profile should be valid: {e}"));
        let binding = ResolvedSignerBinding::new(authority, key_record, mismatched_profile, None);

        let metadata = VerificationMetadata::new(
            test_verified_at(),
            VerificationPosture::Online,
            binding,
            matching_ownership(),
            VerifiedRevocationState::NonRevocable,
        );

        let result =
            ensure_metadata_matches_document(&metadata, &doc, CanonicalizationProfile::Rfc8785);

        assert_eq!(result, Err(TrustGrantError::SignatureProfileMismatch));
    }

    #[test]
    fn metadata_rejects_inactive_signer_key() {
        let doc = parse_validated(MATCHING_DOC_JSON);
        let authority = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("authority id should be valid: {error}"));
        // Key expired before the verification timestamp
        let expired_key = AuthorityKeyRecord::new(
            "root-key-1",
            "ed25519",
            "base64-root-public-key",
            Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("valid timestamp")),
            Utc.with_ymd_and_hms(2025, 12, 31, 23, 59, 59)
                .single()
                .unwrap_or_else(|| panic!("valid timestamp")),
        )
        .unwrap_or_else(|e| panic!("authority key record should be valid: {e}"));
        let signature_profile = SignatureProfile::new("jcs+ed25519", "RFC8785")
            .unwrap_or_else(|e| panic!("signature profile should be valid: {e}"));
        let binding = ResolvedSignerBinding::new(authority, expired_key, signature_profile, None);

        let metadata = VerificationMetadata::new(
            test_verified_at(),
            VerificationPosture::Online,
            binding,
            matching_ownership(),
            VerifiedRevocationState::NonRevocable,
        );

        let result =
            ensure_metadata_matches_document(&metadata, &doc, CanonicalizationProfile::Rfc8785);

        assert_eq!(result, Err(TrustGrantError::SignerKeyInactive));
    }

    #[test]
    fn metadata_rejects_issuer_principal_mismatch() {
        let doc = parse_validated(MATCHING_DOC_WITH_PRINCIPAL_JSON);
        let authority = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("authority id should be valid: {error}"));
        let key_record = AuthorityKeyRecord::new(
            "root-key-1",
            "ed25519",
            "base64-root-public-key",
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("valid timestamp")),
            Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("valid timestamp")),
        )
        .unwrap_or_else(|e| panic!("authority key record should be valid: {e}"));
        let signature_profile = SignatureProfile::new("jcs+ed25519", "RFC8785")
            .unwrap_or_else(|e| panic!("signature profile should be valid: {e}"));
        // Delegated principal in binding doesn't match document's issuer_principal
        let mismatched_principal = DelegatedPrincipalRef::new("service", "wrong-worker")
            .unwrap_or_else(|e| panic!("delegated principal should be valid: {e}"));
        let binding = ResolvedSignerBinding::new(
            authority,
            key_record,
            signature_profile,
            Some(mismatched_principal),
        );

        let metadata = VerificationMetadata::new(
            test_verified_at(),
            VerificationPosture::Online,
            binding,
            matching_ownership(),
            VerifiedRevocationState::NonRevocable,
        );

        let result =
            ensure_metadata_matches_document(&metadata, &doc, CanonicalizationProfile::Rfc8785);

        assert_eq!(result, Err(TrustGrantError::IssuerPrincipalMismatch));
    }

    #[test]
    fn metadata_rejects_ownership_origin_mismatch() {
        let doc = parse_validated(MATCHING_DOC_JSON);
        let metadata_origin = AuthorityId::new("https://different-origin.example.com")
            .unwrap_or_else(|error| panic!("authority id should be valid: {error}"));
        let owning = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("authority id should be valid: {error}"));
        let ownership = OwnershipVerificationRecord::new(
            metadata_origin,
            owning,
            test_verified_at(),
            OwnershipProofKind::StaticOwner,
            None,
        );

        let metadata = VerificationMetadata::new(
            test_verified_at(),
            VerificationPosture::Online,
            matching_signer_binding(),
            ownership,
            VerifiedRevocationState::NonRevocable,
        );

        let result =
            ensure_metadata_matches_document(&metadata, &doc, CanonicalizationProfile::Rfc8785);

        assert_eq!(result, Err(TrustGrantError::OwnershipOriginMismatch));
    }

    #[test]
    fn metadata_rejects_active_owning_authority_mismatch() {
        let doc = parse_validated(MATCHING_DOC_JSON);
        let origin = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("authority id should be valid: {error}"));
        let wrong_owning = AuthorityId::new("https://different-owning.example.com")
            .unwrap_or_else(|error| panic!("authority id should be valid: {error}"));
        let ownership = OwnershipVerificationRecord::new(
            origin,
            wrong_owning,
            test_verified_at(),
            OwnershipProofKind::StaticOwner,
            None,
        );

        let metadata = VerificationMetadata::new(
            test_verified_at(),
            VerificationPosture::Online,
            matching_signer_binding(),
            ownership,
            VerifiedRevocationState::NonRevocable,
        );

        let result =
            ensure_metadata_matches_document(&metadata, &doc, CanonicalizationProfile::Rfc8785);

        assert_eq!(result, Err(TrustGrantError::ActiveOwningAuthorityMismatch));
    }

    // ── ensure_revocation_state_matches_document error-path tests ──

    #[test]
    fn revocation_state_rejects_missing_proof_for_revocable_grant() {
        let doc = parse_validated(REVOCABLE_DOC_JSON);
        let metadata = matching_metadata(VerifiedRevocationState::NonRevocable);

        let result = ensure_revocation_state_matches_document(&metadata, &doc);

        assert_eq!(result, Err(TrustGrantError::MissingRevocationProof));
    }

    #[test]
    fn revocation_state_accepts_checked_proof_for_revocable_grant() {
        let doc = parse_validated(REVOCABLE_DOC_JSON);
        let metadata =
            matching_metadata(VerifiedRevocationState::Checked(active_revocation_record()));

        let result = ensure_revocation_state_matches_document(&metadata, &doc);

        assert!(
            result.is_ok(),
            "checked proof for revocable grant should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn revocation_state_accepts_non_revocable_for_non_revocable_grant() {
        let doc = parse_validated(MATCHING_DOC_JSON);
        let metadata = matching_metadata(VerifiedRevocationState::NonRevocable);

        let result = ensure_revocation_state_matches_document(&metadata, &doc);

        assert!(
            result.is_ok(),
            "non-revocable for non-revocable grant should succeed: {:?}",
            result.err()
        );
    }

    // ── rehydration failure tests ──────────────────────────────────

    #[test]
    fn rehydration_rejects_explicit_revocation_required_policy() {
        // ExplicitRevocationRequired is not representable in v0 wire format
        // so into_raw_document_for_consistency_check must return an error.
        let json = r#"{
            "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
            "version":0,
            "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
            "revision":1,
            "supersedes":null,
            "supersession_policy":"coexist",
            "issuer_authority":"https://issuer.example.com",
            "origin_authority":"https://issuer.example.com",
            "active_owning_authority":"https://issuer.example.com",
            "key_id":"root-key-1",
            "target_scope":{"all":true,"allow":null,"deny":null},
            "capabilities":{"recognize":true,"mint":false},
            "default_audience_scope":null,
            "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
            "global_constraints":null,
            "revocation":null,
            "issued_at":"2026-04-07T12:00:00Z",
            "signature":"rehydrated-signature",
            "issuer_principal":null
        }"#;
        let raw = RawTrustGrantDocument::parse_json_str(json)
            .unwrap_or_else(|error| panic!("raw document should parse: {error}"));

        let validated = ValidatedTrustGrantDocument::try_from(raw)
            .unwrap_or_else(|error| panic!("validation should succeed: {error}"));

        use trustgrant_domain::{GrantLineage, SupersessionPolicy};

        let parts = NormalizedTrustGrantDocumentParts {
            lineage: GrantLineage::new(
                validated.lineage().trustgrant_id(),
                validated.lineage().grant_series_id(),
                validated.lineage().revision(),
                validated.lineage().supersedes(),
                SupersessionPolicy::ExplicitRevocationRequired,
            ),
            issuer_authority: validated.issuer_authority().clone(),
            ownership_authority_state: validated.ownership_authority_state().clone(),
            key_id: validated.key_id().clone(),
            target_scope: validated.target_scope().clone(),
            capabilities: validated.capabilities().clone(),
            default_audience_scope: validated.default_audience_scope().to_vec(),
            resource_scope: validated.resource_scope().clone(),
            global_time_window: validated.global_time_window().cloned(),
            revocation: validated.revocation().cloned(),
            issued_at: validated.issued_at(),
            issuer_principal: validated.issuer_principal().cloned(),
            interoperability_profile: validated.interoperability_profile().cloned(),
        };

        let normalized = NormalizedTrustGrantDocument::from_parts(parts);

        let result = normalized.into_raw_document_for_consistency_check();
        assert_eq!(
            result,
            Err(trustgrant_error::TrustGrantError::UnsupportedV0WireSupersessionPolicy),
            "ExplicitRevocationRequired should fail rehydration"
        );
    }
}
