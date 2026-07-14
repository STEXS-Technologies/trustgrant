use tracing;

use trustgrant_document::{RawTrustGrantDocument, ValidatedTrustGrantDocument};
use trustgrant_error::TrustGrantError;
use trustgrant_ownership::{OwnershipChainVerifier, OwnershipTransitionVerifier};
use trustgrant_ports::{VerificationContext, VerificationSources};
use trustgrant_revocation::VerifiedRevocationState;

use super::bundle::TrustGrantProofBundle;
use super::canonicalize::{CanonicalTrustGrantBytes, canonicalize_trustgrant};
use super::consistency::{
    ensure_metadata_matches_document, ensure_revocation_state_is_acceptable,
    ensure_revocation_state_matches_document,
};
use super::signature::{SignatureVerificationRequest, SignatureVerifier};
use super::{VerificationMetadata, VerifiedTrustGrant};
use trustgrant_domain::CanonicalizationProfile;

/// The output of a successful verification pipeline.
///
/// Contains both the [`VerifiedTrustGrant`] (validated document +
/// verification metadata) and the canonical signable bytes that were used
/// for signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationArtifacts {
    verified_grant: VerifiedTrustGrant,
    canonical_bytes: CanonicalTrustGrantBytes,
}

impl VerificationArtifacts {
    #[must_use = "verified grant is required for registration and evaluation"]
    pub const fn verified_grant(&self) -> &VerifiedTrustGrant {
        &self.verified_grant
    }

    #[must_use = "canonical bytes may be retained for audit or debugging"]
    pub const fn canonical_bytes(&self) -> &CanonicalTrustGrantBytes {
        &self.canonical_bytes
    }
}

/// End-to-end verification pipeline for TrustGrant documents.
///
/// The pipeline orchestrates parsing, validation, canonicalization,
/// signer-binding resolution, revocation checks, ownership verification,
/// and signature verification in a single pass. Use the stateless
/// `VerificationPipeline::new()` entrypoints for each grant.
#[derive(Debug, Default, Clone, Copy)]
pub struct VerificationPipeline;

impl VerificationPipeline {
    #[must_use = "verification pipeline should be reused by adapters"]
    pub const fn new() -> Self {
        Self
    }

    /// Parses, validates, canonicalizes, verifies, and normalizes one
    /// TrustGrant into verified runtime state.
    ///
    /// Use this when you already have resolved [`VerificationMetadata`]
    /// (signer binding, ownership, revocation state) from external sources
    /// and want a single-call verify.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use trustgrant_verify::VerificationPipeline;
    /// # // Full example requires a SignatureVerifier and VerificationMetadata.
    /// # // See integration tests for end-to-end usage.
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when parsing, validation, canonicalization,
    /// signer-binding checks, revocation freshness checks, or signature
    /// verification fails.
    pub fn verify_json_str(
        self,
        json: &str,
        verifier: &impl SignatureVerifier,
        metadata: VerificationMetadata,
    ) -> Result<VerificationArtifacts, TrustGrantError> {
        let raw_document = RawTrustGrantDocument::parse_json_str(json)?;

        self.verify_raw_document(&raw_document, verifier, metadata)
    }

    /// Parses, validates, canonicalizes, verifies, and normalizes one
    /// TrustGrant from JSON bytes.
    ///
    /// Use this when the source is already in bytes (e.g. from a file or
    /// network buffer) and you have pre-resolved [`VerificationMetadata`].
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when parsing, validation, canonicalization,
    /// signer-binding checks, revocation freshness checks, or signature
    /// verification fails.
    pub fn verify_json_bytes(
        self,
        bytes: &[u8],
        verifier: &impl SignatureVerifier,
        metadata: VerificationMetadata,
    ) -> Result<VerificationArtifacts, TrustGrantError> {
        let raw_document = RawTrustGrantDocument::parse_json_bytes(bytes)?;

        self.verify_raw_document(&raw_document, verifier, metadata)
    }

    /// Parses, validates, resolves proof inputs, verifies, and normalizes one
    /// TrustGrant into verified runtime state.
    ///
    /// Use this when you have adapter-facing [`VerificationSources`] to resolve
    /// signer binding, ownership, and revocation proofs on the fly.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when parsing, validation, proof resolution,
    /// canonicalization, signer-binding checks, ownership checks, revocation
    /// freshness checks, or signature verification fails.
    pub fn verify_json_str_with_sources(
        self,
        json: &str,
        verifier: &impl SignatureVerifier,
        sources: VerificationSources<'_>,
        context: VerificationContext,
    ) -> Result<VerificationArtifacts, TrustGrantError> {
        let raw_document = RawTrustGrantDocument::parse_json_str(json)?;

        self.verify_raw_document_with_sources(&raw_document, verifier, sources, context)
    }

    /// Parses, validates, resolves proof inputs, verifies, and normalizes one
    /// TrustGrant from JSON bytes using adapter-facing proof sources.
    ///
    /// Use this when the source is in bytes and you have adapter-facing
    /// [`VerificationSources`] for proof resolution.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when parsing, validation, proof resolution,
    /// canonicalization, signer-binding checks, ownership checks, revocation
    /// freshness checks, or signature verification fails.
    pub fn verify_json_bytes_with_sources(
        self,
        bytes: &[u8],
        verifier: &impl SignatureVerifier,
        sources: VerificationSources<'_>,
        context: VerificationContext,
    ) -> Result<VerificationArtifacts, TrustGrantError> {
        let raw_document = RawTrustGrantDocument::parse_json_bytes(bytes)?;

        self.verify_raw_document_with_sources(&raw_document, verifier, sources, context)
    }

    /// Verifies one JSON TrustGrant using one shared proof bundle as the
    /// discovery, revocation, and ownership proof source.
    ///
    /// Use this when all proof material has been assembled into a
    /// [`TrustGrantProofBundle`] (e.g. for offline or cached verification).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use trustgrant_verify::VerificationPipeline;
    /// # // Full example requires a SignatureVerifier, TrustGrantProofBundle,
    /// # // and VerificationContext. See integration tests.
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when parsing, validation, proof resolution,
    /// canonicalization, signer-binding checks, ownership checks, revocation
    /// freshness checks, or signature verification fails.
    pub fn verify_json_str_with_bundle(
        self,
        json: &str,
        verifier: &impl SignatureVerifier,
        bundle: &TrustGrantProofBundle,
        context: VerificationContext,
    ) -> Result<VerificationArtifacts, TrustGrantError> {
        self.verify_json_str_with_sources(json, verifier, bundle.as_sources(), context)
    }

    /// Verifies one JSON-byte TrustGrant using one shared proof bundle as the
    /// discovery, revocation, and ownership proof source.
    ///
    /// Use this when source is bytes and proof material is in a
    /// [`TrustGrantProofBundle`].
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when parsing, validation, proof resolution,
    /// canonicalization, signer-binding checks, ownership checks, revocation
    /// freshness checks, or signature verification fails.
    pub fn verify_json_bytes_with_bundle(
        self,
        bytes: &[u8],
        verifier: &impl SignatureVerifier,
        bundle: &TrustGrantProofBundle,
        context: VerificationContext,
    ) -> Result<VerificationArtifacts, TrustGrantError> {
        self.verify_json_bytes_with_sources(bytes, verifier, bundle.as_sources(), context)
    }

    /// Verifies one already-parsed raw TrustGrant document.
    ///
    /// Use this when you already have a [`RawTrustGrantDocument`] and
    /// pre-resolved [`VerificationMetadata`], avoiding a JSON re-parse.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when validation, canonicalization,
    /// signer-binding checks, revocation freshness checks, or signature
    /// verification fails.
    pub fn verify_raw_document(
        self,
        raw_document: &RawTrustGrantDocument,
        verifier: &impl SignatureVerifier,
        metadata: VerificationMetadata,
    ) -> Result<VerificationArtifacts, TrustGrantError> {
        let validated_document = ValidatedTrustGrantDocument::try_from(raw_document.clone())?;
        verify_impl(raw_document, validated_document, verifier, metadata)
    }

    /// Verifies one already-parsed raw TrustGrant document using adapter-facing
    /// proof sources.
    ///
    /// Use this when you have a pre-parsed [`RawTrustGrantDocument`] and
    /// adapter-facing [`VerificationSources`], avoiding a JSON re-parse.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when validation, proof resolution,
    /// canonicalization, signer-binding checks, ownership checks, revocation
    /// freshness checks, or signature verification fails.
    pub fn verify_raw_document_with_sources(
        self,
        raw_document: &RawTrustGrantDocument,
        verifier: &impl SignatureVerifier,
        sources: VerificationSources<'_>,
        context: VerificationContext,
    ) -> Result<VerificationArtifacts, TrustGrantError> {
        let validated_document = ValidatedTrustGrantDocument::try_from(raw_document.clone())?;
        let signer_binding = sources.discovery_source().resolve_signer_binding(
            validated_document.issuer_authority(),
            validated_document.key_id(),
            validated_document.issuer_principal(),
            context,
        )?;
        let transition_verifier = OwnershipTransitionVerifier::new();
        let transitions = sources
            .ownership_source()
            .resolve_ownership_transition_chain(&validated_document, context)?
            .into_iter()
            .map(|raw_transition| {
                transition_verifier.verify_raw_document(
                    &raw_transition,
                    verifier,
                    sources.discovery_source(),
                    context,
                )
            })
            .map(|result| result.map(|verified_transition| verified_transition.record().clone()))
            .collect::<Result<Vec<_>, _>>()?;
        let ownership = OwnershipChainVerifier::new().verify_document_ownership(
            &validated_document,
            &transitions,
            context.verified_at(),
        )?;
        let revocation = if requires_revocation_check(&validated_document) {
            VerifiedRevocationState::Checked(
                sources.revocation_source().resolve_revocation_record(
                    &validated_document,
                    &signer_binding,
                    context,
                )?,
            )
        } else {
            VerifiedRevocationState::NonRevocable
        };
        let metadata = VerificationMetadata::new(
            context.verified_at(),
            context.posture(),
            signer_binding,
            ownership,
            revocation,
        );

        verify_impl(raw_document, validated_document, verifier, metadata)
    }
}

fn verify_impl(
    raw_document: &RawTrustGrantDocument,
    validated_document: ValidatedTrustGrantDocument,
    verifier: &impl SignatureVerifier,
    metadata: VerificationMetadata,
) -> Result<VerificationArtifacts, TrustGrantError> {
    let tg_id = &raw_document.trustgrant_id;
    let _span = tracing::info_span!("verify", trustgrant_id = %tg_id).entered();
    let canonical_profile = CanonicalizationProfile::Rfc8785;
    let canonical_bytes = canonicalize_trustgrant(raw_document, canonical_profile)?;
    tracing::debug!(trustgrant_id = %tg_id, "canonicalized");

    ensure_metadata_matches_document(&metadata, &validated_document, canonical_profile)?;
    ensure_revocation_state_matches_document(&metadata, &validated_document)?;
    ensure_revocation_state_is_acceptable(&metadata)?;
    tracing::debug!(trustgrant_id = %tg_id, "metadata_consistent");

    let signature_request = SignatureVerificationRequest::new(
        canonical_bytes.as_slice(),
        canonical_profile,
        metadata.signer_binding(),
        validated_document.signature(),
    );

    verifier.verify_signature(&signature_request)?;
    tracing::debug!(trustgrant_id = %tg_id, "signature_verified");

    tracing::info!(trustgrant_id = %tg_id, "verified");
    Ok(VerificationArtifacts {
        verified_grant: VerifiedTrustGrant::new(validated_document, metadata),
        canonical_bytes,
    })
}

fn requires_revocation_check(document: &ValidatedTrustGrantDocument) -> bool {
    document
        .revocation()
        .is_some_and(|revocation| revocation.revocable())
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::VerificationPipeline;
    use crate::bundle::{BundleRevocationProof, TrustGrantProofBundle};
    use crate::signature::{SignatureVerificationRequest, SignatureVerifier};
    use crate::{VerificationMetadata, VerificationPosture};
    use trustgrant_discovery::parse_authority_discovery_document;
    use trustgrant_discovery::{AuthorityKeyRecord, ResolvedSignerBinding, SignatureProfile};
    use trustgrant_document::RawOwnershipTransitionDocument;
    use trustgrant_document::RawTrustGrantDocument;
    use trustgrant_document::{ValidatedPrincipal, ValidatedTrustGrantDocument};
    use trustgrant_domain::{AuthorityId, KeyId};
    use trustgrant_domain::{OwnershipProofKind, OwnershipVerificationRecord};
    use trustgrant_error::TrustGrantError;
    use trustgrant_ports::{
        AuthorityDiscoverySource, OwnershipTransitionProofSource, RevocationProofSource,
        VerificationContext, VerificationSources,
    };
    use trustgrant_revocation::{
        ProofFinality, RevocationRecord, RevocationSourceKind, RevocationStatus,
        VerifiedRevocationState,
    };
    use trustgrant_revocation::{RevocationFreshnessPolicy, parse_revocation_status_proof};

    #[derive(Debug, Default)]
    struct FakeSignatureVerifier;

    #[derive(Debug, Default)]
    struct FakeDiscoverySource;

    impl AuthorityDiscoverySource for FakeDiscoverySource {
        fn resolve_signer_binding(
            &self,
            _issuer_authority: &AuthorityId,
            _key_id: &KeyId,
            _issuer_principal: Option<&ValidatedPrincipal>,
            _context: VerificationContext,
        ) -> Result<ResolvedSignerBinding, TrustGrantError> {
            Ok(signer_binding())
        }
    }

    #[derive(Debug, Default)]
    struct FakeRevocationSource;

    impl RevocationProofSource for FakeRevocationSource {
        fn resolve_revocation_record(
            &self,
            _document: &ValidatedTrustGrantDocument,
            _signer_binding: &ResolvedSignerBinding,
            context: VerificationContext,
        ) -> Result<RevocationRecord, TrustGrantError> {
            RevocationRecord::new(
                RevocationStatus::Active,
                RevocationSourceKind::Api,
                ProofFinality::Observed,
                context.verified_at(),
                fixed_timestamp(2026, 4, 7, 12, 5, 0),
            )
        }
    }

    #[derive(Debug, Default)]
    struct FakeOwnershipSource;

    impl OwnershipTransitionProofSource for FakeOwnershipSource {
        fn resolve_ownership_transition_chain(
            &self,
            _document: &ValidatedTrustGrantDocument,
            _context: VerificationContext,
        ) -> Result<Vec<RawOwnershipTransitionDocument>, TrustGrantError> {
            Ok(Vec::new())
        }
    }

    impl SignatureVerifier for FakeSignatureVerifier {
        fn verify_signature(
            &self,
            request: &SignatureVerificationRequest<'_>,
        ) -> Result<(), TrustGrantError> {
            if request.signature() == "valid-signature"
                && request.key_id().as_str() == "root-key-1"
                && request.algorithm().as_str() == "ed25519"
                && request.signature_profile().format().as_str() == "jcs+ed25519"
                && request.issuer_authority().as_str() == "https://issuer.example.com"
                && !request.canonical_bytes().is_empty()
            {
                Ok(())
            } else {
                Err(TrustGrantError::SignatureVerificationFailed)
            }
        }
    }

    fn metadata() -> VerificationMetadata {
        VerificationMetadata::new(
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            VerificationPosture::Online,
            signer_binding(),
            ownership_record(),
            VerifiedRevocationState::Checked(
                match RevocationRecord::new(
                    RevocationStatus::Active,
                    RevocationSourceKind::Api,
                    ProofFinality::Observed,
                    fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    fixed_timestamp(2026, 4, 7, 12, 5, 0),
                ) {
                    Ok(value) => value,
                    Err(error) => panic!("revocation record should be valid: {error}"),
                },
            ),
        )
    }

    fn ownership_record() -> OwnershipVerificationRecord {
        OwnershipVerificationRecord::new(
            match AuthorityId::new("https://issuer.example.com") {
                Ok(value) => value,
                Err(error) => panic!("origin authority should be valid: {error}"),
            },
            match AuthorityId::new("https://issuer.example.com") {
                Ok(value) => value,
                Err(error) => panic!("active owning authority should be valid: {error}"),
            },
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            OwnershipProofKind::StaticOwner,
            None,
        )
    }

    fn signer_binding() -> ResolvedSignerBinding {
        ResolvedSignerBinding::new(
            match AuthorityId::new("https://issuer.example.com") {
                Ok(value) => value,
                Err(error) => panic!("authority should be valid: {error}"),
            },
            match AuthorityKeyRecord::new(
                "root-key-1",
                "ed25519",
                "base64-public-key",
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                fixed_timestamp(2026, 4, 8, 12, 0, 0),
            ) {
                Ok(value) => value,
                Err(error) => panic!("key record should be valid: {error}"),
            },
            match SignatureProfile::new("jcs+ed25519", "RFC8785") {
                Ok(value) => value,
                Err(error) => panic!("signature profile should be valid: {error}"),
            },
            None,
        )
    }

    fn valid_json(signature: &str) -> String {
        json_with_revocation(signature, true)
    }

    fn non_revocable_json(signature: &str) -> String {
        json_with_revocation(signature, false)
    }

    fn json_with_revocation(signature: &str, revocable: bool) -> String {
        format!(
            r#"{{
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
              "target_scope":{{"all":true,"allow":null,"deny":null}},
              "capabilities":{{"recognize":true,"mint":false}},
              "default_audience_scope":null,
              "resource_scope":{{"types":{{"item":{{"all":true,"allow":null,"deny":null,"capabilities":{{"recognize":null,"mint":false}},"constraints":{{"minting":{{"max_total":null,"max_per_user":null}},"audience_scope":null}},"operations":null}}}}}},
              "revocation":{{"revocable":{revocable},"revocation_endpoint":"https://issuer.example.com/revocation"}},
              "issued_at":"2026-04-07T12:00:00Z",
              "signature":"{signature}"
            }}"#
        )
    }

    #[test]
    fn verification_pipeline_returns_verified_grant_and_canonical_bytes() {
        let pipeline = VerificationPipeline::new();
        let artifacts = match pipeline.verify_json_str(
            &valid_json("valid-signature"),
            &FakeSignatureVerifier,
            metadata(),
        ) {
            Ok(artifacts) => artifacts,
            Err(error) => panic!("verification should succeed: {error}"),
        };

        assert_eq!(
            artifacts
                .verified_grant()
                .lineage()
                .trustgrant_id()
                .to_string(),
            "tg_123e4567-e89b-12d3-a456-426614174000"
        );
        assert_eq!(
            artifacts
                .verified_grant()
                .metadata()
                .signer_binding()
                .key_record()
                .algorithm()
                .as_str(),
            "ed25519"
        );
        assert!(
            std::str::from_utf8(artifacts.canonical_bytes().as_slice())
                .unwrap_or_else(|error| panic!("canonical bytes should be valid UTF-8: {error}"))
                .contains("\"issuer_authority\":\"https://issuer.example.com\"")
        );
    }

    #[test]
    fn verification_pipeline_rejects_invalid_signature() {
        let pipeline = VerificationPipeline::new();
        let result = pipeline.verify_json_str(
            &valid_json("wrong-signature"),
            &FakeSignatureVerifier,
            metadata(),
        );

        assert_eq!(result, Err(TrustGrantError::SignatureVerificationFailed));
    }

    #[test]
    fn verification_pipeline_rejects_key_id_mismatch() {
        let pipeline = VerificationPipeline::new();
        let mismatched_metadata = VerificationMetadata::new(
            metadata().verified_at(),
            metadata().posture(),
            ResolvedSignerBinding::new(
                metadata().signer_binding().issuer_authority().clone(),
                match AuthorityKeyRecord::new(
                    "other-key",
                    "ed25519",
                    "base64-public-key",
                    fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    fixed_timestamp(2026, 4, 8, 12, 0, 0),
                ) {
                    Ok(value) => value,
                    Err(error) => panic!("key record should be valid: {error}"),
                },
                metadata().signer_binding().signature_profile().clone(),
                None,
            ),
            metadata().ownership().clone(),
            metadata().revocation().checked_record().map_or_else(
                || panic!("test metadata should carry revocation record"),
                VerifiedRevocationState::Checked,
            ),
        );

        let result = pipeline.verify_json_str(
            &valid_json("valid-signature"),
            &FakeSignatureVerifier,
            mismatched_metadata,
        );

        assert_eq!(result, Err(TrustGrantError::KeyIdMismatch));
    }

    #[test]
    fn verification_pipeline_rejects_stale_revocation_record() {
        let pipeline = VerificationPipeline::new();
        let stale_metadata = VerificationMetadata::new(
            fixed_timestamp(2026, 4, 7, 12, 6, 0),
            VerificationPosture::Cached,
            signer_binding(),
            ownership_record(),
            VerifiedRevocationState::Checked(
                match RevocationRecord::new(
                    RevocationStatus::Active,
                    RevocationSourceKind::Api,
                    ProofFinality::Observed,
                    fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    fixed_timestamp(2026, 4, 7, 12, 5, 0),
                ) {
                    Ok(value) => value,
                    Err(error) => panic!("revocation record should be valid: {error}"),
                },
            ),
        );

        let result = pipeline.verify_json_str(
            &valid_json("valid-signature"),
            &FakeSignatureVerifier,
            stale_metadata,
        );

        assert_eq!(result, Err(TrustGrantError::StaleRevocationRecord));
    }

    #[test]
    fn verification_pipeline_rejects_live_revocation_record_for_cached_posture() {
        let pipeline = VerificationPipeline::new();
        let cached_metadata = VerificationMetadata::new(
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            VerificationPosture::Cached,
            signer_binding(),
            ownership_record(),
            VerifiedRevocationState::Checked(
                match RevocationRecord::new(
                    RevocationStatus::Active,
                    RevocationSourceKind::Api,
                    ProofFinality::Observed,
                    fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    fixed_timestamp(2026, 4, 7, 12, 5, 0),
                ) {
                    Ok(value) => value,
                    Err(error) => panic!("revocation record should be valid: {error}"),
                },
            ),
        );

        let result = pipeline.verify_json_str(
            &valid_json("valid-signature"),
            &FakeSignatureVerifier,
            cached_metadata,
        );

        assert_eq!(
            result,
            Err(TrustGrantError::VerificationPostureRequiresNonLiveRevocation)
        );
    }

    #[test]
    fn verification_pipeline_rejects_insufficient_revocation_finality_for_cached_posture() {
        let pipeline = VerificationPipeline::new();
        let cached_metadata = VerificationMetadata::new(
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            VerificationPosture::Cached,
            signer_binding(),
            ownership_record(),
            VerifiedRevocationState::Checked(
                match RevocationRecord::new(
                    RevocationStatus::Active,
                    RevocationSourceKind::ProofBundle,
                    ProofFinality::Observed,
                    fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    fixed_timestamp(2026, 4, 7, 12, 5, 0),
                ) {
                    Ok(value) => value,
                    Err(error) => panic!("revocation record should be valid: {error}"),
                },
            ),
        );

        let result = pipeline.verify_json_str(
            &valid_json("valid-signature"),
            &FakeSignatureVerifier,
            cached_metadata,
        );

        assert_eq!(
            result,
            Err(TrustGrantError::InsufficientRevocationProofFinality)
        );
    }

    #[test]
    fn verification_pipeline_accepts_non_revocable_grant_without_revocation_state() {
        let pipeline = VerificationPipeline::new();
        let metadata = VerificationMetadata::new(
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            VerificationPosture::Online,
            signer_binding(),
            ownership_record(),
            VerifiedRevocationState::NonRevocable,
        );

        let result = pipeline.verify_json_str(
            &non_revocable_json("valid-signature"),
            &FakeSignatureVerifier,
            metadata,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn verification_pipeline_rejects_checked_revocation_for_non_revocable_grant() {
        let pipeline = VerificationPipeline::new();
        let result = pipeline.verify_json_str(
            &non_revocable_json("valid-signature"),
            &FakeSignatureVerifier,
            metadata(),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::UnexpectedRevocationProofForNonRevocableGrant)
        );
    }

    #[test]
    fn verification_pipeline_resolves_metadata_from_sources() {
        let pipeline = VerificationPipeline::new();
        let artifacts = match pipeline.verify_json_str_with_sources(
            &valid_json("valid-signature"),
            &FakeSignatureVerifier,
            VerificationSources::new(
                &FakeDiscoverySource,
                &FakeRevocationSource,
                &FakeOwnershipSource,
            ),
            VerificationContext::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
            ),
        ) {
            Ok(value) => value,
            Err(error) => panic!("verification with sources should succeed: {error}"),
        };

        assert_eq!(
            artifacts
                .verified_grant()
                .metadata()
                .ownership()
                .active_owning_authority()
                .as_str(),
            "https://issuer.example.com"
        );
    }

    fn proof_bundle() -> TrustGrantProofBundle {
        let discovery_document = match parse_authority_discovery_document(
            r#"{
                "authority_id":"https://issuer.example.com",
                "keys":[{"key_id":"root-key-1","algorithm":"ed25519","public_key":"base64-public-key","not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}],
                "signature_profile":{"format":"jcs+ed25519","canonicalization":"RFC8785"},
                "issued_at":"2026-04-07T12:00:00Z"
            }"#,
        ) {
            Ok(doc) => doc,
            Err(error) => panic!("discovery document should parse: {error}"),
        };

        let revocation_proof = BundleRevocationProof::new(
            match parse_revocation_status_proof(
                r#"{"trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000","status":"active","checked_at":"2026-04-07T12:00:00Z"}"#,
            ) {
                Ok(proof) => proof,
                Err(error) => panic!("revocation proof should parse: {error}"),
            },
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            match RevocationFreshnessPolicy::new(86400, 86400) {
                Ok(policy) => policy,
                Err(error) => panic!("freshness policy should be valid: {error}"),
            },
        );

        match TrustGrantProofBundle::new().with_discovery_document(discovery_document) {
            Ok(b) => b,
            Err(error) => panic!("discovery insert should succeed: {error}"),
        }
        .with_revocation_proof(revocation_proof)
        .unwrap_or_else(|error| panic!("revocation insert should succeed: {error}"))
    }

    fn verification_context() -> VerificationContext {
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            VerificationPosture::Online,
        )
    }

    #[test]
    fn verification_pipeline_accepts_valid_json_bytes() {
        let pipeline = VerificationPipeline::new();
        let bytes = valid_json("valid-signature").into_bytes();

        let artifacts = match pipeline.verify_json_bytes(&bytes, &FakeSignatureVerifier, metadata())
        {
            Ok(artifacts) => artifacts,
            Err(error) => panic!("json bytes verification should succeed: {error}"),
        };

        assert_eq!(
            artifacts
                .verified_grant()
                .lineage()
                .trustgrant_id()
                .to_string(),
            "tg_123e4567-e89b-12d3-a456-426614174000"
        );
    }

    #[test]
    fn verification_pipeline_accepts_raw_document() {
        let pipeline = VerificationPipeline::new();
        let raw = match RawTrustGrantDocument::parse_json_str(&valid_json("valid-signature")) {
            Ok(doc) => doc,
            Err(error) => panic!("parsing should succeed: {error}"),
        };

        let artifacts = match pipeline.verify_raw_document(&raw, &FakeSignatureVerifier, metadata())
        {
            Ok(artifacts) => artifacts,
            Err(error) => panic!("raw document verification should succeed: {error}"),
        };

        assert_eq!(
            artifacts
                .verified_grant()
                .lineage()
                .trustgrant_id()
                .to_string(),
            "tg_123e4567-e89b-12d3-a456-426614174000"
        );
    }

    #[test]
    fn verification_pipeline_accepts_valid_json_bytes_with_sources() {
        let pipeline = VerificationPipeline::new();
        let bytes = valid_json("valid-signature").into_bytes();

        let artifacts = match pipeline.verify_json_bytes_with_sources(
            &bytes,
            &FakeSignatureVerifier,
            VerificationSources::new(
                &FakeDiscoverySource,
                &FakeRevocationSource,
                &FakeOwnershipSource,
            ),
            verification_context(),
        ) {
            Ok(value) => value,
            Err(error) => panic!("json bytes with sources verification should succeed: {error}"),
        };

        assert_eq!(
            artifacts
                .verified_grant()
                .metadata()
                .ownership()
                .active_owning_authority()
                .as_str(),
            "https://issuer.example.com"
        );
    }

    #[test]
    fn verification_pipeline_accepts_valid_document_with_proof_bundle() {
        let pipeline = VerificationPipeline::new();
        let bundle = proof_bundle();

        let artifacts = match pipeline.verify_json_str_with_bundle(
            &valid_json("valid-signature"),
            &FakeSignatureVerifier,
            &bundle,
            verification_context(),
        ) {
            Ok(value) => value,
            Err(error) => panic!("bundle verification should succeed: {error}"),
        };

        assert_eq!(
            artifacts
                .verified_grant()
                .metadata()
                .ownership()
                .active_owning_authority()
                .as_str(),
            "https://issuer.example.com"
        );
    }

    #[test]
    fn verification_pipeline_accepts_valid_json_bytes_with_proof_bundle() {
        let pipeline = VerificationPipeline::new();
        let bundle = proof_bundle();
        let bytes = valid_json("valid-signature").into_bytes();

        let artifacts = match pipeline.verify_json_bytes_with_bundle(
            &bytes,
            &FakeSignatureVerifier,
            &bundle,
            verification_context(),
        ) {
            Ok(value) => value,
            Err(error) => panic!("bytes bundle verification should succeed: {error}"),
        };

        assert_eq!(
            artifacts
                .verified_grant()
                .metadata()
                .ownership()
                .active_owning_authority()
                .as_str(),
            "https://issuer.example.com"
        );
    }

    #[test]
    fn verification_pipeline_rejects_unknown_proof_finality_for_cached_posture() {
        let pipeline = VerificationPipeline::new();
        // Use a non-live source kind (ProofBundle) so the source-kind check
        // passes for cached posture; the finality check then rejects Unknown
        // because Unknown < TrustedSnapshot.
        let cached_metadata = VerificationMetadata::new(
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            VerificationPosture::Cached,
            signer_binding(),
            ownership_record(),
            VerifiedRevocationState::Checked(
                match RevocationRecord::new(
                    RevocationStatus::Active,
                    RevocationSourceKind::ProofBundle,
                    ProofFinality::Unknown,
                    fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    fixed_timestamp(2026, 4, 7, 12, 5, 0),
                ) {
                    Ok(value) => value,
                    Err(error) => panic!("revocation record should be valid: {error}"),
                },
            ),
        );

        let result = pipeline.verify_json_str(
            &valid_json("valid-signature"),
            &FakeSignatureVerifier,
            cached_metadata,
        );

        assert_eq!(
            result,
            Err(TrustGrantError::InsufficientRevocationProofFinality)
        );
    }

    #[test]
    fn verification_accepts_epoch_timestamps() {
        // Grant with not_before at Unix epoch (1970-01-01T00:00:00Z),
        // not_after far in the future → should verify successfully.
        let pipeline = VerificationPipeline::new();
        let json = r#"{"trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000","version":0,"grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001","revision":1,"supersedes":null,"supersession_policy":"coexist","issuer_authority":"https://issuer.example.com","origin_authority":"https://issuer.example.com","active_owning_authority":"https://issuer.example.com","key_id":"root-key-1","target_scope":{"all":true,"allow":null,"deny":null},"capabilities":{"recognize":true,"mint":false},"default_audience_scope":null,"resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},"global_constraints":{"time":{"not_before":"1970-01-01T00:00:00Z","not_after":"2099-12-31T23:59:59Z"}},"revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},"issued_at":"1970-01-01T00:00:00Z","signature":"valid-signature"}"#;

        let artifacts = pipeline
            .verify_json_str(json, &FakeSignatureVerifier, metadata())
            .unwrap_or_else(|error| panic!("epoch-timestamp verification should succeed: {error}"));

        assert_eq!(
            artifacts
                .verified_grant()
                .lineage()
                .trustgrant_id()
                .to_string(),
            "tg_123e4567-e89b-12d3-a456-426614174000"
        );
    }

    #[test]
    fn verification_pipeline_accepts_chain_state_revocation_in_online_posture() {
        let pipeline = VerificationPipeline::new();
        let online_metadata = VerificationMetadata::new(
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            VerificationPosture::Online,
            signer_binding(),
            ownership_record(),
            VerifiedRevocationState::Checked(
                match RevocationRecord::new(
                    RevocationStatus::Active,
                    RevocationSourceKind::ChainState,
                    ProofFinality::Finalized,
                    fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    fixed_timestamp(2026, 4, 7, 12, 5, 0),
                ) {
                    Ok(value) => value,
                    Err(error) => panic!("revocation record should be valid: {error}"),
                },
            ),
        );

        let result = pipeline.verify_json_str(
            &valid_json("valid-signature"),
            &FakeSignatureVerifier,
            online_metadata,
        );

        assert!(result.is_ok());
    }

    // ---------------------------------------------------------------------------
    // Error propagation tests – verify errors surface correctly through all
    // 6 entry-point methods and the raw-document path.
    // ---------------------------------------------------------------------------

    #[test]
    fn verify_json_str_rejects_invalid_json() {
        let pipeline = VerificationPipeline::new();
        let result =
            pipeline.verify_json_str("not json at all", &FakeSignatureVerifier, metadata());
        assert!(result.is_err());
        assert_eq!(result, Err(TrustGrantError::InvalidJsonDocument));
    }

    #[test]
    fn verify_json_bytes_rejects_invalid_json() {
        let pipeline = VerificationPipeline::new();
        let result =
            pipeline.verify_json_bytes(b"not json at all", &FakeSignatureVerifier, metadata());
        assert!(result.is_err());
        assert_eq!(result, Err(TrustGrantError::InvalidJsonDocument));
    }

    #[test]
    fn verify_json_str_rejects_empty_trustgrant_id() {
        let pipeline = VerificationPipeline::new();
        let invalid_json = json_with_empty_trustgrant_id("valid-signature");
        let result = pipeline.verify_json_str(&invalid_json, &FakeSignatureVerifier, metadata());
        assert!(result.is_err());
        assert_eq!(result, Err(TrustGrantError::MissingIdSeparator));
    }

    #[test]
    fn verify_json_bytes_rejects_empty_trustgrant_id() {
        let pipeline = VerificationPipeline::new();
        let invalid_bytes = json_with_empty_trustgrant_id("valid-signature").into_bytes();
        let result = pipeline.verify_json_bytes(&invalid_bytes, &FakeSignatureVerifier, metadata());
        assert!(result.is_err());
        assert_eq!(result, Err(TrustGrantError::MissingIdSeparator));
    }

    #[test]
    fn verify_raw_document_rejects_empty_trustgrant_id() {
        let pipeline = VerificationPipeline::new();
        let raw = match RawTrustGrantDocument::parse_json_str(&json_with_empty_trustgrant_id(
            "valid-signature",
        )) {
            Ok(doc) => doc,
            Err(error) => panic!("raw parse of structurally-valid JSON should succeed: {error}"),
        };
        let result = pipeline.verify_raw_document(&raw, &FakeSignatureVerifier, metadata());
        assert!(result.is_err());
        assert_eq!(result, Err(TrustGrantError::MissingIdSeparator));
    }

    #[test]
    fn verify_json_str_with_bundle_propagates_missing_revocation() {
        let pipeline = VerificationPipeline::new();
        // Bundle with discovery but no revocation proof – revocable grant
        // triggers revocation resolution which returns MissingRevocationProof.
        let bundle = bundle_with_discovery_only();
        let result = pipeline.verify_json_str_with_bundle(
            &valid_json("valid-signature"),
            &FakeSignatureVerifier,
            &bundle,
            verification_context(),
        );
        assert!(result.is_err());
        assert_eq!(result, Err(TrustGrantError::MissingRevocationProof));
    }

    #[test]
    fn verify_json_bytes_with_bundle_propagates_missing_revocation() {
        let pipeline = VerificationPipeline::new();
        let bundle = bundle_with_discovery_only();
        let bytes = valid_json("valid-signature").into_bytes();
        let result = pipeline.verify_json_bytes_with_bundle(
            &bytes,
            &FakeSignatureVerifier,
            &bundle,
            verification_context(),
        );
        assert!(result.is_err());
        assert_eq!(result, Err(TrustGrantError::MissingRevocationProof));
    }

    #[test]
    fn empty_bundle_missing_discovery_document_returns_error() {
        let pipeline = VerificationPipeline::new();
        let empty_bundle = TrustGrantProofBundle::new();
        let result = pipeline.verify_json_str_with_bundle(
            &valid_json("valid-signature"),
            &FakeSignatureVerifier,
            &empty_bundle,
            verification_context(),
        );
        assert!(result.is_err());
        assert_eq!(
            result,
            Err(TrustGrantError::MissingAuthorityDiscoveryDocument)
        );
    }

    // ---- test-data helpers ------------------------------------------------

    /// JSON that parses successfully but fails document validation because
    /// the trustgrant_id is empty.
    fn json_with_empty_trustgrant_id(signature: &str) -> String {
        format!(
            r#"{{
              "trustgrant_id":"",
              "version":0,
              "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
              "revision":1,
              "supersedes":null,
              "supersession_policy":"coexist",
              "issuer_authority":"https://issuer.example.com",
              "origin_authority":"https://issuer.example.com",
              "active_owning_authority":"https://issuer.example.com",
              "key_id":"root-key-1",
              "target_scope":{{"all":true,"allow":null,"deny":null}},
              "capabilities":{{"recognize":true,"mint":false}},
              "default_audience_scope":null,
              "resource_scope":{{"types":{{"item":{{"all":true,"allow":null,"deny":null,"capabilities":{{"recognize":null,"mint":false}},"constraints":{{"minting":{{"max_total":null,"max_per_user":null}},"audience_scope":null}},"operations":null}}}}}},
              "revocation":{{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"}},
              "issued_at":"2026-04-07T12:00:00Z",
              "signature":"{signature}"
            }}"#
        )
    }

    /// A proof bundle that carries a valid discovery document but no
    /// revocation proof – ideal for testing error propagation from the
    /// revocation source.
    fn bundle_with_discovery_only() -> TrustGrantProofBundle {
        let discovery_document = match parse_authority_discovery_document(
            r#"{
                "authority_id":"https://issuer.example.com",
                "keys":[{"key_id":"root-key-1","algorithm":"ed25519","public_key":"base64-public-key","not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}],
                "signature_profile":{"format":"jcs+ed25519","canonicalization":"RFC8785"},
                "issued_at":"2026-04-07T12:00:00Z"
            }"#,
        ) {
            Ok(doc) => doc,
            Err(error) => panic!("discovery document should parse: {error}"),
        };
        match TrustGrantProofBundle::new().with_discovery_document(discovery_document) {
            Ok(bundle) => bundle,
            Err(error) => panic!("discovery-only bundle should assemble: {error}"),
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
            .unwrap_or_else(|| panic!("fixed timestamp should be valid"))
    }

    // -----------------------------------------------------------------------
    // Verification gap tests – cover postures and timing boundaries that
    // existing tests do not exercise through the direct pipeline path.
    // -----------------------------------------------------------------------

    #[test]
    fn verification_pipeline_accepts_offline_posture() {
        let metadata = VerificationMetadata::new(
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            VerificationPosture::Offline,
            signer_binding(),
            ownership_record(),
            VerifiedRevocationState::Checked(
                RevocationRecord::new(
                    RevocationStatus::Active,
                    RevocationSourceKind::Snapshot, // non-live source required for offline posture
                    ProofFinality::Finalized,
                    fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    fixed_timestamp(2026, 4, 7, 12, 5, 0),
                )
                .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
            ),
        );
        let artifacts = VerificationPipeline::new()
            .verify_json_str(
                valid_json("valid-signature").as_str(),
                &FakeSignatureVerifier,
                metadata,
            )
            .unwrap_or_else(|error| panic!("offline verification should succeed: {error}"));
        assert!(!artifacts.canonical_bytes().as_slice().is_empty());
    }

    #[test]
    fn verification_accepts_revocation_at_exact_fresh_until_boundary() {
        let fresh_until = fixed_timestamp(2026, 4, 7, 12, 5, 0);
        // verified_at == fresh_until → should be accepted (still fresh)
        let metadata = VerificationMetadata::new(
            fresh_until,
            VerificationPosture::Online,
            signer_binding(),
            ownership_record(),
            VerifiedRevocationState::Checked(
                RevocationRecord::new(
                    RevocationStatus::Active,
                    RevocationSourceKind::Api,
                    ProofFinality::Observed,
                    fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    fresh_until,
                )
                .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
            ),
        );
        let artifacts = VerificationPipeline::new()
            .verify_json_str(
                valid_json("valid-signature").as_str(),
                &FakeSignatureVerifier,
                metadata,
            )
            .unwrap_or_else(|error| panic!("exact fresh_until boundary should succeed: {error}"));
        assert!(!artifacts.canonical_bytes().as_slice().is_empty());
    }
}
