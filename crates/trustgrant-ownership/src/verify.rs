use chrono::{DateTime, Utc};

use trustgrant_discovery::ResolvedSignerBinding;
use trustgrant_document::{RawOwnershipTransitionDocument, ValidatedOwnershipTransitionDocument};
use trustgrant_domain::{AuthorityId, CanonicalizationProfile, KeyId, OwnershipTransitionRecord};
use trustgrant_error::TrustGrantError;
use trustgrant_ports::{
    AuthorityDiscoverySource, SignatureVerificationRequest, SignatureVerifier, VerificationContext,
    VerificationPosture,
};

use super::canonicalize::{canonicalize_transition_acceptance, canonicalize_transition_proposal};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipTransitionVerificationMetadata {
    verified_at: DateTime<Utc>,
    posture: VerificationPosture,
    predecessor_signer_binding: ResolvedSignerBinding,
    successor_signer_binding: ResolvedSignerBinding,
}

impl OwnershipTransitionVerificationMetadata {
    #[must_use = "verification metadata should be attached to verified transitions"]
    pub const fn new(
        verified_at: DateTime<Utc>,
        posture: VerificationPosture,
        predecessor_signer_binding: ResolvedSignerBinding,
        successor_signer_binding: ResolvedSignerBinding,
    ) -> Self {
        Self {
            verified_at,
            posture,
            predecessor_signer_binding,
            successor_signer_binding,
        }
    }

    #[must_use = "verified_at is required for audit and time-based checks"]
    pub const fn verified_at(&self) -> DateTime<Utc> {
        self.verified_at
    }

    #[must_use = "posture is required for audit and policy"]
    pub const fn posture(&self) -> VerificationPosture {
        self.posture
    }

    #[must_use = "predecessor signer binding is required for audit"]
    pub const fn predecessor_signer_binding(&self) -> &ResolvedSignerBinding {
        &self.predecessor_signer_binding
    }

    #[must_use = "successor signer binding is required for audit"]
    pub const fn successor_signer_binding(&self) -> &ResolvedSignerBinding {
        &self.successor_signer_binding
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOwnershipTransition {
    document: ValidatedOwnershipTransitionDocument,
    metadata: OwnershipTransitionVerificationMetadata,
    record: OwnershipTransitionRecord,
}

impl VerifiedOwnershipTransition {
    #[must_use = "verified transitions should only be created after proof verification"]
    pub const fn new(
        document: ValidatedOwnershipTransitionDocument,
        metadata: OwnershipTransitionVerificationMetadata,
        record: OwnershipTransitionRecord,
    ) -> Self {
        Self {
            document,
            metadata,
            record,
        }
    }

    #[must_use = "validated transition document is required for audit"]
    pub const fn document(&self) -> &ValidatedOwnershipTransitionDocument {
        &self.document
    }

    #[must_use = "metadata is required for audit"]
    pub const fn metadata(&self) -> &OwnershipTransitionVerificationMetadata {
        &self.metadata
    }

    #[must_use = "normalized record is required for chain verification"]
    pub const fn record(&self) -> &OwnershipTransitionRecord {
        &self.record
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct OwnershipTransitionVerifier;

impl OwnershipTransitionVerifier {
    #[must_use = "ownership transition verifier should be reused by adapters and pipelines"]
    pub const fn new() -> Self {
        Self
    }

    /// Parses, validates, and verifies one ownership transition proof.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when parsing, validation, signer resolution,
    /// canonicalization, or signature verification fails.
    pub fn verify_json_str(
        self,
        json: &str,
        verifier: &impl SignatureVerifier,
        discovery_source: &impl AuthorityDiscoverySource,
        context: VerificationContext,
    ) -> Result<VerifiedOwnershipTransition, TrustGrantError> {
        let raw_document = RawOwnershipTransitionDocument::parse_json_str(json)?;

        self.verify_raw_document(&raw_document, verifier, discovery_source, context)
    }

    /// Parses, validates, and verifies one ownership transition proof from
    /// JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when parsing, validation, signer resolution,
    /// canonicalization, or signature verification fails.
    pub fn verify_json_bytes(
        self,
        bytes: &[u8],
        verifier: &impl SignatureVerifier,
        discovery_source: &impl AuthorityDiscoverySource,
        context: VerificationContext,
    ) -> Result<VerifiedOwnershipTransition, TrustGrantError> {
        let raw_document = RawOwnershipTransitionDocument::parse_json_bytes(bytes)?;

        self.verify_raw_document(&raw_document, verifier, discovery_source, context)
    }

    /// Validates and verifies one already-parsed ownership transition proof.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when validation, signer resolution,
    /// canonicalization, or signature verification fails.
    pub fn verify_raw_document(
        self,
        raw_document: &RawOwnershipTransitionDocument,
        verifier: &impl SignatureVerifier,
        discovery_source: &(impl AuthorityDiscoverySource + ?Sized),
        context: VerificationContext,
    ) -> Result<VerifiedOwnershipTransition, TrustGrantError> {
        let validated_document =
            ValidatedOwnershipTransitionDocument::try_from(raw_document.clone())?;
        let predecessor_signer_binding = discovery_source.resolve_signer_binding(
            validated_document.parties().predecessor_authority(),
            validated_document.predecessor_signature().key_id(),
            None,
            context,
        )?;
        let successor_signer_binding = discovery_source.resolve_signer_binding(
            validated_document.parties().successor_authority(),
            validated_document.successor_acceptance().key_id(),
            None,
            context,
        )?;
        let canonical_profile = CanonicalizationProfile::Rfc8785;

        ensure_transition_signer_binding(
            &predecessor_signer_binding,
            validated_document.parties().predecessor_authority(),
            validated_document.predecessor_signature().key_id(),
            canonical_profile,
            context.verified_at(),
        )?;
        ensure_transition_signer_binding(
            &successor_signer_binding,
            validated_document.parties().successor_authority(),
            validated_document.successor_acceptance().key_id(),
            canonical_profile,
            context.verified_at(),
        )?;

        if validated_document.successor_acceptance().accepted_at() > context.verified_at() {
            return Err(TrustGrantError::InvalidOwnershipTransitionAcceptanceTime);
        }

        let proposal_bytes = canonicalize_transition_proposal(raw_document, canonical_profile)?;
        let predecessor_request = SignatureVerificationRequest::new(
            proposal_bytes.as_slice(),
            canonical_profile,
            &predecessor_signer_binding,
            validated_document.predecessor_signature().signature(),
        );
        verifier
            .verify_signature(&predecessor_request)
            .map_err(|_error| TrustGrantError::OwnershipTransitionPredecessorSignatureFailed)?;

        let acceptance_bytes = canonicalize_transition_acceptance(raw_document, canonical_profile)?;
        let successor_request = SignatureVerificationRequest::new(
            acceptance_bytes.as_slice(),
            canonical_profile,
            &successor_signer_binding,
            validated_document.successor_acceptance().signature(),
        );
        verifier
            .verify_signature(&successor_request)
            .map_err(|_error| TrustGrantError::OwnershipTransitionSuccessorSignatureFailed)?;

        let record = validated_document.to_record()?;
        let metadata = OwnershipTransitionVerificationMetadata::new(
            context.verified_at(),
            context.posture(),
            predecessor_signer_binding,
            successor_signer_binding,
        );

        Ok(VerifiedOwnershipTransition::new(
            validated_document,
            metadata,
            record,
        ))
    }
}

fn ensure_transition_signer_binding(
    signer_binding: &ResolvedSignerBinding,
    expected_authority: &AuthorityId,
    expected_key_id: &KeyId,
    canonical_profile: CanonicalizationProfile,
    verified_at: DateTime<Utc>,
) -> Result<(), TrustGrantError> {
    if signer_binding.issuer_authority() != expected_authority {
        return Err(TrustGrantError::SignerAuthorityMismatch);
    }

    if signer_binding.key_record().key_id() != expected_key_id {
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

    if !signer_binding.key_record().is_active_at(verified_at) {
        return Err(TrustGrantError::SignerKeyInactive);
    }

    if signer_binding.delegated_principal().is_some() {
        return Err(TrustGrantError::IssuerPrincipalMismatch);
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::OwnershipTransitionVerifier;
    use trustgrant_discovery::{
        AuthorityKeyRecord, DelegatedPrincipalRef, ResolvedSignerBinding, SignatureProfile,
    };
    use trustgrant_document::ValidatedPrincipal;
    use trustgrant_domain::KeyId;
    use trustgrant_error::TrustGrantError;
    use trustgrant_ports::{
        AuthorityDiscoverySource, SignatureVerificationRequest, SignatureVerifier,
        VerificationContext, VerificationPosture,
    };

    #[derive(Debug, Default)]
    struct FakeSignatureVerifier;

    impl SignatureVerifier for FakeSignatureVerifier {
        fn verify_signature(
            &self,
            request: &SignatureVerificationRequest<'_>,
        ) -> Result<(), TrustGrantError> {
            if request.signature_profile().format().as_str() == "jcs+ed25519"
                && request.signature_profile().canonicalization().as_str() == "RFC8785"
                && !request.signature().is_empty()
                && !request.canonical_bytes().is_empty()
            {
                Ok(())
            } else {
                Err(TrustGrantError::SignatureVerificationFailed)
            }
        }
    }

    #[derive(Debug, Default)]
    struct FakeDiscoverySource;

    impl AuthorityDiscoverySource for FakeDiscoverySource {
        fn resolve_signer_binding(
            &self,
            issuer_authority: &trustgrant_domain::AuthorityId,
            key_id: &KeyId,
            issuer_principal: Option<&ValidatedPrincipal>,
            _context: VerificationContext,
        ) -> Result<ResolvedSignerBinding, TrustGrantError> {
            if issuer_principal.is_some() {
                return Err(TrustGrantError::IssuerPrincipalMismatch);
            }

            let key_record = AuthorityKeyRecord::new(
                key_id.as_str().to_owned(),
                "ed25519",
                "public-key-material",
                fixed_timestamp(2026, 1, 1, 0, 0, 0),
                fixed_timestamp(2027, 1, 1, 0, 0, 0),
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

    #[test]
    fn transition_verifier_accepts_valid_transition() {
        let verifier = OwnershipTransitionVerifier::new();
        let result = verifier.verify_json_str(
            VALID_TRANSITION_JSON,
            &FakeSignatureVerifier,
            &FakeDiscoverySource,
            VerificationContext::new(
                fixed_timestamp(2026, 4, 7, 12, 30, 0),
                VerificationPosture::Online,
            ),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn transition_verifier_rejects_future_acceptance_timestamp() {
        let verifier = OwnershipTransitionVerifier::new();
        let result = verifier.verify_json_str(
            FUTURE_ACCEPTANCE_JSON,
            &FakeSignatureVerifier,
            &FakeDiscoverySource,
            VerificationContext::new(
                fixed_timestamp(2026, 4, 7, 12, 30, 0),
                VerificationPosture::Online,
            ),
        );

        assert_eq!(
            result.map(|_value| ()),
            Err(TrustGrantError::InvalidOwnershipTransitionAcceptanceTime)
        );
    }

    #[test]
    fn verified_transition_metadata_accessors_return_expected_values() {
        let verifier = OwnershipTransitionVerifier::new();
        let result = verifier
            .verify_json_str(
                VALID_TRANSITION_JSON,
                &FakeSignatureVerifier,
                &FakeDiscoverySource,
                VerificationContext::new(
                    fixed_timestamp(2026, 4, 7, 12, 30, 0),
                    VerificationPosture::Online,
                ),
            )
            .unwrap_or_else(|error| panic!("verification should succeed: {error}"));

        // OwnershipTransitionVerificationMetadata accessors
        let metadata = result.metadata();
        assert_eq!(
            metadata.verified_at(),
            fixed_timestamp(2026, 4, 7, 12, 30, 0)
        );
        assert_eq!(metadata.posture(), VerificationPosture::Online);
        assert_eq!(
            metadata
                .predecessor_signer_binding()
                .issuer_authority()
                .as_str(),
            "https://origin.example.com"
        );
        assert_eq!(
            metadata
                .successor_signer_binding()
                .issuer_authority()
                .as_str(),
            "https://successor.example.com"
        );

        // VerifiedOwnershipTransition accessors
        assert_eq!(
            result.document().parties().predecessor_authority().as_str(),
            "https://origin.example.com"
        );
        assert_eq!(result.metadata(), metadata);
    }

    #[test]
    fn transition_verifier_rejects_signer_authority_mismatch() {
        let verifier = OwnershipTransitionVerifier::new();
        let result = verifier.verify_json_str(
            VALID_TRANSITION_JSON,
            &FakeSignatureVerifier,
            &MismatchedAuthorityDiscoverySource,
            VerificationContext::new(
                fixed_timestamp(2026, 4, 7, 12, 30, 0),
                VerificationPosture::Online,
            ),
        );

        assert_eq!(
            result.map(|_value| ()),
            Err(TrustGrantError::SignerAuthorityMismatch)
        );
    }

    #[test]
    fn transition_verifier_rejects_key_id_mismatch() {
        let verifier = OwnershipTransitionVerifier::new();
        let result = verifier.verify_json_str(
            VALID_TRANSITION_JSON,
            &FakeSignatureVerifier,
            &MismatchedKeyIdDiscoverySource,
            VerificationContext::new(
                fixed_timestamp(2026, 4, 7, 12, 30, 0),
                VerificationPosture::Online,
            ),
        );

        assert_eq!(result.map(|_value| ()), Err(TrustGrantError::KeyIdMismatch));
    }

    #[test]
    fn transition_verifier_rejects_signature_profile_mismatch() {
        let verifier = OwnershipTransitionVerifier::new();
        let result = verifier.verify_json_str(
            VALID_TRANSITION_JSON,
            &FakeSignatureVerifier,
            &MismatchedProfileDiscoverySource,
            VerificationContext::new(
                fixed_timestamp(2026, 4, 7, 12, 30, 0),
                VerificationPosture::Online,
            ),
        );

        assert_eq!(
            result.map(|_value| ()),
            Err(TrustGrantError::SignatureProfileMismatch)
        );
    }

    #[test]
    fn transition_verifier_rejects_inactive_signer_key() {
        let verifier = OwnershipTransitionVerifier::new();
        let result = verifier.verify_json_str(
            VALID_TRANSITION_JSON,
            &FakeSignatureVerifier,
            &InactiveKeyDiscoverySource,
            VerificationContext::new(
                fixed_timestamp(2026, 4, 7, 12, 30, 0),
                VerificationPosture::Online,
            ),
        );

        assert_eq!(
            result.map(|_value| ()),
            Err(TrustGrantError::SignerKeyInactive)
        );
    }

    #[test]
    fn transition_verifier_rejects_delegated_principal() {
        let verifier = OwnershipTransitionVerifier::new();
        let result = verifier.verify_json_str(
            VALID_TRANSITION_JSON,
            &FakeSignatureVerifier,
            &DelegatedPrincipalDiscoverySource,
            VerificationContext::new(
                fixed_timestamp(2026, 4, 7, 12, 30, 0),
                VerificationPosture::Online,
            ),
        );

        assert_eq!(
            result.map(|_value| ()),
            Err(TrustGrantError::IssuerPrincipalMismatch)
        );
    }

    #[derive(Debug, Default)]
    struct MismatchedAuthorityDiscoverySource;

    impl AuthorityDiscoverySource for MismatchedAuthorityDiscoverySource {
        fn resolve_signer_binding(
            &self,
            _issuer_authority: &trustgrant_domain::AuthorityId,
            key_id: &KeyId,
            _issuer_principal: Option<&ValidatedPrincipal>,
            _context: VerificationContext,
        ) -> Result<ResolvedSignerBinding, TrustGrantError> {
            let wrong_authority = trustgrant_domain::AuthorityId::new("https://wrong.example.com")?;
            let key_record = AuthorityKeyRecord::new(
                key_id.as_str().to_owned(),
                "ed25519",
                "public-key-material",
                fixed_timestamp(2026, 1, 1, 0, 0, 0),
                fixed_timestamp(2027, 1, 1, 0, 0, 0),
            )?;
            let signature_profile = SignatureProfile::new("jcs+ed25519", "RFC8785")?;
            Ok(ResolvedSignerBinding::new(
                wrong_authority,
                key_record,
                signature_profile,
                None,
            ))
        }
    }

    #[derive(Debug, Default)]
    struct MismatchedKeyIdDiscoverySource;

    impl AuthorityDiscoverySource for MismatchedKeyIdDiscoverySource {
        fn resolve_signer_binding(
            &self,
            issuer_authority: &trustgrant_domain::AuthorityId,
            _key_id: &KeyId,
            _issuer_principal: Option<&ValidatedPrincipal>,
            _context: VerificationContext,
        ) -> Result<ResolvedSignerBinding, TrustGrantError> {
            let key_record = AuthorityKeyRecord::new(
                "wrong-key-id",
                "ed25519",
                "public-key-material",
                fixed_timestamp(2026, 1, 1, 0, 0, 0),
                fixed_timestamp(2027, 1, 1, 0, 0, 0),
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

    #[derive(Debug, Default)]
    struct MismatchedProfileDiscoverySource;

    impl AuthorityDiscoverySource for MismatchedProfileDiscoverySource {
        fn resolve_signer_binding(
            &self,
            issuer_authority: &trustgrant_domain::AuthorityId,
            key_id: &KeyId,
            _issuer_principal: Option<&ValidatedPrincipal>,
            _context: VerificationContext,
        ) -> Result<ResolvedSignerBinding, TrustGrantError> {
            let key_record = AuthorityKeyRecord::new(
                key_id.as_str().to_owned(),
                "ed25519",
                "public-key-material",
                fixed_timestamp(2026, 1, 1, 0, 0, 0),
                fixed_timestamp(2027, 1, 1, 0, 0, 0),
            )?;
            let signature_profile = SignatureProfile::new("jcs+ed25519", "WRONG_CANON")?;
            Ok(ResolvedSignerBinding::new(
                issuer_authority.clone(),
                key_record,
                signature_profile,
                None,
            ))
        }
    }

    #[derive(Debug, Default)]
    struct InactiveKeyDiscoverySource;

    impl AuthorityDiscoverySource for InactiveKeyDiscoverySource {
        fn resolve_signer_binding(
            &self,
            issuer_authority: &trustgrant_domain::AuthorityId,
            key_id: &KeyId,
            _issuer_principal: Option<&ValidatedPrincipal>,
            _context: VerificationContext,
        ) -> Result<ResolvedSignerBinding, TrustGrantError> {
            let key_record = AuthorityKeyRecord::new(
                key_id.as_str().to_owned(),
                "ed25519",
                "public-key-material",
                fixed_timestamp(2020, 1, 1, 0, 0, 0),
                fixed_timestamp(2021, 1, 1, 0, 0, 0),
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

    #[derive(Debug, Default)]
    struct DelegatedPrincipalDiscoverySource;

    impl AuthorityDiscoverySource for DelegatedPrincipalDiscoverySource {
        fn resolve_signer_binding(
            &self,
            issuer_authority: &trustgrant_domain::AuthorityId,
            key_id: &KeyId,
            _issuer_principal: Option<&ValidatedPrincipal>,
            _context: VerificationContext,
        ) -> Result<ResolvedSignerBinding, TrustGrantError> {
            let key_record = AuthorityKeyRecord::new(
                key_id.as_str().to_owned(),
                "ed25519",
                "public-key-material",
                fixed_timestamp(2026, 1, 1, 0, 0, 0),
                fixed_timestamp(2027, 1, 1, 0, 0, 0),
            )?;
            let signature_profile = SignatureProfile::new("jcs+ed25519", "RFC8785")?;
            let delegated = DelegatedPrincipalRef::new("user", "alice")?;
            Ok(ResolvedSignerBinding::new(
                issuer_authority.clone(),
                key_record,
                signature_profile,
                Some(delegated),
            ))
        }
    }

    #[test]
    fn transition_verifier_accepts_valid_transition_from_json_bytes() {
        let verifier = OwnershipTransitionVerifier::new();
        let result = verifier.verify_json_bytes(
            VALID_TRANSITION_JSON.as_bytes(),
            &FakeSignatureVerifier,
            &FakeDiscoverySource,
            VerificationContext::new(
                fixed_timestamp(2026, 4, 7, 12, 30, 0),
                VerificationPosture::Online,
            ),
        );

        assert!(result.is_ok());
    }

    const VALID_TRANSITION_JSON: &str = r#"{
      "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174000",
      "version":0,
      "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174001",
      "revision":1,
      "supersedes_transition_id":null,
      "origin_authority":"https://origin.example.com",
      "from_authority":"https://origin.example.com",
      "to_authority":"https://successor.example.com",
      "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":null}],"deny":null}}},
      "global_constraints":{"time":{"not_before":"2026-04-07T11:00:00Z","not_after":"2026-04-07T13:00:00Z"}},
      "effective_at":"2026-04-07T12:00:00Z",
      "predecessor_signature":{"key_id":"root-key-1","signature":"predecessor-signature"},
      "successor_acceptance":{"accepted_at":"2026-04-07T11:30:00Z","key_id":"successor-key-1","signature":"successor-signature"}
    }"#;

    const FUTURE_ACCEPTANCE_JSON: &str = r#"{
      "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174000",
      "version":0,
      "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174001",
      "revision":1,
      "supersedes_transition_id":null,
      "origin_authority":"https://origin.example.com",
      "from_authority":"https://origin.example.com",
      "to_authority":"https://successor.example.com",
      "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":null}],"deny":null}}},
      "global_constraints":null,
      "effective_at":"2026-04-07T12:00:00Z",
      "predecessor_signature":{"key_id":"root-key-1","signature":"predecessor-signature"},
      "successor_acceptance":{"accepted_at":"2026-04-07T13:30:00Z","key_id":"successor-key-1","signature":"successor-signature"}
    }"#;

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
}
