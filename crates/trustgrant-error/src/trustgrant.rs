use thiserror::Error;

/// All errors produced by the TrustGrant protocol core.
///
/// # Error boundaries
///
/// Errors are classified by whether retrying the same input could succeed:
///
/// **Fatal** — malformed input or protocol violation. The input must change
/// for verification to succeed. Retrying with the same inputs will always
/// fail. Examples: `InvalidJsonDocument`, `SignatureVerificationFailed`,
/// `KeyIdMismatch`, `InvalidProtocolVersion`.
///
/// **Recoverable** — transient condition that may resolve on retry with fresh
/// data. Examples: `StaleRevocationRecord`, `MissingRevocationProof`,
/// `MissingAuthorityDiscoveryDocument`.
///
/// Application-level retry logic should only retry on recoverable errors.
/// Fatal errors should be surfaced immediately.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TrustGrantError {
    #[error("authority ID must not be empty")]
    EmptyAuthorityId,
    #[error("field `{0}` must not be empty")]
    EmptyStringField(&'static str),
    #[error("field `{field}` contains invalid character `{character}`")]
    InvalidStringFieldCharacter {
        field: &'static str,
        character: char,
    },
    #[error("authority ID contains invalid character `{0}`")]
    InvalidAuthorityIdCharacter(char),
    #[error("authority ID must include a non-empty scheme prefix")]
    InvalidAuthorityIdMissingScheme,
    #[error("scope `{0}` has an invalid all/allow shape")]
    InvalidScopeShape(&'static str),
    #[error("selector has an invalid all/values/expressions shape")]
    InvalidSelectorShape,
    #[error("selector expression uses unsupported predicate `{0}`")]
    UnsupportedSelectorExpressionPredicate(String),
    #[error("selector expression has invalid syntax")]
    InvalidSelectorExpressionSyntax,
    #[error("document `{document}` exceeds the maximum size of {max_bytes} bytes")]
    DocumentTooLarge {
        document: &'static str,
        max_bytes: usize,
    },
    #[error("collection `{field}` exceeds the maximum size of {max_items} items")]
    CollectionTooLarge {
        field: &'static str,
        max_items: usize,
    },
    #[error("field `{field}` exceeds the maximum size of {max_bytes} bytes")]
    StringTooLong {
        field: &'static str,
        max_bytes: usize,
    },
    #[error("duplicate selector is not allowed")]
    DuplicateSelector,
    #[error("duplicate key id is not allowed")]
    DuplicateKeyId,
    #[error("duplicate operation name is not allowed")]
    DuplicateOperationName,
    #[error("duplicate audience authority entry is not allowed")]
    DuplicateAudienceAuthority,
    #[error("a state-changing execution request requires an intent ID")]
    MissingMutationIntentId,
    #[error("a state-changing existing-resource request requires an expected resource version")]
    MissingExpectedResourceVersion,
    #[error("resource reference is missing its canonical resource type")]
    MissingResourceTypeBinding,
    #[error("mint template reference is missing its template identifier")]
    MissingTemplateId,
    #[error("resource binding is incompatible with the requested operation")]
    InvalidMutationResourceBinding,
    #[error("resource reference type does not match the request resource type")]
    ResourceTypeBindingMismatch,
    #[error("custom operation name must not reuse reserved built-in capability or operation names")]
    ReservedOperationName,
    #[error("trustgrant document JSON is invalid")]
    InvalidJsonDocument,
    #[error("trustgrant canonicalization failed")]
    CanonicalizationFailure,
    #[error("authority discovery document JSON is invalid")]
    InvalidDiscoveryDocument,
    #[error("delegated principal key document JSON is invalid")]
    InvalidDelegatedPrincipalDocument,
    #[error("revocation proof JSON is invalid")]
    InvalidRevocationProofDocument,
    #[error("ownership transition JSON is invalid")]
    InvalidOwnershipTransitionDocument,
    #[error("trustgrant signature verification failed")]
    SignatureVerificationFailed,
    #[error("ownership transition predecessor signature verification failed")]
    OwnershipTransitionPredecessorSignatureFailed,
    #[error("ownership transition successor acceptance signature verification failed")]
    OwnershipTransitionSuccessorSignatureFailed,
    #[error("resolved signer authority does not match the document issuer authority")]
    SignerAuthorityMismatch,
    #[error("resolved signer key id does not match the document key id")]
    KeyIdMismatch,
    #[error("authority discovery document authority does not match the expected issuer authority")]
    DiscoveryAuthorityMismatch,
    #[error(
        "delegated principal key document authority does not match the expected issuer authority"
    )]
    DelegatedDiscoveryAuthorityMismatch,
    #[error("requested signing key is missing from resolved authority discovery material")]
    MissingSigningKey,
    #[error("delegated principal key lookup is not supported by this authority")]
    DelegationNotSupported,
    #[error(
        "delegated principal key document principal does not match the signed document issuer principal"
    )]
    DelegatedPrincipalMismatch,
    #[error("resolved ownership origin authority does not match the document origin authority")]
    OwnershipOriginMismatch,
    #[error("resolved active owning authority does not match the document active owning authority")]
    ActiveOwningAuthorityMismatch,
    #[error(
        "ownership transition chain is required when active owning authority differs from origin authority"
    )]
    MissingOwnershipTransitionChain,
    #[error("ownership transition chain contains an incompatible origin authority")]
    OwnershipTransitionOriginMismatch,
    #[error("ownership transition chain does not resolve to the document active owning authority")]
    OwnershipTransitionActiveOwnerMismatch,
    #[error("ownership transition chain is not valid for the resolved lineage")]
    InvalidOwnershipTransitionChain,
    #[error("ownership transition scope does not cover the document resource scope")]
    OwnershipTransitionScopeMismatch,
    #[error("resolved signer key is not active at verification time")]
    SignerKeyInactive,
    #[error("resolved signature profile does not match the canonicalization profile")]
    SignatureProfileMismatch,
    #[error("issuer principal binding does not match the signed document")]
    IssuerPrincipalMismatch,
    #[error("revocation freshness window must have checked_at before or equal to fresh_until")]
    InvalidRevocationFreshnessWindow,
    #[error("revocation freshness policy must use strictly positive TTL values")]
    InvalidRevocationPolicy,
    #[error("revocation evidence is stale at verification time")]
    StaleRevocationRecord,
    #[error("revocation evidence does not satisfy the required proof finality")]
    InsufficientRevocationProofFinality,
    #[error("the selected verification posture requires non-live revocation evidence")]
    VerificationPostureRequiresNonLiveRevocation,
    #[error("authority discovery document is missing from provided verification material")]
    MissingAuthorityDiscoveryDocument,
    #[error("delegated principal key document is missing from provided verification material")]
    MissingDelegatedPrincipalDocument,
    #[error("revocation proof is missing from provided verification material")]
    MissingRevocationProof,
    #[error("revocation proof does not match the requested trustgrant")]
    RevocationProofGrantMismatch,
    #[error("proof bundle entry `{0}` conflicts with an existing entry")]
    ConflictingProofBundleEntry(&'static str),
    #[error("non-revocable trustgrant must not carry revocation proof state")]
    UnexpectedRevocationProofForNonRevocableGrant,
    #[error("prefixed ID must contain an underscore separator")]
    MissingIdSeparator,
    #[error("prefixed ID does not use expected prefix `{expected_prefix}`")]
    InvalidIdPrefix { expected_prefix: &'static str },
    #[error("prefixed ID does not contain a valid UUID")]
    InvalidIdUuid,
    #[error("unsupported protocol version `{0}`")]
    InvalidProtocolVersion(u8),
    #[error("revision one must not declare supersedes")]
    InvalidSupersedesForFirstRevision,
    #[error("non-first ownership transition revisions must declare supersedes_transition_id")]
    MissingSupersedesForNonFirstOwnershipTransitionRevision,
    #[error("grant lineage must not supersede the same document")]
    SelfSupersession,
    #[error("ownership transition from and to authorities must differ")]
    InvalidOwnershipTransitionParties,
    #[error("ownership transition requires an explicit finite resource scope")]
    InvalidOwnershipTransitionScope,
    #[error("ownership transition effective_at must fall within the declared time window")]
    InvalidOwnershipTransitionEffectiveAt,
    #[error("ownership transition acceptance timestamp must not be in the future")]
    InvalidOwnershipTransitionAcceptanceTime,
    /// The supersession policy in an ownership transition cannot be encoded in the
    /// v0 wire format. The v1+ policy model is not backward-compatible with v0.
    #[error("supersession policy cannot be converted to the v0 wire contract")]
    UnsupportedV0WireSupersessionPolicy,
    /// A field in a persisted verified-grant record (cached verification result)
    /// contains an invalid or corrupt value.
    #[error("persisted verified-grant record field `{0}` is invalid")]
    InvalidPersistedVerifiedGrantRecord(&'static str),
    /// The version of a persisted verified-grant record is not supported by this
    /// verifier. The record may have been written by a newer version.
    #[error("unsupported persisted verified-grant record version `{0}`")]
    UnsupportedPersistedVerifiedGrantRecordVersion(u16),
    /// A time window has `not_before` after `not_after`, which is an invalid range.
    /// The start must precede or equal the end.
    #[error("time window must have not_before before or equal to not_after")]
    InvalidTimeWindow,
    /// A key validity window has `not_before` after `not_after`, which is an invalid
    /// range. The key's activation must precede or equal its expiration.
    #[error("key validity window must have not_before before or equal to not_after")]
    InvalidKeyValidityWindow,
    /// A document declares revision zero. Revisions must be strictly greater than
    /// zero.
    #[error("revision must be greater than zero")]
    ZeroRevision,
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::TrustGrantError;

    #[test]
    fn empty_authority_id_display() {
        let err = TrustGrantError::EmptyAuthorityId;
        assert_eq!(err.to_string(), "authority ID must not be empty");
    }

    #[test]
    fn empty_string_field_display() {
        let err = TrustGrantError::EmptyStringField("test_field");
        assert_eq!(err.to_string(), "field `test_field` must not be empty");
    }

    #[test]
    fn invalid_string_field_character_display() {
        let err = TrustGrantError::InvalidStringFieldCharacter {
            field: "name",
            character: '@',
        };
        assert_eq!(
            err.to_string(),
            "field `name` contains invalid character `@`"
        );
    }

    #[test]
    fn document_too_large_display() {
        let err = TrustGrantError::DocumentTooLarge {
            document: "test",
            max_bytes: 1024,
        };
        assert_eq!(
            err.to_string(),
            "document `test` exceeds the maximum size of 1024 bytes"
        );
    }

    #[test]
    fn invalid_string_field_character_is_clonable_and_eq() {
        let err = TrustGrantError::InvalidStringFieldCharacter {
            field: "name",
            character: '@',
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn different_variants_are_not_equal() {
        let empty = TrustGrantError::EmptyAuthorityId;
        let missing_scheme = TrustGrantError::InvalidAuthorityIdMissingScheme;
        assert_ne!(empty, missing_scheme);
    }

    #[test]
    fn error_trait_source_returns_none() {
        // All TrustGrantError variants use #[error("...")] (not #[from]),
        // so source() should return None for all.
        use std::error::Error;
        let err = TrustGrantError::SignatureVerificationFailed;
        assert!(err.source().is_none());
    }

    #[test]
    fn invalid_id_prefix_display() {
        let err = TrustGrantError::InvalidIdPrefix {
            expected_prefix: "tg_",
        };
        assert_eq!(
            err.to_string(),
            "prefixed ID does not use expected prefix `tg_`"
        );
    }

    #[test]
    fn reserved_operation_name_display() {
        assert_eq!(
            TrustGrantError::ReservedOperationName.to_string(),
            "custom operation name must not reuse reserved built-in capability or operation names"
        );
    }

    #[test]
    fn collection_too_large_display() {
        let err = TrustGrantError::CollectionTooLarge {
            field: "selectors",
            max_items: 32,
        };
        assert_eq!(
            err.to_string(),
            "collection `selectors` exceeds the maximum size of 32 items"
        );
    }

    #[test]
    fn invalid_id_prefix_is_clonable_and_eq() {
        let err_a = TrustGrantError::InvalidIdPrefix {
            expected_prefix: "tg_",
        };
        let err_b = TrustGrantError::InvalidIdPrefix {
            expected_prefix: "tg_",
        };
        assert_eq!(err_a, err_b);
        assert_eq!(err_a, err_b);
    }

    #[test]
    fn different_named_field_values_are_not_equal() {
        let a = TrustGrantError::InvalidIdPrefix {
            expected_prefix: "tg_",
        };
        let b = TrustGrantError::InvalidIdPrefix {
            expected_prefix: "tgs_",
        };
        assert_ne!(a, b);
    }

    #[test]
    fn variety_of_variants_are_debug_format() {
        // Confirm Debug is implemented (compile-time check).
        let variants: [TrustGrantError; 4] = [
            TrustGrantError::EmptyAuthorityId,
            TrustGrantError::CanonicalizationFailure,
            TrustGrantError::DuplicateSelector,
            TrustGrantError::InvalidJsonDocument,
        ];
        for variant in &variants {
            let debug = format!("{variant:?}");
            assert!(!debug.is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // Additional Display coverage – unit variants
    // -----------------------------------------------------------------------

    #[test]
    fn signature_verification_failed_display() {
        assert_eq!(
            TrustGrantError::SignatureVerificationFailed.to_string(),
            "trustgrant signature verification failed"
        );
    }

    #[test]
    fn stale_revocation_record_display() {
        assert_eq!(
            TrustGrantError::StaleRevocationRecord.to_string(),
            "revocation evidence is stale at verification time"
        );
    }

    #[test]
    fn missing_authority_discovery_document_display() {
        assert_eq!(
            TrustGrantError::MissingAuthorityDiscoveryDocument.to_string(),
            "authority discovery document is missing from provided verification material"
        );
    }

    #[test]
    fn invalid_ownership_transition_chain_display() {
        assert_eq!(
            TrustGrantError::InvalidOwnershipTransitionChain.to_string(),
            "ownership transition chain is not valid for the resolved lineage"
        );
    }

    #[test]
    fn invalid_json_document_display() {
        assert_eq!(
            TrustGrantError::InvalidJsonDocument.to_string(),
            "trustgrant document JSON is invalid"
        );
    }

    #[test]
    fn canonicalization_failure_display() {
        assert_eq!(
            TrustGrantError::CanonicalizationFailure.to_string(),
            "trustgrant canonicalization failed"
        );
    }

    #[test]
    fn duplicate_selector_display() {
        assert_eq!(
            TrustGrantError::DuplicateSelector.to_string(),
            "duplicate selector is not allowed"
        );
    }

    #[test]
    fn duplicate_key_id_display() {
        assert_eq!(
            TrustGrantError::DuplicateKeyId.to_string(),
            "duplicate key id is not allowed"
        );
    }

    #[test]
    fn duplicate_operation_name_display() {
        assert_eq!(
            TrustGrantError::DuplicateOperationName.to_string(),
            "duplicate operation name is not allowed"
        );
    }

    #[test]
    fn invalid_discovery_document_display() {
        assert_eq!(
            TrustGrantError::InvalidDiscoveryDocument.to_string(),
            "authority discovery document JSON is invalid"
        );
    }

    #[test]
    fn invalid_delegated_principal_document_display() {
        assert_eq!(
            TrustGrantError::InvalidDelegatedPrincipalDocument.to_string(),
            "delegated principal key document JSON is invalid"
        );
    }

    #[test]
    fn invalid_revocation_proof_document_display() {
        assert_eq!(
            TrustGrantError::InvalidRevocationProofDocument.to_string(),
            "revocation proof JSON is invalid"
        );
    }

    #[test]
    fn invalid_ownership_transition_document_display() {
        assert_eq!(
            TrustGrantError::InvalidOwnershipTransitionDocument.to_string(),
            "ownership transition JSON is invalid"
        );
    }

    #[test]
    fn signer_authority_mismatch_display() {
        assert_eq!(
            TrustGrantError::SignerAuthorityMismatch.to_string(),
            "resolved signer authority does not match the document issuer authority"
        );
    }

    #[test]
    fn key_id_mismatch_display() {
        assert_eq!(
            TrustGrantError::KeyIdMismatch.to_string(),
            "resolved signer key id does not match the document key id"
        );
    }

    #[test]
    fn discovery_authority_mismatch_display() {
        assert_eq!(
            TrustGrantError::DiscoveryAuthorityMismatch.to_string(),
            "authority discovery document authority does not match the expected issuer authority"
        );
    }

    #[test]
    fn missing_signing_key_display() {
        assert_eq!(
            TrustGrantError::MissingSigningKey.to_string(),
            "requested signing key is missing from resolved authority discovery material"
        );
    }

    #[test]
    fn delegation_not_supported_display() {
        assert_eq!(
            TrustGrantError::DelegationNotSupported.to_string(),
            "delegated principal key lookup is not supported by this authority"
        );
    }

    #[test]
    fn missing_revocation_proof_display() {
        assert_eq!(
            TrustGrantError::MissingRevocationProof.to_string(),
            "revocation proof is missing from provided verification material"
        );
    }

    #[test]
    fn revocation_proof_grant_mismatch_display() {
        assert_eq!(
            TrustGrantError::RevocationProofGrantMismatch.to_string(),
            "revocation proof does not match the requested trustgrant"
        );
    }

    #[test]
    fn signer_key_inactive_display() {
        assert_eq!(
            TrustGrantError::SignerKeyInactive.to_string(),
            "resolved signer key is not active at verification time"
        );
    }

    #[test]
    fn signature_profile_mismatch_display() {
        assert_eq!(
            TrustGrantError::SignatureProfileMismatch.to_string(),
            "resolved signature profile does not match the canonicalization profile"
        );
    }

    #[test]
    fn issuer_principal_mismatch_display() {
        assert_eq!(
            TrustGrantError::IssuerPrincipalMismatch.to_string(),
            "issuer principal binding does not match the signed document"
        );
    }

    #[test]
    fn invalid_time_window_display() {
        assert_eq!(
            TrustGrantError::InvalidTimeWindow.to_string(),
            "time window must have not_before before or equal to not_after"
        );
    }

    #[test]
    fn zero_revision_display() {
        assert_eq!(
            TrustGrantError::ZeroRevision.to_string(),
            "revision must be greater than zero"
        );
    }

    #[test]
    fn missing_id_separator_display() {
        assert_eq!(
            TrustGrantError::MissingIdSeparator.to_string(),
            "prefixed ID must contain an underscore separator"
        );
    }

    #[test]
    fn invalid_id_uuid_display() {
        assert_eq!(
            TrustGrantError::InvalidIdUuid.to_string(),
            "prefixed ID does not contain a valid UUID"
        );
    }

    #[test]
    fn self_supersession_display() {
        assert_eq!(
            TrustGrantError::SelfSupersession.to_string(),
            "grant lineage must not supersede the same document"
        );
    }

    #[test]
    fn invalid_scope_shape_display() {
        assert_eq!(
            TrustGrantError::InvalidScopeShape("target_scope").to_string(),
            "scope `target_scope` has an invalid all/allow shape"
        );
    }

    #[test]
    fn invalid_selector_shape_display() {
        assert_eq!(
            TrustGrantError::InvalidSelectorShape.to_string(),
            "selector has an invalid all/values/expressions shape"
        );
    }

    #[test]
    fn invalid_selector_expression_syntax_display() {
        assert_eq!(
            TrustGrantError::InvalidSelectorExpressionSyntax.to_string(),
            "selector expression has invalid syntax"
        );
    }

    #[test]
    fn invalid_protocol_version_display() {
        assert_eq!(
            TrustGrantError::InvalidProtocolVersion(99).to_string(),
            "unsupported protocol version `99`"
        );
    }

    #[test]
    fn invalid_revocation_freshness_window_display() {
        assert_eq!(
            TrustGrantError::InvalidRevocationFreshnessWindow.to_string(),
            "revocation freshness window must have checked_at before or equal to fresh_until"
        );
    }

    #[test]
    fn invalid_revocation_policy_display() {
        assert_eq!(
            TrustGrantError::InvalidRevocationPolicy.to_string(),
            "revocation freshness policy must use strictly positive TTL values"
        );
    }

    // -----------------------------------------------------------------------
    // Additional Display coverage – tuple variants
    // -----------------------------------------------------------------------

    #[test]
    fn unsupported_selector_expression_predicate_display() {
        let err = TrustGrantError::UnsupportedSelectorExpressionPredicate("regex".to_owned());
        assert_eq!(
            err.to_string(),
            "selector expression uses unsupported predicate `regex`"
        );
    }

    #[test]
    fn conflicting_proof_bundle_entry_display() {
        let err = TrustGrantError::ConflictingProofBundleEntry("discovery");
        assert_eq!(
            err.to_string(),
            "proof bundle entry `discovery` conflicts with an existing entry"
        );
    }

    #[test]
    fn invalid_persisted_verified_grant_record_display() {
        let err = TrustGrantError::InvalidPersistedVerifiedGrantRecord("revocation_endpoint");
        assert_eq!(
            err.to_string(),
            "persisted verified-grant record field `revocation_endpoint` is invalid"
        );
    }

    #[test]
    fn unsupported_persisted_verified_grant_record_version_display() {
        assert_eq!(
            TrustGrantError::UnsupportedPersistedVerifiedGrantRecordVersion(42).to_string(),
            "unsupported persisted verified-grant record version `42`"
        );
    }

    // -----------------------------------------------------------------------
    // Additional Display coverage – named-field variants
    // -----------------------------------------------------------------------

    #[test]
    fn string_too_long_display() {
        let err = TrustGrantError::StringTooLong {
            field: "key_id",
            max_bytes: 128,
        };
        assert_eq!(
            err.to_string(),
            "field `key_id` exceeds the maximum size of 128 bytes"
        );
    }

    #[test]
    fn invalid_string_field_character_named_display() {
        let err = TrustGrantError::InvalidStringFieldCharacter {
            field: "authority_id",
            character: ' ',
        };
        assert_eq!(
            err.to_string(),
            "field `authority_id` contains invalid character ` `"
        );
    }

    #[test]
    fn missing_ownership_transition_chain_display() {
        assert_eq!(
            TrustGrantError::MissingOwnershipTransitionChain.to_string(),
            "ownership transition chain is required when active owning authority differs from origin authority"
        );
    }

    #[test]
    fn ownership_transition_origin_mismatch_display() {
        assert_eq!(
            TrustGrantError::OwnershipTransitionOriginMismatch.to_string(),
            "ownership transition chain contains an incompatible origin authority"
        );
    }

    #[test]
    fn ownership_transition_scope_mismatch_display() {
        assert_eq!(
            TrustGrantError::OwnershipTransitionScopeMismatch.to_string(),
            "ownership transition scope does not cover the document resource scope"
        );
    }

    #[test]
    fn ownership_transition_active_owner_mismatch_display() {
        assert_eq!(
            TrustGrantError::OwnershipTransitionActiveOwnerMismatch.to_string(),
            "ownership transition chain does not resolve to the document active owning authority"
        );
    }

    #[test]
    fn ownership_origin_mismatch_display() {
        assert_eq!(
            TrustGrantError::OwnershipOriginMismatch.to_string(),
            "resolved ownership origin authority does not match the document origin authority"
        );
    }

    #[test]
    fn active_owning_authority_mismatch_display() {
        assert_eq!(
            TrustGrantError::ActiveOwningAuthorityMismatch.to_string(),
            "resolved active owning authority does not match the document active owning authority"
        );
    }

    #[test]
    fn delegated_discovery_authority_mismatch_display() {
        assert_eq!(
            TrustGrantError::DelegatedDiscoveryAuthorityMismatch.to_string(),
            "delegated principal key document authority does not match the expected issuer authority"
        );
    }

    #[test]
    fn delegated_principal_mismatch_display() {
        assert_eq!(
            TrustGrantError::DelegatedPrincipalMismatch.to_string(),
            "delegated principal key document principal does not match the signed document issuer principal"
        );
    }

    #[test]
    fn missing_delegated_principal_document_display() {
        assert_eq!(
            TrustGrantError::MissingDelegatedPrincipalDocument.to_string(),
            "delegated principal key document is missing from provided verification material"
        );
    }

    #[test]
    fn insufficient_revocation_proof_finality_display() {
        assert_eq!(
            TrustGrantError::InsufficientRevocationProofFinality.to_string(),
            "revocation evidence does not satisfy the required proof finality"
        );
    }

    #[test]
    fn verification_posture_requires_non_live_revocation_display() {
        assert_eq!(
            TrustGrantError::VerificationPostureRequiresNonLiveRevocation.to_string(),
            "the selected verification posture requires non-live revocation evidence"
        );
    }

    #[test]
    fn unexpected_revocation_proof_for_non_revocable_grant_display() {
        assert_eq!(
            TrustGrantError::UnexpectedRevocationProofForNonRevocableGrant.to_string(),
            "non-revocable trustgrant must not carry revocation proof state"
        );
    }

    #[test]
    fn invalid_ownership_transition_parties_display() {
        assert_eq!(
            TrustGrantError::InvalidOwnershipTransitionParties.to_string(),
            "ownership transition from and to authorities must differ"
        );
    }

    #[test]
    fn invalid_ownership_transition_scope_display() {
        assert_eq!(
            TrustGrantError::InvalidOwnershipTransitionScope.to_string(),
            "ownership transition requires an explicit finite resource scope"
        );
    }

    #[test]
    fn invalid_ownership_transition_effective_at_display() {
        assert_eq!(
            TrustGrantError::InvalidOwnershipTransitionEffectiveAt.to_string(),
            "ownership transition effective_at must fall within the declared time window"
        );
    }

    #[test]
    fn invalid_ownership_transition_acceptance_time_display() {
        assert_eq!(
            TrustGrantError::InvalidOwnershipTransitionAcceptanceTime.to_string(),
            "ownership transition acceptance timestamp must not be in the future"
        );
    }

    #[test]
    fn unsupported_v0_wire_supersession_policy_display() {
        assert_eq!(
            TrustGrantError::UnsupportedV0WireSupersessionPolicy.to_string(),
            "supersession policy cannot be converted to the v0 wire contract"
        );
    }

    #[test]
    fn invalid_key_validity_window_display() {
        assert_eq!(
            TrustGrantError::InvalidKeyValidityWindow.to_string(),
            "key validity window must have not_before before or equal to not_after"
        );
    }

    #[test]
    fn invalid_supersedes_for_first_revision_display() {
        assert_eq!(
            TrustGrantError::InvalidSupersedesForFirstRevision.to_string(),
            "revision one must not declare supersedes"
        );
    }

    #[test]
    fn missing_supersedes_for_non_first_ownership_transition_revision_display() {
        assert_eq!(
            TrustGrantError::MissingSupersedesForNonFirstOwnershipTransitionRevision.to_string(),
            "non-first ownership transition revisions must declare supersedes_transition_id"
        );
    }

    #[test]
    fn ownership_transition_predecessor_signature_failed_display() {
        assert_eq!(
            TrustGrantError::OwnershipTransitionPredecessorSignatureFailed.to_string(),
            "ownership transition predecessor signature verification failed"
        );
    }

    #[test]
    fn ownership_transition_successor_signature_failed_display() {
        assert_eq!(
            TrustGrantError::OwnershipTransitionSuccessorSignatureFailed.to_string(),
            "ownership transition successor acceptance signature verification failed"
        );
    }

    #[test]
    fn invalid_authority_id_character_display() {
        assert_eq!(
            TrustGrantError::InvalidAuthorityIdCharacter('#').to_string(),
            "authority ID contains invalid character `#`"
        );
    }

    #[test]
    fn invalid_authority_id_missing_scheme_display() {
        assert_eq!(
            TrustGrantError::InvalidAuthorityIdMissingScheme.to_string(),
            "authority ID must include a non-empty scheme prefix"
        );
    }

    // -----------------------------------------------------------------------
    // Exhaustive count check – make sure every variant has a Display string
    // -----------------------------------------------------------------------

    #[test]
    fn every_variant_has_nonempty_display() {
        // This array should grow as new variants are added.
        // If it fails, you added a variant without a #[error("...")] or
        // forgot to add it to this list.
        let all_variants: Vec<TrustGrantError> = vec![
            TrustGrantError::EmptyAuthorityId,
            TrustGrantError::EmptyStringField("x"),
            TrustGrantError::InvalidStringFieldCharacter {
                field: "x",
                character: '!',
            },
            TrustGrantError::InvalidAuthorityIdCharacter('!'),
            TrustGrantError::InvalidAuthorityIdMissingScheme,
            TrustGrantError::InvalidScopeShape("x"),
            TrustGrantError::InvalidSelectorShape,
            TrustGrantError::UnsupportedSelectorExpressionPredicate("x".into()),
            TrustGrantError::InvalidSelectorExpressionSyntax,
            TrustGrantError::DocumentTooLarge {
                document: "x",
                max_bytes: 1,
            },
            TrustGrantError::CollectionTooLarge {
                field: "x",
                max_items: 1,
            },
            TrustGrantError::StringTooLong {
                field: "x",
                max_bytes: 1,
            },
            TrustGrantError::DuplicateSelector,
            TrustGrantError::DuplicateKeyId,
            TrustGrantError::DuplicateOperationName,
            TrustGrantError::ReservedOperationName,
            TrustGrantError::InvalidJsonDocument,
            TrustGrantError::CanonicalizationFailure,
            TrustGrantError::InvalidDiscoveryDocument,
            TrustGrantError::InvalidDelegatedPrincipalDocument,
            TrustGrantError::InvalidRevocationProofDocument,
            TrustGrantError::InvalidOwnershipTransitionDocument,
            TrustGrantError::SignatureVerificationFailed,
            TrustGrantError::OwnershipTransitionPredecessorSignatureFailed,
            TrustGrantError::OwnershipTransitionSuccessorSignatureFailed,
            TrustGrantError::SignerAuthorityMismatch,
            TrustGrantError::KeyIdMismatch,
            TrustGrantError::DiscoveryAuthorityMismatch,
            TrustGrantError::DelegatedDiscoveryAuthorityMismatch,
            TrustGrantError::MissingSigningKey,
            TrustGrantError::DelegationNotSupported,
            TrustGrantError::DelegatedPrincipalMismatch,
            TrustGrantError::OwnershipOriginMismatch,
            TrustGrantError::ActiveOwningAuthorityMismatch,
            TrustGrantError::MissingOwnershipTransitionChain,
            TrustGrantError::OwnershipTransitionOriginMismatch,
            TrustGrantError::OwnershipTransitionActiveOwnerMismatch,
            TrustGrantError::InvalidOwnershipTransitionChain,
            TrustGrantError::OwnershipTransitionScopeMismatch,
            TrustGrantError::SignerKeyInactive,
            TrustGrantError::SignatureProfileMismatch,
            TrustGrantError::IssuerPrincipalMismatch,
            TrustGrantError::InvalidRevocationFreshnessWindow,
            TrustGrantError::InvalidRevocationPolicy,
            TrustGrantError::StaleRevocationRecord,
            TrustGrantError::InsufficientRevocationProofFinality,
            TrustGrantError::VerificationPostureRequiresNonLiveRevocation,
            TrustGrantError::MissingAuthorityDiscoveryDocument,
            TrustGrantError::MissingDelegatedPrincipalDocument,
            TrustGrantError::MissingRevocationProof,
            TrustGrantError::RevocationProofGrantMismatch,
            TrustGrantError::ConflictingProofBundleEntry("x"),
            TrustGrantError::UnexpectedRevocationProofForNonRevocableGrant,
            TrustGrantError::MissingIdSeparator,
            TrustGrantError::InvalidIdPrefix {
                expected_prefix: "x",
            },
            TrustGrantError::InvalidIdUuid,
            TrustGrantError::InvalidProtocolVersion(0),
            TrustGrantError::InvalidSupersedesForFirstRevision,
            TrustGrantError::MissingSupersedesForNonFirstOwnershipTransitionRevision,
            TrustGrantError::SelfSupersession,
            TrustGrantError::InvalidOwnershipTransitionParties,
            TrustGrantError::InvalidOwnershipTransitionScope,
            TrustGrantError::InvalidOwnershipTransitionEffectiveAt,
            TrustGrantError::InvalidOwnershipTransitionAcceptanceTime,
            TrustGrantError::UnsupportedV0WireSupersessionPolicy,
            TrustGrantError::InvalidPersistedVerifiedGrantRecord("x"),
            TrustGrantError::UnsupportedPersistedVerifiedGrantRecordVersion(0),
            TrustGrantError::InvalidTimeWindow,
            TrustGrantError::InvalidKeyValidityWindow,
            TrustGrantError::ZeroRevision,
        ];

        for variant in &all_variants {
            let display = variant.to_string();
            assert!(
                !display.is_empty(),
                "variant should have a non-empty Display string: {variant:?}"
            );
        }
    }
}
