#![forbid(unsafe_code)]

//! Core TrustGrant protocol crate - umbrella re-exports.
//!
//! This crate re-exports all sub-crates for backward compatibility.
//! For granular dependency management, depend on specific sub-crates directly.

pub use trustgrant_discovery as discovery;
pub use trustgrant_document as document;
pub use trustgrant_domain as domain;
pub use trustgrant_error as error;
pub use trustgrant_error::limits;
pub use trustgrant_evaluate as evaluate;
pub use trustgrant_issue as issue;
pub use trustgrant_ownership as ownership;
pub use trustgrant_ports as ports;
pub use trustgrant_revocation as revocation;
pub use trustgrant_verify as verify;

// Re-exports for backward compatibility
pub use discovery::{
    AlgorithmName, AuthorityDiscoveryDocument, AuthorityKeyRecord, CanonicalizationName,
    DelegatedPrincipalKeyDocument, DelegatedPrincipalRef, DiscoveryDelegation,
    DiscoveryRevocationPolicy, PublicKeyMaterial, ResolvedSignerBinding, SignatureFormat,
    SignatureProfile, parse_authority_discovery_document, parse_delegated_principal_key_document,
};
pub use document::{
    OwnershipTransitionAcceptance, OwnershipTransitionSignature, RawOwnershipTransitionAcceptance,
    RawOwnershipTransitionDocument, RawOwnershipTransitionGlobalConstraints,
    RawOwnershipTransitionResourceScope, RawOwnershipTransitionResourceType,
    RawOwnershipTransitionSelector, RawOwnershipTransitionSignature,
    RawOwnershipTransitionTimeWindow, RawTrustGrantDocument, ValidatedAudienceEntry,
    ValidatedCapabilities, ValidatedOperationScope, ValidatedOwnershipTransitionDocument,
    ValidatedPrincipal, ValidatedResourceType, ValidatedScope, ValidatedSelector,
    ValidatedTrustGrantDocument,
};
pub use domain::{
    AuthorityId, AuthorityScheme, CanonicalizationProfile, CustomOperationName, GrantLineage,
    GrantRevision, GrantSeriesId, KeyId, OperationName, OwnershipAuthorityState,
    OwnershipProofKind, OwnershipResourceScope, OwnershipSelector, OwnershipTimeWindow,
    OwnershipTransitionLineage, OwnershipTransitionParties, OwnershipTransitionRecord,
    OwnershipVerificationRecord, PrincipalId, PrincipalKind, ResourceTypeName, SelectorExpression,
    SelectorKind, SelectorPredicate, SupersessionPolicy, TransitionId, TransitionSeriesId,
    TrustGrantId,
};
pub use error::TrustGrantError;
pub use evaluate::{
    EvaluationDecision, EvaluationDenyReason, EvaluationEngine, EvaluationRequest, MintContext,
    RequestedCapability, RequestedOperation, ResourceContext, SelectorContext,
};
pub use issue::{TrustGrantDraft, TrustGrantDraftAuthorities};
pub use ownership::{
    CanonicalOwnershipTransitionBytes, OwnershipChainVerifier,
    OwnershipTransitionVerificationMetadata, OwnershipTransitionVerifier,
    VerifiedOwnershipTransition, canonicalize_transition_acceptance,
    canonicalize_transition_proposal,
};
pub use ports::{
    AuthorityDiscoverySource, DiscoverySource, OwnershipTransitionProofSource,
    RevocationProofSource, RevocationSource, SignatureVerificationRequest, SignatureVerifier,
    StorageSource, StoredGrantId, VerificationContext, VerificationPosture, VerificationSources,
};
pub use revocation::{
    ProofFinality, RevocationFreshnessPolicy, RevocationRecord, RevocationSourceKind,
    RevocationStatus, RevocationStatusProof, VerifiedRevocationState,
    parse_revocation_status_proof,
};
pub use verify::{
    BundleRevocationProof, CanonicalTrustGrantBytes, NormalizedTrustGrantDocument,
    TrustGrantProofBundle, VerificationArtifacts, VerificationMetadata, VerificationPipeline,
    VerificationPolicy, VerifiedTrustGrant, VerifiedTrustGrantRecord, canonicalize_trustgrant,
    ensure_metadata_matches_document,
};
