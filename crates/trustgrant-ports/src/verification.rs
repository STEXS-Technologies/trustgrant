use chrono::{DateTime, Utc};

use trustgrant_discovery::ResolvedSignerBinding;
use trustgrant_document::RawOwnershipTransitionDocument;
use trustgrant_document::{ValidatedPrincipal, ValidatedTrustGrantDocument};
use trustgrant_domain::{AuthorityId, KeyId};
use trustgrant_error::TrustGrantError;
use trustgrant_revocation::RevocationRecord;

use super::signature::VerificationPosture;

/// Temporal and policy context for one verification call.
///
/// Carries the effective verification timestamp and the
/// [`VerificationPosture`] that governs which proof sources to consult.
/// All verification entry points in the TrustGrant core accept this
/// context to ensure consistent time-based and posture-aware evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationContext {
    verified_at: DateTime<Utc>,
    posture: VerificationPosture,
}

/// One assembled set of proof sources for a single verification call.
///
/// Groups the three proof-source traits that the verification pipeline
/// needs: authority discovery, revocation proof, and ownership transition
/// proof. Created by the surrounding adapter after any multi-source
/// reconciliation, then passed to the pipeline's source-driven entry
/// points.
#[derive(Clone, Copy)]
pub struct VerificationSources<'source> {
    discovery_source: &'source dyn AuthorityDiscoverySource,
    revocation_source: &'source dyn RevocationProofSource,
    ownership_source: &'source dyn OwnershipTransitionProofSource,
}

impl<'source> VerificationSources<'source> {
    /// Creates one already-selected proof-source set for a single verification
    /// call.
    ///
    /// The TrustGrant core does not merge mirrored sources or arbitrate
    /// conflicting proof inputs. If a deployment wants multi-source
    /// reconciliation, that must happen before constructing this value.
    #[must_use]
    pub const fn new(
        discovery_source: &'source dyn AuthorityDiscoverySource,
        revocation_source: &'source dyn RevocationProofSource,
        ownership_source: &'source dyn OwnershipTransitionProofSource,
    ) -> Self {
        Self {
            discovery_source,
            revocation_source,
            ownership_source,
        }
    }

    /// Discovery source is required for signer resolution.
    #[must_use]
    pub const fn discovery_source(&self) -> &'source dyn AuthorityDiscoverySource {
        self.discovery_source
    }

    /// Revocation source is required for revocation proof resolution.
    #[must_use]
    pub const fn revocation_source(&self) -> &'source dyn RevocationProofSource {
        self.revocation_source
    }

    /// Ownership source is required for ownership proof resolution.
    #[must_use]
    pub const fn ownership_source(&self) -> &'source dyn OwnershipTransitionProofSource {
        self.ownership_source
    }
}

impl VerificationContext {
    /// Verification context is required to resolve proof inputs.
    #[must_use]
    pub const fn new(verified_at: DateTime<Utc>, posture: VerificationPosture) -> Self {
        Self {
            verified_at,
            posture,
        }
    }

    /// Verified_at is required for key and proof freshness checks.
    #[must_use]
    pub const fn verified_at(&self) -> DateTime<Utc> {
        self.verified_at
    }

    /// Posture is required for proof-source policy.
    #[must_use]
    pub const fn posture(&self) -> VerificationPosture {
        self.posture
    }
}

pub trait AuthorityDiscoverySource {
    /// Resolves signer material for one validated TrustGrant signer.
    ///
    /// The surrounding adapter is expected to choose one final authoritative
    /// discovery source set before calling this port.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when signer material cannot be resolved or
    /// is not acceptable to the caller.
    fn resolve_signer_binding(
        &self,
        issuer_authority: &AuthorityId,
        key_id: &KeyId,
        issuer_principal: Option<&ValidatedPrincipal>,
        context: VerificationContext,
    ) -> Result<ResolvedSignerBinding, TrustGrantError>;
}

pub trait RevocationProofSource {
    /// Resolves revocation state for one validated TrustGrant.
    ///
    /// The surrounding adapter is expected to choose one final authoritative
    /// revocation source set before calling this port.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when revocation proof resolution fails.
    fn resolve_revocation_record(
        &self,
        document: &ValidatedTrustGrantDocument,
        signer_binding: &ResolvedSignerBinding,
        context: VerificationContext,
    ) -> Result<RevocationRecord, TrustGrantError>;
}

pub trait OwnershipTransitionProofSource {
    /// Resolves accepted ownership-transition proof documents for one validated
    /// TrustGrant.
    ///
    /// The surrounding adapter is expected to choose one final authoritative
    /// ownership-proof source set before calling this port.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when ownership proof resolution fails.
    fn resolve_ownership_transition_chain(
        &self,
        document: &ValidatedTrustGrantDocument,
        context: VerificationContext,
    ) -> Result<Vec<RawOwnershipTransitionDocument>, TrustGrantError>;
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use std::ptr;

    use trustgrant_discovery::ResolvedSignerBinding;
    use trustgrant_document::{
        RawOwnershipTransitionDocument, ValidatedPrincipal, ValidatedTrustGrantDocument,
    };
    use trustgrant_domain::{AuthorityId, KeyId};
    use trustgrant_error::TrustGrantError;
    use trustgrant_revocation::RevocationRecord;

    use super::{
        AuthorityDiscoverySource, OwnershipTransitionProofSource, RevocationProofSource,
        VerificationContext, VerificationSources,
    };
    use crate::VerificationPosture;

    // ---------------------------------------------------------------------------
    // Mock sources for VerificationSources tests
    // ---------------------------------------------------------------------------

    struct MockDiscoverySource;

    impl AuthorityDiscoverySource for MockDiscoverySource {
        fn resolve_signer_binding(
            &self,
            _: &AuthorityId,
            _: &KeyId,
            _: Option<&ValidatedPrincipal>,
            _: VerificationContext,
        ) -> Result<ResolvedSignerBinding, TrustGrantError> {
            Err(TrustGrantError::MissingSigningKey)
        }
    }

    struct MockRevocationSource;

    impl RevocationProofSource for MockRevocationSource {
        fn resolve_revocation_record(
            &self,
            _: &ValidatedTrustGrantDocument,
            _: &ResolvedSignerBinding,
            _: VerificationContext,
        ) -> Result<RevocationRecord, TrustGrantError> {
            Err(TrustGrantError::MissingRevocationProof)
        }
    }

    struct MockOwnershipSource;

    impl OwnershipTransitionProofSource for MockOwnershipSource {
        fn resolve_ownership_transition_chain(
            &self,
            _: &ValidatedTrustGrantDocument,
            _: VerificationContext,
        ) -> Result<Vec<RawOwnershipTransitionDocument>, TrustGrantError> {
            Err(TrustGrantError::MissingOwnershipTransitionChain)
        }
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    fn timestamp() -> DateTime<Utc> {
        DateTime::from_timestamp_millis(0).unwrap_or(DateTime::UNIX_EPOCH)
    }

    // ---------------------------------------------------------------------------
    // VerificationContext tests
    // ---------------------------------------------------------------------------

    #[test]
    fn verification_context_constructor_creates_with_timestamp_and_posture() {
        let ts = timestamp();
        let posture = VerificationPosture::Online;

        let ctx = VerificationContext::new(ts, posture);

        assert_eq!(ctx.verified_at(), ts);
        assert_eq!(ctx.posture(), posture);
    }

    #[test]
    fn verification_context_verified_at_returns_constructor_timestamp() {
        let ts = timestamp();
        let ctx = VerificationContext::new(ts, VerificationPosture::Cached);

        assert_eq!(ctx.verified_at(), ts);
    }

    #[test]
    fn verification_context_posture_returns_constructor_posture() {
        let posture = VerificationPosture::Offline;
        let ctx = VerificationContext::new(timestamp(), posture);

        assert_eq!(ctx.posture(), posture);
    }

    #[test]
    fn verification_context_debug_and_clone_and_copy_and_eq() {
        let ts = timestamp();
        let posture = VerificationPosture::Online;
        let ctx1 = VerificationContext::new(ts, posture);

        // Clone + Copy: assigning to a new binding is a Copy, not a move
        let ctx2 = ctx1;
        assert_eq!(ctx1, ctx2);

        // Debug does not panic
        let debug_str = format!("{:?}", ctx1);
        assert!(!debug_str.is_empty());

        // PartialEq + Eq: reflexivity, symmetry, transitivity (different instances)
        let posture_alt = VerificationPosture::Offline;
        let ctx3 = VerificationContext::new(ts, posture_alt);
        assert_eq!(ctx1, ctx1);
        assert_eq!(ctx2, ctx1);
        assert_ne!(ctx1, ctx3);
    }

    // ---------------------------------------------------------------------------
    // VerificationSources tests
    // ---------------------------------------------------------------------------

    #[test]
    fn verification_sources_new_creates_sources_object() {
        let discovery = MockDiscoverySource;
        let revocation = MockRevocationSource;
        let ownership = MockOwnershipSource;

        let _sources = VerificationSources::new(&discovery, &revocation, &ownership);
    }

    #[test]
    fn verification_sources_discovery_source_returns_same_reference() {
        let discovery = MockDiscoverySource;
        let revocation = MockRevocationSource;
        let ownership = MockOwnershipSource;

        let sources = VerificationSources::new(&discovery, &revocation, &ownership);

        let returned: &dyn AuthorityDiscoverySource = sources.discovery_source();
        let expected: &dyn AuthorityDiscoverySource = &discovery;

        assert!(ptr::eq(
            returned as *const dyn AuthorityDiscoverySource,
            expected as *const dyn AuthorityDiscoverySource,
        ));
    }

    #[test]
    fn verification_sources_revocation_source_returns_same_reference() {
        let discovery = MockDiscoverySource;
        let revocation = MockRevocationSource;
        let ownership = MockOwnershipSource;

        let sources = VerificationSources::new(&discovery, &revocation, &ownership);

        let returned: &dyn RevocationProofSource = sources.revocation_source();
        let expected: &dyn RevocationProofSource = &revocation;

        assert!(ptr::eq(
            returned as *const dyn RevocationProofSource,
            expected as *const dyn RevocationProofSource,
        ));
    }

    #[test]
    fn verification_sources_ownership_source_returns_same_reference() {
        let discovery = MockDiscoverySource;
        let revocation = MockRevocationSource;
        let ownership = MockOwnershipSource;

        let sources = VerificationSources::new(&discovery, &revocation, &ownership);

        let returned: &dyn OwnershipTransitionProofSource = sources.ownership_source();
        let expected: &dyn OwnershipTransitionProofSource = &ownership;

        assert!(ptr::eq(
            returned as *const dyn OwnershipTransitionProofSource,
            expected as *const dyn OwnershipTransitionProofSource,
        ));
    }
}
