use trustgrant_discovery::{
    AuthorityDiscoveryDocument, DelegatedPrincipalKeyDocument, DelegatedPrincipalRef,
};
use trustgrant_domain::AuthorityId;
use trustgrant_error::TrustGrantError;

use crate::VerificationContext;

/// Optional port for fetching raw discovery documents from authority endpoints.
///
/// You do NOT need to implement this trait if you already have the discovery
/// documents as structured domain types. The protocol core works with
/// [`AuthorityDiscoveryDocument`] and [`DelegatedPrincipalKeyDocument`] directly
/// via [`TrustGrantProofBundle`].
///
/// Implement this trait only when your application fetches raw JSON from
/// authority endpoints and needs a standard contract for that transport layer.
///
/// # Relationship to [`AuthorityDiscoverySource`]
///
/// - [`DiscoverySource`] — fetches raw JSON documents from authority endpoints.
///   Optional. Used by the **application** to assemble proof bundles.
/// - [`AuthorityDiscoverySource`](crate::AuthorityDiscoverySource) — resolves
///   signer bindings from already-fetched documents. Used by the **verification
///   pipeline** via [`VerificationSources`](crate::VerificationSources).
///
/// # Example (mock)
///
/// ```rust,ignore
/// use trustgrant_ports::{DiscoverySource, VerificationContext};
/// # use trustgrant_domain::AuthorityId;
/// # use trustgrant_discovery::DelegatedPrincipalRef;
///
/// struct MockDiscovery;
///
/// impl DiscoverySource for MockDiscovery {
///     fn fetch_authority_discovery(
///         &self,
///         authority: &AuthorityId,
///         context: VerificationContext,
///     ) -> Result<AuthorityDiscoveryDocument, TrustGrantError> {
///         Err(TrustGrantError::MissingAuthorityDiscoveryDocument)
///     }
///
///     fn fetch_delegated_principal(
///         &self,
///         authority: &AuthorityId,
///         principal: &DelegatedPrincipalRef,
///         context: VerificationContext,
///     ) -> Result<DelegatedPrincipalKeyDocument, TrustGrantError> {
///         Err(TrustGrantError::MissingDelegatedPrincipalDocument)
///     }
/// }
/// ```
pub trait DiscoverySource {
    /// Fetches the authority discovery document for one authority.
    ///
    /// The document contains the authority's signing keys, signature profile,
    /// revocation policy, and delegation configuration.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError::MissingAuthorityDiscoveryDocument`] when the
    /// document cannot be fetched, or [`TrustGrantError::InvalidDiscoveryDocument`]
    /// when the response cannot be parsed.
    fn fetch_authority_discovery(
        &self,
        authority: &AuthorityId,
        context: VerificationContext,
    ) -> Result<AuthorityDiscoveryDocument, TrustGrantError>;

    /// Fetches the delegated principal key document for one principal.
    ///
    /// The document contains the principal's signing keys scoped under a
    /// specific authority that supports delegation.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError::MissingDelegatedPrincipalDocument`] when the
    /// document cannot be fetched.
    fn fetch_delegated_principal(
        &self,
        authority: &AuthorityId,
        principal: &DelegatedPrincipalRef,
        context: VerificationContext,
    ) -> Result<DelegatedPrincipalKeyDocument, TrustGrantError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use trustgrant_domain::AuthorityId;
    use trustgrant_error::TrustGrantError;
    use crate::VerificationContext;
    use chrono::{TimeZone, Utc};

    struct MockDiscovery;

    impl DiscoverySource for MockDiscovery {
        fn fetch_authority_discovery(
            &self,
            _: &AuthorityId,
            _: VerificationContext,
        ) -> Result<AuthorityDiscoveryDocument, TrustGrantError> {
            Err(TrustGrantError::MissingAuthorityDiscoveryDocument)
        }

        fn fetch_delegated_principal(
            &self,
            _: &AuthorityId,
            _: &DelegatedPrincipalRef,
            _: VerificationContext,
        ) -> Result<DelegatedPrincipalKeyDocument, TrustGrantError> {
            Err(TrustGrantError::MissingDelegatedPrincipalDocument)
        }
    }

    fn ctx() -> VerificationContext {
        VerificationContext::new(
            Utc.with_ymd_and_hms(2026, 4, 7, 12, 0, 0).single().unwrap(),
            crate::VerificationPosture::Online,
        )
    }

    #[test]
    fn mock_discovery_returns_not_found_for_authority() {
        let source = MockDiscovery;
        let authority =
            AuthorityId::new("https://issuer.example.com").unwrap();
        let result = source.fetch_authority_discovery(&authority, ctx());
        assert_eq!(
            result,
            Err(TrustGrantError::MissingAuthorityDiscoveryDocument)
        );
    }

    #[test]
    fn mock_discovery_returns_not_found_for_principal() {
        use trustgrant_discovery::DelegatedPrincipalRef;
        let source = MockDiscovery;
        let authority =
            AuthorityId::new("https://issuer.example.com").unwrap();
        let principal =
            DelegatedPrincipalRef::new("service", "issuer-worker").unwrap();
        let result =
            source.fetch_delegated_principal(&authority, &principal, ctx());
        assert_eq!(
            result,
            Err(TrustGrantError::MissingDelegatedPrincipalDocument)
        );
    }
}
