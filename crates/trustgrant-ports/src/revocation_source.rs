use trustgrant_domain::TrustGrantId;
use trustgrant_error::TrustGrantError;
use trustgrant_revocation::RevocationRecord;

/// Optional port for checking revocation status from a revocation endpoint.
///
/// You do NOT need to implement this trait if you already have the revocation
/// record as a structured domain type. The protocol core works with
/// [`RevocationRecord`] directly via [`TrustGrantProofBundle`].
///
/// Implement this trait only when your application fetches raw revocation
/// status from authority endpoints and needs a standard contract for that
/// transport layer.
///
/// # Relationship to [`RevocationProofSource`]
///
/// - [`RevocationSource`] — fetches raw revocation status from authority
///   endpoints. Optional. Used by the **application** to assemble proof bundles.
/// - [`RevocationProofSource`](crate::RevocationProofSource) — resolves
///   revocation records from already-fetched proofs. Used by the **verification
///   pipeline** via [`VerificationSources`](crate::VerificationSources).
///
/// # Example (mock)
///
/// ```
/// use trustgrant_ports::RevocationSource;
/// use trustgrant_domain::TrustGrantId;
/// use trustgrant_error::TrustGrantError;
/// use trustgrant_revocation::RevocationRecord;
///
/// struct MockRevocation;
///
/// impl RevocationSource for MockRevocation {
///     fn check_revocation(&self, trustgrant_id: &TrustGrantId) -> Result<RevocationRecord, TrustGrantError> {
///         Err(TrustGrantError::MissingRevocationProof)
///     }
/// }
/// ```
pub trait RevocationSource {
    /// Checks the revocation status for one TrustGrant.
    ///
    /// Returns a [`RevocationRecord`] indicating whether the grant is active
    /// or revoked, the source of the proof, and the timestamps for freshness
    /// evaluation.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError::MissingRevocationProof`] when the grant is
    /// revocable but no revocation proof is available. Returns
    /// [`TrustGrantError::RevocationProofGrantMismatch`] when the response
    /// references a different grant.
    fn check_revocation(
        &self,
        trustgrant_id: &TrustGrantId,
    ) -> Result<RevocationRecord, TrustGrantError>;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    use super::*;
    use trustgrant_domain::TrustGrantId;
    use trustgrant_error::TrustGrantError;

    struct MockRevocation;

    impl RevocationSource for MockRevocation {
        fn check_revocation(&self, _: &TrustGrantId) -> Result<RevocationRecord, TrustGrantError> {
            Err(TrustGrantError::MissingRevocationProof)
        }
    }

    #[test]
    fn mock_revocation_returns_missing_proof() {
        let source = MockRevocation;
        let id = "tg_123e4567-e89b-12d3-a456-426614174000"
            .parse::<TrustGrantId>()
            .unwrap_or_else(|error| panic!("failed to parse TrustGrantId: {error}"));
        let result = source.check_revocation(&id);
        assert_eq!(result, Err(TrustGrantError::MissingRevocationProof));
    }
}
