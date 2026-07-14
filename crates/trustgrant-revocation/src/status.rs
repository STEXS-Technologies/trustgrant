use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use trustgrant_error::TrustGrantError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The finality level of a revocation proof.
///
/// Describes how conclusive the proof is, from an unknown state through
/// to cryptographically finalized (e.g. on-chain settlement).
pub enum ProofFinality {
    /// No finality information is available.
    Unknown,
    /// The proof was observed from a live endpoint response.
    ///
    /// Indicates the revocation status was obtained by calling an
    /// authority's revocation endpoint at a point in time.
    Observed,
    /// The proof comes from a trusted snapshot.
    ///
    /// Suitable for offline or cached verification where the snapshot
    /// is considered authoritative by the verifier's policy.
    TrustedSnapshot,
    /// The proof is cryptographically finalized.
    ///
    /// The revocation status has been settled on a blockchain or other
    /// finality-providing layer and cannot be reversed.
    Finalized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The kind of source that produced a revocation proof.
///
/// Distinguishes between live API responses, static snapshots, embedded
/// proof bundles, on-chain state, and other sources. Used by the
/// verification pipeline to apply posture-aware freshness policies.
pub enum RevocationSourceKind {
    /// Live response from an authority's revocation API endpoint.
    Api,
    /// Static revocation snapshot (e.g. a pre-compiled list).
    Snapshot,
    /// Revocation proof embedded in a proof bundle.
    ProofBundle,
    /// On-chain revocation state (e.g. a smart contract).
    ChainState,
    /// Any other source not covered by the above variants.
    Other,
}

impl RevocationSourceKind {
    /// Verification posture policy must distinguish live from non-live evidence.
    #[must_use]
    pub const fn is_non_live(self) -> bool {
        matches!(self, Self::Snapshot | Self::ProofBundle)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRecord {
    status: RevocationStatus,
    source_kind: RevocationSourceKind,
    finality: ProofFinality,
    checked_at: DateTime<Utc>,
    fresh_until: DateTime<Utc>,
}

impl RevocationRecord {
    /// Creates one revocation record with explicit freshness bounds.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the freshness window is inverted.
    pub fn new(
        status: RevocationStatus,
        source_kind: RevocationSourceKind,
        finality: ProofFinality,
        checked_at: DateTime<Utc>,
        fresh_until: DateTime<Utc>,
    ) -> Result<Self, TrustGrantError> {
        if checked_at > fresh_until {
            return Err(TrustGrantError::InvalidRevocationFreshnessWindow);
        }

        Ok(Self {
            status,
            source_kind,
            finality,
            checked_at,
            fresh_until,
        })
    }

    /// Revocation status is required for evaluation and audit.
    #[must_use]
    pub const fn status(&self) -> RevocationStatus {
        self.status
    }

    /// Revocation source kind is required for audit and policy.
    #[must_use]
    pub const fn source_kind(&self) -> RevocationSourceKind {
        self.source_kind
    }

    /// Proof finality is required for posture-aware verification.
    #[must_use]
    pub const fn finality(&self) -> ProofFinality {
        self.finality
    }

    /// Revocation checked_at is required for audit.
    #[must_use]
    pub const fn checked_at(&self) -> DateTime<Utc> {
        self.checked_at
    }

    /// Revocation freshness must be inspected by callers.
    #[must_use]
    pub const fn fresh_until(&self) -> DateTime<Utc> {
        self.fresh_until
    }

    /// Revocation freshness is required for safe cached verification.
    #[must_use]
    pub fn is_fresh_at(&self, timestamp: DateTime<Utc>) -> bool {
        timestamp <= self.fresh_until
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The resolved revocation state after verification.
///
/// Indicates whether the TrustGrant is non-revocable (revocation was
/// never configured) or has been checked against a revocation source
/// and produced a [`RevocationRecord`].
pub enum VerifiedRevocationState {
    /// The grant is non-revocable — no revocation proof was required.
    NonRevocable,
    /// The grant was checked and a revocation record was produced.
    Checked(RevocationRecord),
}

impl VerifiedRevocationState {
    /// Verification must know whether revocation proof was required.
    #[must_use]
    pub const fn checked_record(self) -> Option<RevocationRecord> {
        match self {
            Self::NonRevocable => None,
            Self::Checked(record) => Some(record),
        }
    }

    /// Evaluation must know whether the checked grant was revoked.
    #[must_use]
    pub fn is_revoked(self) -> bool {
        match self {
            Self::NonRevocable => false,
            Self::Checked(record) => record.status() == RevocationStatus::Revoked,
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::{ProofFinality, RevocationRecord, RevocationSourceKind, RevocationStatus};

    #[test]
    fn revocation_record_rejects_inverted_freshness_window() {
        let result = RevocationRecord::new(
            RevocationStatus::Active,
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            fixed_timestamp(2026, 4, 7, 12, 5, 0),
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        );

        assert!(result.is_err());
    }

    #[test]
    fn revocation_record_reports_freshness() {
        let record = match RevocationRecord::new(
            RevocationStatus::Active,
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            fixed_timestamp(2026, 4, 7, 12, 5, 0),
        ) {
            Ok(value) => value,
            Err(error) => panic!("revocation record should be valid: {error}"),
        };

        assert!(record.is_fresh_at(fixed_timestamp(2026, 4, 7, 12, 4, 59)));
        assert!(!record.is_fresh_at(fixed_timestamp(2026, 4, 7, 12, 5, 1)));
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

    #[test]
    fn non_revocable_state_is_not_revoked() {
        let state = super::VerifiedRevocationState::NonRevocable;
        assert!(!state.is_revoked());
    }

    #[test]
    fn non_revocable_state_checked_record_is_none() {
        let state = super::VerifiedRevocationState::NonRevocable;
        assert!(state.checked_record().is_none());
    }

    #[test]
    fn checked_state_with_revoked_status_is_revoked() {
        let record = RevocationRecord::new(
            RevocationStatus::Revoked,
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            fixed_timestamp(2026, 4, 7, 12, 5, 0),
        )
        .unwrap_or_else(|error| panic!("revocation record should be valid: {error}"));

        let state = super::VerifiedRevocationState::Checked(record);
        assert!(state.is_revoked());
    }

    #[test]
    fn checked_state_with_active_status_is_not_revoked() {
        let record = RevocationRecord::new(
            RevocationStatus::Active,
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            fixed_timestamp(2026, 4, 7, 12, 5, 0),
        )
        .unwrap_or_else(|error| panic!("revocation record should be valid: {error}"));

        let state = super::VerifiedRevocationState::Checked(record);
        assert!(!state.is_revoked());
    }

    // --- T2: is_non_live tests ---

    #[test]
    fn revocation_source_kind_is_non_live_snapshot_is_non_live() {
        assert!(RevocationSourceKind::Snapshot.is_non_live());
    }

    #[test]
    fn revocation_source_kind_is_non_live_proof_bundle_is_non_live() {
        assert!(RevocationSourceKind::ProofBundle.is_non_live());
    }

    #[test]
    fn revocation_source_kind_is_non_live_api_is_live() {
        assert!(!RevocationSourceKind::Api.is_non_live());
    }

    #[test]
    fn revocation_source_kind_is_non_live_other_is_not_non_live() {
        assert!(!RevocationSourceKind::Other.is_non_live());
    }

    // --- T3: serde round-trip tests ---

    #[test]
    fn revocation_status_serde_round_trip() {
        let cases = [RevocationStatus::Active, RevocationStatus::Revoked];
        for status in &cases {
            let json = serde_json::to_string(status)
                .unwrap_or_else(|e| panic!("serialize RevocationStatus failed: {e}"));
            let deserialized: RevocationStatus = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("deserialize RevocationStatus failed: {e}"));
            assert_eq!(*status, deserialized);
        }
    }

    #[test]
    fn revocation_source_kind_serde_round_trip() {
        let cases = [
            RevocationSourceKind::Api,
            RevocationSourceKind::Snapshot,
            RevocationSourceKind::ProofBundle,
            RevocationSourceKind::ChainState,
            RevocationSourceKind::Other,
        ];
        for kind in &cases {
            let json = serde_json::to_string(kind)
                .unwrap_or_else(|e| panic!("serialize RevocationSourceKind failed: {e}"));
            let deserialized: RevocationSourceKind = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("deserialize RevocationSourceKind failed: {e}"));
            assert_eq!(*kind, deserialized);
        }
    }

    #[test]
    fn proof_finality_serde_round_trip() {
        let cases = [ProofFinality::Observed, ProofFinality::Finalized];
        for finality in &cases {
            let json = serde_json::to_string(finality)
                .unwrap_or_else(|e| panic!("serialize ProofFinality failed: {e}"));
            let deserialized: ProofFinality = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("deserialize ProofFinality failed: {e}"));
            assert_eq!(*finality, deserialized);
        }
    }

    // --- existing tests below ---

    #[test]
    fn checked_state_returns_some_record() {
        let record = RevocationRecord::new(
            RevocationStatus::Active,
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            fixed_timestamp(2026, 4, 7, 12, 5, 0),
        )
        .unwrap_or_else(|error| panic!("revocation record should be valid: {error}"));

        let state = super::VerifiedRevocationState::Checked(record);
        assert!(state.checked_record().is_some());
    }
}
