use std::num::NonZeroU64;

use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;

use super::{ProofFinality, RevocationRecord, RevocationSourceKind, RevocationStatus};
use trustgrant_domain::TrustGrantId;
use trustgrant_error::TrustGrantError;
use trustgrant_error::limits::{MAX_REVOCATION_PROOF_JSON_BYTES, ensure_json_size};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationFreshnessPolicy {
    non_revoked_ttl_seconds: NonZeroU64,
    max_stale_seconds: NonZeroU64,
}

impl RevocationFreshnessPolicy {
    /// Creates one revocation freshness policy.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when one of the TTL values is zero.
    pub const fn new(
        non_revoked_ttl_seconds: u64,
        max_stale_seconds: u64,
    ) -> Result<Self, TrustGrantError> {
        let Some(non_revoked_ttl_seconds) = NonZeroU64::new(non_revoked_ttl_seconds) else {
            return Err(TrustGrantError::InvalidRevocationPolicy);
        };
        let Some(max_stale_seconds) = NonZeroU64::new(max_stale_seconds) else {
            return Err(TrustGrantError::InvalidRevocationPolicy);
        };

        Ok(Self {
            non_revoked_ttl_seconds,
            max_stale_seconds,
        })
    }

    /// Non-revoked ttl participates in record freshness normalization.
    pub const fn non_revoked_ttl_seconds(&self) -> u64 {
        self.non_revoked_ttl_seconds.get()
    }

    /// Max stale seconds participates in record freshness normalization.
    #[must_use]
    pub const fn max_stale_seconds(&self) -> u64 {
        self.max_stale_seconds.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawRevocationStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRevocationStatusProof {
    trustgrant_id: String,
    status: RawRevocationStatus,
    checked_at: DateTime<Utc>,
}

/// One parsed revocation status proof from a revocation endpoint.
///
/// Contains the TrustGrant identifier, the revocation status (active or
/// revoked), and the timestamp when the status was checked. Use
/// [`into_record`](Self::into_record) to normalise this proof into a
/// [`RevocationRecord`] with source kind, finality, and freshness policy
/// applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationStatusProof {
    trustgrant_id: TrustGrantId,
    status: RevocationStatus,
    checked_at: DateTime<Utc>,
}

impl RevocationStatusProof {
    /// Trustgrant id participates in proof-to-document matching.
    #[must_use]
    pub const fn trustgrant_id(&self) -> TrustGrantId {
        self.trustgrant_id
    }

    /// Status participates in verification and evaluation.
    #[must_use]
    pub const fn status(&self) -> RevocationStatus {
        self.status
    }

    /// Checked_at participates in freshness normalization.
    #[must_use]
    pub const fn checked_at(&self) -> DateTime<Utc> {
        self.checked_at
    }

    /// Normalizes one revocation proof into one runtime revocation record.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the freshness policy cannot be applied.
    pub fn into_record(
        self,
        source_kind: RevocationSourceKind,
        finality: ProofFinality,
        policy: RevocationFreshnessPolicy,
    ) -> Result<RevocationRecord, TrustGrantError> {
        let ttl_seconds = match self.status {
            RevocationStatus::Active => policy.non_revoked_ttl_seconds(),
            RevocationStatus::Revoked => policy.max_stale_seconds(),
        };
        let ttl_seconds = i64::try_from(ttl_seconds)
            .map_err(|_error| TrustGrantError::InvalidRevocationPolicy)?;
        let fresh_until = self
            .checked_at
            .checked_add_signed(Duration::seconds(ttl_seconds))
            .ok_or(TrustGrantError::InvalidRevocationPolicy)?;

        RevocationRecord::new(
            self.status,
            source_kind,
            finality,
            self.checked_at,
            fresh_until,
        )
    }
}

impl TryFrom<RawRevocationStatusProof> for RevocationStatusProof {
    type Error = TrustGrantError;

    fn try_from(raw: RawRevocationStatusProof) -> Result<Self, Self::Error> {
        Ok(Self {
            trustgrant_id: raw.trustgrant_id.parse::<TrustGrantId>()?,
            status: match raw.status {
                RawRevocationStatus::Active => RevocationStatus::Active,
                RawRevocationStatus::Revoked => RevocationStatus::Revoked,
            },
            checked_at: raw.checked_at,
        })
    }
}

/// Parses one revocation proof payload into normalized proof input.
///
/// # Examples
///
/// Parse an active-status proof and normalise it into a revocation record:
///
/// ```rust
/// # use trustgrant_revocation::{
/// #     parse_revocation_status_proof,
/// #     ProofFinality, RevocationFreshnessPolicy, RevocationSourceKind,
/// #     RevocationStatus,
/// # };
/// let json = r#"{
///   "trustgrant_id": "tg_123e4567-e89b-12d3-a456-426614174000",
///   "status": "active",
///   "checked_at": "2026-04-07T12:00:00Z"
/// }"#;
///
/// let proof = parse_revocation_status_proof(json)
///     .expect("valid revocation proof");
///
/// assert_eq!(proof.status(), RevocationStatus::Active);
/// assert_eq!(
///     proof.trustgrant_id().to_string(),
///     "tg_123e4567-e89b-12d3-a456-426614174000",
/// );
///
/// // Normalise into a record with policy
/// let policy = RevocationFreshnessPolicy::new(120, 900)
///     .expect("valid policy");
/// let record = proof
///     .into_record(
///         RevocationSourceKind::Api,
///         ProofFinality::Observed,
///         policy,
///     )
///     .expect("valid record");
/// assert_eq!(record.status(), RevocationStatus::Active);
/// ```
///
/// # Errors
///
/// Returns [`TrustGrantError`] when the JSON or normalized proof is invalid.
pub fn parse_revocation_status_proof(json: &str) -> Result<RevocationStatusProof, TrustGrantError> {
    ensure_json_size(
        "revocation_proof",
        json.len(),
        MAX_REVOCATION_PROOF_JSON_BYTES,
    )?;

    serde_json::from_str::<RawRevocationStatusProof>(json)
        .map_err(|_error| TrustGrantError::InvalidRevocationProofDocument)?
        .try_into()
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::{RevocationFreshnessPolicy, parse_revocation_status_proof};
    use crate::{ProofFinality, RevocationSourceKind, RevocationStatus};
    use trustgrant_error::TrustGrantError;
    use trustgrant_error::limits::MAX_REVOCATION_PROOF_JSON_BYTES;

    #[test]
    fn revocation_policy_rejects_zero_ttls() {
        let result = RevocationFreshnessPolicy::new(0, 900);

        assert_eq!(result, Err(TrustGrantError::InvalidRevocationPolicy));
    }

    // ── Line 31: zero max_stale_seconds ─────────────────────────────────

    #[test]
    fn revocation_policy_rejects_zero_max_stale_seconds() {
        let result = RevocationFreshnessPolicy::new(120, 0);

        assert_eq!(result, Err(TrustGrantError::InvalidRevocationPolicy));
    }

    // ── Lines 80-86: status() and checked_at() accessors ────────────────

    #[test]
    fn revocation_status_proof_status_accessor() {
        let proof = match parse_revocation_status_proof(
            r#"{
              "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
              "status":"revoked",
              "checked_at":"2026-04-07T12:00:00Z"
            }"#,
        ) {
            Ok(value) => value,
            Err(error) => panic!("proof should parse: {error}"),
        };

        assert_eq!(proof.status(), RevocationStatus::Revoked);
    }

    #[test]
    fn revocation_status_proof_checked_at_accessor() {
        let proof = match parse_revocation_status_proof(
            r#"{
              "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
              "status":"active",
              "checked_at":"2026-04-07T12:00:00Z"
            }"#,
        ) {
            Ok(value) => value,
            Err(error) => panic!("proof should parse: {error}"),
        };

        assert_eq!(proof.checked_at(), fixed_timestamp(2026, 4, 7, 12, 0, 0));
    }

    #[test]
    fn revocation_proof_normalizes_non_revoked_ttl() {
        let proof = match parse_revocation_status_proof(
            r#"{
              "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
              "status":"active",
              "checked_at":"2026-04-07T12:00:00Z"
            }"#,
        ) {
            Ok(value) => value,
            Err(error) => panic!("proof should parse: {error}"),
        };
        let record = match proof.into_record(
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            RevocationFreshnessPolicy::new(120, 900)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        ) {
            Ok(value) => value,
            Err(error) => panic!("record should normalize: {error}"),
        };

        assert_eq!(record.status(), RevocationStatus::Active);
        assert_eq!(record.fresh_until(), fixed_timestamp(2026, 4, 7, 12, 2, 0));
    }

    #[test]
    fn revocation_proof_rejects_oversized_json() {
        let oversized_padding = " ".repeat(MAX_REVOCATION_PROOF_JSON_BYTES);
        let json = format!(
            r#"{{"trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000","status":"active","checked_at":"2026-04-07T12:00:00Z"}}{oversized_padding}"#
        );

        let result = parse_revocation_status_proof(&json);

        assert_eq!(
            result,
            Err(TrustGrantError::DocumentTooLarge {
                document: "revocation_proof",
                max_bytes: MAX_REVOCATION_PROOF_JSON_BYTES,
            })
        );
    }

    #[test]
    fn revocation_proof_rejects_unknown_fields() {
        let result = parse_revocation_status_proof(
            r#"{
              "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
              "status":"active",
              "checked_at":"2026-04-07T12:00:00Z",
              "unexpected":"value"
            }"#,
        );

        assert_eq!(result, Err(TrustGrantError::InvalidRevocationProofDocument));
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
}
