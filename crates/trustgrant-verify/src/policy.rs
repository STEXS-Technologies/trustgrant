use trustgrant_revocation::{ProofFinality, RevocationSourceKind};

use super::VerificationPosture;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationPolicy {
    minimum_revocation_finality: ProofFinality,
    require_non_live_revocation_source: bool,
}

impl VerificationPolicy {
    /// Verification should use an explicit posture-derived policy.
    #[must_use]
    pub const fn for_posture(posture: VerificationPosture) -> Self {
        match posture {
            VerificationPosture::Online => Self {
                minimum_revocation_finality: ProofFinality::Observed,
                require_non_live_revocation_source: false,
            },
            VerificationPosture::Cached | VerificationPosture::Offline => Self {
                minimum_revocation_finality: ProofFinality::TrustedSnapshot,
                require_non_live_revocation_source: true,
            },
        }
    }

    /// Revocation finality participates in proof-policy enforcement.
    #[must_use]
    pub const fn minimum_revocation_finality(self) -> ProofFinality {
        self.minimum_revocation_finality
    }

    /// Offline verification may require snapshot-like sources.
    #[must_use]
    pub const fn require_non_live_revocation_source(self) -> bool {
        self.require_non_live_revocation_source
    }

    /// Verification must reject revocation evidence with insufficient finality.
    #[must_use]
    pub fn accepts_revocation_finality(self, finality: ProofFinality) -> bool {
        finality >= self.minimum_revocation_finality
    }

    /// Verification must reject live revocation sources when posture forbids them.
    #[must_use]
    pub const fn accepts_revocation_source_kind(self, source_kind: RevocationSourceKind) -> bool {
        !self.require_non_live_revocation_source || source_kind.is_non_live()
    }

    /// Callers may need to distinguish live-source rejection from other posture checks.
    #[must_use]
    pub const fn requires_non_live_revocation_source(self) -> bool {
        self.require_non_live_revocation_source
    }
}

#[cfg(test)]
mod tests {
    use super::VerificationPolicy;
    use trustgrant_ports::VerificationPosture;
    use trustgrant_revocation::{ProofFinality, RevocationSourceKind};

    // ── for_posture ─────────────────────────────────────────────────────

    #[test]
    fn for_posture_online_sets_observed_min_finality_and_allows_live_sources() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Online);
        assert_eq!(
            policy.minimum_revocation_finality(),
            ProofFinality::Observed
        );
        assert!(!policy.require_non_live_revocation_source());
    }

    #[test]
    fn for_posture_cached_sets_trusted_snapshot_min_finality_and_requires_non_live() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Cached);
        assert_eq!(
            policy.minimum_revocation_finality(),
            ProofFinality::TrustedSnapshot
        );
        assert!(policy.require_non_live_revocation_source());
    }

    #[test]
    fn for_posture_offline_sets_trusted_snapshot_min_finality_and_requires_non_live() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Offline);
        assert_eq!(
            policy.minimum_revocation_finality(),
            ProofFinality::TrustedSnapshot
        );
        assert!(policy.require_non_live_revocation_source());
    }

    // ── minimum_revocation_finality ─────────────────────────────────────

    #[test]
    fn minimum_revocation_finality_online_is_observed() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Online);
        assert_eq!(
            policy.minimum_revocation_finality(),
            ProofFinality::Observed
        );
    }

    #[test]
    fn minimum_revocation_finality_cached_is_trusted_snapshot() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Cached);
        assert_eq!(
            policy.minimum_revocation_finality(),
            ProofFinality::TrustedSnapshot
        );
    }

    #[test]
    fn minimum_revocation_finality_offline_is_trusted_snapshot() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Offline);
        assert_eq!(
            policy.minimum_revocation_finality(),
            ProofFinality::TrustedSnapshot
        );
    }

    // ── require_non_live_revocation_source ──────────────────────────────

    #[test]
    fn require_non_live_revocation_source_online_is_false() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Online);
        assert!(!policy.require_non_live_revocation_source());
    }

    #[test]
    fn require_non_live_revocation_source_cached_is_true() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Cached);
        assert!(policy.require_non_live_revocation_source());
    }

    #[test]
    fn require_non_live_revocation_source_offline_is_true() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Offline);
        assert!(policy.require_non_live_revocation_source());
    }

    // ── accepts_revocation_finality ─────────────────────────────────────

    #[test]
    fn online_accepts_observed_finality() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Online);
        assert!(policy.accepts_revocation_finality(ProofFinality::Observed));
    }

    #[test]
    fn online_rejects_unknown_finality() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Online);
        assert!(!policy.accepts_revocation_finality(ProofFinality::Unknown));
    }

    #[test]
    fn online_accepts_trusted_snapshot_finality_as_higher_than_minimum() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Online);
        assert!(policy.accepts_revocation_finality(ProofFinality::TrustedSnapshot));
    }

    #[test]
    fn cached_accepts_trusted_snapshot_finality() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Cached);
        assert!(policy.accepts_revocation_finality(ProofFinality::TrustedSnapshot));
    }

    #[test]
    fn cached_rejects_observed_finality() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Cached);
        assert!(!policy.accepts_revocation_finality(ProofFinality::Observed));
    }

    #[test]
    fn cached_accepts_finalized_finality_as_higher_than_minimum() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Cached);
        assert!(policy.accepts_revocation_finality(ProofFinality::Finalized));
    }

    // ── accepts_revocation_source_kind ──────────────────────────────────

    #[test]
    fn online_accepts_live_revocation_source() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Online);
        assert!(policy.accepts_revocation_source_kind(RevocationSourceKind::Api));
    }

    #[test]
    fn cached_rejects_live_revocation_source() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Cached);
        assert!(!policy.accepts_revocation_source_kind(RevocationSourceKind::Api));
    }

    #[test]
    fn cached_accepts_non_live_revocation_source() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Cached);
        assert!(policy.accepts_revocation_source_kind(RevocationSourceKind::Snapshot));
    }

    // ── requires_non_live_revocation_source ─────────────────────────────

    #[test]
    fn requires_non_live_revocation_source_online_is_false() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Online);
        assert!(!policy.requires_non_live_revocation_source());
    }

    #[test]
    fn requires_non_live_revocation_source_cached_is_true() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Cached);
        assert!(policy.requires_non_live_revocation_source());
    }

    #[test]
    fn requires_non_live_revocation_source_offline_is_true() {
        let policy = VerificationPolicy::for_posture(VerificationPosture::Offline);
        assert!(policy.requires_non_live_revocation_source());
    }
}
