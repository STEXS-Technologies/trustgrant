use std::num::NonZeroU64;

use trustgrant_error::TrustGrantError;

use super::ids::{GrantSeriesId, TrustGrantId};

/// A non-zero revision number within a grant series.
///
/// Revisions start at 1 and increment with each new version of a grant
/// within the same series.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GrantRevision(NonZeroU64);

impl GrantRevision {
    /// Creates a non-zero grant revision.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError::ZeroRevision`] when `value` is zero.
    pub const fn new(value: u64) -> Result<Self, TrustGrantError> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(TrustGrantError::ZeroRevision),
        }
    }

    /// Revision value should be used for lineage ordering.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Determines how a new grant revision relates to previous revisions of the
/// same series.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupersessionPolicy {
    /// The new revision coexists with all previous revisions; all are valid.
    Coexist,
    /// The new revision supersedes the immediately previous revision.
    SupersedePrevious,
    /// The new revision is valid but prior revisions remain valid until
    /// explicitly revoked.
    ExplicitRevocationRequired,
}

/// Identifies one grant within a series and tracks its supersession
/// relationship.
///
/// Combines the concrete trustgrant ID, series ID, revision number,
/// optional superseded predecessor, and the supersession policy that
/// governs the relationship.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantLineage {
    trustgrant_id: TrustGrantId,
    grant_series_id: GrantSeriesId,
    revision: GrantRevision,
    supersedes: Option<TrustGrantId>,
    supersession_policy: SupersessionPolicy,
}

impl GrantLineage {
    /// Grant lineage should be used for registration, lookup, or evaluation.
    #[must_use]
    pub const fn new(
        trustgrant_id: TrustGrantId,
        grant_series_id: GrantSeriesId,
        revision: GrantRevision,
        supersedes: Option<TrustGrantId>,
        supersession_policy: SupersessionPolicy,
    ) -> Self {
        Self {
            trustgrant_id,
            grant_series_id,
            revision,
            supersedes,
            supersession_policy,
        }
    }

    /// Document identity is part of exact-grant evaluation.
    #[must_use]
    pub const fn trustgrant_id(&self) -> TrustGrantId {
        self.trustgrant_id
    }

    /// Series identity is part of lineage lookup.
    #[must_use]
    pub const fn grant_series_id(&self) -> GrantSeriesId {
        self.grant_series_id
    }

    /// Revision is part of lineage ordering.
    #[must_use]
    pub const fn revision(&self) -> GrantRevision {
        self.revision
    }

    /// Superseded document is part of lineage traversal.
    #[must_use]
    pub const fn supersedes(&self) -> Option<TrustGrantId> {
        self.supersedes
    }

    /// Supersession policy is part of lineage semantics.
    #[must_use]
    pub const fn supersession_policy(&self) -> SupersessionPolicy {
        self.supersession_policy
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::{GrantLineage, GrantRevision, SupersessionPolicy};
    use crate::{GrantSeriesId, TrustGrantId};

    #[test]
    fn revision_rejects_zero() {
        assert!(GrantRevision::new(0).is_err());
    }

    #[test]
    fn lineage_keeps_exact_document_and_series() {
        let trustgrant_id = TrustGrantId::generate();
        let grant_series_id = GrantSeriesId::generate();
        let revision = match GrantRevision::new(1) {
            Ok(value) => value,
            Err(error) => panic!("revision one should be valid: {error}"),
        };
        let lineage = GrantLineage::new(
            trustgrant_id,
            grant_series_id,
            revision,
            None,
            SupersessionPolicy::Coexist,
        );

        assert_eq!(lineage.trustgrant_id(), trustgrant_id);
        assert_eq!(lineage.grant_series_id(), grant_series_id);
        assert_eq!(lineage.revision().get(), 1);
        assert_eq!(lineage.supersedes(), None);
        assert_eq!(lineage.supersession_policy(), SupersessionPolicy::Coexist);
    }
}
