use std::num::NonZeroU64;

use trustgrant_error::TrustGrantError;

use super::ids::{GrantSeriesId, TrustGrantId};

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

    #[must_use = "revision value should be used for lineage ordering"]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupersessionPolicy {
    Coexist,
    SupersedePrevious,
    ExplicitRevocationRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantLineage {
    trustgrant_id: TrustGrantId,
    grant_series_id: GrantSeriesId,
    revision: GrantRevision,
    supersedes: Option<TrustGrantId>,
    supersession_policy: SupersessionPolicy,
}

impl GrantLineage {
    #[must_use = "grant lineage should be used for registration, lookup, or evaluation"]
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

    #[must_use = "document identity is part of exact-grant evaluation"]
    pub const fn trustgrant_id(&self) -> TrustGrantId {
        self.trustgrant_id
    }

    #[must_use = "series identity is part of lineage lookup"]
    pub const fn grant_series_id(&self) -> GrantSeriesId {
        self.grant_series_id
    }

    #[must_use = "revision is part of lineage ordering"]
    pub const fn revision(&self) -> GrantRevision {
        self.revision
    }

    #[must_use = "superseded document is part of lineage traversal"]
    pub const fn supersedes(&self) -> Option<TrustGrantId> {
        self.supersedes
    }

    #[must_use = "supersession policy is part of lineage semantics"]
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
