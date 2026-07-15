use std::collections::{BTreeMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    AuthorityId, GrantRevision, ResourceTypeName, SelectorKind, TransitionId, TransitionSeriesId,
};
use trustgrant_error::TrustGrantError;

/// Describes the lineage of one ownership transition within a transition
/// series.
///
/// Records the transition identifier, series, revision number, and optional
/// predecessor to enable deterministic chain stitching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipTransitionLineage {
    transition_id: TransitionId,
    transition_series_id: TransitionSeriesId,
    revision: GrantRevision,
    supersedes_transition_id: Option<TransitionId>,
}

impl OwnershipTransitionLineage {
    /// Creates one ownership-transition lineage descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when revision/supersession invariants are
    /// violated.
    #[must_use]
    pub fn new(
        transition_id: TransitionId,
        transition_series_id: TransitionSeriesId,
        revision: GrantRevision,
        supersedes_transition_id: Option<TransitionId>,
    ) -> Result<Self, TrustGrantError> {
        if revision.get() == 1 && supersedes_transition_id.is_some() {
            return Err(TrustGrantError::InvalidSupersedesForFirstRevision);
        }

        // Permanent invariant from ownership-transition fuzzing: a non-first
        // revision without an explicit predecessor cannot be stitched into a
        // deterministic lineage later, so it must be rejected at validation.
        if revision.get() > 1 && supersedes_transition_id.is_none() {
            return Err(TrustGrantError::MissingSupersedesForNonFirstOwnershipTransitionRevision);
        }

        if supersedes_transition_id == Some(transition_id) {
            return Err(TrustGrantError::SelfSupersession);
        }

        Ok(Self {
            transition_id,
            transition_series_id,
            revision,
            supersedes_transition_id,
        })
    }

    /// Transition id is required for proof-chain identity.
    #[must_use]
    pub const fn transition_id(&self) -> TransitionId {
        self.transition_id
    }

    /// Transition series id is required for lineage tracking.
    #[must_use]
    pub const fn transition_series_id(&self) -> TransitionSeriesId {
        self.transition_series_id
    }

    /// Revision is required for transition ordering.
    #[must_use]
    pub const fn revision(&self) -> GrantRevision {
        self.revision
    }

    /// Supersedes transition id is required for conflict resolution.
    #[must_use]
    pub const fn supersedes_transition_id(&self) -> Option<TransitionId> {
        self.supersedes_transition_id
    }
}

/// One explicit selector within an ownership resource scope.
///
/// Each selector pairs a [`SelectorKind`] with a list of values and
/// participates in ownership-scope matching.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OwnershipSelector {
    kind: SelectorKind,
    values: Vec<String>,
}

impl OwnershipSelector {
    /// Creates one explicit ownership-scope selector.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when kind or values are invalid, or when
    /// duplicate values are present.
    #[must_use]
    pub fn new(kind: impl Into<String>, values: Vec<String>) -> Result<Self, TrustGrantError> {
        if values.is_empty() {
            return Err(TrustGrantError::InvalidOwnershipTransitionScope);
        }

        let mut normalized_values = Vec::with_capacity(values.len());
        let mut seen = HashSet::with_capacity(values.len());

        for value in values {
            let normalized = normalize_non_empty("ownership_selector.value", &value)?.to_owned();

            if !seen.insert(normalized.clone()) {
                return Err(TrustGrantError::DuplicateSelector);
            }

            normalized_values.push(normalized);
        }

        Ok(Self {
            kind: SelectorKind::new(kind)?,
            values: normalized_values,
        })
    }

    /// Selector kind is required for ownership-scope matching.
    #[must_use]
    pub const fn kind(&self) -> &SelectorKind {
        &self.kind
    }

    /// Selector values are required for ownership-scope matching.
    #[must_use]
    pub fn values(&self) -> &[String] {
        &self.values
    }
}

/// The resource-scope portion of an ownership transition.
///
/// Contains a set of selectors that describe which resources are covered by
/// an ownership transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipResourceScope {
    selectors: Vec<OwnershipSelector>,
}

impl OwnershipResourceScope {
    /// Creates one explicit ownership resource-scope entry.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the selector set is empty or contains
    /// duplicates.
    #[must_use]
    pub fn new(selectors: Vec<OwnershipSelector>) -> Result<Self, TrustGrantError> {
        if selectors.is_empty() {
            return Err(TrustGrantError::InvalidOwnershipTransitionScope);
        }

        let mut seen = HashSet::with_capacity(selectors.len());

        for selector in &selectors {
            if !seen.insert(selector.clone()) {
                return Err(TrustGrantError::DuplicateSelector);
            }
        }

        Ok(Self { selectors })
    }

    /// Selectors are required for ownership-scope matching.
    #[must_use]
    pub fn selectors(&self) -> &[OwnershipSelector] {
        &self.selectors
    }
}

/// A time window bounding when an ownership transition is valid.
///
/// The window is defined by a `not_before` and `not_after` pair; the
/// transition is only valid if the evaluation timestamp falls within
/// `[not_before, not_after]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnershipTimeWindow {
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

impl OwnershipTimeWindow {
    /// Creates one ownership transition time window.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the time window is inverted.
    #[must_use]
    pub fn new(
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
    ) -> Result<Self, TrustGrantError> {
        if not_before > not_after {
            return Err(TrustGrantError::InvalidTimeWindow);
        }

        Ok(Self {
            not_before,
            not_after,
        })
    }

    /// Not_before is required for transition validity checks.
    #[must_use]
    pub const fn not_before(&self) -> DateTime<Utc> {
        self.not_before
    }

    /// Not_after is required for transition validity checks.
    #[must_use]
    pub const fn not_after(&self) -> DateTime<Utc> {
        self.not_after
    }

    /// Callers must know whether a transition is valid at one time.
    #[must_use]
    pub fn contains(&self, timestamp: DateTime<Utc>) -> bool {
        timestamp >= self.not_before && timestamp <= self.not_after
    }
}

/// The three parties involved in an ownership transition: origin,
/// predecessor, and successor authorities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipTransitionParties {
    origin_authority: AuthorityId,
    predecessor_authority: AuthorityId,
    successor_authority: AuthorityId,
}

impl OwnershipTransitionParties {
    /// Creates one validated ownership-transition party set.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when predecessor and successor are equal.
    #[must_use]
    pub fn new(
        origin_authority: AuthorityId,
        predecessor_authority: AuthorityId,
        successor_authority: AuthorityId,
    ) -> Result<Self, TrustGrantError> {
        if predecessor_authority == successor_authority {
            return Err(TrustGrantError::InvalidOwnershipTransitionParties);
        }

        Ok(Self {
            origin_authority,
            predecessor_authority,
            successor_authority,
        })
    }

    /// Origin authority is required for canonical lineage validation.
    #[must_use]
    pub const fn origin_authority(&self) -> &AuthorityId {
        &self.origin_authority
    }

    /// Predecessor authority is required for transfer validation.
    #[must_use]
    pub const fn predecessor_authority(&self) -> &AuthorityId {
        &self.predecessor_authority
    }

    /// Successor authority is required for transfer validation.
    #[must_use]
    pub const fn successor_authority(&self) -> &AuthorityId {
        &self.successor_authority
    }
}

/// A complete, validated ownership transition record.
///
/// Combines lineage, parties, resource scope, optional time window, and
/// effective-at timestamp into one self-contained transition proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipTransitionRecord {
    lineage: OwnershipTransitionLineage,
    parties: OwnershipTransitionParties,
    resource_scope: BTreeMap<ResourceTypeName, OwnershipResourceScope>,
    time_window: Option<OwnershipTimeWindow>,
    effective_at: DateTime<Utc>,
}

impl OwnershipTransitionRecord {
    /// Creates one validated ownership transition record.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when participant, scope, or time-window
    /// invariants are violated.
    #[must_use]
    pub fn new(
        lineage: OwnershipTransitionLineage,
        parties: OwnershipTransitionParties,
        resource_scope: BTreeMap<ResourceTypeName, OwnershipResourceScope>,
        time_window: Option<OwnershipTimeWindow>,
        effective_at: DateTime<Utc>,
    ) -> Result<Self, TrustGrantError> {
        if resource_scope.is_empty() {
            return Err(TrustGrantError::InvalidOwnershipTransitionScope);
        }

        if let Some(time_window) = time_window
            && !time_window.contains(effective_at)
        {
            return Err(TrustGrantError::InvalidOwnershipTransitionEffectiveAt);
        }

        Ok(Self {
            lineage,
            parties,
            resource_scope,
            time_window,
            effective_at,
        })
    }

    /// Transition lineage is required for proof-chain identity.
    #[must_use]
    pub const fn lineage(&self) -> &OwnershipTransitionLineage {
        &self.lineage
    }

    /// Origin authority is required for canonical lineage validation.
    #[must_use]
    pub const fn origin_authority(&self) -> &AuthorityId {
        self.parties.origin_authority()
    }

    /// Predecessor authority is required for predecessor validation.
    #[must_use]
    pub const fn predecessor_authority(&self) -> &AuthorityId {
        self.parties.predecessor_authority()
    }

    /// Successor authority is required for successor validation.
    #[must_use]
    pub const fn successor_authority(&self) -> &AuthorityId {
        self.parties.successor_authority()
    }

    /// Transition parties are required for ownership transfer validation.
    #[must_use]
    pub const fn parties(&self) -> &OwnershipTransitionParties {
        &self.parties
    }

    /// Resource scope is required for transition applicability checks.
    #[must_use]
    pub const fn resource_scope(&self) -> &BTreeMap<ResourceTypeName, OwnershipResourceScope> {
        &self.resource_scope
    }

    /// Time window is required for temporal transition checks.
    #[must_use]
    pub const fn time_window(&self) -> Option<&OwnershipTimeWindow> {
        self.time_window.as_ref()
    }

    /// Effective_at is required for activation ordering.
    #[must_use]
    pub const fn effective_at(&self) -> DateTime<Utc> {
        self.effective_at
    }
}

/// Classifies how ownership was proven for a verified grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipProofKind {
    /// The grant issuer is the static, non-transitioned owner.
    StaticOwner,
    /// Ownership was established through a chain of transition proofs.
    TransitionChain,
}

/// Records the outcome of an ownership verification check.
///
/// Captures the resolved origin authority, active owning authority, when
/// the check was performed, what kind of proof was used, and the
/// transition-chain tip (if applicable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipVerificationRecord {
    origin_authority: AuthorityId,
    active_owning_authority: AuthorityId,
    checked_at: DateTime<Utc>,
    proof_kind: OwnershipProofKind,
    transition_chain_tip: Option<TransitionId>,
}

impl OwnershipVerificationRecord {
    /// Ownership verification state should be attached to verified grants.
    #[must_use]
    pub const fn new(
        origin_authority: AuthorityId,
        active_owning_authority: AuthorityId,
        checked_at: DateTime<Utc>,
        proof_kind: OwnershipProofKind,
        transition_chain_tip: Option<TransitionId>,
    ) -> Self {
        Self {
            origin_authority,
            active_owning_authority,
            checked_at,
            proof_kind,
            transition_chain_tip,
        }
    }

    /// Origin authority is required for canonical lineage identity.
    #[must_use]
    pub const fn origin_authority(&self) -> &AuthorityId {
        &self.origin_authority
    }

    /// Active owning authority is required for owner-level verification.
    #[must_use]
    pub const fn active_owning_authority(&self) -> &AuthorityId {
        &self.active_owning_authority
    }

    /// Checked_at is required for audit and cache freshness.
    #[must_use]
    pub const fn checked_at(&self) -> DateTime<Utc> {
        self.checked_at
    }

    /// Proof kind is required for audit and debugging.
    #[must_use]
    pub const fn proof_kind(&self) -> OwnershipProofKind {
        self.proof_kind
    }

    /// Transition chain tip is required for lineage-aware audit.
    #[must_use]
    pub const fn transition_chain_tip(&self) -> Option<TransitionId> {
        self.transition_chain_tip
    }
}

fn normalize_non_empty<'value>(
    field_name: &'static str,
    value: &'value str,
) -> Result<&'value str, TrustGrantError> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(TrustGrantError::EmptyStringField(field_name));
    }

    Ok(trimmed)
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{TimeZone, Utc};

    use super::{
        OwnershipProofKind, OwnershipResourceScope, OwnershipSelector, OwnershipTimeWindow,
        OwnershipTransitionLineage, OwnershipTransitionParties, OwnershipTransitionRecord,
        OwnershipVerificationRecord,
    };
    use crate::{AuthorityId, GrantRevision, ResourceTypeName, TransitionId, TransitionSeriesId};
    use trustgrant_error::TrustGrantError;

    #[test]
    fn ownership_transition_record_rejects_same_from_and_to_authority() {
        let authority = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("authority should be valid: {error}"));
        let result =
            OwnershipTransitionParties::new(authority.clone(), authority.clone(), authority);

        assert!(result.is_err());
    }

    #[test]
    fn ownership_transition_lineage_rejects_non_first_revision_without_supersedes() {
        let result = OwnershipTransitionLineage::new(
            "tgt_123e4567-e89b-12d3-a456-426614174000"
                .parse::<TransitionId>()
                .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
            "tgts_123e4567-e89b-12d3-a456-426614174001"
                .parse::<TransitionSeriesId>()
                .unwrap_or_else(|error| panic!("transition series id should parse: {error}")),
            GrantRevision::new(2)
                .unwrap_or_else(|error| panic!("revision should be valid: {error}")),
            None,
        );

        assert_eq!(
            result,
            Err(TrustGrantError::MissingSupersedesForNonFirstOwnershipTransitionRevision)
        );
    }

    #[test]
    fn ownership_transition_record_rejects_effective_at_outside_time_window() {
        let result = OwnershipTransitionRecord::new(
            transition_lineage(),
            OwnershipTransitionParties::new(
                authority("https://origin.example.com"),
                authority("https://from.example.com"),
                authority("https://to.example.com"),
            )
            .unwrap_or_else(|error| panic!("parties should be valid: {error}")),
            resource_scope(),
            Some(
                OwnershipTimeWindow::new(
                    fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    fixed_timestamp(2026, 4, 8, 12, 0, 0),
                )
                .unwrap_or_else(|error| panic!("time window should be valid: {error}")),
            ),
            fixed_timestamp(2026, 4, 9, 12, 0, 0),
        );

        assert!(result.is_err());
    }

    #[test]
    fn ownership_verification_record_keeps_transition_tip() {
        let transition_tip = "tgt_123e4567-e89b-12d3-a456-426614174000"
            .parse::<TransitionId>()
            .unwrap_or_else(|error| panic!("transition id should parse: {error}"));
        let record = OwnershipVerificationRecord::new(
            authority("https://origin.example.com"),
            authority("https://to.example.com"),
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            OwnershipProofKind::TransitionChain,
            Some(transition_tip),
        );

        assert_eq!(
            record.transition_chain_tip().map(|value| value.to_string()),
            Some("tgt_123e4567-e89b-12d3-a456-426614174000".to_owned())
        );
    }

    // ── Line 33: revision 1 with supersedes ─────────────────────────────

    #[test]
    fn ownership_transition_lineage_rejects_supersedes_on_first_revision() {
        let result = OwnershipTransitionLineage::new(
            "tgt_123e4567-e89b-12d3-a456-426614174000"
                .parse::<TransitionId>()
                .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
            "tgts_123e4567-e89b-12d3-a456-426614174001"
                .parse::<TransitionSeriesId>()
                .unwrap_or_else(|error| panic!("transition series id should parse: {error}")),
            GrantRevision::new(1)
                .unwrap_or_else(|error| panic!("revision should be valid: {error}")),
            Some(
                "tgt_aabbccdd-e89b-12d3-a456-426614174002"
                    .parse::<TransitionId>()
                    .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
            ),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::InvalidSupersedesForFirstRevision)
        );
    }

    // ── Line 44: self-supersession ─────────────────────────────────────

    #[test]
    fn ownership_transition_lineage_rejects_self_supersession() {
        let transition_id = "tgt_123e4567-e89b-12d3-a456-426614174000"
            .parse::<TransitionId>()
            .unwrap_or_else(|error| panic!("transition id should parse: {error}"));
        let result = OwnershipTransitionLineage::new(
            transition_id,
            "tgts_123e4567-e89b-12d3-a456-426614174001"
                .parse::<TransitionSeriesId>()
                .unwrap_or_else(|error| panic!("transition series id should parse: {error}")),
            GrantRevision::new(2)
                .unwrap_or_else(|error| panic!("revision should be valid: {error}")),
            Some(transition_id),
        );

        assert_eq!(result, Err(TrustGrantError::SelfSupersession));
    }

    // ── Line 91: empty selector values ──────────────────────────────────

    #[test]
    fn ownership_selector_rejects_empty_values() {
        let result = OwnershipSelector::new("id", vec![]);
        assert_eq!(
            result,
            Err(TrustGrantError::InvalidOwnershipTransitionScope)
        );
    }

    // ── Line 101: duplicate selector values ─────────────────────────────

    #[test]
    fn ownership_selector_rejects_duplicate_values() {
        let result = OwnershipSelector::new(
            "id",
            vec!["canonical_item_1".to_owned(), "canonical_item_1".to_owned()],
        );
        assert_eq!(result, Err(TrustGrantError::DuplicateSelector));
    }

    // ── Line 138: empty resource scope selectors ────────────────────────

    #[test]
    fn ownership_resource_scope_rejects_empty_selectors() {
        let result = OwnershipResourceScope::new(vec![]);
        assert_eq!(
            result,
            Err(TrustGrantError::InvalidOwnershipTransitionScope)
        );
    }

    // ── Line 145: duplicate selectors in resource scope ─────────────────

    #[test]
    fn ownership_resource_scope_rejects_duplicate_selectors() {
        let selector = OwnershipSelector::new("id", vec!["item_1".to_owned()])
            .unwrap_or_else(|error| panic!("selector should be valid: {error}"));
        let result = OwnershipResourceScope::new(vec![selector.clone(), selector]);
        assert_eq!(result, Err(TrustGrantError::DuplicateSelector));
    }

    // ── Line 175: inverted time window ──────────────────────────────────

    #[test]
    fn ownership_time_window_rejects_inverted_bounds() {
        let result = OwnershipTimeWindow::new(
            fixed_timestamp(2026, 4, 8, 12, 0, 0),
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        );
        assert_eq!(result, Err(TrustGrantError::InvalidTimeWindow));
    }

    // ── Lines 185-191: time window accessors ────────────────────────────

    #[test]
    fn ownership_time_window_accessors_return_expected_values() {
        let window = OwnershipTimeWindow::new(
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            fixed_timestamp(2026, 4, 8, 12, 0, 0),
        )
        .unwrap_or_else(|error| panic!("time window should be valid: {error}"));
        assert_eq!(window.not_before(), fixed_timestamp(2026, 4, 7, 12, 0, 0));
        assert_eq!(window.not_after(), fixed_timestamp(2026, 4, 8, 12, 0, 0));
    }

    // ── Line 269: empty resource scope in record ────────────────────────

    #[test]
    fn ownership_transition_record_rejects_empty_resource_scope() {
        let result = OwnershipTransitionRecord::new(
            transition_lineage(),
            OwnershipTransitionParties::new(
                authority("https://origin.example.com"),
                authority("https://from.example.com"),
                authority("https://to.example.com"),
            )
            .unwrap_or_else(|error| panic!("parties should be valid: {error}")),
            BTreeMap::new(),
            None,
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        );
        assert_eq!(
            result,
            Err(TrustGrantError::InvalidOwnershipTransitionScope)
        );
    }

    // ── Line 308: parties() accessor ────────────────────────────────────

    #[test]
    fn ownership_transition_record_parties_accessor() {
        let parties = OwnershipTransitionParties::new(
            authority("https://origin.example.com"),
            authority("https://from.example.com"),
            authority("https://to.example.com"),
        )
        .unwrap_or_else(|error| panic!("parties should be valid: {error}"));
        let record = OwnershipTransitionRecord::new(
            transition_lineage(),
            parties,
            resource_scope(),
            None,
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        )
        .unwrap_or_else(|error| panic!("record should be valid: {error}"));
        assert_eq!(
            record.parties().origin_authority().as_str(),
            "https://origin.example.com"
        );
        assert_eq!(
            record.parties().predecessor_authority().as_str(),
            "https://from.example.com"
        );
        assert_eq!(
            record.parties().successor_authority().as_str(),
            "https://to.example.com"
        );
    }

    // ── Line 395: normalize_non_empty empty string error ────────────────

    #[test]
    fn ownership_selector_value_whitespace_only_rejected() {
        let result = OwnershipSelector::new("id", vec!["   ".to_owned()]);
        assert_eq!(
            result,
            Err(TrustGrantError::EmptyStringField(
                "ownership_selector.value"
            ))
        );
    }

    fn authority(value: &str) -> AuthorityId {
        AuthorityId::new(value).unwrap_or_else(|error| panic!("authority should be valid: {error}"))
    }

    fn transition_lineage() -> OwnershipTransitionLineage {
        OwnershipTransitionLineage::new(
            "tgt_123e4567-e89b-12d3-a456-426614174000"
                .parse::<TransitionId>()
                .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
            "tgts_123e4567-e89b-12d3-a456-426614174001"
                .parse::<TransitionSeriesId>()
                .unwrap_or_else(|error| panic!("transition series id should parse: {error}")),
            GrantRevision::new(1)
                .unwrap_or_else(|error| panic!("revision should be valid: {error}")),
            None,
        )
        .unwrap_or_else(|error| panic!("transition lineage should be valid: {error}"))
    }

    fn resource_scope() -> BTreeMap<ResourceTypeName, OwnershipResourceScope> {
        let mut scope = BTreeMap::new();
        scope.insert(
            ResourceTypeName::new("item")
                .unwrap_or_else(|error| panic!("resource type should be valid: {error}")),
            OwnershipResourceScope::new(vec![
                OwnershipSelector::new("id", vec!["canonical_item_1".to_owned()])
                    .unwrap_or_else(|error| panic!("selector should be valid: {error}")),
            ])
            .unwrap_or_else(|error| panic!("resource scope should be valid: {error}")),
        );
        scope
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
