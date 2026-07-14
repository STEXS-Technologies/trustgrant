use chrono::{DateTime, Utc};
use trustgrant_domain::{AuthorityId, TrustGrantId};

use crate::request::{EvaluationRequest, IntentId, ResourceBinding};

/// Reasons why an evaluation request was denied.
///
/// Each variant corresponds to a specific check in the evaluation spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationDenyReason {
    /// The grant has been revoked.
    Revoked,
    /// The grant's time window has not yet started (`evaluated_at < not_before`).
    NotYetValid,
    /// The grant's time window has expired (`evaluated_at > not_after`).
    Expired,
    /// The target scope has an explicit deny selector that matched.
    TargetDenied,
    /// The target scope does not have an allow selector that matched.
    TargetNotAllowed,
    /// The requested resource type is not present in the grant's resource scope.
    ResourceTypeNotGranted,
    /// The resource scope has an explicit deny selector that matched.
    ResourceDenied,
    /// The resource scope does not have an allow selector that matched.
    ResourceNotAllowed,
    /// The audience scope has an explicit deny selector that matched.
    AudienceDenied,
    /// The audience scope does not have an allow selector that matched.
    AudienceNotAllowed,
    /// The audience principal scope has an explicit deny selector that matched.
    AudiencePrincipalDenied,
    /// The audience principal scope does not have an allow selector that matched.
    AudiencePrincipalNotAllowed,
    /// The requested capability is disabled at the grant or resource-type level.
    CapabilityDisabled,
    /// The requested operation is denied by the operation scope.
    OperationDenied,
    /// The request's origin authority does not match the grant's origin authority.
    OriginAuthorityMismatch,
    /// Mint-constraint evaluation requires a `MintContext` but none was provided.
    MissingMintContext,
    /// Per-user mint limits require an audience principal context but none was
    /// provided.
    MissingAudiencePrincipalContext,
    /// The total mint count has reached the `max_total` limit.
    MintTotalLimitReached,
    /// The per-user mint count has reached the `max_per_user` limit.
    MintPerUserLimitReached,
    /// The request selectors have not been verified against trusted evidence.
    ///
    /// The integration layer must call [`EvaluationRequest::verify_selectors`]
    /// after populating selectors from an authenticated identity, canonical
    /// inventory record, or issuer-signed metadata source. The engine rejects
    /// mint operations with unverified selectors to prevent self-assertion of
    /// selector claims (spec §13 step 0).
    UnverifiedSelectors,
    /// The revocation proof data is stale — its freshness window has expired.
    ///
    /// The revocation record was checked at `checked_at` and is only valid
    /// until `fresh_until`. The evaluation timestamp is after `fresh_until`,
    /// so the engine cannot trust the revocation status. The caller must
    /// refresh the revocation proof before retrying.
    StaleRevocationData,
    /// The requested custom operation requires an interoperability profile
    /// on the grant, but none was set. Grants with `operations.all = true`
    /// must declare an `interoperability_profile` to authorize custom
    /// operations.
    OperationNotInProfile,
}

/// The result of evaluating one grant against one request.
///
/// An `EvaluationDecision` carries the evaluated grant's ID and an optional
/// deny reason. When `deny_reason` is `None`, the evaluation passed (allow).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvaluationDecision {
    trustgrant_id: TrustGrantId,
    deny_reason: Option<EvaluationDenyReason>,
}

impl EvaluationDecision {
    /// Allow decisions are consumed by callers.
    #[must_use]
    pub const fn allow(trustgrant_id: TrustGrantId) -> Self {
        Self {
            trustgrant_id,
            deny_reason: None,
        }
    }

    /// Deny decisions are consumed by callers.
    #[must_use]
    pub const fn deny(trustgrant_id: TrustGrantId, deny_reason: EvaluationDenyReason) -> Self {
        Self {
            trustgrant_id,
            deny_reason: Some(deny_reason),
        }
    }

    /// Callers need to know whether evaluation passed.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        self.deny_reason.is_none()
    }

    /// Callers need to know which exact grant was evaluated.
    #[must_use]
    pub const fn trustgrant_id(&self) -> TrustGrantId {
        self.trustgrant_id
    }

    /// Deny reason is required for audit and debugging.
    #[must_use]
    pub const fn deny_reason(&self) -> Option<EvaluationDenyReason> {
        self.deny_reason
    }
}

/// The outcome of evaluating one grant against one request.
///
/// Wraps an [`EvaluationDecision`] with the complete request context that
/// produced it. This is the record that the execution layer MUST use to ensure
/// atomic, idempotent authorization.
///
/// The execution layer must:
/// - Verify that `intent_id` has not been previously processed (replay prevention)
/// - When acting on an existing resource, check that the current resource
///   version matches the version in the binding (stale-state detection)
/// - Persist the outcome as an append-only audit event before applying any
///   state mutation
/// - Treat an allow outcome as a precondition, not a standalone authorization
///   to execute without the above checks
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationOutcome {
    decision: EvaluationDecision,
    request: EvaluationRequest,
}

impl EvaluationOutcome {
    /// Evaluation outcomes should be inspected by callers.
    #[must_use]
    pub(crate) const fn new(decision: EvaluationDecision, request: EvaluationRequest) -> Self {
        Self { decision, request }
    }

    /// The evaluation decision (allow or deny).
    #[must_use]
    pub const fn decision(&self) -> &EvaluationDecision {
        &self.decision
    }

    /// The intent ID that was bound to this evaluation, if any.
    #[must_use]
    pub const fn intent_id(&self) -> Option<&IntentId> {
        self.request.intent_id()
    }

    /// The resource binding used during evaluation.
    #[must_use]
    pub const fn resource_binding(&self) -> &ResourceBinding {
        self.request.resource_binding()
    }

    /// The origin authority from the resource binding.
    #[must_use]
    pub const fn origin_authority(&self) -> &AuthorityId {
        self.request.origin_authority()
    }

    /// When the evaluation was performed.
    #[must_use]
    pub const fn evaluated_at(&self) -> DateTime<Utc> {
        self.request.evaluated_at()
    }

    /// The complete request that was evaluated.
    ///
    /// Execution adapters must persist this binding, or an authenticated digest
    /// of it, alongside the decision so an allow cannot be replayed for a
    /// different resource, operation, subject, or audience.
    #[must_use]
    pub const fn request(&self) -> &EvaluationRequest {
        &self.request
    }
}

impl std::fmt::Display for EvaluationDenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvaluationDenyReason::Revoked => write!(f, "revoked"),
            EvaluationDenyReason::NotYetValid => write!(f, "not yet valid"),
            EvaluationDenyReason::Expired => write!(f, "expired"),
            EvaluationDenyReason::TargetDenied => write!(f, "target denied"),
            EvaluationDenyReason::TargetNotAllowed => write!(f, "target not allowed"),
            EvaluationDenyReason::ResourceTypeNotGranted => write!(f, "resource type not granted"),
            EvaluationDenyReason::ResourceDenied => write!(f, "resource denied"),
            EvaluationDenyReason::ResourceNotAllowed => write!(f, "resource not allowed"),
            EvaluationDenyReason::AudienceDenied => write!(f, "audience denied"),
            EvaluationDenyReason::AudienceNotAllowed => write!(f, "audience not allowed"),
            EvaluationDenyReason::AudiencePrincipalDenied => write!(f, "audience principal denied"),
            EvaluationDenyReason::AudiencePrincipalNotAllowed => {
                write!(f, "audience principal not allowed")
            }
            EvaluationDenyReason::CapabilityDisabled => write!(f, "capability disabled"),
            EvaluationDenyReason::OperationDenied => write!(f, "operation denied"),
            EvaluationDenyReason::OriginAuthorityMismatch => {
                write!(f, "origin authority does not match the grant")
            }
            EvaluationDenyReason::MissingMintContext => write!(f, "missing mint context"),
            EvaluationDenyReason::MissingAudiencePrincipalContext => {
                write!(f, "missing audience principal context")
            }
            EvaluationDenyReason::MintTotalLimitReached => write!(f, "mint total limit reached"),
            EvaluationDenyReason::MintPerUserLimitReached => {
                write!(f, "mint per user limit reached")
            }
            EvaluationDenyReason::StaleRevocationData => {
                write!(f, "stale revocation data")
            }
            EvaluationDenyReason::UnverifiedSelectors => {
                write!(f, "unverified selectors")
            }
            EvaluationDenyReason::OperationNotInProfile => {
                write!(f, "operation not in profile")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::decision::{EvaluationDecision, EvaluationDenyReason};
    use crate::EvaluationOutcome;
    use trustgrant_domain::TrustGrantId;

    #[test]
    fn allow_creates_allowed_decision() {
        let id = TrustGrantId::generate();
        let decision = EvaluationDecision::allow(id);

        assert!(decision.is_allowed());
        assert_eq!(decision.deny_reason(), None);
        assert_eq!(decision.trustgrant_id(), id);
    }

    #[test]
    fn deny_with_revoked_creates_denied_decision() {
        let id = TrustGrantId::generate();
        let decision = EvaluationDecision::deny(id, EvaluationDenyReason::Revoked);

        assert!(!decision.is_allowed());
        assert_eq!(decision.deny_reason(), Some(EvaluationDenyReason::Revoked));
        assert_eq!(decision.trustgrant_id(), id);
    }

    #[test]
    fn deny_with_expired_creates_denied_decision() {
        let id = TrustGrantId::generate();
        let decision = EvaluationDecision::deny(id, EvaluationDenyReason::Expired);

        assert!(!decision.is_allowed());
        assert_eq!(decision.deny_reason(), Some(EvaluationDenyReason::Expired));
        assert_eq!(decision.trustgrant_id(), id);
    }

    #[test]
    fn deny_with_target_denied_creates_denied_decision() {
        let id = TrustGrantId::generate();
        let decision = EvaluationDecision::deny(id, EvaluationDenyReason::TargetDenied);

        assert!(!decision.is_allowed());
        assert_eq!(
            decision.deny_reason(),
            Some(EvaluationDenyReason::TargetDenied)
        );
        assert_eq!(decision.trustgrant_id(), id);
    }

    #[test]
    fn deny_with_target_not_allowed_creates_denied_decision() {
        let id = TrustGrantId::generate();
        let decision = EvaluationDecision::deny(id, EvaluationDenyReason::TargetNotAllowed);

        assert!(!decision.is_allowed());
        assert_eq!(
            decision.deny_reason(),
            Some(EvaluationDenyReason::TargetNotAllowed)
        );
        assert_eq!(decision.trustgrant_id(), id);
    }

    #[test]
    fn deny_with_capability_disabled_creates_denied_decision() {
        let id = TrustGrantId::generate();
        let decision = EvaluationDecision::deny(id, EvaluationDenyReason::CapabilityDisabled);

        assert!(!decision.is_allowed());
        assert_eq!(
            decision.deny_reason(),
            Some(EvaluationDenyReason::CapabilityDisabled)
        );
        assert_eq!(decision.trustgrant_id(), id);
    }

    #[test]
    fn deny_with_missing_mint_context_creates_denied_decision() {
        let id = TrustGrantId::generate();
        let decision = EvaluationDecision::deny(id, EvaluationDenyReason::MissingMintContext);

        assert!(!decision.is_allowed());
        assert_eq!(
            decision.deny_reason(),
            Some(EvaluationDenyReason::MissingMintContext)
        );
        assert_eq!(decision.trustgrant_id(), id);
    }

    #[test]
    fn deny_with_mint_total_limit_reached_creates_denied_decision() {
        let id = TrustGrantId::generate();
        let decision = EvaluationDecision::deny(id, EvaluationDenyReason::MintTotalLimitReached);

        assert!(!decision.is_allowed());
        assert_eq!(
            decision.deny_reason(),
            Some(EvaluationDenyReason::MintTotalLimitReached)
        );
        assert_eq!(decision.trustgrant_id(), id);
    }

    #[test]
    fn trustgrant_id_returns_correct_id_for_allow() {
        let id = TrustGrantId::generate();
        let decision = EvaluationDecision::allow(id);

        assert_eq!(decision.trustgrant_id(), id);
    }

    #[test]
    fn trustgrant_id_returns_correct_id_for_deny() {
        let id = TrustGrantId::generate();
        let decision = EvaluationDecision::deny(id, EvaluationDenyReason::Revoked);

        assert_eq!(decision.trustgrant_id(), id);
    }

    #[test]
    fn is_allowed_returns_true_for_allow() {
        let id = TrustGrantId::generate();
        let decision = EvaluationDecision::allow(id);

        assert!(decision.is_allowed());
    }

    #[test]
    fn is_allowed_returns_false_for_deny() {
        let id = TrustGrantId::generate();
        let decision = EvaluationDecision::deny(id, EvaluationDenyReason::Revoked);

        assert!(!decision.is_allowed());
    }

    #[test]
    fn deny_reason_returns_none_for_allow() {
        let id = TrustGrantId::generate();
        let decision = EvaluationDecision::allow(id);

        assert_eq!(decision.deny_reason(), None);
    }

    #[test]
    fn deny_reason_returns_some_for_deny() {
        let id = TrustGrantId::generate();
        let decision = EvaluationDecision::deny(id, EvaluationDenyReason::Expired);

        assert_eq!(decision.deny_reason(), Some(EvaluationDenyReason::Expired));
    }

    #[test]
    fn evaluation_decision_implements_debug() {
        let id = TrustGrantId::generate();
        let decision = EvaluationDecision::allow(id);

        // Debug formatting does not panic and produces output
        let debug_str = format!("{decision:?}");
        assert!(!debug_str.is_empty());
    }

    #[test]
    fn evaluation_decision_implements_clone() {
        let id = TrustGrantId::generate();
        let decision = EvaluationDecision::deny(id, EvaluationDenyReason::Revoked);
        let cloned = decision;

        assert_eq!(cloned, decision);
    }

    #[test]
    fn evaluation_decision_implements_copy() {
        let id = TrustGrantId::generate();
        let decision = EvaluationDecision::allow(id);
        let copied = decision;

        assert_eq!(copied, decision);
        // Original still accessible (Copy semantics)
        assert_eq!(decision.trustgrant_id(), id);
    }

    #[test]
    fn evaluation_decision_implements_partial_eq_and_eq() {
        let id = TrustGrantId::generate();
        let a = EvaluationDecision::allow(id);
        let b = EvaluationDecision::allow(id);

        assert_eq!(a, b);
        assert_ne!(
            a,
            EvaluationDecision::deny(id, EvaluationDenyReason::Revoked)
        );
    }

    #[test]
    fn evaluation_deny_reason_display_origin_authority_mismatch() {
        assert_eq!(
            EvaluationDenyReason::OriginAuthorityMismatch.to_string(),
            "origin authority does not match the grant",
        );
    }

    #[test]
    fn evaluation_deny_reason_all_display_impls() {
        // Every deny reason must have a non-empty Display output
        let cases = [
            (EvaluationDenyReason::Revoked, "revoked"),
            (EvaluationDenyReason::NotYetValid, "not yet valid"),
            (EvaluationDenyReason::Expired, "expired"),
            (EvaluationDenyReason::TargetDenied, "target denied"),
            (EvaluationDenyReason::TargetNotAllowed, "target not allowed"),
            (
                EvaluationDenyReason::ResourceTypeNotGranted,
                "resource type not granted",
            ),
            (EvaluationDenyReason::ResourceDenied, "resource denied"),
            (
                EvaluationDenyReason::ResourceNotAllowed,
                "resource not allowed",
            ),
            (EvaluationDenyReason::AudienceDenied, "audience denied"),
            (
                EvaluationDenyReason::AudienceNotAllowed,
                "audience not allowed",
            ),
            (
                EvaluationDenyReason::AudiencePrincipalDenied,
                "audience principal denied",
            ),
            (
                EvaluationDenyReason::AudiencePrincipalNotAllowed,
                "audience principal not allowed",
            ),
            (
                EvaluationDenyReason::CapabilityDisabled,
                "capability disabled",
            ),
            (EvaluationDenyReason::OperationDenied, "operation denied"),
            (
                EvaluationDenyReason::MissingMintContext,
                "missing mint context",
            ),
            (
                EvaluationDenyReason::MissingAudiencePrincipalContext,
                "missing audience principal context",
            ),
            (
                EvaluationDenyReason::MintTotalLimitReached,
                "mint total limit reached",
            ),
            (
                EvaluationDenyReason::MintPerUserLimitReached,
                "mint per user limit reached",
            ),
            (
                EvaluationDenyReason::StaleRevocationData,
                "stale revocation data",
            ),
            (
                EvaluationDenyReason::UnverifiedSelectors,
                "unverified selectors",
            ),
            (
                EvaluationDenyReason::OperationNotInProfile,
                "operation not in profile",
            ),
        ];
        for (reason, expected) in &cases {
            assert_eq!(reason.to_string(), *expected, "display for {reason:?}");
        }
        // Also test the one with a longer message separately
        assert_eq!(
            EvaluationDenyReason::OriginAuthorityMismatch.to_string(),
            "origin authority does not match the grant",
        );
    }

    #[test]
    fn evaluation_outcome_holds_decision_and_context() {
        use chrono::{TimeZone, Utc};
        use crate::request::IntentId;

        let trustgrant_id = TrustGrantId::generate();
        let decision = EvaluationDecision::allow(trustgrant_id);

        let binding = crate::request::ResourceBinding::Existing(
            crate::request::ResourceRef::new(
                trustgrant_domain::AuthorityId::new("https://issuer.example.com").unwrap(),
                "rsc-1".to_owned(),
            ),
        );

        let ts = Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0).single().unwrap();

        let request = crate::request::EvaluationRequest::new(
            crate::request::RequestedOperation::Capability(crate::request::RequestedCapability::Recognize),
            binding,
            trustgrant_domain::AuthorityId::new("https://target.example.com").unwrap(),
            trustgrant_domain::AuthorityId::new("https://audience.example.com").unwrap(),
            crate::request::ResourceContext::new("item").unwrap(),
            ts,
        )
        .unwrap()
        .with_intent_id(IntentId::new("txn-001").unwrap());

        let outcome = EvaluationOutcome::new(decision, request);

        // Decision is accessible through outcome
        assert!(outcome.decision().is_allowed());
        assert_eq!(outcome.decision().trustgrant_id(), trustgrant_id);

        // Context fields round-trip
        assert_eq!(
            outcome.intent_id().map(IntentId::as_str),
            Some("txn-001")
        );
        assert_eq!(
            outcome.origin_authority().as_str(),
            "https://issuer.example.com"
        );
        assert_eq!(outcome.evaluated_at(), ts);
    }

    #[test]
    fn evaluation_outcome_without_intent_id() {
        use chrono::{TimeZone, Utc};

        let trustgrant_id = TrustGrantId::generate();
        let decision = EvaluationDecision::deny(trustgrant_id, EvaluationDenyReason::Revoked);

        let ts = Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0).single().unwrap();
        let request = crate::request::EvaluationRequest::new(
            crate::request::RequestedOperation::Capability(crate::request::RequestedCapability::Recognize),
            crate::request::ResourceBinding::Existing(
                crate::request::ResourceRef::new(
                    trustgrant_domain::AuthorityId::new("https://issuer.example.com").unwrap(),
                    "rsc-2".to_owned(),
                ),
            ),
            trustgrant_domain::AuthorityId::new("https://target.example.com").unwrap(),
            trustgrant_domain::AuthorityId::new("https://audience.example.com").unwrap(),
            crate::request::ResourceContext::new("item").unwrap(),
            ts,
        )
        .unwrap();

        let outcome = EvaluationOutcome::new(decision, request);

        // Without intent_id
        assert!(outcome.intent_id().is_none());
        assert!(!outcome.decision().is_allowed());
        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::Revoked)
        );
    }

    #[test]
    fn evaluation_outcome_resource_binding_mint() {
        use chrono::{TimeZone, Utc};

        let trustgrant_id = TrustGrantId::generate();
        let decision = EvaluationDecision::allow(trustgrant_id);

        let ts = Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0).single().unwrap();
        let binding = crate::request::ResourceBinding::Mint(
            crate::request::TemplateRef::new(
                trustgrant_domain::AuthorityId::new("https://issuer.example.com").unwrap(),
            ),
        );
        let request = crate::request::EvaluationRequest::new(
            crate::request::RequestedOperation::Capability(crate::request::RequestedCapability::Recognize),
            binding,
            trustgrant_domain::AuthorityId::new("https://target.example.com").unwrap(),
            trustgrant_domain::AuthorityId::new("https://audience.example.com").unwrap(),
            crate::request::ResourceContext::new("item").unwrap(),
            ts,
        )
        .unwrap();

        let outcome = EvaluationOutcome::new(decision, request.clone());

        assert!(outcome.decision().is_allowed());
        assert!(outcome.resource_binding().is_mint());
        assert_eq!(
            outcome.origin_authority().as_str(),
            "https://issuer.example.com"
        );
        assert_eq!(
            outcome.resource_binding().origin_authority().as_str(),
            "https://issuer.example.com"
        );
    }
}
