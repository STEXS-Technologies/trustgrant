use chrono::{DateTime, Utc};
use trustgrant_domain::{AuthorityId, TrustGrantId};

use crate::request::ResourceBinding;

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
    #[must_use = "allow decisions are consumed by callers"]
    pub const fn allow(trustgrant_id: TrustGrantId) -> Self {
        Self {
            trustgrant_id,
            deny_reason: None,
        }
    }

    #[must_use = "deny decisions are consumed by callers"]
    pub const fn deny(trustgrant_id: TrustGrantId, deny_reason: EvaluationDenyReason) -> Self {
        Self {
            trustgrant_id,
            deny_reason: Some(deny_reason),
        }
    }

    #[must_use = "callers need to know whether evaluation passed"]
    pub const fn is_allowed(&self) -> bool {
        self.deny_reason.is_none()
    }

    #[must_use = "callers need to know which exact grant was evaluated"]
    pub const fn trustgrant_id(&self) -> TrustGrantId {
        self.trustgrant_id
    }

    #[must_use = "deny reason is required for audit and debugging"]
    pub const fn deny_reason(&self) -> Option<EvaluationDenyReason> {
        self.deny_reason
    }
}

/// The outcome of evaluating one grant against one request.
///
/// Wraps an [`EvaluationDecision`] with the execution context that produced it:
/// the intent ID (if any), the resource binding used, and the evaluation
/// timestamp. This is the record that the execution layer MUST use to ensure
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
    intent_id: Option<String>,
    resource_binding: ResourceBinding,
    origin_authority: AuthorityId,
    evaluated_at: DateTime<Utc>,
}

impl EvaluationOutcome {
    #[must_use = "evaluation outcomes should be inspected by callers"]
    pub(crate) fn new(
        decision: EvaluationDecision,
        intent_id: Option<String>,
        resource_binding: ResourceBinding,
        evaluated_at: DateTime<Utc>,
    ) -> Self {
        let origin_authority = resource_binding.origin_authority().clone();
        Self {
            decision,
            intent_id,
            resource_binding,
            origin_authority,
            evaluated_at,
        }
    }

    /// The evaluation decision (allow or deny).
    #[must_use = "the decision determines whether to authorize work"]
    pub const fn decision(&self) -> &EvaluationDecision {
        &self.decision
    }

    /// The intent ID that was bound to this evaluation, if any.
    #[must_use = "intent ID enables replay detection"]
    pub fn intent_id(&self) -> Option<&str> {
        self.intent_id.as_deref()
    }

    /// The resource binding used during evaluation.
    #[must_use = "resource binding identifies what was authorized"]
    pub const fn resource_binding(&self) -> &ResourceBinding {
        &self.resource_binding
    }

    /// The origin authority from the resource binding.
    #[must_use = "origin authority is required for spec §13 step 3 enforcement"]
    pub const fn origin_authority(&self) -> &AuthorityId {
        &self.origin_authority
    }

    /// When the evaluation was performed.
    #[must_use = "evaluation timestamp is required for audit"]
    pub const fn evaluated_at(&self) -> DateTime<Utc> {
        self.evaluated_at
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
        }
    }
}

#[cfg(test)]
mod tests {
    use trustgrant_domain::TrustGrantId;
    use crate::decision::{EvaluationDecision, EvaluationDenyReason};

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
}
