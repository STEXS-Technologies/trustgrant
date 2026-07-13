use trustgrant_domain::TrustGrantId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationDenyReason {
    Revoked,
    NotYetValid,
    Expired,
    TargetDenied,
    TargetNotAllowed,
    ResourceTypeNotGranted,
    ResourceDenied,
    ResourceNotAllowed,
    AudienceDenied,
    AudienceNotAllowed,
    AudiencePrincipalDenied,
    AudiencePrincipalNotAllowed,
    CapabilityDisabled,
    OperationDenied,
    /// The request's origin authority does not match the grant's origin authority.
    OriginAuthorityMismatch,
    MissingMintContext,
    MissingAudiencePrincipalContext,
    MintTotalLimitReached,
    MintPerUserLimitReached,
}

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
}
