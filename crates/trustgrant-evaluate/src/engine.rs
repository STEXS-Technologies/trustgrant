use std::collections::HashSet;

use super::decision::{EvaluationDecision, EvaluationDenyReason, EvaluationOutcome};
use super::request::{EvaluationRequest, RequestedCapability, RequestedOperation, SelectorContext};
use trustgrant_document::{
    ValidatedAudienceEntry, ValidatedCapabilities, ValidatedMintingConstraints,
    ValidatedResourceType, ValidatedScope, ValidatedSelector,
};
use trustgrant_domain::TrustGrantId;
use trustgrant_verify::{NormalizedTrustGrantDocument, VerifiedTrustGrant};

/// The core authorization engine that evaluates a verified grant against an
/// evaluation request.
///
/// The engine is stateless and implements the TrustGrant evaluation spec
/// (§13). It checks revocation status, time windows, origin authority,
/// target scope, resource scope, capabilities, operations, audience, and
/// minting constraints.
#[derive(Debug, Default, Clone, Copy)]
pub struct EvaluationEngine;

impl EvaluationEngine {
    /// Evaluation engine should be reused for repeated authorization checks.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Evaluates one verified grant against one request.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use trustgrant_evaluate::{
    ///     EvaluationEngine, EvaluationRequest, RequestedCapability,
    ///     RequestedOperation, ResourceContext,
    /// };
    /// use trustgrant_domain::AuthorityId;
    /// # // Minimum skeleton — full evaluation requires a verified grant fixture.
    /// # // See integration tests for complete examples.
    /// ```
    ///
    /// The caller is responsible for providing a [`VerifiedTrustGrant`] obtained
    /// through the verification pipeline and a properly populated
    /// [`EvaluationRequest`].
    #[must_use]
    pub fn evaluate(
        self,
        grant: &VerifiedTrustGrant,
        request: &EvaluationRequest,
    ) -> EvaluationOutcome {
        let _span = tracing::info_span!("evaluate",
            trustgrant_id = %grant.lineage().trustgrant_id(),
            operation = ?request.operation(),
        )
        .entered();
        let trustgrant_id = grant.lineage().trustgrant_id();

        let decision = self.evaluate_inner(grant, request, trustgrant_id);

        EvaluationOutcome::new(decision, request.clone())
    }

    fn evaluate_inner(
        self,
        grant: &VerifiedTrustGrant,
        request: &EvaluationRequest,
        trustgrant_id: TrustGrantId,
    ) -> EvaluationDecision {
        // Spec §13 step 1: Check revocation status and freshness.
        // The revocation record's freshness window is computed from the
        // issuer's declared policy — if the data is stale, deny regardless
        // of whether the status says Active or Revoked.
        match grant.metadata().revocation() {
            trustgrant_revocation::VerifiedRevocationState::Checked(record) => {
                if !record.is_fresh_at(request.evaluated_at()) {
                    tracing::debug!(
                        trustgrant_id = %trustgrant_id,
                        operation = ?request.operation(),
                        reason = ?EvaluationDenyReason::StaleRevocationData,
                        checked_at = %record.checked_at(),
                        fresh_until = %record.fresh_until(),
                    );
                    return EvaluationDecision::deny(
                        trustgrant_id,
                        EvaluationDenyReason::StaleRevocationData,
                    );
                }
                if record.status() == trustgrant_revocation::RevocationStatus::Revoked {
                    tracing::debug!(
                        trustgrant_id = %trustgrant_id,
                        operation = ?request.operation(),
                        reason = ?EvaluationDenyReason::Revoked,
                    );
                    return EvaluationDecision::deny(trustgrant_id, EvaluationDenyReason::Revoked);
                }
            }
            trustgrant_revocation::VerifiedRevocationState::NonRevocable => {}
        }

        if let Some(time_window) = grant.document().global_time_window() {
            if request.evaluated_at() < time_window.not_before() {
                tracing::debug!(
                    trustgrant_id = %trustgrant_id,
                    operation = ?request.operation(),
                    reason = ?EvaluationDenyReason::NotYetValid,
                );
                return EvaluationDecision::deny(trustgrant_id, EvaluationDenyReason::NotYetValid);
            }

            if request.evaluated_at() > time_window.not_after() {
                tracing::debug!(
                    trustgrant_id = %trustgrant_id,
                    operation = ?request.operation(),
                    reason = ?EvaluationDenyReason::Expired,
                );
                return EvaluationDecision::deny(trustgrant_id, EvaluationDenyReason::Expired);
            }
        }

        // Spec §13 step 3: Check origin authority
        // The binding is mandatory — failure is not optional.
        {
            let request_origin = request.origin_authority();
            let grant_origin = grant
                .document()
                .ownership_authority_state()
                .origin_authority();
            if request_origin != grant_origin {
                tracing::debug!(
                    trustgrant_id = %trustgrant_id,
                    operation = ?request.operation(),
                    reason = ?EvaluationDenyReason::OriginAuthorityMismatch,
                );
                return EvaluationDecision::deny(
                    trustgrant_id,
                    EvaluationDenyReason::OriginAuthorityMismatch,
                );
            }
        }

        match evaluate_scope(grant.document().target_scope(), request.target_context()) {
            ScopeEvaluation::Allowed => {}
            ScopeEvaluation::Denied(reason) => {
                tracing::debug!(
                    trustgrant_id = %trustgrant_id,
                    operation = ?request.operation(),
                    ?reason,
                );
                return EvaluationDecision::deny(trustgrant_id, reason);
            }
        }

        let Some(resource_type) = grant
            .document()
            .resource_scope()
            .get(request.resource().resource_type())
        else {
            tracing::debug!(
                trustgrant_id = %trustgrant_id,
                operation = ?request.operation(),
                reason = ?EvaluationDenyReason::ResourceTypeNotGranted,
            );
            return EvaluationDecision::deny(
                trustgrant_id,
                EvaluationDenyReason::ResourceTypeNotGranted,
            );
        };

        match evaluate_resource_type(grant.document(), resource_type, request) {
            ResourceEvaluation::Allowed => {}
            ResourceEvaluation::Denied(reason) => {
                tracing::debug!(
                    trustgrant_id = %trustgrant_id,
                    operation = ?request.operation(),
                    ?reason,
                );
                return EvaluationDecision::deny(trustgrant_id, reason);
            }
        }

        tracing::debug!(
            trustgrant_id = %trustgrant_id,
            operation = ?request.operation(),
            "allowed",
        );
        EvaluationDecision::allow(trustgrant_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeEvaluation {
    Allowed,
    Denied(EvaluationDenyReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResourceEvaluation {
    Allowed,
    Denied(EvaluationDenyReason),
}

fn evaluate_resource_type(
    grant_document: &NormalizedTrustGrantDocument,
    resource_type: &ValidatedResourceType,
    request: &EvaluationRequest,
) -> ResourceEvaluation {
    // Spec step 5: check capability allows operation
    if !is_capability_enabled(
        grant_document.capabilities(),
        resource_type,
        request.operation(),
    ) {
        return ResourceEvaluation::Denied(EvaluationDenyReason::CapabilityDisabled);
    }

    // Spec step 6: check resource matches resource_scope
    match evaluate_scope_with_reasons(
        resource_type.all(),
        resource_type.allow(),
        resource_type.deny(),
        request.resource().selectors(),
        EvaluationDenyReason::ResourceDenied,
        EvaluationDenyReason::ResourceNotAllowed,
    ) {
        ScopeEvaluation::Allowed => {}
        ScopeEvaluation::Denied(reason) => return ResourceEvaluation::Denied(reason),
    }

    // Spec step 7: check operation matches operations if present
    if !is_operation_allowed(resource_type, request.operation()) {
        return ResourceEvaluation::Denied(EvaluationDenyReason::OperationDenied);
    }

    // Spec step 8: check audience matches audience_scope
    let audience_scope = if resource_type.constraints().audience_scope().is_empty() {
        grant_document.default_audience_scope()
    } else {
        resource_type.constraints().audience_scope()
    };

    match evaluate_audience(audience_scope, request) {
        ScopeEvaluation::Denied(reason) => return ResourceEvaluation::Denied(reason),
        ScopeEvaluation::Allowed => {}
    }

    // Spec step 9: check minting constraints if minting is requested
    if let Err(reason) =
        evaluate_minting_constraints(resource_type.constraints().minting(), request)
    {
        return ResourceEvaluation::Denied(reason);
    }

    ResourceEvaluation::Allowed
}

fn evaluate_scope(scope: &ValidatedScope, context: &SelectorContext) -> ScopeEvaluation {
    evaluate_scope_with_reasons(
        scope.all(),
        scope.allow(),
        scope.deny(),
        context,
        EvaluationDenyReason::TargetDenied,
        EvaluationDenyReason::TargetNotAllowed,
    )
}

fn evaluate_scope_with_reasons(
    all: bool,
    allow: &[ValidatedSelector],
    deny: &[ValidatedSelector],
    context: &SelectorContext,
    denied_reason: EvaluationDenyReason,
    not_allowed_reason: EvaluationDenyReason,
) -> ScopeEvaluation {
    // Spec Section 10: allow is primary and explicit
    if !all
        && !allow.iter().any(|selector| {
            matches!(
                selector_matches_context(selector, context),
                SelectorMatch::Matched
            )
        })
    {
        return ScopeEvaluation::Denied(not_allowed_reason);
    }

    // Spec Section 10: deny is always subtractive — checked after allow
    if deny.iter().any(|selector| {
        matches!(
            selector_matches_context(selector, context),
            SelectorMatch::Matched
        )
    }) {
        return ScopeEvaluation::Denied(denied_reason);
    }

    ScopeEvaluation::Allowed
}

fn evaluate_audience(
    audience_scope: &[ValidatedAudienceEntry],
    request: &EvaluationRequest,
) -> ScopeEvaluation {
    if audience_scope.is_empty() {
        return ScopeEvaluation::Allowed;
    }

    let audience_entry = audience_scope
        .iter()
        .find(|entry| entry.authority_id() == request.audience_authority());

    let Some(audience_entry) = audience_entry else {
        return ScopeEvaluation::Denied(EvaluationDenyReason::AudienceNotAllowed);
    };

    match evaluate_scope_with_reasons(
        audience_entry.scope().all(),
        audience_entry.scope().allow(),
        audience_entry.scope().deny(),
        request.audience_context(),
        EvaluationDenyReason::AudienceDenied,
        EvaluationDenyReason::AudienceNotAllowed,
    ) {
        ScopeEvaluation::Allowed => {}
        ScopeEvaluation::Denied(reason) => return ScopeEvaluation::Denied(reason),
    }

    let Some(principal_scope) = audience_entry.principal_scope() else {
        return ScopeEvaluation::Allowed;
    };

    evaluate_scope_with_reasons(
        principal_scope.all(),
        principal_scope.allow(),
        principal_scope.deny(),
        request.audience_principal_context(),
        EvaluationDenyReason::AudiencePrincipalDenied,
        EvaluationDenyReason::AudiencePrincipalNotAllowed,
    )
}

fn is_capability_enabled(
    grant_capabilities: &ValidatedCapabilities,
    resource_type: &ValidatedResourceType,
    operation: &RequestedOperation,
) -> bool {
    match operation {
        RequestedOperation::Capability(RequestedCapability::Recognize) => resource_type
            .capabilities()
            .recognize()
            .unwrap_or_else(|| grant_capabilities.recognize()),
        RequestedOperation::Capability(RequestedCapability::Mint) => resource_type
            .capabilities()
            .mint()
            .unwrap_or_else(|| grant_capabilities.mint()),
        RequestedOperation::Custom(_) => {
            // Custom operations are authorized solely by the operations scope
            // (allow/deny lists). They are not gated on built-in capabilities
            // because custom operations are application-defined and have no
            // corresponding built-in capability.
            true
        }
    }
}

fn is_operation_allowed(
    resource_type: &ValidatedResourceType,
    operation: &RequestedOperation,
) -> bool {
    let Some(operation_scope) = resource_type.operations() else {
        // v0 compatibility mode (spec Section 6.1):
        // operations=null → implicit recognize and create allowed
        // Custom operations still need explicit operations scope
        return matches!(
            operation,
            RequestedOperation::Capability(RequestedCapability::Recognize)
                | RequestedOperation::Capability(RequestedCapability::Mint)
        );
    };

    let requested_name = match operation {
        RequestedOperation::Capability(RequestedCapability::Recognize) => "recognize",
        RequestedOperation::Capability(RequestedCapability::Mint) => "create",
        RequestedOperation::Custom(operation) => operation.as_str(),
    };

    if operation_scope
        .deny()
        .iter()
        .any(|denied_operation| denied_operation.as_str() == requested_name)
    {
        return false;
    }

    if operation_scope.all() {
        return true;
    }

    operation_scope
        .allow()
        .iter()
        .any(|allowed_operation| allowed_operation.as_str() == requested_name)
}

const fn evaluate_minting_constraints(
    constraints: &ValidatedMintingConstraints,
    request: &EvaluationRequest,
) -> Result<(), EvaluationDenyReason> {
    if !matches!(
        request.operation(),
        RequestedOperation::Capability(RequestedCapability::Mint)
    ) {
        return Ok(());
    }

    let Some(mint_context) = request.mint_context() else {
        return if constraints.max_total().is_some() || constraints.max_per_user().is_some() {
            Err(EvaluationDenyReason::MissingMintContext)
        } else {
            Ok(())
        };
    };

    if let Some(max_total) = constraints.max_total() {
        let total = mint_context.current_total_mints();
        let quantity = mint_context.requested_quantity();
        // Requested quantity must be at least 1 (enforced by MintContext).
        // Check: current + quantity > max → denied.
        if total.saturating_add(quantity) > max_total {
            return Err(EvaluationDenyReason::MintTotalLimitReached);
        }
    }

    if let Some(max_per_user) = constraints.max_per_user() {
        if request.audience_principal_context().is_empty() {
            return Err(EvaluationDenyReason::MissingAudiencePrincipalContext);
        }

        let per_user = mint_context.current_mints_for_audience();
        let quantity = mint_context.requested_quantity();
        if per_user.saturating_add(quantity) > max_per_user {
            return Err(EvaluationDenyReason::MintPerUserLimitReached);
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectorMatch {
    Matched,
    NotMatched,
}

fn selector_matches_context(
    selector: &ValidatedSelector,
    context: &SelectorContext,
) -> SelectorMatch {
    tracing::trace!(kind = ?selector.kind());
    if selector.all() {
        tracing::trace!(kind = ?selector.kind(), "matched");
        return SelectorMatch::Matched;
    }

    let Some(context_values) = context.values_for_kind(selector.kind()) else {
        tracing::trace!(kind = ?selector.kind(), "not_matched");
        return SelectorMatch::NotMatched;
    };

    if context_values.len() <= 8 {
        // Small set: linear scan (avoids HashSet allocation overhead)
        if selector
            .values()
            .iter()
            .any(|value| context_values.iter().any(|candidate| candidate == value))
        {
            tracing::trace!(kind = ?selector.kind(), "matched");
            return SelectorMatch::Matched;
        }
    } else {
        // Larger set: build a hashed set for O(1) lookups
        let context_set: HashSet<&str> = context_values.iter().map(|s| s.as_str()).collect();
        if selector
            .values()
            .iter()
            .any(|value| context_set.contains(value.as_str()))
        {
            tracing::trace!(kind = ?selector.kind(), "matched");
            return SelectorMatch::Matched;
        }
    }

    if selector
        .expressions()
        .iter()
        .any(|expression| context_values.iter().any(|value| expression.matches(value)))
    {
        tracing::trace!(kind = ?selector.kind(), "matched");
        SelectorMatch::Matched
    } else {
        tracing::trace!(kind = ?selector.kind(), "not_matched");
        SelectorMatch::NotMatched
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use chrono::{DateTime, TimeZone, Utc};

    use super::EvaluationEngine;
    use crate::{
        EvaluationDenyReason, EvaluationRequest, MintContext, RequestedCapability,
        RequestedOperation, ResourceBinding, ResourceContext, ResourceRef, TemplateRef,
    };
    use trustgrant_discovery::{
        AuthorityKeyRecord, DelegatedPrincipalRef, ResolvedSignerBinding, SignatureProfile,
    };
    use trustgrant_document::ValidatedTrustGrantDocument;
    use trustgrant_document::raw::{
        RawAudienceEntry, RawCapabilities, RawGlobalConstraints, RawMintingConstraints,
        RawOperationScope, RawPrincipal, RawResourceScope, RawResourceType, RawRevocation,
        RawScope, RawSelector, RawSupersessionPolicy, RawTimeWindow, RawTrustGrantDocument,
        RawTypeCapabilities, RawTypeConstraints,
    };
    use trustgrant_domain::AuthorityId;
    use trustgrant_domain::{
        CustomOperationName, OwnershipProofKind, OwnershipVerificationRecord, Utf16Key,
    };
    use trustgrant_revocation::{
        ProofFinality, RevocationRecord, RevocationSourceKind, RevocationStatus,
        VerifiedRevocationState,
    };
    use trustgrant_verify::{VerificationMetadata, VerificationPosture, VerifiedTrustGrant};

    fn verified_grant() -> VerifiedTrustGrant {
        let json = r#"{
          "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
          "version":0,
          "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
          "revision":1,
          "supersedes":null,
          "supersession_policy":"coexist",
          "issuer_authority":"https://issuer.example.com",
          "origin_authority":"https://issuer.example.com",
          "active_owning_authority":"https://issuer.example.com",
          "key_id":"root-key-1",
          "target_scope":{"all":false,"allow":[{"kind":"authority","all":false,"values":["https://target.example.com"],"expressions":null}],"deny":null},
          "capabilities":{"recognize":true,"mint":false},
          "default_audience_scope":null,
          "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":10,"max_per_user":1},"audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":{"all":false,"allow":[{"kind":"actor","all":false,"values":["player-123"],"expressions":null}],"deny":null}}]},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
          "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
          "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
          "issued_at":"2026-04-07T12:00:00Z",
          "signature":"base64-signature",
          "issuer_principal":{"kind":"service","id":"issuer-worker"}
        }"#;

        let raw = match RawTrustGrantDocument::parse_json_str(json) {
            Ok(document) => document,
            Err(error) => panic!("raw document should parse: {error}"),
        };
        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => panic!("validated document should succeed: {error}"),
        };

        VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        )
    }

    fn mint_grant() -> VerifiedTrustGrant {
        let json = r#"{
          "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174010",
          "version":0,
          "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174011",
          "revision":1,
          "supersedes":null,
          "supersession_policy":"coexist",
          "issuer_authority":"https://issuer.example.com",
          "origin_authority":"https://issuer.example.com",
          "active_owning_authority":"https://issuer.example.com",
          "key_id":"root-key-1",
          "target_scope":{"all":false,"allow":[{"kind":"authority","all":false,"values":["https://target.example.com"],"expressions":null}],"deny":null},
          "capabilities":{"recognize":false,"mint":true},
          "default_audience_scope":null,
          "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":false,"mint":true},"constraints":{"minting":{"max_total":10,"max_per_user":1},"audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":{"all":false,"allow":[{"kind":"actor","all":false,"values":["player-123"],"expressions":null}],"deny":null}}]},"operations":{"all":false,"allow":["create"],"deny":null}}}},
          "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
          "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
          "issued_at":"2026-04-07T12:00:00Z",
          "signature":"base64-signature",
          "issuer_principal":{"kind":"service","id":"issuer-worker"}
        }"#;

        let raw = match RawTrustGrantDocument::parse_json_str(json) {
            Ok(document) => document,
            Err(error) => panic!("raw mint document should parse: {error}"),
        };
        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => panic!("validated mint document should succeed: {error}"),
        };

        VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        )
    }

    fn mint_grant_without_operations() -> VerifiedTrustGrant {
        let raw = RawTrustGrantDocument {
            trustgrant_id: "tg_123e4567-e89b-12d3-a456-426614174012".into(),
            version: 0,
            grant_series_id: "tgs_123e4567-e89b-12d3-a456-426614174013".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://issuer.example.com".into(),
            active_owning_authority: "https://issuer.example.com".into(),
            key_id: "root-key-1".into(),
            target_scope: RawScope {
                all: false,
                allow: Some(vec![RawSelector {
                    kind: "authority".into(),
                    all: false,
                    values: Some(vec!["https://target.example.com".into()]),
                    expressions: None,
                }]),
                deny: None,
            },
            capabilities: RawCapabilities {
                recognize: false,
                mint: true,
            },
            default_audience_scope: None,
            resource_scope: RawResourceScope {
                types: std::collections::BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: false,
                        allow: Some(vec![RawSelector {
                            kind: "namespace".into(),
                            all: false,
                            values: Some(vec!["weapons".into()]),
                            expressions: None,
                        }]),
                        deny: None,
                        capabilities: RawTypeCapabilities {
                            recognize: Some(false),
                            mint: Some(true),
                        },
                        constraints: RawTypeConstraints {
                            minting: RawMintingConstraints {
                                max_total: Some(10),
                                max_per_user: Some(1),
                            },
                            audience_scope: Some(vec![RawAudienceEntry {
                                authority_id: "https://audience.example.com".into(),
                                scope: RawScope {
                                    all: true,
                                    allow: None,
                                    deny: None,
                                },
                                principal_scope: Some(RawScope {
                                    all: false,
                                    allow: Some(vec![RawSelector {
                                        kind: "actor".into(),
                                        all: false,
                                        values: Some(vec!["player-123".into()]),
                                        expressions: None,
                                    }]),
                                    deny: None,
                                }),
                            }]),
                        },
                        operations: None,
                    },
                )]),
            },
            global_constraints: Some(RawGlobalConstraints {
                time: Some(RawTimeWindow {
                    not_before: fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    not_after: fixed_timestamp(2026, 4, 8, 12, 0, 0),
                }),
            }),
            revocation: Some(RawRevocation {
                revocable: true,
                revocation_endpoint: "https://issuer.example.com/revocation".into(),
            }),
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "base64-signature".into(),
            issuer_principal: Some(RawPrincipal {
                kind: "service".into(),
                id: "issuer-worker".into(),
            }),
        };

        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => panic!("validated implicit-mint document should succeed: {error}"),
        };

        VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        )
    }

    fn mint_grant_without_principal_scope() -> VerifiedTrustGrant {
        let raw = RawTrustGrantDocument {
            trustgrant_id: "tg_e0000000-0000-1000-a000-000000000005".into(),
            version: 0,
            grant_series_id: "tgs_e0000000-0000-1000-a000-000000000005".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://issuer.example.com".into(),
            active_owning_authority: "https://issuer.example.com".into(),
            key_id: "root-key-1".into(),
            target_scope: RawScope {
                all: false,
                allow: Some(vec![RawSelector {
                    kind: "authority".into(),
                    all: false,
                    values: Some(vec!["https://target.example.com".into()]),
                    expressions: None,
                }]),
                deny: None,
            },
            capabilities: RawCapabilities {
                recognize: false,
                mint: true,
            },
            default_audience_scope: None,
            resource_scope: RawResourceScope {
                types: std::collections::BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: false,
                        allow: Some(vec![RawSelector {
                            kind: "namespace".into(),
                            all: false,
                            values: Some(vec!["weapons".into()]),
                            expressions: None,
                        }]),
                        deny: None,
                        capabilities: RawTypeCapabilities {
                            recognize: Some(false),
                            mint: Some(true),
                        },
                        constraints: RawTypeConstraints {
                            minting: RawMintingConstraints {
                                max_total: Some(10),
                                max_per_user: Some(1),
                            },
                            audience_scope: Some(vec![RawAudienceEntry {
                                authority_id: "https://audience.example.com".into(),
                                scope: RawScope {
                                    all: true,
                                    allow: None,
                                    deny: None,
                                },
                                principal_scope: None,
                            }]),
                        },
                        operations: Some(RawOperationScope {
                            all: false,
                            allow: Some(vec!["create".into()]),
                            deny: None,
                        }),
                    },
                )]),
            },
            global_constraints: Some(RawGlobalConstraints {
                time: Some(RawTimeWindow {
                    not_before: fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    not_after: fixed_timestamp(2026, 4, 8, 12, 0, 0),
                }),
            }),
            revocation: Some(RawRevocation {
                revocable: true,
                revocation_endpoint: "https://issuer.example.com/revocation".into(),
            }),
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "base64-signature".into(),
            issuer_principal: Some(RawPrincipal {
                kind: "service".into(),
                id: "issuer-worker".into(),
            }),
        };

        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => {
                panic!("validated mint-without-principal document should succeed: {error}")
            }
        };

        VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        )
    }

    fn expression_grant() -> VerifiedTrustGrant {
        let raw = RawTrustGrantDocument {
            trustgrant_id: "tg_123e4567-e89b-12d3-a456-426614174020".into(),
            version: 0,
            grant_series_id: "tgs_123e4567-e89b-12d3-a456-426614174021".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://issuer.example.com".into(),
            active_owning_authority: "https://issuer.example.com".into(),
            key_id: "root-key-1".into(),
            target_scope: RawScope {
                all: false,
                allow: Some(vec![RawSelector {
                    kind: "authority".into(),
                    all: false,
                    values: Some(vec!["https://target.example.com".into()]),
                    expressions: None,
                }]),
                deny: None,
            },
            capabilities: RawCapabilities {
                recognize: true,
                mint: false,
            },
            default_audience_scope: None,
            resource_scope: RawResourceScope {
                types: std::collections::BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: false,
                        allow: Some(vec![RawSelector {
                            kind: "namespace".into(),
                            all: false,
                            values: None,
                            expressions: Some(vec![r#"startsWith("weapon_")"#.into()]),
                        }]),
                        deny: None,
                        capabilities: RawTypeCapabilities {
                            recognize: Some(true),
                            mint: Some(false),
                        },
                        constraints: RawTypeConstraints {
                            minting: RawMintingConstraints {
                                max_total: None,
                                max_per_user: None,
                            },
                            audience_scope: None,
                        },
                        operations: Some(RawOperationScope {
                            all: false,
                            allow: Some(vec!["recognize".into()]),
                            deny: None,
                        }),
                    },
                )]),
            },
            global_constraints: Some(RawGlobalConstraints {
                time: Some(RawTimeWindow {
                    not_before: fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    not_after: fixed_timestamp(2026, 4, 8, 12, 0, 0),
                }),
            }),
            revocation: Some(RawRevocation {
                revocable: true,
                revocation_endpoint: "https://issuer.example.com/revocation".into(),
            }),
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "base64-signature".into(),
            issuer_principal: Some(RawPrincipal {
                kind: "service".into(),
                id: "issuer-worker".into(),
            }),
        };

        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => panic!("validated expression document should succeed: {error}"),
        };

        VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        )
    }

    fn origin() -> AuthorityId {
        AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"))
    }

    fn ownership_record() -> OwnershipVerificationRecord {
        OwnershipVerificationRecord::new(
            origin(),
            origin(),
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            OwnershipProofKind::StaticOwner,
            None,
        )
    }

    fn signer_binding() -> ResolvedSignerBinding {
        ResolvedSignerBinding::new(
            AuthorityId::new("https://issuer.example.com")
                .unwrap_or_else(|error| panic!("issuer authority should be valid: {error}")),
            AuthorityKeyRecord::new(
                "root-key-1",
                "ed25519",
                "base64-public-key",
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                fixed_timestamp(2026, 4, 8, 12, 0, 0),
            )
            .unwrap_or_else(|error| panic!("key record should be valid: {error}")),
            SignatureProfile::new("jcs+ed25519", "RFC8785")
                .unwrap_or_else(|error| panic!("signature profile should be valid: {error}")),
            Some(
                DelegatedPrincipalRef::new("service", "issuer-worker")
                    .unwrap_or_else(|error| panic!("delegated principal should be valid: {error}")),
            ),
        )
    }

    fn recognize_request() -> EvaluationRequest {
        let mut resource = match ResourceContext::new("item") {
            Ok(resource) => resource,
            Err(error) => panic!("resource context should be valid: {error}"),
        };
        if let Err(error) = resource.insert_selector("namespace", "weapons") {
            panic!("resource selector should be valid: {error}");
        }

        let origin = origin();
        let mut request = match EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Recognize),
            ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
            match AuthorityId::new("https://target.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid target authority: {error}"),
            },
            match AuthorityId::new("https://audience.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid audience authority: {error}"),
            },
            resource,
            fixed_timestamp(2026, 4, 7, 13, 0, 0),
        ) {
            Ok(request) => request,
            Err(error) => panic!("evaluation request should be valid: {error}"),
        };

        if let Err(error) = request.insert_audience_principal_selector("actor", "player-123") {
            panic!("audience principal selector should be valid: {error}");
        }

        request
    }

    fn recognize_request_at(timestamp: DateTime<Utc>) -> EvaluationRequest {
        let mut resource = match ResourceContext::new("item") {
            Ok(resource) => resource,
            Err(error) => panic!("resource context should be valid: {error}"),
        };
        if let Err(error) = resource.insert_selector("namespace", "weapons") {
            panic!("resource selector should be valid: {error}");
        }

        let origin = origin();
        let mut request = match EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Recognize),
            ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
            match AuthorityId::new("https://target.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid target authority: {error}"),
            },
            match AuthorityId::new("https://audience.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid audience authority: {error}"),
            },
            resource,
            timestamp,
        ) {
            Ok(request) => request,
            Err(error) => panic!("evaluation request should be valid: {error}"),
        };

        if let Err(error) = request.insert_audience_principal_selector("actor", "player-123") {
            panic!("audience principal selector should be valid: {error}");
        }

        request
    }

    fn mint_request() -> EvaluationRequest {
        let mut resource = match ResourceContext::new("item") {
            Ok(resource) => resource,
            Err(error) => panic!("mint resource context should be valid: {error}"),
        };
        if let Err(error) = resource.insert_selector("namespace", "weapons") {
            panic!("mint resource selector should be valid: {error}");
        }

        let origin = origin();
        let mut request = match EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Mint),
            ResourceBinding::Mint(TemplateRef::new(origin)),
            match AuthorityId::new("https://target.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid target authority: {error}"),
            },
            match AuthorityId::new("https://audience.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid audience authority: {error}"),
            },
            resource,
            fixed_timestamp(2026, 4, 7, 13, 0, 0),
        ) {
            Ok(request) => request,
            Err(error) => panic!("mint evaluation request should be valid: {error}"),
        };

        if let Err(error) = request.insert_audience_principal_selector("actor", "player-123") {
            panic!("mint audience principal selector should be valid: {error}");
        }

        request
    }

    fn expression_request(namespace: &str) -> EvaluationRequest {
        let mut resource = match ResourceContext::new("item") {
            Ok(resource) => resource,
            Err(error) => panic!("expression resource context should be valid: {error}"),
        };
        if let Err(error) = resource.insert_selector("namespace", namespace) {
            panic!("expression resource selector should be valid: {error}");
        }

        let origin = origin();
        match EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Recognize),
            ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
            match AuthorityId::new("https://target.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid target authority: {error}"),
            },
            match AuthorityId::new("https://audience.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid audience authority: {error}"),
            },
            resource,
            fixed_timestamp(2026, 4, 7, 13, 0, 0),
        ) {
            Ok(request) => request,
            Err(error) => panic!("expression evaluation request should be valid: {error}"),
        }
    }

    #[test]
    fn evaluation_allows_matching_recognize_request() {
        let engine = EvaluationEngine::new();
        let outcome = engine.evaluate(&verified_grant(), &recognize_request());

        assert!(outcome.decision().is_allowed());
        assert_eq!(outcome.decision().deny_reason(), None);
    }

    #[test]
    fn evaluation_denies_when_revoked() {
        let engine = EvaluationEngine::new();
        let mut grant = verified_grant();
        let active_revocation = grant
            .metadata()
            .revocation()
            .checked_record()
            .unwrap_or_else(|| panic!("test grant should carry revocation record"));
        grant = VerifiedTrustGrant::new(
            grant.document().clone(),
            VerificationMetadata::new(
                grant.metadata().verified_at(),
                grant.metadata().posture(),
                grant.metadata().signer_binding().clone(),
                grant.metadata().ownership().clone(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Revoked,
                        active_revocation.source_kind(),
                        active_revocation.finality(),
                        active_revocation.checked_at(),
                        active_revocation.fresh_until(),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        );

        let outcome = engine.evaluate(&grant, &recognize_request());

        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::Revoked)
        );
    }

    #[test]
    fn evaluation_denies_stale_revocation_data() {
        let engine = EvaluationEngine::new();
        let mut grant = verified_grant();
        let active_revocation = grant
            .metadata()
            .revocation()
            .checked_record()
            .unwrap_or_else(|| panic!("test grant should carry revocation record"));
        // Construct a revocation record with a fresh_until in the past
        // relative to the evaluation time (2026-04-07T13:00:00Z).
        grant = VerifiedTrustGrant::new(
            grant.document().clone(),
            VerificationMetadata::new(
                grant.metadata().verified_at(),
                grant.metadata().posture(),
                grant.metadata().signer_binding().clone(),
                grant.metadata().ownership().clone(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        active_revocation.source_kind(),
                        active_revocation.finality(),
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 7, 12, 30, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        );

        let outcome = engine.evaluate(&grant, &recognize_request());

        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::StaleRevocationData)
        );
    }

    #[test]
    fn evaluation_denies_stale_revocation_even_when_status_is_revoked() {
        // When revocation data is stale, the engine denies with
        // StaleRevocationData regardless of whether the recorded status
        // says Active or Revoked. Freshness is checked first.
        let engine = EvaluationEngine::new();
        let mut grant = verified_grant();
        grant = VerifiedTrustGrant::new(
            grant.document().clone(),
            VerificationMetadata::new(
                grant.metadata().verified_at(),
                grant.metadata().posture(),
                grant.metadata().signer_binding().clone(),
                grant.metadata().ownership().clone(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Revoked,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 7, 12, 30, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        );

        let outcome = engine.evaluate(&grant, &recognize_request());

        // Freshness check comes before status check — stale data always
        // denies with StaleRevocationData, even if the record says Revoked.
        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::StaleRevocationData)
        );
    }

    #[test]
    fn evaluation_allows_fresh_active_revocation_data() {
        // Fresh revocation data with Active status should allow evaluation
        // to proceed to subsequent checks.
        let engine = EvaluationEngine::new();
        let grant = verified_grant();

        let outcome = engine.evaluate(&grant, &recognize_request());

        assert!(outcome.decision().is_allowed());
    }

    #[test]
    fn evaluation_allows_non_revocable_grant_regardless_of_time() {
        // Grants that are NonRevocable bypass revocation checks entirely,
        // including freshness. Evaluation should proceed normally.
        let engine = EvaluationEngine::new();
        let mut grant = verified_grant();
        grant = VerifiedTrustGrant::new(
            grant.document().clone(),
            VerificationMetadata::new(
                grant.metadata().verified_at(),
                grant.metadata().posture(),
                grant.metadata().signer_binding().clone(),
                grant.metadata().ownership().clone(),
                VerifiedRevocationState::NonRevocable,
            ),
        );

        let outcome = engine.evaluate(&grant, &recognize_request());

        assert!(outcome.decision().is_allowed());
    }

    #[test]
    fn evaluation_allows_revocation_at_exact_freshness_boundary() {
        // evaluated_at == fresh_until is considered fresh (inclusive bound).
        let engine = EvaluationEngine::new();
        let mut grant = verified_grant();
        grant = VerifiedTrustGrant::new(
            grant.document().clone(),
            VerificationMetadata::new(
                grant.metadata().verified_at(),
                grant.metadata().posture(),
                grant.metadata().signer_binding().clone(),
                grant.metadata().ownership().clone(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 7, 13, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        );

        // Create a request with evaluated_at == fresh_until
        let request = recognize_request_at(fixed_timestamp(2026, 4, 7, 13, 0, 0));
        let outcome = engine.evaluate(&grant, &request);

        assert!(outcome.decision().is_allowed());
    }

    #[test]
    fn evaluation_denies_stale_revocation_just_past_freshness_boundary() {
        // evaluated_at == fresh_until + 1 second is stale.
        let engine = EvaluationEngine::new();
        let mut grant = verified_grant();
        grant = VerifiedTrustGrant::new(
            grant.document().clone(),
            VerificationMetadata::new(
                grant.metadata().verified_at(),
                grant.metadata().posture(),
                grant.metadata().signer_binding().clone(),
                grant.metadata().ownership().clone(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 7, 13, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        );

        // Create a request with evaluated_at just past fresh_until
        let request = recognize_request_at(fixed_timestamp(2026, 4, 7, 13, 0, 1));
        let outcome = engine.evaluate(&grant, &request);

        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::StaleRevocationData)
        );
    }

    #[test]
    fn evaluation_denies_when_principal_scope_does_not_match() {
        let engine = EvaluationEngine::new();
        let mut request = recognize_request();
        request = match EvaluationRequest::new(
            request.operation().clone(),
            request.resource_binding().clone(),
            request.target_authority().clone(),
            request.audience_authority().clone(),
            request.resource().clone(),
            request.evaluated_at(),
        ) {
            Ok(request) => request,
            Err(error) => panic!("request rebuild should succeed: {error}"),
        };

        if let Err(error) = request.insert_audience_principal_selector("actor", "other-player") {
            panic!("audience principal selector should be valid: {error}");
        }

        let outcome = engine.evaluate(&verified_grant(), &request);

        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::AudiencePrincipalNotAllowed)
        );
    }

    #[test]
    fn evaluation_denies_mint_without_runtime_mint_context() {
        let outcome = EvaluationEngine::new().evaluate(&mint_grant(), &mint_request());

        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::MissingMintContext)
        );
    }

    #[test]
    fn evaluation_denies_mint_when_audience_principal_context_is_absent() {
        // When max_per_user is set, the engine demands an audience principal
        // context.  This test uses a grant whose audience entry has no
        // principal_scope (so the audience check passes) but the minting
        // constraints still require principal context for per-user counting.
        //
        // SelectorContext::is_empty() checks whether any selector entries
        // exist (the entries Vec).  Through the public API it is impossible
        // to insert a selector kind with zero values — insert() always
        // creates an entry with at least one value.  Therefore the behaviour
        // is binary: either a caller has called
        // insert_audience_principal_selector() (is_empty → false) or they
        // have not (is_empty → true).  A hypothetical "selector with
        // values: []" cannot be constructed via the public API surface.

        let mut resource = match ResourceContext::new("item") {
            Ok(resource) => resource,
            Err(error) => panic!("resource context should be valid: {error}"),
        };
        if let Err(error) = resource.insert_selector("namespace", "weapons") {
            panic!("resource selector should be valid: {error}");
        }

        let origin = origin();
        let request = match EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Mint),
            ResourceBinding::Mint(TemplateRef::new(origin)),
            match AuthorityId::new("https://target.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid target authority: {error}"),
            },
            match AuthorityId::new("https://audience.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid audience authority: {error}"),
            },
            resource,
            fixed_timestamp(2026, 4, 7, 13, 0, 0),
        ) {
            Ok(request) => request,
            Err(error) => panic!("mint evaluation request should be valid: {error}"),
        }
        .with_runtime_mint_context(MintContext::new(5, 0));

        let outcome =
            EvaluationEngine::new().evaluate(&mint_grant_without_principal_scope(), &request);

        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::MissingAudiencePrincipalContext),
        );
    }

    #[test]
    fn evaluation_denies_mint_when_total_limit_is_reached() {
        let request = mint_request().with_runtime_mint_context(MintContext::new(10, 0));
        let outcome = EvaluationEngine::new().evaluate(&mint_grant(), &request);

        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::MintTotalLimitReached)
        );
    }

    #[test]
    fn evaluation_denies_mint_when_per_user_limit_is_reached() {
        let request = mint_request().with_runtime_mint_context(MintContext::new(2, 1));
        let outcome = EvaluationEngine::new().evaluate(&mint_grant(), &request);

        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::MintPerUserLimitReached)
        );
    }

    #[test]
    fn evaluation_allows_mint_when_constraints_are_respected() {
        let request = mint_request().with_runtime_mint_context(MintContext::new(9, 0));
        let outcome = EvaluationEngine::new().evaluate(&mint_grant(), &request);

        assert!(outcome.decision().is_allowed());
    }

    #[test]
    fn evaluation_allows_create_when_mint_operations_are_absent() {
        let request = mint_request().with_runtime_mint_context(MintContext::new(9, 0));
        let outcome = EvaluationEngine::new().evaluate(&mint_grant_without_operations(), &request);

        assert!(outcome.decision().is_allowed());
    }

    #[test]
    fn evaluation_allows_matching_selector_expression() {
        let outcome = EvaluationEngine::new()
            .evaluate(&expression_grant(), &expression_request("weapon_epic"));

        assert!(outcome.decision().is_allowed());
    }

    #[test]
    fn evaluation_denies_non_matching_selector_expression() {
        let outcome = EvaluationEngine::new()
            .evaluate(&expression_grant(), &expression_request("armor_epic"));

        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::ResourceNotAllowed)
        );
    }

    #[test]
    fn evaluation_denies_expired_grant() {
        let engine = EvaluationEngine::new();
        let grant = verified_grant();
        // not_after is 2026-04-08T12:00:00Z; evaluated_at after that => Expired
        let mut resource = match ResourceContext::new("item") {
            Ok(resource) => resource,
            Err(error) => panic!("resource context should be valid: {error}"),
        };
        if let Err(error) = resource.insert_selector("namespace", "weapons") {
            panic!("resource selector should be valid: {error}");
        }
        let origin = origin();
        let request = match EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Recognize),
            ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
            match AuthorityId::new("https://target.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid target authority: {error}"),
            },
            match AuthorityId::new("https://audience.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid audience authority: {error}"),
            },
            resource,
            fixed_timestamp(2026, 4, 8, 13, 0, 0),
        ) {
            Ok(request) => request,
            Err(error) => panic!("evaluation request should be valid: {error}"),
        };

        let outcome = engine.evaluate(&grant, &request);
        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::Expired)
        );
    }

    #[test]
    fn evaluation_denies_not_yet_valid_grant() {
        let engine = EvaluationEngine::new();
        let grant = verified_grant();
        // not_before is 2026-04-07T12:00:00Z; evaluated_at before that => NotYetValid
        let mut resource = match ResourceContext::new("item") {
            Ok(resource) => resource,
            Err(error) => panic!("resource context should be valid: {error}"),
        };
        if let Err(error) = resource.insert_selector("namespace", "weapons") {
            panic!("resource selector should be valid: {error}");
        }
        let origin = origin();
        let request = match EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Recognize),
            ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
            match AuthorityId::new("https://target.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid target authority: {error}"),
            },
            match AuthorityId::new("https://audience.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid audience authority: {error}"),
            },
            resource,
            fixed_timestamp(2026, 4, 7, 11, 0, 0),
        ) {
            Ok(request) => request,
            Err(error) => panic!("evaluation request should be valid: {error}"),
        };

        let outcome = engine.evaluate(&grant, &request);
        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::NotYetValid)
        );
    }

    #[test]
    fn evaluation_denies_resource_type_not_granted() {
        let engine = EvaluationEngine::new();
        let grant = verified_grant();
        // Grant only has resource type "item"; request "weapon" => ResourceTypeNotGranted
        let mut resource = match ResourceContext::new("weapon") {
            Ok(resource) => resource,
            Err(error) => panic!("resource context should be valid: {error}"),
        };
        if let Err(error) = resource.insert_selector("namespace", "weapons") {
            panic!("resource selector should be valid: {error}");
        }
        let origin = origin();
        let request = match EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Recognize),
            ResourceBinding::Existing(ResourceRef::new(origin, "weapon".to_owned())),
            match AuthorityId::new("https://target.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid target authority: {error}"),
            },
            match AuthorityId::new("https://audience.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid audience authority: {error}"),
            },
            resource,
            fixed_timestamp(2026, 4, 7, 13, 0, 0),
        ) {
            Ok(request) => request,
            Err(error) => panic!("evaluation request should be valid: {error}"),
        };
        let outcome = engine.evaluate(&grant, &request);
        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::ResourceTypeNotGranted)
        );
    }

    #[test]
    fn evaluation_denies_target_denied_by_selector() {
        let engine = EvaluationEngine::new();
        // Build request whose target authority is "https://denied.example.com"
        // Grant target_scope deny is empty, so we need to build a grant with deny.
        // Instead, use a target that doesn't match the allow list.
        // The grant allows authority "https://target.example.com" but not others => TargetNotAllowed.
        // For TargetDenied we need a deny selector that matches. Build a custom grant.
        let raw = RawTrustGrantDocument {
            trustgrant_id: "tg_123e4567-e89b-12d3-a456-426614174090".into(),
            version: 0,
            grant_series_id: "tgs_123e4567-e89b-12d3-a456-426614174091".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://issuer.example.com".into(),
            active_owning_authority: "https://issuer.example.com".into(),
            key_id: "root-key-1".into(),
            target_scope: RawScope {
                all: false,
                allow: Some(vec![RawSelector {
                    kind: "authority".into(),
                    all: false,
                    values: Some(vec!["https://target.example.com".into()]),
                    expressions: None,
                }]),
                deny: Some(vec![RawSelector {
                    kind: "authority".into(),
                    all: false,
                    values: Some(vec!["https://target.example.com".into()]),
                    expressions: None,
                }]),
            },
            capabilities: RawCapabilities {
                recognize: true,
                mint: false,
            },
            default_audience_scope: None,
            resource_scope: RawResourceScope {
                types: std::collections::BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: false,
                        allow: Some(vec![RawSelector {
                            kind: "namespace".into(),
                            all: false,
                            values: Some(vec!["weapons".into()]),
                            expressions: None,
                        }]),
                        deny: None,
                        capabilities: RawTypeCapabilities {
                            recognize: Some(true),
                            mint: Some(false),
                        },
                        constraints: RawTypeConstraints {
                            minting: RawMintingConstraints {
                                max_total: None,
                                max_per_user: None,
                            },
                            audience_scope: None,
                        },
                        operations: None,
                    },
                )]),
            },
            global_constraints: Some(RawGlobalConstraints {
                time: Some(RawTimeWindow {
                    not_before: fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    not_after: fixed_timestamp(2026, 4, 8, 12, 0, 0),
                }),
            }),
            revocation: Some(RawRevocation {
                revocable: true,
                revocation_endpoint: "https://issuer.example.com/revocation".into(),
            }),
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "base64-signature".into(),
            issuer_principal: Some(RawPrincipal {
                kind: "service".into(),
                id: "issuer-worker".into(),
            }),
        };

        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => panic!("validated document should succeed: {error}"),
        };

        let deny_grant = VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        );

        let outcome = engine.evaluate(&deny_grant, &recognize_request());
        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::TargetDenied)
        );
    }

    #[test]
    fn evaluation_denies_operation_denied_by_deny_list() {
        let engine = EvaluationEngine::new();
        let _grant = verified_grant();
        // The grant resource type "item" has operations.allow = ["recognize"] and deny = null.
        // Build a grant with operations deny = ["recognize"] to trigger OperationDenied.
        let raw = RawTrustGrantDocument {
            trustgrant_id: "tg_123e4567-e89b-12d3-a456-426614174092".into(),
            version: 0,
            grant_series_id: "tgs_123e4567-e89b-12d3-a456-426614174093".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://issuer.example.com".into(),
            active_owning_authority: "https://issuer.example.com".into(),
            key_id: "root-key-1".into(),
            target_scope: RawScope {
                all: false,
                allow: Some(vec![RawSelector {
                    kind: "authority".into(),
                    all: false,
                    values: Some(vec!["https://target.example.com".into()]),
                    expressions: None,
                }]),
                deny: None,
            },
            capabilities: RawCapabilities {
                recognize: true,
                mint: false,
            },
            default_audience_scope: None,
            resource_scope: RawResourceScope {
                types: std::collections::BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: false,
                        allow: Some(vec![RawSelector {
                            kind: "namespace".into(),
                            all: false,
                            values: Some(vec!["weapons".into()]),
                            expressions: None,
                        }]),
                        deny: None,
                        capabilities: RawTypeCapabilities {
                            recognize: Some(true),
                            mint: Some(false),
                        },
                        constraints: RawTypeConstraints {
                            minting: RawMintingConstraints {
                                max_total: None,
                                max_per_user: None,
                            },
                            audience_scope: None,
                        },
                        operations: Some(RawOperationScope {
                            all: false,
                            allow: Some(vec!["other_op".into()]),
                            deny: Some(vec!["recognize".into()]),
                        }),
                    },
                )]),
            },
            global_constraints: Some(RawGlobalConstraints {
                time: Some(RawTimeWindow {
                    not_before: fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    not_after: fixed_timestamp(2026, 4, 8, 12, 0, 0),
                }),
            }),
            revocation: Some(RawRevocation {
                revocable: true,
                revocation_endpoint: "https://issuer.example.com/revocation".into(),
            }),
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "base64-signature".into(),
            issuer_principal: Some(RawPrincipal {
                kind: "service".into(),
                id: "issuer-worker".into(),
            }),
        };

        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => panic!("validated document should succeed: {error}"),
        };

        let deny_grant = VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        );

        let outcome = engine.evaluate(&deny_grant, &recognize_request());
        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::OperationDenied)
        );
    }

    #[test]
    fn evaluation_denies_capability_disabled_when_type_overrides_to_false() {
        let engine = EvaluationEngine::new();

        let raw = RawTrustGrantDocument {
            trustgrant_id: "tg_a0000000-0000-1000-a000-000000000001".into(),
            version: 0,
            grant_series_id: "tgs_a0000000-0000-1000-a000-000000000001".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://issuer.example.com".into(),
            active_owning_authority: "https://issuer.example.com".into(),
            key_id: "root-key-1".into(),
            target_scope: RawScope {
                all: false,
                allow: Some(vec![RawSelector {
                    kind: "authority".into(),
                    all: false,
                    values: Some(vec!["https://target.example.com".into()]),
                    expressions: None,
                }]),
                deny: None,
            },
            capabilities: RawCapabilities {
                recognize: true,
                mint: false,
            },
            default_audience_scope: None,
            resource_scope: RawResourceScope {
                types: std::collections::BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: false,
                        allow: Some(vec![RawSelector {
                            kind: "namespace".into(),
                            all: false,
                            values: Some(vec!["weapons".into()]),
                            expressions: None,
                        }]),
                        deny: None,
                        capabilities: RawTypeCapabilities {
                            recognize: Some(false),
                            mint: Some(false),
                        },
                        constraints: RawTypeConstraints {
                            minting: RawMintingConstraints {
                                max_total: None,
                                max_per_user: None,
                            },
                            audience_scope: None,
                        },
                        operations: Some(RawOperationScope {
                            all: false,
                            allow: Some(vec!["recognize".into()]),
                            deny: None,
                        }),
                    },
                )]),
            },
            global_constraints: Some(RawGlobalConstraints {
                time: Some(RawTimeWindow {
                    not_before: fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    not_after: fixed_timestamp(2026, 4, 8, 12, 0, 0),
                }),
            }),
            revocation: Some(RawRevocation {
                revocable: true,
                revocation_endpoint: "https://issuer.example.com/revocation".into(),
            }),
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "base64-signature".into(),
            issuer_principal: Some(RawPrincipal {
                kind: "service".into(),
                id: "issuer-worker".into(),
            }),
        };

        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => panic!("validated document should succeed: {error}"),
        };

        let grant = VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        );

        let outcome = engine.evaluate(&grant, &recognize_request());

        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::CapabilityDisabled),
        );
    }

    #[test]
    fn evaluation_denies_audience_denied_by_selector() {
        let engine = EvaluationEngine::new();

        let raw = RawTrustGrantDocument {
            trustgrant_id: "tg_b0000000-0000-1000-a000-000000000002".into(),
            version: 0,
            grant_series_id: "tgs_b0000000-0000-1000-a000-000000000002".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://issuer.example.com".into(),
            active_owning_authority: "https://issuer.example.com".into(),
            key_id: "root-key-1".into(),
            target_scope: RawScope {
                all: false,
                allow: Some(vec![RawSelector {
                    kind: "authority".into(),
                    all: false,
                    values: Some(vec!["https://target.example.com".into()]),
                    expressions: None,
                }]),
                deny: None,
            },
            capabilities: RawCapabilities {
                recognize: true,
                mint: false,
            },
            default_audience_scope: None,
            resource_scope: RawResourceScope {
                types: std::collections::BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: false,
                        allow: Some(vec![RawSelector {
                            kind: "namespace".into(),
                            all: false,
                            values: Some(vec!["weapons".into()]),
                            expressions: None,
                        }]),
                        deny: None,
                        capabilities: RawTypeCapabilities {
                            recognize: Some(true),
                            mint: Some(false),
                        },
                        constraints: RawTypeConstraints {
                            minting: RawMintingConstraints {
                                max_total: None,
                                max_per_user: None,
                            },
                            audience_scope: Some(vec![RawAudienceEntry {
                                authority_id: "https://audience.example.com".into(),
                                scope: RawScope {
                                    all: false,
                                    allow: Some(vec![RawSelector {
                                        kind: "authority_id".into(),
                                        all: false,
                                        values: Some(vec!["https://audience.example.com".into()]),
                                        expressions: None,
                                    }]),
                                    deny: Some(vec![RawSelector {
                                        kind: "authority".into(),
                                        all: false,
                                        values: Some(vec!["https://audience.example.com".into()]),
                                        expressions: None,
                                    }]),
                                },
                                principal_scope: None,
                            }]),
                        },
                        operations: Some(RawOperationScope {
                            all: false,
                            allow: Some(vec!["recognize".into()]),
                            deny: None,
                        }),
                    },
                )]),
            },
            global_constraints: Some(RawGlobalConstraints {
                time: Some(RawTimeWindow {
                    not_before: fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    not_after: fixed_timestamp(2026, 4, 8, 12, 0, 0),
                }),
            }),
            revocation: Some(RawRevocation {
                revocable: true,
                revocation_endpoint: "https://issuer.example.com/revocation".into(),
            }),
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "base64-signature".into(),
            issuer_principal: Some(RawPrincipal {
                kind: "service".into(),
                id: "issuer-worker".into(),
            }),
        };

        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => panic!("validated audience-denied document should succeed: {error}"),
        };

        let grant = VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        );

        let outcome = engine.evaluate(&grant, &recognize_request());

        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::AudienceDenied),
        );
    }

    #[test]
    fn evaluation_denies_audience_not_allowed_when_authority_mismatches() {
        let engine = EvaluationEngine::new();

        let raw = RawTrustGrantDocument {
            trustgrant_id: "tg_c0000000-0000-1000-a000-000000000003".into(),
            version: 0,
            grant_series_id: "tgs_c0000000-0000-1000-a000-000000000003".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://issuer.example.com".into(),
            active_owning_authority: "https://issuer.example.com".into(),
            key_id: "root-key-1".into(),
            target_scope: RawScope {
                all: false,
                allow: Some(vec![RawSelector {
                    kind: "authority".into(),
                    all: false,
                    values: Some(vec!["https://target.example.com".into()]),
                    expressions: None,
                }]),
                deny: None,
            },
            capabilities: RawCapabilities {
                recognize: true,
                mint: false,
            },
            default_audience_scope: None,
            resource_scope: RawResourceScope {
                types: std::collections::BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: false,
                        allow: Some(vec![RawSelector {
                            kind: "namespace".into(),
                            all: false,
                            values: Some(vec!["weapons".into()]),
                            expressions: None,
                        }]),
                        deny: None,
                        capabilities: RawTypeCapabilities {
                            recognize: Some(true),
                            mint: Some(false),
                        },
                        constraints: RawTypeConstraints {
                            minting: RawMintingConstraints {
                                max_total: None,
                                max_per_user: None,
                            },
                            audience_scope: Some(vec![RawAudienceEntry {
                                authority_id: "https://other.example.com".into(),
                                scope: RawScope {
                                    all: true,
                                    allow: None,
                                    deny: None,
                                },
                                principal_scope: None,
                            }]),
                        },
                        operations: Some(RawOperationScope {
                            all: false,
                            allow: Some(vec!["recognize".into()]),
                            deny: None,
                        }),
                    },
                )]),
            },
            global_constraints: Some(RawGlobalConstraints {
                time: Some(RawTimeWindow {
                    not_before: fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    not_after: fixed_timestamp(2026, 4, 8, 12, 0, 0),
                }),
            }),
            revocation: Some(RawRevocation {
                revocable: true,
                revocation_endpoint: "https://issuer.example.com/revocation".into(),
            }),
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "base64-signature".into(),
            issuer_principal: Some(RawPrincipal {
                kind: "service".into(),
                id: "issuer-worker".into(),
            }),
        };

        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => {
                panic!("validated audience-not-allowed document should succeed: {error}")
            }
        };

        let grant = VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        );

        let outcome = engine.evaluate(&grant, &recognize_request());

        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::AudienceNotAllowed),
        );
    }

    #[test]
    fn evaluation_denies_operation_denied_when_all_scope_has_deny_list() {
        let engine = EvaluationEngine::new();

        let raw = RawTrustGrantDocument {
            trustgrant_id: "tg_d0000000-0000-1000-a000-000000000004".into(),
            version: 0,
            grant_series_id: "tgs_d0000000-0000-1000-a000-000000000004".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://issuer.example.com".into(),
            active_owning_authority: "https://issuer.example.com".into(),
            key_id: "root-key-1".into(),
            target_scope: RawScope {
                all: false,
                allow: Some(vec![RawSelector {
                    kind: "authority".into(),
                    all: false,
                    values: Some(vec!["https://target.example.com".into()]),
                    expressions: None,
                }]),
                deny: None,
            },
            capabilities: RawCapabilities {
                recognize: true,
                mint: false,
            },
            default_audience_scope: None,
            resource_scope: RawResourceScope {
                types: std::collections::BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: false,
                        allow: Some(vec![RawSelector {
                            kind: "namespace".into(),
                            all: false,
                            values: Some(vec!["weapons".into()]),
                            expressions: None,
                        }]),
                        deny: None,
                        capabilities: RawTypeCapabilities {
                            recognize: Some(true),
                            mint: Some(false),
                        },
                        constraints: RawTypeConstraints {
                            minting: RawMintingConstraints {
                                max_total: None,
                                max_per_user: None,
                            },
                            audience_scope: None,
                        },
                        operations: Some(RawOperationScope {
                            all: true,
                            allow: None,
                            deny: Some(vec!["recognize".into()]),
                        }),
                    },
                )]),
            },
            global_constraints: Some(RawGlobalConstraints {
                time: Some(RawTimeWindow {
                    not_before: fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    not_after: fixed_timestamp(2026, 4, 8, 12, 0, 0),
                }),
            }),
            revocation: Some(RawRevocation {
                revocable: true,
                revocation_endpoint: "https://issuer.example.com/revocation".into(),
            }),
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "base64-signature".into(),
            issuer_principal: Some(RawPrincipal {
                kind: "service".into(),
                id: "issuer-worker".into(),
            }),
        };

        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => panic!("validated document should succeed: {error}"),
        };

        let grant = VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        );

        let outcome = engine.evaluate(&grant, &recognize_request());

        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::OperationDenied),
        );
    }

    #[test]
    fn evaluation_denies_custom_operation_when_no_operations_scope() {
        let engine = EvaluationEngine::new();
        let grant = mint_grant_without_operations();

        let custom_op = match CustomOperationName::new("my_action") {
            Ok(name) => name,
            Err(error) => panic!("custom operation name should be valid: {error}"),
        };

        let mut resource = match ResourceContext::new("item") {
            Ok(resource) => resource,
            Err(error) => panic!("resource context should be valid: {error}"),
        };
        if let Err(error) = resource.insert_selector("namespace", "weapons") {
            panic!("resource selector should be valid: {error}");
        }

        let origin = origin();
        let request = match EvaluationRequest::new(
            RequestedOperation::Custom(custom_op),
            ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
            match AuthorityId::new("https://target.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid target authority: {error}"),
            },
            match AuthorityId::new("https://audience.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid audience authority: {error}"),
            },
            resource,
            fixed_timestamp(2026, 4, 7, 13, 0, 0),
        ) {
            Ok(request) => request,
            Err(error) => panic!("evaluation request should be valid: {error}"),
        };

        let outcome = engine.evaluate(&grant, &request);

        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::OperationDenied),
        );
    }

    #[test]
    fn evaluation_allows_custom_operation_without_capabilities_when_operations_scope_permits() {
        // Custom operations are authorized solely by the operations scope,
        // not gated on built-in capabilities (recognize/mint).
        let engine = EvaluationEngine::new();

        let raw = RawTrustGrantDocument {
            trustgrant_id: "tg_f0000000-0000-1000-a000-000000000006".into(),
            version: 0,
            grant_series_id: "tgs_f0000000-0000-1000-a000-000000000006".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://issuer.example.com".into(),
            active_owning_authority: "https://issuer.example.com".into(),
            key_id: "root-key-1".into(),
            target_scope: RawScope {
                all: false,
                allow: Some(vec![RawSelector {
                    kind: "authority".into(),
                    all: false,
                    values: Some(vec!["https://target.example.com".into()]),
                    expressions: None,
                }]),
                deny: None,
            },
            capabilities: RawCapabilities {
                recognize: false,
                mint: false,
            },
            default_audience_scope: None,
            resource_scope: RawResourceScope {
                types: std::collections::BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: false,
                        allow: Some(vec![RawSelector {
                            kind: "namespace".into(),
                            all: false,
                            values: Some(vec!["weapons".into()]),
                            expressions: None,
                        }]),
                        deny: None,
                        capabilities: RawTypeCapabilities {
                            recognize: Some(false),
                            mint: Some(false),
                        },
                        constraints: RawTypeConstraints {
                            minting: RawMintingConstraints {
                                max_total: None,
                                max_per_user: None,
                            },
                            audience_scope: None,
                        },
                        operations: Some(RawOperationScope {
                            all: true,
                            allow: None,
                            deny: None,
                        }),
                    },
                )]),
            },
            global_constraints: Some(RawGlobalConstraints {
                time: Some(RawTimeWindow {
                    not_before: fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    not_after: fixed_timestamp(2026, 4, 8, 12, 0, 0),
                }),
            }),
            revocation: Some(RawRevocation {
                revocable: true,
                revocation_endpoint: "https://issuer.example.com/revocation".into(),
            }),
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "base64-signature".into(),
            issuer_principal: Some(RawPrincipal {
                kind: "service".into(),
                id: "issuer-worker".into(),
            }),
        };

        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => panic!("validated document should succeed: {error}"),
        };

        let grant = VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        );

        let custom_op = match CustomOperationName::new("transfer") {
            Ok(name) => name,
            Err(error) => panic!("custom operation name should be valid: {error}"),
        };

        let mut resource = match ResourceContext::new("item") {
            Ok(resource) => resource,
            Err(error) => panic!("resource context should be valid: {error}"),
        };
        if let Err(error) = resource.insert_selector("namespace", "weapons") {
            panic!("resource selector should be valid: {error}");
        }

        let origin = origin();
        let request = match EvaluationRequest::new(
            RequestedOperation::Custom(custom_op),
            ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
            match AuthorityId::new("https://target.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid target authority: {error}"),
            },
            match AuthorityId::new("https://audience.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid audience authority: {error}"),
            },
            resource,
            fixed_timestamp(2026, 4, 7, 13, 0, 0),
        ) {
            Ok(request) => request,
            Err(error) => panic!("evaluation request should be valid: {error}"),
        };

        let outcome = engine.evaluate(&grant, &request);

        assert!(outcome.decision().is_allowed());
    }

    #[test]
    fn evaluation_denies_custom_operation_when_operations_scope_restrictive_even_with_capabilities()
    {
        // Custom operations are gated by the operations scope alone.
        // Even with capabilities enabled, a restrictive operations scope denies.
        let engine = EvaluationEngine::new();

        let raw = RawTrustGrantDocument {
            trustgrant_id: "tg_f0000000-0000-1000-a000-000000000007".into(),
            version: 0,
            grant_series_id: "tgs_f0000000-0000-1000-a000-000000000007".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://issuer.example.com".into(),
            active_owning_authority: "https://issuer.example.com".into(),
            key_id: "root-key-1".into(),
            target_scope: RawScope {
                all: false,
                allow: Some(vec![RawSelector {
                    kind: "authority".into(),
                    all: false,
                    values: Some(vec!["https://target.example.com".into()]),
                    expressions: None,
                }]),
                deny: None,
            },
            capabilities: RawCapabilities {
                recognize: true,
                mint: true,
            },
            default_audience_scope: None,
            resource_scope: RawResourceScope {
                types: std::collections::BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: false,
                        allow: Some(vec![RawSelector {
                            kind: "namespace".into(),
                            all: false,
                            values: Some(vec!["weapons".into()]),
                            expressions: None,
                        }]),
                        deny: None,
                        capabilities: RawTypeCapabilities {
                            recognize: None,
                            mint: None,
                        },
                        constraints: RawTypeConstraints {
                            minting: RawMintingConstraints {
                                max_total: None,
                                max_per_user: None,
                            },
                            audience_scope: None,
                        },
                        operations: Some(RawOperationScope {
                            all: false,
                            allow: Some(vec!["download".into()]),
                            deny: None,
                        }),
                    },
                )]),
            },
            global_constraints: Some(RawGlobalConstraints {
                time: Some(RawTimeWindow {
                    not_before: fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    not_after: fixed_timestamp(2026, 4, 8, 12, 0, 0),
                }),
            }),
            revocation: Some(RawRevocation {
                revocable: true,
                revocation_endpoint: "https://issuer.example.com/revocation".into(),
            }),
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "base64-signature".into(),
            issuer_principal: Some(RawPrincipal {
                kind: "service".into(),
                id: "issuer-worker".into(),
            }),
        };

        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => panic!("validated document should succeed: {error}"),
        };

        let grant = VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        );

        let custom_op = match CustomOperationName::new("upload") {
            Ok(name) => name,
            Err(error) => panic!("custom operation name should be valid: {error}"),
        };

        let mut resource = match ResourceContext::new("item") {
            Ok(resource) => resource,
            Err(error) => panic!("resource context should be valid: {error}"),
        };
        if let Err(error) = resource.insert_selector("namespace", "weapons") {
            panic!("resource selector should be valid: {error}");
        }

        let origin = origin();
        let request = match EvaluationRequest::new(
            RequestedOperation::Custom(custom_op),
            ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
            match AuthorityId::new("https://target.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid target authority: {error}"),
            },
            match AuthorityId::new("https://audience.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid audience authority: {error}"),
            },
            resource,
            fixed_timestamp(2026, 4, 7, 13, 0, 0),
        ) {
            Ok(request) => request,
            Err(error) => panic!("evaluation request should be valid: {error}"),
        };

        let outcome = engine.evaluate(&grant, &request);

        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::OperationDenied),
        );
    }

    // ── Regression tests for spec-compliance fixes ────────────────────────

    #[test]
    fn evaluation_ordering_capability_before_resource_scope() {
        // F2 regression: spec Section 13 defines evaluation order as
        // capability → resource → operation → audience → minting.
        // When BOTH capability AND resource scope fail, the deny reason
        // must reflect the EARLIER check (capability).
        let engine = EvaluationEngine::new();

        let raw = RawTrustGrantDocument {
            trustgrant_id: "tg_123e4567-e89b-12d3-a456-426614174030".into(),
            version: 0,
            grant_series_id: "tgs_123e4567-e89b-12d3-a456-426614174031".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://issuer.example.com".into(),
            active_owning_authority: "https://issuer.example.com".into(),
            key_id: "root-key-1".into(),
            target_scope: RawScope {
                all: false,
                allow: Some(vec![RawSelector {
                    kind: "authority".into(),
                    all: false,
                    values: Some(vec!["https://target.example.com".into()]),
                    expressions: None,
                }]),
                deny: None,
            },
            capabilities: RawCapabilities {
                recognize: true,
                mint: false,
            },
            default_audience_scope: None,
            resource_scope: RawResourceScope {
                types: std::collections::BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: false,
                        allow: Some(vec![RawSelector {
                            kind: "namespace".into(),
                            all: false,
                            values: Some(vec!["weapons".into()]),
                            expressions: None,
                        }]),
                        deny: None,
                        // Type-level override: recognize disabled
                        capabilities: RawTypeCapabilities {
                            recognize: Some(false),
                            mint: Some(false),
                        },
                        constraints: RawTypeConstraints {
                            minting: RawMintingConstraints {
                                max_total: None,
                                max_per_user: None,
                            },
                            audience_scope: None,
                        },
                        operations: Some(RawOperationScope {
                            all: false,
                            allow: Some(vec!["recognize".into()]),
                            deny: None,
                        }),
                    },
                )]),
            },
            global_constraints: Some(RawGlobalConstraints {
                time: Some(RawTimeWindow {
                    not_before: fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    not_after: fixed_timestamp(2026, 4, 8, 12, 0, 0),
                }),
            }),
            revocation: Some(RawRevocation {
                revocable: true,
                revocation_endpoint: "https://issuer.example.com/revocation".into(),
            }),
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "base64-signature".into(),
            issuer_principal: Some(RawPrincipal {
                kind: "service".into(),
                id: "issuer-worker".into(),
            }),
        };

        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => panic!("validated document should succeed: {error}"),
        };

        let grant = VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        );

        // Request with namespace "armor" — doesn't match allow list "weapons".
        // Capability is also disabled at type level.
        // Capability check runs first per spec Section 13, so we must get
        // CapabilityDisabled, NOT ResourceNotAllowed.
        let mut resource = match ResourceContext::new("item") {
            Ok(resource) => resource,
            Err(error) => panic!("resource context should be valid: {error}"),
        };
        if let Err(error) = resource.insert_selector("namespace", "armor") {
            panic!("resource selector should be valid: {error}");
        }

        let origin = origin();
        let request = match EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Recognize),
            ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
            match AuthorityId::new("https://target.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid target authority: {error}"),
            },
            match AuthorityId::new("https://audience.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid audience authority: {error}"),
            },
            resource,
            fixed_timestamp(2026, 4, 7, 13, 0, 0),
        ) {
            Ok(request) => request,
            Err(error) => panic!("evaluation request should be valid: {error}"),
        };

        let outcome = engine.evaluate(&grant, &request);

        // CapabilityDisabled must come first — it is checked before resource
        // scope in the spec ordering.  If resource scope were checked first,
        // the deny reason would incorrectly be ResourceNotAllowed.
        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::CapabilityDisabled),
        );
    }

    #[test]
    fn scope_evaluation_deny_wins_over_allow() {
        // F3 regression: spec Section 10 says allow is primary but deny is
        // always subtractive.  When a value matches BOTH an allow selector
        // AND a deny selector, deny wins and the reason must be the
        // deny-specific reason (ResourceDenied), not the not-allowed reason.
        let engine = EvaluationEngine::new();

        let raw = RawTrustGrantDocument {
            trustgrant_id: "tg_123e4567-e89b-12d3-a456-426614174032".into(),
            version: 0,
            grant_series_id: "tgs_123e4567-e89b-12d3-a456-426614174033".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://issuer.example.com".into(),
            active_owning_authority: "https://issuer.example.com".into(),
            key_id: "root-key-1".into(),
            target_scope: RawScope {
                all: false,
                allow: Some(vec![RawSelector {
                    kind: "authority".into(),
                    all: false,
                    values: Some(vec!["https://target.example.com".into()]),
                    expressions: None,
                }]),
                deny: None,
            },
            capabilities: RawCapabilities {
                recognize: true,
                mint: false,
            },
            default_audience_scope: None,
            resource_scope: RawResourceScope {
                types: std::collections::BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: false,
                        // Allow "weapons"
                        allow: Some(vec![RawSelector {
                            kind: "namespace".into(),
                            all: false,
                            values: Some(vec!["weapons".into()]),
                            expressions: None,
                        }]),
                        // Deny "weapons" — same value as allow
                        deny: Some(vec![RawSelector {
                            kind: "namespace".into(),
                            all: false,
                            values: Some(vec!["weapons".into()]),
                            expressions: None,
                        }]),
                        capabilities: RawTypeCapabilities {
                            recognize: Some(true),
                            mint: Some(false),
                        },
                        constraints: RawTypeConstraints {
                            minting: RawMintingConstraints {
                                max_total: None,
                                max_per_user: None,
                            },
                            audience_scope: None,
                        },
                        operations: Some(RawOperationScope {
                            all: false,
                            allow: Some(vec!["recognize".into()]),
                            deny: None,
                        }),
                    },
                )]),
            },
            global_constraints: Some(RawGlobalConstraints {
                time: Some(RawTimeWindow {
                    not_before: fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    not_after: fixed_timestamp(2026, 4, 8, 12, 0, 0),
                }),
            }),
            revocation: Some(RawRevocation {
                revocable: true,
                revocation_endpoint: "https://issuer.example.com/revocation".into(),
            }),
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "base64-signature".into(),
            issuer_principal: Some(RawPrincipal {
                kind: "service".into(),
                id: "issuer-worker".into(),
            }),
        };

        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => panic!("validated document should succeed: {error}"),
        };

        let grant = VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        );

        // Request namespace "weapons" — matches both allow and deny.
        // Deny must win, and the reason must be ResourceDenied (not ResourceNotAllowed).
        let outcome = engine.evaluate(&grant, &recognize_request());

        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::ResourceDenied),
        );
    }

    #[test]
    fn evaluation_denies_custom_operation_by_operations_scope_not_capability() {
        // D2 regression: custom operations are gated solely by the operations
        // scope, not by built-in capabilities.  When capabilities are all
        // enabled but the operations scope only allows "download", requesting
        // a custom "upload" must be denied by OperationDenied — never
        // CapabilityDisabled.
        let engine = EvaluationEngine::new();

        let raw = RawTrustGrantDocument {
            trustgrant_id: "tg_123e4567-e89b-12d3-a456-426614174034".into(),
            version: 0,
            grant_series_id: "tgs_123e4567-e89b-12d3-a456-426614174035".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://issuer.example.com".into(),
            active_owning_authority: "https://issuer.example.com".into(),
            key_id: "root-key-1".into(),
            target_scope: RawScope {
                all: false,
                allow: Some(vec![RawSelector {
                    kind: "authority".into(),
                    all: false,
                    values: Some(vec!["https://target.example.com".into()]),
                    expressions: None,
                }]),
                deny: None,
            },
            capabilities: RawCapabilities {
                recognize: true,
                mint: true,
            },
            default_audience_scope: None,
            resource_scope: RawResourceScope {
                types: std::collections::BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: false,
                        allow: Some(vec![RawSelector {
                            kind: "namespace".into(),
                            all: false,
                            values: Some(vec!["weapons".into()]),
                            expressions: None,
                        }]),
                        deny: None,
                        capabilities: RawTypeCapabilities {
                            recognize: None,
                            mint: None,
                        },
                        constraints: RawTypeConstraints {
                            minting: RawMintingConstraints {
                                max_total: None,
                                max_per_user: None,
                            },
                            audience_scope: None,
                        },
                        // Only "download" is allowed — "upload" is not
                        operations: Some(RawOperationScope {
                            all: false,
                            allow: Some(vec!["download".into()]),
                            deny: None,
                        }),
                    },
                )]),
            },
            global_constraints: Some(RawGlobalConstraints {
                time: Some(RawTimeWindow {
                    not_before: fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    not_after: fixed_timestamp(2026, 4, 8, 12, 0, 0),
                }),
            }),
            revocation: Some(RawRevocation {
                revocable: true,
                revocation_endpoint: "https://issuer.example.com/revocation".into(),
            }),
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "base64-signature".into(),
            issuer_principal: Some(RawPrincipal {
                kind: "service".into(),
                id: "issuer-worker".into(),
            }),
        };

        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => panic!("validated document should succeed: {error}"),
        };

        let grant = VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        );

        let custom_op = match CustomOperationName::new("upload") {
            Ok(name) => name,
            Err(error) => panic!("custom operation name should be valid: {error}"),
        };

        let mut resource = match ResourceContext::new("item") {
            Ok(resource) => resource,
            Err(error) => panic!("resource context should be valid: {error}"),
        };
        if let Err(error) = resource.insert_selector("namespace", "weapons") {
            panic!("resource selector should be valid: {error}");
        }

        let origin = origin();
        let request = match EvaluationRequest::new(
            RequestedOperation::Custom(custom_op),
            ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
            match AuthorityId::new("https://target.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid target authority: {error}"),
            },
            match AuthorityId::new("https://audience.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid audience authority: {error}"),
            },
            resource,
            fixed_timestamp(2026, 4, 7, 13, 0, 0),
        ) {
            Ok(request) => request,
            Err(error) => panic!("evaluation request should be valid: {error}"),
        };

        let outcome = engine.evaluate(&grant, &request);

        // Operations scope is the sole gate for custom operations.
        // "upload" is not in the allow list ["download"], so it must be
        // OperationDenied — never CapabilityDisabled (which only applies
        // to built-in recognize/mint capabilities).
        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::OperationDenied),
        );
        assert_ne!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::CapabilityDisabled),
        );
    }

    #[test]
    fn evaluation_denies_target_when_in_both_allow_and_deny() {
        // Extension of F3: deny-wins-over-allow for TARGET scope (previously
        // only tested for resource scope).  When the target authority appears
        // in both allow and deny of target_scope, deny wins and the reason
        // must be TargetDenied (not TargetNotAllowed).
        let engine = EvaluationEngine::new();

        let json = r#"{
          "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174040",
          "version":0,
          "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174041",
          "revision":1,
          "supersedes":null,
          "supersession_policy":"coexist",
          "issuer_authority":"https://issuer.example.com",
          "origin_authority":"https://issuer.example.com",
          "active_owning_authority":"https://issuer.example.com",
          "key_id":"root-key-1",
          "target_scope":{"all":false,
            "allow":[{"kind":"authority","all":false,"values":["https://target.example.com"],"expressions":null}],
            "deny":[{"kind":"authority","all":false,"values":["https://target.example.com"],"expressions":null}]
          },
          "capabilities":{"recognize":true,"mint":false},
          "default_audience_scope":null,
          "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
          "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
          "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
          "issued_at":"2026-04-07T12:00:00Z",
          "signature":"base64-signature",
          "issuer_principal":{"kind":"service","id":"issuer-worker"}
        }"#;

        let raw = match RawTrustGrantDocument::parse_json_str(json) {
            Ok(document) => document,
            Err(error) => panic!("raw document should parse: {error}"),
        };
        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => panic!("validated document should succeed: {error}"),
        };

        let grant = VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        );

        let outcome = engine.evaluate(&grant, &recognize_request());

        // Target "https://target.example.com" is in both allow and deny of
        // target_scope.  Deny must win with TargetDenied — not TargetNotAllowed.
        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::TargetDenied),
        );
    }

    #[test]
    fn evaluation_empty_deny_list_behaves_like_null_deny() {
        // Both `"deny":null` and `"deny":[]` in target_scope should produce
        // identical evaluation — neither should deny anything.  The validated
        // layer normalises both to an empty Vec<ValidatedSelector>.
        let engine = EvaluationEngine::new();

        // Grant A: target_scope with deny=null (the usual pattern)
        let json_a = r#"{
          "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174042",
          "version":0,
          "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174043",
          "revision":1,
          "supersedes":null,
          "supersession_policy":"coexist",
          "issuer_authority":"https://issuer.example.com",
          "origin_authority":"https://issuer.example.com",
          "active_owning_authority":"https://issuer.example.com",
          "key_id":"root-key-1",
          "target_scope":{"all":false,
            "allow":[{"kind":"authority","all":false,"values":["https://target.example.com"],"expressions":null}],
            "deny":null
          },
          "capabilities":{"recognize":true,"mint":false},
          "default_audience_scope":null,
          "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
          "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
          "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
          "issued_at":"2026-04-07T12:00:00Z",
          "signature":"base64-signature",
          "issuer_principal":{"kind":"service","id":"issuer-worker"}
        }"#;

        // Grant B: target_scope with deny=[] (empty array — not null)
        let json_b = r#"{
          "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174044",
          "version":0,
          "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174045",
          "revision":1,
          "supersedes":null,
          "supersession_policy":"coexist",
          "issuer_authority":"https://issuer.example.com",
          "origin_authority":"https://issuer.example.com",
          "active_owning_authority":"https://issuer.example.com",
          "key_id":"root-key-1",
          "target_scope":{"all":false,
            "allow":[{"kind":"authority","all":false,"values":["https://target.example.com"],"expressions":null}],
            "deny":[]
          },
          "capabilities":{"recognize":true,"mint":false},
          "default_audience_scope":null,
          "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
          "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
          "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
          "issued_at":"2026-04-07T12:00:00Z",
          "signature":"base64-signature",
          "issuer_principal":{"kind":"service","id":"issuer-worker"}
        }"#;

        let make_grant = |json: &str, _trustgrant_id: &str| -> VerifiedTrustGrant {
            let raw = match RawTrustGrantDocument::parse_json_str(json) {
                Ok(document) => document,
                Err(error) => panic!("raw document should parse: {error}"),
            };
            let validated = match ValidatedTrustGrantDocument::try_from(raw) {
                Ok(document) => document,
                Err(error) => panic!("validated document should succeed: {error}"),
            };

            VerifiedTrustGrant::new(
                validated,
                VerificationMetadata::new(
                    fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    VerificationPosture::Online,
                    signer_binding(),
                    ownership_record(),
                    VerifiedRevocationState::Checked(
                        RevocationRecord::new(
                            RevocationStatus::Active,
                            RevocationSourceKind::Api,
                            ProofFinality::Observed,
                            fixed_timestamp(2026, 4, 7, 12, 0, 0),
                            fixed_timestamp(2026, 4, 9, 12, 0, 0),
                        )
                        .unwrap_or_else(|error| {
                            panic!("revocation record should be valid: {error}")
                        }),
                    ),
                ),
            )
        };

        let grant_a = make_grant(json_a, "tg_a");
        let grant_b = make_grant(json_b, "tg_b");
        let request = recognize_request();

        let outcome_a = engine.evaluate(&grant_a, &request);
        let outcome_b = engine.evaluate(&grant_b, &request);

        // Both should allow — empty deny list and null deny are equivalent.
        assert!(
            outcome_a.decision().is_allowed(),
            "grant A (null deny) should allow, got: {:?}",
            outcome_a.decision().deny_reason(),
        );
        assert!(
            outcome_b.decision().is_allowed(),
            "grant B (empty deny) should allow, got: {:?}",
            outcome_b.decision().deny_reason(),
        );
    }

    #[test]
    fn evaluation_audience_matches_first_entry_when_multiple_match() {
        // When a request's audience authority matches multiple audience entries
        // in the grant, the first matching entry is used (via .find() in the
        // audience evaluation).  This test creates a grant with two audience
        // entries for the same authority_id: the first allows, the second
        // denies.  The result should be ALLOW (first entry wins).
        let engine = EvaluationEngine::new();

        let json = r#"{
          "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174046",
          "version":0,
          "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174047",
          "revision":1,
          "supersedes":null,
          "supersession_policy":"coexist",
          "issuer_authority":"https://issuer.example.com",
          "origin_authority":"https://issuer.example.com",
          "active_owning_authority":"https://issuer.example.com",
          "key_id":"root-key-1",
          "target_scope":{"all":false,
            "allow":[{"kind":"authority","all":false,"values":["https://target.example.com"],"expressions":null}],
            "deny":null
          },
          "capabilities":{"recognize":true,"mint":false},
          "default_audience_scope":null,
          "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":[
            {"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":null},
            {"authority_id":"https://audience.example.com","scope":{"all":false,"allow":[{"kind":"authority_id","all":false,"values":["https://audience.example.com"],"expressions":null}],"deny":[{"kind":"authority_id","all":false,"values":["https://audience.example.com"],"expressions":null}]},"principal_scope":null}
          ]},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
          "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
          "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
          "issued_at":"2026-04-07T12:00:00Z",
          "signature":"base64-signature",
          "issuer_principal":{"kind":"service","id":"issuer-worker"}
        }"#;

        let raw = match RawTrustGrantDocument::parse_json_str(json) {
            Ok(document) => document,
            Err(error) => panic!("raw document should parse: {error}"),
        };
        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => panic!("validated document should succeed: {error}"),
        };

        let grant = VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        );

        let outcome = engine.evaluate(&grant, &recognize_request());

        // First audience entry has scope all=true (allows everything).
        // Second entry has all=false with no allow (denies everything).
        // .find() returns the first match, so the first entry wins → ALLOW.
        assert!(
            outcome.decision().is_allowed(),
            "first audience entry should win, got deny: {:?}",
            outcome.decision().deny_reason(),
        );
        assert_eq!(outcome.decision().deny_reason(), None);
    }

    // ── Multi-resource-type evaluation ─────────────────────────────────

    /// Helper: grant with two resource types ("item" and "badge"), both with
    /// recognize enabled.
    fn multi_type_grant() -> VerifiedTrustGrant {
        let json = r#"{
          "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174050",
          "version":0,
          "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174051",
          "revision":1,
          "supersedes":null,
          "supersession_policy":"coexist",
          "issuer_authority":"https://issuer.example.com",
          "origin_authority":"https://issuer.example.com",
          "active_owning_authority":"https://issuer.example.com",
          "key_id":"root-key-1",
          "target_scope":{"all":false,"allow":[{"kind":"authority","all":false,"values":["https://target.example.com"],"expressions":null}],"deny":null},
          "capabilities":{"recognize":true,"mint":false},
          "default_audience_scope":null,
          "resource_scope":{"types":{
            "item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}},
            "badge":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["achievements"],"expressions":null}],"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}
          }},
          "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
          "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
          "issued_at":"2026-04-07T12:00:00Z",
          "signature":"base64-signature",
          "issuer_principal":{"kind":"service","id":"issuer-worker"}
        }"#;

        let raw = match RawTrustGrantDocument::parse_json_str(json) {
            Ok(document) => document,
            Err(error) => panic!("multi-type raw document should parse: {error}"),
        };
        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => panic!("multi-type validated document should succeed: {error}"),
        };

        VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        )
    }

    fn recognize_request_for(resource_type: &str, namespace: &str) -> EvaluationRequest {
        let mut resource = match ResourceContext::new(resource_type) {
            Ok(resource) => resource,
            Err(error) => panic!("resource context should be valid: {error}"),
        };
        if let Err(error) = resource.insert_selector("namespace", namespace) {
            panic!("resource selector should be valid: {error}");
        }

        let origin = origin();
        match EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Recognize),
            ResourceBinding::Existing(ResourceRef::new(origin, resource_type.to_owned())),
            match AuthorityId::new("https://target.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid target authority: {error}"),
            },
            match AuthorityId::new("https://audience.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid audience authority: {error}"),
            },
            resource,
            fixed_timestamp(2026, 4, 7, 13, 0, 0),
        ) {
            Ok(request) => request,
            Err(error) => panic!("evaluation request should be valid: {error}"),
        }
    }

    #[test]
    fn evaluation_allows_multiple_resource_types_in_one_grant() {
        let engine = EvaluationEngine::new();
        let grant = multi_type_grant();

        // Evaluating "item" with namespace "weapons" → allowed
        let outcome_item = engine.evaluate(&grant, &recognize_request_for("item", "weapons"));
        assert!(
            outcome_item.decision().is_allowed(),
            "item recognition should be allowed, got: {:?}",
            outcome_item.decision().deny_reason(),
        );

        // Evaluating "badge" with namespace "achievements" → allowed
        let outcome_badge =
            engine.evaluate(&grant, &recognize_request_for("badge", "achievements"));
        assert!(
            outcome_badge.decision().is_allowed(),
            "badge recognition should be allowed, got: {:?}",
            outcome_badge.decision().deny_reason(),
        );
    }

    #[test]
    fn evaluation_denies_unknown_resource_type_in_multi_type_grant() {
        let engine = EvaluationEngine::new();
        let grant = multi_type_grant();

        // Requesting resource type "weapon" which is NOT in the grant → ResourceTypeNotGranted
        let outcome = engine.evaluate(&grant, &recognize_request_for("weapon", "weapons"));
        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::ResourceTypeNotGranted),
        );
    }

    // ── Mint-without-constraints (line 293 coverage) ──────────────────

    fn mint_grant_without_constraints() -> VerifiedTrustGrant {
        let raw = RawTrustGrantDocument {
            trustgrant_id: "tg_e0000000-0000-1000-a000-000000000008".into(),
            version: 0,
            grant_series_id: "tgs_e0000000-0000-1000-a000-000000000008".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://issuer.example.com".into(),
            active_owning_authority: "https://issuer.example.com".into(),
            key_id: "root-key-1".into(),
            target_scope: RawScope {
                all: false,
                allow: Some(vec![RawSelector {
                    kind: "authority".into(),
                    all: false,
                    values: Some(vec!["https://target.example.com".into()]),
                    expressions: None,
                }]),
                deny: None,
            },
            capabilities: RawCapabilities {
                recognize: false,
                mint: true,
            },
            default_audience_scope: None,
            resource_scope: RawResourceScope {
                types: std::collections::BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: false,
                        allow: Some(vec![RawSelector {
                            kind: "namespace".into(),
                            all: false,
                            values: Some(vec!["weapons".into()]),
                            expressions: None,
                        }]),
                        deny: None,
                        capabilities: RawTypeCapabilities {
                            recognize: Some(false),
                            mint: Some(true),
                        },
                        constraints: RawTypeConstraints {
                            // NO minting constraints → line 293
                            minting: RawMintingConstraints {
                                max_total: None,
                                max_per_user: None,
                            },
                            audience_scope: Some(vec![RawAudienceEntry {
                                authority_id: "https://audience.example.com".into(),
                                scope: RawScope {
                                    all: true,
                                    allow: None,
                                    deny: None,
                                },
                                principal_scope: Some(RawScope {
                                    all: false,
                                    allow: Some(vec![RawSelector {
                                        kind: "actor".into(),
                                        all: false,
                                        values: Some(vec!["player-123".into()]),
                                        expressions: None,
                                    }]),
                                    deny: None,
                                }),
                            }]),
                        },
                        operations: None,
                    },
                )]),
            },
            global_constraints: Some(RawGlobalConstraints {
                time: Some(RawTimeWindow {
                    not_before: fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    not_after: fixed_timestamp(2026, 4, 8, 12, 0, 0),
                }),
            }),
            revocation: Some(RawRevocation {
                revocable: true,
                revocation_endpoint: "https://issuer.example.com/revocation".into(),
            }),
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "base64-signature".into(),
            issuer_principal: Some(RawPrincipal {
                kind: "service".into(),
                id: "issuer-worker".into(),
            }),
        };

        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => {
                panic!("validated mint-without-constraints document should succeed: {error}")
            }
        };

        VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        )
    }

    #[test]
    fn evaluation_allows_mint_without_context_when_no_constraints() {
        // Line 293: evaluate_minting_constraints returns Ok(()) when the
        // operation IS Mint but there's no MintContext AND no max_total /
        // max_per_user constraints.
        let engine = EvaluationEngine::new();
        let grant = mint_grant_without_constraints();
        let request = mint_request(); // No .with_runtime_mint_context()
        let outcome = engine.evaluate(&grant, &request);

        assert!(
            outcome.decision().is_allowed(),
            "expected allow, got deny: {:?}",
            outcome.decision().deny_reason(),
        );
    }

    // ── Selector-level `all: true` coverage (line 327) ────────────────

    #[test]
    fn evaluation_allows_any_resource_when_scope_all_is_true() {
        // Line 327: selector_matches_context returns SelectorMatch::Matched
        // when a selector has all: true, regardless of context values.
        let engine = EvaluationEngine::new();

        let raw = RawTrustGrantDocument {
            trustgrant_id: "tg_e0000000-0000-1000-a000-000000000009".into(),
            version: 0,
            grant_series_id: "tgs_e0000000-0000-1000-a000-000000000009".into(),
            revision: 1,
            supersedes: None,
            supersession_policy: RawSupersessionPolicy::Coexist,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://issuer.example.com".into(),
            active_owning_authority: "https://issuer.example.com".into(),
            key_id: "root-key-1".into(),
            target_scope: RawScope {
                all: false,
                allow: Some(vec![RawSelector {
                    kind: "authority".into(),
                    all: false,
                    values: Some(vec!["https://target.example.com".into()]),
                    expressions: None,
                }]),
                deny: None,
            },
            capabilities: RawCapabilities {
                recognize: true,
                mint: false,
            },
            default_audience_scope: None,
            resource_scope: RawResourceScope {
                types: std::collections::BTreeMap::from([(
                    Utf16Key::new("item"),
                    RawResourceType {
                        all: false,
                        allow: Some(vec![RawSelector {
                            kind: "namespace".into(),
                            all: true, // ← matches ANY namespace value
                            values: None,
                            expressions: None,
                        }]),
                        deny: None,
                        capabilities: RawTypeCapabilities {
                            recognize: Some(true),
                            mint: Some(false),
                        },
                        constraints: RawTypeConstraints {
                            minting: RawMintingConstraints {
                                max_total: None,
                                max_per_user: None,
                            },
                            audience_scope: None,
                        },
                        operations: Some(RawOperationScope {
                            all: false,
                            allow: Some(vec!["recognize".into()]),
                            deny: None,
                        }),
                    },
                )]),
            },
            global_constraints: Some(RawGlobalConstraints {
                time: Some(RawTimeWindow {
                    not_before: fixed_timestamp(2026, 4, 7, 12, 0, 0),
                    not_after: fixed_timestamp(2026, 4, 8, 12, 0, 0),
                }),
            }),
            revocation: Some(RawRevocation {
                revocable: true,
                revocation_endpoint: "https://issuer.example.com/revocation".into(),
            }),
            issued_at: fixed_timestamp(2026, 4, 7, 12, 0, 0),
            signature: "base64-signature".into(),
            issuer_principal: Some(RawPrincipal {
                kind: "service".into(),
                id: "issuer-worker".into(),
            }),
        };

        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => panic!("validated all-scope document should succeed: {error}"),
        };

        let grant = VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding(),
                ownership_record(),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        fixed_timestamp(2026, 4, 7, 12, 0, 0),
                        fixed_timestamp(2026, 4, 9, 12, 0, 0),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        );

        // Use a namespace that would NOT match a normal value-based selector
        // to prove the `all: true` on the selector makes it match anything.
        let request = recognize_request_for("item", "something_completely_different");
        let outcome = engine.evaluate(&grant, &request);

        assert!(
            outcome.decision().is_allowed(),
            "expected allow with all:true selector, got deny: {:?}",
            outcome.decision().deny_reason(),
        );
    }

    #[test]
    fn evaluation_uses_hashset_for_selector_matching_with_many_context_values() {
        let engine = EvaluationEngine::new();
        let grant = verified_grant();

        // Build a resource context with 9+ namespace values to trigger HashSet path
        // in selector_matches_context (context_values.len() > 8).
        let mut resource = match ResourceContext::new("item") {
            Ok(resource) => resource,
            Err(error) => panic!("resource context should be valid: {error}"),
        };
        for i in 0..9 {
            let value = format!("namespace_{i}");
            if let Err(error) = resource.insert_selector("namespace", &value) {
                panic!("resource selector should be valid: {error}");
            }
        }
        // Now insert the value that matches the grant's namespace selector ("weapons")
        if let Err(error) = resource.insert_selector("namespace", "weapons") {
            panic!("resource selector should be valid: {error}");
        }

        let origin = origin();
        let mut request = match EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Recognize),
            ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
            match AuthorityId::new("https://target.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid target authority: {error}"),
            },
            match AuthorityId::new("https://audience.example.com") {
                Ok(authority) => authority,
                Err(error) => panic!("valid audience authority: {error}"),
            },
            resource,
            fixed_timestamp(2026, 4, 7, 13, 0, 0),
        ) {
            Ok(request) => request,
            Err(error) => panic!("evaluation request should be valid: {error}"),
        };

        if let Err(error) = request.insert_audience_principal_selector("actor", "player-123") {
            panic!("audience principal selector should be valid: {error}");
        }

        let outcome = engine.evaluate(&grant, &request);
        assert!(
            outcome.decision().is_allowed(),
            "expected allow with matching selector via HashSet path, got deny: {:?}",
            outcome.decision().deny_reason(),
        );
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
