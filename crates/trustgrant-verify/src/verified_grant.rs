use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use compact_str::CompactString;

use trustgrant_discovery::ResolvedSignerBinding;
use trustgrant_document::RawTrustGrantDocument;
use trustgrant_document::raw::{
    RawAudienceEntry, RawCapabilities, RawGlobalConstraints, RawMintingConstraints,
    RawOperationScope, RawPrincipal, RawResourceScope, RawResourceType, RawRevocation, RawScope,
    RawSelector, RawSupersessionPolicy, RawTimeWindow, RawTypeCapabilities, RawTypeConstraints,
};
use trustgrant_document::{
    ValidatedAudienceEntry, ValidatedCapabilities, ValidatedPrincipal, ValidatedResourceType,
    ValidatedRevocation, ValidatedScope, ValidatedSelector, ValidatedTimeWindow,
    ValidatedTrustGrantDocument,
};
use trustgrant_domain::{
    AuthorityId, GrantLineage, KeyId, OwnershipAuthorityState, OwnershipVerificationRecord,
    ResourceTypeName, SupersessionPolicy, Utf16Key,
};
use trustgrant_error::TrustGrantError;
use trustgrant_ports::VerificationPosture;
use trustgrant_revocation::VerifiedRevocationState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedTrustGrantDocument {
    lineage: GrantLineage,
    issuer_authority: AuthorityId,
    ownership_authority_state: OwnershipAuthorityState,
    key_id: KeyId,
    target_scope: ValidatedScope,
    capabilities: ValidatedCapabilities,
    default_audience_scope: Vec<ValidatedAudienceEntry>,
    resource_scope: BTreeMap<ResourceTypeName, ValidatedResourceType>,
    global_time_window: Option<ValidatedTimeWindow>,
    revocation: Option<ValidatedRevocation>,
    issued_at: DateTime<Utc>,
    issuer_principal: Option<ValidatedPrincipal>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizedTrustGrantDocumentParts {
    pub(crate) lineage: GrantLineage,
    pub(crate) issuer_authority: AuthorityId,
    pub(crate) ownership_authority_state: OwnershipAuthorityState,
    pub(crate) key_id: KeyId,
    pub(crate) target_scope: ValidatedScope,
    pub(crate) capabilities: ValidatedCapabilities,
    pub(crate) default_audience_scope: Vec<ValidatedAudienceEntry>,
    pub(crate) resource_scope: BTreeMap<ResourceTypeName, ValidatedResourceType>,
    pub(crate) global_time_window: Option<ValidatedTimeWindow>,
    pub(crate) revocation: Option<ValidatedRevocation>,
    pub(crate) issued_at: DateTime<Utc>,
    pub(crate) issuer_principal: Option<ValidatedPrincipal>,
}

impl NormalizedTrustGrantDocument {
    #[must_use = "normalized verified state must stay valid by construction"]
    pub(crate) fn from_parts(parts: NormalizedTrustGrantDocumentParts) -> Self {
        Self {
            lineage: parts.lineage,
            issuer_authority: parts.issuer_authority,
            ownership_authority_state: parts.ownership_authority_state,
            key_id: parts.key_id,
            target_scope: parts.target_scope,
            capabilities: parts.capabilities,
            default_audience_scope: parts.default_audience_scope,
            resource_scope: parts.resource_scope,
            global_time_window: parts.global_time_window,
            revocation: parts.revocation,
            issued_at: parts.issued_at,
            issuer_principal: parts.issuer_principal,
        }
    }

    #[must_use = "normalized lineage is required for evaluation and persistence"]
    pub const fn lineage(&self) -> &GrantLineage {
        &self.lineage
    }

    #[must_use = "issuer authority is required for audit and routing"]
    pub const fn issuer_authority(&self) -> &AuthorityId {
        &self.issuer_authority
    }

    #[must_use = "ownership state is required for owner-level evaluation"]
    pub const fn ownership_authority_state(&self) -> &OwnershipAuthorityState {
        &self.ownership_authority_state
    }

    #[must_use = "key id remains part of normalized audit state"]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    #[must_use = "target scope is required for evaluation"]
    pub const fn target_scope(&self) -> &ValidatedScope {
        &self.target_scope
    }

    #[must_use = "capabilities are required for evaluation"]
    pub const fn capabilities(&self) -> &ValidatedCapabilities {
        &self.capabilities
    }

    #[must_use = "default audience scope is required for evaluation fallback"]
    pub fn default_audience_scope(&self) -> &[ValidatedAudienceEntry] {
        &self.default_audience_scope
    }

    #[must_use = "resource scope is required for evaluation"]
    pub const fn resource_scope(&self) -> &BTreeMap<ResourceTypeName, ValidatedResourceType> {
        &self.resource_scope
    }

    #[must_use = "global time window may constrain grant validity"]
    pub const fn global_time_window(&self) -> Option<&ValidatedTimeWindow> {
        self.global_time_window.as_ref()
    }

    #[must_use = "revocation policy remains part of normalized audit state"]
    pub const fn revocation(&self) -> Option<&ValidatedRevocation> {
        self.revocation.as_ref()
    }

    #[must_use = "issued_at remains part of normalized audit state"]
    pub const fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    #[must_use = "issuer principal remains part of normalized audit state"]
    pub const fn issuer_principal(&self) -> Option<&ValidatedPrincipal> {
        self.issuer_principal.as_ref()
    }

    pub(crate) fn into_raw_document_for_consistency_check(
        self,
    ) -> Result<RawTrustGrantDocument, TrustGrantError> {
        let supersession_policy = match self.lineage.supersession_policy() {
            SupersessionPolicy::Coexist => RawSupersessionPolicy::Coexist,
            SupersessionPolicy::SupersedePrevious => RawSupersessionPolicy::SupersedePrevious,
            SupersessionPolicy::ExplicitRevocationRequired => {
                return Err(TrustGrantError::UnsupportedV0WireSupersessionPolicy);
            }
        };

        Ok(RawTrustGrantDocument {
            trustgrant_id: self.lineage.trustgrant_id().to_string().into(),
            version: 0,
            grant_series_id: self.lineage.grant_series_id().to_string().into(),
            revision: self.lineage.revision().get(),
            supersedes: self
                .lineage
                .supersedes()
                .map(|value| value.to_string().into()),
            supersession_policy,
            issuer_authority: self.issuer_authority.to_string().into(),
            origin_authority: self
                .ownership_authority_state
                .origin_authority()
                .to_string()
                .into(),
            active_owning_authority: self
                .ownership_authority_state
                .active_owning_authority()
                .to_string()
                .into(),
            key_id: self.key_id.as_str().to_owned().into(),
            target_scope: raw_scope(&self.target_scope),
            capabilities: RawCapabilities::new(
                self.capabilities.recognize(),
                self.capabilities.mint(),
            ),
            default_audience_scope: (!self.default_audience_scope.is_empty()).then(|| {
                self.default_audience_scope
                    .into_iter()
                    .map(|entry| raw_audience_entry(&entry))
                    .collect()
            }),
            resource_scope: RawResourceScope::new(
                self.resource_scope
                    .iter()
                    .map(|(resource_type, resource_record)| {
                        (
                            Utf16Key::new(resource_type.as_str()),
                            raw_resource_type(resource_record),
                        )
                    })
                    .collect(),
            ),
            global_constraints: self.global_time_window.map(|time_window| {
                RawGlobalConstraints::new(Some(RawTimeWindow::new(
                    time_window.not_before(),
                    time_window.not_after(),
                )))
            }),
            revocation: self.revocation.map(|revocation| {
                RawRevocation::new(revocation.revocable(), revocation.revocation_endpoint())
            }),
            issued_at: self.issued_at,
            // Rehydrate consistency checks reuse the raw->validated conversion
            // path. The protocol rule excludes `signature` from signed
            // canonical bytes, but raw validation still requires the published
            // document field to be present and non-empty.
            signature: CompactString::from("rehydrated-signature"),
            issuer_principal: self.issuer_principal.as_ref().map(raw_principal),
        })
    }
}

impl From<ValidatedTrustGrantDocument> for NormalizedTrustGrantDocument {
    fn from(document: ValidatedTrustGrantDocument) -> Self {
        Self::from_parts(NormalizedTrustGrantDocumentParts {
            lineage: document.lineage().clone(),
            issuer_authority: document.issuer_authority().clone(),
            ownership_authority_state: document.ownership_authority_state().clone(),
            key_id: document.key_id().clone(),
            target_scope: document.target_scope().clone(),
            capabilities: document.capabilities().clone(),
            default_audience_scope: document.default_audience_scope().to_vec(),
            resource_scope: document.resource_scope().clone(),
            global_time_window: document.global_time_window().cloned(),
            revocation: document.revocation().cloned(),
            issued_at: document.issued_at(),
            issuer_principal: document.issuer_principal().cloned(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationMetadata {
    verified_at: DateTime<Utc>,
    posture: VerificationPosture,
    signer_binding: ResolvedSignerBinding,
    ownership: OwnershipVerificationRecord,
    revocation: VerifiedRevocationState,
}

impl VerificationMetadata {
    #[must_use = "verification metadata should be attached to verified grants"]
    pub const fn new(
        verified_at: DateTime<Utc>,
        posture: VerificationPosture,
        signer_binding: ResolvedSignerBinding,
        ownership: OwnershipVerificationRecord,
        revocation: VerifiedRevocationState,
    ) -> Self {
        Self {
            verified_at,
            posture,
            signer_binding,
            ownership,
            revocation,
        }
    }

    #[must_use = "verified_at is required for audit and cache freshness"]
    pub const fn verified_at(&self) -> DateTime<Utc> {
        self.verified_at
    }

    #[must_use = "verification posture is required for audit and policy"]
    pub const fn posture(&self) -> VerificationPosture {
        self.posture
    }

    #[must_use = "resolved signer binding is required for audit and persistence"]
    pub const fn signer_binding(&self) -> &ResolvedSignerBinding {
        &self.signer_binding
    }

    #[must_use = "ownership verification state is required for audit and lineage handling"]
    pub const fn ownership(&self) -> &OwnershipVerificationRecord {
        &self.ownership
    }

    #[must_use = "revocation state is required for evaluation and freshness policy"]
    pub const fn revocation(&self) -> &VerifiedRevocationState {
        &self.revocation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTrustGrant {
    document: NormalizedTrustGrantDocument,
    metadata: VerificationMetadata,
}

impl VerifiedTrustGrant {
    #[must_use = "verified grants should only be created after signature and proof checks"]
    pub fn new(
        document: impl Into<NormalizedTrustGrantDocument>,
        metadata: VerificationMetadata,
    ) -> Self {
        Self {
            document: document.into(),
            metadata,
        }
    }

    #[must_use = "verified document state is required for evaluation and audit"]
    pub const fn document(&self) -> &NormalizedTrustGrantDocument {
        &self.document
    }

    #[must_use = "verification metadata is required for evaluation and audit"]
    pub const fn metadata(&self) -> &VerificationMetadata {
        &self.metadata
    }

    #[must_use = "lineage is required for exact-grant evaluation"]
    pub const fn lineage(&self) -> &GrantLineage {
        self.document.lineage()
    }

    #[must_use = "issuer authority is required for audit"]
    pub const fn issuer_authority(&self) -> &AuthorityId {
        self.document.issuer_authority()
    }

    #[must_use = "ownership state is required for owner-level evaluation"]
    pub const fn ownership_authority_state(&self) -> &OwnershipAuthorityState {
        self.document.ownership_authority_state()
    }
}

fn raw_scope(scope: &ValidatedScope) -> RawScope {
    RawScope::new(
        scope.all(),
        (!scope.allow().is_empty()).then(|| scope.allow().iter().map(raw_selector).collect()),
        (!scope.deny().is_empty()).then(|| scope.deny().iter().map(raw_selector).collect()),
    )
}

fn raw_selector(selector: &ValidatedSelector) -> RawSelector {
    RawSelector::new(
        selector.kind().as_str(),
        selector.all(),
        (!selector.values().is_empty()).then(|| {
            selector
                .values()
                .iter()
                .map(|s| CompactString::from(s.as_str()))
                .collect()
        }),
        (!selector.expressions().is_empty()).then(|| {
            selector
                .expressions()
                .iter()
                .map(|e| e.to_string().into())
                .collect()
        }),
    )
}

fn raw_audience_entry(entry: &ValidatedAudienceEntry) -> RawAudienceEntry {
    RawAudienceEntry::new(
        entry.authority_id().to_string(),
        raw_scope(entry.scope()),
        entry.principal_scope().map(raw_scope),
    )
}

fn raw_resource_type(resource_type: &ValidatedResourceType) -> RawResourceType {
    RawResourceType::new(
        resource_type.all(),
        (!resource_type.allow().is_empty())
            .then(|| resource_type.allow().iter().map(raw_selector).collect()),
        (!resource_type.deny().is_empty())
            .then(|| resource_type.deny().iter().map(raw_selector).collect()),
        RawTypeCapabilities::new(
            resource_type.capabilities().recognize(),
            resource_type.capabilities().mint(),
        ),
        RawTypeConstraints::new(
            RawMintingConstraints::new(
                resource_type.constraints().minting().max_total(),
                resource_type.constraints().minting().max_per_user(),
            ),
            (!resource_type.constraints().audience_scope().is_empty()).then(|| {
                resource_type
                    .constraints()
                    .audience_scope()
                    .iter()
                    .map(raw_audience_entry)
                    .collect()
            }),
        ),
        resource_type.operations().map(|operations| {
            RawOperationScope::new(
                operations.all(),
                (!operations.allow().is_empty()).then(|| {
                    operations
                        .allow()
                        .iter()
                        .map(|operation| operation.as_str().into())
                        .collect()
                }),
                (!operations.deny().is_empty()).then(|| {
                    operations
                        .deny()
                        .iter()
                        .map(|operation| operation.as_str().into())
                        .collect()
                }),
            )
        }),
    )
}

fn raw_principal(principal: &ValidatedPrincipal) -> RawPrincipal {
    RawPrincipal::new(principal.kind().as_str(), principal.id().as_str())
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use trustgrant_document::RawTrustGrantDocument;
    use trustgrant_document::ValidatedTrustGrantDocument;
    use trustgrant_domain::{GrantLineage, SupersessionPolicy};
    use trustgrant_error::TrustGrantError;

    use super::{NormalizedTrustGrantDocument, NormalizedTrustGrantDocumentParts};

    fn make_document_with_policy(policy: SupersessionPolicy) -> NormalizedTrustGrantDocument {
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
            "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
            "revocation":null,
            "issued_at":"2026-04-07T12:00:00Z",
            "signature":"base64-signature"
        }"#;
        let raw = RawTrustGrantDocument::parse_json_str(json)
            .unwrap_or_else(|error| panic!("raw document should parse: {error}"));
        let validated = ValidatedTrustGrantDocument::try_from(raw)
            .unwrap_or_else(|error| panic!("validated document should be valid: {error}"));

        let document: NormalizedTrustGrantDocument = validated.into();
        let lineage = GrantLineage::new(
            document.lineage().trustgrant_id(),
            document.lineage().grant_series_id(),
            document.lineage().revision(),
            document.lineage().supersedes(),
            policy,
        );

        NormalizedTrustGrantDocument::from_parts(NormalizedTrustGrantDocumentParts {
            lineage,
            issuer_authority: document.issuer_authority().clone(),
            ownership_authority_state: document.ownership_authority_state().clone(),
            key_id: document.key_id().clone(),
            target_scope: document.target_scope().clone(),
            capabilities: document.capabilities().clone(),
            default_audience_scope: document.default_audience_scope().to_vec(),
            resource_scope: document.resource_scope().clone(),
            global_time_window: document.global_time_window().cloned(),
            revocation: document.revocation().cloned(),
            issued_at: document.issued_at(),
            issuer_principal: document.issuer_principal().cloned(),
        })
    }

    #[test]
    fn explicit_revocation_required_fails_raw_conversion() {
        let document = make_document_with_policy(SupersessionPolicy::ExplicitRevocationRequired);
        let result = document.into_raw_document_for_consistency_check();
        assert_eq!(
            result,
            Err(TrustGrantError::UnsupportedV0WireSupersessionPolicy)
        );
    }

    #[test]
    fn coexist_policy_succeeds_raw_conversion() {
        let document = make_document_with_policy(SupersessionPolicy::Coexist);
        let result = document.into_raw_document_for_consistency_check();
        assert!(result.is_ok());
    }

    #[test]
    fn supersede_policy_succeeds_raw_conversion() {
        let document = make_document_with_policy(SupersessionPolicy::SupersedePrevious);
        let result = document.into_raw_document_for_consistency_check();
        assert!(result.is_ok());
    }

    // ── Lines 315-321: issuer_authority and ownership_authority_state accessors ──

    #[test]
    fn normalized_document_accessors_return_expected_values() {
        let document = make_document_with_policy(SupersessionPolicy::Coexist);

        assert!(document.issuer_authority().as_str().contains("issuer"));
        assert!(
            document
                .ownership_authority_state()
                .origin_authority()
                .as_str()
                .contains("issuer")
        );
        assert!(
            document
                .ownership_authority_state()
                .active_owning_authority()
                .as_str()
                .contains("issuer")
        );
    }

    // ── Lines 340-343: raw_selector expression .to_string() path ─────────

    #[test]
    fn raw_selector_preserves_expressions() {
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
            "target_scope":{"all":false,"allow":[{"kind":"authority","all":false,"values":["https://target.example.com"],"expressions":["startsWith(\"https://\")"]}],"deny":null},
            "capabilities":{"recognize":true,"mint":false},
            "default_audience_scope":null,
            "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
            "revocation":null,
            "issued_at":"2026-04-07T12:00:00Z",
            "signature":"sig"
        }"#;
        let raw = RawTrustGrantDocument::parse_json_str(json)
            .unwrap_or_else(|error| panic!("raw document should parse: {error}"));
        let validated = ValidatedTrustGrantDocument::try_from(raw)
            .unwrap_or_else(|error| panic!("validated document should be valid: {error}"));
        let normalized = NormalizedTrustGrantDocument::from(validated);
        let reconstituted = normalized
            .into_raw_document_for_consistency_check()
            .unwrap_or_else(|error| panic!("reconstitution should succeed: {error}"));

        // Verify expressions survived round-trip through raw_selector
        let allow = reconstituted
            .target_scope
            .allow
            .unwrap_or_else(|| panic!("allow should be Some"));
        let selector = allow
            .first()
            .unwrap_or_else(|| panic!("allow should have at least one element"));
        let expressions = selector
            .expressions
            .as_ref()
            .unwrap_or_else(|| panic!("expressions should be Some"));
        assert_eq!(expressions.len(), 1);
        assert_eq!(
            expressions
                .first()
                .unwrap_or_else(|| panic!("expressions should have at least one element")),
            r#"startsWith("https://")"#
        );
    }
}
