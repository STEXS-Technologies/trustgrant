use std::collections::BTreeMap;
use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use trustgrant_discovery::{
    AuthorityKeyRecord, DelegatedPrincipalRef, ResolvedSignerBinding, SignatureProfile,
};
use trustgrant_document::validated::{ValidatedTypeCapabilities, ValidatedTypeConstraints};
use trustgrant_document::{
    ValidatedAudienceEntry, ValidatedCapabilities, ValidatedMintingConstraints,
    ValidatedOperationScope, ValidatedPrincipal, ValidatedResourceType, ValidatedRevocation,
    ValidatedScope, ValidatedSelector, ValidatedTimeWindow,
};
use trustgrant_domain::{
    AuthorityId, GrantLineage, GrantRevision, GrantSeriesId, KeyId, OperationName,
    OwnershipAuthorityState, PrincipalId, PrincipalKind, ResourceTypeName, SelectorExpression,
    SelectorKind, SupersessionPolicy, TransitionId, TrustGrantId,
};
use trustgrant_domain::{OwnershipProofKind, OwnershipVerificationRecord};
use trustgrant_error::TrustGrantError;
use trustgrant_error::limits::{
    MAX_AUDIENCE_ENTRIES, MAX_OPERATIONS_PER_SCOPE, MAX_RESOURCE_TYPES,
    MAX_SELECTOR_EXPRESSION_BYTES, MAX_SELECTOR_EXPRESSIONS_PER_SELECTOR, MAX_SELECTOR_VALUE_BYTES,
    MAX_SELECTOR_VALUES_PER_SELECTOR, MAX_SELECTORS_PER_SCOPE, ensure_collection_limit,
    ensure_string_limit,
};
use trustgrant_revocation::VerifiedRevocationState;

use super::consistency::{canonical_profile_for_rehydrate, ensure_verified_grant_consistent};
use super::verified_grant::NormalizedTrustGrantDocumentParts;
use super::{
    NormalizedTrustGrantDocument, VerificationMetadata, VerificationPosture, VerifiedTrustGrant,
};

const VERIFIED_TRUSTGRANT_RECORD_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedTrustGrantRecord {
    record_version: u16,
    document: NormalizedTrustGrantDocumentRecord,
    metadata: VerificationMetadataRecord,
}

impl VerifiedTrustGrantRecord {
    /// Rehydrates one verified TrustGrant from a borrowed persistence record.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the persisted record cannot be
    /// converted back into normalized verified state.
    pub fn try_to_verified_grant(&self) -> Result<VerifiedTrustGrant, TrustGrantError> {
        if self.record_version != VERIFIED_TRUSTGRANT_RECORD_VERSION {
            return Err(
                TrustGrantError::UnsupportedPersistedVerifiedGrantRecordVersion(
                    self.record_version,
                ),
            );
        }

        let verified_grant = VerifiedTrustGrant::new(
            self.document.try_to_normalized_document()?,
            self.metadata.clone().try_into_metadata()?,
        );

        ensure_verified_grant_consistent(
            &verified_grant,
            canonical_profile_for_rehydrate(verified_grant.metadata().posture()),
        )?;

        Ok(verified_grant)
    }

    /// Rehydrates one verified TrustGrant from its persistence-facing record.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the persisted record cannot be
    /// converted back into normalized verified state.
    pub fn try_into_verified_grant(self) -> Result<VerifiedTrustGrant, TrustGrantError> {
        self.try_to_verified_grant()
    }
}

impl From<&VerifiedTrustGrant> for VerifiedTrustGrantRecord {
    fn from(value: &VerifiedTrustGrant) -> Self {
        Self {
            record_version: VERIFIED_TRUSTGRANT_RECORD_VERSION,
            document: NormalizedTrustGrantDocumentRecord::from(value.document()),
            metadata: VerificationMetadataRecord::from(value.metadata()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NormalizedTrustGrantDocumentRecord {
    trustgrant_id: String,
    grant_series_id: String,
    revision: u64,
    supersedes: Option<String>,
    supersession_policy: SupersessionPolicyRecord,
    issuer_authority: String,
    origin_authority: String,
    active_owning_authority: String,
    key_id: String,
    target_scope: ScopeRecord,
    capabilities: CapabilitiesRecord,
    default_audience_scope: Vec<AudienceEntryRecord>,
    resource_scope: BTreeMap<String, ResourceTypeRecord>,
    global_time_window: Option<TimeWindowRecord>,
    revocation: Option<RevocationPolicyRecord>,
    issued_at: DateTime<Utc>,
    issuer_principal: Option<PrincipalRecord>,
}

impl NormalizedTrustGrantDocumentRecord {
    fn try_to_normalized_document(&self) -> Result<NormalizedTrustGrantDocument, TrustGrantError> {
        ensure_collection_limit(
            "verified_record.default_audience_scope",
            self.default_audience_scope.len(),
            MAX_AUDIENCE_ENTRIES,
        )?;
        ensure_collection_limit(
            "verified_record.resource_scope",
            self.resource_scope.len(),
            MAX_RESOURCE_TYPES,
        )?;
        let trustgrant_id = self.trustgrant_id.parse::<TrustGrantId>()?;
        let grant_series_id = self.grant_series_id.parse::<GrantSeriesId>()?;
        let revision = GrantRevision::new(self.revision)?;
        let supersedes = self
            .supersedes
            .as_deref()
            .map(str::parse::<TrustGrantId>)
            .transpose()?;

        if revision.get() == 1 && supersedes.is_some() {
            return Err(TrustGrantError::InvalidSupersedesForFirstRevision);
        }

        if supersedes == Some(trustgrant_id) {
            return Err(TrustGrantError::SelfSupersession);
        }

        let supersession_policy = match self.supersession_policy {
            SupersessionPolicyRecord::Coexist => SupersessionPolicy::Coexist,
            SupersessionPolicyRecord::SupersedePrevious => SupersessionPolicy::SupersedePrevious,
            SupersessionPolicyRecord::ExplicitRevocationRequired => {
                return Err(TrustGrantError::UnsupportedV0WireSupersessionPolicy);
            }
        };

        Ok(NormalizedTrustGrantDocument::from_parts(
            NormalizedTrustGrantDocumentParts {
                lineage: GrantLineage::new(
                    trustgrant_id,
                    grant_series_id,
                    revision,
                    supersedes,
                    supersession_policy,
                ),
                issuer_authority: AuthorityId::new(self.issuer_authority.clone())?,
                ownership_authority_state: OwnershipAuthorityState::new(
                    AuthorityId::new(self.origin_authority.clone())?,
                    AuthorityId::new(self.active_owning_authority.clone())?,
                ),
                key_id: KeyId::new(self.key_id.clone())?,
                target_scope: self.target_scope.try_to_validated_scope("target_scope")?,
                capabilities: ValidatedCapabilities::new(
                    self.capabilities.recognize,
                    self.capabilities.mint,
                ),
                default_audience_scope: self
                    .default_audience_scope
                    .iter()
                    .map(|entry| entry.try_to_validated_audience_entry("default_audience_scope"))
                    .collect::<Result<Vec<_>, _>>()?,
                resource_scope: self
                    .resource_scope
                    .iter()
                    .map(|(resource_type_name, record)| {
                        Ok((
                            ResourceTypeName::new(resource_type_name.clone())?,
                            record.try_to_validated_resource_type()?,
                        ))
                    })
                    .collect::<Result<BTreeMap<_, _>, _>>()?,
                global_time_window: self
                    .global_time_window
                    .as_ref()
                    .map(TimeWindowRecord::try_to_validated_time_window)
                    .transpose()?,
                revocation: self
                    .revocation
                    .as_ref()
                    .map(RevocationPolicyRecord::try_to_validated_revocation),
                issued_at: self.issued_at,
                issuer_principal: self
                    .issuer_principal
                    .as_ref()
                    .map(PrincipalRecord::try_to_validated_principal)
                    .transpose()?,
            },
        ))
    }
}

impl From<&NormalizedTrustGrantDocument> for NormalizedTrustGrantDocumentRecord {
    fn from(value: &NormalizedTrustGrantDocument) -> Self {
        Self {
            trustgrant_id: value.lineage().trustgrant_id().to_string(),
            grant_series_id: value.lineage().grant_series_id().to_string(),
            revision: value.lineage().revision().get(),
            supersedes: value.lineage().supersedes().map(|id| id.to_string()),
            supersession_policy: SupersessionPolicyRecord::from(
                value.lineage().supersession_policy(),
            ),
            issuer_authority: value.issuer_authority().to_string(),
            origin_authority: value
                .ownership_authority_state()
                .origin_authority()
                .to_string(),
            active_owning_authority: value
                .ownership_authority_state()
                .active_owning_authority()
                .to_string(),
            key_id: value.key_id().as_str().to_owned(),
            target_scope: ScopeRecord::from(value.target_scope()),
            capabilities: CapabilitiesRecord::from(value.capabilities()),
            default_audience_scope: value
                .default_audience_scope()
                .iter()
                .map(AudienceEntryRecord::from)
                .collect(),
            resource_scope: value
                .resource_scope()
                .iter()
                .map(|(resource_type, resource_record)| {
                    (
                        resource_type.as_str().to_owned(),
                        ResourceTypeRecord::from(resource_record),
                    )
                })
                .collect(),
            global_time_window: value.global_time_window().map(TimeWindowRecord::from),
            revocation: value.revocation().map(RevocationPolicyRecord::from),
            issued_at: value.issued_at(),
            issuer_principal: value.issuer_principal().map(PrincipalRecord::from),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SupersessionPolicyRecord {
    Coexist,
    SupersedePrevious,
    ExplicitRevocationRequired,
}

impl From<SupersessionPolicy> for SupersessionPolicyRecord {
    fn from(value: SupersessionPolicy) -> Self {
        match value {
            SupersessionPolicy::Coexist => Self::Coexist,
            SupersessionPolicy::SupersedePrevious => Self::SupersedePrevious,
            SupersessionPolicy::ExplicitRevocationRequired => Self::ExplicitRevocationRequired,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeRecord {
    all: bool,
    allow: Vec<SelectorRecord>,
    deny: Vec<SelectorRecord>,
}

impl ScopeRecord {
    fn try_to_validated_scope(
        &self,
        scope_name: &'static str,
    ) -> Result<ValidatedScope, TrustGrantError> {
        ensure_collection_limit(
            "verified_record.scope.allow",
            self.allow.len(),
            MAX_SELECTORS_PER_SCOPE,
        )?;
        ensure_collection_limit(
            "verified_record.scope.deny",
            self.deny.len(),
            MAX_SELECTORS_PER_SCOPE,
        )?;
        ValidatedScope::new(
            scope_name,
            self.all,
            validate_unique_selectors(&self.allow)?,
            validate_unique_selectors(&self.deny)?,
        )
    }
}

impl From<&ValidatedScope> for ScopeRecord {
    fn from(value: &ValidatedScope) -> Self {
        Self {
            all: value.all(),
            allow: value.allow().iter().map(SelectorRecord::from).collect(),
            deny: value.deny().iter().map(SelectorRecord::from).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectorRecord {
    kind: String,
    all: bool,
    values: Vec<String>,
    expressions: Vec<String>,
}

impl SelectorRecord {
    fn try_to_validated_selector(&self) -> Result<ValidatedSelector, TrustGrantError> {
        ensure_collection_limit(
            "verified_record.selector_values",
            self.values.len(),
            MAX_SELECTOR_VALUES_PER_SELECTOR,
        )?;
        ensure_collection_limit(
            "verified_record.selector_expressions",
            self.expressions.len(),
            MAX_SELECTOR_EXPRESSIONS_PER_SELECTOR,
        )?;
        ValidatedSelector::new(
            SelectorKind::new(self.kind.clone())?,
            self.all,
            normalize_persisted_non_empty_strings(
                "selector.value",
                &self.values,
                MAX_SELECTOR_VALUE_BYTES,
            )?,
            self.expressions
                .iter()
                .map(|expression| {
                    let expression = normalize_persisted_non_empty_string(
                        "selector.expression",
                        expression,
                        Some(MAX_SELECTOR_EXPRESSION_BYTES),
                    )?;
                    SelectorExpression::parse(&expression)
                })
                .collect::<Result<Vec<_>, _>>()?,
        )
    }
}

impl From<&ValidatedSelector> for SelectorRecord {
    fn from(value: &ValidatedSelector) -> Self {
        Self {
            kind: value.kind().as_str().to_owned(),
            all: value.all(),
            values: value.values().to_vec(),
            expressions: value
                .expressions()
                .iter()
                .map(ToString::to_string)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilitiesRecord {
    recognize: bool,
    mint: bool,
}

impl From<&ValidatedCapabilities> for CapabilitiesRecord {
    fn from(value: &ValidatedCapabilities) -> Self {
        Self {
            recognize: value.recognize(),
            mint: value.mint(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AudienceEntryRecord {
    authority_id: String,
    scope: ScopeRecord,
    principal_scope: Option<ScopeRecord>,
}

impl AudienceEntryRecord {
    fn try_to_validated_audience_entry(
        &self,
        scope_name: &'static str,
    ) -> Result<ValidatedAudienceEntry, TrustGrantError> {
        Ok(ValidatedAudienceEntry::new(
            AuthorityId::new(self.authority_id.clone())?,
            self.scope.try_to_validated_scope(scope_name)?,
            self.principal_scope
                .as_ref()
                .map(|scope| scope.try_to_validated_scope(scope_name))
                .transpose()?,
        ))
    }
}

impl From<&ValidatedAudienceEntry> for AudienceEntryRecord {
    fn from(value: &ValidatedAudienceEntry) -> Self {
        Self {
            authority_id: value.authority_id().to_string(),
            scope: ScopeRecord::from(value.scope()),
            principal_scope: value.principal_scope().map(ScopeRecord::from),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceTypeRecord {
    all: bool,
    allow: Vec<SelectorRecord>,
    deny: Vec<SelectorRecord>,
    capabilities: TypeCapabilitiesRecord,
    constraints: TypeConstraintsRecord,
    operations: Option<OperationScopeRecord>,
}

impl ResourceTypeRecord {
    fn try_to_validated_resource_type(&self) -> Result<ValidatedResourceType, TrustGrantError> {
        ensure_collection_limit(
            "verified_record.resource_type.allow",
            self.allow.len(),
            MAX_SELECTORS_PER_SCOPE,
        )?;
        ensure_collection_limit(
            "verified_record.resource_type.deny",
            self.deny.len(),
            MAX_SELECTORS_PER_SCOPE,
        )?;
        ensure_collection_limit(
            "verified_record.resource_type.audience_scope",
            self.constraints.audience_scope.len(),
            MAX_AUDIENCE_ENTRIES,
        )?;
        ValidatedResourceType::new(
            self.all,
            validate_unique_selectors(&self.allow)?,
            validate_unique_selectors(&self.deny)?,
            ValidatedTypeCapabilities::new(self.capabilities.recognize, self.capabilities.mint),
            ValidatedTypeConstraints::new(
                ValidatedMintingConstraints::new(
                    self.constraints.minting.max_total,
                    self.constraints.minting.max_per_user,
                ),
                self.constraints
                    .audience_scope
                    .iter()
                    .map(|entry| {
                        entry.try_to_validated_audience_entry("resource_scope.audience_scope")
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            self.operations
                .as_ref()
                .map(OperationScopeRecord::try_to_validated_operation_scope)
                .transpose()?,
        )
    }
}

impl From<&ValidatedResourceType> for ResourceTypeRecord {
    fn from(value: &ValidatedResourceType) -> Self {
        Self {
            all: value.all(),
            allow: value.allow().iter().map(SelectorRecord::from).collect(),
            deny: value.deny().iter().map(SelectorRecord::from).collect(),
            capabilities: TypeCapabilitiesRecord::from(value.capabilities()),
            constraints: TypeConstraintsRecord::from(value.constraints()),
            operations: value.operations().map(OperationScopeRecord::from),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TypeCapabilitiesRecord {
    recognize: Option<bool>,
    mint: Option<bool>,
}

impl From<&ValidatedTypeCapabilities> for TypeCapabilitiesRecord {
    fn from(value: &ValidatedTypeCapabilities) -> Self {
        Self {
            recognize: value.recognize(),
            mint: value.mint(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TypeConstraintsRecord {
    minting: MintingConstraintsRecord,
    audience_scope: Vec<AudienceEntryRecord>,
}

impl From<&ValidatedTypeConstraints> for TypeConstraintsRecord {
    fn from(value: &ValidatedTypeConstraints) -> Self {
        Self {
            minting: MintingConstraintsRecord::from(value.minting()),
            audience_scope: value
                .audience_scope()
                .iter()
                .map(AudienceEntryRecord::from)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MintingConstraintsRecord {
    max_total: Option<u64>,
    max_per_user: Option<u64>,
}

impl From<&ValidatedMintingConstraints> for MintingConstraintsRecord {
    fn from(value: &ValidatedMintingConstraints) -> Self {
        Self {
            max_total: value.max_total(),
            max_per_user: value.max_per_user(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationScopeRecord {
    all: bool,
    allow: Vec<String>,
    deny: Vec<String>,
}

impl OperationScopeRecord {
    fn try_to_validated_operation_scope(&self) -> Result<ValidatedOperationScope, TrustGrantError> {
        ensure_collection_limit(
            "verified_record.operation_scope.allow",
            self.allow.len(),
            MAX_OPERATIONS_PER_SCOPE,
        )?;
        ensure_collection_limit(
            "verified_record.operation_scope.deny",
            self.deny.len(),
            MAX_OPERATIONS_PER_SCOPE,
        )?;
        ValidatedOperationScope::new(
            self.all,
            self.allow
                .iter()
                .map(|operation| OperationName::new(operation.clone()))
                .collect::<Result<Vec<_>, _>>()?,
            self.deny
                .iter()
                .map(|operation| OperationName::new(operation.clone()))
                .collect::<Result<Vec<_>, _>>()?,
        )
    }
}

impl From<&ValidatedOperationScope> for OperationScopeRecord {
    fn from(value: &ValidatedOperationScope) -> Self {
        Self {
            all: value.all(),
            allow: value
                .allow()
                .iter()
                .map(|operation| operation.as_str().to_owned())
                .collect(),
            deny: value
                .deny()
                .iter()
                .map(|operation| operation.as_str().to_owned())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimeWindowRecord {
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

impl TimeWindowRecord {
    fn try_to_validated_time_window(&self) -> Result<ValidatedTimeWindow, TrustGrantError> {
        ValidatedTimeWindow::new(self.not_before, self.not_after)
    }
}

impl From<&ValidatedTimeWindow> for TimeWindowRecord {
    fn from(value: &ValidatedTimeWindow) -> Self {
        Self {
            not_before: value.not_before(),
            not_after: value.not_after(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationPolicyRecord {
    revocable: bool,
    revocation_endpoint: String,
}

impl RevocationPolicyRecord {
    fn try_to_validated_revocation(&self) -> ValidatedRevocation {
        ValidatedRevocation::new(self.revocable, self.revocation_endpoint.clone().into())
    }
}

impl From<&ValidatedRevocation> for RevocationPolicyRecord {
    fn from(value: &ValidatedRevocation) -> Self {
        Self {
            revocable: value.revocable(),
            revocation_endpoint: value.revocation_endpoint().to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalRecord {
    kind: String,
    id: String,
}

impl PrincipalRecord {
    fn try_to_validated_principal(&self) -> Result<ValidatedPrincipal, TrustGrantError> {
        Ok(ValidatedPrincipal::new(
            PrincipalKind::new(self.kind.clone())?,
            PrincipalId::new(self.id.clone())?,
        ))
    }
}

fn validate_unique_selectors(
    records: &[SelectorRecord],
) -> Result<Vec<ValidatedSelector>, TrustGrantError> {
    let mut seen = HashSet::with_capacity(records.len());
    let mut validated = Vec::with_capacity(records.len());

    for record in records {
        let selector = record.try_to_validated_selector()?;

        if !seen.insert(selector.clone()) {
            return Err(TrustGrantError::DuplicateSelector);
        }

        validated.push(selector);
    }

    Ok(validated)
}

fn normalize_persisted_non_empty_string(
    field_name: &'static str,
    value: &str,
    max_bytes: Option<usize>,
) -> Result<String, TrustGrantError> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(TrustGrantError::EmptyStringField(field_name));
    }

    if let Some(max_bytes) = max_bytes {
        ensure_string_limit(field_name, trimmed, max_bytes)?;
    }

    Ok(trimmed.to_owned())
}

fn normalize_persisted_non_empty_strings(
    field_name: &'static str,
    values: &[String],
    max_bytes: usize,
) -> Result<Vec<String>, TrustGrantError> {
    values
        .iter()
        .map(|value| normalize_persisted_non_empty_string(field_name, value, Some(max_bytes)))
        .collect()
}

impl From<&ValidatedPrincipal> for PrincipalRecord {
    fn from(value: &ValidatedPrincipal) -> Self {
        Self {
            kind: value.kind().as_str().to_owned(),
            id: value.id().as_str().to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationMetadataRecord {
    verified_at: DateTime<Utc>,
    posture: VerificationPosture,
    signer_binding: ResolvedSignerBindingRecord,
    ownership: OwnershipVerificationRecordRecord,
    revocation: VerifiedRevocationState,
}

impl VerificationMetadataRecord {
    fn try_into_metadata(self) -> Result<VerificationMetadata, TrustGrantError> {
        Ok(VerificationMetadata::new(
            self.verified_at,
            self.posture,
            self.signer_binding.try_into_binding()?,
            self.ownership.try_into_ownership()?,
            self.revocation,
        ))
    }
}

impl From<&VerificationMetadata> for VerificationMetadataRecord {
    fn from(value: &VerificationMetadata) -> Self {
        Self {
            verified_at: value.verified_at(),
            posture: value.posture(),
            signer_binding: ResolvedSignerBindingRecord::from(value.signer_binding()),
            ownership: OwnershipVerificationRecordRecord::from(value.ownership()),
            revocation: *value.revocation(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedSignerBindingRecord {
    issuer_authority: String,
    key_record: AuthorityKeyRecordRecord,
    signature_profile: SignatureProfileRecord,
    delegated_principal: Option<PrincipalRecord>,
}

impl ResolvedSignerBindingRecord {
    fn try_into_binding(self) -> Result<ResolvedSignerBinding, TrustGrantError> {
        Ok(ResolvedSignerBinding::new(
            AuthorityId::new(self.issuer_authority)?,
            self.key_record.try_into_key_record()?,
            self.signature_profile.try_into_signature_profile()?,
            self.delegated_principal
                .map(PrincipalRecord::try_into_delegated_principal)
                .transpose()?,
        ))
    }
}

impl From<&ResolvedSignerBinding> for ResolvedSignerBindingRecord {
    fn from(value: &ResolvedSignerBinding) -> Self {
        Self {
            issuer_authority: value.issuer_authority().to_string(),
            key_record: AuthorityKeyRecordRecord::from(value.key_record()),
            signature_profile: SignatureProfileRecord::from(value.signature_profile()),
            delegated_principal: value
                .delegated_principal()
                .map(|principal| PrincipalRecord {
                    kind: principal.kind().as_str().to_owned(),
                    id: principal.id().as_str().to_owned(),
                }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityKeyRecordRecord {
    key_id: String,
    algorithm: String,
    public_key: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

impl AuthorityKeyRecordRecord {
    fn try_into_key_record(self) -> Result<AuthorityKeyRecord, TrustGrantError> {
        AuthorityKeyRecord::new(
            self.key_id,
            self.algorithm,
            self.public_key,
            self.not_before,
            self.not_after,
        )
    }
}

impl From<&AuthorityKeyRecord> for AuthorityKeyRecordRecord {
    fn from(value: &AuthorityKeyRecord) -> Self {
        Self {
            key_id: value.key_id().as_str().to_owned(),
            algorithm: value.algorithm().as_str().to_owned(),
            public_key: value.public_key().as_str().to_owned(),
            not_before: value.not_before(),
            not_after: value.not_after(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureProfileRecord {
    format: String,
    canonicalization: String,
}

impl SignatureProfileRecord {
    fn try_into_signature_profile(self) -> Result<SignatureProfile, TrustGrantError> {
        SignatureProfile::new(self.format, self.canonicalization)
    }
}

impl From<&SignatureProfile> for SignatureProfileRecord {
    fn from(value: &SignatureProfile) -> Self {
        Self {
            format: value.format().as_str().to_owned(),
            canonicalization: value.canonicalization().as_str().to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnershipVerificationRecordRecord {
    origin_authority: String,
    active_owning_authority: String,
    checked_at: DateTime<Utc>,
    proof_kind: OwnershipProofKind,
    transition_chain_tip: Option<String>,
}

impl OwnershipVerificationRecordRecord {
    fn try_into_ownership(self) -> Result<OwnershipVerificationRecord, TrustGrantError> {
        Ok(OwnershipVerificationRecord::new(
            AuthorityId::new(self.origin_authority)?,
            AuthorityId::new(self.active_owning_authority)?,
            self.checked_at,
            self.proof_kind,
            self.transition_chain_tip
                .map(|value| value.parse::<TransitionId>())
                .transpose()
                .map_err(|_error| TrustGrantError::InvalidIdUuid)?,
        ))
    }
}

impl From<&OwnershipVerificationRecord> for OwnershipVerificationRecordRecord {
    fn from(value: &OwnershipVerificationRecord) -> Self {
        Self {
            origin_authority: value.origin_authority().to_string(),
            active_owning_authority: value.active_owning_authority().to_string(),
            checked_at: value.checked_at(),
            proof_kind: value.proof_kind(),
            transition_chain_tip: value
                .transition_chain_tip()
                .map(|id: trustgrant_domain::TransitionId| id.to_string()),
        }
    }
}

impl PrincipalRecord {
    fn try_into_delegated_principal(self) -> Result<DelegatedPrincipalRef, TrustGrantError> {
        DelegatedPrincipalRef::new(self.kind, self.id)
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use chrono::{TimeZone, Utc};
    use serde_json::Value;

    use super::VerifiedTrustGrantRecord;
    use crate::{VerificationMetadata, VerificationPosture, VerifiedTrustGrant};
    use trustgrant_discovery::{AuthorityKeyRecord, ResolvedSignerBinding, SignatureProfile};
    use trustgrant_document::RawTrustGrantDocument;
    use trustgrant_document::ValidatedTrustGrantDocument;
    use trustgrant_domain::AuthorityId;
    use trustgrant_domain::{OwnershipProofKind, OwnershipVerificationRecord};
    use trustgrant_error::TrustGrantError;
    use trustgrant_error::limits::{
        MAX_PUBLIC_KEY_MATERIAL_BYTES, MAX_RESOURCE_TYPES, MAX_SELECTORS_PER_SCOPE,
    };
    use trustgrant_revocation::{
        ProofFinality, RevocationRecord, RevocationSourceKind, RevocationStatus,
        VerifiedRevocationState,
    };

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
            "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
            "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
            "issued_at":"2026-04-07T12:00:00Z",
            "signature":"base64-signature"
        }"#;
        let raw = RawTrustGrantDocument::parse_json_str(json)
            .unwrap_or_else(|error| panic!("raw document should parse: {error}"));
        let validated = ValidatedTrustGrantDocument::try_from(raw)
            .unwrap_or_else(|error| panic!("validated document should be valid: {error}"));

        VerifiedTrustGrant::new(
            validated,
            VerificationMetadata::new(
                Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                    .single()
                    .unwrap_or_else(|| panic!("timestamp should be valid")),
                VerificationPosture::Online,
                ResolvedSignerBinding::new(
                    AuthorityId::new("https://issuer.example.com")
                        .unwrap_or_else(|error| panic!("authority should be valid: {error}")),
                    AuthorityKeyRecord::new(
                        "root-key-1",
                        "ed25519",
                        "base64-public-key",
                        Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                            .single()
                            .unwrap_or_else(|| panic!("timestamp should be valid")),
                        Utc.with_ymd_and_hms(2026, 4, 9, 12, 0, 0)
                            .single()
                            .unwrap_or_else(|| panic!("timestamp should be valid")),
                    )
                    .unwrap_or_else(|error| panic!("key record should be valid: {error}")),
                    SignatureProfile::new("jcs+ed25519", "RFC8785").unwrap_or_else(|error| {
                        panic!("signature profile should be valid: {error}")
                    }),
                    None,
                ),
                OwnershipVerificationRecord::new(
                    AuthorityId::new("https://issuer.example.com")
                        .unwrap_or_else(|error| panic!("authority should be valid: {error}")),
                    AuthorityId::new("https://issuer.example.com")
                        .unwrap_or_else(|error| panic!("authority should be valid: {error}")),
                    Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                        .single()
                        .unwrap_or_else(|| panic!("timestamp should be valid")),
                    OwnershipProofKind::StaticOwner,
                    None,
                ),
                VerifiedRevocationState::Checked(
                    RevocationRecord::new(
                        RevocationStatus::Active,
                        RevocationSourceKind::Api,
                        ProofFinality::Observed,
                        Utc.with_ymd_and_hms(2026, 4, 8, 12, 0, 0)
                            .single()
                            .unwrap_or_else(|| panic!("timestamp should be valid")),
                        Utc.with_ymd_and_hms(2026, 4, 8, 12, 5, 0)
                            .single()
                            .unwrap_or_else(|| panic!("timestamp should be valid")),
                    )
                    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
                ),
            ),
        )
    }

    #[test]
    fn verified_grant_record_roundtrips() {
        let verified = verified_grant();
        let record = VerifiedTrustGrantRecord::from(&verified);
        let reparsed = record
            .try_into_verified_grant()
            .unwrap_or_else(|error| panic!("record should roundtrip: {error}"));

        assert_eq!(reparsed.lineage(), verified.lineage());
        assert_eq!(
            reparsed.metadata().ownership().active_owning_authority(),
            verified.metadata().ownership().active_owning_authority()
        );
    }

    #[test]
    fn verified_record_rejects_excessive_resource_scope() {
        let record = VerifiedTrustGrantRecord::from(&verified_grant());
        let mut json = serde_json::to_value(&record)
            .unwrap_or_else(|error| panic!("record should serialize: {error}"));
        let object = json
            .as_object_mut()
            .unwrap_or_else(|| panic!("record should serialize to object"));
        let document = object
            .get_mut("document")
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("document should serialize to object"));
        let resource_scope = document
            .get_mut("resource_scope")
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("resource scope should serialize to object"));
        let resource_record = resource_scope
            .values()
            .next()
            .cloned()
            .unwrap_or_else(|| panic!("fixture should contain one resource type"));

        for index in 0..=MAX_RESOURCE_TYPES {
            resource_scope.insert(format!("item_{index}"), resource_record.clone());
        }

        let tampered = serde_json::from_value::<VerifiedTrustGrantRecord>(json)
            .unwrap_or_else(|error| panic!("tampered record should deserialize: {error}"));

        assert_eq!(
            tampered.try_into_verified_grant(),
            Err(TrustGrantError::CollectionTooLarge {
                field: "verified_record.resource_scope",
                max_items: MAX_RESOURCE_TYPES,
            })
        );
    }

    #[test]
    fn verified_record_rejects_excessive_scope_selectors() {
        let record = VerifiedTrustGrantRecord::from(&verified_grant());
        let mut json = serde_json::to_value(&record)
            .unwrap_or_else(|error| panic!("record should serialize: {error}"));
        let object = json
            .as_object_mut()
            .unwrap_or_else(|| panic!("record should serialize to object"));
        let document = object
            .get_mut("document")
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("document should serialize to object"));
        let target_scope = document
            .get_mut("target_scope")
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("target scope should serialize to object"));
        let allow = target_scope
            .get_mut("allow")
            .and_then(Value::as_array_mut)
            .unwrap_or_else(|| panic!("allow selectors should serialize to array"));
        let selector = allow
            .first()
            .cloned()
            .unwrap_or_else(|| panic!("fixture should contain one selector"));

        for _ in 0..MAX_SELECTORS_PER_SCOPE {
            allow.push(selector.clone());
        }

        let tampered = serde_json::from_value::<VerifiedTrustGrantRecord>(json)
            .unwrap_or_else(|error| panic!("tampered record should deserialize: {error}"));

        assert_eq!(
            tampered.try_into_verified_grant(),
            Err(TrustGrantError::CollectionTooLarge {
                field: "verified_record.scope.allow",
                max_items: MAX_SELECTORS_PER_SCOPE,
            })
        );
    }

    #[test]
    fn verified_record_rejects_signer_authority_mismatch() {
        let mut json = serde_json::to_value(VerifiedTrustGrantRecord::from(&verified_grant()))
            .unwrap_or_else(|error| panic!("record should serialize: {error}"));
        let object = json
            .as_object_mut()
            .unwrap_or_else(|| panic!("record should serialize to object"));
        let metadata = object
            .get_mut("metadata")
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("metadata should serialize to object"));
        let signer_binding = metadata
            .get_mut("signer_binding")
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("signer binding should serialize to object"));
        signer_binding.insert(
            "issuer_authority".to_owned(),
            Value::String("https://other.example.com".to_owned()),
        );

        let tampered = serde_json::from_value::<VerifiedTrustGrantRecord>(json)
            .unwrap_or_else(|error| panic!("tampered record should deserialize: {error}"));

        assert_eq!(
            tampered.try_into_verified_grant(),
            Err(TrustGrantError::SignerAuthorityMismatch)
        );
    }

    #[test]
    fn verified_record_rejects_cached_posture_with_live_revocation_source() {
        let mut json = serde_json::to_value(VerifiedTrustGrantRecord::from(&verified_grant()))
            .unwrap_or_else(|error| panic!("record should serialize: {error}"));
        let object = json
            .as_object_mut()
            .unwrap_or_else(|| panic!("record should serialize to object"));
        let metadata = object
            .get_mut("metadata")
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("metadata should serialize to object"));
        metadata.insert("posture".to_owned(), Value::String("cached".to_owned()));

        let tampered = serde_json::from_value::<VerifiedTrustGrantRecord>(json)
            .unwrap_or_else(|error| panic!("tampered record should deserialize: {error}"));

        assert_eq!(
            tampered.try_into_verified_grant(),
            Err(TrustGrantError::VerificationPostureRequiresNonLiveRevocation)
        );
    }

    #[test]
    fn verified_record_rejects_unsupported_record_version() {
        let mut json = serde_json::to_value(VerifiedTrustGrantRecord::from(&verified_grant()))
            .unwrap_or_else(|error| panic!("record should serialize: {error}"));
        let object = json
            .as_object_mut()
            .unwrap_or_else(|| panic!("record should serialize to object"));
        object.insert("record_version".to_owned(), Value::Number(2.into()));

        let tampered = serde_json::from_value::<VerifiedTrustGrantRecord>(json)
            .unwrap_or_else(|error| panic!("tampered record should deserialize: {error}"));

        assert_eq!(
            tampered.try_into_verified_grant(),
            Err(TrustGrantError::UnsupportedPersistedVerifiedGrantRecordVersion(2))
        );
    }

    #[test]
    fn verified_record_rejects_oversized_public_key_material() {
        let mut json = serde_json::to_value(VerifiedTrustGrantRecord::from(&verified_grant()))
            .unwrap_or_else(|error| panic!("record should serialize: {error}"));
        let object = json
            .as_object_mut()
            .unwrap_or_else(|| panic!("record should serialize to object"));
        let metadata = object
            .get_mut("metadata")
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("metadata should serialize to object"));
        let signer_binding = metadata
            .get_mut("signer_binding")
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("signer binding should serialize to object"));
        let key_record = signer_binding
            .get_mut("key_record")
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("key record should serialize to object"));
        key_record.insert(
            "public_key".to_owned(),
            Value::String("a".repeat(MAX_PUBLIC_KEY_MATERIAL_BYTES + 1)),
        );

        let tampered = serde_json::from_value::<VerifiedTrustGrantRecord>(json)
            .unwrap_or_else(|error| panic!("tampered record should deserialize: {error}"));

        assert_eq!(
            tampered.try_into_verified_grant(),
            Err(TrustGrantError::StringTooLong {
                field: "public_key",
                max_bytes: MAX_PUBLIC_KEY_MATERIAL_BYTES,
            })
        );
    }

    #[test]
    fn verified_record_rejects_tampered_key_id() {
        let record = VerifiedTrustGrantRecord::from(&verified_grant());
        let mut json = serde_json::to_value(&record)
            .unwrap_or_else(|error| panic!("record should serialize: {error}"));
        let object = json
            .as_object_mut()
            .unwrap_or_else(|| panic!("record should serialize to object"));
        let document = object
            .get_mut("document")
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("document should serialize to object"));
        document.insert(
            "key_id".to_owned(),
            Value::String("tampered-key".to_owned()),
        );

        let tampered = serde_json::from_value::<VerifiedTrustGrantRecord>(json)
            .unwrap_or_else(|error| panic!("tampered record should deserialize: {error}"));

        assert_eq!(
            tampered.try_into_verified_grant(),
            Err(TrustGrantError::KeyIdMismatch)
        );
    }

    #[test]
    fn verified_record_rejects_tampered_signature_field() {
        let record = VerifiedTrustGrantRecord::from(&verified_grant());
        let mut json = serde_json::to_value(&record)
            .unwrap_or_else(|error| panic!("record should serialize: {error}"));
        let object = json
            .as_object_mut()
            .unwrap_or_else(|| panic!("record should serialize to object"));
        // The record uses deny_unknown_fields, so adding a "signature" field
        // to the top level should be rejected at deserialization time.
        object.insert(
            "signature".to_owned(),
            Value::String("tampered-signature".to_owned()),
        );

        let result = serde_json::from_value::<VerifiedTrustGrantRecord>(json);
        assert!(
            result.is_err(),
            "record with injected signature field should fail deserialization"
        );
    }

    #[test]
    fn verified_record_with_version_zero_is_rejected() {
        let mut json = serde_json::to_value(VerifiedTrustGrantRecord::from(&verified_grant()))
            .unwrap_or_else(|error| panic!("record should serialize: {error}"));
        let object = json
            .as_object_mut()
            .unwrap_or_else(|| panic!("record should serialize to object"));
        object.insert("record_version".to_owned(), Value::Number(0.into()));

        let tampered = serde_json::from_value::<VerifiedTrustGrantRecord>(json)
            .unwrap_or_else(|error| panic!("tampered record should deserialize: {error}"));

        assert_eq!(
            tampered.try_into_verified_grant(),
            Err(TrustGrantError::UnsupportedPersistedVerifiedGrantRecordVersion(0))
        );
    }

    #[test]
    fn verified_record_deserialization_rejects_unknown_fields() {
        let mut json = serde_json::to_value(VerifiedTrustGrantRecord::from(&verified_grant()))
            .unwrap_or_else(|error| panic!("record should serialize: {error}"));
        let object = json
            .as_object_mut()
            .unwrap_or_else(|| panic!("record should serialize to object"));
        object.insert("unexpected".to_owned(), Value::String("value".to_owned()));

        let result = serde_json::from_value::<VerifiedTrustGrantRecord>(json);

        assert!(result.is_err());
    }
}
