use chrono::{DateTime, Utc};
use compact_str::CompactString;
use std::collections::{BTreeMap, HashSet};

use crate::raw::{
    InteroperabilityProfile, PostRevocationEffect, RawAudienceEntry, RawCapabilities,
    RawGlobalConstraints, RawMintingConstraints, RawOperationScope, RawPrincipal, RawResourceScope,
    RawResourceType, RawRevocation, RawScope, RawSelector, RawSupersessionPolicy,
    RawTrustGrantDocument, RawTypeCapabilities, RawTypeConstraints,
};
use trustgrant_domain::{
    AuthorityId, GrantLineage, GrantRevision, GrantSeriesId, KeyId, OperationName,
    OwnershipAuthorityState, PrincipalId, PrincipalKind, ResourceTypeName, SelectorExpression,
    SelectorKind, SupersessionPolicy, TrustGrantId,
};
use trustgrant_error::TrustGrantError;
use trustgrant_error::limits::{
    MAX_AUDIENCE_ENTRIES, MAX_OPERATIONS_PER_SCOPE, MAX_RESOURCE_TYPES,
    MAX_SELECTOR_EXPRESSION_BYTES, MAX_SELECTOR_EXPRESSIONS_PER_SELECTOR, MAX_SELECTOR_VALUE_BYTES,
    MAX_SELECTOR_VALUES_PER_SELECTOR, MAX_SELECTORS_PER_SCOPE, ensure_collection_limit,
    ensure_string_limit,
};

/// A fully validated TrustGrant document ready for evaluation.
///
/// Produced by converting a [`RawTrustGrantDocument`] through
/// `TryFrom<RawTrustGrantDocument>`. All string and collection limits have
/// been checked, identifiers have been normalized, and scope shapes have
/// been verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedTrustGrantDocument {
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
    signature: String,
    issuer_principal: Option<ValidatedPrincipal>,
    interoperability_profile: Option<InteroperabilityProfile>,
}

impl ValidatedTrustGrantDocument {
    /// Validated lineage is required for registration and lookup.
    pub const fn lineage(&self) -> &GrantLineage {
        &self.lineage
    }

    /// Issuer authority is required for signature and trust evaluation.
    #[must_use]
    pub const fn issuer_authority(&self) -> &AuthorityId {
        &self.issuer_authority
    }

    /// Ownership state is required for owner-level evaluation.
    #[must_use]
    pub const fn ownership_authority_state(&self) -> &OwnershipAuthorityState {
        &self.ownership_authority_state
    }

    /// Signing key id is required for verification and audit.
    #[must_use]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// Target scope is required for evaluation.
    #[must_use]
    pub const fn target_scope(&self) -> &ValidatedScope {
        &self.target_scope
    }

    /// Top-level capabilities are required for evaluation.
    #[must_use]
    pub const fn capabilities(&self) -> &ValidatedCapabilities {
        &self.capabilities
    }

    /// Default audience entries are used for evaluation or publication.
    #[must_use]
    pub fn default_audience_scope(&self) -> &[ValidatedAudienceEntry] {
        &self.default_audience_scope
    }

    /// Resource scope is required for evaluation.
    #[must_use]
    pub const fn resource_scope(&self) -> &BTreeMap<ResourceTypeName, ValidatedResourceType> {
        &self.resource_scope
    }

    /// Global time window may constrain validity.
    #[must_use]
    pub const fn global_time_window(&self) -> Option<&ValidatedTimeWindow> {
        self.global_time_window.as_ref()
    }

    /// Revocation policy may constrain validity.
    #[must_use]
    pub const fn revocation(&self) -> Option<&ValidatedRevocation> {
        self.revocation.as_ref()
    }

    /// Issued_at is part of the signed wire document.
    #[must_use]
    pub const fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    /// Signature is required for verification.
    #[must_use]
    pub fn signature(&self) -> &str {
        &self.signature
    }

    /// Issuer principal may narrow the logical signer identity.
    #[must_use]
    pub const fn issuer_principal(&self) -> Option<&ValidatedPrincipal> {
        self.issuer_principal.as_ref()
    }

    /// Interoperability profile declares the operational context for custom
    /// operations. Profiles constrain which custom operation names are valid.
    #[must_use]
    pub const fn interoperability_profile(&self) -> Option<&InteroperabilityProfile> {
        self.interoperability_profile.as_ref()
    }
}

/// Converts a raw (unvalidated) TrustGrant document into a validated one.
///
/// # Examples
///
/// ```rust
/// use trustgrant_document::ValidatedTrustGrantDocument;
/// use trustgrant_document::raw::RawTrustGrantDocument;
///
/// let json = r#"{
///   "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
///   "version":0,
///   "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
///   "revision":1,
///   "supersession_policy":"coexist",
///   "issuer_authority":"https://issuer.example.com",
///   "origin_authority":"https://issuer.example.com",
///   "active_owning_authority":"https://issuer.example.com",
///   "key_id":"root-key-1",
///   "target_scope":{"all":true,"allow":null,"deny":null},
///   "capabilities":{"recognize":true,"mint":false},
///   "resource_scope":{"types":{}},
///   "issued_at":"2026-04-07T12:00:00Z",
///   "signature":"base64-signature"
/// }"#;
///
/// let raw = RawTrustGrantDocument::parse_json_str(json).expect("valid JSON");
/// let validated = ValidatedTrustGrantDocument::try_from(raw)
///     .expect("document validation");
///
/// assert_eq!(
///     validated.lineage().trustgrant_id().to_string(),
///     "tg_123e4567-e89b-12d3-a456-426614174000"
/// );
/// ```
impl TryFrom<RawTrustGrantDocument> for ValidatedTrustGrantDocument {
    type Error = TrustGrantError;

    fn try_from(raw: RawTrustGrantDocument) -> Result<Self, Self::Error> {
        if raw.version != 0 {
            return Err(TrustGrantError::InvalidProtocolVersion(raw.version));
        }

        let trustgrant_id = raw.trustgrant_id.parse::<TrustGrantId>()?;
        let grant_series_id = raw.grant_series_id.parse::<GrantSeriesId>()?;
        let revision = GrantRevision::new(raw.revision)?;
        let supersedes = raw
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

        let supersession_policy = match raw.supersession_policy {
            RawSupersessionPolicy::Coexist => SupersessionPolicy::Coexist,
            RawSupersessionPolicy::SupersedePrevious => SupersessionPolicy::SupersedePrevious,
        };

        let lineage = GrantLineage::new(
            trustgrant_id,
            grant_series_id,
            revision,
            supersedes,
            supersession_policy,
        );

        let issuer_authority = AuthorityId::new(raw.issuer_authority)?;
        let origin_authority = AuthorityId::new(raw.origin_authority)?;
        let active_owning_authority = AuthorityId::new(raw.active_owning_authority)?;
        let ownership_authority_state =
            OwnershipAuthorityState::new(origin_authority, active_owning_authority);

        let key_id = KeyId::new(raw.key_id)?;
        let signature = normalize_non_empty_string("signature", &raw.signature, None)?;
        let target_scope = validate_scope("target_scope", raw.target_scope)?;
        let capabilities = ValidatedCapabilities::from_raw(raw.capabilities);
        let default_audience_scope =
            validate_audience_entries("default_audience_scope", raw.default_audience_scope)?;
        let resource_scope = validate_resource_scope(raw.resource_scope)?;
        let global_time_window = validate_global_constraints(raw.global_constraints)?;
        let revocation = raw.revocation.map(ValidatedRevocation::from_raw);
        let issuer_principal = raw
            .issuer_principal
            .map(ValidatedPrincipal::try_from)
            .transpose()?;

        Ok(Self {
            lineage,
            issuer_authority,
            ownership_authority_state,
            key_id,
            target_scope,
            capabilities,
            default_audience_scope,
            resource_scope,
            global_time_window,
            revocation,
            issued_at: raw.issued_at,
            signature,
            issuer_principal,
            interoperability_profile: raw.interoperability_profile,
        })
    }
}

/// A validated issuer principal with normalized kind and identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPrincipal {
    kind: PrincipalKind,
    id: PrincipalId,
}

impl ValidatedPrincipal {
    /// Persisted principal state must stay valid by construction.
    pub const fn new(kind: PrincipalKind, id: PrincipalId) -> Self {
        Self { kind, id }
    }

    /// Principal kind is part of signer attribution.
    #[must_use]
    pub const fn kind(&self) -> &PrincipalKind {
        &self.kind
    }

    /// Principal identifier is part of signer attribution.
    #[must_use]
    pub const fn id(&self) -> &PrincipalId {
        &self.id
    }
}

impl TryFrom<RawPrincipal> for ValidatedPrincipal {
    type Error = TrustGrantError;

    fn try_from(raw: RawPrincipal) -> Result<Self, Self::Error> {
        Ok(Self {
            kind: PrincipalKind::new(raw.kind)?,
            id: PrincipalId::new(raw.id)?,
        })
    }
}

/// Validated top-level built-in capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCapabilities {
    recognize: bool,
    mint: bool,
}

impl ValidatedCapabilities {
    /// Capability state must stay valid by construction.
    pub const fn new(recognize: bool, mint: bool) -> Self {
        Self { recognize, mint }
    }

    const fn from_raw(raw: RawCapabilities) -> Self {
        Self::new(raw.recognize, raw.mint)
    }

    /// Recognize capability drives evaluation behavior.
    #[must_use]
    pub const fn recognize(&self) -> bool {
        self.recognize
    }

    /// Mint capability drives evaluation behavior.
    #[must_use]
    pub const fn mint(&self) -> bool {
        self.mint
    }
}

/// A validated selector with normalized kind, values, and expressions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValidatedSelector {
    kind: SelectorKind,
    all: bool,
    values: Vec<String>,
    expressions: Vec<SelectorExpression>,
}

impl ValidatedSelector {
    /// Creates a new validated selector.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError::InvalidSelectorShape`] if `all` is `true`
    /// and values or expressions are non-empty, or if `all` is `false`
    /// and both values and expressions are empty.
    pub fn new(
        kind: SelectorKind,
        all: bool,
        values: Vec<String>,
        expressions: Vec<SelectorExpression>,
    ) -> Result<Self, TrustGrantError> {
        if all && (!values.is_empty() || !expressions.is_empty()) {
            return Err(TrustGrantError::InvalidSelectorShape);
        }

        if !all && values.is_empty() && expressions.is_empty() {
            return Err(TrustGrantError::InvalidSelectorShape);
        }

        Ok(Self {
            kind,
            all,
            values,
            expressions,
        })
    }

    /// Selector kind participates in evaluation matching.
    pub const fn kind(&self) -> &SelectorKind {
        &self.kind
    }

    /// Selector all flag participates in evaluation matching.
    #[must_use]
    pub const fn all(&self) -> bool {
        self.all
    }

    /// Selector values participate in evaluation matching.
    #[must_use]
    pub fn values(&self) -> &[String] {
        &self.values
    }

    /// Selector expressions participate in evaluation matching.
    #[must_use]
    pub fn expressions(&self) -> &[SelectorExpression] {
        &self.expressions
    }
}

/// A validated scope block with allow/deny selector lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedScope {
    all: bool,
    allow: Vec<ValidatedSelector>,
    deny: Vec<ValidatedSelector>,
}

impl ValidatedScope {
    /// Creates a new validated scope.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError::InvalidScopeShape`] if `all` is `true`
    /// and allow selectors are present, or if `all` is `false` and
    /// no allow selectors are provided.
    pub fn new(
        scope_name: &'static str,
        all: bool,
        allow: Vec<ValidatedSelector>,
        deny: Vec<ValidatedSelector>,
    ) -> Result<Self, TrustGrantError> {
        validate_scope_shape(scope_name, all, allow.is_empty(), !allow.is_empty())?;

        Ok(Self { all, allow, deny })
    }

    /// Scope all flag participates in evaluation matching.
    pub const fn all(&self) -> bool {
        self.all
    }

    /// Allow selectors participate in evaluation matching.
    #[must_use]
    pub fn allow(&self) -> &[ValidatedSelector] {
        &self.allow
    }

    /// Deny selectors participate in evaluation matching.
    #[must_use]
    pub fn deny(&self) -> &[ValidatedSelector] {
        &self.deny
    }
}

/// A validated operation scope with allow/deny operation lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedOperationScope {
    allow: Vec<OperationName>,
    deny: Vec<OperationName>,
}

impl ValidatedOperationScope {
    /// Creates a new validated operation scope.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError::InvalidScopeShape("operations")`] if no
    /// allow operations are provided.
    ///
    /// Returns [`TrustGrantError::DuplicateOperationName`] if duplicate
    /// operation names exist in the allow or deny lists.
    pub fn new(
        allow: Vec<OperationName>,
        deny: Vec<OperationName>,
    ) -> Result<Self, TrustGrantError> {
        if allow.is_empty() {
            return Err(TrustGrantError::InvalidScopeShape("operations"));
        }

        ensure_no_duplicate_operations(&allow)?;
        ensure_no_duplicate_operations(&deny)?;

        Ok(Self { allow, deny })
    }

    /// Allowed operations participate in evaluation matching.
    #[must_use]
    pub fn allow(&self) -> &[OperationName] {
        &self.allow
    }

    /// Denied operations participate in evaluation matching.
    #[must_use]
    pub fn deny(&self) -> &[OperationName] {
        &self.deny
    }
}

/// A validated audience entry with authority, scope, and optional principal
/// scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAudienceEntry {
    authority_id: AuthorityId,
    scope: ValidatedScope,
    principal_scope: Option<ValidatedScope>,
}

impl ValidatedAudienceEntry {
    /// Persisted audience entry state must stay valid by construction.
    #[must_use]
    pub const fn new(
        authority_id: AuthorityId,
        scope: ValidatedScope,
        principal_scope: Option<ValidatedScope>,
    ) -> Self {
        Self {
            authority_id,
            scope,
            principal_scope,
        }
    }

    /// Audience authority participates in evaluation matching.
    #[must_use]
    pub const fn authority_id(&self) -> &AuthorityId {
        &self.authority_id
    }

    /// Audience scope participates in evaluation matching.
    #[must_use]
    pub const fn scope(&self) -> &ValidatedScope {
        &self.scope
    }

    /// Principal scope may further constrain the audience.
    #[must_use]
    pub const fn principal_scope(&self) -> Option<&ValidatedScope> {
        self.principal_scope.as_ref()
    }
}

/// A validated resource type scope with capabilities, constraints, and
/// optional operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedResourceType {
    all: bool,
    allow: Vec<ValidatedSelector>,
    deny: Vec<ValidatedSelector>,
    capabilities: ValidatedTypeCapabilities,
    constraints: ValidatedTypeConstraints,
    operations: Option<ValidatedOperationScope>,
}

impl ValidatedResourceType {
    /// Creates a new validated resource type scope.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError::InvalidScopeShape`] if `all` is `true`
    /// and allow selectors are present, or if `all` is `false` and
    /// no allow selectors are provided.
    pub fn new(
        all: bool,
        allow: Vec<ValidatedSelector>,
        deny: Vec<ValidatedSelector>,
        capabilities: ValidatedTypeCapabilities,
        constraints: ValidatedTypeConstraints,
        operations: Option<ValidatedOperationScope>,
    ) -> Result<Self, TrustGrantError> {
        validate_scope_shape(
            "resource_scope.types",
            all,
            allow.is_empty(),
            !allow.is_empty(),
        )?;

        Ok(Self {
            all,
            allow,
            deny,
            capabilities,
            constraints,
            operations,
        })
    }

    /// Resource type all flag participates in evaluation matching.
    pub const fn all(&self) -> bool {
        self.all
    }

    /// Resource type allow selectors participate in evaluation matching.
    #[must_use]
    pub fn allow(&self) -> &[ValidatedSelector] {
        &self.allow
    }

    /// Resource type deny selectors participate in evaluation matching.
    #[must_use]
    pub fn deny(&self) -> &[ValidatedSelector] {
        &self.deny
    }

    /// Resource type capabilities participate in evaluation.
    #[must_use]
    pub const fn capabilities(&self) -> &ValidatedTypeCapabilities {
        &self.capabilities
    }

    /// Resource type constraints participate in evaluation.
    #[must_use]
    pub const fn constraints(&self) -> &ValidatedTypeConstraints {
        &self.constraints
    }

    /// Resource type operations participate in evaluation.
    #[must_use]
    pub const fn operations(&self) -> Option<&ValidatedOperationScope> {
        self.operations.as_ref()
    }
}

/// Validated per-type capability overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedTypeCapabilities {
    recognize: Option<bool>,
    mint: Option<bool>,
}

impl ValidatedTypeCapabilities {
    /// Persisted type capability state must stay valid by construction.
    #[must_use]
    pub const fn new(recognize: Option<bool>, mint: Option<bool>) -> Self {
        Self { recognize, mint }
    }

    /// Resource type recognize override participates in evaluation.
    #[must_use]
    pub const fn recognize(&self) -> Option<bool> {
        self.recognize
    }

    /// Resource type mint override participates in evaluation.
    #[must_use]
    pub const fn mint(&self) -> Option<bool> {
        self.mint
    }
}

/// Validated per-type constraints (minting limits + audience scope).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedTypeConstraints {
    minting: ValidatedMintingConstraints,
    audience_scope: Vec<ValidatedAudienceEntry>,
}

impl ValidatedTypeConstraints {
    /// Persisted type constraint state must stay valid by construction.
    #[must_use]
    pub const fn new(
        minting: ValidatedMintingConstraints,
        audience_scope: Vec<ValidatedAudienceEntry>,
    ) -> Self {
        Self {
            minting,
            audience_scope,
        }
    }

    /// Minting constraints participate in evaluation.
    #[must_use]
    pub const fn minting(&self) -> &ValidatedMintingConstraints {
        &self.minting
    }

    /// Audience constraints participate in evaluation.
    #[must_use]
    pub fn audience_scope(&self) -> &[ValidatedAudienceEntry] {
        &self.audience_scope
    }
}

/// Validated minting constraints with optional limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedMintingConstraints {
    max_total: Option<u64>,
    max_per_user: Option<u64>,
}

impl ValidatedMintingConstraints {
    /// Persisted minting limits must stay valid by construction.
    #[must_use]
    pub const fn new(max_total: Option<u64>, max_per_user: Option<u64>) -> Self {
        Self {
            max_total,
            max_per_user,
        }
    }

    /// Minting max_total participates in evaluation.
    #[must_use]
    pub const fn max_total(&self) -> Option<u64> {
        self.max_total
    }

    /// Minting max_per_user participates in evaluation.
    #[must_use]
    pub const fn max_per_user(&self) -> Option<u64> {
        self.max_per_user
    }
}

/// A validated time window ensuring `not_before <= not_after`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedTimeWindow {
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

impl ValidatedTimeWindow {
    /// Creates a new validated time window.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError::InvalidTimeWindow`] if `not_before`
    /// is later than `not_after`.
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

    /// Not_before participates in time-based evaluation.
    pub const fn not_before(&self) -> DateTime<Utc> {
        self.not_before
    }

    /// Not_after participates in time-based evaluation.
    #[must_use]
    pub const fn not_after(&self) -> DateTime<Utc> {
        self.not_after
    }
}

/// Validated revocation policy with normalized endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedRevocation {
    revocable: bool,
    revocation_endpoint: CompactString,
    post_revocation_effect: PostRevocationEffect,
}

impl ValidatedRevocation {
    /// Persisted revocation policy must stay valid by construction.
    #[must_use]
    pub const fn new(revocable: bool, revocation_endpoint: CompactString) -> Self {
        Self {
            revocable,
            revocation_endpoint,
            post_revocation_effect: PostRevocationEffect::BlockAll,
        }
    }

    fn from_raw(raw: RawRevocation) -> Self {
        Self {
            revocable: raw.revocable,
            revocation_endpoint: raw.revocation_endpoint,
            post_revocation_effect: raw.post_revocation_effect,
        }
    }

    /// Revocable flag participates in revocation policy.
    #[must_use]
    pub const fn revocable(&self) -> bool {
        self.revocable
    }

    /// Revocation endpoint participates in revocation policy.
    #[must_use]
    pub fn revocation_endpoint(&self) -> &str {
        &self.revocation_endpoint
    }

    /// What happens after this grant is revoked.
    #[must_use]
    pub const fn post_revocation_effect(&self) -> PostRevocationEffect {
        self.post_revocation_effect
    }

    /// Sets the post-revocation effect. Used during rehydration from a
    /// persisted record.
    #[must_use]
    pub const fn with_post_revocation_effect(mut self, effect: PostRevocationEffect) -> Self {
        self.post_revocation_effect = effect;
        self
    }
}

fn validate_resource_scope(
    raw: RawResourceScope,
) -> Result<BTreeMap<ResourceTypeName, ValidatedResourceType>, TrustGrantError> {
    ensure_collection_limit("resource_scope.types", raw.types.len(), MAX_RESOURCE_TYPES)?;

    raw.types
        .into_iter()
        .map(|(resource_type_name, raw_resource_type)| {
            let resource_type_name = ResourceTypeName::new(resource_type_name)?;
            let resource_type = validate_resource_type(raw_resource_type)?;

            Ok((resource_type_name, resource_type))
        })
        .collect()
}

fn validate_resource_type(raw: RawResourceType) -> Result<ValidatedResourceType, TrustGrantError> {
    let allow = validate_selectors(raw.allow)?;
    let deny = validate_selectors(raw.deny)?;
    let capabilities = validate_type_capabilities(raw.capabilities);
    let constraints = validate_type_constraints(raw.constraints)?;
    let operations = raw.operations.map(validate_operation_scope).transpose()?;

    validate_scope_shape(
        "resource_scope.types",
        raw.all,
        allow.is_empty(),
        !allow.is_empty(),
    )?;

    Ok(ValidatedResourceType {
        all: raw.all,
        allow,
        deny,
        capabilities,
        constraints,
        operations,
    })
}

const fn validate_type_capabilities(raw: RawTypeCapabilities) -> ValidatedTypeCapabilities {
    ValidatedTypeCapabilities::new(raw.recognize, raw.mint)
}

fn validate_type_constraints(
    raw: RawTypeConstraints,
) -> Result<ValidatedTypeConstraints, TrustGrantError> {
    Ok(ValidatedTypeConstraints {
        minting: validate_minting_constraints(raw.minting),
        audience_scope: validate_audience_entries(
            "resource_scope.audience_scope",
            raw.audience_scope,
        )?,
    })
}

const fn validate_minting_constraints(raw: RawMintingConstraints) -> ValidatedMintingConstraints {
    ValidatedMintingConstraints::new(raw.max_total, raw.max_per_user)
}

fn validate_global_constraints(
    raw: Option<RawGlobalConstraints>,
) -> Result<Option<ValidatedTimeWindow>, TrustGrantError> {
    let Some(raw) = raw else {
        return Ok(None);
    };

    let Some(time) = raw.time else {
        return Ok(None);
    };

    Ok(Some(ValidatedTimeWindow::new(
        time.not_before,
        time.not_after,
    )?))
}

fn validate_audience_entries(
    scope_name: &'static str,
    raw: Option<Vec<RawAudienceEntry>>,
) -> Result<Vec<ValidatedAudienceEntry>, TrustGrantError> {
    let entries = raw.unwrap_or_default();
    ensure_collection_limit(scope_name, entries.len(), MAX_AUDIENCE_ENTRIES)?;

    let mut seen_authorities = HashSet::new();
    entries
        .into_iter()
        .map(|entry| {
            let authority_id = AuthorityId::new(entry.authority_id)?;
            if !seen_authorities.insert(authority_id.clone()) {
                return Err(TrustGrantError::DuplicateAudienceAuthority);
            }
            Ok(ValidatedAudienceEntry::new(
                authority_id,
                validate_scope(scope_name, entry.scope)?,
                entry
                    .principal_scope
                    .map(|scope| validate_scope(scope_name, scope))
                    .transpose()?,
            ))
        })
        .collect()
}

fn validate_scope(
    scope_name: &'static str,
    raw: RawScope,
) -> Result<ValidatedScope, TrustGrantError> {
    let allow = validate_selectors(raw.allow)?;
    let deny = validate_selectors(raw.deny)?;

    ValidatedScope::new(scope_name, raw.all, allow, deny)
}

const fn validate_scope_shape(
    scope_name: &'static str,
    all: bool,
    allow_is_empty: bool,
    allow_present: bool,
) -> Result<(), TrustGrantError> {
    if all && !allow_is_empty {
        return Err(TrustGrantError::InvalidScopeShape(scope_name));
    }

    if !all && !allow_present {
        return Err(TrustGrantError::InvalidScopeShape(scope_name));
    }

    Ok(())
}

fn validate_selectors(
    raw: Option<Vec<RawSelector>>,
) -> Result<Vec<ValidatedSelector>, TrustGrantError> {
    let selectors = raw.unwrap_or_default();
    ensure_collection_limit("scope.selectors", selectors.len(), MAX_SELECTORS_PER_SCOPE)?;
    let mut seen = HashSet::with_capacity(selectors.len());
    let mut validated = Vec::with_capacity(selectors.len());

    for selector in selectors {
        let validated_selector = validate_selector(selector)?;

        if !seen.insert(validated_selector.clone()) {
            return Err(TrustGrantError::DuplicateSelector);
        }

        validated.push(validated_selector);
    }

    Ok(validated)
}

fn validate_selector(raw: RawSelector) -> Result<ValidatedSelector, TrustGrantError> {
    let kind = SelectorKind::new(raw.kind)?;
    let values = normalize_non_empty_strings(raw.values)?;
    let expressions = validate_selector_expressions(raw.expressions)?;

    if raw.all && (!values.is_empty() || !expressions.is_empty()) {
        return Err(TrustGrantError::InvalidSelectorShape);
    }

    if !raw.all && values.is_empty() && expressions.is_empty() {
        return Err(TrustGrantError::InvalidSelectorShape);
    }

    Ok(ValidatedSelector {
        kind,
        all: raw.all,
        values,
        expressions,
    })
}

fn validate_selector_expressions(
    expressions: Option<Vec<CompactString>>,
) -> Result<Vec<SelectorExpression>, TrustGrantError> {
    let expressions = expressions.unwrap_or_default();
    ensure_collection_limit(
        "selector.expression",
        expressions.len(),
        MAX_SELECTOR_EXPRESSIONS_PER_SELECTOR,
    )?;

    expressions
        .into_iter()
        .map(|expression| {
            let expression = normalize_non_empty_string(
                "selector.expression",
                &expression,
                Some(MAX_SELECTOR_EXPRESSION_BYTES),
            )?;
            SelectorExpression::parse(&expression)
        })
        .collect()
}

fn validate_operation_scope(
    raw: RawOperationScope,
) -> Result<ValidatedOperationScope, TrustGrantError> {
    let allow = normalize_non_empty_operation_names(raw.allow)?;
    let deny = normalize_non_empty_operation_names(raw.deny)?;

    ValidatedOperationScope::new(allow, deny)
}

fn ensure_no_duplicate_operations(operations: &[OperationName]) -> Result<(), TrustGrantError> {
    let mut seen = HashSet::with_capacity(operations.len());

    for operation in operations {
        if !seen.insert(operation.as_str()) {
            return Err(TrustGrantError::DuplicateOperationName);
        }
    }

    Ok(())
}

fn normalize_non_empty_string(
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

fn normalize_non_empty_strings(
    values: Option<Vec<CompactString>>,
) -> Result<Vec<String>, TrustGrantError> {
    let values = values.unwrap_or_default();
    ensure_collection_limit(
        "selector.values",
        values.len(),
        MAX_SELECTOR_VALUES_PER_SELECTOR,
    )?;

    let normalized: Vec<String> = values
        .into_iter()
        .map(|value| {
            normalize_non_empty_string("selector.value", &value, Some(MAX_SELECTOR_VALUE_BYTES))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut seen = std::collections::BTreeSet::new();
    Ok(normalized
        .into_iter()
        .filter(|v| seen.insert(v.clone()))
        .collect())
}

fn normalize_non_empty_operation_names(
    values: Option<Vec<CompactString>>,
) -> Result<Vec<OperationName>, TrustGrantError> {
    let values = values.unwrap_or_default();
    ensure_collection_limit("operations", values.len(), MAX_OPERATIONS_PER_SCOPE)?;

    values.into_iter().map(OperationName::new).collect()
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use std::collections::BTreeMap;

    use super::{ValidatedOperationScope, ValidatedSelector, ValidatedTrustGrantDocument};
    use crate::raw::{
        RawAudienceEntry, RawGlobalConstraints, RawMintingConstraints, RawOperationScope,
        RawResourceScope, RawResourceType, RawRevocation, RawScope, RawSelector,
        RawTrustGrantDocument, RawTypeCapabilities, RawTypeConstraints,
    };
    use trustgrant_domain::{OperationName, SelectorKind, Utf16Key};
    use trustgrant_error::TrustGrantError;
    use trustgrant_error::limits::{
        MAX_AUDIENCE_ENTRIES, MAX_OPERATIONS_PER_SCOPE, MAX_RESOURCE_TYPES,
        MAX_SELECTOR_EXPRESSION_BYTES, MAX_SELECTOR_EXPRESSIONS_PER_SELECTOR,
        MAX_SELECTOR_VALUES_PER_SELECTOR, MAX_SELECTORS_PER_SCOPE,
    };

    fn parse_valid_raw_document() -> RawTrustGrantDocument {
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
          "default_audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":null}],
          "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":10,"max_per_user":1},"audience_scope":null},"operations":{"allow":["recognize"],"deny":null}}}},
          "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
          "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
          "issued_at":"2026-04-07T12:00:00Z",
          "signature":"base64-signature",
          "issuer_principal":{"kind":"service","id":"issuer-worker"}
        }"#;

        match RawTrustGrantDocument::parse_json_str(json) {
            Ok(document) => document,
            Err(error) => panic!("raw document should parse: {error}"),
        }
    }

    #[test]
    fn validated_document_keeps_lineage_and_ownership() {
        let raw = parse_valid_raw_document();
        let validated = match ValidatedTrustGrantDocument::try_from(raw) {
            Ok(document) => document,
            Err(error) => panic!("validated document should succeed: {error}"),
        };

        assert_eq!(
            validated.lineage().trustgrant_id().to_string(),
            "tg_123e4567-e89b-12d3-a456-426614174000"
        );
        assert_eq!(
            validated
                .ownership_authority_state()
                .origin_authority()
                .as_str(),
            "https://issuer.example.com"
        );
        assert_eq!(validated.target_scope().allow().len(), 1);
        assert_eq!(validated.resource_scope().len(), 1);
        assert!(validated.capabilities().recognize());
        assert!(!validated.capabilities().mint());
    }

    #[test]
    fn validated_document_rejects_self_supersession() {
        let mut raw = parse_valid_raw_document();
        raw.revision = 2;
        raw.supersedes = Some(raw.trustgrant_id.clone());

        let validated = ValidatedTrustGrantDocument::try_from(raw);

        assert!(validated.is_err());
    }

    #[test]
    fn validated_document_rejects_first_revision_supersedes() {
        let mut raw = parse_valid_raw_document();
        raw.supersedes = Some("tg_123e4567-e89b-12d3-a456-426614174099".into());

        let validated = ValidatedTrustGrantDocument::try_from(raw);

        assert!(validated.is_err());
    }

    #[test]
    fn validated_document_rejects_duplicate_selectors() {
        let mut raw = parse_valid_raw_document();
        let selector = raw.target_scope.allow.clone().unwrap_or_default().pop();
        if let Some(selector) = selector {
            raw.target_scope.allow = Some(vec![selector.clone(), selector]);
        }

        let validated = ValidatedTrustGrantDocument::try_from(raw);

        assert!(validated.is_err());
    }

    #[test]
    fn validated_document_rejects_inverted_time_window() {
        let mut raw = parse_valid_raw_document();
        if let Some(global_constraints) = raw.global_constraints.as_mut()
            && let Some(time) = global_constraints.time.as_mut()
        {
            std::mem::swap(&mut time.not_before, &mut time.not_after);
        }

        let validated = ValidatedTrustGrantDocument::try_from(raw);

        assert!(validated.is_err());
    }

    #[test]
    fn validated_document_rejects_unsupported_selector_expression() {
        let mut raw = parse_valid_raw_document();
        if let Some(selector) = raw
            .target_scope
            .allow
            .as_mut()
            .and_then(|selectors| selectors.first_mut())
        {
            selector.values = None;
            selector.expressions = Some(vec![r#"regex("^target")"#.into()]);
        }

        let validated = ValidatedTrustGrantDocument::try_from(raw);

        assert_eq!(
            validated,
            Err(TrustGrantError::UnsupportedSelectorExpressionPredicate(
                "regex".to_owned(),
            ))
        );
    }

    #[test]
    fn validated_document_rejects_too_many_selector_values() {
        let mut raw = parse_valid_raw_document();
        if let Some(selector) = raw
            .target_scope
            .allow
            .as_mut()
            .and_then(|selectors| selectors.first_mut())
        {
            selector.values = Some(
                (0..=MAX_SELECTOR_VALUES_PER_SELECTOR)
                    .map(|index| format!("value_{index}").into())
                    .collect(),
            );
        }

        let validated = ValidatedTrustGrantDocument::try_from(raw);

        assert_eq!(
            validated,
            Err(TrustGrantError::CollectionTooLarge {
                field: "selector.values",
                max_items: MAX_SELECTOR_VALUES_PER_SELECTOR,
            })
        );
    }

    #[test]
    fn validated_document_rejects_too_many_selector_expressions() {
        let mut raw = parse_valid_raw_document();
        if let Some(selector) = raw
            .target_scope
            .allow
            .as_mut()
            .and_then(|selectors| selectors.first_mut())
        {
            selector.values = None;
            selector.expressions = Some(
                (0..=MAX_SELECTOR_EXPRESSIONS_PER_SELECTOR)
                    .map(|index| format!(r#"contains("value_{index}")"#).into())
                    .collect(),
            );
        }

        let validated = ValidatedTrustGrantDocument::try_from(raw);

        assert_eq!(
            validated,
            Err(TrustGrantError::CollectionTooLarge {
                field: "selector.expression",
                max_items: MAX_SELECTOR_EXPRESSIONS_PER_SELECTOR,
            })
        );
    }

    #[test]
    fn validated_document_rejects_overlong_selector_expression() {
        let mut raw = parse_valid_raw_document();
        if let Some(selector) = raw
            .target_scope
            .allow
            .as_mut()
            .and_then(|selectors| selectors.first_mut())
        {
            selector.values = None;
            selector.expressions = Some(vec![
                format!(
                    r#"contains("{}")"#,
                    "a".repeat(MAX_SELECTOR_EXPRESSION_BYTES)
                )
                .into(),
            ]);
        }

        let validated = ValidatedTrustGrantDocument::try_from(raw);

        assert_eq!(
            validated,
            Err(TrustGrantError::StringTooLong {
                field: "selector.expression",
                max_bytes: MAX_SELECTOR_EXPRESSION_BYTES,
            })
        );
    }

    // ── MAX_AUDIENCE_ENTRIES ──────────────────────────────────────────

    #[test]
    fn validated_document_accepts_at_max_audience_entries() {
        let mut raw = parse_valid_raw_document();
        let entries: Vec<_> = (0..MAX_AUDIENCE_ENTRIES)
            .map(|i| {
                RawAudienceEntry::new(
                    format!("https://audience{}.example.com", i),
                    RawScope::all(),
                    None,
                )
            })
            .collect();
        raw.default_audience_scope = Some(entries);

        let validated = ValidatedTrustGrantDocument::try_from(raw);

        assert!(
            validated.is_ok(),
            "expected Ok at MAX_AUDIENCE_ENTRIES boundary, got {validated:?}"
        );
    }

    #[test]
    fn validated_document_rejects_too_many_audience_entries() {
        let mut raw = parse_valid_raw_document();
        let entries: Vec<_> = (0..=MAX_AUDIENCE_ENTRIES)
            .map(|i| {
                RawAudienceEntry::new(
                    format!("https://audience{}.example.com", i),
                    RawScope::all(),
                    None,
                )
            })
            .collect();
        raw.default_audience_scope = Some(entries);

        let validated = ValidatedTrustGrantDocument::try_from(raw);

        assert_eq!(
            validated,
            Err(TrustGrantError::CollectionTooLarge {
                field: "default_audience_scope",
                max_items: MAX_AUDIENCE_ENTRIES,
            })
        );
    }

    // ── MAX_RESOURCE_TYPES ────────────────────────────────────────────

    #[test]
    fn validated_document_accepts_at_max_resource_types() {
        let mut raw = parse_valid_raw_document();
        let mut types = BTreeMap::new();
        for i in 0..MAX_RESOURCE_TYPES {
            types.insert(
                Utf16Key::new(format!("type_{}", i)),
                RawResourceType::new(
                    true,
                    None,
                    None,
                    RawTypeCapabilities::new(None, None),
                    RawTypeConstraints::new(RawMintingConstraints::new(None, None), None),
                    None,
                ),
            );
        }
        raw.resource_scope = RawResourceScope::new(types);

        let validated = ValidatedTrustGrantDocument::try_from(raw);

        assert!(
            validated.is_ok(),
            "expected Ok at MAX_RESOURCE_TYPES boundary, got {validated:?}"
        );
    }

    #[test]
    fn validated_document_rejects_too_many_resource_types() {
        let mut raw = parse_valid_raw_document();
        let mut types = BTreeMap::new();
        for i in 0..=MAX_RESOURCE_TYPES {
            types.insert(
                Utf16Key::new(format!("type_{}", i)),
                RawResourceType::new(
                    true,
                    None,
                    None,
                    RawTypeCapabilities::new(None, None),
                    RawTypeConstraints::new(RawMintingConstraints::new(None, None), None),
                    None,
                ),
            );
        }
        raw.resource_scope = RawResourceScope::new(types);

        let validated = ValidatedTrustGrantDocument::try_from(raw);

        assert_eq!(
            validated,
            Err(TrustGrantError::CollectionTooLarge {
                field: "resource_scope.types",
                max_items: MAX_RESOURCE_TYPES,
            })
        );
    }

    // ── MAX_SELECTORS_PER_SCOPE ───────────────────────────────────────

    #[test]
    fn validated_document_accepts_at_max_selectors_per_scope() {
        let mut raw = parse_valid_raw_document();
        let selectors: Vec<_> = (0..MAX_SELECTORS_PER_SCOPE)
            .map(|i| {
                RawSelector::values(
                    "authority",
                    vec![format!("https://target{}.example.com", i).into()],
                )
            })
            .collect();
        raw.target_scope.allow = Some(selectors);

        let validated = ValidatedTrustGrantDocument::try_from(raw);

        assert!(
            validated.is_ok(),
            "expected Ok at MAX_SELECTORS_PER_SCOPE boundary, got {validated:?}"
        );
    }

    #[test]
    fn validated_document_rejects_too_many_selectors_per_scope() {
        let mut raw = parse_valid_raw_document();
        let selectors: Vec<_> = (0..=MAX_SELECTORS_PER_SCOPE)
            .map(|i| {
                RawSelector::values(
                    "authority",
                    vec![format!("https://target{}.example.com", i).into()],
                )
            })
            .collect();
        raw.target_scope.allow = Some(selectors);

        let validated = ValidatedTrustGrantDocument::try_from(raw);

        assert_eq!(
            validated,
            Err(TrustGrantError::CollectionTooLarge {
                field: "scope.selectors",
                max_items: MAX_SELECTORS_PER_SCOPE,
            })
        );
    }

    // ── MAX_OPERATIONS_PER_SCOPE ──────────────────────────────────────

    #[test]
    fn validated_document_accepts_at_max_operations_per_scope() {
        let mut raw = parse_valid_raw_document();
        let operations: Vec<_> = (0..MAX_OPERATIONS_PER_SCOPE)
            .map(|i| format!("op_{}", i).into())
            .collect();
        if let Some(types) = raw.resource_scope.types.get_mut("item") {
            types.operations = Some(RawOperationScope::allow(operations));
        }

        let validated = ValidatedTrustGrantDocument::try_from(raw);

        assert!(
            validated.is_ok(),
            "expected Ok at MAX_OPERATIONS_PER_SCOPE boundary, got {validated:?}"
        );
    }

    #[test]
    fn validated_document_rejects_too_many_operations_per_scope() {
        let mut raw = parse_valid_raw_document();
        let operations: Vec<_> = (0..=MAX_OPERATIONS_PER_SCOPE)
            .map(|i| format!("op_{}", i).into())
            .collect();
        if let Some(types) = raw.resource_scope.types.get_mut("item") {
            types.operations = Some(RawOperationScope::allow(operations));
        }

        let validated = ValidatedTrustGrantDocument::try_from(raw);

        assert_eq!(
            validated,
            Err(TrustGrantError::CollectionTooLarge {
                field: "operations",
                max_items: MAX_OPERATIONS_PER_SCOPE,
            })
        );
    }

    // ── value deduplication ──────────────────────────────────────────

    #[test]
    fn normalized_selector_values_are_deduplicated_preserving_order() {
        let mut raw = parse_valid_raw_document();
        if let Some(selector) = raw
            .target_scope
            .allow
            .as_mut()
            .and_then(|selectors| selectors.first_mut())
        {
            selector.values = Some(vec!["a".into(), "a".into(), "b".into(), "a".into()]);
        }

        let validated = ValidatedTrustGrantDocument::try_from(raw).unwrap_or_else(|e| {
            panic!("document with duplicate selector values should be accepted: {e}")
        });

        let selector = validated
            .target_scope()
            .allow()
            .first()
            .unwrap_or_else(|| panic!("expected at least one selector"));
        assert_eq!(
            selector.values(),
            &["a", "b"],
            "first occurrences should be kept, order preserved"
        );
    }

    #[test]
    fn validated_document_accepts_non_revocable_grant_with_false_flag() {
        let mut raw = parse_valid_raw_document();
        raw.revocation = Some(RawRevocation::new(
            false,
            "https://issuer.example.com/revocation",
        ));

        let validated = ValidatedTrustGrantDocument::try_from(raw)
            .unwrap_or_else(|e| panic!("non-revocable grant should validate: {e}"));

        let revocation = validated
            .revocation()
            .unwrap_or_else(|| panic!("revocation should be present"));
        assert!(!revocation.revocable());
    }

    #[test]
    fn validated_document_accepts_grant_without_revocation_block() {
        let mut raw = parse_valid_raw_document();
        raw.revocation = None;

        let validated = ValidatedTrustGrantDocument::try_from(raw)
            .unwrap_or_else(|e| panic!("grant without revocation should validate: {e}"));

        assert!(validated.revocation().is_none());
    }

    #[test]
    fn validated_document_accepts_empty_default_audience_scope() {
        let mut raw = parse_valid_raw_document();
        raw.default_audience_scope = Some(vec![]);

        let validated = ValidatedTrustGrantDocument::try_from(raw)
            .unwrap_or_else(|e| panic!("empty audience scope should validate: {e}"));

        assert!(validated.default_audience_scope().is_empty());
    }

    // ── zero-length collection edge cases ───────────────────────────

    #[test]
    fn validated_document_rejects_empty_allow_with_all_false() {
        let mut raw = parse_valid_raw_document();
        raw.target_scope.all = false;
        raw.target_scope.allow = Some(vec![]);

        let validated = ValidatedTrustGrantDocument::try_from(raw);

        assert_eq!(
            validated,
            Err(TrustGrantError::InvalidScopeShape("target_scope"))
        );
    }

    #[test]
    fn validated_document_accepts_empty_deny_list() {
        let mut raw = parse_valid_raw_document();
        raw.target_scope.deny = Some(vec![]);

        let validated = ValidatedTrustGrantDocument::try_from(raw);

        assert!(
            validated.is_ok(),
            "empty deny list should be accepted, got {validated:?}"
        );
    }

    #[test]
    fn validated_document_accepts_zero_resource_types() {
        let mut raw = parse_valid_raw_document();
        raw.resource_scope = RawResourceScope::new(BTreeMap::new());

        let validated = ValidatedTrustGrantDocument::try_from(raw);

        assert!(
            validated.is_ok(),
            "zero-length resource types should be accepted, got {validated:?}"
        );
        let validated = validated.unwrap_or_else(|e| panic!("should be Ok: {e}"));
        assert!(validated.resource_scope().is_empty());
    }

    #[test]
    fn validated_document_rejects_duplicate_audience_authorities() {
        let mut raw = parse_valid_raw_document();
        let entries = raw
            .default_audience_scope
            .as_ref()
            .unwrap_or_else(|| panic!("fixture must have audience entries"));
        let entry = entries
            .first()
            .cloned()
            .unwrap_or_else(|| panic!("fixture must have audience entries"));
        raw.default_audience_scope = Some(vec![entry.clone(), entry]);

        let result = ValidatedTrustGrantDocument::try_from(raw);

        assert_eq!(result, Err(TrustGrantError::DuplicateAudienceAuthority));
    }

    // ── ValidatedSelector::new error branches ────────────────────────

    #[test]
    fn validated_selector_rejects_all_true_with_non_empty_values() {
        let kind = SelectorKind::new("authority")
            .unwrap_or_else(|e| panic!("authority selector kind should be valid: {e}"));
        let result =
            ValidatedSelector::new(kind, true, vec!["https://example.com".to_owned()], vec![]);
        assert_eq!(result, Err(TrustGrantError::InvalidSelectorShape));
    }

    #[test]
    fn validated_selector_rejects_all_false_with_no_values_or_expressions() {
        let kind = SelectorKind::new("authority")
            .unwrap_or_else(|e| panic!("authority selector kind should be valid: {e}"));
        let result = ValidatedSelector::new(kind, false, vec![], vec![]);
        assert_eq!(result, Err(TrustGrantError::InvalidSelectorShape));
    }

    // ── ValidatedOperationScope::new error branches ──────────────────

    #[test]
    fn validated_operation_scope_rejects_empty_allow() {
        let result = ValidatedOperationScope::new(vec![], vec![]);
        assert_eq!(
            result,
            Err(TrustGrantError::InvalidScopeShape("operations"))
        );
    }

    // ── validate_scope_shape with all=true and non-empty allow ───────

    #[test]
    fn validated_document_rejects_scope_with_all_true_and_non_empty_allow() {
        let mut raw = parse_valid_raw_document();
        raw.target_scope.all = true;
        // Keep the existing non-empty allow list to trigger the error
        let validated = ValidatedTrustGrantDocument::try_from(raw);
        assert_eq!(
            validated,
            Err(TrustGrantError::InvalidScopeShape("target_scope"))
        );
    }

    // ── validate_global_constraints with time=None ──────────────────

    #[test]
    fn validated_document_accepts_global_constraints_without_time() {
        let mut raw = parse_valid_raw_document();
        raw.global_constraints = Some(RawGlobalConstraints::new(None));
        let validated = ValidatedTrustGrantDocument::try_from(raw)
            .unwrap_or_else(|e| panic!("global constraints without time should validate: {e}"));
        assert!(validated.global_time_window().is_none());
    }

    // ── validate_selector error branches ────────────────────────────

    #[test]
    fn validated_document_rejects_selector_all_true_with_values() {
        let mut raw = parse_valid_raw_document();
        if let Some(selectors) = raw.target_scope.allow.as_mut()
            && let Some(selector) = selectors.first_mut()
        {
            selector.all = true;
            selector.values = Some(vec!["should-not-be-here".into()]);
        }
        let validated = ValidatedTrustGrantDocument::try_from(raw);
        assert_eq!(validated, Err(TrustGrantError::InvalidSelectorShape));
    }

    #[test]
    fn validated_document_rejects_selector_all_false_with_no_values_or_expressions() {
        let mut raw = parse_valid_raw_document();
        if let Some(selectors) = raw.target_scope.allow.as_mut()
            && let Some(selector) = selectors.first_mut()
        {
            selector.all = false;
            selector.values = None;
            selector.expressions = None;
        }
        let validated = ValidatedTrustGrantDocument::try_from(raw);
        assert_eq!(validated, Err(TrustGrantError::InvalidSelectorShape));
    }

    // ── ensure_no_duplicate_operations ──────────────────────────────

    #[test]
    fn validated_document_rejects_duplicate_operation_names() {
        let mut raw = parse_valid_raw_document();
        if let Some(types) = raw.resource_scope.types.get_mut("item") {
            types.operations = Some(RawOperationScope {
                allow: Some(vec!["custom:use".into(), "custom:use".into()]),
                deny: None,
            });
        }
        let validated = ValidatedTrustGrantDocument::try_from(raw);
        assert_eq!(validated, Err(TrustGrantError::DuplicateOperationName));
    }

    // ── normalize_non_empty_string with empty/whitespace string ─────

    #[test]
    fn validated_document_rejects_whitespace_signature() {
        let mut raw = parse_valid_raw_document();
        raw.signature = "   ".into();
        let validated = ValidatedTrustGrantDocument::try_from(raw);
        assert_eq!(
            validated,
            Err(TrustGrantError::EmptyStringField("signature"))
        );
    }
}
