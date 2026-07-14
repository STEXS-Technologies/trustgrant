use chrono::{DateTime, Utc};

use trustgrant_domain::{AuthorityId, CustomOperationName, ResourceTypeName, SelectorKind};
use trustgrant_error::TrustGrantError;
use trustgrant_error::limits::{
    MAX_REQUEST_SELECTOR_KINDS, MAX_REQUEST_SELECTOR_VALUE_BYTES, MAX_REQUEST_VALUES_PER_KIND,
    ensure_collection_limit, ensure_string_limit,
};

/// A built-in capability that can be requested during evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedCapability {
    /// The `recognize` capability — identify and validate resources.
    Recognize,
    /// The `mint` capability — create new grant instances.
    Mint,
}

/// The operation being requested during evaluation.
///
/// Can be a built-in capability or a custom application-defined operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestedOperation {
    /// A built-in capability operation (`Recognize` or `Mint`).
    Capability(RequestedCapability),
    /// An application-defined custom operation.
    Custom(CustomOperationName),
}

/// A collection of selector values indexed by selector kind.
///
/// Provides O(1) lookup for built-in selector kinds (authority, namespace,
/// actor) and linear fallback for user-defined kinds. Used to represent
/// target, audience, and audience-principal contexts during evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SelectorContext {
    entries: Vec<SelectorValues>,
    /// Fixed-size index mapping built-in selector kinds to entry positions.
    ///
    /// - Slot 0 → Authority
    /// - Slot 1 → Namespace
    /// - Slot 2 → Actor
    /// - Slot 3 → (unused; reserved for potential future built-in kinds)
    ///
    /// `None` means no entry has been inserted for that kind yet.
    /// User-defined ("Other") kinds are never cached here.
    kind_index: [Option<usize>; 4],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectorValues {
    kind: SelectorKind,
    values: Vec<String>,
}

impl SelectorContext {
    #[must_use = "new selector contexts should be populated before evaluation"]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one selector value under a selector kind.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the selector kind or value is empty.
    pub fn insert(
        &mut self,
        kind: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), TrustGrantError> {
        let kind = SelectorKind::new(kind.into())?;
        let value = value.into();
        let value = normalize_context_value("selector_context.value", &value)?;

        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.kind.same_kind(&kind))
        {
            if !entry.values.iter().any(|existing| existing == &value) {
                ensure_collection_limit(
                    "request.selector_values",
                    entry.values.len().saturating_add(1),
                    MAX_REQUEST_VALUES_PER_KIND,
                )?;
                entry.values.push(value);
            }
            return Ok(());
        }

        ensure_collection_limit(
            "request.selector_kinds",
            self.entries.len().saturating_add(1),
            MAX_REQUEST_SELECTOR_KINDS,
        )?;
        let kind_index_slot = kind_index_for_selector_kind(&kind);
        self.entries.push(SelectorValues {
            kind,
            values: vec![value],
        });

        // Populate the O(1) index for built-in kinds.
        if let Some(idx) = kind_index_slot
            && let Some(entry_idx) = self.entries.len().checked_sub(1)
            && let Some(slot) = self.kind_index.get_mut(idx)
        {
            *slot = Some(entry_idx);
        }

        Ok(())
    }

    #[must_use = "evaluation needs to inspect values by selector kind"]
    pub fn values_for_kind(&self, kind: &SelectorKind) -> Option<&[String]> {
        if let Some(idx) = kind_index_for_selector_kind(kind)
            && let Some(Some(entry_idx)) = self.kind_index.get(idx)
            && let Some(entry) = self.entries.get(*entry_idx)
        {
            return Some(&entry.values);
        }
        // Fall back to linear scan for Other kinds or missing built-in entries.
        self.entries
            .iter()
            .find(|entry| entry.kind.same_kind(kind))
            .map(|entry| entry.values.as_slice())
    }

    #[must_use = "tests and adapters may need borrowed selector-kind access"]
    pub fn values_for_kind_str(&self, kind: &str) -> Option<&[String]> {
        self.entries
            .iter()
            .find(|entry| entry.kind.as_str() == kind)
            .map(|entry| entry.values.as_slice())
    }

    #[must_use = "evaluation may need to know whether any selector values were provided"]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn stable_key(&self) -> String {
        let mut entries: Vec<(&str, Vec<&str>)> = self
            .entries
            .iter()
            .map(|entry| {
                let mut values: Vec<&str> = entry.values.iter().map(String::as_str).collect();
                values.sort_unstable();
                (entry.kind.as_str(), values)
            })
            .collect();
        entries.sort_unstable_by(|left, right| left.0.cmp(right.0));

        entries
            .into_iter()
            .fold(String::new(), |mut key, (kind, values)| {
                key.push_str(&kind.len().to_string());
                key.push(':');
                key.push_str(kind);
                values.into_iter().for_each(|value| {
                    key.push('|');
                    key.push_str(&value.len().to_string());
                    key.push(':');
                    key.push_str(value);
                });
                key.push(';');
                key
            })
    }
}

/// An immutable reference to an existing resource.
///
/// Carries the origin authority that created or owns the resource, the
/// resource's unique identifier within that authority's namespace, and an
/// optional expected version for stale-state detection. Used in
/// [`ResourceBinding::Existing`] to bind an evaluation request to a specific
/// resource instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRef {
    origin_authority: AuthorityId,
    resource_type: Option<ResourceTypeName>,
    resource_id: String,
    expected_version: Option<u64>,
}

impl ResourceRef {
    /// Creates a new resource reference.
    #[must_use = "resource references are required for evaluation"]
    pub const fn new(origin_authority: AuthorityId, resource_id: String) -> Self {
        Self {
            origin_authority,
            resource_type: None,
            resource_id,
            expected_version: None,
        }
    }

    /// Creates a canonical resource reference for an execution request.
    ///
    /// The resource type is part of canonical identity. State-changing
    /// requests must use this constructor (or otherwise supply the same
    /// type binding) so an identifier cannot be confused across types.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] if the resource type or identifier is invalid.
    pub fn new_typed(
        origin_authority: AuthorityId,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Result<Self, TrustGrantError> {
        let resource_type = ResourceTypeName::new(resource_type.into())?;
        let resource_id = normalize_context_value("resource_ref.resource_id", &resource_id.into())?;

        Ok(Self {
            origin_authority,
            resource_type: Some(resource_type),
            resource_id,
            expected_version: None,
        })
    }

    /// The authority that originated the resource.
    #[must_use = "origin authority is required for spec §13 step 3 enforcement"]
    pub const fn origin_authority(&self) -> &AuthorityId {
        &self.origin_authority
    }

    /// The resource's unique identifier within the origin authority's namespace.
    #[must_use = "resource ID identifies the specific resource instance"]
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    /// The resource type bound into this reference, when one was supplied.
    #[must_use = "resource type is part of canonical resource identity"]
    pub const fn resource_type(&self) -> Option<&ResourceTypeName> {
        self.resource_type.as_ref()
    }

    /// The expected version of the resource, if known.
    ///
    /// When set, the execution layer MUST verify that the current resource
    /// version matches this value before applying any mutation. This enables
    /// stale-state detection in concurrent environments.
    #[must_use = "expected version is used for stale-state detection"]
    pub const fn expected_version(&self) -> Option<u64> {
        self.expected_version
    }

    /// Sets the expected resource version for stale-state detection.
    #[must_use = "builder should be consumed"]
    pub const fn with_expected_version(mut self, version: u64) -> Self {
        self.expected_version = Some(version);
        self
    }
}

/// A reference to a mint template or resource class for mint operations.
///
/// Carries the origin authority and resource class information. Used in
/// [`ResourceBinding::Mint`] when the request is for minting new resources
/// rather than acting on an existing one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateRef {
    origin_authority: AuthorityId,
    template_id: Option<String>,
}

impl TemplateRef {
    /// Creates a new template reference for mint operations.
    #[must_use = "template references are required for mint evaluation"]
    pub const fn new(origin_authority: AuthorityId) -> Self {
        Self {
            origin_authority,
            template_id: None,
        }
    }

    /// Creates a mint-template reference bound to one issuer-defined template.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] if the template identifier is invalid.
    pub fn new_typed(
        origin_authority: AuthorityId,
        template_id: impl Into<String>,
    ) -> Result<Self, TrustGrantError> {
        let template_id = normalize_context_value("template_ref.template_id", &template_id.into())?;

        Ok(Self {
            origin_authority,
            template_id: Some(template_id),
        })
    }

    /// The authority that defines the mint template or resource class.
    #[must_use = "origin authority is required for spec §13 step 3 enforcement"]
    pub const fn origin_authority(&self) -> &AuthorityId {
        &self.origin_authority
    }

    /// The issuer-defined template identifier, when the reference is typed.
    #[must_use = "template identifier binds a mint to its authorized class"]
    pub fn template_id(&self) -> Option<&str> {
        self.template_id.as_deref()
    }
}

/// The binding between an evaluation request and the resource being acted upon.
///
/// Distinguishes requests that target an existing resource (with a known
/// [`ResourceRef`]) from requests that create new resources via minting
/// (with a [`TemplateRef`]).
///
/// The binding provides the `origin_authority` used in spec §13 step 3 to
/// verify that the grant's origin matches the resource's origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceBinding {
    /// The request acts on an existing resource identified by a [`ResourceRef`].
    Existing(ResourceRef),
    /// The request creates new resources via minting, referencing a [`TemplateRef`].
    Mint(TemplateRef),
}

impl ResourceBinding {
    /// Returns the origin authority from whichever binding variant is active.
    #[must_use = "origin authority is required for spec §13 step 3 enforcement"]
    pub const fn origin_authority(&self) -> &AuthorityId {
        match self {
            Self::Existing(ref_) => ref_.origin_authority(),
            Self::Mint(template) => template.origin_authority(),
        }
    }

    /// Whether this binding is a mint request.
    #[must_use = "mint vs existing-resource semantics differ during evaluation"]
    pub const fn is_mint(&self) -> bool {
        matches!(self, Self::Mint(_))
    }
}

/// Runtime mint counters used to enforce minting constraints.
///
/// Provides the current total mint count and per-audience mint count to the
/// evaluation engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintContext {
    current_total_mints: u64,
    current_mints_for_audience: u64,
}

impl MintContext {
    #[must_use = "mint context should be provided for mint-constraint evaluation"]
    pub const fn new(current_total_mints: u64, current_mints_for_audience: u64) -> Self {
        Self {
            current_total_mints,
            current_mints_for_audience,
        }
    }

    #[must_use = "total minted count is required for max_total checks"]
    pub const fn current_total_mints(&self) -> u64 {
        self.current_total_mints
    }

    #[must_use = "audience minted count is required for max_per_user checks"]
    pub const fn current_mints_for_audience(&self) -> u64 {
        self.current_mints_for_audience
    }
}

/// Describes the resource being acted upon during evaluation.
///
/// Carries the resource type name and a set of selector values that
/// identify the specific resource instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceContext {
    resource_type: ResourceTypeName,
    selectors: SelectorContext,
}

impl ResourceContext {
    /// Creates one resource evaluation context.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the resource type is empty.
    pub fn new(resource_type: impl Into<String>) -> Result<Self, TrustGrantError> {
        Ok(Self {
            resource_type: ResourceTypeName::new(resource_type)?,
            selectors: SelectorContext::new(),
        })
    }

    /// Adds one resource selector value.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the selector kind or value is empty.
    pub fn insert_selector(
        &mut self,
        kind: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), TrustGrantError> {
        self.selectors.insert(kind, value)
    }

    #[must_use = "resource type is required for evaluation"]
    pub const fn resource_type(&self) -> &ResourceTypeName {
        &self.resource_type
    }

    #[must_use = "resource selectors are required for evaluation"]
    pub const fn selectors(&self) -> &SelectorContext {
        &self.selectors
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationRequest {
    operation: RequestedOperation,
    resource_binding: ResourceBinding,
    intent_id: Option<IntentId>,
    target_authority: AuthorityId,
    target_context: SelectorContext,
    audience_authority: AuthorityId,
    audience_context: SelectorContext,
    audience_principal_context: SelectorContext,
    resource: ResourceContext,
    mint_context: Option<MintContext>,
    evaluated_at: DateTime<Utc>,
}

impl EvaluationRequest {
    /// Creates one evaluation request with canonical authority selector entries.
    ///
    /// The `resource_binding` parameter carries the origin authority and
    /// distinguishes existing-resource requests from mint requests. The engine
    /// always checks that the binding's origin authority matches the grant's
    /// origin authority (spec §13 step 3).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use trustgrant_evaluate::{
    ///     EvaluationRequest, RequestedCapability, RequestedOperation,
    ///     ResourceBinding, ResourceRef, ResourceContext,
    /// };
    /// use trustgrant_domain::AuthorityId;
    /// use chrono::Utc;
    ///
    /// let origin = AuthorityId::new("https://issuer.example.com").unwrap();
    /// let resource = ResourceContext::new("item")
    ///     .expect("valid resource type");
    /// let request = EvaluationRequest::new(
    ///     RequestedOperation::Capability(RequestedCapability::Recognize),
    ///     ResourceBinding::Existing(ResourceRef::new(
    ///         origin,
    ///         "resource-42".to_owned(),
    ///     )),
    ///     AuthorityId::new("https://target.example.com").unwrap(),
    ///     AuthorityId::new("https://audience.example.com").unwrap(),
    ///     resource,
    ///     Utc::now(),
    /// ).expect("valid evaluation request");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when resource or selector inputs are invalid.
    pub fn new(
        operation: RequestedOperation,
        resource_binding: ResourceBinding,
        target_authority: AuthorityId,
        audience_authority: AuthorityId,
        resource: ResourceContext,
        evaluated_at: DateTime<Utc>,
    ) -> Result<Self, TrustGrantError> {
        let mut target_context = SelectorContext::new();
        target_context.insert("authority", target_authority.as_str())?;
        target_context.insert("authority_id", target_authority.as_str())?;

        let mut audience_context = SelectorContext::new();
        audience_context.insert("authority", audience_authority.as_str())?;
        audience_context.insert("authority_id", audience_authority.as_str())?;

        Ok(Self {
            operation,
            resource_binding,
            intent_id: None,
            target_authority,
            target_context,
            audience_authority,
            audience_context,
            audience_principal_context: SelectorContext::new(),
            resource,
            mint_context: None,
            evaluated_at,
        })
    }

    /// Adds one target-scope selector.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the selector kind or value is empty.
    pub fn insert_target_selector(
        &mut self,
        kind: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), TrustGrantError> {
        self.target_context.insert(kind, value)
    }

    /// Adds one audience-scope selector.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the selector kind or value is empty.
    pub fn insert_audience_selector(
        &mut self,
        kind: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), TrustGrantError> {
        self.audience_context.insert(kind, value)
    }

    /// Adds one audience principal selector.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the selector kind or value is empty.
    pub fn insert_audience_principal_selector(
        &mut self,
        kind: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), TrustGrantError> {
        self.audience_principal_context.insert(kind, value)
    }

    #[must_use = "mint evaluation may require explicit runtime mint counters"]
    pub const fn with_mint_context(mut self, mint_context: MintContext) -> Self {
        self.mint_context = Some(mint_context);
        self
    }

    /// Sets a validated intent ID for this request.
    ///
    /// An intent ID uniquely identifies an authorization attempt. When set, the
    /// evaluation outcome is bound to this ID, enabling the execution layer to
    /// detect and reject duplicate or replayed authorization attempts.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] if the identifier is empty or exceeds the
    /// request-value size limit.
    #[must_use = "intent ID should be set for idempotent authorization"]
    pub fn with_intent_id(mut self, intent_id: impl Into<String>) -> Result<Self, TrustGrantError> {
        self.intent_id = Some(IntentId::new(intent_id.into())?);
        Ok(self)
    }

    #[must_use = "requested operation is required for evaluation"]
    pub const fn operation(&self) -> &RequestedOperation {
        &self.operation
    }

    /// The resource binding for this request, carrying the origin authority
    /// and distinguishing existing-resource requests from mint requests.
    #[must_use = "resource binding is required for evaluation and spec §13 step 3"]
    pub const fn resource_binding(&self) -> &ResourceBinding {
        &self.resource_binding
    }

    /// The intent ID for this request, if set.
    ///
    /// Binds the evaluation outcome to a specific authorization attempt.
    #[must_use = "intent ID is required for idempotent authorization"]
    pub const fn intent_id(&self) -> Option<&IntentId> {
        self.intent_id.as_ref()
    }

    /// The origin authority bound to this request (convenience accessor).
    ///
    /// Delegates to [`ResourceBinding::origin_authority`].
    #[must_use = "origin authority is required for spec §13 step 3 enforcement"]
    pub const fn origin_authority(&self) -> &AuthorityId {
        self.resource_binding.origin_authority()
    }

    #[must_use = "target authority is required for evaluation and audit"]
    pub const fn target_authority(&self) -> &AuthorityId {
        &self.target_authority
    }

    #[must_use = "target selectors are required for evaluation"]
    pub const fn target_context(&self) -> &SelectorContext {
        &self.target_context
    }

    #[must_use = "audience authority is required for evaluation"]
    pub const fn audience_authority(&self) -> &AuthorityId {
        &self.audience_authority
    }

    #[must_use = "audience selectors are required for evaluation"]
    pub const fn audience_context(&self) -> &SelectorContext {
        &self.audience_context
    }

    #[must_use = "audience principal selectors are required for evaluation"]
    pub const fn audience_principal_context(&self) -> &SelectorContext {
        &self.audience_principal_context
    }

    #[must_use = "resource context is required for evaluation"]
    pub const fn resource(&self) -> &ResourceContext {
        &self.resource
    }

    #[must_use = "mint context is required for mint-constraint evaluation"]
    pub const fn mint_context(&self) -> Option<MintContext> {
        self.mint_context
    }

    #[must_use = "evaluation time is required for time-window checks"]
    pub const fn evaluated_at(&self) -> DateTime<Utc> {
        self.evaluated_at
    }

    pub(crate) fn same_mutation_intent(&self, other: &Self) -> bool {
        self.operation == other.operation
            && self.resource_binding == other.resource_binding
            && self.target_authority == other.target_authority
            && self.target_context == other.target_context
            && self.audience_authority == other.audience_authority
            && self.audience_context == other.audience_context
            && self.audience_principal_context == other.audience_principal_context
            && self.resource == other.resource
    }
}

/// A validated, bounded identifier for one state-changing execution intent.
///
/// The ID is scoped by the execution adapter's idempotency store and must be
/// paired with the full request binding. Reusing it for a different request is
/// an intent conflict, not a successful retry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IntentId(String);

impl IntentId {
    /// Creates one validated intent ID.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the identifier is empty or too large.
    pub fn new(value: impl Into<String>) -> Result<Self, TrustGrantError> {
        Ok(Self(normalize_context_value("intent_id", &value.into())?))
    }

    #[must_use = "intent IDs are used for idempotency lookup"]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for IntentId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Maps a built-in [`SelectorKind`] to its fixed index within
/// [`SelectorContext::kind_index`].  Returns `None` for user-defined kinds.
const fn kind_index_for_selector_kind(kind: &SelectorKind) -> Option<usize> {
    kind.kind_index()
}

fn normalize_context_value(
    field_name: &'static str,
    value: &str,
) -> Result<String, TrustGrantError> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(TrustGrantError::EmptyStringField(field_name));
    }

    ensure_string_limit(field_name, trimmed, MAX_REQUEST_SELECTOR_VALUE_BYTES)?;

    Ok(trimmed.to_owned())
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::{
        EvaluationRequest, IntentId, RequestedCapability, RequestedOperation, ResourceBinding,
        ResourceContext, ResourceRef, SelectorContext,
    };
    use trustgrant_domain::AuthorityId;
    use trustgrant_error::TrustGrantError;
    use trustgrant_error::limits::{
        MAX_REQUEST_SELECTOR_KINDS, MAX_REQUEST_SELECTOR_VALUE_BYTES, MAX_REQUEST_VALUES_PER_KIND,
    };

    #[test]
    fn selector_context_rejects_too_many_selector_kinds() {
        let mut context = SelectorContext::new();

        for index in 0..MAX_REQUEST_SELECTOR_KINDS {
            context
                .insert(format!("kind_{index}"), "value")
                .unwrap_or_else(|error| panic!("selector kind should fit: {error}"));
        }

        let result = context.insert("kind_overflow", "value");

        assert_eq!(
            result,
            Err(TrustGrantError::CollectionTooLarge {
                field: "request.selector_kinds",
                max_items: MAX_REQUEST_SELECTOR_KINDS,
            })
        );
    }

    #[test]
    fn selector_context_rejects_too_many_values_per_kind() {
        let mut context = SelectorContext::new();

        for index in 0..MAX_REQUEST_VALUES_PER_KIND {
            context
                .insert("namespace", format!("value_{index}"))
                .unwrap_or_else(|error| panic!("selector value should fit: {error}"));
        }

        let result = context.insert("namespace", "value_overflow");

        assert_eq!(
            result,
            Err(TrustGrantError::CollectionTooLarge {
                field: "request.selector_values",
                max_items: MAX_REQUEST_VALUES_PER_KIND,
            })
        );
    }

    #[test]
    fn selector_context_rejects_overlong_value() {
        let mut context = SelectorContext::new();
        let result = context.insert(
            "namespace",
            "a".repeat(MAX_REQUEST_SELECTOR_VALUE_BYTES + 1),
        );

        assert_eq!(
            result,
            Err(TrustGrantError::StringTooLong {
                field: "selector_context.value",
                max_bytes: MAX_REQUEST_SELECTOR_VALUE_BYTES,
            })
        );
    }

    #[test]
    fn evaluation_request_populates_both_authority_selector_aliases() {
        let resource = ResourceContext::new("item")
            .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
        let origin = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"));
        let request = EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Recognize),
            ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
            AuthorityId::new("https://target.example.com")
                .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
            AuthorityId::new("https://audience.example.com")
                .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
            resource,
            fixed_timestamp(2026, 4, 8, 12, 0, 0),
        )
        .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));

        assert_eq!(
            request
                .target_context()
                .values_for_kind_str("authority")
                .and_then(|values| values.first())
                .map(String::as_str),
            Some("https://target.example.com")
        );
        assert_eq!(
            request
                .target_context()
                .values_for_kind_str("authority_id")
                .and_then(|values| values.first())
                .map(String::as_str),
            Some("https://target.example.com")
        );
        assert_eq!(
            request
                .audience_context()
                .values_for_kind_str("authority")
                .and_then(|values| values.first())
                .map(String::as_str),
            Some("https://audience.example.com")
        );
        assert_eq!(
            request
                .audience_context()
                .values_for_kind_str("authority_id")
                .and_then(|values| values.first())
                .map(String::as_str),
            Some("https://audience.example.com")
        );
    }

    #[test]
    fn selector_context_is_empty_when_no_entries() {
        let mut context = SelectorContext::new();
        assert!(context.is_empty());
        context
            .insert("test_kind", "test_value")
            .unwrap_or_else(|e| panic!("insert should succeed: {e}"));
        assert!(!context.is_empty());
    }

    #[test]
    fn evaluation_request_insert_target_selector() {
        let resource = ResourceContext::new("item")
            .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
        let origin = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"));
        let mut request = EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Recognize),
            ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
            AuthorityId::new("https://target.example.com")
                .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
            AuthorityId::new("https://audience.example.com")
                .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
            resource,
            fixed_timestamp(2026, 4, 8, 12, 0, 0),
        )
        .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));

        assert!(
            request
                .insert_target_selector("namespace", "weapons")
                .is_ok()
        );
        assert_eq!(
            request
                .target_context()
                .values_for_kind_str("namespace")
                .and_then(|values| values.first())
                .map(String::as_str),
            Some("weapons")
        );
    }

    #[test]
    fn selector_context_dedup_same_kind_by_values() {
        let mut context = SelectorContext::new();
        context
            .insert("namespace", "value1")
            .unwrap_or_else(|e| panic!("insert should succeed: {e}"));
        // Same kind → hits the find() dedup path (line 64).
        context
            .insert("namespace", "value2")
            .unwrap_or_else(|e| panic!("insert should succeed: {e}"));

        let values = context
            .values_for_kind_str("namespace")
            .unwrap_or_else(|| panic!("values should be present for kind"));
        assert_eq!(values.len(), 2);
        assert!(values.contains(&"value1".to_owned()));
        assert!(values.contains(&"value2".to_owned()));
    }

    #[test]
    fn selector_context_rejects_whitespace_only_value() {
        let mut context = SelectorContext::new();
        let result = context.insert("namespace", "   ");

        assert_eq!(
            result,
            Err(TrustGrantError::EmptyStringField("selector_context.value"))
        );
    }

    #[test]
    fn evaluation_request_insert_audience_selector() {
        let resource = ResourceContext::new("item")
            .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
        let origin = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"));
        let mut request = EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Recognize),
            ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
            AuthorityId::new("https://target.example.com")
                .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
            AuthorityId::new("https://audience.example.com")
                .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
            resource,
            fixed_timestamp(2026, 4, 8, 12, 0, 0),
        )
        .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));

        assert!(
            request
                .insert_audience_selector("actor", "player-42")
                .is_ok()
        );
        assert_eq!(
            request
                .audience_context()
                .values_for_kind_str("actor")
                .and_then(|values| values.first())
                .map(String::as_str),
            Some("player-42")
        );
    }

    #[test]
    fn intent_id_round_trips_through_request() {
        let origin = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("origin should be valid: {error}"));
        let resource = ResourceContext::new("item")
            .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
        let request = EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Recognize),
            ResourceBinding::Existing(ResourceRef::new(origin, "rsc-1".to_owned())),
            AuthorityId::new("https://target.example.com")
                .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
            AuthorityId::new("https://audience.example.com")
                .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
            resource,
            fixed_timestamp(2026, 4, 8, 12, 0, 0),
        )
        .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"))
        .with_intent_id("txn-001")
        .unwrap_or_else(|error| panic!("intent_id should be valid: {error}"));

        assert_eq!(request.intent_id().map(IntentId::as_str), Some("txn-001"));
    }

    #[test]
    fn intent_id_rejects_empty() {
        let result = IntentId::new("");
        assert_eq!(
            result,
            Err(TrustGrantError::EmptyStringField("intent_id"))
        );
    }

    #[test]
    fn resource_ref_expected_version_round_trips() {
        let origin = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("origin should be valid: {error}"));
        let ref_ = ResourceRef::new(origin.clone(), "rsc-1".to_owned())
            .with_expected_version(7);

        assert_eq!(ref_.expected_version(), Some(7));
        assert_eq!(ref_.origin_authority(), &origin);
        assert_eq!(ref_.resource_id(), "rsc-1");
    }

    #[test]
    fn resource_ref_expected_version_defaults_to_none() {
        let origin = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("origin should be valid: {error}"));
        let ref_ = ResourceRef::new(origin, "rsc-1".to_owned());

        assert_eq!(ref_.expected_version(), None);
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
