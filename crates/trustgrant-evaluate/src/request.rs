use chrono::{DateTime, Utc};

use trustgrant_domain::{AuthorityId, CustomOperationName, ResourceTypeName, SelectorKind};
use trustgrant_error::TrustGrantError;
use trustgrant_error::limits::{
    MAX_REQUEST_SELECTOR_KINDS, MAX_REQUEST_SELECTOR_VALUE_BYTES, MAX_REQUEST_VALUES_PER_KIND,
    ensure_collection_limit, ensure_string_limit,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedCapability {
    Recognize,
    Mint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestedOperation {
    Capability(RequestedCapability),
    Custom(CustomOperationName),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SelectorContext {
    entries: Vec<SelectorValues>,
    /// Fixed-size index mapping built-in selector kinds to entry positions.
    ///
    /// - Slot 0 → Authority
    /// - Slot 1 → Namespace
    /// - Slot 2 → PlayerId
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
}

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
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when resource or selector inputs are invalid.
    pub fn new(
        operation: RequestedOperation,
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

    #[must_use = "requested operation is required for evaluation"]
    pub const fn operation(&self) -> &RequestedOperation {
        &self.operation
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
        EvaluationRequest, RequestedCapability, RequestedOperation, ResourceContext,
        SelectorContext,
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
        let request = EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Recognize),
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
        let mut request = EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Recognize),
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
        let mut request = EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Recognize),
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
                .insert_audience_selector("player_id", "player-42")
                .is_ok()
        );
        assert_eq!(
            request
                .audience_context()
                .values_for_kind_str("player_id")
                .and_then(|values| values.first())
                .map(String::as_str),
            Some("player-42")
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
