use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use trustgrant_domain::Utf16Key;

use trustgrant_error::TrustGrantError;
use trustgrant_error::limits::{MAX_TRUSTGRANT_JSON_BYTES, ensure_json_size};

/// The raw, unvalidated wire representation of a TrustGrant document.
///
/// Fields map directly to JSON keys. Use [`RawTrustGrantDocument::parse_json_str`]
/// or [`RawTrustGrantDocument::parse_json_bytes`] to deserialize, then convert to
/// [`ValidatedTrustGrantDocument`] via `TryFrom`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTrustGrantDocument {
    pub trustgrant_id: CompactString,
    pub version: u8,
    pub grant_series_id: CompactString,
    pub revision: u64,
    pub supersedes: Option<CompactString>,
    pub supersession_policy: RawSupersessionPolicy,
    pub issuer_authority: CompactString,
    pub origin_authority: CompactString,
    pub active_owning_authority: CompactString,
    pub key_id: CompactString,
    pub target_scope: RawScope,
    pub capabilities: RawCapabilities,
    pub default_audience_scope: Option<Vec<RawAudienceEntry>>,
    pub resource_scope: RawResourceScope,
    pub global_constraints: Option<RawGlobalConstraints>,
    pub revocation: Option<RawRevocation>,
    pub issued_at: DateTime<Utc>,
    pub signature: CompactString,
    pub issuer_principal: Option<RawPrincipal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interoperability_profile: Option<InteroperabilityProfile>,
}

impl RawTrustGrantDocument {
    /// Parses a raw TrustGrant document from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the input exceeds the protocol size
    /// limit, is not valid JSON, or does not match the TrustGrant v0 wire
    /// shape.
    pub fn parse_json_bytes(bytes: &[u8]) -> Result<Self, TrustGrantError> {
        ensure_json_size("trustgrant", bytes.len(), MAX_TRUSTGRANT_JSON_BYTES)?;

        serde_json::from_slice(bytes).map_err(|_error| TrustGrantError::InvalidJsonDocument)
    }

    /// Parses a raw TrustGrant document from a JSON string.
    ///
    /// # Examples
    ///
    /// ```rust
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
    /// let doc = RawTrustGrantDocument::parse_json_str(json)
    ///     .expect("valid TrustGrant JSON");
    /// assert_eq!(doc.trustgrant_id.as_str(), "tg_123e4567-e89b-12d3-a456-426614174000");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the input exceeds the protocol size
    /// limit, is not valid JSON, or does not match the TrustGrant v0 wire
    /// shape.
    pub fn parse_json_str(json: &str) -> Result<Self, TrustGrantError> {
        ensure_json_size("trustgrant", json.len(), MAX_TRUSTGRANT_JSON_BYTES)?;

        serde_json::from_str(json).map_err(|_error| TrustGrantError::InvalidJsonDocument)
    }

    /// Serializes one raw TrustGrant document to JSON.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] when serialization fails.
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Wire supersession policy for a TrustGrant document.
///
/// Maps directly from the JSON `supersession_policy` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawSupersessionPolicy {
    /// New revision coexists with prior revisions.
    Coexist,
    /// New revision supersedes the immediately previous revision.
    SupersedePrevious,
}

impl RawSupersessionPolicy {
    /// Supersession policy string representation for canonicalization.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Coexist => "coexist",
            Self::SupersedePrevious => "supersede_previous",
        }
    }
}

/// Wire representation of an issuer principal reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPrincipal {
    /// Principal kind (e.g. `service`, `user`).
    pub kind: CompactString,
    /// Principal identifier within its kind.
    pub id: CompactString,
}

impl RawPrincipal {
    /// Raw issuer principal should be forwarded into one draft or document.
    #[must_use]
    pub fn new(kind: impl Into<CompactString>, id: impl Into<CompactString>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
        }
    }
}

/// Wire representation of a scope block (`target_scope`, audience scopes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawScope {
    /// When `true`, the scope matches all values unconditionally.
    pub all: bool,
    /// Selectors that explicitly allow matching values.
    pub allow: Option<Vec<RawSelector>>,
    /// Selectors that explicitly deny matching values.
    pub deny: Option<Vec<RawSelector>>,
}

impl RawScope {
    /// All-scope should be used in a raw document or draft.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            all: true,
            allow: None,
            deny: None,
        }
    }

    /// Allow-scope should be used in a raw document or draft.
    #[must_use]
    pub const fn allow(selectors: Vec<RawSelector>) -> Self {
        Self {
            all: false,
            allow: Some(selectors),
            deny: None,
        }
    }

    /// Custom scope should be used in a raw document or draft.
    #[must_use]
    pub const fn new(
        all: bool,
        allow: Option<Vec<RawSelector>>,
        deny: Option<Vec<RawSelector>>,
    ) -> Self {
        Self { all, allow, deny }
    }
}

/// Wire representation of one selector in a scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSelector {
    /// Selector kind (e.g. `authority`, `namespace`, `actor`).
    pub kind: CompactString,
    /// When `true`, the selector matches all values unconditionally.
    pub all: bool,
    /// Explicit value strings to match.
    pub values: Option<Vec<CompactString>>,
    /// Selector expressions (e.g. `startsWith("vip_")`).
    pub expressions: Option<Vec<CompactString>>,
}

impl RawSelector {
    /// All-selector should be used in a raw document or draft.
    #[must_use]
    pub fn all(kind: impl Into<CompactString>) -> Self {
        Self {
            kind: kind.into(),
            all: true,
            values: None,
            expressions: None,
        }
    }

    /// Value-selector should be used in a raw document or draft.
    #[must_use]
    pub fn values(kind: impl Into<CompactString>, values: Vec<CompactString>) -> Self {
        Self {
            kind: kind.into(),
            all: false,
            values: Some(values),
            expressions: None,
        }
    }

    /// Expression-selector should be used in a raw document or draft.
    #[must_use]
    pub fn expressions(kind: impl Into<CompactString>, expressions: Vec<CompactString>) -> Self {
        Self {
            kind: kind.into(),
            all: false,
            values: None,
            expressions: Some(expressions),
        }
    }

    /// Custom selector should be used in a raw document or draft.
    #[must_use]
    pub fn new(
        kind: impl Into<CompactString>,
        all: bool,
        values: Option<Vec<CompactString>>,
        expressions: Option<Vec<CompactString>>,
    ) -> Self {
        Self {
            kind: kind.into(),
            all,
            values,
            expressions,
        }
    }
}

/// Wire representation of top-level built-in capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawCapabilities {
    /// Whether the `recognize` capability is enabled.
    pub recognize: bool,
    /// Whether the `mint` capability is enabled.
    pub mint: bool,
}

impl RawCapabilities {
    /// Raw capabilities should be used in a raw document or draft.
    #[must_use]
    pub const fn new(recognize: bool, mint: bool) -> Self {
        Self { recognize, mint }
    }
}

/// Wire representation of the resource scope map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawResourceScope {
    /// Map from resource type name to its scope definition.
    pub types: BTreeMap<Utf16Key, RawResourceType>,
}

impl RawResourceScope {
    /// Resource scope should be used in a raw document or draft.
    #[must_use]
    pub const fn new(types: BTreeMap<Utf16Key, RawResourceType>) -> Self {
        Self { types }
    }
}

/// Wire representation of one resource type scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawResourceType {
    /// When `true`, the type matches all resources unconditionally.
    pub all: bool,
    /// Selectors that explicitly allow resources of this type.
    pub allow: Option<Vec<RawSelector>>,
    /// Selectors that explicitly deny resources of this type.
    pub deny: Option<Vec<RawSelector>>,
    /// Per-type capability overrides.
    pub capabilities: RawTypeCapabilities,
    /// Constraints for this resource type.
    pub constraints: RawTypeConstraints,
    /// Operation scope (allow/deny lists of operation names).
    pub operations: Option<RawOperationScope>,
}

impl RawResourceType {
    /// Resource type scope should be used in a raw document or draft.
    #[must_use]
    pub const fn new(
        all: bool,
        allow: Option<Vec<RawSelector>>,
        deny: Option<Vec<RawSelector>>,
        capabilities: RawTypeCapabilities,
        constraints: RawTypeConstraints,
        operations: Option<RawOperationScope>,
    ) -> Self {
        Self {
            all,
            allow,
            deny,
            capabilities,
            constraints,
            operations,
        }
    }
}

/// Wire representation of per-type capability overrides.
///
/// `None` means "inherit from the top-level capabilities block".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawTypeCapabilities {
    /// Per-type `recognize` override (`None` = inherit).
    pub recognize: Option<bool>,
    /// Per-type `mint` override (`None` = inherit).
    pub mint: Option<bool>,
}

impl RawTypeCapabilities {
    /// Raw type capabilities should be used in a raw document or draft.
    #[must_use]
    pub const fn new(recognize: Option<bool>, mint: Option<bool>) -> Self {
        Self { recognize, mint }
    }
}

/// Wire representation of per-type constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTypeConstraints {
    /// Minting limits for this resource type.
    pub minting: RawMintingConstraints,
    /// Audience scope entries specific to this resource type.
    pub audience_scope: Option<Vec<RawAudienceEntry>>,
}

impl RawTypeConstraints {
    /// Raw type constraints should be used in a raw document or draft.
    #[must_use]
    pub const fn new(
        minting: RawMintingConstraints,
        audience_scope: Option<Vec<RawAudienceEntry>>,
    ) -> Self {
        Self {
            minting,
            audience_scope,
        }
    }
}

/// Wire representation of minting constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawMintingConstraints {
    /// Maximum total number of mint operations allowed.
    pub max_total: Option<u64>,
    /// Maximum number of mint operations per unique audience principal.
    pub max_per_user: Option<u64>,
}

impl RawMintingConstraints {
    /// Raw minting constraints should be used in a raw document or draft.
    #[must_use]
    pub const fn new(max_total: Option<u64>, max_per_user: Option<u64>) -> Self {
        Self {
            max_total,
            max_per_user,
        }
    }
}

/// Wire representation of an operation scope (allow/deny lists).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawOperationScope {
    /// When `true`, all operations are allowed unconditionally.
    pub all: bool,
    /// Explicitly allowed operation names.
    pub allow: Option<Vec<CompactString>>,
    /// Explicitly denied operation names.
    pub deny: Option<Vec<CompactString>>,
}

impl RawOperationScope {
    /// All-operations scope should be used in a raw document or draft.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            all: true,
            allow: None,
            deny: None,
        }
    }

    /// Allow-operations scope should be used in a raw document or draft.
    #[must_use]
    pub const fn allow(operations: Vec<CompactString>) -> Self {
        Self {
            all: false,
            allow: Some(operations),
            deny: None,
        }
    }

    /// Custom operations scope should be used in a raw document or draft.
    #[must_use]
    pub const fn new(
        all: bool,
        allow: Option<Vec<CompactString>>,
        deny: Option<Vec<CompactString>>,
    ) -> Self {
        Self { all, allow, deny }
    }
}

/// Wire representation of one audience entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawAudienceEntry {
    /// Target audience authority identifier.
    pub authority_id: CompactString,
    /// Scope that the audience authority must match.
    pub scope: RawScope,
    /// Optional principal scope narrowing the audience.
    pub principal_scope: Option<RawScope>,
}

impl RawAudienceEntry {
    /// Raw audience entry should be used in a raw document or draft.
    #[must_use]
    pub fn new(
        authority_id: impl Into<CompactString>,
        scope: RawScope,
        principal_scope: Option<RawScope>,
    ) -> Self {
        Self {
            authority_id: authority_id.into(),
            scope,
            principal_scope,
        }
    }
}

/// Wire representation of global grant constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawGlobalConstraints {
    pub time: Option<RawTimeWindow>,
}

impl RawGlobalConstraints {
    /// Raw global constraints should be used in a raw document or draft.
    #[must_use]
    pub const fn new(time: Option<RawTimeWindow>) -> Self {
        Self { time }
    }
}

/// Wire representation of a time window with `not_before` and `not_after`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTimeWindow {
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

impl RawTimeWindow {
    /// Raw time window should be used in a raw document or draft.
    #[must_use]
    pub const fn new(not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> Self {
        Self {
            not_before,
            not_after,
        }
    }
}

/// A declared protocol profile that this grant follows.
///
/// Carries the profile name and version. The engine uses this to constrain
/// custom operations: when `operations.all = true`, only custom operations
/// that belong to the declared profile are authorized. Without a profile,
/// `operations.all` only authorizes built-in operations (recognize for v0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InteroperabilityProfile {
    /// Profile name (e.g. `"shared_inventory_v1"`).
    pub name: CompactString,
    /// Profile version.
    pub version: u64,
}

impl InteroperabilityProfile {
    /// Creates a new interoperability profile declaration.
    #[must_use]
    pub fn new(name: impl Into<CompactString>, version: u64) -> Self {
        Self {
            name: name.into(),
            version,
        }
    }

    /// The profile name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The profile version.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }
}

/// What happens after a grant is revoked.
///
/// Defines which operations remain available and how existing resources
/// are affected. This is a signed policy field in the grant document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostRevocationEffect {
    /// Only future mint operations are blocked. Recognition and custom
    /// operations on already-issued resources still work.
    BlockMintingOnly,
    /// All operations on the grant are blocked. This is the default and
    /// most conservative behavior.
    BlockAll,
}

impl Default for PostRevocationEffect {
    fn default() -> Self {
        Self::BlockAll
    }
}

/// Wire representation of a revocation policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRevocation {
    pub revocable: bool,
    pub revocation_endpoint: CompactString,
    pub post_revocation_effect: PostRevocationEffect,
}

impl RawRevocation {
    /// Raw revocation policy should be used in a raw document or draft.
    #[must_use]
    pub fn new(revocable: bool, revocation_endpoint: impl Into<CompactString>) -> Self {
        Self {
            revocable,
            revocation_endpoint: revocation_endpoint.into(),
            post_revocation_effect: PostRevocationEffect::BlockAll,
        }
    }

    /// Sets the post-revocation effect for this policy.
    #[must_use]
    pub const fn with_post_revocation_effect(
        mut self,
        effect: PostRevocationEffect,
    ) -> Self {
        self.post_revocation_effect = effect;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::RawTrustGrantDocument;
    use trustgrant_error::TrustGrantError;
    use trustgrant_error::limits::MAX_TRUSTGRANT_JSON_BYTES;

    #[test]
    fn parse_json_str_accepts_minimal_valid_shape() {
        let json = r#"{
          "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
          "version":0,
          "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
          "revision":1,
          "supersession_policy":"coexist",
          "issuer_authority":"https://issuer.example.com",
          "origin_authority":"https://issuer.example.com",
          "active_owning_authority":"https://issuer.example.com",
          "key_id":"root-key-1",
          "target_scope":{"all":true,"allow":null,"deny":null},
          "capabilities":{"recognize":true,"mint":false},
          "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
          "issued_at":"2026-04-07T12:00:00Z",
          "signature":"base64-signature"
        }"#;

        let parsed = RawTrustGrantDocument::parse_json_str(json);

        assert!(parsed.is_ok());
    }

    #[test]
    fn parse_json_str_rejects_malformed_json() {
        assert!(RawTrustGrantDocument::parse_json_str("{invalid").is_err());
    }

    #[test]
    fn parse_json_str_rejects_unclosed_braces() {
        assert!(
            RawTrustGrantDocument::parse_json_str(
                r#"{"trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000""#
            )
            .is_err()
        );
    }

    #[test]
    fn parse_json_str_rejects_empty_string() {
        assert!(RawTrustGrantDocument::parse_json_str("").is_err());
    }

    #[test]
    fn parse_json_str_accepts_empty_resource_scope_types() {
        let json = r#"{
          "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174099",
          "version":0,
          "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174099",
          "revision":1,
          "supersedes":null,
          "supersession_policy":"coexist",
          "issuer_authority":"https://issuer.example.com",
          "origin_authority":"https://issuer.example.com",
          "active_owning_authority":"https://issuer.example.com",
          "key_id":"root-key-1",
          "target_scope":{"all":false,"allow":[{"kind":"authority_id","all":false,"values":["https://target.example.com"],"expressions":null}],"deny":null},
          "capabilities":{"recognize":true,"mint":false},
          "default_audience_scope":null,
          "resource_scope":{"types":{}},
          "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
          "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
          "issued_at":"2026-04-07T12:00:00Z",
          "signature":"base64-signature",
          "issuer_principal":null
        }"#;
        let raw = match RawTrustGrantDocument::parse_json_str(json) {
            Ok(doc) => doc,
            Err(_) => return,
        };
        assert!(raw.resource_scope.types.is_empty());
    }

    #[test]
    fn parse_json_str_rejects_oversized_document() {
        let oversized_signature = "a".repeat(MAX_TRUSTGRANT_JSON_BYTES);
        let json = format!(
            r#"{{
              "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
              "version":0,
              "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
              "revision":1,
              "supersession_policy":"coexist",
              "issuer_authority":"https://issuer.example.com",
              "origin_authority":"https://issuer.example.com",
              "active_owning_authority":"https://issuer.example.com",
              "key_id":"root-key-1",
              "target_scope":{{"all":true,"allow":null,"deny":null}},
              "capabilities":{{"recognize":true,"mint":false}},
              "resource_scope":{{"types":{{"item":{{"all":true,"allow":null,"deny":null,"capabilities":{{"recognize":true,"mint":false}},"constraints":{{"minting":{{"max_total":null,"max_per_user":null}},"audience_scope":null}},"operations":null}}}}}},
              "issued_at":"2026-04-07T12:00:00Z",
              "signature":"{oversized_signature}"
            }}"#
        );

        let parsed = RawTrustGrantDocument::parse_json_str(&json);

        assert_eq!(
            parsed,
            Err(TrustGrantError::DocumentTooLarge {
                document: "trustgrant",
                max_bytes: MAX_TRUSTGRANT_JSON_BYTES,
            })
        );
    }

    #[test]
    fn parse_json_str_rejects_unknown_fields() {
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
          "target_scope":{"all":true,"allow":null,"deny":null},
          "capabilities":{"recognize":true,"mint":false},
          "default_audience_scope":null,
          "resource_scope":{"types":{}},
          "global_constraints":null,
          "revocation":null,
          "issued_at":"2026-04-07T12:00:00Z",
          "signature":"base64-signature",
          "issuer_principal":null,
          "unexpected":"value"
        }"#;

        let parsed = RawTrustGrantDocument::parse_json_str(json);

        assert_eq!(parsed, Err(TrustGrantError::InvalidJsonDocument));
    }

    #[test]
    fn raw_operation_scope_all_creates_all_true_scope() {
        use crate::raw::RawOperationScope;

        let scope = RawOperationScope::all();
        assert!(scope.all);
        assert!(scope.allow.is_none());
        assert!(scope.deny.is_none());
    }
}
