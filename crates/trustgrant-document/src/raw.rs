use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use trustgrant_domain::Utf16Key;


use trustgrant_error::TrustGrantError;
use trustgrant_error::limits::{MAX_TRUSTGRANT_JSON_BYTES, ensure_json_size};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawSupersessionPolicy {
    Coexist,
    SupersedePrevious,
}

impl RawSupersessionPolicy {
    #[must_use = "supersession policy string representation for canonicalization"]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Coexist => "coexist",
            Self::SupersedePrevious => "supersede_previous",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPrincipal {
    pub kind: CompactString,
    pub id: CompactString,
}

impl RawPrincipal {
    #[must_use = "raw issuer principal should be forwarded into one draft or document"]
    pub fn new(kind: impl Into<CompactString>, id: impl Into<CompactString>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawScope {
    pub all: bool,
    pub allow: Option<Vec<RawSelector>>,
    pub deny: Option<Vec<RawSelector>>,
}

impl RawScope {
    #[must_use = "all-scope should be used in a raw document or draft"]
    pub const fn all() -> Self {
        Self {
            all: true,
            allow: None,
            deny: None,
        }
    }

    #[must_use = "allow-scope should be used in a raw document or draft"]
    pub const fn allow(selectors: Vec<RawSelector>) -> Self {
        Self {
            all: false,
            allow: Some(selectors),
            deny: None,
        }
    }

    #[must_use = "custom scope should be used in a raw document or draft"]
    pub const fn new(
        all: bool,
        allow: Option<Vec<RawSelector>>,
        deny: Option<Vec<RawSelector>>,
    ) -> Self {
        Self { all, allow, deny }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSelector {
    pub kind: CompactString,
    pub all: bool,
    pub values: Option<Vec<CompactString>>,
    pub expressions: Option<Vec<CompactString>>,
}

impl RawSelector {
    #[must_use = "all-selector should be used in a raw document or draft"]
    pub fn all(kind: impl Into<CompactString>) -> Self {
        Self {
            kind: kind.into(),
            all: true,
            values: None,
            expressions: None,
        }
    }

    #[must_use = "value-selector should be used in a raw document or draft"]
    pub fn values(kind: impl Into<CompactString>, values: Vec<CompactString>) -> Self {
        Self {
            kind: kind.into(),
            all: false,
            values: Some(values),
            expressions: None,
        }
    }

    #[must_use = "expression-selector should be used in a raw document or draft"]
    pub fn expressions(kind: impl Into<CompactString>, expressions: Vec<CompactString>) -> Self {
        Self {
            kind: kind.into(),
            all: false,
            values: None,
            expressions: Some(expressions),
        }
    }

    #[must_use = "custom selector should be used in a raw document or draft"]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawCapabilities {
    pub recognize: bool,
    pub mint: bool,
}

impl RawCapabilities {
    #[must_use = "raw capabilities should be used in a raw document or draft"]
    pub const fn new(recognize: bool, mint: bool) -> Self {
        Self { recognize, mint }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawResourceScope {
    pub types: BTreeMap<Utf16Key, RawResourceType>,
}

impl RawResourceScope {
    #[must_use = "resource scope should be used in a raw document or draft"]
    pub const fn new(types: BTreeMap<Utf16Key, RawResourceType>) -> Self {
        Self { types }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawResourceType {
    pub all: bool,
    pub allow: Option<Vec<RawSelector>>,
    pub deny: Option<Vec<RawSelector>>,
    pub capabilities: RawTypeCapabilities,
    pub constraints: RawTypeConstraints,
    pub operations: Option<RawOperationScope>,
}

impl RawResourceType {
    #[must_use = "resource type scope should be used in a raw document or draft"]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawTypeCapabilities {
    pub recognize: Option<bool>,
    pub mint: Option<bool>,
}

impl RawTypeCapabilities {
    #[must_use = "raw type capabilities should be used in a raw document or draft"]
    pub const fn new(recognize: Option<bool>, mint: Option<bool>) -> Self {
        Self { recognize, mint }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTypeConstraints {
    pub minting: RawMintingConstraints,
    pub audience_scope: Option<Vec<RawAudienceEntry>>,
}

impl RawTypeConstraints {
    #[must_use = "raw type constraints should be used in a raw document or draft"]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawMintingConstraints {
    pub max_total: Option<u64>,
    pub max_per_user: Option<u64>,
}

impl RawMintingConstraints {
    #[must_use = "raw minting constraints should be used in a raw document or draft"]
    pub const fn new(max_total: Option<u64>, max_per_user: Option<u64>) -> Self {
        Self {
            max_total,
            max_per_user,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawOperationScope {
    pub all: bool,
    pub allow: Option<Vec<CompactString>>,
    pub deny: Option<Vec<CompactString>>,
}

impl RawOperationScope {
    #[must_use = "all-operations scope should be used in a raw document or draft"]
    pub const fn all() -> Self {
        Self {
            all: true,
            allow: None,
            deny: None,
        }
    }

    #[must_use = "allow-operations scope should be used in a raw document or draft"]
    pub const fn allow(operations: Vec<CompactString>) -> Self {
        Self {
            all: false,
            allow: Some(operations),
            deny: None,
        }
    }

    #[must_use = "custom operations scope should be used in a raw document or draft"]
    pub const fn new(
        all: bool,
        allow: Option<Vec<CompactString>>,
        deny: Option<Vec<CompactString>>,
    ) -> Self {
        Self { all, allow, deny }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawAudienceEntry {
    pub authority_id: CompactString,
    pub scope: RawScope,
    pub principal_scope: Option<RawScope>,
}

impl RawAudienceEntry {
    #[must_use = "raw audience entry should be used in a raw document or draft"]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawGlobalConstraints {
    pub time: Option<RawTimeWindow>,
}

impl RawGlobalConstraints {
    #[must_use = "raw global constraints should be used in a raw document or draft"]
    pub const fn new(time: Option<RawTimeWindow>) -> Self {
        Self { time }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTimeWindow {
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

impl RawTimeWindow {
    #[must_use = "raw time window should be used in a raw document or draft"]
    pub const fn new(not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> Self {
        Self {
            not_before,
            not_after,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRevocation {
    pub revocable: bool,
    pub revocation_endpoint: CompactString,
}

impl RawRevocation {
    #[must_use = "raw revocation policy should be used in a raw document or draft"]
    pub fn new(revocable: bool, revocation_endpoint: impl Into<CompactString>) -> Self {
        Self {
            revocable,
            revocation_endpoint: revocation_endpoint.into(),
        }
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
          "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
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
