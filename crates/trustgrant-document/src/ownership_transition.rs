use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use trustgrant_domain::Utf16Key;

use trustgrant_domain::{
    AuthorityId, GrantRevision, KeyId, OwnershipResourceScope, OwnershipSelector,
    OwnershipTimeWindow, OwnershipTransitionLineage, OwnershipTransitionParties,
    OwnershipTransitionRecord, ResourceTypeName, TransitionId, TransitionSeriesId,
};
use trustgrant_error::{
    TrustGrantError,
    limits::{
        MAX_OWNERSHIP_TRANSITION_JSON_BYTES, MAX_RESOURCE_TYPES, MAX_SELECTOR_VALUE_BYTES,
        MAX_SELECTOR_VALUES_PER_SELECTOR, MAX_SELECTORS_PER_SCOPE, ensure_collection_limit,
        ensure_json_size, ensure_string_limit,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawOwnershipTransitionDocument {
    pub transition_id: CompactString,
    pub version: u8,
    pub transition_series_id: CompactString,
    pub revision: u64,
    pub supersedes_transition_id: Option<CompactString>,
    pub origin_authority: CompactString,
    pub from_authority: CompactString,
    pub to_authority: CompactString,
    pub canonical_resource_scope: RawOwnershipTransitionResourceScope,
    pub global_constraints: Option<RawOwnershipTransitionGlobalConstraints>,
    pub effective_at: DateTime<Utc>,
    pub predecessor_signature: RawOwnershipTransitionSignature,
    pub successor_acceptance: RawOwnershipTransitionAcceptance,
}

impl RawOwnershipTransitionDocument {
    /// Parses a raw ownership transition document from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the input exceeds the protocol size
    /// limit, is not valid JSON, or does not match the ownership-transition v0
    /// wire shape.
    pub fn parse_json_bytes(bytes: &[u8]) -> Result<Self, TrustGrantError> {
        ensure_json_size(
            "ownership_transition",
            bytes.len(),
            MAX_OWNERSHIP_TRANSITION_JSON_BYTES,
        )?;

        serde_json::from_slice(bytes)
            .map_err(|_error| TrustGrantError::InvalidOwnershipTransitionDocument)
    }

    /// Parses a raw ownership transition document from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the input exceeds the protocol size
    /// limit, is not valid JSON, or does not match the ownership-transition v0
    /// wire shape.
    pub fn parse_json_str(json: &str) -> Result<Self, TrustGrantError> {
        ensure_json_size(
            "ownership_transition",
            json.len(),
            MAX_OWNERSHIP_TRANSITION_JSON_BYTES,
        )?;

        serde_json::from_str(json)
            .map_err(|_error| TrustGrantError::InvalidOwnershipTransitionDocument)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawOwnershipTransitionResourceScope {
    pub types: BTreeMap<Utf16Key, RawOwnershipTransitionResourceType>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawOwnershipTransitionResourceType {
    pub all: bool,
    pub allow: Option<Vec<RawOwnershipTransitionSelector>>,
    pub deny: Option<Vec<RawOwnershipTransitionSelector>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawOwnershipTransitionSelector {
    pub kind: CompactString,
    pub all: bool,
    pub values: Option<Vec<CompactString>>,
    pub expressions: Option<Vec<CompactString>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawOwnershipTransitionGlobalConstraints {
    pub time: Option<RawOwnershipTransitionTimeWindow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawOwnershipTransitionTimeWindow {
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawOwnershipTransitionSignature {
    pub key_id: CompactString,
    pub signature: CompactString,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawOwnershipTransitionAcceptance {
    pub accepted_at: DateTime<Utc>,
    pub key_id: CompactString,
    pub signature: CompactString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipTransitionSignature {
    key_id: KeyId,
    signature: CompactString,
}

impl OwnershipTransitionSignature {
    #[must_use = "transition signature key id is required for verification"]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    #[must_use = "transition signature bytes are required for verification"]
    pub fn signature(&self) -> &str {
        &self.signature
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipTransitionAcceptance {
    accepted_at: DateTime<Utc>,
    key_id: KeyId,
    signature: CompactString,
}

impl OwnershipTransitionAcceptance {
    #[must_use = "acceptance timestamp is required for validity checks"]
    pub const fn accepted_at(&self) -> DateTime<Utc> {
        self.accepted_at
    }

    #[must_use = "acceptance key id is required for signature verification"]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    #[must_use = "acceptance signature bytes are required for verification"]
    pub fn signature(&self) -> &str {
        &self.signature
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedOwnershipTransitionDocument {
    lineage: OwnershipTransitionLineage,
    parties: OwnershipTransitionParties,
    resource_scope: BTreeMap<ResourceTypeName, OwnershipResourceScope>,
    time_window: Option<OwnershipTimeWindow>,
    effective_at: DateTime<Utc>,
    predecessor_signature: OwnershipTransitionSignature,
    successor_acceptance: OwnershipTransitionAcceptance,
}

impl ValidatedOwnershipTransitionDocument {
    #[must_use = "lineage is required for transition chain verification"]
    pub const fn lineage(&self) -> &OwnershipTransitionLineage {
        &self.lineage
    }

    #[must_use = "parties are required for ownership verification"]
    pub const fn parties(&self) -> &OwnershipTransitionParties {
        &self.parties
    }

    #[must_use = "resource scope is required for ownership verification"]
    pub const fn resource_scope(&self) -> &BTreeMap<ResourceTypeName, OwnershipResourceScope> {
        &self.resource_scope
    }

    #[must_use = "time window participates in transition validity checks"]
    pub const fn time_window(&self) -> Option<&OwnershipTimeWindow> {
        self.time_window.as_ref()
    }

    #[must_use = "effective_at participates in transition ordering"]
    pub const fn effective_at(&self) -> DateTime<Utc> {
        self.effective_at
    }

    #[must_use = "predecessor signature is required for proof verification"]
    pub const fn predecessor_signature(&self) -> &OwnershipTransitionSignature {
        &self.predecessor_signature
    }

    #[must_use = "successor acceptance is required for proof verification"]
    pub const fn successor_acceptance(&self) -> &OwnershipTransitionAcceptance {
        &self.successor_acceptance
    }

    /// Converts one verified ownership transition document into normalized
    /// runtime ownership state.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the normalized record invariants are
    /// violated.
    pub fn to_record(&self) -> Result<OwnershipTransitionRecord, TrustGrantError> {
        OwnershipTransitionRecord::new(
            self.lineage.clone(),
            self.parties.clone(),
            self.resource_scope.clone(),
            self.time_window,
            self.effective_at,
        )
    }
}

impl TryFrom<RawOwnershipTransitionDocument> for ValidatedOwnershipTransitionDocument {
    type Error = TrustGrantError;

    fn try_from(raw: RawOwnershipTransitionDocument) -> Result<Self, Self::Error> {
        if raw.version != 0 {
            return Err(TrustGrantError::InvalidProtocolVersion(raw.version));
        }

        let transition_id = raw.transition_id.parse::<TransitionId>()?;
        let transition_series_id = raw.transition_series_id.parse::<TransitionSeriesId>()?;
        let revision = GrantRevision::new(raw.revision)?;
        let supersedes_transition_id = raw
            .supersedes_transition_id
            .as_deref()
            .map(str::parse::<TransitionId>)
            .transpose()?;
        let lineage = OwnershipTransitionLineage::new(
            transition_id,
            transition_series_id,
            revision,
            supersedes_transition_id,
        )?;
        let parties = OwnershipTransitionParties::new(
            AuthorityId::new(raw.origin_authority)?,
            AuthorityId::new(raw.from_authority)?,
            AuthorityId::new(raw.to_authority)?,
        )?;
        let resource_scope = validate_transition_scope(raw.canonical_resource_scope)?;
        let time_window = raw
            .global_constraints
            .and_then(|constraints| constraints.time)
            .map(|window| OwnershipTimeWindow::new(window.not_before, window.not_after))
            .transpose()?;

        if let Some(time_window) = time_window
            && !time_window.contains(raw.effective_at)
        {
            return Err(TrustGrantError::InvalidOwnershipTransitionEffectiveAt);
        }

        let predecessor_signature =
            validate_transition_signature(raw.predecessor_signature, "predecessor_signature")?;
        let successor_acceptance = validate_transition_acceptance(raw.successor_acceptance)?;

        Ok(Self {
            lineage,
            parties,
            resource_scope,
            time_window,
            effective_at: raw.effective_at,
            predecessor_signature,
            successor_acceptance,
        })
    }
}

fn validate_transition_scope(
    raw: RawOwnershipTransitionResourceScope,
) -> Result<BTreeMap<ResourceTypeName, OwnershipResourceScope>, TrustGrantError> {
    if raw.types.is_empty() {
        return Err(TrustGrantError::InvalidOwnershipTransitionScope);
    }
    ensure_collection_limit(
        "ownership_transition.resource_types",
        raw.types.len(),
        MAX_RESOURCE_TYPES,
    )?;

    raw.types
        .into_iter()
        .map(|(resource_type_name, raw_resource_type)| {
            let resource_type_name = ResourceTypeName::new(resource_type_name)?;
            let resource_scope = validate_transition_resource_type(raw_resource_type)?;

            Ok((resource_type_name, resource_scope))
        })
        .collect()
}

fn validate_transition_resource_type(
    raw: RawOwnershipTransitionResourceType,
) -> Result<OwnershipResourceScope, TrustGrantError> {
    if raw.all || raw.deny.is_some() {
        return Err(TrustGrantError::InvalidOwnershipTransitionScope);
    }

    let Some(selectors) = raw.allow else {
        return Err(TrustGrantError::InvalidOwnershipTransitionScope);
    };
    ensure_collection_limit(
        "ownership_transition.selectors",
        selectors.len(),
        MAX_SELECTORS_PER_SCOPE,
    )?;
    let selectors = selectors
        .into_iter()
        .map(validate_transition_selector)
        .collect::<Result<Vec<_>, _>>()?;

    OwnershipResourceScope::new(selectors)
}

fn validate_transition_selector(
    raw: RawOwnershipTransitionSelector,
) -> Result<OwnershipSelector, TrustGrantError> {
    if raw.all || raw.expressions.is_some() {
        return Err(TrustGrantError::InvalidOwnershipTransitionScope);
    }

    let Some(values) = raw.values else {
        return Err(TrustGrantError::InvalidOwnershipTransitionScope);
    };
    ensure_collection_limit(
        "ownership_transition.selector_values",
        values.len(),
        MAX_SELECTOR_VALUES_PER_SELECTOR,
    )?;

    let values = values
        .into_iter()
        .map(|value| {
            ensure_string_limit(
                "ownership_transition.selector_value",
                &value,
                MAX_SELECTOR_VALUE_BYTES,
            )?;
            Ok(value.into())
        })
        .collect::<Result<Vec<_>, TrustGrantError>>()?;

    OwnershipSelector::new(raw.kind, values)
}

fn validate_transition_signature(
    raw: RawOwnershipTransitionSignature,
    field_name: &'static str,
) -> Result<OwnershipTransitionSignature, TrustGrantError> {
    Ok(OwnershipTransitionSignature {
        key_id: KeyId::new(raw.key_id)?,
        signature: normalize_non_empty(field_name, &raw.signature)?
            .to_owned()
            .into(),
    })
}

fn validate_transition_acceptance(
    raw: RawOwnershipTransitionAcceptance,
) -> Result<OwnershipTransitionAcceptance, TrustGrantError> {
    Ok(OwnershipTransitionAcceptance {
        accepted_at: raw.accepted_at,
        key_id: KeyId::new(raw.key_id)?,
        signature: normalize_non_empty("successor_acceptance.signature", &raw.signature)?
            .to_owned()
            .into(),
    })
}

fn normalize_non_empty<'value>(
    field_name: &'static str,
    value: &'value str,
) -> Result<&'value str, TrustGrantError> {
    let normalized = value.trim();
    if normalized.is_empty() {
        Err(TrustGrantError::EmptyStringField(field_name))
    } else {
        Ok(normalized)
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::{RawOwnershipTransitionDocument, ValidatedOwnershipTransitionDocument};
    use trustgrant_error::{TrustGrantError, limits::MAX_SELECTOR_VALUES_PER_SELECTOR};

    #[test]
    fn validated_transition_rejects_wildcard_scope() {
        let raw = match RawOwnershipTransitionDocument::parse_json_str(
            r#"{
              "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174000",
              "version":0,
              "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174001",
              "revision":1,
              "supersedes_transition_id":null,
              "origin_authority":"https://origin.example.com",
              "from_authority":"https://origin.example.com",
              "to_authority":"https://successor.example.com",
              "canonical_resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null}}},
              "global_constraints":null,
              "effective_at":"2026-04-07T12:00:00Z",
              "predecessor_signature":{"key_id":"root-key-1","signature":"predecessor-signature"},
              "successor_acceptance":{"accepted_at":"2026-04-07T11:00:00Z","key_id":"successor-key-1","signature":"successor-signature"}
            }"#,
        ) {
            Ok(value) => value,
            Err(error) => panic!("raw transition should parse: {error}"),
        };

        let result = ValidatedOwnershipTransitionDocument::try_from(raw);

        assert_eq!(
            result,
            Err(TrustGrantError::InvalidOwnershipTransitionScope)
        );
    }

    #[test]
    fn validated_transition_rejects_effective_at_outside_time_window() {
        let raw = match RawOwnershipTransitionDocument::parse_json_str(
            r#"{
              "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174000",
              "version":0,
              "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174001",
              "revision":1,
              "supersedes_transition_id":null,
              "origin_authority":"https://origin.example.com",
              "from_authority":"https://origin.example.com",
              "to_authority":"https://successor.example.com",
              "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":null}],"deny":null}}},
              "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-07T13:00:00Z"}},
              "effective_at":"2026-04-07T14:00:00Z",
              "predecessor_signature":{"key_id":"root-key-1","signature":"predecessor-signature"},
              "successor_acceptance":{"accepted_at":"2026-04-07T11:00:00Z","key_id":"successor-key-1","signature":"successor-signature"}
            }"#,
        ) {
            Ok(value) => value,
            Err(error) => panic!("raw transition should parse: {error}"),
        };

        let result = ValidatedOwnershipTransitionDocument::try_from(raw);

        assert_eq!(
            result,
            Err(TrustGrantError::InvalidOwnershipTransitionEffectiveAt)
        );
    }

    #[test]
    fn validated_transition_rejects_non_first_revision_without_supersedes() {
        let raw = match RawOwnershipTransitionDocument::parse_json_str(
            r#"{
              "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174000",
              "version":0,
              "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174001",
              "revision":2,
              "supersedes_transition_id":null,
              "origin_authority":"https://origin.example.com",
              "from_authority":"https://origin.example.com",
              "to_authority":"https://successor.example.com",
              "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":null}],"deny":null}}},
              "global_constraints":null,
              "effective_at":"2026-04-07T12:00:00Z",
              "predecessor_signature":{"key_id":"root-key-1","signature":"predecessor-signature"},
              "successor_acceptance":{"accepted_at":"2026-04-07T11:00:00Z","key_id":"successor-key-1","signature":"successor-signature"}
            }"#,
        ) {
            Ok(value) => value,
            Err(error) => panic!("raw transition should parse: {error}"),
        };

        let result = ValidatedOwnershipTransitionDocument::try_from(raw);

        assert_eq!(
            result,
            Err(TrustGrantError::MissingSupersedesForNonFirstOwnershipTransitionRevision)
        );
    }

    #[test]
    fn parse_json_str_rejects_oversized_transition_document() {
        let oversized_signature =
            "a".repeat(trustgrant_error::limits::MAX_OWNERSHIP_TRANSITION_JSON_BYTES);
        let json = format!(
            r#"{{
              "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174000",
              "version":0,
              "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174001",
              "revision":1,
              "supersedes_transition_id":null,
              "origin_authority":"https://origin.example.com",
              "from_authority":"https://origin.example.com",
              "to_authority":"https://successor.example.com",
              "canonical_resource_scope":{{"types":{{"item":{{"all":false,"allow":[{{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":null}}],"deny":null}}}}}},
              "global_constraints":null,
              "effective_at":"2026-04-07T12:00:00Z",
              "predecessor_signature":{{"key_id":"root-key-1","signature":"{oversized_signature}"}},
              "successor_acceptance":{{"accepted_at":"2026-04-07T11:00:00Z","key_id":"successor-key-1","signature":"successor-signature"}}
            }}"#
        );

        let result = RawOwnershipTransitionDocument::parse_json_str(&json);

        assert_eq!(
            result,
            Err(TrustGrantError::DocumentTooLarge {
                document: "ownership_transition",
                max_bytes: trustgrant_error::limits::MAX_OWNERSHIP_TRANSITION_JSON_BYTES,
            })
        );
    }

    #[test]
    fn parse_json_str_rejects_unknown_fields() {
        let result = RawOwnershipTransitionDocument::parse_json_str(
            r#"{
              "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174000",
              "version":0,
              "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174001",
              "revision":1,
              "supersedes_transition_id":null,
              "origin_authority":"https://issuer.example.com",
              "from_authority":"https://issuer.example.com",
              "to_authority":"https://successor.example.com",
              "canonical_resource_scope":{"types":{}},
              "global_constraints":null,
              "effective_at":"2026-04-07T12:00:00Z",
              "predecessor_signature":{"key_id":"root-key-1","signature":"pred"},
              "successor_acceptance":{"accepted_at":"2026-04-07T12:05:00Z","key_id":"succ-key-1","signature":"succ"},
              "unexpected":"value"
            }"#,
        );

        assert_eq!(
            result,
            Err(TrustGrantError::InvalidOwnershipTransitionDocument)
        );
    }

    #[test]
    fn validated_transition_rejects_too_many_selector_values() {
        let values = (0..=MAX_SELECTOR_VALUES_PER_SELECTOR)
            .map(|index| format!("canonical_item_{index}"))
            .collect::<Vec<_>>()
            .join("\",\"");
        let raw = match RawOwnershipTransitionDocument::parse_json_str(&format!(
            r#"{{
              "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174000",
              "version":0,
              "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174001",
              "revision":1,
              "supersedes_transition_id":null,
              "origin_authority":"https://origin.example.com",
              "from_authority":"https://origin.example.com",
              "to_authority":"https://successor.example.com",
              "canonical_resource_scope":{{"types":{{"item":{{"all":false,"allow":[{{"kind":"id","all":false,"values":["{values}"],"expressions":null}}],"deny":null}}}}}},
              "global_constraints":null,
              "effective_at":"2026-04-07T12:00:00Z",
              "predecessor_signature":{{"key_id":"root-key-1","signature":"predecessor-signature"}},
              "successor_acceptance":{{"accepted_at":"2026-04-07T11:00:00Z","key_id":"successor-key-1","signature":"successor-signature"}}
            }}"#
        )) {
            Ok(value) => value,
            Err(error) => panic!("raw transition should parse: {error}"),
        };

        let result = ValidatedOwnershipTransitionDocument::try_from(raw);

        assert_eq!(
            result,
            Err(TrustGrantError::CollectionTooLarge {
                field: "ownership_transition.selector_values",
                max_items: MAX_SELECTOR_VALUES_PER_SELECTOR,
            })
        );
    }

    #[test]
    fn validated_to_record_round_trips_fields() {
        let raw = match RawOwnershipTransitionDocument::parse_json_str(
            r#"{
              "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174000",
              "version":0,
              "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174001",
              "revision":1,
              "supersedes_transition_id":null,
              "origin_authority":"https://origin.example.com",
              "from_authority":"https://origin.example.com",
              "to_authority":"https://successor.example.com",
              "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":null}],"deny":null}}},
              "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-07T13:00:00Z"}},
              "effective_at":"2026-04-07T12:00:00Z",
              "predecessor_signature":{"key_id":"root-key-1","signature":"predecessor-signature"},
              "successor_acceptance":{"accepted_at":"2026-04-07T11:00:00Z","key_id":"successor-key-1","signature":"successor-signature"}
            }"#,
        ) {
            Ok(value) => value,
            Err(error) => panic!("raw transition should parse: {error}"),
        };

        let validated = match ValidatedOwnershipTransitionDocument::try_from(raw) {
            Ok(value) => value,
            Err(error) => panic!("transition should validate: {error}"),
        };

        let record = match validated.to_record() {
            Ok(value) => value,
            Err(error) => panic!("to_record should succeed: {error}"),
        };

        assert_eq!(
            record.lineage().transition_id().to_string(),
            "tgt_123e4567-e89b-12d3-a456-426614174000"
        );
        assert_eq!(
            record.lineage().transition_series_id().to_string(),
            "tgts_123e4567-e89b-12d3-a456-426614174001"
        );
        assert_eq!(record.lineage().revision().get(), 1);
        assert!(record.lineage().supersedes_transition_id().is_none());
        assert_eq!(
            record.origin_authority().as_str(),
            "https://origin.example.com"
        );
        assert_eq!(
            record.predecessor_authority().as_str(),
            "https://origin.example.com"
        );
        assert_eq!(
            record.successor_authority().as_str(),
            "https://successor.example.com"
        );
        assert!(record.time_window().is_some());
        assert!(!record.resource_scope().is_empty());
    }

    #[test]
    fn validated_transition_accessors_return_expected_values() {
        // Use the same JSON pattern as validated_to_record_round_trips_fields
        let raw = match RawOwnershipTransitionDocument::parse_json_str(
            r#"{
              "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174000",
              "version":0,
              "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174001",
              "revision":1,
              "supersedes_transition_id":null,
              "origin_authority":"https://issuer.example.com",
              "from_authority":"https://issuer.example.com",
              "to_authority":"https://successor.example.com",
              "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":null}],"deny":null}}},
              "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-07T13:00:00Z"}},
              "effective_at":"2026-04-07T12:00:00Z",
              "predecessor_signature":{"key_id":"root-key-1","signature":"predecessor-signature"},
              "successor_acceptance":{"accepted_at":"2026-04-07T11:00:00Z","key_id":"successor-key-1","signature":"successor-signature"}
            }"#,
        ) {
            Ok(value) => value,
            Err(error) => panic!("raw transition should parse: {error}"),
        };

        let validated = match ValidatedOwnershipTransitionDocument::try_from(raw) {
            Ok(value) => value,
            Err(error) => panic!("transition should validate: {error}"),
        };

        assert!(
            validated
                .lineage()
                .transition_id()
                .to_string()
                .starts_with("tgt_")
        );
        assert!(
            validated
                .parties()
                .origin_authority()
                .as_str()
                .contains("issuer")
        );
        assert!(!validated.resource_scope().is_empty());
        assert!(validated.time_window().is_some());
        assert!(
            validated
                .predecessor_signature()
                .key_id()
                .as_str()
                .contains("root")
        );
        assert!(
            validated
                .successor_acceptance()
                .key_id()
                .as_str()
                .contains("successor")
        );
    }

    #[test]
    fn validated_transition_rejects_invalid_protocol_version() {
        let raw = match RawOwnershipTransitionDocument::parse_json_str(
            r#"{
              "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174000",
              "version":1,
              "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174001",
              "revision":1,
              "supersedes_transition_id":null,
              "origin_authority":"https://origin.example.com",
              "from_authority":"https://origin.example.com",
              "to_authority":"https://successor.example.com",
              "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":null}],"deny":null}}},
              "global_constraints":null,
              "effective_at":"2026-04-07T12:00:00Z",
              "predecessor_signature":{"key_id":"root-key-1","signature":"predecessor-signature"},
              "successor_acceptance":{"accepted_at":"2026-04-07T11:00:00Z","key_id":"successor-key-1","signature":"successor-signature"}
            }"#,
        ) {
            Ok(value) => value,
            Err(error) => panic!("raw transition should parse: {error}"),
        };

        let result = ValidatedOwnershipTransitionDocument::try_from(raw);

        assert_eq!(result, Err(TrustGrantError::InvalidProtocolVersion(1)));
    }

    #[test]
    fn validated_transition_rejects_empty_resource_scope_types() {
        let raw = match RawOwnershipTransitionDocument::parse_json_str(
            r#"{
              "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174000",
              "version":0,
              "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174001",
              "revision":1,
              "supersedes_transition_id":null,
              "origin_authority":"https://origin.example.com",
              "from_authority":"https://origin.example.com",
              "to_authority":"https://successor.example.com",
              "canonical_resource_scope":{"types":{}},
              "global_constraints":null,
              "effective_at":"2026-04-07T12:00:00Z",
              "predecessor_signature":{"key_id":"root-key-1","signature":"predecessor-signature"},
              "successor_acceptance":{"accepted_at":"2026-04-07T11:00:00Z","key_id":"successor-key-1","signature":"successor-signature"}
            }"#,
        ) {
            Ok(value) => value,
            Err(error) => panic!("raw transition should parse: {error}"),
        };

        let result = ValidatedOwnershipTransitionDocument::try_from(raw);

        assert_eq!(
            result,
            Err(TrustGrantError::InvalidOwnershipTransitionScope)
        );
    }

    #[test]
    fn validated_transition_rejects_selector_with_all_true() {
        let raw = match RawOwnershipTransitionDocument::parse_json_str(
            r#"{
              "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174000",
              "version":0,
              "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174001",
              "revision":1,
              "supersedes_transition_id":null,
              "origin_authority":"https://origin.example.com",
              "from_authority":"https://origin.example.com",
              "to_authority":"https://successor.example.com",
              "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":true,"values":["canonical_item_1"],"expressions":null}],"deny":null}}},
              "global_constraints":null,
              "effective_at":"2026-04-07T12:00:00Z",
              "predecessor_signature":{"key_id":"root-key-1","signature":"predecessor-signature"},
              "successor_acceptance":{"accepted_at":"2026-04-07T11:00:00Z","key_id":"successor-key-1","signature":"successor-signature"}
            }"#,
        ) {
            Ok(value) => value,
            Err(error) => panic!("raw transition should parse: {error}"),
        };

        let result = ValidatedOwnershipTransitionDocument::try_from(raw);

        assert_eq!(
            result,
            Err(TrustGrantError::InvalidOwnershipTransitionScope)
        );
    }

    #[test]
    fn validated_transition_rejects_selector_with_expressions() {
        let raw = match RawOwnershipTransitionDocument::parse_json_str(
            r#"{
              "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174000",
              "version":0,
              "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174001",
              "revision":1,
              "supersedes_transition_id":null,
              "origin_authority":"https://origin.example.com",
              "from_authority":"https://origin.example.com",
              "to_authority":"https://successor.example.com",
              "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":["regex:.*"]}],"deny":null}}},
              "global_constraints":null,
              "effective_at":"2026-04-07T12:00:00Z",
              "predecessor_signature":{"key_id":"root-key-1","signature":"predecessor-signature"},
              "successor_acceptance":{"accepted_at":"2026-04-07T11:00:00Z","key_id":"successor-key-1","signature":"successor-signature"}
            }"#,
        ) {
            Ok(value) => value,
            Err(error) => panic!("raw transition should parse: {error}"),
        };

        let result = ValidatedOwnershipTransitionDocument::try_from(raw);

        assert_eq!(
            result,
            Err(TrustGrantError::InvalidOwnershipTransitionScope)
        );
    }

    #[test]
    fn validated_transition_rejects_selector_with_missing_values() {
        let raw = match RawOwnershipTransitionDocument::parse_json_str(
            r#"{
              "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174000",
              "version":0,
              "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174001",
              "revision":1,
              "supersedes_transition_id":null,
              "origin_authority":"https://origin.example.com",
              "from_authority":"https://origin.example.com",
              "to_authority":"https://successor.example.com",
              "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":null,"expressions":null}],"deny":null}}},
              "global_constraints":null,
              "effective_at":"2026-04-07T12:00:00Z",
              "predecessor_signature":{"key_id":"root-key-1","signature":"predecessor-signature"},
              "successor_acceptance":{"accepted_at":"2026-04-07T11:00:00Z","key_id":"successor-key-1","signature":"successor-signature"}
            }"#,
        ) {
            Ok(value) => value,
            Err(error) => panic!("raw transition should parse: {error}"),
        };

        let result = ValidatedOwnershipTransitionDocument::try_from(raw);

        assert_eq!(
            result,
            Err(TrustGrantError::InvalidOwnershipTransitionScope)
        );
    }

    #[test]
    fn parse_json_bytes_accepts_valid_transition() {
        let json = r#"{
            "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174000",
            "version":0,
            "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174001",
            "revision":1,
            "supersedes_transition_id":null,
            "origin_authority":"https://origin.example.com",
            "from_authority":"https://origin.example.com",
            "to_authority":"https://successor.example.com",
            "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":null}],"deny":null}}},
            "global_constraints":null,
            "effective_at":"2026-04-07T12:00:00Z",
            "predecessor_signature":{"key_id":"root-key-1","signature":"predecessor-signature"},
            "successor_acceptance":{"accepted_at":"2026-04-07T11:00:00Z","key_id":"successor-key-1","signature":"successor-signature"}
        }"#;

        let doc = RawOwnershipTransitionDocument::parse_json_bytes(json.as_bytes())
            .unwrap_or_else(|e| panic!("parse should be Ok: {e}"));
        assert_eq!(
            doc.transition_id,
            "tgt_123e4567-e89b-12d3-a456-426614174000"
        );
        assert_eq!(doc.version, 0);
        assert_eq!(doc.origin_authority, "https://origin.example.com");
    }
}
