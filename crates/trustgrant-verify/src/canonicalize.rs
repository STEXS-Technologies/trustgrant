use std::collections::BTreeMap;
use std::io::Write;

use chrono::{DateTime, SecondsFormat, Utc};
use compact_str::CompactString;
use itoa::Buffer as ItoaBuffer;

use trustgrant_document::raw::{
    PostRevocationEffect, RawAudienceEntry, RawCapabilities, RawGlobalConstraints,
    RawMintingConstraints, RawOperationScope, RawPrincipal, RawResourceScope, RawResourceType,
    RawRevocation, RawScope, RawSelector, RawSupersessionPolicy, RawTimeWindow,
    RawTrustGrantDocument, RawTypeCapabilities, RawTypeConstraints,
};
use trustgrant_domain::{CanonicalizationProfile, Utf16Key};
use trustgrant_error::TrustGrantError;

/// Deterministic canonical bytes of a TrustGrant document suitable for
/// signature verification.
///
/// Produced by [`canonicalize_trustgrant`] and consumed by signature verifier
/// adapters. The canonical form omits the `signature` field itself and uses
/// a fixed RFC 8785–equivalent key order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalTrustGrantBytes(Vec<u8>);

impl CanonicalTrustGrantBytes {
    /// Canonical bytes should be passed to signature verification.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// Produces deterministic signable bytes for one raw TrustGrant document.
///
/// The v0 canonicalization profile serializes the TrustGrant wire document with
/// a fixed RFC 8785-equivalent key order and omits the `signature` field itself
/// from the signable payload.
///
/// # Errors
///
/// Returns [`TrustGrantError::CanonicalizationFailure`] when serialization of
/// the canonical signable payload fails.
pub fn canonicalize_trustgrant(
    raw_document: &RawTrustGrantDocument,
    profile: CanonicalizationProfile,
) -> Result<CanonicalTrustGrantBytes, TrustGrantError> {
    match profile {
        CanonicalizationProfile::Rfc8785 => canonicalize_json_v0(raw_document),
    }
}

fn canonicalize_json_v0(
    raw_document: &RawTrustGrantDocument,
) -> Result<CanonicalTrustGrantBytes, TrustGrantError> {
    let mut canonical_bytes = Vec::with_capacity(1536);
    write_trustgrant_document(&mut canonical_bytes, raw_document)?;

    Ok(CanonicalTrustGrantBytes(canonical_bytes))
}

fn write_trustgrant_document(
    writer: &mut Vec<u8>,
    raw_document: &RawTrustGrantDocument,
) -> Result<(), TrustGrantError> {
    write_bytes(writer, b"{")?;
    write_json_string_field(
        writer,
        "active_owning_authority",
        &raw_document.active_owning_authority,
    )?;
    write_bytes(writer, b",")?;
    write_capabilities_field(writer, "capabilities", raw_document.capabilities)?;
    write_bytes(writer, b",")?;
    write_audience_scope_field(
        writer,
        "default_audience_scope",
        raw_document.default_audience_scope.as_deref(),
    )?;
    write_bytes(writer, b",")?;
    write_global_constraints_field(
        writer,
        "global_constraints",
        raw_document.global_constraints.as_ref(),
    )?;
    write_bytes(writer, b",")?;
    write_json_string_field(writer, "grant_series_id", &raw_document.grant_series_id)?;
    write_bytes(writer, b",")?;
    write_datetime_field(writer, "issued_at", raw_document.issued_at)?;
    write_bytes(writer, b",")?;
    write_json_string_field(writer, "issuer_authority", &raw_document.issuer_authority)?;
    write_bytes(writer, b",")?;
    write_principal_field(
        writer,
        "issuer_principal",
        raw_document.issuer_principal.as_ref(),
    )?;
    write_bytes(writer, b",")?;
    write_json_string_field(writer, "key_id", &raw_document.key_id)?;
    write_bytes(writer, b",")?;
    write_json_string_field(writer, "origin_authority", &raw_document.origin_authority)?;
    write_bytes(writer, b",")?;
    write_resource_scope_field(writer, "resource_scope", &raw_document.resource_scope)?;
    write_bytes(writer, b",")?;
    write_u64_field(writer, "revision", raw_document.revision)?;
    write_bytes(writer, b",")?;
    write_revocation_field(writer, "revocation", raw_document.revocation.as_ref())?;
    write_bytes(writer, b",")?;
    write_optional_string_field(writer, "supersedes", raw_document.supersedes.as_deref())?;
    write_bytes(writer, b",")?;
    write_supersession_policy_field(
        writer,
        "supersession_policy",
        raw_document.supersession_policy,
    )?;
    write_bytes(writer, b",")?;
    write_scope_field(writer, "target_scope", &raw_document.target_scope)?;
    write_bytes(writer, b",")?;
    write_json_string_field(writer, "trustgrant_id", &raw_document.trustgrant_id)?;
    write_bytes(writer, b",")?;
    write_u8_field(writer, "version", raw_document.version)?;
    write_bytes(writer, b"}")
}

fn write_scope_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    scope: &RawScope,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;
    write_scope(writer, scope)
}

fn write_scope(writer: &mut Vec<u8>, scope: &RawScope) -> Result<(), TrustGrantError> {
    write_bytes(writer, b"{")?;
    write_bool_field(writer, "all", scope.all)?;
    write_bytes(writer, b",")?;
    write_selectors_field(writer, "allow", scope.allow.as_deref())?;
    write_bytes(writer, b",")?;
    write_selectors_field(writer, "deny", scope.deny.as_deref())?;
    write_bytes(writer, b"}")
}

fn write_selectors_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    selectors: Option<&[RawSelector]>,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;

    let Some(selectors) = selectors else {
        return write_null(writer);
    };

    write_bytes(writer, b"[")?;

    for (index, selector) in selectors.iter().enumerate() {
        if index > 0 {
            write_bytes(writer, b",")?;
        }

        write_selector(writer, selector)?;
    }

    write_bytes(writer, b"]")
}

fn write_selector(writer: &mut Vec<u8>, selector: &RawSelector) -> Result<(), TrustGrantError> {
    write_bytes(writer, b"{")?;
    write_bool_field(writer, "all", selector.all)?;
    write_bytes(writer, b",")?;
    write_string_array_field(writer, "expressions", selector.expressions.as_deref())?;
    write_bytes(writer, b",")?;
    write_json_string_field(writer, "kind", &selector.kind)?;
    write_bytes(writer, b",")?;
    write_string_array_field(writer, "values", selector.values.as_deref())?;
    write_bytes(writer, b"}")
}

fn write_capabilities_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    capabilities: RawCapabilities,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;
    write_bytes(writer, b"{")?;
    write_bool_field(writer, "mint", capabilities.mint)?;
    write_bytes(writer, b",")?;
    write_bool_field(writer, "recognize", capabilities.recognize)?;
    write_bytes(writer, b"}")
}

fn write_audience_scope_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    entries: Option<&[RawAudienceEntry]>,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;
    write_audience_entries(writer, entries)
}

fn write_audience_entries(
    writer: &mut Vec<u8>,
    entries: Option<&[RawAudienceEntry]>,
) -> Result<(), TrustGrantError> {
    let Some(entries) = entries else {
        return write_null(writer);
    };

    write_bytes(writer, b"[")?;

    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            write_bytes(writer, b",")?;
        }

        write_audience_entry(writer, entry)?;
    }

    write_bytes(writer, b"]")
}

fn write_audience_entry(
    writer: &mut Vec<u8>,
    entry: &RawAudienceEntry,
) -> Result<(), TrustGrantError> {
    write_bytes(writer, b"{")?;
    write_json_string_field(writer, "authority_id", &entry.authority_id)?;
    write_bytes(writer, b",")?;
    write_optional_scope_field(writer, "principal_scope", entry.principal_scope.as_ref())?;
    write_bytes(writer, b",")?;
    write_scope_field(writer, "scope", &entry.scope)?;
    write_bytes(writer, b"}")
}

fn write_optional_scope_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    scope: Option<&RawScope>,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;

    let Some(scope) = scope else {
        return write_null(writer);
    };

    write_scope(writer, scope)
}

fn write_resource_scope_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    resource_scope: &RawResourceScope,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;
    write_bytes(writer, b"{")?;
    write_resource_type_map_field(writer, "types", &resource_scope.types)?;
    write_bytes(writer, b"}")
}

fn write_resource_type_map_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    resource_types: &BTreeMap<Utf16Key, RawResourceType>,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;
    write_bytes(writer, b"{")?;

    for (index, (resource_type_name, resource_type)) in resource_types.iter().enumerate() {
        if index > 0 {
            write_bytes(writer, b",")?;
        }

        write_json_string(writer, resource_type_name.as_str())?;
        write_bytes(writer, b":")?;
        write_resource_type(writer, resource_type)?;
    }

    write_bytes(writer, b"}")
}

fn write_resource_type(
    writer: &mut Vec<u8>,
    resource_type: &RawResourceType,
) -> Result<(), TrustGrantError> {
    write_bytes(writer, b"{")?;
    write_bool_field(writer, "all", resource_type.all)?;
    write_bytes(writer, b",")?;
    write_selectors_field(writer, "allow", resource_type.allow.as_deref())?;
    write_bytes(writer, b",")?;
    write_type_capabilities_field(writer, "capabilities", resource_type.capabilities)?;
    write_bytes(writer, b",")?;
    write_type_constraints_field(writer, "constraints", &resource_type.constraints)?;
    write_bytes(writer, b",")?;
    write_selectors_field(writer, "deny", resource_type.deny.as_deref())?;
    write_bytes(writer, b",")?;
    write_operation_scope_field(writer, "operations", resource_type.operations.as_ref())?;
    write_bytes(writer, b"}")
}

fn write_type_capabilities_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    capabilities: RawTypeCapabilities,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;
    write_bytes(writer, b"{")?;
    write_optional_bool_field(writer, "mint", capabilities.mint)?;
    write_bytes(writer, b",")?;
    write_optional_bool_field(writer, "recognize", capabilities.recognize)?;
    write_bytes(writer, b"}")
}

fn write_type_constraints_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    constraints: &RawTypeConstraints,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;
    write_bytes(writer, b"{")?;
    write_audience_scope_field(
        writer,
        "audience_scope",
        constraints.audience_scope.as_deref(),
    )?;
    write_bytes(writer, b",")?;
    write_minting_constraints_field(writer, "minting", constraints.minting)?;
    write_bytes(writer, b"}")
}

fn write_minting_constraints_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    constraints: RawMintingConstraints,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;
    write_bytes(writer, b"{")?;
    write_optional_u64_field(writer, "max_per_user", constraints.max_per_user)?;
    write_bytes(writer, b",")?;
    write_optional_u64_field(writer, "max_total", constraints.max_total)?;
    write_bytes(writer, b"}")
}

fn write_operation_scope_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    operation_scope: Option<&RawOperationScope>,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;

    let Some(operation_scope) = operation_scope else {
        return write_null(writer);
    };

    write_bytes(writer, b"{")?;
    write_bool_field(writer, "all", operation_scope.all)?;
    write_bytes(writer, b",")?;
    write_string_array_field(writer, "allow", operation_scope.allow.as_deref())?;
    write_bytes(writer, b",")?;
    write_string_array_field(writer, "deny", operation_scope.deny.as_deref())?;
    write_bytes(writer, b"}")
}

fn write_global_constraints_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    constraints: Option<&RawGlobalConstraints>,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;

    let Some(constraints) = constraints else {
        return write_null(writer);
    };

    write_bytes(writer, b"{")?;
    write_time_window_field(writer, "time", constraints.time.as_ref())?;
    write_bytes(writer, b"}")
}

fn write_time_window_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    time_window: Option<&RawTimeWindow>,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;

    let Some(time_window) = time_window else {
        return write_null(writer);
    };

    write_bytes(writer, b"{")?;
    write_datetime_field(writer, "not_after", time_window.not_after)?;
    write_bytes(writer, b",")?;
    write_datetime_field(writer, "not_before", time_window.not_before)?;
    write_bytes(writer, b"}")
}

fn write_revocation_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    revocation: Option<&RawRevocation>,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;

    let Some(revocation) = revocation else {
        return write_null(writer);
    };

    write_bytes(writer, b"{")?;
    // JCS order: "p" before "r", so post_revocation_effect comes first
    let effect = match revocation.post_revocation_effect {
        PostRevocationEffect::BlockAll => "block_all",
        PostRevocationEffect::BlockMintingOnly => "block_minting_only",
    };
    write_json_string_field(writer, "post_revocation_effect", effect)?;
    write_bytes(writer, b",")?;
    write_bool_field(writer, "revocable", revocation.revocable)?;
    write_bytes(writer, b",")?;
    write_json_string_field(
        writer,
        "revocation_endpoint",
        &revocation.revocation_endpoint,
    )?;
    write_bytes(writer, b"}")
}

fn write_principal_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    principal: Option<&RawPrincipal>,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;

    let Some(principal) = principal else {
        return write_null(writer);
    };

    write_bytes(writer, b"{")?;
    write_json_string_field(writer, "id", &principal.id)?;
    write_bytes(writer, b",")?;
    write_json_string_field(writer, "kind", &principal.kind)?;
    write_bytes(writer, b"}")
}

fn write_supersession_policy_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    supersession_policy: RawSupersessionPolicy,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;
    write_json_string(writer, supersession_policy.as_str())
}

fn write_string_array_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    values: Option<&[CompactString]>,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;

    let Some(values) = values else {
        return write_null(writer);
    };

    write_bytes(writer, b"[")?;

    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            write_bytes(writer, b",")?;
        }

        write_json_string(writer, value)?;
    }

    write_bytes(writer, b"]")
}

fn write_field_name(writer: &mut Vec<u8>, field_name: &str) -> Result<(), TrustGrantError> {
    write_json_string(writer, field_name)?;
    write_bytes(writer, b":")
}

fn write_json_string_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    value: &str,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;
    write_json_string(writer, value)
}

fn write_optional_string_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    value: Option<&str>,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;

    let Some(value) = value else {
        return write_null(writer);
    };

    write_json_string(writer, value)
}

fn write_bool_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    value: bool,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;
    write_bool(writer, value)
}

fn write_optional_bool_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    value: Option<bool>,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;

    let Some(value) = value else {
        return write_null(writer);
    };

    write_bool(writer, value)
}

fn write_u8_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    value: u8,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;
    write_u64(writer, u64::from(value))
}

fn write_u64_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    value: u64,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;
    write_u64(writer, value)
}

fn write_optional_u64_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    value: Option<u64>,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;

    let Some(value) = value else {
        return write_null(writer);
    };

    write_u64(writer, value)
}

fn write_datetime_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    value: DateTime<Utc>,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;
    writer.push(b'"');
    writer.extend_from_slice(
        value
            .to_rfc3339_opts(SecondsFormat::AutoSi, true)
            .as_bytes(),
    );
    writer.push(b'"');
    Ok(())
}

fn write_json_string(writer: &mut Vec<u8>, value: &str) -> Result<(), TrustGrantError> {
    serde_json::to_writer(writer, value).map_err(|_error| TrustGrantError::CanonicalizationFailure)
}

fn write_bool(writer: &mut Vec<u8>, value: bool) -> Result<(), TrustGrantError> {
    if value {
        write_bytes(writer, b"true")
    } else {
        write_bytes(writer, b"false")
    }
}

fn write_u64(writer: &mut Vec<u8>, value: u64) -> Result<(), TrustGrantError> {
    let mut buffer = ItoaBuffer::new();
    write_bytes(writer, buffer.format(value).as_bytes())
}

fn write_null(writer: &mut Vec<u8>) -> Result<(), TrustGrantError> {
    write_bytes(writer, b"null")
}

fn write_bytes(writer: &mut Vec<u8>, bytes: &[u8]) -> Result<(), TrustGrantError> {
    writer
        .write_all(bytes)
        .map_err(|_error| TrustGrantError::CanonicalizationFailure)
}

// RawSupersessionPolicy::as_str is defined in trustgrant-document

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{DateTime, Utc};
    use serde_json::Value;

    use super::{CanonicalizationProfile, canonicalize_trustgrant};
    use trustgrant_document::raw::{
        RawAudienceEntry, RawCapabilities, RawGlobalConstraints, RawMintingConstraints,
        RawOperationScope, RawPrincipal, RawResourceScope, RawResourceType, RawRevocation,
        RawScope, RawSelector, RawSupersessionPolicy, RawTimeWindow, RawTrustGrantDocument,
        RawTypeCapabilities, RawTypeConstraints,
    };
    use trustgrant_domain::Utf16Key;

    fn parse_document(signature: &str) -> RawTrustGrantDocument {
        let json = format!(
            r#"{{
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
              "target_scope":{{"all":true,"allow":null,"deny":null}},
              "capabilities":{{"recognize":true,"mint":false}},
              "default_audience_scope":null,
              "resource_scope":{{"types":{{"item":{{"all":true,"allow":null,"deny":null,"capabilities":{{"recognize":null,"mint":false}},"constraints":{{"minting":{{"max_total":null,"max_per_user":null}},"audience_scope":null}},"operations":null}}}}}},
              "issued_at":"2026-04-07T12:00:00Z",
              "signature":"{signature}"
            }}"#
        );

        match RawTrustGrantDocument::parse_json_str(&json) {
            Ok(document) => document,
            Err(error) => panic!("raw document should parse: {error}"),
        }
    }

    fn canonicalize_with_serde_jcs_oracle(
        raw_document: &RawTrustGrantDocument,
    ) -> Result<Vec<u8>, trustgrant_error::TrustGrantError> {
        let mut value = serde_json::to_value(raw_document)
            .map_err(|_error| trustgrant_error::TrustGrantError::CanonicalizationFailure)?;
        let Some(object) = value.as_object_mut() else {
            return Err(trustgrant_error::TrustGrantError::CanonicalizationFailure);
        };

        object.remove("signature");
        serde_jcs::to_vec(&Value::Object(object.clone()))
            .map_err(|_error| trustgrant_error::TrustGrantError::CanonicalizationFailure)
    }

    fn assert_matches_oracle(raw_document: &RawTrustGrantDocument) {
        let specialized =
            match canonicalize_trustgrant(raw_document, CanonicalizationProfile::Rfc8785) {
                Ok(bytes) => bytes,
                Err(error) => panic!("specialized canonicalization should succeed: {error}"),
            };
        let oracle = match canonicalize_with_serde_jcs_oracle(raw_document) {
            Ok(bytes) => bytes,
            Err(error) => panic!("oracle canonicalization should succeed: {error}"),
        };

        assert_eq!(specialized.as_slice(), oracle.as_slice());
    }

    #[test]
    fn canonicalization_is_deterministic_for_same_document() {
        let raw_document = parse_document("sig-a");

        let first = canonicalize_trustgrant(&raw_document, CanonicalizationProfile::Rfc8785);
        let second = canonicalize_trustgrant(&raw_document, CanonicalizationProfile::Rfc8785);

        assert_eq!(first, second);
    }

    #[test]
    fn canonicalization_excludes_signature_field() {
        let left = parse_document("sig-a");
        let right = parse_document("sig-b");

        let left_bytes = match canonicalize_trustgrant(&left, CanonicalizationProfile::Rfc8785) {
            Ok(bytes) => bytes,
            Err(error) => panic!("canonicalization should succeed: {error}"),
        };
        let right_bytes = match canonicalize_trustgrant(&right, CanonicalizationProfile::Rfc8785) {
            Ok(bytes) => bytes,
            Err(error) => panic!("canonicalization should succeed: {error}"),
        };

        assert_eq!(left_bytes, right_bytes);
        let serialized = match std::str::from_utf8(left_bytes.as_slice()) {
            Ok(value) => value,
            Err(error) => panic!("canonical bytes should be valid UTF-8 JSON: {error}"),
        };
        assert!(!serialized.contains("\"signature\""));
    }

    #[test]
    fn canonicalization_matches_serde_jcs_oracle_for_minimal_document() {
        let raw_document = parse_document("sig-a");

        assert_matches_oracle(&raw_document);
    }

    /// Verifies that `"field": null` and an entirely absent field produce the
    /// same canonical bytes. serde treats both as `Option::None`, so the
    /// canonicalizer should emit `null` for both paths.
    #[test]
    fn canonicalization_null_vs_absent_fields_are_identical() {
        // Grant A: explicit nulls for optional fields
        let json_a = r#"{
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
          "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
          "global_constraints":null,
          "revocation":null,
          "issued_at":"2026-04-07T12:00:00Z",
          "signature":"sig-a",
          "issuer_principal":null
        }"#;

        // Grant B: omit the optional fields entirely
        let json_b = r#"{
          "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
          "version":0,
          "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
          "revision":1,
          "supersession_policy":"coexist",
          "issuer_authority":"https://issuer.example.com",
          "origin_authority":"https://issuer.example.com",
          "active_owning_authority":"https://issuer.example.com",
          "key_id":"root-key-1",
          "target_scope":{"all":true},
          "capabilities":{"recognize":true,"mint":false},
          "resource_scope":{"types":{"item":{"all":true,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{}}}}},
          "issued_at":"2026-04-07T12:00:00Z",
          "signature":"sig-b"
        }"#;

        let raw_a = RawTrustGrantDocument::parse_json_str(json_a)
            .unwrap_or_else(|error| panic!("grant A should parse: {error}"));
        let raw_b = RawTrustGrantDocument::parse_json_str(json_b)
            .unwrap_or_else(|error| panic!("grant B should parse: {error}"));

        let canonical_a = canonicalize_trustgrant(&raw_a, CanonicalizationProfile::Rfc8785)
            .unwrap_or_else(|error| panic!("canonicalize grant A: {error}"));
        let canonical_b = canonicalize_trustgrant(&raw_b, CanonicalizationProfile::Rfc8785)
            .unwrap_or_else(|error| panic!("canonicalize grant B: {error}"));

        assert_eq!(canonical_a, canonical_b);
    }

    #[test]
    fn canonicalization_matches_serde_jcs_oracle_for_complex_document() {
        let raw_document = RawTrustGrantDocument {
            trustgrant_id: "tg_123e4567-e89b-12d3-a456-426614174000".into(),
            version: 0,
            grant_series_id: "tgs_123e4567-e89b-12d3-a456-426614174001".into(),
            revision: 2,
            supersedes: Some("tg_123e4567-e89b-12d3-a456-426614174099".into()),
            supersession_policy: RawSupersessionPolicy::SupersedePrevious,
            issuer_authority: "https://issuer.example.com".into(),
            origin_authority: "https://issuer.example.com".into(),
            active_owning_authority: "https://issuer.example.com".into(),
            key_id: "root-key-1".into(),
            target_scope: RawScope::new(
                false,
                Some(vec![RawSelector::new(
                    "authority",
                    false,
                    Some(vec![
                        "https://target.example.com".into(),
                        "https://target-two.example.com".into(),
                    ]),
                    Some(vec!["startsWith(\"https://target\")".into()]),
                )]),
                Some(vec![RawSelector::all("deny_authority")]),
            ),
            capabilities: RawCapabilities::new(true, true),
            default_audience_scope: Some(vec![RawAudienceEntry::new(
                "https://audience.example.com",
                RawScope::all(),
                Some(RawScope::allow(vec![RawSelector::expressions(
                    "actor",
                    vec!["contains(\"player\")".into()],
                )])),
            )]),
            resource_scope: RawResourceScope::new(BTreeMap::from([
                (
                    Utf16Key::new("ä_item"),
                    RawResourceType::new(
                        false,
                        Some(vec![RawSelector::values(
                            "namespace",
                            vec!["weapons".into()],
                        )]),
                        None,
                        RawTypeCapabilities::new(Some(true), Some(false)),
                        RawTypeConstraints::new(
                            RawMintingConstraints::new(Some(10), Some(1)),
                            None,
                        ),
                        None,
                    ),
                ),
                (
                    Utf16Key::new("z_item"),
                    RawResourceType::new(
                        false,
                        Some(vec![RawSelector::expressions(
                            "namespace",
                            vec!["endsWith(\"gear\")".into()],
                        )]),
                        Some(vec![RawSelector::values("id", vec!["forbidden".into()])]),
                        RawTypeCapabilities::new(None, Some(true)),
                        RawTypeConstraints::new(
                            RawMintingConstraints::new(None, None),
                            Some(vec![RawAudienceEntry::new(
                                "https://audience.example.com",
                                RawScope::allow(vec![RawSelector::values(
                                    "authority",
                                    vec!["https://audience.example.com".into()],
                                )]),
                                None,
                            )]),
                        ),
                        Some(RawOperationScope::new(
                            false,
                            Some(vec!["custom:use".into(), "recognize".into()]),
                            Some(vec!["custom:deny".into()]),
                        )),
                    ),
                ),
            ])),
            global_constraints: Some(RawGlobalConstraints::new(Some(RawTimeWindow::new(
                DateTime::parse_from_rfc3339("2026-04-07T12:00:00Z")
                    .unwrap_or_else(|error| panic!("valid fixture timestamp: {error}"))
                    .with_timezone(&Utc),
                DateTime::parse_from_rfc3339("2026-04-08T12:00:00Z")
                    .unwrap_or_else(|error| panic!("valid fixture timestamp: {error}"))
                    .with_timezone(&Utc),
            )))),
            revocation: Some(RawRevocation::new(
                true,
                "https://issuer.example.com/revocation",
            )),
            issued_at: DateTime::parse_from_rfc3339("2026-04-07T12:00:00Z")
                .unwrap_or_else(|error| panic!("valid fixture timestamp: {error}"))
                .with_timezone(&Utc),
            signature: "base64-signature".into(),
            issuer_principal: Some(RawPrincipal::new("service", "issuer-worker")),
            interoperability_profile: None,
        };

        assert_matches_oracle(&raw_document);
    }

    // ── Lines 578-584: write_json_string escape characters ──────────────

    #[test]
    fn canonicalization_escapes_special_characters() {
        let mut raw = parse_document("sig");
        raw.key_id = "key\\with\nspecial\tchars\r".into();

        let canonical = canonicalize_trustgrant(&raw, CanonicalizationProfile::Rfc8785)
            .unwrap_or_else(|e| panic!("canonicalization should succeed: {e}"));
        let output = String::from_utf8(canonical.as_slice().to_vec())
            .unwrap_or_else(|_| panic!("valid utf8"));

        assert!(output.contains(r"key\\with\nspecial\tchars\r"));
    }
}
