use std::collections::BTreeMap;
use std::io::Write;

use chrono::{DateTime, SecondsFormat, Utc};
use compact_str::CompactString;
use itoa::Buffer as ItoaBuffer;

use trustgrant_document::{
    RawOwnershipTransitionAcceptance, RawOwnershipTransitionDocument,
    RawOwnershipTransitionGlobalConstraints, RawOwnershipTransitionResourceScope,
    RawOwnershipTransitionResourceType, RawOwnershipTransitionSelector,
    RawOwnershipTransitionSignature, RawOwnershipTransitionTimeWindow,
};
use trustgrant_domain::{CanonicalizationProfile, Utf16Key};
use trustgrant_error::TrustGrantError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalOwnershipTransitionBytes(Vec<u8>);

impl CanonicalOwnershipTransitionBytes {
    #[must_use = "canonical bytes should be passed to signature verification"]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// Produces deterministic signable bytes for the predecessor transition proof.
///
/// The predecessor signs the proposed transfer payload without the embedded
/// signature sections.
///
/// # Errors
///
/// Returns [`TrustGrantError::CanonicalizationFailure`] when serialization of
/// the canonical signable payload fails.
pub fn canonicalize_transition_proposal(
    raw_document: &RawOwnershipTransitionDocument,
    profile: CanonicalizationProfile,
) -> Result<CanonicalOwnershipTransitionBytes, TrustGrantError> {
    match profile {
        CanonicalizationProfile::Rfc8785 => canonicalize_transition_proposal_v0(raw_document),
    }
}

/// Produces deterministic signable bytes for successor acceptance.
///
/// The successor signs the full accepted transition payload:
/// - the proposed transfer payload
/// - the predecessor signature proof
/// - the acceptance timestamp
/// - the successor acceptance key id
///
/// The successor signature itself is excluded.
///
/// # Errors
///
/// Returns [`TrustGrantError::CanonicalizationFailure`] when serialization of
/// the canonical accepted payload fails.
pub fn canonicalize_transition_acceptance(
    raw_document: &RawOwnershipTransitionDocument,
    profile: CanonicalizationProfile,
) -> Result<CanonicalOwnershipTransitionBytes, TrustGrantError> {
    match profile {
        CanonicalizationProfile::Rfc8785 => canonicalize_transition_acceptance_v0(raw_document),
    }
}

fn canonicalize_transition_proposal_v0(
    raw_document: &RawOwnershipTransitionDocument,
) -> Result<CanonicalOwnershipTransitionBytes, TrustGrantError> {
    let mut canonical_bytes = Vec::with_capacity(768);
    write_transition_proposal(&mut canonical_bytes, raw_document)?;

    Ok(CanonicalOwnershipTransitionBytes(canonical_bytes))
}

fn canonicalize_transition_acceptance_v0(
    raw_document: &RawOwnershipTransitionDocument,
) -> Result<CanonicalOwnershipTransitionBytes, TrustGrantError> {
    let mut canonical_bytes = Vec::with_capacity(896);
    write_transition_acceptance(&mut canonical_bytes, raw_document)?;

    Ok(CanonicalOwnershipTransitionBytes(canonical_bytes))
}

fn write_transition_proposal(
    writer: &mut Vec<u8>,
    raw_document: &RawOwnershipTransitionDocument,
) -> Result<(), TrustGrantError> {
    write_bytes(writer, b"{")?;
    write_resource_scope_field(
        writer,
        "canonical_resource_scope",
        &raw_document.canonical_resource_scope,
    )?;
    write_bytes(writer, b",")?;
    write_datetime_field(writer, "effective_at", raw_document.effective_at)?;
    write_bytes(writer, b",")?;
    write_json_string_field(writer, "from_authority", &raw_document.from_authority)?;
    write_bytes(writer, b",")?;
    write_global_constraints_field(
        writer,
        "global_constraints",
        raw_document.global_constraints.as_ref(),
    )?;
    write_bytes(writer, b",")?;
    write_json_string_field(writer, "origin_authority", &raw_document.origin_authority)?;
    write_bytes(writer, b",")?;
    write_u64_field(writer, "revision", raw_document.revision)?;
    write_bytes(writer, b",")?;
    write_optional_string_field(
        writer,
        "supersedes_transition_id",
        raw_document.supersedes_transition_id.as_deref(),
    )?;
    write_bytes(writer, b",")?;
    write_json_string_field(writer, "to_authority", &raw_document.to_authority)?;
    write_bytes(writer, b",")?;
    write_json_string_field(writer, "transition_id", &raw_document.transition_id)?;
    write_bytes(writer, b",")?;
    write_json_string_field(
        writer,
        "transition_series_id",
        &raw_document.transition_series_id,
    )?;
    write_bytes(writer, b",")?;
    write_u8_field(writer, "version", raw_document.version)?;
    write_bytes(writer, b"}")
}

fn write_transition_acceptance(
    writer: &mut Vec<u8>,
    raw_document: &RawOwnershipTransitionDocument,
) -> Result<(), TrustGrantError> {
    write_bytes(writer, b"{")?;
    write_resource_scope_field(
        writer,
        "canonical_resource_scope",
        &raw_document.canonical_resource_scope,
    )?;
    write_bytes(writer, b",")?;
    write_datetime_field(writer, "effective_at", raw_document.effective_at)?;
    write_bytes(writer, b",")?;
    write_json_string_field(writer, "from_authority", &raw_document.from_authority)?;
    write_bytes(writer, b",")?;
    write_global_constraints_field(
        writer,
        "global_constraints",
        raw_document.global_constraints.as_ref(),
    )?;
    write_bytes(writer, b",")?;
    write_json_string_field(writer, "origin_authority", &raw_document.origin_authority)?;
    write_bytes(writer, b",")?;
    write_signature_field(
        writer,
        "predecessor_signature",
        &raw_document.predecessor_signature,
    )?;
    write_bytes(writer, b",")?;
    write_u64_field(writer, "revision", raw_document.revision)?;
    write_bytes(writer, b",")?;
    write_acceptance_field(
        writer,
        "successor_acceptance",
        &raw_document.successor_acceptance,
    )?;
    write_bytes(writer, b",")?;
    write_optional_string_field(
        writer,
        "supersedes_transition_id",
        raw_document.supersedes_transition_id.as_deref(),
    )?;
    write_bytes(writer, b",")?;
    write_json_string_field(writer, "to_authority", &raw_document.to_authority)?;
    write_bytes(writer, b",")?;
    write_json_string_field(writer, "transition_id", &raw_document.transition_id)?;
    write_bytes(writer, b",")?;
    write_json_string_field(
        writer,
        "transition_series_id",
        &raw_document.transition_series_id,
    )?;
    write_bytes(writer, b",")?;
    write_u8_field(writer, "version", raw_document.version)?;
    write_bytes(writer, b"}")
}

fn write_resource_scope_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    resource_scope: &RawOwnershipTransitionResourceScope,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;
    write_bytes(writer, b"{")?;
    write_resource_type_map_field(writer, "types", &resource_scope.types)?;
    write_bytes(writer, b"}")
}

fn write_resource_type_map_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    resource_types: &BTreeMap<Utf16Key, RawOwnershipTransitionResourceType>,
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
    resource_type: &RawOwnershipTransitionResourceType,
) -> Result<(), TrustGrantError> {
    write_bytes(writer, b"{")?;
    write_bool_field(writer, "all", resource_type.all)?;
    write_bytes(writer, b",")?;
    write_selectors_field(writer, "allow", resource_type.allow.as_deref())?;
    write_bytes(writer, b",")?;
    write_selectors_field(writer, "deny", resource_type.deny.as_deref())?;
    write_bytes(writer, b"}")
}

fn write_selectors_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    selectors: Option<&[RawOwnershipTransitionSelector]>,
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

fn write_selector(
    writer: &mut Vec<u8>,
    selector: &RawOwnershipTransitionSelector,
) -> Result<(), TrustGrantError> {
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

fn write_global_constraints_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    constraints: Option<&RawOwnershipTransitionGlobalConstraints>,
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
    time_window: Option<&RawOwnershipTransitionTimeWindow>,
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

fn write_signature_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    signature: &RawOwnershipTransitionSignature,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;
    write_bytes(writer, b"{")?;
    write_json_string_field(writer, "key_id", &signature.key_id)?;
    write_bytes(writer, b",")?;
    write_json_string_field(writer, "signature", &signature.signature)?;
    write_bytes(writer, b"}")
}

fn write_acceptance_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    acceptance: &RawOwnershipTransitionAcceptance,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;
    write_bytes(writer, b"{")?;
    write_datetime_field(writer, "accepted_at", acceptance.accepted_at)?;
    write_bytes(writer, b",")?;
    write_json_string_field(writer, "key_id", &acceptance.key_id)?;
    write_bytes(writer, b"}")
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

fn write_bool_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    value: bool,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;
    write_bool(writer, value)
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

fn write_u64_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    value: u64,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;
    write_u64(writer, value)
}

fn write_u8_field(
    writer: &mut Vec<u8>,
    field_name: &str,
    value: u8,
) -> Result<(), TrustGrantError> {
    write_field_name(writer, field_name)?;
    write_u8(writer, value)
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

fn write_u8(writer: &mut Vec<u8>, value: u8) -> Result<(), TrustGrantError> {
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

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use serde_json::{Value, json};

    use super::{canonicalize_transition_acceptance, canonicalize_transition_proposal};
    use trustgrant_document::RawOwnershipTransitionDocument;
    use trustgrant_domain::CanonicalizationProfile;

    fn parse_document(
        predecessor_signature: &str,
        successor_signature: &str,
    ) -> RawOwnershipTransitionDocument {
        let json = json!({
            "transition_id": "tgt_123e4567-e89b-12d3-a456-426614174000",
            "version": 0,
            "transition_series_id": "tgts_123e4567-e89b-12d3-a456-426614174001",
            "revision": 1,
            "supersedes_transition_id": null,
            "origin_authority": "https://origin.example.com",
            "from_authority": "https://origin.example.com",
            "to_authority": "https://successor.example.com",
            "canonical_resource_scope": {
                "types": {
                    "item": {
                        "all": false,
                        "allow": [{
                            "kind": "id",
                            "all": false,
                            "values": ["canonical_item_1"],
                            "expressions": null
                        }],
                        "deny": null
                    }
                }
            },
            "global_constraints": null,
            "effective_at": "2026-04-07T12:00:00Z",
            "predecessor_signature": {
                "key_id": "root-key-1",
                "signature": predecessor_signature
            },
            "successor_acceptance": {
                "accepted_at": "2026-04-07T11:00:00Z",
                "key_id": "successor-key-1",
                "signature": successor_signature
            }
        })
        .to_string();

        match RawOwnershipTransitionDocument::parse_json_str(&json) {
            Ok(value) => value,
            Err(error) => panic!("transition document should parse: {error}"),
        }
    }

    fn complex_document() -> RawOwnershipTransitionDocument {
        let json = json!({
            "transition_id": "tgt_123e4567-e89b-12d3-a456-426614174010",
            "version": 0,
            "transition_series_id": "tgts_123e4567-e89b-12d3-a456-426614174011",
            "revision": 2,
            "supersedes_transition_id": "tgt_123e4567-e89b-12d3-a456-426614174009",
            "origin_authority": "https://origin.example.com",
            "from_authority": "https://origin.example.com",
            "to_authority": "https://successor.example.com",
            "canonical_resource_scope": {
                "types": {
                    "z_item": {
                        "all": false,
                        "allow": [{
                            "kind": "id",
                            "all": false,
                            "values": ["canonical_item_2", "canonical_item_3"],
                            "expressions": null
                        }],
                        "deny": null
                    },
                    "ä_item": {
                        "all": false,
                        "allow": [{
                            "kind": "id",
                            "all": false,
                            "values": ["canonical_item_1"],
                            "expressions": null
                        }],
                        "deny": null
                    }
                }
            },
            "global_constraints": {
                "time": {
                    "not_before": "2026-04-07T11:00:00Z",
                    "not_after": "2026-04-07T13:00:00Z"
                }
            },
            "effective_at": "2026-04-07T12:00:00Z",
            "predecessor_signature": {
                "key_id": "origin-key-1",
                "signature": "origin-signature"
            },
            "successor_acceptance": {
                "accepted_at": "2026-04-07T11:30:00Z",
                "key_id": "successor-key-1",
                "signature": "successor-signature"
            }
        })
        .to_string();

        match RawOwnershipTransitionDocument::parse_json_str(&json) {
            Ok(value) => value,
            Err(error) => panic!("complex transition document should parse: {error}"),
        }
    }

    fn proposal_oracle_bytes(raw_document: &RawOwnershipTransitionDocument) -> Vec<u8> {
        let mut proposal = match serde_json::to_value(raw_document) {
            Ok(value) => value,
            Err(error) => panic!("proposal oracle serialization should succeed: {error}"),
        };
        let proposal_object = proposal
            .as_object_mut()
            .unwrap_or_else(|| panic!("serialized transition should be one JSON object"));
        proposal_object.remove("predecessor_signature");
        proposal_object.remove("successor_acceptance");

        match serde_jcs::to_vec(&proposal) {
            Ok(value) => value,
            Err(error) => panic!("proposal oracle canonicalization should succeed: {error}"),
        }
    }

    fn acceptance_oracle_bytes(raw_document: &RawOwnershipTransitionDocument) -> Vec<u8> {
        let mut acceptance = match serde_json::to_value(raw_document) {
            Ok(value) => value,
            Err(error) => panic!("acceptance oracle serialization should succeed: {error}"),
        };
        let successor_acceptance = acceptance
            .get_mut("successor_acceptance")
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| {
                panic!("serialized transition should contain successor_acceptance object")
            });
        successor_acceptance.remove("signature");

        match serde_jcs::to_vec(&acceptance) {
            Ok(value) => value,
            Err(error) => panic!("acceptance oracle canonicalization should succeed: {error}"),
        }
    }

    #[test]
    fn proposal_canonicalization_excludes_signature_sections() {
        let left = parse_document("sig-a", "sig-b");
        let right = parse_document("sig-z", "sig-y");

        let left_bytes =
            match canonicalize_transition_proposal(&left, CanonicalizationProfile::Rfc8785) {
                Ok(value) => value,
                Err(error) => panic!("proposal canonicalization should succeed: {error}"),
            };
        let right_bytes =
            match canonicalize_transition_proposal(&right, CanonicalizationProfile::Rfc8785) {
                Ok(value) => value,
                Err(error) => panic!("proposal canonicalization should succeed: {error}"),
            };

        assert_eq!(left_bytes, right_bytes);
    }

    #[test]
    fn acceptance_canonicalization_excludes_only_successor_signature() {
        let left = parse_document("sig-a", "sig-b");
        let right = parse_document("sig-a", "sig-c");

        let left_bytes =
            match canonicalize_transition_acceptance(&left, CanonicalizationProfile::Rfc8785) {
                Ok(value) => value,
                Err(error) => panic!("acceptance canonicalization should succeed: {error}"),
            };
        let right_bytes =
            match canonicalize_transition_acceptance(&right, CanonicalizationProfile::Rfc8785) {
                Ok(value) => value,
                Err(error) => panic!("acceptance canonicalization should succeed: {error}"),
            };

        assert_eq!(left_bytes, right_bytes);
    }

    #[test]
    fn proposal_canonicalization_matches_serde_jcs_oracle_for_complex_document() {
        let raw_document = complex_document();

        let specialized =
            match canonicalize_transition_proposal(&raw_document, CanonicalizationProfile::Rfc8785)
            {
                Ok(value) => value,
                Err(error) => panic!("proposal canonicalization should succeed: {error}"),
            };
        let oracle = proposal_oracle_bytes(&raw_document);

        assert_eq!(specialized.as_slice(), oracle.as_slice());
    }

    #[test]
    fn acceptance_canonicalization_matches_serde_jcs_oracle_for_complex_document() {
        let raw_document = complex_document();

        let specialized = match canonicalize_transition_acceptance(
            &raw_document,
            CanonicalizationProfile::Rfc8785,
        ) {
            Ok(value) => value,
            Err(error) => panic!("acceptance canonicalization should succeed: {error}"),
        };
        let oracle = acceptance_oracle_bytes(&raw_document);

        assert_eq!(specialized.as_slice(), oracle.as_slice());
    }
}
