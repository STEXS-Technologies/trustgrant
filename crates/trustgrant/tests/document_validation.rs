#![allow(clippy::panic)]

use trustgrant::{
    CanonicalizationProfile, NormalizedTrustGrantDocument, RawTrustGrantDocument,
    ValidatedTrustGrantDocument, canonicalize_trustgrant, parse_authority_discovery_document,
};

const VALID_TRUSTGRANT_JSON: &str = r#"{
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
  "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":10,"max_per_user":1},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

#[test]
fn raw_document_parses_and_validates_end_to_end() {
    let raw = RawTrustGrantDocument::parse_json_str(VALID_TRUSTGRANT_JSON)
        .unwrap_or_else(|error| panic!("raw document should parse: {error}"));
    let validated = ValidatedTrustGrantDocument::try_from(raw)
        .unwrap_or_else(|error| panic!("validated document should succeed: {error}"));

    assert_eq!(
        validated.lineage().grant_series_id().to_string(),
        "tgs_123e4567-e89b-12d3-a456-426614174001"
    );
    assert_eq!(validated.default_audience_scope().len(), 1);
    assert_eq!(validated.signature(), "base64-signature");
}

#[test]
fn invalid_scope_shape_fails_validation_end_to_end() {
    let invalid_json = VALID_TRUSTGRANT_JSON.replace(
        r#""target_scope":{"all":false,"allow":[{"kind":"authority","all":false,"values":["https://target.example.com"],"expressions":null}],"deny":null}"#,
        r#""target_scope":{"all":false,"allow":null,"deny":null}"#,
    );

    let raw = RawTrustGrantDocument::parse_json_str(&invalid_json)
        .unwrap_or_else(|error| panic!("raw document should still parse: {error}"));
    let validated = ValidatedTrustGrantDocument::try_from(raw);

    assert!(validated.is_err());
}

// ---------------------------------------------------------------------------
// G8: NormalizedTrustGrantDocument construction and field access
// ---------------------------------------------------------------------------

#[test]
fn normalized_document_constructs_from_validated_and_exposes_fields() {
    let raw = RawTrustGrantDocument::parse_json_str(VALID_TRUSTGRANT_JSON)
        .unwrap_or_else(|e| panic!("raw document should parse: {e}"));
    let validated = ValidatedTrustGrantDocument::try_from(raw)
        .unwrap_or_else(|e| panic!("validated document should succeed: {e}"));

    let normalized: NormalizedTrustGrantDocument = validated.into();

    // Lineage fields
    assert_eq!(
        normalized.lineage().trustgrant_id().to_string(),
        "tg_123e4567-e89b-12d3-a456-426614174000"
    );
    assert_eq!(
        normalized.lineage().grant_series_id().to_string(),
        "tgs_123e4567-e89b-12d3-a456-426614174001"
    );
    assert_eq!(normalized.lineage().revision().get(), 1);

    // Issuer authority
    assert_eq!(
        normalized.issuer_authority().as_str(),
        "https://issuer.example.com"
    );

    // Key ID
    assert_eq!(normalized.key_id().as_str(), "root-key-1");

    // Target scope — all() returns bool, not Option<bool>
    assert!(!normalized.target_scope().all());
    assert_eq!(normalized.target_scope().allow().len(), 1);
    assert!(normalized.target_scope().deny().is_empty());

    // Capabilities
    assert!(normalized.capabilities().recognize());
    assert!(!normalized.capabilities().mint());

    // Default audience scope
    assert_eq!(normalized.default_audience_scope().len(), 1);
    assert_eq!(
        normalized.default_audience_scope()[0].authority_id().as_str(),
        "https://audience.example.com"
    );

    // Resource scope
    let resource_scope = normalized.resource_scope();
    assert_eq!(resource_scope.len(), 1);
    let item_type = resource_scope
        .get(&trustgrant::ResourceTypeName::new("item").unwrap_or_else(|e| panic!("ResourceTypeName: {e}")));
    assert!(item_type.is_some());

    // Global time window
    let time_window = normalized.global_time_window();
    assert!(time_window.is_some());
    let tw = time_window.unwrap_or_else(|| panic!("time window should be Some"));
    assert_eq!(
        tw.not_before().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        "2026-04-07T12:00:00Z"
    );

    // Revocation
    let revocation = normalized.revocation();
    assert!(revocation.is_some());
    let rev = revocation.unwrap_or_else(|| panic!("revocation should be Some"));
    assert!(rev.revocable());
    assert_eq!(
        rev.revocation_endpoint(),
        "https://issuer.example.com/revocation"
    );

    // Issued at
    assert_eq!(
        normalized.issued_at().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        "2026-04-07T12:00:00Z"
    );

    // Issuer principal
    let principal = normalized.issuer_principal();
    assert!(principal.is_some());
    let p = principal.unwrap_or_else(|| panic!("principal should be Some"));
    assert_eq!(p.kind().as_str(), "service");
    assert_eq!(p.id().as_str(), "issuer-worker");

    // Ownership authority state
    let ownership = normalized.ownership_authority_state();
    assert_eq!(ownership.origin_authority().as_str(), "https://issuer.example.com");
    assert_eq!(
        ownership.active_owning_authority().as_str(),
        "https://issuer.example.com"
    );
}

// ---------------------------------------------------------------------------
// G9: Negative discovery parsing — malformed JSON & missing fields
// ---------------------------------------------------------------------------

#[test]
fn parse_authority_discovery_malformed_json_returns_error() {
    let result = parse_authority_discovery_document(r#"this is not valid json at all"#);
    assert_eq!(result, Err(trustgrant::TrustGrantError::InvalidDiscoveryDocument));
}

#[test]
fn parse_authority_discovery_missing_keys_field_returns_error() {
    let json = r#"{
      "authority_id":"https://issuer.example.com",
      "signature_profile":{"format":"jcs+ed25519","canonicalization":"RFC8785"},
      "issued_at":"2026-04-07T12:00:00Z"
    }"#;
    let result = parse_authority_discovery_document(json);
    assert_eq!(result, Err(trustgrant::TrustGrantError::InvalidDiscoveryDocument));
}

#[test]
fn parse_authority_discovery_missing_authority_id_returns_error() {
    let json = r#"{
      "keys":[
        {"key_id":"root-key-1","algorithm":"ed25519","public_key":"base64-key","not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}
      ],
      "signature_profile":{"format":"jcs+ed25519","canonicalization":"RFC8785"},
      "issued_at":"2026-04-07T12:00:00Z"
    }"#;
    let result = parse_authority_discovery_document(json);
    assert_eq!(result, Err(trustgrant::TrustGrantError::InvalidDiscoveryDocument));
}

#[test]
fn parse_authority_discovery_missing_signature_profile_returns_error() {
    let json = r#"{
      "authority_id":"https://issuer.example.com",
      "keys":[
        {"key_id":"root-key-1","algorithm":"ed25519","public_key":"base64-key","not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}
      ],
      "issued_at":"2026-04-07T12:00:00Z"
    }"#;
    let result = parse_authority_discovery_document(json);
    assert_eq!(result, Err(trustgrant::TrustGrantError::InvalidDiscoveryDocument));
}

#[test]
fn parse_authority_discovery_unknown_field_returns_error() {
    let json = r#"{
      "authority_id":"https://issuer.example.com",
      "keys":[
        {"key_id":"root-key-1","algorithm":"ed25519","public_key":"base64-key","not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}
      ],
      "signature_profile":{"format":"jcs+ed25519","canonicalization":"RFC8785"},
      "issued_at":"2026-04-07T12:00:00Z",
      "unexpected_field":"boom"
    }"#;
    let result = parse_authority_discovery_document(json);
    assert_eq!(result, Err(trustgrant::TrustGrantError::InvalidDiscoveryDocument));
}

// ---------------------------------------------------------------------------
// G14: Canonicalization of a simple document
// ---------------------------------------------------------------------------

#[test]
fn canonicalization_of_simple_document_produces_non_empty_bytes() {
    let raw = RawTrustGrantDocument::parse_json_str(VALID_TRUSTGRANT_JSON)
        .unwrap_or_else(|e| panic!("raw document should parse: {e}"));
    let canonical = canonicalize_trustgrant(&raw, CanonicalizationProfile::Rfc8785)
        .unwrap_or_else(|e| panic!("canonicalization should succeed: {e}"));

    // Canonical output must be non-empty
    assert!(!canonical.as_slice().is_empty());

    // Canonical output must NOT contain the "signature" field
    let canonical_str = core::str::from_utf8(canonical.as_slice())
        .unwrap_or_else(|e| panic!("canonical bytes must be valid UTF-8: {e}"));
    assert!(
        !canonical_str.contains("\"signature\""),
        "canonical payload should omit the signature field: {canonical_str}",
    );
}

#[test]
fn canonicalization_is_deterministic() {
    let raw = RawTrustGrantDocument::parse_json_str(VALID_TRUSTGRANT_JSON)
        .unwrap_or_else(|e| panic!("raw document should parse: {e}"));
    let canonical_a = canonicalize_trustgrant(&raw, CanonicalizationProfile::Rfc8785)
        .unwrap_or_else(|e| panic!("first canonicalization: {e}"));
    let canonical_b = canonicalize_trustgrant(&raw, CanonicalizationProfile::Rfc8785)
        .unwrap_or_else(|e| panic!("second canonicalization: {e}"));

    // Same input must produce identical output every time
    assert_eq!(canonical_a, canonical_b);
}
