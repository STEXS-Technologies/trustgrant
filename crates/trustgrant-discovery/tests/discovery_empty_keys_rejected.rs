#![allow(clippy::panic)]

use trustgrant_discovery::parse_authority_discovery_document;

/// The fuzz target discovered that an authority discovery document with zero
/// keys could be parsed successfully, violating the invariant that every
/// document must have at least one signing key.
#[test]
fn discovery_document_empty_keys_rejected() {
    let json = r#"{
        "authority_id": "https://issuer.example.com",
        "keys": [],
        "signature_profile": {"format": "jcs+ed25519", "canonicalization": "RFC8785"},
        "issued_at": "2026-04-07T12:00:00Z"
    }"#;
    let result = parse_authority_discovery_document(json);
    assert!(
        result.is_err(),
        "Discovery document with empty keys must be rejected, got: {:?}",
        result
    );
}

/// Normal document with keys still parses and works.
#[test]
fn discovery_document_with_keys_parses_ok() {
    let json = r#"{
        "authority_id": "https://issuer.example.com",
        "keys": [{"key_id":"root-key-1","algorithm":"ed25519","public_key":"base64-key","not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}],
        "signature_profile": {"format": "jcs+ed25519", "canonicalization": "RFC8785"},
        "issued_at": "2026-04-07T12:00:00Z"
    }"#;
    let doc = parse_authority_discovery_document(json)
        .unwrap_or_else(|e| panic!("Valid discovery document should parse: {e}"));
    assert!(
        !doc.keys().is_empty(),
        "Document must have at least one key"
    );
}
