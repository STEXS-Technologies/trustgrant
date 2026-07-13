#![allow(clippy::panic)]

use trustgrant::{RawTrustGrantDocument, ValidatedTrustGrantDocument};

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
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
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
