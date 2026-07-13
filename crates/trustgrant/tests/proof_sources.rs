#![allow(clippy::panic)]

use chrono::{TimeZone, Utc};
use trustgrant::{
    AuthorityId, BundleRevocationProof, EvaluationEngine, EvaluationRequest, ProofFinality,
    RawOwnershipTransitionDocument, RequestedCapability, RequestedOperation, ResourceContext,
    RevocationFreshnessPolicy, RevocationSourceKind, SignatureVerificationRequest,
    SignatureVerifier, TrustGrantError, TrustGrantProofBundle, VerificationContext,
    VerificationPipeline, VerificationPosture, parse_authority_discovery_document,
    parse_delegated_principal_key_document, parse_revocation_status_proof,
};

#[derive(Debug, Default)]
struct FakeSignatureVerifier;

impl SignatureVerifier for FakeSignatureVerifier {
    fn verify_signature(
        &self,
        request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), TrustGrantError> {
        if request.signature_profile().format().as_str() == "jcs+ed25519"
            && request.signature_profile().canonicalization().as_str() == "RFC8785"
            && !request.signature().is_empty()
            && !request.canonical_bytes().is_empty()
        {
            Ok(())
        } else {
            Err(TrustGrantError::SignatureVerificationFailed)
        }
    }
}

#[test]
fn source_driven_verification_resolves_delegated_principal_from_parsed_discovery_docs() {
    let mut proof_bundle = TrustGrantProofBundle::new();
    proof_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(DELEGATED_ROOT_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("root discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("root discovery should insert: {error}"));
    proof_bundle
        .insert_delegated_principal_document(
            parse_delegated_principal_key_document(DELEGATED_PRINCIPAL_KEYS_JSON)
                .unwrap_or_else(|error| panic!("delegated discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("delegated discovery should insert: {error}"));
    proof_bundle
        .insert_revocation_proof(BundleRevocationProof::new(
            parse_revocation_status_proof(DELEGATED_REVOCATION_JSON)
                .unwrap_or_else(|error| panic!("revocation proof should parse: {error}")),
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            RevocationFreshnessPolicy::new(120, 900)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        ))
        .unwrap_or_else(|error| panic!("revocation proof should insert: {error}"));
    let artifacts = VerificationPipeline::new()
        .verify_json_str_with_sources(
            DELEGATED_TRUSTGRANT_JSON,
            &FakeSignatureVerifier,
            proof_bundle.as_sources(),
            VerificationContext::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
            ),
        )
        .unwrap_or_else(|error| panic!("source-driven verification should succeed: {error}"));

    assert_eq!(
        artifacts
            .verified_grant()
            .metadata()
            .signer_binding()
            .delegated_principal()
            .map(|principal| principal.id().as_str()),
        Some("issuer-worker")
    );
}

#[test]
fn source_driven_verification_accepts_verified_transition_chain() {
    let mut proof_bundle = TrustGrantProofBundle::new();
    proof_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(ORIGIN_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("origin discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("origin discovery should insert: {error}"));
    proof_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(SUCCESSOR_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("successor discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("successor discovery should insert: {error}"));
    proof_bundle
        .insert_revocation_proof(BundleRevocationProof::new(
            parse_revocation_status_proof(SUCCESSOR_REVOCATION_JSON)
                .unwrap_or_else(|error| panic!("revocation proof should parse: {error}")),
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            RevocationFreshnessPolicy::new(120, 900)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        ))
        .unwrap_or_else(|error| panic!("revocation proof should insert: {error}"));
    proof_bundle
        .insert_ownership_transition_chain(
            "tg_123e4567-e89b-12d3-a456-426614174100"
                .parse()
                .unwrap_or_else(|error| panic!("trustgrant id should parse: {error}")),
            vec![
                RawOwnershipTransitionDocument::parse_json_str(OWNERSHIP_TRANSITION_JSON)
                    .unwrap_or_else(|error| panic!("transition proof should parse: {error}")),
            ],
        )
        .unwrap_or_else(|error| panic!("ownership chain should insert: {error}"));
    let artifacts = VerificationPipeline::new()
        .verify_json_str_with_sources(
            SUCCESSOR_OWNERSHIP_TRUSTGRANT_JSON,
            &FakeSignatureVerifier,
            proof_bundle.as_sources(),
            VerificationContext::new(
                fixed_timestamp(2026, 4, 7, 12, 30, 0),
                VerificationPosture::Online,
            ),
        )
        .unwrap_or_else(|error| panic!("source-driven verification should succeed: {error}"));

    assert_eq!(
        artifacts
            .verified_grant()
            .metadata()
            .ownership()
            .active_owning_authority()
            .as_str(),
        "https://successor.example.com"
    );
    assert_eq!(
        artifacts
            .verified_grant()
            .metadata()
            .ownership()
            .transition_chain_tip()
            .map(|transition_id| transition_id.to_string()),
        Some("tgt_123e4567-e89b-12d3-a456-426614174200".to_owned())
    );
}

#[test]
fn offline_verification_accepts_trusted_snapshot_revocation_from_bundle() {
    let mut proof_bundle = TrustGrantProofBundle::new();
    proof_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(DELEGATED_ROOT_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("root discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("root discovery should insert: {error}"));
    proof_bundle
        .insert_delegated_principal_document(
            parse_delegated_principal_key_document(DELEGATED_PRINCIPAL_KEYS_JSON)
                .unwrap_or_else(|error| panic!("delegated discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("delegated discovery should insert: {error}"));
    proof_bundle
        .insert_revocation_proof(BundleRevocationProof::new(
            parse_revocation_status_proof(DELEGATED_REVOCATION_JSON)
                .unwrap_or_else(|error| panic!("revocation proof should parse: {error}")),
            RevocationSourceKind::ProofBundle,
            ProofFinality::TrustedSnapshot,
            RevocationFreshnessPolicy::new(120, 900)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        ))
        .unwrap_or_else(|error| panic!("revocation proof should insert: {error}"));

    let result = VerificationPipeline::new().verify_json_str_with_sources(
        DELEGATED_TRUSTGRANT_JSON,
        &FakeSignatureVerifier,
        proof_bundle.as_sources(),
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            VerificationPosture::Offline,
        ),
    );

    assert!(result.is_ok());
}

#[test]
fn offline_verification_rejects_live_api_revocation_evidence() {
    let mut proof_bundle = TrustGrantProofBundle::new();
    proof_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(DELEGATED_ROOT_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("root discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("root discovery should insert: {error}"));
    proof_bundle
        .insert_delegated_principal_document(
            parse_delegated_principal_key_document(DELEGATED_PRINCIPAL_KEYS_JSON)
                .unwrap_or_else(|error| panic!("delegated discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("delegated discovery should insert: {error}"));
    proof_bundle
        .insert_revocation_proof(BundleRevocationProof::new(
            parse_revocation_status_proof(DELEGATED_REVOCATION_JSON)
                .unwrap_or_else(|error| panic!("revocation proof should parse: {error}")),
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            RevocationFreshnessPolicy::new(120, 900)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        ))
        .unwrap_or_else(|error| panic!("revocation proof should insert: {error}"));

    let result = VerificationPipeline::new().verify_json_str_with_sources(
        DELEGATED_TRUSTGRANT_JSON,
        &FakeSignatureVerifier,
        proof_bundle.as_sources(),
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            VerificationPosture::Offline,
        ),
    );

    assert_eq!(
        result,
        Err(TrustGrantError::VerificationPostureRequiresNonLiveRevocation)
    );
}

#[test]
fn cached_verification_rejects_live_api_revocation_evidence() {
    let mut proof_bundle = TrustGrantProofBundle::new();
    proof_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(DELEGATED_ROOT_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("root discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("root discovery should insert: {error}"));
    proof_bundle
        .insert_delegated_principal_document(
            parse_delegated_principal_key_document(DELEGATED_PRINCIPAL_KEYS_JSON)
                .unwrap_or_else(|error| panic!("delegated discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("delegated discovery should insert: {error}"));
    proof_bundle
        .insert_revocation_proof(BundleRevocationProof::new(
            parse_revocation_status_proof(DELEGATED_REVOCATION_JSON)
                .unwrap_or_else(|error| panic!("revocation proof should parse: {error}")),
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            RevocationFreshnessPolicy::new(120, 900)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        ))
        .unwrap_or_else(|error| panic!("revocation proof should insert: {error}"));

    let result = VerificationPipeline::new().verify_json_str_with_sources(
        DELEGATED_TRUSTGRANT_JSON,
        &FakeSignatureVerifier,
        proof_bundle.as_sources(),
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            VerificationPosture::Cached,
        ),
    );

    assert_eq!(
        result,
        Err(TrustGrantError::VerificationPostureRequiresNonLiveRevocation)
    );
}

#[test]
fn cached_verification_rejects_live_chain_state_revocation_evidence() {
    let mut proof_bundle = TrustGrantProofBundle::new();
    proof_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(DELEGATED_ROOT_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("root discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("root discovery should insert: {error}"));
    proof_bundle
        .insert_delegated_principal_document(
            parse_delegated_principal_key_document(DELEGATED_PRINCIPAL_KEYS_JSON)
                .unwrap_or_else(|error| panic!("delegated discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("delegated discovery should insert: {error}"));
    proof_bundle
        .insert_revocation_proof(BundleRevocationProof::new(
            parse_revocation_status_proof(DELEGATED_REVOCATION_JSON)
                .unwrap_or_else(|error| panic!("revocation proof should parse: {error}")),
            RevocationSourceKind::ChainState,
            ProofFinality::Finalized,
            RevocationFreshnessPolicy::new(120, 900)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        ))
        .unwrap_or_else(|error| panic!("revocation proof should insert: {error}"));

    let result = VerificationPipeline::new().verify_json_str_with_sources(
        DELEGATED_TRUSTGRANT_JSON,
        &FakeSignatureVerifier,
        proof_bundle.as_sources(),
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            VerificationPosture::Cached,
        ),
    );

    assert_eq!(
        result,
        Err(TrustGrantError::VerificationPostureRequiresNonLiveRevocation)
    );
}

#[test]
fn cached_verification_accepts_trusted_snapshot_revocation_from_bundle() {
    let mut proof_bundle = TrustGrantProofBundle::new();
    proof_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(DELEGATED_ROOT_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("root discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("root discovery should insert: {error}"));
    proof_bundle
        .insert_delegated_principal_document(
            parse_delegated_principal_key_document(DELEGATED_PRINCIPAL_KEYS_JSON)
                .unwrap_or_else(|error| panic!("delegated discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("delegated discovery should insert: {error}"));
    proof_bundle
        .insert_revocation_proof(BundleRevocationProof::new(
            parse_revocation_status_proof(DELEGATED_REVOCATION_JSON)
                .unwrap_or_else(|error| panic!("revocation proof should parse: {error}")),
            RevocationSourceKind::ProofBundle,
            ProofFinality::TrustedSnapshot,
            RevocationFreshnessPolicy::new(120, 900)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        ))
        .unwrap_or_else(|error| panic!("revocation proof should insert: {error}"));

    let result = VerificationPipeline::new().verify_json_str_with_sources(
        DELEGATED_TRUSTGRANT_JSON,
        &FakeSignatureVerifier,
        proof_bundle.as_sources(),
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            VerificationPosture::Cached,
        ),
    );

    assert!(result.is_ok());
}

#[test]
fn source_driven_verification_accepts_non_revocable_grant_without_revocation_proof() {
    let mut proof_bundle = TrustGrantProofBundle::new();
    proof_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(DELEGATED_ROOT_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("root discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("root discovery should insert: {error}"));
    proof_bundle
        .insert_delegated_principal_document(
            parse_delegated_principal_key_document(DELEGATED_PRINCIPAL_KEYS_JSON)
                .unwrap_or_else(|error| panic!("delegated discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("delegated discovery should insert: {error}"));

    let result = VerificationPipeline::new().verify_json_str_with_sources(
        NON_REVOCABLE_DELEGATED_TRUSTGRANT_JSON,
        &FakeSignatureVerifier,
        proof_bundle.as_sources(),
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            VerificationPosture::Online,
        ),
    );

    assert!(result.is_ok());
}

#[test]
fn source_driven_verification_rejects_delegated_signer_when_authority_does_not_support_delegation()
{
    let mut proof_bundle = TrustGrantProofBundle::new();
    proof_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(NO_DELEGATION_ROOT_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("root discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("root discovery should insert: {error}"));
    proof_bundle
        .insert_revocation_proof(BundleRevocationProof::new(
            parse_revocation_status_proof(DELEGATED_REVOCATION_JSON)
                .unwrap_or_else(|error| panic!("revocation proof should parse: {error}")),
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            RevocationFreshnessPolicy::new(120, 900)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        ))
        .unwrap_or_else(|error| panic!("revocation proof should insert: {error}"));

    let result = VerificationPipeline::new().verify_json_str_with_sources(
        DELEGATED_TRUSTGRANT_JSON,
        &FakeSignatureVerifier,
        proof_bundle.as_sources(),
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            VerificationPosture::Online,
        ),
    );

    assert_eq!(result, Err(TrustGrantError::DelegationNotSupported));
}

#[test]
fn source_driven_verification_and_evaluation_allow_matching_request() {
    let mut proof_bundle = TrustGrantProofBundle::new();
    proof_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(DELEGATED_ROOT_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("root discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("root discovery should insert: {error}"));
    proof_bundle
        .insert_delegated_principal_document(
            parse_delegated_principal_key_document(DELEGATED_PRINCIPAL_KEYS_JSON)
                .unwrap_or_else(|error| panic!("delegated discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("delegated discovery should insert: {error}"));
    proof_bundle
        .insert_revocation_proof(BundleRevocationProof::new(
            parse_revocation_status_proof(DELEGATED_REVOCATION_JSON)
                .unwrap_or_else(|error| panic!("revocation proof should parse: {error}")),
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            RevocationFreshnessPolicy::new(120, 900)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        ))
        .unwrap_or_else(|error| panic!("revocation proof should insert: {error}"));

    let artifacts = VerificationPipeline::new()
        .verify_json_str_with_sources(
            DELEGATED_TRUSTGRANT_JSON,
            &FakeSignatureVerifier,
            proof_bundle.as_sources(),
            VerificationContext::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Online,
            ),
        )
        .unwrap_or_else(|error| panic!("source-driven verification should succeed: {error}"));
    let decision =
        EvaluationEngine::new().evaluate(artifacts.verified_grant(), &matching_request());

    assert!(decision.is_allowed());
}

const DELEGATED_ROOT_DISCOVERY_JSON: &str = r#"{
  "authority_id":"https://issuer.example.com",
  "keys":[
    {
      "key_id":"root-key-1",
      "algorithm":"ed25519",
      "public_key":"base64-root-public-key",
      "not_before":"2026-01-01T00:00:00Z",
      "not_after":"2027-01-01T00:00:00Z"
    }
  ],
  "signature_profile":{
    "format":"jcs+ed25519",
    "canonicalization":"RFC8785"
  },
  "delegation":{
    "principals_supported":true,
    "principal_key_endpoint":"https://issuer.example.com/.well-known/trustgrant/principals/{kind}/{id}"
  },
  "issued_at":"2026-04-07T12:00:00Z"
}"#;

const NO_DELEGATION_ROOT_DISCOVERY_JSON: &str = r#"{
  "authority_id":"https://issuer.example.com",
  "keys":[
    {
      "key_id":"root-key-1",
      "algorithm":"ed25519",
      "public_key":"base64-root-public-key",
      "not_before":"2026-01-01T00:00:00Z",
      "not_after":"2027-01-01T00:00:00Z"
    }
  ],
  "signature_profile":{
    "format":"jcs+ed25519",
    "canonicalization":"RFC8785"
  },
  "issued_at":"2026-04-07T12:00:00Z"
}"#;

const DELEGATED_PRINCIPAL_KEYS_JSON: &str = r#"{
  "authority_id":"https://issuer.example.com",
  "principal":{"kind":"service","id":"issuer-worker"},
  "keys":[
    {
      "key_id":"project-key-1",
      "algorithm":"ed25519",
      "public_key":"base64-delegated-public-key",
      "not_before":"2026-01-01T00:00:00Z",
      "not_after":"2027-01-01T00:00:00Z",
      "revoked":false
    }
  ]
}"#;

const DELEGATED_TRUSTGRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
  "version":0,
  "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
  "revision":1,
  "supersedes":null,
  "supersession_policy":"coexist",
  "issuer_authority":"https://issuer.example.com",
  "origin_authority":"https://issuer.example.com",
  "active_owning_authority":"https://issuer.example.com",
  "key_id":"project-key-1",
  "target_scope":{"all":true,"allow":null,"deny":null},
  "capabilities":{"recognize":true,"mint":false},
  "default_audience_scope":null,
  "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
  "global_constraints":null,
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

const NON_REVOCABLE_DELEGATED_TRUSTGRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174010",
  "version":0,
  "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174011",
  "revision":1,
  "supersedes":null,
  "supersession_policy":"coexist",
  "issuer_authority":"https://issuer.example.com",
  "origin_authority":"https://issuer.example.com",
  "active_owning_authority":"https://issuer.example.com",
  "key_id":"project-key-1",
  "target_scope":{"all":true,"allow":null,"deny":null},
  "capabilities":{"recognize":true,"mint":false},
  "default_audience_scope":null,
  "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
  "global_constraints":null,
  "revocation":{"revocable":false,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

const DELEGATED_REVOCATION_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
  "status":"active",
  "checked_at":"2026-04-07T12:00:00Z"
}"#;

const ORIGIN_DISCOVERY_JSON: &str = r#"{
  "authority_id":"https://origin.example.com",
  "keys":[
    {
      "key_id":"origin-key-1",
      "algorithm":"ed25519",
      "public_key":"base64-origin-public-key",
      "not_before":"2026-01-01T00:00:00Z",
      "not_after":"2027-01-01T00:00:00Z"
    }
  ],
  "signature_profile":{
    "format":"jcs+ed25519",
    "canonicalization":"RFC8785"
  },
  "issued_at":"2026-04-07T12:00:00Z"
}"#;

const SUCCESSOR_DISCOVERY_JSON: &str = r#"{
  "authority_id":"https://successor.example.com",
  "keys":[
    {
      "key_id":"successor-key-1",
      "algorithm":"ed25519",
      "public_key":"base64-successor-public-key",
      "not_before":"2026-01-01T00:00:00Z",
      "not_after":"2027-01-01T00:00:00Z"
    }
  ],
  "signature_profile":{
    "format":"jcs+ed25519",
    "canonicalization":"RFC8785"
  },
  "issued_at":"2026-04-07T12:00:00Z"
}"#;

const SUCCESSOR_OWNERSHIP_TRUSTGRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174100",
  "version":0,
  "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174101",
  "revision":1,
  "supersedes":null,
  "supersession_policy":"coexist",
  "issuer_authority":"https://successor.example.com",
  "origin_authority":"https://origin.example.com",
  "active_owning_authority":"https://successor.example.com",
  "key_id":"successor-key-1",
  "target_scope":{"all":true,"allow":null,"deny":null},
  "capabilities":{"recognize":true,"mint":false},
  "default_audience_scope":null,
  "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":null}],"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["custom:use"],"deny":null}}}},
  "global_constraints":null,
  "revocation":{"revocable":true,"revocation_endpoint":"https://successor.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":null
}"#;

const SUCCESSOR_REVOCATION_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174100",
  "status":"active",
  "checked_at":"2026-04-07T12:30:00Z"
}"#;

const OWNERSHIP_TRANSITION_JSON: &str = r#"{
  "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174200",
  "version":0,
  "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174201",
  "revision":1,
  "supersedes_transition_id":null,
  "origin_authority":"https://origin.example.com",
  "from_authority":"https://origin.example.com",
  "to_authority":"https://successor.example.com",
  "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":null}],"deny":null}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T11:00:00Z","not_after":"2026-04-07T13:00:00Z"}},
  "effective_at":"2026-04-07T12:00:00Z",
  "predecessor_signature":{"key_id":"origin-key-1","signature":"origin-signature"},
  "successor_acceptance":{"accepted_at":"2026-04-07T11:30:00Z","key_id":"successor-key-1","signature":"successor-signature"}
}"#;

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

fn matching_request() -> EvaluationRequest {
    let resource = ResourceContext::new("item")
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));

    EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        AuthorityId::new("https://target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new("https://audience.example.com")
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 12, 0, 30),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"))
}
