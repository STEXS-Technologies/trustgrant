#![allow(clippy::panic)]

use chrono::{TimeZone, Utc};
use trustgrant::{
    AuthorityId, BundleRevocationProof, EvaluationDenyReason, EvaluationEngine, EvaluationRequest,
    ProofFinality, RawOwnershipTransitionDocument, RequestedCapability, RequestedOperation,
    ResourceContext, RevocationFreshnessPolicy, RevocationSourceKind, SignatureVerificationRequest,
    SignatureVerifier, TrustGrantError, TrustGrantProofBundle, VerificationContext,
    VerificationPipeline, VerificationPosture, parse_authority_discovery_document,
    parse_revocation_status_proof,
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

const SUCCESSOR_TRUSTGRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174300",
  "version":0,
  "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174301",
  "revision":1,
  "supersedes":null,
  "supersession_policy":"coexist",
  "issuer_authority":"https://successor.example.com",
  "origin_authority":"https://origin.example.com",
  "active_owning_authority":"https://successor.example.com",
  "key_id":"successor-key-1",
  "target_scope":{"all":false,"allow":[{"kind":"authority","all":false,"values":["https://target.example.com"],"expressions":null}],"deny":null},
  "capabilities":{"recognize":true,"mint":false},
  "default_audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":null}],
  "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["weapon_alpha"],"expressions":null}],"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
  "global_constraints":null,
  "revocation":{"revocable":true,"revocation_endpoint":"https://successor.example.com/revocation"},
  "issued_at":"2026-04-07T12:30:00Z",
  "signature":"base64-signature",
  "issuer_principal":null
}"#;

const OWNERSHIP_TRANSITION_JSON: &str = r#"{
  "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174400",
  "version":0,
  "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174401",
  "revision":1,
  "supersedes_transition_id":null,
  "origin_authority":"https://origin.example.com",
  "from_authority":"https://origin.example.com",
  "to_authority":"https://successor.example.com",
  "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["weapon_alpha"],"expressions":null}],"deny":null}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T11:00:00Z","not_after":"2026-04-07T14:00:00Z"}},
  "effective_at":"2026-04-07T12:00:00Z",
  "predecessor_signature":{"key_id":"origin-key-1","signature":"origin-signature"},
  "successor_acceptance":{"accepted_at":"2026-04-07T11:30:00Z","key_id":"successor-key-1","signature":"successor-signature"}
}"#;

const SUCCESSOR_REVOCATION_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174300",
  "status":"active",
  "checked_at":"2026-04-07T12:30:00Z"
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

/// Build a proof bundle containing both origin and successor discovery documents,
/// the revocation proof, and the ownership transition chain.
fn ownership_pipeline_bundle() -> TrustGrantProofBundle {
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
            "tg_123e4567-e89b-12d3-a456-426614174300"
                .parse()
                .unwrap_or_else(|error| panic!("trustgrant id should parse: {error}")),
            vec![
                RawOwnershipTransitionDocument::parse_json_str(OWNERSHIP_TRANSITION_JSON)
                    .unwrap_or_else(|error| panic!("transition proof should parse: {error}")),
            ],
        )
        .unwrap_or_else(|error| panic!("ownership chain should insert: {error}"));
    proof_bundle
}

#[test]
fn full_ownership_transition_pipeline_verifies_and_evaluates() {
    let proof_bundle = ownership_pipeline_bundle();
    let verifier = FakeSignatureVerifier;

    // Step 1-3: Verify the successor trustgrant with ownership transition chain
    let artifacts = VerificationPipeline::new()
        .verify_json_str_with_sources(
            SUCCESSOR_TRUSTGRANT_JSON,
            &verifier,
            proof_bundle.as_sources(),
            VerificationContext::new(
                fixed_timestamp(2026, 4, 7, 12, 30, 0),
                VerificationPosture::Online,
            ),
        )
        .unwrap_or_else(|error| panic!("full pipeline verification should succeed: {error}"));

    // Step 4: Verify the trustgrant has the correct ownership chain metadata
    let verified = artifacts.verified_grant();
    assert_eq!(
        verified
            .metadata()
            .ownership()
            .active_owning_authority()
            .as_str(),
        "https://successor.example.com"
    );
    assert_eq!(
        verified.metadata().ownership().origin_authority().as_str(),
        "https://origin.example.com"
    );
    assert!(
        verified
            .metadata()
            .ownership()
            .transition_chain_tip()
            .is_some()
    );

    // Step 5: Evaluate the verified grant with a matching request
    let engine = EvaluationEngine::new();
    let mut resource = ResourceContext::new("item")
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("id", "weapon_alpha")
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));
    let request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        AuthorityId::new("https://target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new("https://audience.example.com")
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));

    let decision = engine.evaluate(verified, &request);
    assert!(decision.is_allowed());
}

#[test]
fn ownership_transition_pipeline_rejects_without_transition_chain() {
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
    // Intentionally omit the ownership transition chain

    let result = VerificationPipeline::new().verify_json_str_with_sources(
        SUCCESSOR_TRUSTGRANT_JSON,
        &FakeSignatureVerifier,
        proof_bundle.as_sources(),
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
            VerificationPosture::Online,
        ),
    );

    assert_eq!(
        result,
        Err(TrustGrantError::MissingOwnershipTransitionChain)
    );
}

#[test]
fn ownership_transition_pipeline_rejects_with_wrong_successor_authority() {
    // Build a successor trustgrant that claims a different successor authority
    let wrong_successor_json = SUCCESSOR_TRUSTGRANT_JSON
        .replace(
            r#""issuer_authority":"https://successor.example.com""#,
            r#""issuer_authority":"https://wrong.example.com""#,
        )
        .replace(
            r#""active_owning_authority":"https://successor.example.com""#,
            r#""active_owning_authority":"https://wrong.example.com""#,
        );

    let proof_bundle = ownership_pipeline_bundle();

    let result = VerificationPipeline::new().verify_json_str_with_sources(
        &wrong_successor_json,
        &FakeSignatureVerifier,
        proof_bundle.as_sources(),
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
            VerificationPosture::Online,
        ),
    );

    assert!(result.is_err());
}

#[test]
fn ownership_transition_pipeline_rejects_evaluation_with_audience_mismatch() {
    let proof_bundle = ownership_pipeline_bundle();
    let artifacts = VerificationPipeline::new()
        .verify_json_str_with_sources(
            SUCCESSOR_TRUSTGRANT_JSON,
            &FakeSignatureVerifier,
            proof_bundle.as_sources(),
            VerificationContext::new(
                fixed_timestamp(2026, 4, 7, 12, 30, 0),
                VerificationPosture::Online,
            ),
        )
        .unwrap_or_else(|error| panic!("verification should succeed: {error}"));

    let engine = EvaluationEngine::new();
    let mut resource = ResourceContext::new("item")
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("id", "weapon_alpha")
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));
    let request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        AuthorityId::new("https://target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new("https://wrong-audience.example.com")
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));

    let decision = engine.evaluate(artifacts.verified_grant(), &request);
    assert_eq!(
        decision.deny_reason(),
        Some(EvaluationDenyReason::AudienceNotAllowed)
    );
}
