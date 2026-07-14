#![allow(clippy::panic)]

use chrono::{TimeZone, Utc};
use trustgrant::{
    AuthorityId, BundleRevocationProof, EvaluationDenyReason, EvaluationEngine, EvaluationRequest,
    ProofFinality, RequestedCapability, RequestedOperation, ResourceBinding, ResourceContext,
    ResourceRef, RevocationFreshnessPolicy, RevocationSourceKind, SignatureVerificationRequest,
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

const ROOT_DISCOVERY_JSON: &str = r#"{
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

const SIMPLE_TRUSTGRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174500",
  "version":0,
  "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174501",
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
  "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":true,"allow":null,"deny":null}}}},
  "global_constraints":null,
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":null
}"#;

const STALE_REVOCATION_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174500",
  "status":"active",
  "checked_at":"2026-04-01T00:00:00Z"
}"#;

const FRESH_REVOCATION_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174500",
  "status":"active",
  "checked_at":"2026-04-07T12:00:00Z"
}"#;

const REVOKED_REVOCATION_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174500",
  "status":"revoked",
  "checked_at":"2026-04-07T12:00:00Z"
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

fn offline_bundle(revocation_json: &str) -> TrustGrantProofBundle {
    let mut proof_bundle = TrustGrantProofBundle::new();
    proof_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(ROOT_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("discovery should insert: {error}"));
    proof_bundle
        .insert_revocation_proof(BundleRevocationProof::new(
            parse_revocation_status_proof(revocation_json)
                .unwrap_or_else(|error| panic!("revocation proof should parse: {error}")),
            RevocationSourceKind::ProofBundle,
            ProofFinality::TrustedSnapshot,
            RevocationFreshnessPolicy::new(120, 900)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        ))
        .unwrap_or_else(|error| panic!("revocation proof should insert: {error}"));
    proof_bundle
}

#[test]
fn offline_verification_succeeds_with_trusted_snapshot_revocation() {
    let proof_bundle = offline_bundle(FRESH_REVOCATION_JSON);

    let result = VerificationPipeline::new().verify_json_str_with_sources(
        SIMPLE_TRUSTGRANT_JSON,
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
fn offline_verification_rejects_stale_revocation_record() {
    // Even in offline posture, the freshness check on the revocation record
    // still applies. A stale record (checked well before the verification time
    // minus the freshness policy window) is rejected.
    let proof_bundle = offline_bundle(STALE_REVOCATION_JSON);

    let result = VerificationPipeline::new().verify_json_str_with_sources(
        SIMPLE_TRUSTGRANT_JSON,
        &FakeSignatureVerifier,
        proof_bundle.as_sources(),
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            VerificationPosture::Offline,
        ),
    );

    assert_eq!(result, Err(TrustGrantError::StaleRevocationRecord));
}

#[test]
fn offline_verification_rejects_live_api_revocation() {
    let mut proof_bundle = TrustGrantProofBundle::new();
    proof_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(ROOT_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("discovery should insert: {error}"));
    proof_bundle
        .insert_revocation_proof(BundleRevocationProof::new(
            parse_revocation_status_proof(FRESH_REVOCATION_JSON)
                .unwrap_or_else(|error| panic!("revocation proof should parse: {error}")),
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            RevocationFreshnessPolicy::new(120, 900)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        ))
        .unwrap_or_else(|error| panic!("revocation proof should insert: {error}"));

    let result = VerificationPipeline::new().verify_json_str_with_sources(
        SIMPLE_TRUSTGRANT_JSON,
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
fn offline_verification_detects_revoked_grant() {
    let proof_bundle = offline_bundle(REVOKED_REVOCATION_JSON);

    let artifacts = VerificationPipeline::new()
        .verify_json_str_with_sources(
            SIMPLE_TRUSTGRANT_JSON,
            &FakeSignatureVerifier,
            proof_bundle.as_sources(),
            VerificationContext::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Offline,
            ),
        )
        .unwrap_or_else(|error| panic!("verification should succeed: {error}"));

    let engine = EvaluationEngine::new();
    let resource = ResourceContext::new("item")
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    let request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(ResourceRef::new(
            AuthorityId::new("https://issuer.example.com")
                .unwrap_or_else(|error| panic!("origin authority should be valid: {error}")),
            "item".to_owned(),
        )),
        AuthorityId::new("https://target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 12, 0, 30),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));

    let outcome = engine.evaluate(artifacts.verified_grant(), &request);
    assert_eq!(
        outcome.decision().deny_reason(),
        Some(EvaluationDenyReason::Revoked)
    );
}

#[test]
fn offline_verification_rejects_chain_state_revocation() {
    let mut proof_bundle = TrustGrantProofBundle::new();
    proof_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(ROOT_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("discovery should insert: {error}"));
    proof_bundle
        .insert_revocation_proof(BundleRevocationProof::new(
            parse_revocation_status_proof(FRESH_REVOCATION_JSON)
                .unwrap_or_else(|error| panic!("revocation proof should parse: {error}")),
            RevocationSourceKind::ChainState,
            ProofFinality::Finalized,
            RevocationFreshnessPolicy::new(120, 900)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        ))
        .unwrap_or_else(|error| panic!("revocation proof should insert: {error}"));

    let result = VerificationPipeline::new().verify_json_str_with_sources(
        SIMPLE_TRUSTGRANT_JSON,
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
fn cached_verification_rejects_stale_trusted_snapshot_revocation() {
    // Cached posture should reject stale trusted snapshot (unlike offline)
    let proof_bundle = offline_bundle(STALE_REVOCATION_JSON);

    let result = VerificationPipeline::new().verify_json_str_with_sources(
        SIMPLE_TRUSTGRANT_JSON,
        &FakeSignatureVerifier,
        proof_bundle.as_sources(),
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            VerificationPosture::Cached,
        ),
    );

    // Cached posture requires fresh revocation state
    assert!(result.is_err());
}
