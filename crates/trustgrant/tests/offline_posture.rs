#![allow(clippy::panic)]

use chrono::{TimeZone, Utc};
use trustgrant::{
    AuthorityId, BundleRevocationProof, EvaluationDenyReason, EvaluationEngine,
    EvaluationRequest, ProofFinality, RequestedCapability, RequestedOperation, ResourceBinding,
    ResourceContext, ResourceRef, RevocationFreshnessPolicy, RevocationSourceKind, RevocationStatus,
    SignatureVerificationRequest, SignatureVerifier, TrustGrantError, TrustGrantProofBundle,
    VerificationContext, VerificationPipeline, VerificationPolicy, VerificationPosture,
    parse_authority_discovery_document, parse_revocation_status_proof,
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
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":null
}"#;

const NON_REVOCABLE_TRUSTGRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174501",
  "version":0,
  "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174502",
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
  "revocation":{"revocable":false,"revocation_endpoint":"","post_revocation_effect":"block_all"},
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
            RevocationFreshnessPolicy::new(86400, 86400)
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
            RevocationFreshnessPolicy::new(86400, 86400)
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
            RevocationFreshnessPolicy::new(86400, 86400)
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

// ---------------------------------------------------------------------------
// Hot-path evaluation freshness checks
// ---------------------------------------------------------------------------

#[test]
fn offline_evaluation_denies_when_revocation_data_has_expired() {
    // Verify with fresh revocation data, then evaluate at a time after
    // the freshness window has closed. The engine should deny with
    // StaleRevocationData even though the verification passed.
    let proof_bundle = offline_bundle(FRESH_REVOCATION_JSON);

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
    // Evaluate 48 hours after verification — well past the 24-hour freshness window.
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
        fixed_timestamp(2026, 4, 9, 12, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));

    let outcome = engine.evaluate(artifacts.verified_grant(), &request);

    assert_eq!(
        outcome.decision().deny_reason(),
        Some(EvaluationDenyReason::StaleRevocationData)
    );
}

#[test]
fn offline_evaluation_allows_with_non_revocable_grant() {
    // Grants without revocation capability should bypass all revocation
    // checks, including freshness, at both verification and evaluation time.
    // The grant JSON has revocable: false, so no revocation proof is needed.
    let mut proof_bundle = TrustGrantProofBundle::new();
    proof_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(ROOT_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("discovery should insert: {error}"));

    let artifacts = VerificationPipeline::new()
        .verify_json_str_with_sources(
            NON_REVOCABLE_TRUSTGRANT_JSON,
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
        fixed_timestamp(2030, 1, 1, 0, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));

    let outcome = engine.evaluate(artifacts.verified_grant(), &request);

    assert!(outcome.decision().is_allowed());
}

#[test]
fn offline_evaluation_allows_with_fresh_revocation_data() {
    // Verify with fresh revocation data and evaluate within the freshness
    // window — the engine should allow evaluation to proceed and return
    // an allow decision for a matching request.
    let proof_bundle = offline_bundle(FRESH_REVOCATION_JSON);

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

    // The grant has target_scope.all = true and resource_scope.all = true,
    // so a matching request should be allowed.
    assert!(outcome.decision().is_allowed());
}

// ---------------------------------------------------------------------------
// G4: VerificationPolicy unit tests
// ---------------------------------------------------------------------------

#[test]
fn for_posture_online_returns_observed_min_finality_and_no_live_requirement() {
    let policy = VerificationPolicy::for_posture(VerificationPosture::Online);
    assert_eq!(policy.minimum_revocation_finality(), ProofFinality::Observed);
    assert!(!policy.require_non_live_revocation_source());
}

#[test]
fn for_posture_cached_returns_trusted_snapshot_min_finality_and_requires_non_live() {
    let policy = VerificationPolicy::for_posture(VerificationPosture::Cached);
    assert_eq!(
        policy.minimum_revocation_finality(),
        ProofFinality::TrustedSnapshot
    );
    assert!(policy.require_non_live_revocation_source());
}

#[test]
fn for_posture_offline_returns_trusted_snapshot_min_finality_and_requires_non_live() {
    let policy = VerificationPolicy::for_posture(VerificationPosture::Offline);
    assert_eq!(
        policy.minimum_revocation_finality(),
        ProofFinality::TrustedSnapshot
    );
    assert!(policy.require_non_live_revocation_source());
}

#[test]
fn accepts_revocation_finality_for_all_posture_variants() {
    // Online: accepts Observed and anything >= Observed
    let online = VerificationPolicy::for_posture(VerificationPosture::Online);
    assert!(online.accepts_revocation_finality(ProofFinality::Observed));
    assert!(online.accepts_revocation_finality(ProofFinality::TrustedSnapshot));
    assert!(online.accepts_revocation_finality(ProofFinality::Finalized));
    assert!(!online.accepts_revocation_finality(ProofFinality::Unknown));

    // Cached: accepts TrustedSnapshot and anything >= TrustedSnapshot
    let cached = VerificationPolicy::for_posture(VerificationPosture::Cached);
    assert!(cached.accepts_revocation_finality(ProofFinality::TrustedSnapshot));
    assert!(cached.accepts_revocation_finality(ProofFinality::Finalized));
    assert!(!cached.accepts_revocation_finality(ProofFinality::Observed));
    assert!(!cached.accepts_revocation_finality(ProofFinality::Unknown));

    // Offline: same as Cached
    let offline = VerificationPolicy::for_posture(VerificationPosture::Offline);
    assert!(offline.accepts_revocation_finality(ProofFinality::TrustedSnapshot));
    assert!(offline.accepts_revocation_finality(ProofFinality::Finalized));
    assert!(!offline.accepts_revocation_finality(ProofFinality::Observed));
    assert!(!offline.accepts_revocation_finality(ProofFinality::Unknown));
}

#[test]
fn accepts_revocation_source_kind_for_all_posture_variants() {
    // Online: accepts any source kind
    let online = VerificationPolicy::for_posture(VerificationPosture::Online);
    assert!(online.accepts_revocation_source_kind(RevocationSourceKind::Api));
    assert!(online.accepts_revocation_source_kind(RevocationSourceKind::Snapshot));
    assert!(online.accepts_revocation_source_kind(RevocationSourceKind::ProofBundle));
    assert!(online.accepts_revocation_source_kind(RevocationSourceKind::ChainState));
    assert!(online.accepts_revocation_source_kind(RevocationSourceKind::Other));

    // Cached: rejects live sources, accepts non-live
    let cached = VerificationPolicy::for_posture(VerificationPosture::Cached);
    assert!(!cached.accepts_revocation_source_kind(RevocationSourceKind::Api));
    assert!(!cached.accepts_revocation_source_kind(RevocationSourceKind::ChainState));
    assert!(!cached.accepts_revocation_source_kind(RevocationSourceKind::Other));
    assert!(cached.accepts_revocation_source_kind(RevocationSourceKind::Snapshot));
    assert!(cached.accepts_revocation_source_kind(RevocationSourceKind::ProofBundle));

    // Offline: same as Cached
    let offline = VerificationPolicy::for_posture(VerificationPosture::Offline);
    assert!(!offline.accepts_revocation_source_kind(RevocationSourceKind::Api));
    assert!(!offline.accepts_revocation_source_kind(RevocationSourceKind::ChainState));
    assert!(!offline.accepts_revocation_source_kind(RevocationSourceKind::Other));
    assert!(offline.accepts_revocation_source_kind(RevocationSourceKind::Snapshot));
    assert!(offline.accepts_revocation_source_kind(RevocationSourceKind::ProofBundle));
}

// ---------------------------------------------------------------------------
// G7: RevocationStatusProof standalone tests
// ---------------------------------------------------------------------------

#[test]
fn parse_revocation_status_proof_valid_json_returns_proof() {
    let json = r#"{
      "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
      "status":"active",
      "checked_at":"2026-04-07T12:00:00Z"
    }"#;

    let proof = parse_revocation_status_proof(json)
        .unwrap_or_else(|e| panic!("valid proof should parse: {e}"));

    assert_eq!(
        proof.trustgrant_id().to_string(),
        "tg_123e4567-e89b-12d3-a456-426614174000"
    );
    assert_eq!(proof.status(), RevocationStatus::Active);
    assert_eq!(proof.checked_at(), fixed_timestamp(2026, 4, 7, 12, 0, 0));
}

#[test]
fn parse_revocation_status_proof_revoked_json_returns_revoked() {
    let json = r#"{
      "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174001",
      "status":"revoked",
      "checked_at":"2026-04-07T12:30:00Z"
    }"#;

    let proof = parse_revocation_status_proof(json)
        .unwrap_or_else(|e| panic!("revoked proof should parse: {e}"));

    assert_eq!(proof.status(), RevocationStatus::Revoked);
    assert_eq!(
        proof.trustgrant_id().to_string(),
        "tg_123e4567-e89b-12d3-a456-426614174001"
    );
}

#[test]
fn parse_revocation_status_proof_invalid_json_returns_error() {
    let json = r#"not valid json at all"#;
    let result = parse_revocation_status_proof(json);
    assert_eq!(result, Err(TrustGrantError::InvalidRevocationProofDocument));
}

#[test]
fn parse_revocation_status_proof_unknown_fields_returns_error() {
    let json = r#"{
      "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
      "status":"active",
      "checked_at":"2026-04-07T12:00:00Z",
      "extra_field":"unexpected"
    }"#;
    let result = parse_revocation_status_proof(json);
    assert_eq!(result, Err(TrustGrantError::InvalidRevocationProofDocument));
}

#[test]
fn revocation_status_proof_into_record_with_active_status_and_online_policy() {
    let json = r#"{
      "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
      "status":"active",
      "checked_at":"2026-04-07T12:00:00Z"
    }"#;
    let proof = parse_revocation_status_proof(json)
        .unwrap_or_else(|e| panic!("valid proof should parse: {e}"));

    let policy = RevocationFreshnessPolicy::new(3600, 86400)
        .unwrap_or_else(|e| panic!("valid policy: {e}"));
    let record = proof
        .into_record(RevocationSourceKind::Api, ProofFinality::Observed, policy)
        .unwrap_or_else(|e| panic!("record should normalize: {e}"));

    assert_eq!(record.status(), RevocationStatus::Active);
    assert_eq!(record.source_kind(), RevocationSourceKind::Api);
    assert_eq!(record.finality(), ProofFinality::Observed);
    // fresh_until = checked_at + non_revoked_ttl(3600s) = 13:00:00
    assert_eq!(record.fresh_until(), fixed_timestamp(2026, 4, 7, 13, 0, 0));
}

#[test]
fn revocation_status_proof_into_record_with_revoked_status_and_offline_policy() {
    let json = r#"{
      "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
      "status":"revoked",
      "checked_at":"2026-04-07T12:00:00Z"
    }"#;
    let proof = parse_revocation_status_proof(json)
        .unwrap_or_else(|e| panic!("valid proof should parse: {e}"));

    let policy = RevocationFreshnessPolicy::new(3600, 7200)
        .unwrap_or_else(|e| panic!("valid policy: {e}"));
    let record = proof
        .into_record(
            RevocationSourceKind::ProofBundle,
            ProofFinality::TrustedSnapshot,
            policy,
        )
        .unwrap_or_else(|e| panic!("record should normalize: {e}"));

    assert_eq!(record.status(), RevocationStatus::Revoked);
    assert_eq!(record.source_kind(), RevocationSourceKind::ProofBundle);
    assert_eq!(record.finality(), ProofFinality::TrustedSnapshot);
    // fresh_until = checked_at + max_stale_ttl(7200s) = 14:00:00
    assert_eq!(record.fresh_until(), fixed_timestamp(2026, 4, 7, 14, 0, 0));
}

// ---------------------------------------------------------------------------
// G18: Very short RevocationFreshnessPolicy (60s)
// ---------------------------------------------------------------------------

#[test]
fn revocation_freshness_policy_very_short_ttl_record_stale_after_61_seconds() {
    // Use RevocationFreshnessPolicy::new(60, 60) — very short freshness.
    let policy = RevocationFreshnessPolicy::new(60, 60)
        .unwrap_or_else(|e| panic!("valid policy: {e}"));

    // Proof checked_at = 12:00:00, so fresh_until = 12:01:00.
    let json = r#"{
      "trustgrant_id":"tg_00000000-0000-0000-0000-000000000018",
      "status":"active",
      "checked_at":"2026-04-07T12:00:00Z"
    }"#;
    let proof = parse_revocation_status_proof(json)
        .unwrap_or_else(|e| panic!("valid proof: {e}"));

    let record = proof
        .into_record(RevocationSourceKind::Api, ProofFinality::Observed, policy)
        .unwrap_or_else(|e| panic!("record: {e}"));

    // Exactly 60 seconds later → still fresh (fresh_until is inclusive).
    assert!(record.is_fresh_at(fixed_timestamp(2026, 4, 7, 12, 1, 0)));

    // 61 seconds later → stale.
    assert!(!record.is_fresh_at(fixed_timestamp(2026, 4, 7, 12, 1, 1)));
}


