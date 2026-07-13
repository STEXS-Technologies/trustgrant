#![allow(clippy::panic)]

//! Integration tests for the persistence/recovery path:
//! create a verified grant → serialize to record → rehydrate from record → evaluate.

use chrono::{TimeZone, Utc};

use trustgrant::{
    AuthorityId, AuthorityKeyRecord, EvaluationDenyReason, EvaluationEngine, EvaluationRequest,
    MintContext, OwnershipProofKind, OwnershipVerificationRecord, ProofFinality,
    RequestedCapability, RequestedOperation, ResolvedSignerBinding, ResourceContext,
    RevocationRecord, RevocationSourceKind, RevocationStatus, SignatureProfile,
    SignatureVerificationRequest, SignatureVerifier, TrustGrantError, VerificationMetadata,
    VerificationPipeline, VerificationPosture, VerifiedRevocationState, VerifiedTrustGrant,
    VerifiedTrustGrantRecord,
};

// ---------------------------------------------------------------------------
// Test JSON fixtures
// ---------------------------------------------------------------------------

const RECOGNIZE_TRUSTGRANT_JSON: &str = r#"{
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
  "default_audience_scope":null,
  "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":{"all":false,"allow":[{"kind":"player_id","all":false,"values":["player-123"],"expressions":null}],"deny":null}}]},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

/// Mint grant: top-level and resource-type capabilities both have mint=true,
/// with max_total=10 and max_per_user=1.
const MINT_TRUSTGRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174050",
  "version":0,
  "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174051",
  "revision":1,
  "supersedes":null,
  "supersession_policy":"coexist",
  "issuer_authority":"https://issuer.example.com",
  "origin_authority":"https://issuer.example.com",
  "active_owning_authority":"https://issuer.example.com",
  "key_id":"root-key-1",
  "target_scope":{"all":false,"allow":[{"kind":"authority","all":false,"values":["https://target.example.com"],"expressions":null}],"deny":null},
  "capabilities":{"recognize":true,"mint":true},
  "default_audience_scope":null,
  "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":true},"constraints":{"minting":{"max_total":10,"max_per_user":1},"audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":{"all":false,"allow":[{"kind":"player_id","all":false,"values":["player-123"],"expressions":null}],"deny":null}}]},"operations":{"all":false,"allow":["create"],"deny":null}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

// ---------------------------------------------------------------------------
// Fake signature verifier
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct FakeSignatureVerifier;

impl SignatureVerifier for FakeSignatureVerifier {
    fn verify_signature(
        &self,
        request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), TrustGrantError> {
        if request.signature() == "base64-signature"
            && request.key_id().as_str() == "root-key-1"
            && !request.canonical_bytes().is_empty()
        {
            Ok(())
        } else {
            Err(TrustGrantError::SignatureVerificationFailed)
        }
    }
}

// ---------------------------------------------------------------------------
// Shared test helpers
// ---------------------------------------------------------------------------

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

fn verification_metadata(revocation_status: RevocationStatus) -> VerificationMetadata {
    VerificationMetadata::new(
        fixed_timestamp(2026, 4, 7, 12, 0, 0),
        VerificationPosture::Online,
        signer_binding(),
        ownership_record(),
        VerifiedRevocationState::Checked(
            RevocationRecord::new(
                revocation_status,
                RevocationSourceKind::Api,
                ProofFinality::Observed,
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                fixed_timestamp(2026, 4, 7, 12, 5, 0),
            )
            .unwrap_or_else(|error| panic!("revocation record should be valid: {error}")),
        ),
    )
}

fn ownership_record() -> OwnershipVerificationRecord {
    OwnershipVerificationRecord::new(
        AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("origin authority should be valid: {error}")),
        AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("active owning authority should be valid: {error}")),
        fixed_timestamp(2026, 4, 7, 12, 0, 0),
        OwnershipProofKind::StaticOwner,
        None,
    )
}

fn signer_binding() -> ResolvedSignerBinding {
    ResolvedSignerBinding::new(
        AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("issuer authority should be valid: {error}")),
        AuthorityKeyRecord::new(
            "root-key-1",
            "ed25519",
            "base64-public-key",
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            fixed_timestamp(2026, 4, 8, 12, 0, 0),
        )
        .unwrap_or_else(|error| panic!("key record should be valid: {error}")),
        SignatureProfile::new("jcs+ed25519", "RFC8785")
            .unwrap_or_else(|error| panic!("signature profile should be valid: {error}")),
        Some(
            trustgrant::DelegatedPrincipalRef::new("service", "issuer-worker")
                .unwrap_or_else(|error| panic!("delegated principal should be valid: {error}")),
        ),
    )
}

/// Verify a JSON string and return the verified grant.
fn verify_grant(json: &str, revocation_status: RevocationStatus) -> VerifiedTrustGrant {
    let pipeline = VerificationPipeline::new();
    let artifacts = pipeline
        .verify_json_str(
            json,
            &FakeSignatureVerifier,
            verification_metadata(revocation_status),
        )
        .unwrap_or_else(|error| panic!("pipeline verification should succeed: {error}"));
    artifacts.verified_grant().clone()
}

/// Create a recognize request for the "player-123" principal.
fn recognize_request() -> EvaluationRequest {
    let mut resource = ResourceContext::new("item")
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));

    let mut request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        AuthorityId::new("https://target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new("https://audience.example.com")
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));

    request
        .insert_audience_principal_selector("player_id", "player-123")
        .unwrap_or_else(|error| panic!("principal selector should be valid: {error}"));

    request
}

/// Create a mint request with the given mint counters.
fn mint_request(total_mints: u64, mints_for_audience: u64) -> EvaluationRequest {
    let mut resource = ResourceContext::new("item")
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));

    let mut request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Mint),
        AuthorityId::new("https://target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new("https://audience.example.com")
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));

    request
        .insert_audience_principal_selector("player_id", "player-123")
        .unwrap_or_else(|error| panic!("principal selector should be valid: {error}"));

    request.with_mint_context(MintContext::new(total_mints, mints_for_audience))
}

// ---------------------------------------------------------------------------
// Test: Rehydrated grant preserves default_audience_scope and issuer_principal
// ---------------------------------------------------------------------------

const AUDIENCE_SCOPE_AND_PRINCIPAL_JSON: &str = r#"{
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
  "default_audience_scope":[
    {"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":null}
  ],
  "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":null}}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

#[test]
fn rehydrated_grant_with_audience_scope_and_principal_preserves_both() {
    // 1. Verify a grant that has both default_audience_scope and issuer_principal
    let verified = verify_grant(AUDIENCE_SCOPE_AND_PRINCIPAL_JSON, RevocationStatus::Active);

    // 2. Convert to record → serialize → deserialize (disk simulation)
    let record = VerifiedTrustGrantRecord::from(&verified);
    let json = serde_json::to_string(&record)
        .unwrap_or_else(|error| panic!("record should serialize: {error}"));
    let persisted: VerifiedTrustGrantRecord = serde_json::from_str(&json)
        .unwrap_or_else(|error| panic!("record should deserialize: {error}"));

    // 3. Rehydrate
    let rehydrated = persisted
        .try_to_verified_grant()
        .unwrap_or_else(|error| panic!("rehydration should succeed: {error}"));

    // 4. Verify default_audience_scope survived rehydration
    let audience_scope = rehydrated.document().default_audience_scope();
    assert_eq!(
        audience_scope.len(),
        1,
        "default_audience_scope should contain one entry after rehydration"
    );
    assert_eq!(
        audience_scope
            .first()
            .unwrap_or_else(|| panic!("audience_scope should not be empty"))
            .authority_id()
            .as_str(),
        "https://audience.example.com",
        "audience authority_id should survive rehydration"
    );

    // 5. Verify issuer_principal survived rehydration
    let principal = rehydrated
        .document()
        .issuer_principal()
        .unwrap_or_else(|| panic!("issuer_principal should be present after rehydration"));
    assert_eq!(
        principal.kind().as_str(),
        "service",
        "issuer_principal kind should survive rehydration"
    );
    assert_eq!(
        principal.id().as_str(),
        "issuer-worker",
        "issuer_principal id should survive rehydration"
    );
}

// ---------------------------------------------------------------------------
// Test 1: Verify → rehydrate → evaluate (recognize)
// ---------------------------------------------------------------------------

#[test]
fn rehydrated_recognize_grant_allows_matching_request() {
    // 1. Verify
    let verified = verify_grant(RECOGNIZE_TRUSTGRANT_JSON, RevocationStatus::Active);

    // 2. Convert to record (in-memory persistence form)
    let record = VerifiedTrustGrantRecord::from(&verified);

    // 3. Serialize to JSON and deserialize back (simulates disk persistence)
    let json = serde_json::to_string(&record)
        .unwrap_or_else(|error| panic!("record should serialize: {error}"));
    let persisted: VerifiedTrustGrantRecord = serde_json::from_str(&json)
        .unwrap_or_else(|error| panic!("record should deserialize: {error}"));

    // 4. Rehydrate from the persisted record
    let rehydrated = persisted
        .try_to_verified_grant()
        .unwrap_or_else(|error| panic!("rehydration should succeed: {error}"));

    // 5. Evaluate
    let engine = EvaluationEngine::new();
    let decision = engine.evaluate(&rehydrated, &recognize_request());

    assert!(decision.is_allowed());
}

// ---------------------------------------------------------------------------
// Test 2: Verify → rehydrate → evaluate (mint with constraints)
// ---------------------------------------------------------------------------

#[test]
fn rehydrated_mint_grant_allows_under_total_limit() {
    // 1. Verify
    let verified = verify_grant(MINT_TRUSTGRANT_JSON, RevocationStatus::Active);

    // 2. Convert → persist → rehydrate
    let record = VerifiedTrustGrantRecord::from(&verified);
    let json = serde_json::to_string(&record)
        .unwrap_or_else(|error| panic!("record should serialize: {error}"));
    let persisted: VerifiedTrustGrantRecord = serde_json::from_str(&json)
        .unwrap_or_else(|error| panic!("record should deserialize: {error}"));
    let rehydrated = persisted
        .try_to_verified_grant()
        .unwrap_or_else(|error| panic!("rehydration should succeed: {error}"));

    // 3. Evaluate at 9/10 → should be allowed
    let engine = EvaluationEngine::new();
    let decision = engine.evaluate(&rehydrated, &mint_request(9, 0));

    assert!(decision.is_allowed());
}

#[test]
fn rehydrated_mint_grant_denies_at_total_limit() {
    // 1. Verify
    let verified = verify_grant(MINT_TRUSTGRANT_JSON, RevocationStatus::Active);

    // 2. Convert → persist → rehydrate
    let record = VerifiedTrustGrantRecord::from(&verified);
    let json = serde_json::to_string(&record)
        .unwrap_or_else(|error| panic!("record should serialize: {error}"));
    let persisted: VerifiedTrustGrantRecord = serde_json::from_str(&json)
        .unwrap_or_else(|error| panic!("record should deserialize: {error}"));
    let rehydrated = persisted
        .try_to_verified_grant()
        .unwrap_or_else(|error| panic!("rehydration should succeed: {error}"));

    // 3. Evaluate at 10/10 → should deny with MintTotalLimitReached
    let engine = EvaluationEngine::new();
    let decision = engine.evaluate(&rehydrated, &mint_request(10, 0));

    assert_eq!(
        decision.deny_reason(),
        Some(EvaluationDenyReason::MintTotalLimitReached)
    );
}

// ---------------------------------------------------------------------------
// Test 3: Rehydration round-trip preserves deny reason
// ---------------------------------------------------------------------------

#[test]
fn rehydrated_revoked_grant_preserves_deny_reason() {
    // 1. Verify with a revoked grant
    let verified = verify_grant(RECOGNIZE_TRUSTGRANT_JSON, RevocationStatus::Revoked);

    // 2. Evaluate before persistence → should deny for Revoked
    let engine = EvaluationEngine::new();
    let original_decision = engine.evaluate(&verified, &recognize_request());
    assert_eq!(
        original_decision.deny_reason(),
        Some(EvaluationDenyReason::Revoked)
    );

    // 3. Convert → persist → rehydrate
    let record = VerifiedTrustGrantRecord::from(&verified);
    let json = serde_json::to_string(&record)
        .unwrap_or_else(|error| panic!("record should serialize: {error}"));
    let persisted: VerifiedTrustGrantRecord = serde_json::from_str(&json)
        .unwrap_or_else(|error| panic!("record should deserialize: {error}"));
    let rehydrated = persisted
        .try_to_verified_grant()
        .unwrap_or_else(|error| panic!("rehydration should succeed: {error}"));

    // 4. Evaluate after rehydration → same deny reason
    let rehydrated_decision = engine.evaluate(&rehydrated, &recognize_request());
    assert_eq!(
        rehydrated_decision.deny_reason(),
        Some(EvaluationDenyReason::Revoked)
    );
}
