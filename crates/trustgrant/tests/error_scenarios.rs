#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unwrap_in_result,
    clippy::panic_in_result_fn,
    clippy::indexing_slicing
)]

use chrono::{TimeZone, Utc};

use trustgrant::{
    AuthorityId, AuthorityKeyRecord, EvaluationDenyReason, EvaluationEngine, EvaluationRequest,
    MintContext, OwnershipProofKind, OwnershipVerificationRecord, ProofFinality,
    RequestedCapability, RequestedOperation, ResolvedSignerBinding, ResourceBinding,
    ResourceContext, ResourceRef, RevocationRecord, RevocationSourceKind, RevocationStatus,
    SignatureProfile, SignatureVerificationRequest, SignatureVerifier, TemplateRef,
    TrustGrantError, VerificationMetadata, VerificationPipeline, VerificationPosture,
    VerifiedRevocationState, VerifiedTrustGrant,
};

// ---------------------------------------------------------------------------
// Base valid JSON (same as evaluation.rs)
// ---------------------------------------------------------------------------

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
  "default_audience_scope":null,
  "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":10,"max_per_user":1},"audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":{"all":false,"allow":[{"kind":"actor","all":false,"values":["player-123"],"expressions":null}],"deny":null}}]},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

// ---------------------------------------------------------------------------
// Fake signature verifiers
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

#[derive(Debug, Default)]
struct AlwaysFailSignatureVerifier;

impl SignatureVerifier for AlwaysFailSignatureVerifier {
    fn verify_signature(
        &self,
        _request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), TrustGrantError> {
        Err(TrustGrantError::SignatureVerificationFailed)
    }
}

// ---------------------------------------------------------------------------
// Helpers
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
                fixed_timestamp(2026, 4, 9, 12, 0, 0),
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

/// Verifies a JSON string using the fake (always-pass) verifier and returns the
/// verified grant.
fn verified_grant_from_json(json: &str, revocation_status: RevocationStatus) -> VerifiedTrustGrant {
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

/// Builds a standard recognize request targeting the grant's expected authorities.
fn recognize_request(actor: &str) -> EvaluationRequest {
    let mut resource = ResourceContext::new("item")
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));

    let origin = AuthorityId::new("https://issuer.example.com")
        .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"));

    let mut request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
        AuthorityId::new("https://target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new("https://audience.example.com")
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));

    request
        .insert_audience_principal_selector("actor", actor)
        .unwrap_or_else(|error| panic!("principal selector should be valid: {error}"));

    request
}

/// Builds a recognize request with an explicit evaluation timestamp.
fn recognize_request_at(actor: &str, evaluated_at: chrono::DateTime<Utc>) -> EvaluationRequest {
    let mut resource = ResourceContext::new("item")
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));

    let origin = AuthorityId::new("https://issuer.example.com")
        .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"));

    let mut request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
        AuthorityId::new("https://target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new("https://audience.example.com")
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        evaluated_at,
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));

    request
        .insert_audience_principal_selector("actor", actor)
        .unwrap_or_else(|error| panic!("principal selector should be valid: {error}"));

    request
}

// ---------------------------------------------------------------------------
// Test 1: Invalid version fails verification
// ---------------------------------------------------------------------------

#[test]
fn invalid_version_fails_verification() {
    let json = r#"{
  "trustgrant_id":"tg_00000000-0000-0000-0000-000000000001",
  "version":1,
  "grant_series_id":"tgs_00000000-0000-0000-0000-000000000002",
  "revision":1,
  "supersedes":null,
  "supersession_policy":"coexist",
  "issuer_authority":"https://issuer.example.com",
  "origin_authority":"https://issuer.example.com",
  "active_owning_authority":"https://issuer.example.com",
  "key_id":"root-key-1",
  "target_scope":{"all":true,"allow":null,"deny":null},
  "capabilities":{"recognize":true,"mint":true},
  "default_audience_scope":null,
  "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":true},"constraints":{"minting":{"max_total":10,"max_per_user":1},"audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":{"all":false,"allow":[{"kind":"actor","all":false,"values":["player-123"],"expressions":null}],"deny":null}}]},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

    let pipeline = VerificationPipeline::new();
    let result = pipeline.verify_json_str(
        json,
        &FakeSignatureVerifier,
        verification_metadata(RevocationStatus::Active),
    );

    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    };
    assert!(
        matches!(err, TrustGrantError::InvalidProtocolVersion(1)),
        "expected InvalidProtocolVersion(1), got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Expired grant evaluation
// ---------------------------------------------------------------------------

#[test]
fn expired_grant_evaluation_denied() {
    let grant = verified_grant_from_json(VALID_TRUSTGRANT_JSON, RevocationStatus::Active);

    // not_after is 2026-04-08T12:00:00Z — evaluate after that window
    let engine = EvaluationEngine::new();
    let request = recognize_request_at("player-123", fixed_timestamp(2026, 4, 9, 12, 0, 0));
    let outcome = engine.evaluate(&grant, &request);

    assert_eq!(
        outcome.decision().deny_reason(),
        Some(EvaluationDenyReason::Expired)
    );
}

// ---------------------------------------------------------------------------
// Test 3: Not-yet-valid grant evaluation
// ---------------------------------------------------------------------------

#[test]
fn not_yet_valid_grant_evaluation_denied() {
    let grant = verified_grant_from_json(VALID_TRUSTGRANT_JSON, RevocationStatus::Active);

    // not_before is 2026-04-07T12:00:00Z — evaluate before that
    let engine = EvaluationEngine::new();
    let request = recognize_request_at("player-123", fixed_timestamp(2026, 4, 6, 12, 0, 0));
    let outcome = engine.evaluate(&grant, &request);

    assert_eq!(
        outcome.decision().deny_reason(),
        Some(EvaluationDenyReason::NotYetValid)
    );
}

// ---------------------------------------------------------------------------
// Test 4: Revoked grant evaluation
// ---------------------------------------------------------------------------

#[test]
fn revoked_grant_evaluation_denied() {
    let grant = verified_grant_from_json(VALID_TRUSTGRANT_JSON, RevocationStatus::Revoked);

    let engine = EvaluationEngine::new();
    let outcome = engine.evaluate(&grant, &recognize_request("player-123"));

    assert_eq!(
        outcome.decision().deny_reason(),
        Some(EvaluationDenyReason::Revoked)
    );
}

// ---------------------------------------------------------------------------
// Test 5: Signature verification failure
// ---------------------------------------------------------------------------

#[test]
fn signature_verification_failure_returns_error() {
    let pipeline = VerificationPipeline::new();
    let result = pipeline.verify_json_str(
        VALID_TRUSTGRANT_JSON,
        &AlwaysFailSignatureVerifier,
        verification_metadata(RevocationStatus::Active),
    );

    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    };
    assert!(
        matches!(err, TrustGrantError::SignatureVerificationFailed),
        "expected SignatureVerificationFailed, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 6: Target scope deny
// ---------------------------------------------------------------------------

#[test]
fn target_scope_deny_evaluation_denied() {
    let grant = verified_grant_from_json(VALID_TRUSTGRANT_JSON, RevocationStatus::Active);

    // The grant's target_scope allows only "https://target.example.com".
    // Request targeting a different authority → TargetNotAllowed.
    let mut resource = ResourceContext::new("item")
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));

    let origin = AuthorityId::new("https://issuer.example.com")
        .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"));

    let mut request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
        AuthorityId::new("https://different-target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new("https://audience.example.com")
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));
    request
        .insert_audience_principal_selector("actor", "player-123")
        .unwrap_or_else(|error| panic!("principal selector should be valid: {error}"));

    let engine = EvaluationEngine::new();
    let outcome = engine.evaluate(&grant, &request);

    // The target doesn't match the allow list → TargetNotAllowed (no deny list entry matches)
    assert_eq!(
        outcome.decision().deny_reason(),
        Some(EvaluationDenyReason::TargetNotAllowed)
    );
}

// ---------------------------------------------------------------------------
// Test 7: Audience mismatch
// ---------------------------------------------------------------------------

#[test]
fn audience_mismatch_evaluation_denied() {
    let grant = verified_grant_from_json(VALID_TRUSTGRANT_JSON, RevocationStatus::Active);

    // The grant has audience_scope for "https://audience.example.com" only.
    // Request targeting "https://other-audience.example.com" → AudienceNotAllowed.
    let mut resource = ResourceContext::new("item")
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));

    let origin = AuthorityId::new("https://issuer.example.com")
        .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"));

    let mut request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
        AuthorityId::new("https://target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new("https://other-audience.example.com")
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));
    request
        .insert_audience_principal_selector("actor", "player-123")
        .unwrap_or_else(|error| panic!("principal selector should be valid: {error}"));

    let engine = EvaluationEngine::new();
    let outcome = engine.evaluate(&grant, &request);

    assert_eq!(
        outcome.decision().deny_reason(),
        Some(EvaluationDenyReason::AudienceNotAllowed)
    );
}

// ---------------------------------------------------------------------------
// Test 8: Empty resource type lookup
// ---------------------------------------------------------------------------

#[test]
fn resource_type_not_granted_evaluation_denied() {
    let grant = verified_grant_from_json(VALID_TRUSTGRANT_JSON, RevocationStatus::Active);

    // The grant only defines resource type "item". Request "weapon" type → ResourceTypeNotGranted.
    let resource = ResourceContext::new("weapon")
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));

    let origin = AuthorityId::new("https://issuer.example.com")
        .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"));

    let request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(ResourceRef::new(origin, "weapon".to_owned())),
        AuthorityId::new("https://target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new("https://audience.example.com")
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));

    let engine = EvaluationEngine::new();
    let outcome = engine.evaluate(&grant, &request);

    assert_eq!(
        outcome.decision().deny_reason(),
        Some(EvaluationDenyReason::ResourceTypeNotGranted)
    );
}

// ---------------------------------------------------------------------------
// Test 9: Operation deny list (recognize in both allow and deny → deny wins)
// ---------------------------------------------------------------------------

#[test]
fn operation_deny_list_evaluation_denied() {
    // Grant with recognize in both allow and deny → deny wins.
    let json = r#"{
  "trustgrant_id":"tg_00000000-0000-0000-0000-000000000010",
  "version":0,
  "grant_series_id":"tgs_00000000-0000-0000-0000-000000000011",
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
  "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":["recognize"]}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

    let grant = verified_grant_from_json(json, RevocationStatus::Active);

    let engine = EvaluationEngine::new();
    let outcome = engine.evaluate(&grant, &recognize_request("player-123"));

    assert_eq!(
        outcome.decision().deny_reason(),
        Some(EvaluationDenyReason::OperationDenied)
    );
}

// ---------------------------------------------------------------------------
// Test 10: MissingMintContext
// ---------------------------------------------------------------------------

#[test]
fn missing_mint_context_evaluation_denied() {
    // Grant with minting constraints but request uses Mint capability
    // without providing a MintContext.
    let json = r#"{
  "trustgrant_id":"tg_00000000-0000-0000-0000-000000000020",
  "version":0,
  "grant_series_id":"tgs_00000000-0000-0000-0000-000000000021",
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
  "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":true},"constraints":{"minting":{"max_total":10,"max_per_user":1},"audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":{"all":false,"allow":[{"kind":"actor","all":false,"values":["player-123"],"expressions":null}],"deny":null}}]},"operations":{"all":false,"allow":["recognize","create"],"deny":null}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

    let grant = verified_grant_from_json(json, RevocationStatus::Active);

    // Build a Mint request WITHOUT providing MintContext
    let mut resource = ResourceContext::new("item")
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));

    let origin = AuthorityId::new("https://issuer.example.com")
        .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"));

    let mut request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Mint),
        ResourceBinding::Mint(TemplateRef::new(origin)),
        AuthorityId::new("https://target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new("https://audience.example.com")
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));
    request
        .insert_audience_principal_selector("actor", "player-123")
        .unwrap_or_else(|error| panic!("principal selector should be valid: {error}"));

    // NOTE: We do NOT call request.with_mint_context_for_testing(...) — intentionally omitting it.
    let request = request.verify_selectors();

    let engine = EvaluationEngine::new();
    let outcome = engine.evaluate(&grant, &request);

    assert_eq!(
        outcome.decision().deny_reason(),
        Some(EvaluationDenyReason::MissingMintContext)
    );
}

// ---------------------------------------------------------------------------
// Test 11: UnverifiedSelectors deny path for mint (spec §13 step 0)
// ---------------------------------------------------------------------------

/// Mint-enabled grant without audience principal scope (mint=true, "create" operation).
const MINT_WITHOUT_PRINCIPAL_SCOPE_JSON: &str = r#"{
  "trustgrant_id":"tg_00000000-0000-0000-0000-000000000030",
  "version":0,
  "grant_series_id":"tgs_00000000-0000-0000-0000-000000000031",
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
  "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":true},"constraints":{"minting":{"max_total":10,"max_per_user":1},"audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":null}]},"operations":{"all":false,"allow":["recognize","create"],"deny":null}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

#[test]
fn unverified_selectors_denies_mint() {
    // Mint without verify_selectors() → UnverifiedSelectors
    let grant =
        verified_grant_from_json(MINT_WITHOUT_PRINCIPAL_SCOPE_JSON, RevocationStatus::Active);

    // Build a mint request WITHOUT calling .verify_selectors()
    let mut resource = ResourceContext::new("item")
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));

    let origin = AuthorityId::new("https://issuer.example.com")
        .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"));

    let request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Mint),
        ResourceBinding::Mint(TemplateRef::new(origin)),
        AuthorityId::new("https://target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new("https://audience.example.com")
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));

    // NOTE: No .verify_selectors() call

    let engine = EvaluationEngine::new();
    let outcome = engine.evaluate(&grant, &request);

    assert_eq!(
        outcome.decision().deny_reason(),
        Some(EvaluationDenyReason::UnverifiedSelectors)
    );
}

// ---------------------------------------------------------------------------
// Test 12: AudienceDenied — audience scope deny list matches
// ---------------------------------------------------------------------------

/// Grant where the audience entry has an explicit deny matching the audience.
const AUDIENCE_DENIED_JSON: &str = r#"{
  "trustgrant_id":"tg_00000000-0000-0000-0000-000000000040",
  "version":0,
  "grant_series_id":"tgs_00000000-0000-0000-0000-000000000041",
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
  "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":false,"allow":[{"kind":"authority","all":false,"values":["https://audience.example.com"],"expressions":null}],"deny":[{"kind":"authority","all":false,"values":["https://audience.example.com"],"expressions":null}]},"principal_scope":null}]},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

#[test]
fn audience_denied_evaluation_denied() {
    let grant = verified_grant_from_json(AUDIENCE_DENIED_JSON, RevocationStatus::Active);
    let engine = EvaluationEngine::new();
    // The audience entry's scope has an explicit deny matching the request's
    // audience context → AudienceDenied (deny wins over allow per spec §10).
    let outcome = engine.evaluate(&grant, &recognize_request("player-123"));

    assert_eq!(
        outcome.decision().deny_reason(),
        Some(EvaluationDenyReason::AudienceDenied)
    );
}

// ---------------------------------------------------------------------------
// Test 13: AudiencePrincipalDenied — principal scope deny list matches
// ---------------------------------------------------------------------------

/// Grant where the audience entry's principal scope has an explicit deny.
const AUDIENCE_PRINCIPAL_DENIED_JSON: &str = r#"{
  "trustgrant_id":"tg_00000000-0000-0000-0000-000000000050",
  "version":0,
  "grant_series_id":"tgs_00000000-0000-0000-0000-000000000051",
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
  "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":{"all":false,"allow":[{"kind":"actor","all":false,"values":["player-123"],"expressions":null}],"deny":[{"kind":"actor","all":false,"values":["player-123"],"expressions":null}]}}]},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

#[test]
fn audience_principal_denied_evaluation_denied() {
    let grant = verified_grant_from_json(AUDIENCE_PRINCIPAL_DENIED_JSON, RevocationStatus::Active);
    let engine = EvaluationEngine::new();
    // The principal scope has an explicit deny matching "player-123".
    // Deny wins over allow → AudiencePrincipalDenied.
    let outcome = engine.evaluate(&grant, &recognize_request("player-123"));

    assert_eq!(
        outcome.decision().deny_reason(),
        Some(EvaluationDenyReason::AudiencePrincipalDenied)
    );
}

// ---------------------------------------------------------------------------
// Test 14: MissingAudiencePrincipalContext — mint with per-user limit
// ---------------------------------------------------------------------------

/// Mint-enabled grant with per-user minting limit but no audience principal
/// context in the request.
const MISSING_AUDIENCE_PRINCIPAL_CONTEXT_JSON: &str = r#"{
  "trustgrant_id":"tg_00000000-0000-0000-0000-000000000060",
  "version":0,
  "grant_series_id":"tgs_00000000-0000-0000-0000-000000000061",
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
  "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":true},"constraints":{"minting":{"max_total":10,"max_per_user":1},"audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":null}]},"operations":{"all":false,"allow":["recognize","create"],"deny":null}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

#[test]
fn missing_audience_principal_context_evaluation_denied() {
    let grant = verified_grant_from_json(
        MISSING_AUDIENCE_PRINCIPAL_CONTEXT_JSON,
        RevocationStatus::Active,
    );

    // Build a mint request WITHOUT inserting audience principal selectors.
    // Per-user mint limits require an audience principal context.
    let mut resource = ResourceContext::new("item")
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));

    let origin = AuthorityId::new("https://issuer.example.com")
        .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"));

    let request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Mint),
        ResourceBinding::Mint(TemplateRef::new(origin)),
        AuthorityId::new("https://target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new("https://audience.example.com")
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"))
    .with_mint_context_for_testing(MintContext::new(5, 0))
    .verify_selectors();

    // NOTE: No .insert_audience_principal_selector() call

    let engine = EvaluationEngine::new();
    let outcome = engine.evaluate(&grant, &request);

    assert_eq!(
        outcome.decision().deny_reason(),
        Some(EvaluationDenyReason::MissingAudiencePrincipalContext)
    );
}

// ---------------------------------------------------------------------------
// Test 15: Stale revocation record at verification time
// ---------------------------------------------------------------------------

#[test]
fn stale_revocation_at_verification_level() {
    // Create a revocation record whose fresh_until is before verified_at.
    // checked_at must be <= fresh_until for the record to be internally valid.
    let fresh_until = fixed_timestamp(2026, 4, 6, 12, 0, 0);
    let checked_at = fixed_timestamp(2026, 4, 5, 12, 0, 0);
    let verified_at = fixed_timestamp(2026, 4, 7, 12, 0, 0);

    let record = RevocationRecord::new(
        RevocationStatus::Active,
        RevocationSourceKind::Api,
        ProofFinality::Observed,
        checked_at,
        fresh_until,
    )
    .unwrap_or_else(|error| panic!("revocation record should be valid: {error}"));

    assert!(
        fresh_until < verified_at,
        "precondition: fresh_until should be before verified_at"
    );

    let meta = VerificationMetadata::new(
        verified_at,
        VerificationPosture::Online,
        signer_binding(),
        ownership_record(),
        VerifiedRevocationState::Checked(record),
    );

    let pipeline = VerificationPipeline::new();
    let result = pipeline.verify_json_str(VALID_TRUSTGRANT_JSON, &FakeSignatureVerifier, meta);

    assert_eq!(result, Err(TrustGrantError::StaleRevocationRecord));
}

// ---------------------------------------------------------------------------
// Test 16: BlockMintingOnly — verification succeeds, recognize allowed,
//          mint denied
// ---------------------------------------------------------------------------

/// Grant with post_revocation_effect = "block_minting_only", revocable,
/// mint capability enabled, and both "recognize" and "create" operations.
const BLOCK_MINTING_ONLY_JSON: &str = r#"{
  "trustgrant_id":"tg_00000000-0000-0000-0000-000000000070",
  "version":0,
  "grant_series_id":"tgs_00000000-0000-0000-0000-000000000071",
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
  "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":true},"constraints":{"minting":{"max_total":10,"max_per_user":1},"audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":{"all":false,"allow":[{"kind":"actor","all":false,"values":["player-123"],"expressions":null}],"deny":null}}]},"operations":{"all":false,"allow":["recognize","create"],"deny":null}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_minting_only"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

#[test]
fn block_minting_only_survives_verification_and_denies_mint() {
    let pipeline = VerificationPipeline::new();
    let artifacts = pipeline
        .verify_json_str(
            BLOCK_MINTING_ONLY_JSON,
            &FakeSignatureVerifier,
            verification_metadata(RevocationStatus::Revoked),
        )
        .unwrap_or_else(|error| {
            panic!("verification should succeed with block_minting_only: {error}")
        });

    let grant = artifacts.verified_grant();

    let engine = EvaluationEngine::new();

    // Recognize should be allowed under block_minting_only
    let outcome = engine.evaluate(grant, &recognize_request("player-123"));
    assert!(
        outcome.decision().is_allowed(),
        "recognize should be allowed under block_minting_only",
    );

    // Build a mint request
    let mut resource = ResourceContext::new("item")
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));

    let origin = AuthorityId::new("https://issuer.example.com")
        .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"));

    let mut mint_req = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Mint),
        ResourceBinding::Mint(TemplateRef::new(origin)),
        AuthorityId::new("https://target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new("https://audience.example.com")
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));
    mint_req
        .insert_audience_principal_selector("actor", "player-123")
        .unwrap_or_else(|error| panic!("principal selector should be valid: {error}"));
    let mint_req = mint_req
        .with_mint_context_for_testing(MintContext::new(5, 0))
        .verify_selectors();

    // Mint should be denied with Revoked
    let second_outcome = engine.evaluate(grant, &mint_req);
    assert!(!second_outcome.decision().is_allowed());
    assert_eq!(
        second_outcome.decision().deny_reason(),
        Some(EvaluationDenyReason::Revoked),
        "mint should be denied due to revocation with block_minting_only",
    );
}
