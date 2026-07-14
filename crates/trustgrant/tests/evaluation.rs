#![allow(clippy::panic)]

use chrono::{TimeZone, Utc};

use trustgrant::{
    AuthorityId, AuthorityKeyRecord, EvaluationDenyReason, EvaluationEngine, EvaluationRequest,
    OwnershipProofKind, OwnershipVerificationRecord, ProofFinality, RequestedCapability,
    RequestedOperation, ResolvedSignerBinding, ResourceBinding, ResourceContext, ResourceRef,
    RevocationRecord, RevocationSourceKind, RevocationStatus, SignatureProfile,
    SignatureVerificationRequest, SignatureVerifier, TrustGrantError, VerificationMetadata,
    VerificationPipeline, VerificationPosture, VerifiedRevocationState, VerifiedTrustGrant,
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
  "default_audience_scope":null,
  "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":10,"max_per_user":1},"audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":{"all":false,"allow":[{"kind":"actor","all":false,"values":["player-123"],"expressions":null}],"deny":null}}]},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

const AUTHORITY_ID_TARGET_TRUSTGRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174010",
  "version":0,
  "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174011",
  "revision":1,
  "supersedes":null,
  "supersession_policy":"coexist",
  "issuer_authority":"https://issuer.example.com",
  "origin_authority":"https://issuer.example.com",
  "active_owning_authority":"https://issuer.example.com",
  "key_id":"root-key-1",
  "target_scope":{"all":false,"allow":[{"kind":"authority_id","all":false,"values":["https://target.example.com"],"expressions":null}],"deny":null},
  "capabilities":{"recognize":true,"mint":false},
  "default_audience_scope":null,
  "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":10,"max_per_user":1},"audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":{"all":false,"allow":[{"kind":"actor","all":false,"values":["player-123"],"expressions":null}],"deny":null}}]},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

const MIXED_CASE_PRINCIPAL_TRUSTGRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174020",
  "version":0,
  "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174021",
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
  "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":10,"max_per_user":1},"audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":{"all":false,"allow":[{"kind":"Actor","all":false,"values":["player-123"],"expressions":null}],"deny":null}}]},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

const CUSTOM_OPERATION_TRUSTGRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174030",
  "version":0,
  "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174031",
  "revision":1,
  "supersedes":null,
  "supersession_policy":"coexist",
  "issuer_authority":"https://issuer.example.com",
  "origin_authority":"https://issuer.example.com",
  "active_owning_authority":"https://issuer.example.com",
  "key_id":"root-key-1",
  "target_scope":{"all":false,"allow":[{"kind":"authority_id","all":false,"values":["https://target.example.com"],"expressions":null}],"deny":null},
  "capabilities":{"recognize":true,"mint":false},
  "default_audience_scope":null,
  "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":10,"max_per_user":1},"audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":{"all":false,"allow":[{"kind":"actor","all":false,"values":["player-123"],"expressions":null}],"deny":null}}]},"operations":{"all":false,"allow":["asset.download"],"deny":null}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

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

fn verified_grant(revocation_status: RevocationStatus) -> VerifiedTrustGrant {
    verified_grant_from_json(VALID_TRUSTGRANT_JSON, revocation_status)
}

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

fn custom_operation_request(
    operation_name: &str,
    actor: &str,
) -> Result<EvaluationRequest, TrustGrantError> {
    let mut resource = ResourceContext::new("item")?;
    resource.insert_selector("namespace", "weapons")?;

    let origin = AuthorityId::new("https://issuer.example.com")?;

    let mut request = EvaluationRequest::new(
        RequestedOperation::Custom(trustgrant::CustomOperationName::new(operation_name)?),
        ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
        AuthorityId::new("https://target.example.com")?,
        AuthorityId::new("https://audience.example.com")?,
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )?;

    request.insert_audience_principal_selector("actor", actor)?;

    Ok(request)
}

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

#[test]
fn parse_validate_verify_and_evaluate_allows_matching_request() {
    let engine = EvaluationEngine::new();
    let decision = engine.evaluate(
        &verified_grant(RevocationStatus::Active),
        &recognize_request("player-123"),
    );

    assert!(decision.is_allowed());
}

#[test]
fn parse_validate_verify_and_evaluate_denies_revoked_grant() {
    let engine = EvaluationEngine::new();
    let decision = engine.evaluate(
        &verified_grant(RevocationStatus::Revoked),
        &recognize_request("player-123"),
    );

    assert_eq!(decision.deny_reason(), Some(EvaluationDenyReason::Revoked));
}

#[test]
fn parse_validate_verify_and_evaluate_denies_audience_principal_mismatch() {
    let engine = EvaluationEngine::new();
    let decision = engine.evaluate(
        &verified_grant(RevocationStatus::Active),
        &recognize_request("player-999"),
    );

    assert_eq!(
        decision.deny_reason(),
        Some(EvaluationDenyReason::AudiencePrincipalNotAllowed)
    );
}

#[test]
fn parse_validate_verify_and_evaluate_allows_authority_id_target_selector_alias() {
    let engine = EvaluationEngine::new();
    let decision = engine.evaluate(
        &verified_grant_from_json(
            AUTHORITY_ID_TARGET_TRUSTGRANT_JSON,
            RevocationStatus::Active,
        ),
        &recognize_request("player-123"),
    );

    assert!(decision.is_allowed());
}

#[test]
fn parse_validate_verify_and_evaluate_allows_mixed_case_actor_principal_kind() {
    let engine = EvaluationEngine::new();
    let decision = engine.evaluate(
        &verified_grant_from_json(
            MIXED_CASE_PRINCIPAL_TRUSTGRANT_JSON,
            RevocationStatus::Active,
        ),
        &recognize_request("player-123"),
    );

    assert!(
        decision.is_allowed(),
        "Actor (mixed case) should be recognized as the built-in actor kind"
    );
}

#[test]
fn parse_validate_verify_and_evaluate_allows_exact_profile_custom_operation() {
    let engine = EvaluationEngine::new();
    let request = custom_operation_request("asset.download", "player-123")
        .unwrap_or_else(|error| panic!("custom operation request should be valid: {error}"));
    let decision = engine.evaluate(
        &verified_grant_from_json(CUSTOM_OPERATION_TRUSTGRANT_JSON, RevocationStatus::Active),
        &request,
    );

    assert!(decision.is_allowed());
}

#[test]
fn parse_validate_verify_and_evaluate_denies_mixed_case_custom_operation_without_alias() {
    let engine = EvaluationEngine::new();
    let request = custom_operation_request("Asset.Download", "player-123")
        .unwrap_or_else(|error| panic!("custom operation request should be valid: {error}"));
    let decision = engine.evaluate(
        &verified_grant_from_json(CUSTOM_OPERATION_TRUSTGRANT_JSON, RevocationStatus::Active),
        &request,
    );

    assert_eq!(
        decision.deny_reason(),
        Some(EvaluationDenyReason::OperationDenied)
    );
}
