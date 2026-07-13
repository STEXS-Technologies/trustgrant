#![allow(clippy::panic)]

use chrono::{TimeZone, Utc};

use trustgrant::{
    AuthorityId, AuthorityKeyRecord, BundleRevocationProof, EvaluationDenyReason, EvaluationEngine,
    EvaluationRequest, OwnershipProofKind, OwnershipVerificationRecord,
    ProofFinality, RequestedCapability, RequestedOperation, ResolvedSignerBinding, ResourceContext,
    RevocationFreshnessPolicy, RevocationRecord, RevocationSourceKind, RevocationStatus,
    SignatureProfile, SignatureVerificationRequest, SignatureVerifier, SupersessionPolicy,
    TrustGrantError, TrustGrantProofBundle, VerificationContext, VerificationMetadata,
    VerificationPipeline, VerificationPosture, VerifiedRevocationState, VerifiedTrustGrant,
    parse_authority_discovery_document, parse_revocation_status_proof,
};

// ---------------------------------------------------------------------------
// FakeSignatureVerifier (same pattern as evaluation.rs)
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
// Grant JSON constants
// ---------------------------------------------------------------------------

/// Test 1: Grant with two resource types ("item" and "badge").
const MULTI_RESOURCE_TRUSTGRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_aa000001-0000-1000-a000-000000000001",
  "version":0,
  "grant_series_id":"tgs_aa000001-0000-1000-a000-000000000002",
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
  "resource_scope":{"types":{
    "item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}},
    "badge":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["achievements"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}
  }},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

/// Test 2: Grant with a selector expression (startsWith) instead of fixed values.
const SELECTOR_EXPRESSION_TRUSTGRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_bb000001-0000-1000-a000-000000000001",
  "version":0,
  "grant_series_id":"tgs_bb000001-0000-1000-a000-000000000002",
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
  "resource_scope":{"types":{
    "item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":null,"expressions":["startsWith(\"weapon_\")"]}],"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}
  }},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

/// Test 3: Grant with default_audience_scope that has a principal_scope restricting by player_id.
const AUDIENCE_PRINCIPAL_SCOPE_TRUSTGRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_cc000001-0000-1000-a000-000000000001",
  "version":0,
  "grant_series_id":"tgs_cc000001-0000-1000-a000-000000000002",
  "revision":1,
  "supersedes":null,
  "supersession_policy":"coexist",
  "issuer_authority":"https://issuer.example.com",
  "origin_authority":"https://issuer.example.com",
  "active_owning_authority":"https://issuer.example.com",
  "key_id":"root-key-1",
  "target_scope":{"all":true,"allow":null,"deny":null},
  "capabilities":{"recognize":true,"mint":false},
  "default_audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":{"all":false,"allow":[{"kind":"player_id","all":false,"values":["player-123"],"expressions":null}],"deny":null}}],
  "resource_scope":{"types":{
    "item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":true,"allow":null,"deny":null}}
  }},
  "global_constraints":null,
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

/// Test 4: Grant with revocation endpoint, verified via bundle.
const REVOCATION_BUNDLE_TRUSTGRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_dd000001-0000-1000-a000-000000000001",
  "version":0,
  "grant_series_id":"tgs_dd000001-0000-1000-a000-000000000002",
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
  "resource_scope":{"types":{
    "item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":true,"allow":null,"deny":null}}
  }},
  "global_constraints":null,
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

/// Discovery document for the revocation bundle test (with delegation support).
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
  "delegation":{
    "principals_supported":true,
    "principal_key_endpoint":"https://issuer.example.com/.well-known/trustgrant/principals/{kind}/{id}"
  },
  "issued_at":"2026-04-07T12:00:00Z"
}"#;

/// Revocation proof with status=Active for the bundle test.
const ACTIVE_REVOCATION_JSON: &str = r#"{
  "trustgrant_id":"tg_dd000001-0000-1000-a000-000000000001",
  "status":"active",
  "checked_at":"2026-04-07T12:00:00Z"
}"#;

/// Delegated principal key document for the revocation bundle test.
const DELEGATED_PRINCIPAL_KEYS_JSON: &str = r#"{
  "authority_id":"https://issuer.example.com",
  "principal":{"kind":"service","id":"issuer-worker"},
  "keys":[
    {
      "key_id":"root-key-1",
      "algorithm":"ed25519",
      "public_key":"base64-root-public-key",
      "not_before":"2026-01-01T00:00:00Z",
      "not_after":"2027-01-01T00:00:00Z",
      "revoked":false
    }
  ]
}"#;

// ---------------------------------------------------------------------------
// Test 5: Capabilities inheritance — 3 branches
// ---------------------------------------------------------------------------

/// Branch 1: global mint=true, per-type mint=false → per-type wins → disabled.
const CAP_BRANCH1_JSON: &str = r#"{
  "trustgrant_id":"tg_ff000001-0000-1000-a000-000000000001",
  "version":0,
  "grant_series_id":"tgs_ff000001-0000-1000-a000-000000000002",
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
  "resource_scope":{"types":{
    "item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["create"],"deny":null}}
  }},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

/// Branch 2: global mint=false, per-type mint=null → falls through to global (disabled).
const CAP_BRANCH2_JSON: &str = r#"{
  "trustgrant_id":"tg_ff000001-0000-1000-a000-000000000003",
  "version":0,
  "grant_series_id":"tgs_ff000001-0000-1000-a000-000000000004",
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
  "resource_scope":{"types":{
    "item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":null},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["create"],"deny":null}}
  }},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

/// Branch 3: global mint=false, per-type mint=true → per-type overrides → enabled.
const CAP_BRANCH3_JSON: &str = r#"{
  "trustgrant_id":"tg_ff000001-0000-1000-a000-000000000005",
  "version":0,
  "grant_series_id":"tgs_ff000001-0000-1000-a000-000000000006",
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
  "resource_scope":{"types":{
    "item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":true},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["create"],"deny":null}}
  }},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

// ---------------------------------------------------------------------------
// Test 7: Mint with explicit operations scope
// ---------------------------------------------------------------------------

/// Grant with operations = {"all":false,"allow":["create"],"deny":null}.
const OP_SCOPE_CREATE_JSON: &str = r#"{
  "trustgrant_id":"tg_ff000001-0000-1000-a000-000000000007",
  "version":0,
  "grant_series_id":"tgs_ff000001-0000-1000-a000-000000000008",
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
  "resource_scope":{"types":{
    "item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":true},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["create"],"deny":null}}
  }},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

/// Grant with operations = {"all":false,"allow":["recognize"],"deny":null} — no "create".
const OP_SCOPE_RECOGNIZE_JSON: &str = r#"{
  "trustgrant_id":"tg_ff000001-0000-1000-a000-000000000009",
  "version":0,
  "grant_series_id":"tgs_ff000001-0000-1000-a000-000000000010",
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
  "resource_scope":{"types":{
    "item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":true},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}
  }},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

// ---------------------------------------------------------------------------
// Test 8: Supersession policy — coexist and supersede_previous
// ---------------------------------------------------------------------------

/// Grant with supersession_policy="coexist", revision 2.
const SUPERSESSION_COEXIST_JSON: &str = r#"{
  "trustgrant_id":"tg_ff000001-0000-1000-a000-000000000011",
  "version":0,
  "grant_series_id":"tgs_ff000001-0000-1000-a000-000000000012",
  "revision":2,
  "supersedes":null,
  "supersession_policy":"coexist",
  "issuer_authority":"https://issuer.example.com",
  "origin_authority":"https://issuer.example.com",
  "active_owning_authority":"https://issuer.example.com",
  "key_id":"root-key-1",
  "target_scope":{"all":true,"allow":null,"deny":null},
  "capabilities":{"recognize":true,"mint":false},
  "default_audience_scope":null,
  "resource_scope":{"types":{
    "item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":true,"allow":null,"deny":null}}
  }},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

/// Grant with supersession_policy="supersede_previous", revision 2.
const SUPERSESSION_SUPERSEDE_JSON: &str = r#"{
  "trustgrant_id":"tg_ff000001-0000-1000-a000-000000000013",
  "version":0,
  "grant_series_id":"tgs_ff000001-0000-1000-a000-000000000014",
  "revision":2,
  "supersedes":null,
  "supersession_policy":"supersede_previous",
  "issuer_authority":"https://issuer.example.com",
  "origin_authority":"https://issuer.example.com",
  "active_owning_authority":"https://issuer.example.com",
  "key_id":"root-key-1",
  "target_scope":{"all":true,"allow":null,"deny":null},
  "capabilities":{"recognize":true,"mint":false},
  "default_audience_scope":null,
  "resource_scope":{"types":{
    "item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":true,"allow":null,"deny":null}}
  }},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

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

/// Verifies a grant JSON through the full pipeline (online posture, direct metadata).
fn verified_grant_from_json(json: &str) -> VerifiedTrustGrant {
    let pipeline = VerificationPipeline::new();
    let artifacts = pipeline
        .verify_json_str(
            json,
            &FakeSignatureVerifier,
            verification_metadata(RevocationStatus::Active),
        )
        .unwrap_or_else(|error| panic!("pipeline verification should succeed: {error}"));
    artifacts.verified_grant().clone()
}

/// Builds a recognition request for the given resource type, namespace, and player_id.
fn recognize_request(resource_type: &str, namespace: &str, player_id: &str) -> EvaluationRequest {
    let mut resource = ResourceContext::new(resource_type)
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", namespace)
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
        .insert_audience_principal_selector("player_id", player_id)
        .unwrap_or_else(|error| panic!("principal selector should be valid: {error}"));

    request
}

/// Builds a simple recognition request (no audience principal context).
/// Builds a simple mint request (no audience principal context, no mint context).
fn simple_mint_request(resource_type: &str, namespace: &str) -> EvaluationRequest {
    let mut resource = ResourceContext::new(resource_type)
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", namespace)
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));

    EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Mint),
        AuthorityId::new("https://target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new("https://audience.example.com")
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"))
}

fn simple_recognize_request(resource_type: &str, namespace: &str) -> EvaluationRequest {
    let mut resource = ResourceContext::new(resource_type)
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", namespace)
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));

    EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        AuthorityId::new("https://target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new("https://audience.example.com")
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"))
}

/// Builds a proof bundle for offline/bundle verification of the revocation grant.
fn revocation_bundle() -> TrustGrantProofBundle {
    let mut proof_bundle = TrustGrantProofBundle::new();
    proof_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(ROOT_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("discovery should insert: {error}"));
    proof_bundle
        .insert_delegated_principal_document(
            trustgrant::parse_delegated_principal_key_document(DELEGATED_PRINCIPAL_KEYS_JSON)
                .unwrap_or_else(|error| panic!("delegated principal should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("delegated principal should insert: {error}"));
    proof_bundle
        .insert_revocation_proof(BundleRevocationProof::new(
            parse_revocation_status_proof(ACTIVE_REVOCATION_JSON)
                .unwrap_or_else(|error| panic!("revocation proof should parse: {error}")),
            RevocationSourceKind::ProofBundle,
            ProofFinality::TrustedSnapshot,
            RevocationFreshnessPolicy::new(120, 900)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        ))
        .unwrap_or_else(|error| panic!("revocation proof should insert: {error}"));
    proof_bundle
}

// ---------------------------------------------------------------------------
// Test 1: Multiple resource types in one grant
// ---------------------------------------------------------------------------

#[test]
fn multi_resource_grant_verifies_and_allows_item() {
    let grant = verified_grant_from_json(MULTI_RESOURCE_TRUSTGRANT_JSON);
    let engine = EvaluationEngine::new();
    let request = recognize_request("item", "weapons", "player-123");

    let decision = engine.evaluate(&grant, &request);
    assert!(decision.is_allowed());
}

#[test]
fn multi_resource_grant_allows_badge() {
    let grant = verified_grant_from_json(MULTI_RESOURCE_TRUSTGRANT_JSON);
    let engine = EvaluationEngine::new();
    let request = recognize_request("badge", "achievements", "player-123");

    let decision = engine.evaluate(&grant, &request);
    assert!(decision.is_allowed());
}

#[test]
fn multi_resource_grant_denies_unknown_resource_type() {
    let grant = verified_grant_from_json(MULTI_RESOURCE_TRUSTGRANT_JSON);
    let engine = EvaluationEngine::new();
    // "weapon" is not one of the granted resource types ("item" or "badge")
    let request = simple_recognize_request("weapon", "swords");

    let decision = engine.evaluate(&grant, &request);
    assert_eq!(
        decision.deny_reason(),
        Some(EvaluationDenyReason::ResourceTypeNotGranted)
    );
}

// ---------------------------------------------------------------------------
// Test 2: Selector expressions
// ---------------------------------------------------------------------------

#[test]
fn selector_expression_grant_verifies_and_allows_matching_prefix() {
    let grant = verified_grant_from_json(SELECTOR_EXPRESSION_TRUSTGRANT_JSON);
    let engine = EvaluationEngine::new();
    let request = simple_recognize_request("item", "weapon_sword");

    let decision = engine.evaluate(&grant, &request);
    assert!(decision.is_allowed());
}

#[test]
fn selector_expression_grant_denies_non_matching_prefix() {
    let grant = verified_grant_from_json(SELECTOR_EXPRESSION_TRUSTGRANT_JSON);
    let engine = EvaluationEngine::new();
    let request = simple_recognize_request("item", "armor_shield");

    let decision = engine.evaluate(&grant, &request);
    assert_eq!(
        decision.deny_reason(),
        Some(EvaluationDenyReason::ResourceNotAllowed)
    );
}

// ---------------------------------------------------------------------------
// Test 3: Full audience principal scope end-to-end
// ---------------------------------------------------------------------------

#[test]
fn audience_principal_scope_allows_matching_player() {
    let grant = verified_grant_from_json(AUDIENCE_PRINCIPAL_SCOPE_TRUSTGRANT_JSON);
    let engine = EvaluationEngine::new();
    let request = recognize_request("item", "general", "player-123");

    let decision = engine.evaluate(&grant, &request);
    assert!(decision.is_allowed());
}

#[test]
fn audience_principal_scope_denies_non_matching_player() {
    let grant = verified_grant_from_json(AUDIENCE_PRINCIPAL_SCOPE_TRUSTGRANT_JSON);
    let engine = EvaluationEngine::new();
    let request = recognize_request("item", "general", "player-999");

    let decision = engine.evaluate(&grant, &request);
    assert_eq!(
        decision.deny_reason(),
        Some(EvaluationDenyReason::AudiencePrincipalNotAllowed)
    );
}

// ---------------------------------------------------------------------------
// Test 4: Grant with inline revocation endpoint, verified with bundle
// ---------------------------------------------------------------------------

#[test]
fn revocation_bundle_verification_succeeds_with_active_status() {
    let proof_bundle = revocation_bundle();

    let result = VerificationPipeline::new().verify_json_str_with_sources(
        REVOCATION_BUNDLE_TRUSTGRANT_JSON,
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
fn revocation_bundle_evaluation_allows_active_grant() {
    let proof_bundle = revocation_bundle();

    let artifacts = VerificationPipeline::new()
        .verify_json_str_with_sources(
            REVOCATION_BUNDLE_TRUSTGRANT_JSON,
            &FakeSignatureVerifier,
            proof_bundle.as_sources(),
            VerificationContext::new(
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                VerificationPosture::Offline,
            ),
        )
        .unwrap_or_else(|error| panic!("bundle verification should succeed: {error}"));

    let engine = EvaluationEngine::new();
    let request = simple_recognize_request("item", "general");

    let decision = engine.evaluate(artifacts.verified_grant(), &request);
    assert!(decision.is_allowed());
}

// ---------------------------------------------------------------------------
// Test 5: Capabilities inheritance (spec §11)
// ---------------------------------------------------------------------------

#[test]
fn capabilities_inheritance_global_overrides_per_type() {
    // Spec §11: per-type capabilities override global.
    // Branch 1: global mint=true, per-type mint=false → per-type wins → CapabilityDisabled
    // Branch 2: global mint=false, per-type mint=null → falls through to global → CapabilityDisabled
    // Branch 3: global mint=false, per-type mint=true → per-type overrides → allowed

    let engine = EvaluationEngine::new();

    // Branch 1: global=true, per-type=false → CapabilityDisabled
    {
        let grant = verified_grant_from_json(CAP_BRANCH1_JSON);
        let request = simple_mint_request("item", "weapons");
        let decision = engine.evaluate(&grant, &request);
        assert_eq!(
            decision.deny_reason(),
            Some(EvaluationDenyReason::CapabilityDisabled),
            "branch 1: global mint=true, per-type mint=false should disable mint",
        );
    }

    // Branch 2: global=false, per-type=null → uses global → CapabilityDisabled
    {
        let grant = verified_grant_from_json(CAP_BRANCH2_JSON);
        let request = simple_mint_request("item", "weapons");
        let decision = engine.evaluate(&grant, &request);
        assert_eq!(
            decision.deny_reason(),
            Some(EvaluationDenyReason::CapabilityDisabled),
            "branch 2: global mint=false, per-type mint=null should fall through to global (disabled)",
        );
    }

    // Branch 3: global=false, per-type=true → per-type overrides → allowed
    {
        let grant = verified_grant_from_json(CAP_BRANCH3_JSON);
        let request = simple_mint_request("item", "weapons");
        let decision = engine.evaluate(&grant, &request);
        assert!(
            decision.is_allowed(),
            "branch 3: global mint=false, per-type mint=true should allow mint",
        );
    }
}

// ---------------------------------------------------------------------------
// Test 6: Origin authority enforcement (spec §13 step 3)
// ---------------------------------------------------------------------------

#[test]
fn origin_authority_mismatch_denies_evaluation() {
    // Use the existing multi-resource grant (origin_authority="https://issuer.example.com").
    let grant = verified_grant_from_json(MULTI_RESOURCE_TRUSTGRANT_JSON);
    let engine = EvaluationEngine::new();

    // Request with matching origin_authority should succeed.
    {
        let request = simple_recognize_request("item", "weapons")
            .with_origin_authority(
                AuthorityId::new("https://issuer.example.com")
                    .unwrap_or_else(|error| panic!("authority should be valid: {error}")),
            );
        let decision = engine.evaluate(&grant, &request);
        assert!(
            decision.is_allowed(),
            "matching origin_authority should be allowed",
        );
    }

    // Request with mismatched origin_authority should be denied.
    {
        let request = simple_recognize_request("item", "weapons")
            .with_origin_authority(
                AuthorityId::new("https://other.example.com")
                    .unwrap_or_else(|error| panic!("authority should be valid: {error}")),
            );
        let decision = engine.evaluate(&grant, &request);
        assert_eq!(
            decision.deny_reason(),
            Some(EvaluationDenyReason::OriginAuthorityMismatch),
            "mismatched origin_authority should be denied",
        );
    }
}

// ---------------------------------------------------------------------------
// Test 7: Mint with explicit operations scope (spec §6.1)
// ---------------------------------------------------------------------------

#[test]
fn mint_with_explicit_operations_scope() {
    let engine = EvaluationEngine::new();

    // Sub-test: operations scope contains "create" → mint allowed.
    {
        let grant = verified_grant_from_json(OP_SCOPE_CREATE_JSON);
        let request = simple_mint_request("item", "weapons");
        let decision = engine.evaluate(&grant, &request);
        assert!(
            decision.is_allowed(),
            "mint should be allowed when operations scope contains 'create'",
        );
    }

    // Sub-test: operations scope does NOT contain "create" → OperationDenied.
    {
        let grant = verified_grant_from_json(OP_SCOPE_RECOGNIZE_JSON);
        let request = simple_mint_request("item", "weapons");
        let decision = engine.evaluate(&grant, &request);
        assert_eq!(
            decision.deny_reason(),
            Some(EvaluationDenyReason::OperationDenied),
            "mint should be denied when operations scope lacks 'create'",
        );
    }
}

// ---------------------------------------------------------------------------
// Test 8: Supersession policy — supersede_previous (spec §2.5)
// ---------------------------------------------------------------------------

#[test]
fn supersession_policy_supersede_previous_behavior() {
    // Verify that both coexist and supersede_previous policies parse and
    // round-trip through the verification pipeline.

    // Coexist
    {
        let grant = verified_grant_from_json(SUPERSESSION_COEXIST_JSON);
        assert_eq!(
            grant.lineage().supersession_policy(),
            SupersessionPolicy::Coexist,
            "supersession_policy 'coexist' should round-trip",
        );
    }

    // Supersede previous
    {
        let grant = verified_grant_from_json(SUPERSESSION_SUPERSEDE_JSON);
        assert_eq!(
            grant.lineage().supersession_policy(),
            SupersessionPolicy::SupersedePrevious,
            "supersession_policy 'supersede_previous' should round-trip",
        );
    }
}
