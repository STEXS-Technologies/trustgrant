#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result, clippy::panic_in_result_fn, clippy::indexing_slicing)]

use chrono::{TimeZone, Utc};

use trustgrant::limits;
use trustgrant::{
    AuthorityId, AuthorityKeyRecord, BundleRevocationProof, CustomOperationName,
    EvaluationDenyReason, EvaluationEngine, EvaluationRequest, OwnershipProofKind,
    OwnershipVerificationRecord, ProofFinality, RawOwnershipTransitionDocument,
    RawTrustGrantDocument, RequestedCapability, RequestedOperation, ResolvedSignerBinding,
    ResourceBinding, ResourceContext, ResourceRef, RevocationFreshnessPolicy, RevocationRecord,
    RevocationSourceKind, RevocationStatus, SelectorContext, SignatureProfile,
    SignatureVerificationRequest, SignatureVerifier, SupersessionPolicy, TemplateRef,
    TrustGrantError, TrustGrantProofBundle, ValidatedPrincipal, VerificationContext,
    VerificationMetadata, VerificationPipeline, VerificationPosture, VerifiedRevocationState,
    VerifiedTrustGrant, parse_authority_discovery_document, parse_revocation_status_proof,
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
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
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
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

/// Test 3: Grant with default_audience_scope that has a principal_scope restricting by actor.
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
  "default_audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":{"all":false,"allow":[{"kind":"actor","all":false,"values":["player-123"],"expressions":null}],"deny":null}}],
  "resource_scope":{"types":{
    "item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}
  }},
  "global_constraints":null,
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
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
    "item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}
  }},
  "global_constraints":null,
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
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
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
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
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
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
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
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
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
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
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
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
    "item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}
  }},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
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
    "item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}
  }},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
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

/// Builds a recognition request for the given resource type, namespace, and actor.
fn recognize_request(resource_type: &str, namespace: &str, actor: &str) -> EvaluationRequest {
    let mut resource = ResourceContext::new(resource_type)
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", namespace)
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));

    let origin = AuthorityId::new("https://issuer.example.com")
        .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"));

    let mut request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(ResourceRef::new(origin, resource_type.to_owned())),
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

/// Builds a simple recognition request (no audience principal context).
/// Builds a simple mint request (no audience principal context, no mint context).
fn simple_mint_request(resource_type: &str, namespace: &str) -> EvaluationRequest {
    let mut resource = ResourceContext::new(resource_type)
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", namespace)
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));

    let origin = AuthorityId::new("https://issuer.example.com")
        .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"));

    EvaluationRequest::new(
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
    .verify_selectors()
}

fn simple_recognize_request(resource_type: &str, namespace: &str) -> EvaluationRequest {
    let mut resource = ResourceContext::new(resource_type)
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", namespace)
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));

    let origin = AuthorityId::new("https://issuer.example.com")
        .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"));

    EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(ResourceRef::new(origin, resource_type.to_owned())),
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
            RevocationFreshnessPolicy::new(86400, 86400)
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

    let outcome = engine.evaluate(&grant, &request);
    assert!(outcome.decision().is_allowed());
}

#[test]
fn multi_resource_grant_allows_badge() {
    let grant = verified_grant_from_json(MULTI_RESOURCE_TRUSTGRANT_JSON);
    let engine = EvaluationEngine::new();
    let request = recognize_request("badge", "achievements", "player-123");

    let outcome = engine.evaluate(&grant, &request);
    assert!(outcome.decision().is_allowed());
}

#[test]
fn multi_resource_grant_denies_unknown_resource_type() {
    let grant = verified_grant_from_json(MULTI_RESOURCE_TRUSTGRANT_JSON);
    let engine = EvaluationEngine::new();
    // "weapon" is not one of the granted resource types ("item" or "badge")
    let request = simple_recognize_request("weapon", "swords");

    let outcome = engine.evaluate(&grant, &request);
    assert_eq!(
        outcome.decision().deny_reason(),
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

    let outcome = engine.evaluate(&grant, &request);
    assert!(outcome.decision().is_allowed());
}

#[test]
fn selector_expression_grant_denies_non_matching_prefix() {
    let grant = verified_grant_from_json(SELECTOR_EXPRESSION_TRUSTGRANT_JSON);
    let engine = EvaluationEngine::new();
    let request = simple_recognize_request("item", "armor_shield");

    let outcome = engine.evaluate(&grant, &request);
    assert_eq!(
        outcome.decision().deny_reason(),
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

    let outcome = engine.evaluate(&grant, &request);
    assert!(outcome.decision().is_allowed());
}

#[test]
fn audience_principal_scope_denies_non_matching_player() {
    let grant = verified_grant_from_json(AUDIENCE_PRINCIPAL_SCOPE_TRUSTGRANT_JSON);
    let engine = EvaluationEngine::new();
    let request = recognize_request("item", "general", "player-999");

    let outcome = engine.evaluate(&grant, &request);
    assert_eq!(
        outcome.decision().deny_reason(),
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

    let outcome = engine.evaluate(artifacts.verified_grant(), &request);
    assert!(outcome.decision().is_allowed());
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
        let outcome = engine.evaluate(&grant, &request);
        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::CapabilityDisabled),
            "branch 1: global mint=true, per-type mint=false should disable mint",
        );
    }

    // Branch 2: global=false, per-type=null → uses global → CapabilityDisabled
    {
        let grant = verified_grant_from_json(CAP_BRANCH2_JSON);
        let request = simple_mint_request("item", "weapons");
        let outcome = engine.evaluate(&grant, &request);
        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::CapabilityDisabled),
            "branch 2: global mint=false, per-type mint=null should fall through to global (disabled)",
        );
    }

    // Branch 3: global=false, per-type=true → per-type overrides → allowed
    {
        let grant = verified_grant_from_json(CAP_BRANCH3_JSON);
        let request = simple_mint_request("item", "weapons");
        let outcome = engine.evaluate(&grant, &request);
        assert!(
            outcome.decision().is_allowed(),
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
        let origin = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("authority should be valid: {error}"));
        let mut resource = ResourceContext::new("item")
            .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
        resource
            .insert_selector("namespace", "weapons")
            .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));
        let request = EvaluationRequest::new(
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
        let outcome = engine.evaluate(&grant, &request);
        assert!(
            outcome.decision().is_allowed(),
            "matching origin_authority should be allowed",
        );
    }

    // Request with mismatched origin_authority should be denied.
    {
        let origin = AuthorityId::new("https://other.example.com")
            .unwrap_or_else(|error| panic!("authority should be valid: {error}"));
        let mut resource = ResourceContext::new("item")
            .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
        resource
            .insert_selector("namespace", "weapons")
            .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));
        let request = EvaluationRequest::new(
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
        let outcome = engine.evaluate(&grant, &request);
        assert_eq!(
            outcome.decision().deny_reason(),
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
        let outcome = engine.evaluate(&grant, &request);
        assert!(
            outcome.decision().is_allowed(),
            "mint should be allowed when operations scope contains 'create'",
        );
    }

    // Sub-test: operations scope does NOT contain "create" → OperationDenied.
    {
        let grant = verified_grant_from_json(OP_SCOPE_RECOGNIZE_JSON);
        let request = simple_mint_request("item", "weapons");
        let outcome = engine.evaluate(&grant, &request);
        assert_eq!(
            outcome.decision().deny_reason(),
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

// ---------------------------------------------------------------------------
// P2.1: Empty deny list = null deny  (spec §10)
// ---------------------------------------------------------------------------

/// Grant with deny:null in resource scope (equivalent to no deny restrictions).
const DENY_NULL_GRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_aa000001-0000-1000-a000-000000000050",
  "version":0,
  "grant_series_id":"tgs_aa000001-0000-1000-a000-000000000051",
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
    "item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}
  }},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

/// Grant with deny:[] (empty list) — should behave identically to deny:null.
const DENY_EMPTY_GRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_aa000001-0000-1000-a000-000000000052",
  "version":0,
  "grant_series_id":"tgs_aa000001-0000-1000-a000-000000000053",
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
    "item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":[],"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}
  }},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

#[test]
fn empty_deny_list_equals_null_deny() {
    // Spec §10: an empty deny list behaves identically to null deny.
    // Both grants should produce identical evaluation results (allowed).
    let engine = EvaluationEngine::new();

    let grant_null = verified_grant_from_json(DENY_NULL_GRANT_JSON);
    let grant_empty = verified_grant_from_json(DENY_EMPTY_GRANT_JSON);

    let request = simple_recognize_request("item", "weapons");

    let outcome_null = engine.evaluate(&grant_null, &request);
    let outcome_empty = engine.evaluate(&grant_empty, &request);

    assert_eq!(
        outcome_null.decision().is_allowed(),
        outcome_empty.decision().is_allowed(),
        "empty deny list should yield same result as null deny",
    );
    assert!(
        outcome_null.decision().is_allowed(),
        "matching resource should be allowed regardless of deny format",
    );
}

// ---------------------------------------------------------------------------
// P2.2: Multiple audience entries  (spec §9)
// ---------------------------------------------------------------------------

const MULTI_AUDIENCE_GRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_aa000001-0000-1000-a000-000000000054",
  "version":0,
  "grant_series_id":"tgs_aa000001-0000-1000-a000-000000000055",
  "revision":1,
  "supersedes":null,
  "supersession_policy":"coexist",
  "issuer_authority":"https://issuer.example.com",
  "origin_authority":"https://issuer.example.com",
  "active_owning_authority":"https://issuer.example.com",
  "key_id":"root-key-1",
  "target_scope":{"all":true,"allow":null,"deny":null},
  "capabilities":{"recognize":true,"mint":false},
  "default_audience_scope":[
    {"authority_id":"https://audience-a.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":null},
    {"authority_id":"https://audience-b.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":null}
  ],
  "resource_scope":{"types":{
    "item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}
  }},
  "global_constraints":null,
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

fn recognize_request_for_audience(
    resource_type: &str,
    namespace: &str,
    audience: &str,
) -> EvaluationRequest {
    let mut resource = ResourceContext::new(resource_type)
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", namespace)
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));

    let origin = AuthorityId::new("https://issuer.example.com")
        .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"));

    EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(ResourceRef::new(origin, resource_type.to_owned())),
        AuthorityId::new("https://target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new(audience)
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"))
}

#[test]
fn multiple_audience_entries_both_allowed() {
    // Spec §9: audience is an array. Both entries should work.
    let grant = verified_grant_from_json(MULTI_AUDIENCE_GRANT_JSON);
    let engine = EvaluationEngine::new();

    // Request with audience A → allowed
    {
        let request =
            recognize_request_for_audience("item", "general", "https://audience-a.example.com");
        let outcome = engine.evaluate(&grant, &request);
        assert!(
            outcome.decision().is_allowed(),
            "audience A should be allowed"
        );
    }

    // Request with audience B → allowed
    {
        let request =
            recognize_request_for_audience("item", "general", "https://audience-b.example.com");
        let outcome = engine.evaluate(&grant, &request);
        assert!(
            outcome.decision().is_allowed(),
            "audience B should be allowed"
        );
    }

    // Request with audience C → AudienceNotAllowed
    {
        let request =
            recognize_request_for_audience("item", "general", "https://audience-c.example.com");
        let outcome = engine.evaluate(&grant, &request);
        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::AudienceNotAllowed),
            "audience C should not be allowed",
        );
    }
}

// ---------------------------------------------------------------------------
// P2.3: Mixed operations scope (built-in + custom)  (spec §6.1)
// ---------------------------------------------------------------------------

const MIXED_OPS_GRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_aa000001-0000-1000-a000-000000000056",
  "version":0,
  "grant_series_id":"tgs_aa000001-0000-1000-a000-000000000057",
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
    "item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":{"recognize":null,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize","custom:export"],"deny":null}}
  }},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

fn custom_operation_request(
    operation_name: &str,
    resource_type: &str,
    namespace: &str,
) -> EvaluationRequest {
    let custom_op = CustomOperationName::new(operation_name)
        .unwrap_or_else(|error| panic!("custom operation name should be valid: {error}"));

    let mut resource = ResourceContext::new(resource_type)
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", namespace)
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));

    let origin = AuthorityId::new("https://issuer.example.com")
        .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"));

    EvaluationRequest::new(
        RequestedOperation::Custom(custom_op),
        ResourceBinding::Existing(ResourceRef::new(origin, resource_type.to_owned())),
        AuthorityId::new("https://target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new("https://audience.example.com")
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"))
}

#[test]
fn mixed_operations_scope_builtin_and_custom() {
    // Spec §6.1: operations scope can include both built-in (recognize)
    // and custom operations in the same allow list.
    let grant = verified_grant_from_json(MIXED_OPS_GRANT_JSON);
    let engine = EvaluationEngine::new();

    // Request recognize → allowed (via operations, not just capabilities)
    {
        let request = simple_recognize_request("item", "weapons");
        let outcome = engine.evaluate(&grant, &request);
        assert!(
            outcome.decision().is_allowed(),
            "recognize should be allowed via operations scope",
        );
    }

    // Request custom:export → allowed
    {
        let request = custom_operation_request("custom:export", "item", "weapons");
        let outcome = engine.evaluate(&grant, &request);
        assert!(
            outcome.decision().is_allowed(),
            "custom:export should be allowed via operations scope",
        );
    }

    // Request custom:import → OperationDenied
    {
        let request = custom_operation_request("custom:import", "item", "weapons");
        let outcome = engine.evaluate(&grant, &request);
        assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::OperationDenied),
            "custom:import should be denied",
        );
    }
}

// ---------------------------------------------------------------------------
// P3.1: Large document at size boundary
// ---------------------------------------------------------------------------

/// Builds a valid TrustGrant JSON document whose serialized byte length is
/// exactly `target` bytes by padding the `issuer_principal.id` field value.
fn grant_json_at_exact_size(target: usize) -> String {
    // Compact JSON prefix ending at the issuer_principal.id string value.
    let prefix = r#"{"trustgrant_id":"tg_sz","version":0,"grant_series_id":"tgs_sz","revision":1,"supersedes":null,"supersession_policy":"coexist","issuer_authority":"https://issuer.example.com","origin_authority":"https://issuer.example.com","active_owning_authority":"https://issuer.example.com","key_id":"root-key-1","target_scope":{"all":true,"allow":null,"deny":null},"capabilities":{"recognize":true,"mint":false},"default_audience_scope":null,"resource_scope":{"types":{}},"global_constraints":null,"revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},"issued_at":"2026-04-07T12:00:00Z","signature":"base64-signature","issuer_principal":{"kind":"service","id":""#;
    let suffix = r#""}}"#;
    let total = prefix.len().wrapping_add(suffix.len());
    let padding_needed = target.saturating_sub(total);
    format!(
        "{prefix}{padding}{suffix}",
        prefix = prefix,
        padding = "x".repeat(padding_needed),
        suffix = suffix
    )
}

#[test]
fn large_document_at_size_boundary() {
    // Protocol boundary: document at MAX_TRUSTGRANT_JSON_BYTES should
    // be accepted, one byte over should be rejected.
    let max_bytes = limits::MAX_TRUSTGRANT_JSON_BYTES;

    // Build a document that is exactly at the limit.
    let exact = grant_json_at_exact_size(max_bytes);
    assert_eq!(
        exact.len(),
        max_bytes,
        "exact-size document should match limit"
    );
    let exact_result = RawTrustGrantDocument::parse_json_bytes(exact.as_bytes());
    assert!(
        exact_result.is_ok(),
        "document at exact size limit should parse: {:?}",
        exact_result.err(),
    );

    // One byte over the limit should fail.
    let one_more = max_bytes.wrapping_add(1);
    let too_big = grant_json_at_exact_size(one_more);
    assert_eq!(
        too_big.len(),
        one_more,
        "oversize document should be one byte over"
    );
    let big_result = RawTrustGrantDocument::parse_json_bytes(too_big.as_bytes());
    assert!(
        big_result.is_err(),
        "document one byte over limit should be rejected",
    );
}

// ---------------------------------------------------------------------------
// P3.2: Duplicate selectors in evaluation request
// ---------------------------------------------------------------------------

#[test]
fn duplicate_selectors_in_evaluation_request() {
    // The SelectorContext should deduplicate identical selectors.
    let mut context = SelectorContext::new();
    context
        .insert("namespace", "weapons")
        .unwrap_or_else(|error| panic!("first insert should succeed: {error}"));
    context
        .insert("namespace", "weapons")
        .unwrap_or_else(|error| panic!("duplicate insert should succeed: {error}"));

    let values = context
        .values_for_kind_str("namespace")
        .unwrap_or_else(|| panic!("namespace selector should be present"));

    assert_eq!(
        values.len(),
        1,
        "duplicate selector values should be deduplicated",
    );
    assert_eq!(
        values.first(),
        Some(&"weapons".to_owned()),
        "deduplicated value should be preserved",
    );
}

// ---------------------------------------------------------------------------
// G17: SupersessionPolicy chains — grant supersedes a previous revision
// ---------------------------------------------------------------------------

/// Earlier grant (revision 1) that the superseding grant will reference.
const EARLIER_GRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_00000000-0000-0000-0000-000000000001",
  "version":0,
  "grant_series_id":"tgs_00000000-0000-0000-0000-000000000001",
  "revision":1,
  "supersedes":null,
  "supersession_policy":"supersede_previous",
  "issuer_authority":"https://issuer.example.com",
  "origin_authority":"https://issuer.example.com",
  "active_owning_authority":"https://issuer.example.com",
  "key_id":"root-key-1",
  "target_scope":{"all":true,"allow":null,"deny":null},
  "capabilities":{"recognize":true,"mint":false},
  "default_audience_scope":null,
  "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
  "global_constraints":null,
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

/// Superseding grant (revision 2) that supersedes the earlier grant.
const SUPERSEDING_GRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_00000000-0000-0000-0000-000000000002",
  "version":0,
  "grant_series_id":"tgs_00000000-0000-0000-0000-000000000001",
  "revision":2,
  "supersedes":"tg_00000000-0000-0000-0000-000000000001",
  "supersession_policy":"supersede_previous",
  "issuer_authority":"https://issuer.example.com",
  "origin_authority":"https://issuer.example.com",
  "active_owning_authority":"https://issuer.example.com",
  "key_id":"root-key-1",
  "target_scope":{"all":true,"allow":null,"deny":null},
  "capabilities":{"recognize":true,"mint":false},
  "default_audience_scope":null,
  "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
  "global_constraints":null,
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:30:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

#[test]
fn supersession_chain_earlier_grant_has_no_supersedes() {
    let grant = verified_grant_from_json(EARLIER_GRANT_JSON);
    // The earlier grant does not supersede anything.
    assert!(grant.lineage().supersedes().is_none());
    assert_eq!(grant.lineage().revision().get(), 1);
    assert_eq!(
        grant.lineage().supersession_policy(),
        SupersessionPolicy::SupersedePrevious,
    );
}

#[test]
fn supersession_chain_superseding_grant_points_to_earlier() {
    let grant = verified_grant_from_json(SUPERSEDING_GRANT_JSON);
    // The superseding grant's `supersedes` field points to the earlier grant.
    let supersedes = grant.lineage().supersedes();
    assert!(
        supersedes.is_some(),
        "superseding grant should have a supersedes value",
    );
    assert_eq!(
        supersedes.map(|id| id.to_string()).as_deref(),
        Some("tg_00000000-0000-0000-0000-000000000001"),
    );
    assert_eq!(grant.lineage().revision().get(), 2);
    assert_eq!(
        grant.lineage().supersession_policy(),
        SupersessionPolicy::SupersedePrevious,
    );
}

#[test]
fn supersession_chain_both_grants_verify_and_evaluate() {
    // Both grants should verify and evaluate independently.
    let engine = EvaluationEngine::new();

    let earlier = verified_grant_from_json(EARLIER_GRANT_JSON);
    let superseding = verified_grant_from_json(SUPERSEDING_GRANT_JSON);

    let request = simple_recognize_request("item", "general");

    let outcome_earlier = engine.evaluate(&earlier, &request);
    assert!(
        outcome_earlier.decision().is_allowed(),
        "earlier grant should allow matching request",
    );

    let outcome_superseding = engine.evaluate(&superseding, &request);
    assert!(
        outcome_superseding.decision().is_allowed(),
        "superseding grant should allow matching request",
    );
}

// ---------------------------------------------------------------------------
// G19: Grant with supersedes field pointing to an earlier grant
// ---------------------------------------------------------------------------

/// Grant that explicitly supersedes another grant via the `supersedes` field.
const G19_SUPERSEDES_GRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_00000000-0000-0000-0000-000000000003",
  "version":0,
  "grant_series_id":"tgs_00000000-0000-0000-0000-000000000002",
  "revision":2,
  "supersedes":"tg_00000000-0000-0000-0000-000000000001",
  "supersession_policy":"supersede_previous",
  "issuer_authority":"https://issuer.example.com",
  "origin_authority":"https://issuer.example.com",
  "active_owning_authority":"https://issuer.example.com",
  "key_id":"root-key-1",
  "target_scope":{"all":true,"allow":null,"deny":null},
  "capabilities":{"recognize":true,"mint":false},
  "default_audience_scope":null,
  "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
  "global_constraints":null,
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:30:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

#[test]
fn grant_with_supersedes_field_parses_and_evaluates() {
    let grant = verified_grant_from_json(G19_SUPERSEDES_GRANT_JSON);

    // The `supersedes` field must be preserved through parsing/validation.
    let supersedes = grant.lineage().supersedes();
    assert!(
        supersedes.is_some(),
        "grant with supersedes field should have Some value",
    );
    assert_eq!(
        supersedes.map(|id| id.to_string()).as_deref(),
        Some("tg_00000000-0000-0000-0000-000000000001"),
    );

    // The superseding grant should evaluate correctly.
    let engine = EvaluationEngine::new();
    let request = simple_recognize_request("item", "general");
    let outcome = engine.evaluate(&grant, &request);
    assert!(
        outcome.decision().is_allowed(),
        "superseding grant should evaluate to allowed",
    );
}

// ---------------------------------------------------------------------------
// Gap 6: Delegated capability grant — issuer_principal preserved
// ---------------------------------------------------------------------------

/// Grant with issuer_principal set (delegated principal).
const DELEGATED_CAPABILITY_GRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_00000000-0000-1000-a000-000000000070",
  "version":0,
  "grant_series_id":"tgs_00000000-0000-1000-a000-000000000071",
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
  "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

#[test]
fn delegated_capability_grant_preserves_issuer_principal() {
    // Verify that a grant with issuer_principal set preserves the delegated
    // principal through the full verification pipeline.
    let grant = verified_grant_from_json(DELEGATED_CAPABILITY_GRANT_JSON);

    let principal = grant.document().issuer_principal();
    assert!(
        principal.is_some(),
        "delegated capability grant should have issuer_principal",
    );
    assert_eq!(
        principal.map(|p: &ValidatedPrincipal| p.kind().as_str()),
        Some("service"),
        "issuer_principal kind should match",
    );
    assert_eq!(
        principal.map(|p: &ValidatedPrincipal| p.id().as_str()),
        Some("issuer-worker"),
        "issuer_principal id should match",
    );

    // The grant should still evaluate correctly for a matching request.
    let engine = EvaluationEngine::new();
    let request = simple_recognize_request("item", "general");
    let outcome = engine.evaluate(&grant, &request);
    assert!(
        outcome.decision().is_allowed(),
        "delegated capability grant should allow matching request",
    );
}

// ---------------------------------------------------------------------------
// Gap 7: Supersession coexist — two grants in same series both evaluate
// ---------------------------------------------------------------------------

/// First grant in series with coexist policy (revision 1).
const COEXIST_SERIES_GRANT_A_JSON: &str = r#"{
  "trustgrant_id":"tg_00000000-0000-1000-a000-000000000080",
  "version":0,
  "grant_series_id":"tgs_00000000-0000-1000-a000-000000000090",
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
  "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:00:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

/// Second grant in same series with coexist policy (revision 2).
const COEXIST_SERIES_GRANT_B_JSON: &str = r#"{
  "trustgrant_id":"tg_00000000-0000-1000-a000-000000000081",
  "version":0,
  "grant_series_id":"tgs_00000000-0000-1000-a000-000000000090",
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
  "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}},
  "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:30:00Z",
  "signature":"base64-signature",
  "issuer_principal":{"kind":"service","id":"issuer-worker"}
}"#;

#[test]
fn coexist_series_both_grants_verify_and_evaluate() {
    // With coexist policy, both grants in the same series should verify and
    // evaluate independently without conflict.
    let engine = EvaluationEngine::new();

    let grant_a = verified_grant_from_json(COEXIST_SERIES_GRANT_A_JSON);
    let grant_b = verified_grant_from_json(COEXIST_SERIES_GRANT_B_JSON);

    // Both grants should have the same series id
    assert_eq!(
        grant_a.lineage().grant_series_id(),
        grant_b.lineage().grant_series_id()
    );

    // Grant A has revision 1
    assert_eq!(grant_a.lineage().revision().get(), 1);
    assert_eq!(
        grant_a.lineage().supersession_policy(),
        SupersessionPolicy::Coexist,
    );

    // Grant B has revision 2
    assert_eq!(grant_b.lineage().revision().get(), 2);
    assert_eq!(
        grant_b.lineage().supersession_policy(),
        SupersessionPolicy::Coexist,
    );

    // Both should evaluate successfully
    let request = simple_recognize_request("item", "general");

    let outcome_a = engine.evaluate(&grant_a, &request);
    assert!(
        outcome_a.decision().is_allowed(),
        "grant A (coexist) should allow matching request",
    );

    let outcome_b = engine.evaluate(&grant_b, &request);
    assert!(
        outcome_b.decision().is_allowed(),
        "grant B (coexist) should allow matching request",
    );
}

// ---------------------------------------------------------------------------
// P2 gap: full_ownership_transfer_workflow
// ---------------------------------------------------------------------------

#[test]
fn full_ownership_transfer_workflow() {
    // ── Grant JSON (static owner) ──────────────────────────────────────
    // All authorities match — no transition chain needed.
    let static_grant_json = r#"{
      "trustgrant_id":"tg_ff000001-0000-1000-a000-000000000400",
      "version":0,
      "grant_series_id":"tgs_ff000001-0000-1000-a000-000000000401",
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
      "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["general"],"expressions":null}],"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
      "global_constraints":null,
      "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
      "issued_at":"2026-04-07T12:00:00Z",
      "signature":"base64-signature",
      "issuer_principal":null
    }"#;

    // ── Transferred grant JSON (same grant, new owner) ─────────────────
    // Core identity (trustgrant_id, target_scope, capabilities) unchanged,
    // but now owned and re-issued by the successor authority.
    let transferred_grant_json = r#"{
      "trustgrant_id":"tg_ff000001-0000-1000-a000-000000000400",
      "version":0,
      "grant_series_id":"tgs_ff000001-0000-1000-a000-000000000401",
      "revision":1,
      "supersedes":null,
      "supersession_policy":"coexist",
      "issuer_authority":"https://successor.example.com",
      "origin_authority":"https://issuer.example.com",
      "active_owning_authority":"https://successor.example.com",
      "key_id":"root-key-1",
      "target_scope":{"all":true,"allow":null,"deny":null},
      "capabilities":{"recognize":true,"mint":false},
      "default_audience_scope":null,
      "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["general"],"expressions":null}],"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
      "global_constraints":null,
      "revocation":{"revocable":true,"revocation_endpoint":"https://successor.example.com/revocation","post_revocation_effect":"block_all"},
      "issued_at":"2026-04-07T13:00:00Z",
      "signature":"base64-signature",
      "issuer_principal":null
    }"#;

    // ── Discovery documents ────────────────────────────────────────────
    let successor_discovery_json = r#"{
      "authority_id":"https://successor.example.com",
      "keys":[
        {
          "key_id":"root-key-1",
          "algorithm":"ed25519",
          "public_key":"base64-successor-public-key",
          "not_before":"2026-01-01T00:00:00Z",
          "not_after":"2027-01-01T00:00:00Z"
        }
      ],
      "signature_profile":{"format":"jcs+ed25519","canonicalization":"RFC8785"},
      "issued_at":"2026-04-07T12:00:00Z"
    }"#;

    // ── Revocation proof (shared between both phases) ──────────────────
    let revocation_json = r#"{
      "trustgrant_id":"tg_ff000001-0000-1000-a000-000000000400",
      "status":"active",
      "checked_at":"2026-04-07T12:00:00Z"
    }"#;

    // ── Ownership transition document ──────────────────────────────────
    // Transfers from origin (issuer) to successor.
    let transition_json = r#"{
      "transition_id":"tgt_ff000001-0000-1000-a000-000000000500",
      "version":0,
      "transition_series_id":"tgts_ff000001-0000-1000-a000-000000000501",
      "revision":1,
      "supersedes_transition_id":null,
      "origin_authority":"https://issuer.example.com",
      "from_authority":"https://issuer.example.com",
      "to_authority":"https://successor.example.com",
      "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["general"],"expressions":null}],"deny":null}}},
      "global_constraints":null,
      "effective_at":"2026-04-07T12:30:00Z",
      "predecessor_signature":{"key_id":"root-key-1","signature":"base64-signature"},
      "successor_acceptance":{"accepted_at":"2026-04-07T12:00:00Z","key_id":"root-key-1","signature":"base64-signature"}
    }"#;

    let verifier = FakeSignatureVerifier;
    let ts_initial = fixed_timestamp(2026, 4, 7, 12, 0, 0);
    let ts_transfer = fixed_timestamp(2026, 4, 7, 13, 0, 0);

    // ═══════════════════════════════════════════════════════════════════
    // Phase 1: Static owner — no transition chain needed
    // ═══════════════════════════════════════════════════════════════════
    let mut initial_bundle = TrustGrantProofBundle::new();
    initial_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(ROOT_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("discovery should insert: {error}"));
    initial_bundle
        .insert_revocation_proof(BundleRevocationProof::new(
            parse_revocation_status_proof(revocation_json)
                .unwrap_or_else(|error| panic!("revocation proof should parse: {error}")),
            RevocationSourceKind::ProofBundle,
            ProofFinality::TrustedSnapshot,
            RevocationFreshnessPolicy::new(86400, 86400)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        ))
        .unwrap_or_else(|error| panic!("revocation proof should insert: {error}"));

    let artifacts = VerificationPipeline::new()
        .verify_json_str_with_bundle(
            static_grant_json,
            &verifier,
            &initial_bundle,
            VerificationContext::new(ts_initial, VerificationPosture::Online),
        )
        .unwrap_or_else(|error| panic!("static owner verification should succeed: {error}"));

    let verified_grant = artifacts.verified_grant().clone();

    // Verify the ownership is static (no transition chain)
    assert_eq!(
        verified_grant.metadata().ownership().proof_kind(),
        OwnershipProofKind::StaticOwner,
    );
    assert_eq!(
        verified_grant
            .metadata()
            .ownership()
            .active_owning_authority()
            .as_str(),
        "https://issuer.example.com",
    );

    // ═══════════════════════════════════════════════════════════════════
    // Phase 1 step 2: Evaluate recognize request → Allowed
    // ═══════════════════════════════════════════════════════════════════
    let engine = EvaluationEngine::new();
    let request = simple_recognize_request("item", "general");
    let outcome = engine.evaluate(&verified_grant, &request);
    assert!(
        outcome.decision().is_allowed(),
        "static owner grant should allow matching request",
    );

    // ═══════════════════════════════════════════════════════════════════
    // Phase 2: Build proof bundle with ownership transition chain
    // ═══════════════════════════════════════════════════════════════════
    let transfer_bundle = TrustGrantProofBundle::new()
        .with_discovery_document(
            parse_authority_discovery_document(ROOT_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("origin discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("origin discovery should insert: {error}"))
        .with_discovery_document(
            parse_authority_discovery_document(successor_discovery_json)
                .unwrap_or_else(|error| panic!("successor discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("successor discovery should insert: {error}"))
        .with_revocation_proof(BundleRevocationProof::new(
            parse_revocation_status_proof(revocation_json)
                .unwrap_or_else(|error| panic!("revocation proof should parse: {error}")),
            RevocationSourceKind::ProofBundle,
            ProofFinality::TrustedSnapshot,
            RevocationFreshnessPolicy::new(86400, 86400)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        ))
        .unwrap_or_else(|error| panic!("revocation proof should insert: {error}"))
        .with_ownership_transition_chain(
            "tg_ff000001-0000-1000-a000-000000000400"
                .parse()
                .unwrap_or_else(|error| panic!("trustgrant id should parse: {error}")),
            vec![
                RawOwnershipTransitionDocument::parse_json_str(transition_json)
                    .unwrap_or_else(|error| panic!("transition should parse: {error}")),
            ],
        )
        .unwrap_or_else(|error| panic!("ownership chain should insert: {error}"));

    // ═══════════════════════════════════════════════════════════════════
    // Phase 2 step 2: Re-verify the grant with the transition chain
    // ═══════════════════════════════════════════════════════════════════
    let transferred_artifacts = VerificationPipeline::new()
        .verify_json_str_with_bundle(
            transferred_grant_json,
            &verifier,
            &transfer_bundle,
            VerificationContext::new(ts_transfer, VerificationPosture::Online),
        )
        .unwrap_or_else(|error| panic!("transferred grant verification should succeed: {error}"));

    let transferred_grant = transferred_artifacts.verified_grant();

    // Verify the ownership chain was applied
    assert_eq!(
        transferred_grant.metadata().ownership().proof_kind(),
        OwnershipProofKind::TransitionChain,
    );
    assert_eq!(
        transferred_grant
            .metadata()
            .ownership()
            .active_owning_authority()
            .as_str(),
        "https://successor.example.com",
    );
    assert!(
        transferred_grant
            .metadata()
            .ownership()
            .transition_chain_tip()
            .is_some(),
    );

    // ═══════════════════════════════════════════════════════════════════
    // Phase 2 step 3: Evaluate the same recognize request → still Allowed
    // ═══════════════════════════════════════════════════════════════════
    let second_outcome = engine.evaluate(transferred_grant, &request);
    assert!(
        second_outcome.decision().is_allowed(),
        "transferred grant should still allow matching request",
    );
}
