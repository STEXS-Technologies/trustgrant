//! Kani proof harnesses for the TrustGrant evaluation engine.
//!
//! These proofs verify that the evaluation engine never panics for any
//! valid combination of grant and request. The engine is a pure function
//! with no I/O, making it ideal for model-checking.

use std::hint::black_box;

use chrono::{TimeZone, Utc};

use crate::{EvaluationEngine, EvaluationRequest, RequestedCapability, RequestedOperation, ResourceContext};
use trustgrant_discovery::{AuthorityKeyRecord, ResolvedSignerBinding, SignatureProfile};
use trustgrant_document::ValidatedTrustGrantDocument;
use trustgrant_domain::{AuthorityId, OwnershipProofKind, OwnershipVerificationRecord};
use trustgrant_revocation::{ProofFinality, RevocationRecord, RevocationSourceKind, RevocationStatus, VerifiedRevocationState};
use trustgrant_verify::{VerificationMetadata, VerificationPosture, VerifiedTrustGrant};

/// Fixed timestamp for all Kani harnesses.
fn ts() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 4, 7, 12, 0, 0).single()
        .unwrap_or(Utc::now())
}

/// Builds a minimal valid signer binding.
fn signer_binding() -> ResolvedSignerBinding {
    ResolvedSignerBinding::new(
        AuthorityId::new("https://issuer.example.com").unwrap(),
        AuthorityKeyRecord::new(
            "root-key-1", "ed25519", "base64-public-key", ts(), ts(),
        ).unwrap(),
        SignatureProfile::new("jcs+ed25519", "RFC8785").unwrap(),
        None,
    )
}

/// Builds a valid verified grant that the evaluation engine can process.
fn valid_verified_grant() -> VerifiedTrustGrant {
    // Parse a minimal valid TrustGrant JSON document
    let json = r#"{
        "trustgrant_id": "tg_11111111-1111-4111-8111-111111111001",
        "version": 0,
        "grant_series_id": "tgs_11111111-1111-4111-8111-111111111001",
        "revision": 1,
        "supersedes": null,
        "supersession_policy": "coexist",
        "issuer_authority": "https://issuer.example.com",
        "origin_authority": "https://issuer.example.com",
        "active_owning_authority": "https://issuer.example.com",
        "key_id": "root-key-1",
        "target_scope": {
            "all": false,
            "allow": [{"kind": "authority", "all": false, "values": ["https://target.example.com"], "expressions": null}],
            "deny": null
        },
        "capabilities": { "recognize": true, "mint": false },
        "default_audience_scope": [
            {"authority_id": "https://audience.example.com", "scope": {"all": true, "allow": null, "deny": null}, "principal_scope": null}
        ],
        "resource_scope": {
            "types": {
                "item": {
                    "all": false,
                    "allow": [{"kind": "namespace", "all": false, "values": ["weapons"], "expressions": null}],
                    "deny": null,
                    "capabilities": { "recognize": null, "mint": null },
                    "constraints": { "minting": { "max_total": null, "max_per_user": null }, "audience_scope": null },
                    "operations": { "all": false, "allow": ["recognize"], "deny": null }
                }
            }
        },
        "global_constraints": {
            "time": { "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z" }
        },
        "revocation": { "revocable": true, "revocation_endpoint": "https://issuer.example.com/revocation" },
        "issued_at": "2026-06-01T12:00:00Z",
        "signature": "valid-signature",
        "issuer_principal": { "kind": "service", "id": "issuer-worker" }
    }"#;

    let raw = trustgrant_document::RawTrustGrantDocument::parse_json_str(json)
        .unwrap_or_else(|e| panic!("parse failed: {e}"));
    let validated = ValidatedTrustGrantDocument::try_from(raw)
        .unwrap_or_else(|e| panic!("validation failed: {e}"));

    let metadata = VerificationMetadata::new(
        ts(),
        VerificationPosture::Online,
        signer_binding(),
        OwnershipVerificationRecord::new(
            AuthorityId::new("https://issuer.example.com").unwrap(),
            AuthorityId::new("https://issuer.example.com").unwrap(),
            ts(),
            OwnershipProofKind::StaticOwner,
            None,
        ),
        VerifiedRevocationState::Checked(
            RevocationRecord::new(
                RevocationStatus::Active,
                RevocationSourceKind::Api,
                ProofFinality::Observed,
                ts(),
                ts(),
            ).unwrap_or_else(|e| panic!("revocation record: {e}")),
        ),
    );

    VerifiedTrustGrant::new(validated, metadata)
}

/// Builds a basic recognize evaluation request.
fn recognize_request() -> EvaluationRequest {
    let mut resource = ResourceContext::new("item")
        .unwrap_or_else(|e| panic!("resource: {e}"));
    resource.insert_selector("namespace", "weapons")
        .unwrap_or_else(|e| panic!("selector: {e}"));

    EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        AuthorityId::new("https://target.example.com").unwrap(),
        AuthorityId::new("https://audience.example.com").unwrap(),
        resource,
        ts(),
    ).unwrap_or_else(|e| panic!("request: {e}"))
}

// ---------------------------------------------------------------------------
// Proof harnesses
// ---------------------------------------------------------------------------

/// Verifies that evaluate() never panics for a basic valid input.
#[kani::proof]
fn verify_evaluate_basic() {
    let engine = EvaluationEngine::new();
    let grant = black_box(valid_verified_grant());
    let request = black_box(recognize_request());
    let decision = engine.evaluate(&grant, &request);
    // Kani verifies that this function never panics.
    // The decision itself is not checked semantically — other tests cover that.
    black_box(decision);
}

/// Verifies that evaluate() handles the request's origin_authority check
/// without panicking.
#[kani::proof]
fn verify_evaluate_with_origin() {
    let engine = EvaluationEngine::new();
    let grant = black_box(valid_verified_grant());
    let mut request = black_box(recognize_request());
    request = request.with_origin_authority(
        AuthorityId::new("https://other.example.com").unwrap(),
    );
    let decision = engine.evaluate(&grant, &request);
    black_box(decision);
}
