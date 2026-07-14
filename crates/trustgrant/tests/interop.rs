#![allow(clippy::panic, clippy::unwrap_used, clippy::indexing_slicing)]

use std::path::Path;

use chrono::{DateTime, Days, Utc};
use trustgrant::{
    AuthorityId, CustomOperationName, EvaluationEngine, EvaluationRequest, MintContext,
    RequestedCapability, RequestedOperation, ResourceBinding, ResourceContext, ResourceRef,
    TemplateRef, TrustGrantError, VerifiedRevocationState,
    discovery::{AuthorityKeyRecord, ResolvedSignerBinding, SignatureProfile},
    domain::OwnershipVerificationRecord,
    evaluate::EvaluationOutcome,
    ports::{SignatureVerificationRequest, SignatureVerifier, VerificationPosture},
    revocation::{ProofFinality, RevocationRecord, RevocationSourceKind, RevocationStatus},
    verify::{VerificationMetadata, VerificationPipeline},
};

// ---------------------------------------------------------------------------
// Mock signature verifier (accepts any signature)
// ---------------------------------------------------------------------------

struct InteropSignatureVerifier;

impl SignatureVerifier for InteropSignatureVerifier {
    fn verify_signature(
        &self,
        _request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), TrustGrantError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn timestamp(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .unwrap_or_else(|e| panic!("invalid timestamp {s:?}: {e}"))
        .with_timezone(&Utc)
}

fn make_revocation_record(
    verified_at: DateTime<Utc>,
    override_val: Option<&str>,
) -> VerifiedRevocationState {
    // Use a far-future fresh_until so the engine freshness check does not
    // interfere with the specific vector scenario being tested. Vectors that
    // test revocation specifically set their own override values.
    let fresh_until = verified_at
        .checked_add_days(chrono::Days::new(3650))
        .unwrap_or(verified_at);

    match override_val {
        Some("revoked") => VerifiedRevocationState::Checked(
            RevocationRecord::new(
                RevocationStatus::Revoked,
                RevocationSourceKind::Api,
                ProofFinality::Observed,
                verified_at,
                fresh_until,
            )
            .unwrap_or_else(|e| panic!("invalid revocation record: {e}")),
        ),
        Some("non_revocable") => VerifiedRevocationState::NonRevocable,
        _ => VerifiedRevocationState::Checked(
            RevocationRecord::new(
                RevocationStatus::Active,
                RevocationSourceKind::Api,
                ProofFinality::Observed,
                verified_at,
                fresh_until,
            )
            .unwrap_or_else(|e| panic!("invalid revocation record: {e}")),
        ),
    }
}

fn make_metadata(
    verified_at: DateTime<Utc>,
    revocation: VerifiedRevocationState,
) -> VerificationMetadata {
    VerificationMetadata::new(
        verified_at,
        VerificationPosture::Online,
        ResolvedSignerBinding::new(
            AuthorityId::new("https://issuer.example.com")
                .unwrap_or_else(|e| panic!("invalid authority: {e}")),
            AuthorityKeyRecord::new(
                "root-key-1",
                "ed25519",
                "base64-public-key",
                timestamp("2026-01-01T00:00:00Z"),
                timestamp("2027-01-01T00:00:00Z"),
            )
            .unwrap_or_else(|e| panic!("invalid key record: {e}")),
            SignatureProfile::new("jcs+ed25519", "RFC8785")
                .unwrap_or_else(|e| panic!("invalid profile: {e}")),
            Some(
                trustgrant::discovery::DelegatedPrincipalRef::new("service", "issuer-worker")
                    .unwrap_or_else(|e| panic!("invalid principal ref: {e}")),
            ),
        ),
        OwnershipVerificationRecord::new(
            AuthorityId::new("https://issuer.example.com")
                .unwrap_or_else(|e| panic!("invalid authority: {e}")),
            AuthorityId::new("https://issuer.example.com")
                .unwrap_or_else(|e| panic!("invalid authority: {e}")),
            verified_at,
            trustgrant::domain::OwnershipProofKind::StaticOwner,
            None,
        ),
        revocation,
    )
}

fn run_evaluation(
    grant: &trustgrant::verify::VerifiedTrustGrant,
    eval: &serde_json::Value,
) -> EvaluationOutcome {
    let engine = EvaluationEngine::new();

    let req = &eval["request"];
    let evaluated_at = timestamp(req["evaluated_at"].as_str().unwrap());

    let operation: RequestedOperation = match req["operation"].as_str().unwrap() {
        "recognize" => RequestedOperation::Capability(RequestedCapability::Recognize),
        "mint" => RequestedOperation::Capability(RequestedCapability::Mint),
        other => RequestedOperation::Custom(
            CustomOperationName::new(other).unwrap_or_else(|e| panic!("invalid custom op: {e}")),
        ),
    };

    let mut resource = ResourceContext::new(req["resource_type"].as_str().unwrap())
        .unwrap_or_else(|e| panic!("invalid resource: {e}"));

    if let Some(selectors) = req["resource_selectors"].as_object() {
        for (kind, values) in selectors {
            for value in values.as_array().unwrap() {
                resource
                    .insert_selector(kind, value.as_str().unwrap())
                    .unwrap_or_else(|e| panic!("invalid selector: {e}"));
            }
        }
    }

    // Determine origin authority from request, defaulting to issuer
    let origin_str = req
        .get("origin_authority")
        .and_then(|v| v.as_str())
        .unwrap_or("https://issuer.example.com");
    let origin =
        AuthorityId::new(origin_str).unwrap_or_else(|e| panic!("invalid origin authority: {e}"));

    // Build appropriate resource binding based on operation
    let resource_binding = match &operation {
        RequestedOperation::Capability(RequestedCapability::Mint) => {
            ResourceBinding::Mint(TemplateRef::new(origin))
        }
        RequestedOperation::Capability(_) | RequestedOperation::Custom(_) => {
            ResourceBinding::Existing(ResourceRef::new(
                origin,
                req["resource_type"].as_str().unwrap().to_owned(),
            ))
        }
    };

    let mut request = EvaluationRequest::new(
        operation,
        resource_binding,
        AuthorityId::new(req["target_authority"].as_str().unwrap())
            .unwrap_or_else(|e| panic!("invalid target authority: {e}")),
        AuthorityId::new(req["audience_authority"].as_str().unwrap())
            .unwrap_or_else(|e| panic!("invalid audience authority: {e}")),
        resource,
        evaluated_at,
    )
    .unwrap_or_else(|e| panic!("invalid request: {e}"));

    // Handle evaluation setup — e.g. add audience principal selectors
    if let Some(setup) = eval.get("setup").and_then(|v| v.as_str()) {
        match setup {
            "add_audience_principal" => {
                if let Some(principal_selectors) = req
                    .get("audience_principal_selectors")
                    .and_then(|v| v.as_object())
                {
                    for (kind, values) in principal_selectors {
                        for value in values.as_array().unwrap() {
                            request
                                .insert_audience_principal_selector(kind, value.as_str().unwrap())
                                .unwrap_or_else(|e| {
                                    panic!("invalid audience principal selector: {e}")
                                });
                        }
                    }
                }
            }
            other => panic!("unknown evaluation setup: {other}"),
        }
    }

    if let Some(mc) = req.get("mint_context") {
        request = request.with_mint_context(MintContext::new(
            mc["total_minted"].as_u64().unwrap(),
            mc["user_minted"].as_u64().unwrap(),
        ));
    }

    engine.evaluate(grant, &request)
}

fn check_decision(decision: &EvaluationOutcome, expected: &serde_json::Value) -> bool {
    if decision.decision().is_allowed() && expected == "Allowed" {
        return true;
    }
    if let Some(deny_reason) = decision.decision().deny_reason()
        && let serde_json::Value::Object(map) = expected
        && let Some(expected_reason) = map.get("Denied").and_then(|v| v.as_str())
    {
        return format!("{deny_reason:?}").contains(expected_reason);
    }
    false
}

fn run_vector(path: &Path) -> Result<(), String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("failed to read {path:?}: {e}"))?;
    let vector: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("invalid JSON in {path:?}: {e}"))?;

    let description = vector["description"].as_str().unwrap_or("unknown");
    let trustgrant_json = serde_json::to_string(&vector["trustgrant"])
        .map_err(|e| format!("failed to serialize: {e}"))?;

    let pipeline = VerificationPipeline::new();
    let verifier = InteropSignatureVerifier;
    let verified_at = timestamp("2026-06-15T12:00:00Z");
    let revocation_override = vector.get("revocation_override").and_then(|v| v.as_str());
    let revocation = make_revocation_record(verified_at, revocation_override);
    let metadata = make_metadata(verified_at, revocation);

    let verified = pipeline
        .verify_json_str(&trustgrant_json, &verifier, metadata)
        .map_err(|e| format!("{description}: verification failed: {e}"))?;

    let grant = verified.verified_grant();

    if let Some(evaluations) = vector["evaluations"].as_array() {
        for eval in evaluations {
            let desc = eval["description"].as_str().unwrap_or("unnamed");
            let expected = &eval["expected"];
            let outcome = run_evaluation(grant, eval);

            if !check_decision(&outcome, expected) {
                return Err(format!(
                    "{description} / {desc}: expected {expected}, got {outcome:?}",
                ));
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Test entry point — discovers and runs all vector files
// ---------------------------------------------------------------------------

#[test]
fn interop_vectors() {
    let vectors_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("interop")
        .join("vectors");

    let mut passed = 0usize;
    let mut failed: Vec<String> = Vec::new();

    let mut entries: Vec<_> = std::fs::read_dir(&vectors_dir)
        .unwrap_or_else(|e| panic!("cannot read {vectors_dir:?}: {e}"))
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.path());

    for entry in &entries {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            match run_vector(&path) {
                Ok(()) => passed += 1,
                Err(msg) => failed.push(msg),
            }
        }
    }

    assert!(
        passed + failed.len() > 0,
        "no test vector JSON files found in {vectors_dir:?}"
    );

    if !failed.is_empty() {
        panic!(
            "{}/{} interop tests failed:\n  {}",
            failed.len(),
            passed + failed.len(),
            failed.join("\n  ")
        );
    }

    println!("all {passed} interop vectors passed");
}
