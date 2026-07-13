use std::path::Path;

use chrono::{DateTime, Utc};
use trustgrant::{
    AuthorityId, CustomOperationName, EvaluationDecision, EvaluationEngine, EvaluationRequest,
    MintContext, RequestedCapability, RequestedOperation, ResourceContext,
    VerifiedRevocationState,
    discovery::{AuthorityKeyRecord, ResolvedSignerBinding, SignatureProfile},
    domain::OwnershipVerificationRecord,
    ports::{SignatureVerificationRequest, SignatureVerifier, VerificationPosture},
    revocation::{ProofFinality, RevocationRecord, RevocationSourceKind, RevocationStatus},
    verify::{VerificationMetadata, VerificationPipeline},
    TrustGrantError,
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
    match override_val {
        Some("revoked") => VerifiedRevocationState::Checked(
            RevocationRecord::new(
                RevocationStatus::Revoked,
                RevocationSourceKind::Api,
                ProofFinality::Observed,
                verified_at,
                verified_at,
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
                verified_at,
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
) -> EvaluationDecision {
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

    let mut resource =
        ResourceContext::new(req["resource_type"].as_str().unwrap())
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

    let mut request = EvaluationRequest::new(
        operation,
        AuthorityId::new(req["target_authority"].as_str().unwrap())
            .unwrap_or_else(|e| panic!("invalid target authority: {e}")),
        AuthorityId::new(req["audience_authority"].as_str().unwrap())
            .unwrap_or_else(|e| panic!("invalid audience authority: {e}")),
        resource,
        evaluated_at,
    )
    .unwrap_or_else(|e| panic!("invalid request: {e}"));

    // Spec §13 step 3: optional origin authority enforcement
    if let Some(origin) = req.get("origin_authority").and_then(|v| v.as_str()) {
        request = request.with_origin_authority(
            AuthorityId::new(origin)
                .unwrap_or_else(|e| panic!("invalid origin authority: {e}")),
        );
    }

    // Handle evaluation setup — e.g. add audience principal selectors
    if let Some(setup) = eval.get("setup").and_then(|v| v.as_str()) {
        match setup {
            "add_audience_principal" => {
                if let Some(principal_selectors) =
                    req.get("audience_principal_selectors").and_then(|v| v.as_object())
                {
                    for (kind, values) in principal_selectors {
                        for value in values.as_array().unwrap() {
                            request
                                .insert_audience_principal_selector(
                                    kind,
                                    value.as_str().unwrap(),
                                )
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

fn check_decision(decision: EvaluationDecision, expected: &serde_json::Value) -> bool {
    if decision.is_allowed() && expected == "Allowed" {
        return true;
    }
    if let Some(deny_reason) = decision.deny_reason() {
        if let serde_json::Value::Object(map) = expected {
            if let Some(expected_reason) = map.get("Denied").and_then(|v| v.as_str()) {
                return format!("{deny_reason:?}").contains(expected_reason);
            }
        }
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
    let revocation_override = vector
        .get("revocation_override")
        .and_then(|v| v.as_str());
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
            let decision = run_evaluation(grant, eval);

            if !check_decision(decision, expected) {
                return Err(format!(
                    "{description} / {desc}: expected {expected}, got {decision:?}",
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
