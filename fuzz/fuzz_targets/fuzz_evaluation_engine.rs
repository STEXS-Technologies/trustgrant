#![no_main]
use libfuzzer_sys::fuzz_target;

use chrono::{Duration, Utc};

use trustgrant::{
    AuthorityId, AuthorityKeyRecord, DelegatedPrincipalRef, EvaluationEngine, EvaluationRequest,
    MintContext, OwnershipProofKind, OwnershipVerificationRecord, ProofFinality,
    RawTrustGrantDocument, RequestedCapability, RequestedOperation, ResolvedSignerBinding,
    ResourceContext, RevocationRecord, RevocationSourceKind, RevocationStatus, SignatureProfile,
    TrustGrantError, ValidatedTrustGrantDocument, VerificationMetadata, VerificationPosture,
    VerifiedRevocationState, VerifiedTrustGrant,
};

fn build_metadata(doc: &RawTrustGrantDocument) -> Result<VerificationMetadata, TrustGrantError> {
    let now = Utc::now();

    let issuer_authority = AuthorityId::new(doc.issuer_authority.as_str())?;

    let key_record = AuthorityKeyRecord::new(
        doc.key_id.as_str(),
        "ed25519",
        "base64-fuzz-public-key",
        doc.issued_at,
        doc.issued_at
            .checked_add_signed(Duration::days(365))
            .ok_or(TrustGrantError::InvalidKeyValidityWindow)?,
    )?;

    let signature_profile = SignatureProfile::new("jcs+ed25519", "RFC8785")?;

    let delegated_principal = match doc.issuer_principal.as_ref() {
        Some(principal) => Some(DelegatedPrincipalRef::new(
            principal.kind.as_str(),
            principal.id.as_str(),
        )?),
        None => None,
    };

    let signer_binding = ResolvedSignerBinding::new(
        issuer_authority,
        key_record,
        signature_profile,
        delegated_principal,
    );

    let origin_authority = AuthorityId::new(doc.origin_authority.as_str())?;
    let active_owning_authority = AuthorityId::new(doc.active_owning_authority.as_str())?;

    let ownership = OwnershipVerificationRecord::new(
        origin_authority,
        active_owning_authority,
        now,
        OwnershipProofKind::StaticOwner,
        None,
    );

    let revocation = if doc
        .revocation
        .as_ref()
        .is_some_and(|revocation| revocation.revocable)
    {
        VerifiedRevocationState::Checked(RevocationRecord::new(
            RevocationStatus::Active,
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            now,
            now.checked_add_signed(Duration::minutes(5))
                .ok_or(TrustGrantError::InvalidRevocationFreshnessWindow)?,
        )?)
    } else {
        VerifiedRevocationState::NonRevocable
    };

    Ok(VerificationMetadata::new(
        now,
        VerificationPosture::Online,
        signer_binding,
        ownership,
        revocation,
    ))
}

/// Try to build a recognize EvaluationRequest using the document's own fields
/// as hints. Falls back to safe defaults when document fields are unmappable.
fn build_recognize_request(
    doc: &RawTrustGrantDocument,
    evaluated_at: chrono::DateTime<Utc>,
) -> Option<EvaluationRequest> {
    // Use the issuer_authority as a reasonable target (it was already validated
    // during parsing so it is a well-formed authority string).
    let target_authority = AuthorityId::new(doc.issuer_authority.as_str()).ok()?;

    // Use active_owning_authority as the audience authority.
    let audience_authority = AuthorityId::new(doc.active_owning_authority.as_str()).ok()?;

    // Pick the first resource type from the document, or "item" as fallback.
    let resource_type_name = doc
        .resource_scope
        .types
        .keys()
        .next()
        .map(|k| k.as_str())
        .unwrap_or("item");

    let mut resource = ResourceContext::new(resource_type_name).ok()?;

    // Add resource selectors from the document's resource type allow list.
    if let Some(resource_type) = doc.resource_scope.types.get(resource_type_name) {
        for selector in resource_type.allow.iter().flatten() {
            for value in selector.values.iter().flatten() {
                let _ = resource.insert_selector(selector.kind.as_str(), value.as_str());
            }
        }
    }

    // Also add resource selectors from the resource type's deny list.
    if let Some(resource_type) = doc.resource_scope.types.get(resource_type_name) {
        for selector in resource_type.deny.iter().flatten() {
            for value in selector.values.iter().flatten() {
                let _ = resource.insert_selector(selector.kind.as_str(), value.as_str());
            }
        }
    }

    // Build the request.
    let mut request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        target_authority,
        audience_authority,
        resource,
        evaluated_at,
    )
    .ok()?;

    // Add target selectors from the document's target_scope.
    for selector in doc.target_scope.allow.iter().flatten() {
        for value in selector.values.iter().flatten() {
            let _ = request.insert_target_selector(selector.kind.as_str(), value.as_str());
        }
    }
    for selector in doc.target_scope.deny.iter().flatten() {
        for value in selector.values.iter().flatten() {
            let _ = request.insert_target_selector(selector.kind.as_str(), value.as_str());
        }
    }

    // Add audience principal selectors from the document's audience scope entries.
    for audience_entry in doc.default_audience_scope.iter().flatten() {
        if let Some(principal_scope) = &audience_entry.principal_scope {
            for selector in principal_scope.allow.iter().flatten() {
                for value in selector.values.iter().flatten() {
                    let _ = request
                        .insert_audience_principal_selector(selector.kind.as_str(), value.as_str());
                }
            }
        }
    }

    Some(request)
}

/// Try to build a mint EvaluationRequest.
fn build_mint_request(
    doc: &RawTrustGrantDocument,
    evaluated_at: chrono::DateTime<Utc>,
) -> Option<EvaluationRequest> {
    let target_authority = AuthorityId::new(doc.issuer_authority.as_str()).ok()?;
    let audience_authority = AuthorityId::new(doc.active_owning_authority.as_str()).ok()?;

    let resource_type_name = doc
        .resource_scope
        .types
        .keys()
        .next()
        .map(|k| k.as_str())
        .unwrap_or("item");

    let mut resource = ResourceContext::new(resource_type_name).ok()?;

    // Add resource selectors from the document.
    if let Some(resource_type) = doc.resource_scope.types.get(resource_type_name) {
        for selector in resource_type.allow.iter().flatten() {
            for value in selector.values.iter().flatten() {
                let _ = resource.insert_selector(selector.kind.as_str(), value.as_str());
            }
        }
        for selector in resource_type.deny.iter().flatten() {
            for value in selector.values.iter().flatten() {
                let _ = resource.insert_selector(selector.kind.as_str(), value.as_str());
            }
        }
    }

    let mut request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Mint),
        target_authority,
        audience_authority,
        resource,
        evaluated_at,
    )
    .ok()?;

    // Add audience principal selectors.
    for audience_entry in doc.default_audience_scope.iter().flatten() {
        if let Some(principal_scope) = &audience_entry.principal_scope {
            for selector in principal_scope.allow.iter().flatten() {
                for value in selector.values.iter().flatten() {
                    let _ = request
                        .insert_audience_principal_selector(selector.kind.as_str(), value.as_str());
                }
            }
        }
    }

    // Attach mint context so mint constraints are exercised.
    request = request.with_mint_context(MintContext::new(0, 0));

    Some(request)
}

/// Build a request with a resource type not present in the document, exercising
/// the ResourceTypeNotGranted path.
fn build_unmatched_resource_request(
    doc: &RawTrustGrantDocument,
    evaluated_at: chrono::DateTime<Utc>,
) -> Option<EvaluationRequest> {
    let target_authority = AuthorityId::new(doc.issuer_authority.as_str()).ok()?;
    let audience_authority = AuthorityId::new(doc.active_owning_authority.as_str()).ok()?;

    // Pick a resource type name that is NOT in the document.
    let existing_types: std::collections::BTreeSet<&str> = doc
        .resource_scope
        .types
        .keys()
        .map(|k| k.as_str())
        .collect();
    let unmatched_type = if existing_types.contains("item") {
        "nonexistent-fuzz-type"
    } else {
        "item"
    };

    let resource = ResourceContext::new(unmatched_type).ok()?;

    EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        target_authority,
        audience_authority,
        resource,
        evaluated_at,
    )
    .ok()
}

/// Build a request with a non-matching target authority to exercise the
/// TargetNotAllowed deny path.
fn build_mismatched_target_request(
    doc: &RawTrustGrantDocument,
    evaluated_at: chrono::DateTime<Utc>,
) -> Option<EvaluationRequest> {
    // Use a target authority that almost certainly won't match the grant's
    // target_scope selectors.
    let target_authority = AuthorityId::new("https://fuzz.nonexistent.example.com").ok()?;
    let audience_authority = AuthorityId::new(doc.active_owning_authority.as_str()).ok()?;

    let resource_type_name = doc
        .resource_scope
        .types
        .keys()
        .next()
        .map(|k| k.as_str())
        .unwrap_or("item");

    let mut resource = ResourceContext::new(resource_type_name).ok()?;

    if let Some(resource_type) = doc.resource_scope.types.get(resource_type_name) {
        for selector in resource_type.allow.iter().flatten() {
            for value in selector.values.iter().flatten() {
                let _ = resource.insert_selector(selector.kind.as_str(), value.as_str());
            }
        }
    }

    EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        target_authority,
        audience_authority,
        resource,
        evaluated_at,
    )
    .ok()
}

fn evaluate_and_check(grant: &VerifiedTrustGrant, request: &EvaluationRequest) {
    let engine = EvaluationEngine::new();
    let decision = engine.evaluate(grant, request);

    // Canonical invariants: the decision never panics (already verified by
    // virtue of reaching this point), and always returns either allow or deny.
    if decision.is_allowed() {
        assert_eq!(
            decision.trustgrant_id(),
            grant.lineage().trustgrant_id(),
            "allow decision must reference the evaluated grant"
        );
        assert_eq!(
            decision.deny_reason(),
            None,
            "allow decision must not have a deny reason"
        );
    } else {
        // Deny decision: trustgrant_id must still match the evaluated grant.
        assert_eq!(
            decision.trustgrant_id(),
            grant.lineage().trustgrant_id(),
            "deny decision must reference the evaluated grant"
        );
        // deny_reason is always Some for deny.
        assert!(
            decision.deny_reason().is_some(),
            "deny decision must carry a deny reason"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    // Step 1: Parse raw bytes as a TrustGrant document.
    let Ok(raw) = RawTrustGrantDocument::parse_json_bytes(data) else {
        return;
    };

    // Step 2: Validate into a ValidatedTrustGrantDocument.
    let raw_for_metadata = raw.clone();
    let Ok(validated) = ValidatedTrustGrantDocument::try_from(raw) else {
        return;
    };

    // Step 3: Build verification metadata and construct the verified grant.
    let Ok(metadata) = build_metadata(&raw_for_metadata) else {
        return;
    };
    let grant = VerifiedTrustGrant::new(validated, metadata);

    let evaluated_at = Utc::now();

    // Step 4: Build and evaluate several request variants.

    // Variant 1: Recognize request using document-derived fields.
    if let Some(request) = build_recognize_request(&raw_for_metadata, evaluated_at) {
        evaluate_and_check(&grant, &request);
    }

    // Variant 2: Mint request using document-derived fields with mint context.
    if let Some(request) = build_mint_request(&raw_for_metadata, evaluated_at) {
        evaluate_and_check(&grant, &request);
    }

    // Variant 3: Request with an unmatched resource type.
    if let Some(request) = build_unmatched_resource_request(&raw_for_metadata, evaluated_at) {
        evaluate_and_check(&grant, &request);
    }

    // Variant 4: Request with a mismatched target authority.
    if let Some(request) = build_mismatched_target_request(&raw_for_metadata, evaluated_at) {
        evaluate_and_check(&grant, &request);
    }
});
