#![no_main]
use libfuzzer_sys::fuzz_target;

use chrono::{Duration, Utc};

use trustgrant::{
    AuthorityId, AuthorityKeyRecord, CustomOperationName, DelegatedPrincipalRef, EvaluationEngine,
    EvaluationRequest, MutationRequest, OwnershipProofKind, OwnershipVerificationRecord,
    ProofFinality, RawTrustGrantDocument, RequestedOperation, ResolvedSignerBinding,
    ResourceBinding, ResourceContext, ResourceRef, RevocationRecord, RevocationSourceKind,
    RevocationStatus, SignatureProfile, ValidatedTrustGrantDocument, VerificationMetadata,
    VerificationPosture, VerifiedRevocationState, VerifiedTrustGrant,
};

// Helper: build a VerifiedTrustGrant from fuzzer data
fn build_grant(data: &[u8]) -> Option<VerifiedTrustGrant> {
    let raw = RawTrustGrantDocument::parse_json_bytes(data).ok()?;
    let validated = ValidatedTrustGrantDocument::try_from(raw.clone()).ok()?;

    let now = Utc::now();
    let issuer_authority = AuthorityId::new(raw.issuer_authority.as_str()).ok()?;
    let not_after = raw.issued_at.checked_add_signed(Duration::days(365))?;
    let key_record = AuthorityKeyRecord::new(
        raw.key_id.as_str(),
        "ed25519",
        "base64-fuzz",
        raw.issued_at,
        not_after,
    )
    .ok()?;
    let signature_profile = SignatureProfile::new("jcs+ed25519", "RFC8785").ok()?;
    let delegated_principal = raw
        .issuer_principal
        .as_ref()
        .and_then(|p| DelegatedPrincipalRef::new(p.kind.as_str(), p.id.as_str()).ok());
    let signer_binding = ResolvedSignerBinding::new(
        issuer_authority,
        key_record,
        signature_profile,
        delegated_principal,
    );
    let origin_authority = AuthorityId::new(raw.origin_authority.as_str()).ok()?;
    let active_owning_authority = AuthorityId::new(raw.active_owning_authority.as_str()).ok()?;
    let ownership = OwnershipVerificationRecord::new(
        origin_authority,
        active_owning_authority,
        now,
        OwnershipProofKind::StaticOwner,
        None,
    );
    let revocation = if raw.revocation.as_ref().is_some_and(|r| r.revocable) {
        let expires_at = now.checked_add_signed(Duration::minutes(5))?;
        VerifiedRevocationState::Checked(
            RevocationRecord::new(
                RevocationStatus::Active,
                RevocationSourceKind::Api,
                ProofFinality::Observed,
                now,
                expires_at,
            )
            .ok()?,
        )
    } else {
        VerifiedRevocationState::NonRevocable
    };
    let metadata = VerificationMetadata::new(
        now,
        VerificationPosture::Online,
        signer_binding,
        ownership,
        revocation,
    );
    Some(VerifiedTrustGrant::new(validated, metadata))
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Build a request from fuzzer-derived operation name
    let op_name_bytes: String = data
        .iter()
        .take(32)
        .map(|b| (b & 0x7F) as char)
        .filter(|c| c.is_ascii_graphic() || *c == ' ' || *c == '-')
        .collect();

    if op_name_bytes.is_empty() {
        return;
    }

    let custom_op = match CustomOperationName::new(&op_name_bytes) {
        Ok(op) => op,
        Err(_) => return,
    };

    let target = match AuthorityId::new("https://fuzz.example.com") {
        Ok(a) => a,
        Err(_) => return,
    };

    let resource = match ResourceContext::new("item") {
        Ok(r) => r,
        Err(_) => return,
    };

    let request = match EvaluationRequest::new(
        RequestedOperation::Custom(custom_op),
        ResourceBinding::Existing(ResourceRef::new(target.clone(), "res-1".to_string())),
        target.clone(),
        target.clone(),
        resource,
        Utc::now(),
    ) {
        Ok(r) => r,
        Err(_) => return,
    };

    // Try converting to MutationRequest — may fail (that's fine, we test no panics)
    if let Ok(mutation) = MutationRequest::try_from(request) {
        // Builder methods must never panic
        let mutation = mutation.with_actor(target);
        let mutation = mutation.with_envelope_expiry(Utc::now() + Duration::hours(1));

        // Try authorize_mutation if we have a grant
        if let Some(grant) = build_grant(data) {
            let engine = EvaluationEngine::new();
            let _authorization = engine.authorize_mutation(&grant, &mutation);
        }
    }
});
