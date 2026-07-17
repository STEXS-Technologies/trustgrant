#![allow(clippy::panic, clippy::unwrap_used, clippy::map_err_ignore)]

//! End-to-end test with real ed25519 signatures.
//!
//! Uses a real keypair to sign and verify a TrustGrant through the full
//! pipeline: draft → canonicalize → sign → verify → evaluate.

use std::collections::BTreeMap;
use std::hint::black_box;

use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use trustgrant::{
    AuthorityId, EvaluationEngine, EvaluationRequest, RequestedCapability, RequestedOperation,
    ResourceBinding, ResourceContext, ResourceRef, TrustGrantDraft, TrustGrantDraftAuthorities,
    TrustGrantError, VerifiedRevocationState,
    discovery::{AuthorityKeyRecord, ResolvedSignerBinding, SignatureProfile},
    document::raw::{
        RawCapabilities, RawMintingConstraints, RawResourceScope, RawResourceType, RawScope,
        RawSelector, RawTypeCapabilities, RawTypeConstraints,
    },
    domain::{CanonicalizationProfile, OwnershipProofKind, OwnershipVerificationRecord, Utf16Key},
    ports::{SignatureVerificationRequest, SignatureVerifier, VerificationPosture},
    verify::{VerificationMetadata, VerificationPipeline},
};

// ---------------------------------------------------------------------------

struct RealVerifier {
    verifying_key: VerifyingKey,
}

impl SignatureVerifier for RealVerifier {
    fn verify_signature(
        &self,
        request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), TrustGrantError> {
        let sig_bytes = hex::decode(request.signature())
            .map_err(|_| TrustGrantError::SignatureVerificationFailed)?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|_| TrustGrantError::SignatureVerificationFailed)?;
        self.verifying_key
            .verify_strict(request.canonical_bytes(), &sig)
            .map_err(|_| TrustGrantError::SignatureVerificationFailed)
    }
}

fn ts(y: i32, m: u32, d: u32, h: u32, min: u32, s: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, m, d, h, min, s)
        .single()
        .unwrap_or_else(|| panic!("timestamp"))
}

#[test]
fn e2e_real_signing_and_verification() {
    // 1. Generate real ed25519 keypair
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let issuer = AuthorityId::new("https://issuer.test.example.com")
        .unwrap_or_else(|e| panic!("issuer: {e}"));
    let key_id = "test-key-1";

    // 2. Discovery material
    let pk_hex = hex::encode(verifying_key.as_bytes());
    let key_record = AuthorityKeyRecord::new(
        key_id,
        "ed25519",
        &pk_hex,
        ts(2026, 1, 1, 0, 0, 0),
        ts(2027, 1, 1, 0, 0, 0),
    )
    .unwrap_or_else(|e| panic!("key record: {e}"));

    let signer_binding = ResolvedSignerBinding::new(
        issuer.clone(),
        key_record,
        SignatureProfile::new("jcs+ed25519", "RFC8785").unwrap_or_else(|e| panic!("profile: {e}")),
        None,
    );

    let verifier = RealVerifier { verifying_key };

    // 3. Create draft
    let draft = TrustGrantDraft::new(
        TrustGrantDraftAuthorities::self_owned("https://issuer.test.example.com")
            .unwrap_or_else(|e| panic!("authorities: {e}")),
        key_id,
        RawScope::allow(vec![RawSelector::values(
            "authority",
            vec!["https://target.test.example.com".into()],
        )]),
        RawCapabilities::new(true, false),
        RawResourceScope::new(BTreeMap::from([(
            Utf16Key::new("item"),
            RawResourceType::new(
                false,
                Some(vec![RawSelector::values(
                    "namespace",
                    vec!["weapons".into()],
                )]),
                None,
                RawTypeCapabilities::new(Some(true), None),
                RawTypeConstraints::new(RawMintingConstraints::new(None, None), None),
                None,
            ),
        )])),
        ts(2026, 6, 15, 12, 0, 0),
    )
    .unwrap_or_else(|e| panic!("draft: {e}"));

    // 4. Signable → canonicalize → sign
    let signable = draft
        .signable_document()
        .unwrap_or_else(|e| panic!("signable: {e}"));

    let canonical_bytes =
        trustgrant::canonicalize_trustgrant(&signable, CanonicalizationProfile::Rfc8785)
            .unwrap_or_else(|e| panic!("canonicalize: {e}"));

    let signature = signing_key.sign(canonical_bytes.as_slice());
    let signed_doc = draft
        .into_signed_document(hex::encode(signature.to_bytes()))
        .unwrap_or_else(|e| panic!("into_signed: {e}"));

    let signed_json = signed_doc
        .to_json_string()
        .unwrap_or_else(|e| panic!("serialize: {e}"));

    // 5. Verify with real verifier
    let artifacts = VerificationPipeline::new()
        .verify_json_str(
            &signed_json,
            &verifier,
            VerificationMetadata::new(
                ts(2026, 6, 15, 12, 0, 0),
                VerificationPosture::Online,
                signer_binding.clone(),
                OwnershipVerificationRecord::new(
                    issuer.clone(),
                    issuer,
                    ts(2026, 6, 15, 12, 0, 0),
                    OwnershipProofKind::StaticOwner,
                    None,
                ),
                VerifiedRevocationState::NonRevocable,
            ),
        )
        .unwrap_or_else(|e| panic!("verification: {e}"));

    // 6. Check canonical bytes
    let canonical_str = std::str::from_utf8(artifacts.canonical_bytes().as_slice())
        .unwrap_or_else(|e| panic!("utf8: {e}"));
    assert!(canonical_str.contains("\"issuer_authority\""));
    assert!(!canonical_str.contains("\"signature\""));

    // 7. Evaluate
    let verified = artifacts.verified_grant();
    let mut resource = ResourceContext::new("item").unwrap_or_else(|e| panic!("resource: {e}"));
    resource
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|e| panic!("selector: {e}"));

    let request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(ResourceRef::new(
            AuthorityId::new("https://issuer.test.example.com")
                .unwrap_or_else(|e| panic!("origin: {e}")),
            "item".to_owned(),
        )),
        AuthorityId::new("https://target.test.example.com")
            .unwrap_or_else(|e| panic!("target: {e}")),
        AuthorityId::new("https://audience.test.example.com")
            .unwrap_or_else(|e| panic!("audience: {e}")),
        resource,
        ts(2026, 6, 15, 12, 0, 0),
    )
    .unwrap_or_else(|e| panic!("request: {e}"));

    let outcome = EvaluationEngine::new().evaluate(black_box(verified), black_box(&request));
    assert!(outcome.decision().is_allowed(), "should allow: {outcome:?}");

    // 8. Tampered document must fail
    let tampered_json = signed_json.replace("weapons", "armor");
    let tampered_result = VerificationPipeline::new().verify_json_str(
        &tampered_json,
        &verifier,
        VerificationMetadata::new(
            ts(2026, 6, 15, 12, 0, 0),
            VerificationPosture::Online,
            signer_binding,
            OwnershipVerificationRecord::new(
                AuthorityId::new("https://issuer.test.example.com").unwrap(),
                AuthorityId::new("https://issuer.test.example.com").unwrap(),
                ts(2026, 6, 15, 12, 0, 0),
                OwnershipProofKind::StaticOwner,
                None,
            ),
            VerifiedRevocationState::NonRevocable,
        ),
    );
    assert!(tampered_result.is_err(), "tampered doc should fail");
}
