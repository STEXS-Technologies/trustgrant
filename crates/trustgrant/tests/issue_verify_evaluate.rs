#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unwrap_in_result,
    clippy::panic_in_result_fn,
    clippy::indexing_slicing
)]

//! Integration test: full pipeline Issue → Sign → Verify → Evaluate.
//!
//! These tests exercise the complete lifecycle: a `TrustGrantDraft` is created
//! via the issue crate, signed into a raw document, verified through the
//! `VerificationPipeline`, and finally evaluated by the `EvaluationEngine`.

use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};

use trustgrant::document::raw::{
    RawAudienceEntry, RawCapabilities, RawMintingConstraints, RawOperationScope, RawResourceScope,
    RawResourceType, RawScope, RawSelector, RawTypeCapabilities, RawTypeConstraints,
};
use trustgrant::domain::Utf16Key;
use trustgrant::{
    AuthorityId, AuthorityKeyRecord, CustomOperationName, EvaluationDenyReason, EvaluationEngine,
    EvaluationRequest, MintContext, OwnershipProofKind, OwnershipVerificationRecord, ProofFinality,
    RequestedCapability, RequestedOperation, ResolvedSignerBinding, ResourceBinding,
    ResourceContext, ResourceRef, RevocationRecord, RevocationSourceKind, RevocationStatus,
    SignatureProfile, SignatureVerificationRequest, SignatureVerifier, TemplateRef,
    TrustGrantDraft, TrustGrantDraftAuthorities, TrustGrantError, VerificationMetadata,
    VerificationPipeline, VerificationPosture, VerifiedRevocationState,
};

// ---------------------------------------------------------------------------
// Fake signature verifier
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct FakeSignatureVerifier;

const SIGNATURE: &str = "test-signature-1";

impl SignatureVerifier for FakeSignatureVerifier {
    fn verify_signature(
        &self,
        request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), TrustGrantError> {
        if request.signature() == SIGNATURE
            && request.key_id().as_str() == "root-key-1"
            && request.algorithm().as_str() == "ed25519"
            && request.signature_profile().format().as_str() == "jcs+ed25519"
            && request.issuer_authority().as_str() == "https://issuer.example.com"
            && !request.canonical_bytes().is_empty()
        {
            Ok(())
        } else {
            Err(TrustGrantError::SignatureVerificationFailed)
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const ISSUER: &str = "https://issuer.example.com";
const TARGET: &str = "https://target.example.com";
const AUDIENCE: &str = "https://audience.example.com";

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

fn signer_binding() -> ResolvedSignerBinding {
    ResolvedSignerBinding::new(
        AuthorityId::new(ISSUER)
            .unwrap_or_else(|error| panic!("authority should be valid: {error}")),
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
        // No delegated principal — the draft does not set issuer_principal
        None,
    )
}

fn ownership_record() -> OwnershipVerificationRecord {
    OwnershipVerificationRecord::new(
        AuthorityId::new(ISSUER)
            .unwrap_or_else(|error| panic!("origin authority should be valid: {error}")),
        AuthorityId::new(ISSUER)
            .unwrap_or_else(|error| panic!("active owner should be valid: {error}")),
        fixed_timestamp(2026, 4, 7, 12, 0, 0),
        OwnershipProofKind::StaticOwner,
        None,
    )
}

fn verification_metadata_non_revocable() -> VerificationMetadata {
    VerificationMetadata::new(
        fixed_timestamp(2026, 4, 7, 12, 0, 0),
        VerificationPosture::Online,
        signer_binding(),
        ownership_record(),
        VerifiedRevocationState::NonRevocable,
    )
}

fn verification_metadata_revocable(revocation_status: RevocationStatus) -> VerificationMetadata {
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

// ---------------------------------------------------------------------------
// Recognize grant builder
// ---------------------------------------------------------------------------

fn make_recognize_draft() -> TrustGrantDraft {
    let authorities = TrustGrantDraftAuthorities::self_owned(ISSUER)
        .unwrap_or_else(|error| panic!("authorities should be valid: {error}"));

    let target_scope = RawScope::allow(vec![RawSelector::values("authority", vec![TARGET.into()])]);

    let capabilities = RawCapabilities::new(true, false);

    let mut types = BTreeMap::new();
    types.insert(
        Utf16Key::new("item"),
        RawResourceType::new(
            false,
            Some(vec![RawSelector::values(
                "namespace",
                vec!["weapons".into()],
            )]),
            None,
            RawTypeCapabilities::new(Some(true), Some(false)),
            RawTypeConstraints::new(
                RawMintingConstraints::new(Some(10), Some(1)),
                Some(vec![RawAudienceEntry::new(
                    AUDIENCE,
                    RawScope::all(),
                    Some(RawScope::allow(vec![RawSelector::values(
                        "actor",
                        vec!["player-123".into()],
                    )])),
                )]),
            ),
            Some(RawOperationScope::new(
                false,
                Some(vec!["recognize".into()]),
                None,
            )),
        ),
    );
    let resource_scope = RawResourceScope::new(types);

    TrustGrantDraft::new(
        authorities,
        "root-key-1",
        target_scope,
        capabilities,
        resource_scope,
        fixed_timestamp(2026, 4, 7, 12, 0, 0),
    )
    .unwrap_or_else(|error| panic!("draft should be valid: {error}"))
}

fn make_recognize_grant_json() -> String {
    let draft = make_recognize_draft();
    let signed = draft
        .into_signed_document(SIGNATURE)
        .unwrap_or_else(|error| panic!("into_signed_document should succeed: {error}"));
    signed
        .to_json_string()
        .unwrap_or_else(|error| panic!("serialization should succeed: {error}"))
}

// ---------------------------------------------------------------------------
// Mint grant builder
// ---------------------------------------------------------------------------

fn make_mint_draft() -> TrustGrantDraft {
    let authorities = TrustGrantDraftAuthorities::self_owned(ISSUER)
        .unwrap_or_else(|error| panic!("authorities should be valid: {error}"));

    let target_scope = RawScope::allow(vec![RawSelector::values("authority", vec![TARGET.into()])]);

    let capabilities = RawCapabilities::new(false, true);

    let mut types = BTreeMap::new();
    types.insert(
        Utf16Key::new("item"),
        RawResourceType::new(
            false,
            Some(vec![RawSelector::values(
                "namespace",
                vec!["weapons".into()],
            )]),
            None,
            RawTypeCapabilities::new(Some(false), Some(true)),
            RawTypeConstraints::new(
                RawMintingConstraints::new(Some(10), Some(1)),
                Some(vec![RawAudienceEntry::new(
                    AUDIENCE,
                    RawScope::all(),
                    Some(RawScope::allow(vec![RawSelector::values(
                        "actor",
                        vec!["player-123".into()],
                    )])),
                )]),
            ),
            Some(RawOperationScope::new(
                false,
                Some(vec!["create".into()]),
                None,
            )),
        ),
    );
    let resource_scope = RawResourceScope::new(types);

    TrustGrantDraft::new(
        authorities,
        "root-key-1",
        target_scope,
        capabilities,
        resource_scope,
        fixed_timestamp(2026, 4, 7, 12, 0, 0),
    )
    .unwrap_or_else(|error| panic!("draft should be valid: {error}"))
}

fn make_mint_grant_json() -> String {
    let draft = make_mint_draft();
    let signed = draft
        .into_signed_document(SIGNATURE)
        .unwrap_or_else(|error| panic!("into_signed_document should succeed: {error}"));
    signed
        .to_json_string()
        .unwrap_or_else(|error| panic!("serialization should succeed: {error}"))
}

// ---------------------------------------------------------------------------
// Revocable recognize grant JSON (for revoked test)
// ---------------------------------------------------------------------------

/// Builds a revocable recognize grant JSON string directly. This still
/// exercises the full pipeline: the JSON is the signed output of an issuance
/// step.
fn make_recognize_revocable_grant_json() -> String {
    // Build via the draft, get the signed doc, then re-parse and patch in
    // revocation. This is cleaner than hand-writing the full JSON.
    let draft = make_recognize_draft();
    let signed = draft
        .into_signed_document(SIGNATURE)
        .unwrap_or_else(|error| panic!("into_signed_document should succeed: {error}"));
    let json = signed
        .to_json_string()
        .unwrap_or_else(|error| panic!("serialization should succeed: {error}"));

    // Re-parse, inject revocation, re-serialize
    let mut raw = trustgrant::document::RawTrustGrantDocument::parse_json_str(&json)
        .unwrap_or_else(|error| panic!("re-parse should succeed: {error}"));
    raw.revocation = Some(trustgrant::document::raw::RawRevocation::new(
        true,
        "https://issuer.example.com/revocation",
    ));
    raw.to_json_string()
        .unwrap_or_else(|error| panic!("final serialization should succeed: {error}"))
}

// ---------------------------------------------------------------------------
// Combined recognize + mint grant (for block_minting_only test)
// ---------------------------------------------------------------------------

fn make_recognize_and_mint_draft() -> TrustGrantDraft {
    let authorities = TrustGrantDraftAuthorities::self_owned(ISSUER)
        .unwrap_or_else(|error| panic!("authorities should be valid: {error}"));

    let target_scope = RawScope::allow(vec![RawSelector::values("authority", vec![TARGET.into()])]);

    let capabilities = RawCapabilities::new(true, true);

    let mut types = BTreeMap::new();
    types.insert(
        Utf16Key::new("item"),
        RawResourceType::new(
            false,
            Some(vec![RawSelector::values(
                "namespace",
                vec!["weapons".into()],
            )]),
            None,
            RawTypeCapabilities::new(Some(true), Some(true)),
            RawTypeConstraints::new(
                RawMintingConstraints::new(Some(10), Some(1)),
                Some(vec![RawAudienceEntry::new(
                    AUDIENCE,
                    RawScope::all(),
                    Some(RawScope::allow(vec![RawSelector::values(
                        "actor",
                        vec!["player-123".into()],
                    )])),
                )]),
            ),
            Some(RawOperationScope::new(
                false,
                Some(vec!["recognize".into(), "create".into()]),
                None,
            )),
        ),
    );
    let resource_scope = RawResourceScope::new(types);

    TrustGrantDraft::new(
        authorities,
        "root-key-1",
        target_scope,
        capabilities,
        resource_scope,
        fixed_timestamp(2026, 4, 7, 12, 0, 0),
    )
    .unwrap_or_else(|error| panic!("draft should be valid: {error}"))
}

/// Builds a revocable grant JSON (both recognize + mint) with
/// post_revocation_effect = "block_minting_only".
fn make_recognize_mint_revocable_block_minting_only_grant_json() -> String {
    let draft = make_recognize_and_mint_draft();
    let signed = draft
        .into_signed_document(SIGNATURE)
        .unwrap_or_else(|error| panic!("into_signed_document should succeed: {error}"));
    let json = signed
        .to_json_string()
        .unwrap_or_else(|error| panic!("serialization should succeed: {error}"));

    // Re-parse, inject revocation with block_minting_only effect, re-serialize
    let mut raw = trustgrant::document::RawTrustGrantDocument::parse_json_str(&json)
        .unwrap_or_else(|error| panic!("re-parse should succeed: {error}"));
    raw.revocation = Some(
        trustgrant::document::raw::RawRevocation::new(
            true,
            "https://issuer.example.com/revocation",
        )
        .with_post_revocation_effect(
            trustgrant::document::raw::PostRevocationEffect::BlockMintingOnly,
        ),
    );
    raw.to_json_string()
        .unwrap_or_else(|error| panic!("final serialization should succeed: {error}"))
}

// ---------------------------------------------------------------------------
// Custom operation grant builder
// ---------------------------------------------------------------------------

fn make_custom_operation_draft() -> TrustGrantDraft {
    let authorities = TrustGrantDraftAuthorities::self_owned(ISSUER)
        .unwrap_or_else(|error| panic!("authorities should be valid: {error}"));

    let target_scope = RawScope::allow(vec![RawSelector::values("authority", vec![TARGET.into()])]);

    let capabilities = RawCapabilities::new(true, false);

    let mut types = BTreeMap::new();
    types.insert(
        Utf16Key::new("item"),
        RawResourceType::new(
            false,
            Some(vec![RawSelector::values(
                "namespace",
                vec!["weapons".into()],
            )]),
            None,
            RawTypeCapabilities::new(Some(true), Some(false)),
            RawTypeConstraints::new(RawMintingConstraints::new(None, None), None),
            Some(RawOperationScope::new(
                false,
                Some(vec!["asset.download".into()]),
                None,
            )),
        ),
    );
    let resource_scope = RawResourceScope::new(types);

    TrustGrantDraft::new(
        authorities,
        "root-key-1",
        target_scope,
        capabilities,
        resource_scope,
        fixed_timestamp(2026, 4, 7, 12, 0, 0),
    )
    .unwrap_or_else(|error| panic!("draft should be valid: {error}"))
}

fn make_custom_operation_grant_json() -> String {
    let draft = make_custom_operation_draft();
    let signed = draft
        .into_signed_document(SIGNATURE)
        .unwrap_or_else(|error| panic!("into_signed_document should succeed: {error}"));
    signed
        .to_json_string()
        .unwrap_or_else(|error| panic!("serialization should succeed: {error}"))
}

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

fn recognize_request() -> EvaluationRequest {
    let mut resource = ResourceContext::new("item")
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));

    let origin = AuthorityId::new(ISSUER)
        .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"));

    let mut request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
        AuthorityId::new(TARGET)
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new(AUDIENCE)
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));

    request
        .insert_audience_principal_selector("actor", "player-123")
        .unwrap_or_else(|error| panic!("principal selector should be valid: {error}"));

    request
}

fn mint_request() -> EvaluationRequest {
    let mut resource = ResourceContext::new("item")
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));

    let origin = AuthorityId::new(ISSUER)
        .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"));

    let mut request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Mint),
        ResourceBinding::Mint(TemplateRef::new(origin)),
        AuthorityId::new(TARGET)
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new(AUDIENCE)
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));

    request
        .insert_audience_principal_selector("actor", "player-123")
        .unwrap_or_else(|error| panic!("principal selector should be valid: {error}"));

    request.verify_selectors()
}

fn custom_operation_request() -> EvaluationRequest {
    let mut resource = ResourceContext::new("item")
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));

    let origin = AuthorityId::new(ISSUER)
        .unwrap_or_else(|error| panic!("origin authority should be valid: {error}"));

    let mut request = EvaluationRequest::new(
        RequestedOperation::Custom(
            CustomOperationName::new("asset.download")
                .unwrap_or_else(|error| panic!("custom operation should be valid: {error}")),
        ),
        ResourceBinding::Existing(ResourceRef::new(origin, "item".to_owned())),
        AuthorityId::new(TARGET)
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new(AUDIENCE)
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));

    request
        .insert_audience_principal_selector("actor", "player-123")
        .unwrap_or_else(|error| panic!("principal selector should be valid: {error}"));

    request
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn issue_verify_evaluate_recognize() {
    // 1. Issue: create draft -> sign into a raw document -> serialize to JSON
    let grant_json = make_recognize_grant_json();

    // 2. Verify: parse, validate, canonicalize, and verify the signature
    let pipeline = VerificationPipeline::new();
    let artifacts = pipeline
        .verify_json_str(
            &grant_json,
            &FakeSignatureVerifier,
            verification_metadata_non_revocable(),
        )
        .unwrap_or_else(|error| panic!("verification should succeed: {error}"));
    let verified_grant = artifacts.verified_grant();

    // 3. Evaluate: check a recognize request against the verified grant
    let engine = EvaluationEngine::new();
    let outcome = engine.evaluate(verified_grant, &recognize_request());

    assert!(outcome.decision().is_allowed());
    assert_eq!(outcome.decision().deny_reason(), None);
}

#[test]
fn issue_verify_evaluate_mint() {
    // 1. Issue: create mint-enabled draft -> sign -> serialize to JSON
    let grant_json = make_mint_grant_json();

    // 2. Verify
    let pipeline = VerificationPipeline::new();
    let artifacts = pipeline
        .verify_json_str(
            &grant_json,
            &FakeSignatureVerifier,
            verification_metadata_non_revocable(),
        )
        .unwrap_or_else(|error| panic!("verification should succeed: {error}"));
    let verified_grant = artifacts.verified_grant();

    // 3. Evaluate: mint request with MintContext (within limits)
    let engine = EvaluationEngine::new();
    let request = mint_request().with_mint_context_for_testing(MintContext::new(5, 0));
    let outcome = engine.evaluate(verified_grant, &request);

    assert!(outcome.decision().is_allowed());
    assert_eq!(outcome.decision().deny_reason(), None);
}

#[test]
fn issue_verify_evaluate_custom_operation() {
    // 1. Issue: create grant that allows custom operation "asset.download"
    let grant_json = make_custom_operation_grant_json();

    // 2. Verify
    let pipeline = VerificationPipeline::new();
    let artifacts = pipeline
        .verify_json_str(
            &grant_json,
            &FakeSignatureVerifier,
            verification_metadata_non_revocable(),
        )
        .unwrap_or_else(|error| panic!("verification should succeed: {error}"));
    let verified_grant = artifacts.verified_grant();

    // 3. Evaluate: custom operation request
    let engine = EvaluationEngine::new();
    let outcome = engine.evaluate(verified_grant, &custom_operation_request());

    assert!(outcome.decision().is_allowed());
    assert_eq!(outcome.decision().deny_reason(), None);
}

#[test]
fn issue_verify_evaluate_recognize_revoked_denied() {
    // Build a revocable grant via JSON (with revocation endpoint) to test the
    // full pipeline with an active-but-revoked revocation status.
    let grant_json = make_recognize_revocable_grant_json();

    let pipeline = VerificationPipeline::new();
    let artifacts = pipeline
        .verify_json_str(
            &grant_json,
            &FakeSignatureVerifier,
            verification_metadata_revocable(RevocationStatus::Revoked),
        )
        .unwrap_or_else(|error| panic!("verification should succeed: {error}"));
    let verified_grant = artifacts.verified_grant();

    let engine = EvaluationEngine::new();
    let outcome = engine.evaluate(verified_grant, &recognize_request());

    assert!(!outcome.decision().is_allowed());
    assert_eq!(
        outcome.decision().deny_reason(),
        Some(EvaluationDenyReason::Revoked)
    );
}

#[test]
fn issue_verify_evaluate_mint_without_context_denied() {
    // Mint request without MintContext should be denied when max_total is set
    let grant_json = make_mint_grant_json();

    let pipeline = VerificationPipeline::new();
    let artifacts = pipeline
        .verify_json_str(
            &grant_json,
            &FakeSignatureVerifier,
            verification_metadata_non_revocable(),
        )
        .unwrap_or_else(|error| panic!("verification should succeed: {error}"));
    let verified_grant = artifacts.verified_grant();

    let engine = EvaluationEngine::new();
    let outcome = engine.evaluate(verified_grant, &mint_request());

    assert!(!outcome.decision().is_allowed());
    assert_eq!(
        outcome.decision().deny_reason(),
        Some(EvaluationDenyReason::MissingMintContext)
    );
}

#[test]
fn issue_verify_evaluate_canonical_bytes_are_deterministic() {
    // Verify that a single draft produces deterministic canonical bytes,
    // confirming the canonical form is stable for signing.
    let draft = make_recognize_draft();

    let bytes1 = draft
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("canonical bytes should succeed: {error}"));
    let bytes2 = draft
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("second canonical bytes should succeed: {error}"));

    assert_eq!(bytes1, bytes2, "canonical bytes should be deterministic");
    assert!(
        !bytes1.as_slice().is_empty(),
        "canonical bytes should be non-empty"
    );

    // Verify the canonical bytes are valid UTF-8 JSON containing expected fields
    let json_str = std::str::from_utf8(bytes1.as_slice())
        .unwrap_or_else(|error| panic!("canonical bytes should be valid UTF-8: {error}"));
    assert!(
        json_str.contains("\"issuer_authority\":\"https://issuer.example.com\""),
        "canonical bytes should contain issuer_authority"
    );
    assert!(
        json_str.contains("\"key_id\":\"root-key-1\""),
        "canonical bytes should contain key_id"
    );
}

// ---------------------------------------------------------------------------
// BlockMintingOnly full-pipeline test
// ---------------------------------------------------------------------------

#[test]
fn revoked_grant_with_block_minting_only_allows_recognize() {
    // Build grant with post_revocation_effect = "block_minting_only",
    // verify with Revoked status, then evaluate.
    // Recognize should pass, mint should be denied.
    let grant_json = make_recognize_mint_revocable_block_minting_only_grant_json();

    let pipeline = VerificationPipeline::new();
    let artifacts = pipeline
        .verify_json_str(
            &grant_json,
            &FakeSignatureVerifier,
            verification_metadata_revocable(RevocationStatus::Revoked),
        )
        .unwrap_or_else(|error| panic!("verification should succeed: {error}"));
    let verified_grant = artifacts.verified_grant();

    let engine = EvaluationEngine::new();

    // Recognize should pass even though revoked (block_minting_only)
    let outcome = engine.evaluate(verified_grant, &recognize_request());
    assert!(
        outcome.decision().is_allowed(),
        "recognize should be allowed under block_minting_only",
    );

    // Mint should be denied (revoked with block_minting_only)
    let mint_req = mint_request().with_mint_context_for_testing(MintContext::new(5, 0));
    let second_outcome = engine.evaluate(verified_grant, &mint_req);
    assert!(!second_outcome.decision().is_allowed());
    assert_eq!(
        second_outcome.decision().deny_reason(),
        Some(EvaluationDenyReason::Revoked),
        "mint should be denied due to revocation with block_minting_only",
    );
}
