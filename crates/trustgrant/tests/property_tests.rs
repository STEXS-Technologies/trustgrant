#![allow(clippy::panic, clippy::unwrap_used)]

//! Property-based tests for the trustgrant core crate.
//!
//! Uses `proptest` to verify key invariants:
//! 1. Parse → Serialize → Parse round-trip preserves document fields.
//! 2. Canonicalization is deterministic (same input → same output).
//! 3. Evaluation is deterministic (same grant + request → same decision).

use std::collections::BTreeMap;

use proptest::prelude::*;
use trustgrant::document::raw::{
    RawAudienceEntry, RawCapabilities, RawMintingConstraints, RawOperationScope, RawResourceScope,
    RawResourceType, RawScope, RawSelector, RawTrustGrantDocument, RawTypeCapabilities,
    RawTypeConstraints,
};
use trustgrant::domain::Utf16Key;
use trustgrant::{
    AuthorityId, AuthorityKeyRecord, CanonicalizationProfile, DelegatedPrincipalRef,
    EvaluationDenyReason, EvaluationEngine, EvaluationRequest, MintContext, OwnershipProofKind,
    OwnershipVerificationRecord, ProofFinality, RequestedCapability, RequestedOperation,
    ResolvedSignerBinding, ResourceBinding, ResourceContext, ResourceRef, RevocationRecord,
    RevocationSourceKind, RevocationStatus, SignatureProfile, SignatureVerificationRequest,
    SignatureVerifier, TemplateRef, TrustGrantDraft, TrustGrantDraftAuthorities, TrustGrantError,
    ValidatedTrustGrantDocument, VerificationMetadata, VerificationPipeline, VerificationPosture,
    VerifiedRevocationState, VerifiedTrustGrant, evaluate::EvaluationOutcome,
};

// ---------------------------------------------------------------------------
// Fake signature verifier (reused from issue_verify_evaluate tests)
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
) -> chrono::DateTime<chrono::Utc> {
    use chrono::TimeZone;
    chrono::Utc
        .with_ymd_and_hms(year, month, day, hour, minute, second)
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

// ---------------------------------------------------------------------------
// Grant JSON builder — parameterized template for round-trip tests
// ---------------------------------------------------------------------------

/// Builds a valid TrustGrant JSON string with parameterized IDs.
///
/// The UUID must be a valid lowercase hex UUID with hyphens:
/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
fn build_grant_json_with_ids(uuid: &str) -> String {
    let trustgrant_id = format!("tg_{uuid}");
    let grant_series_id = format!("tgs_{uuid}");

    format!(
        r#"{{
            "trustgrant_id":"{trustgrant_id}",
            "version":0,
            "grant_series_id":"{grant_series_id}",
            "revision":1,
            "supersession_policy":"coexist",
            "issuer_authority":"https://issuer.example.com",
            "origin_authority":"https://issuer.example.com",
            "active_owning_authority":"https://issuer.example.com",
            "key_id":"root-key-1",
            "target_scope":{{"all":true,"allow":null,"deny":null}},
            "capabilities":{{"recognize":true,"mint":false}},
            "resource_scope":{{"types":{{"item":{{"all":true,"allow":null,"deny":null,"capabilities":{{"recognize":true,"mint":false}},"constraints":{{"minting":{{"max_total":null,"max_per_user":null}},"audience_scope":null}},"operations":null}}}}}},
            "issued_at":"2026-04-07T12:00:00Z",
            "signature":"test-signature-1"
        }}"#
    )
}

// ---------------------------------------------------------------------------
// Draft builder (for verification/evaluation tests)
// ---------------------------------------------------------------------------

fn build_draft() -> TrustGrantDraft {
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

fn build_signed_json() -> String {
    let draft = build_draft();
    let signed = draft
        .into_signed_document(SIGNATURE)
        .unwrap_or_else(|error| panic!("into_signed_document should succeed: {error}"));
    signed
        .to_json_string()
        .unwrap_or_else(|error| panic!("serialization should succeed: {error}"))
}

fn build_recognize_request() -> EvaluationRequest {
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

// ---------------------------------------------------------------------------
// Test 1: Parse → Serialize → Parse round-trip invariants
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn parse_round_trip_preserves_trustgrant_id(
        uuid in "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    ) {
        let json = build_grant_json_with_ids(&uuid);

        // First parse
        let raw1 = trustgrant::document::RawTrustGrantDocument::parse_json_str(&json)
            .unwrap_or_else(|error| panic!("first parse should succeed: {error}"));

        // Serialize back
        let json2 = raw1
            .to_json_string()
            .unwrap_or_else(|error| panic!("serialization should succeed: {error}"));

        // Second parse
        let raw2 = trustgrant::document::RawTrustGrantDocument::parse_json_str(&json2)
            .unwrap_or_else(|error| panic!("second parse should succeed: {error}"));

        // Key fields must survive the round-trip
        prop_assert_eq!(raw1.trustgrant_id, raw2.trustgrant_id);
        prop_assert_eq!(raw1.grant_series_id, raw2.grant_series_id);
        prop_assert_eq!(raw1.key_id, raw2.key_id);
        prop_assert_eq!(raw1.signature, raw2.signature);
        prop_assert_eq!(raw1.issuer_authority, raw2.issuer_authority);
        prop_assert_eq!(raw1.version, raw2.version);
        prop_assert_eq!(raw1.revision, raw2.revision);
    }
}

proptest! {
    #[test]
    fn parse_round_trip_preserves_capabilities(
        uuid in "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    ) {
        let json = build_grant_json_with_ids(&uuid);

        let raw1 = trustgrant::document::RawTrustGrantDocument::parse_json_str(&json)
            .unwrap_or_else(|error| panic!("first parse should succeed: {error}"));
        let json2 = raw1
            .to_json_string()
            .unwrap_or_else(|error| panic!("serialization should succeed: {error}"));
        let raw2 = trustgrant::document::RawTrustGrantDocument::parse_json_str(&json2)
            .unwrap_or_else(|error| panic!("second parse should succeed: {error}"));

        // Capabilities must survive
        prop_assert_eq!(
            raw1.capabilities.recognize, raw2.capabilities.recognize,
            "recognize capability changed across round-trip"
        );
        prop_assert_eq!(
            raw1.capabilities.mint, raw2.capabilities.mint,
            "mint capability changed across round-trip"
        );
    }
}

proptest! {
    #[test]
    fn parse_round_trip_preserves_supersession_policy(
        uuid in "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    ) {
        let json = build_grant_json_with_ids(&uuid);

        let raw1 = trustgrant::document::RawTrustGrantDocument::parse_json_str(&json)
            .unwrap_or_else(|error| panic!("first parse should succeed: {error}"));
        let json2 = raw1
            .to_json_string()
            .unwrap_or_else(|error| panic!("serialization should succeed: {error}"));
        let raw2 = trustgrant::document::RawTrustGrantDocument::parse_json_str(&json2)
            .unwrap_or_else(|error| panic!("second parse should succeed: {error}"));

        prop_assert_eq!(raw1.supersession_policy, raw2.supersession_policy);
    }
}

// ---------------------------------------------------------------------------
// Test 2: Canonicalization determinism
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn canonicalization_is_deterministic(
        _ in 0..10u8,
    ) {
        let draft = build_draft();
        let signed = draft
            .into_signed_document(SIGNATURE)
            .unwrap_or_else(|error| panic!("into_signed_document should succeed: {error}"));
        let json = signed
            .to_json_string()
            .unwrap_or_else(|error| panic!("serialization should succeed: {error}"));

        let raw = trustgrant::document::RawTrustGrantDocument::parse_json_str(&json)
            .unwrap_or_else(|error| panic!("parse should succeed: {error}"));

        let canonical1 = trustgrant::canonicalize_trustgrant(&raw, CanonicalizationProfile::Rfc8785)
            .unwrap_or_else(|error| panic!("first canonicalization should succeed: {error}"));
        let canonical2 = trustgrant::canonicalize_trustgrant(&raw, CanonicalizationProfile::Rfc8785)
            .unwrap_or_else(|error| panic!("second canonicalization should succeed: {error}"));

        prop_assert_eq!(canonical1.as_slice(), canonical2.as_slice());
    }
}

proptest! {
    #[test]
    fn canonical_bytes_do_not_contain_signature(
        _ in 0..10u8,
    ) {
        let draft = build_draft();
        let signed = draft
            .into_signed_document(SIGNATURE)
            .unwrap_or_else(|error| panic!("into_signed_document should succeed: {error}"));
        let json = signed
            .to_json_string()
            .unwrap_or_else(|error| panic!("serialization should succeed: {error}"));

        let raw = trustgrant::document::RawTrustGrantDocument::parse_json_str(&json)
            .unwrap_or_else(|error| panic!("parse should succeed: {error}"));

        let canonical = trustgrant::canonicalize_trustgrant(&raw, CanonicalizationProfile::Rfc8785)
            .unwrap_or_else(|error| panic!("canonicalization should succeed: {error}"));

        let canonical_str = std::str::from_utf8(canonical.as_slice())
            .unwrap_or_else(|error| panic!("canonical bytes should be valid UTF-8: {error}"));

        // The canonical payload must NOT include the "signature" field,
        // since the signature signs over the canonical form.
        prop_assert!(
            !canonical_str.contains("\"signature\""),
            "canonical bytes should not contain the signature field"
        );
    }
}

proptest! {
    #[test]
    fn canonical_bytes_contain_required_fields(
        _ in 0..10u8,
    ) {
        let draft = build_draft();
        let signed = draft
            .into_signed_document(SIGNATURE)
            .unwrap_or_else(|error| panic!("into_signed_document should succeed: {error}"));
        let json = signed
            .to_json_string()
            .unwrap_or_else(|error| panic!("serialization should succeed: {error}"));

        let raw = trustgrant::document::RawTrustGrantDocument::parse_json_str(&json)
            .unwrap_or_else(|error| panic!("parse should succeed: {error}"));

        let canonical = trustgrant::canonicalize_trustgrant(&raw, CanonicalizationProfile::Rfc8785)
            .unwrap_or_else(|error| panic!("canonicalization should succeed: {error}"));

        let canonical_str = std::str::from_utf8(canonical.as_slice())
            .unwrap_or_else(|error| panic!("canonical bytes should be valid UTF-8: {error}"));

        prop_assert!(canonical_str.contains("\"trustgrant_id\""), "missing trustgrant_id");
        prop_assert!(canonical_str.contains("\"issuer_authority\""), "missing issuer_authority");
        prop_assert!(canonical_str.contains("\"key_id\""), "missing key_id");
        prop_assert!(canonical_str.contains("\"capabilities\""), "missing capabilities");
        prop_assert!(canonical_str.contains("\"target_scope\""), "missing target_scope");
        prop_assert!(canonical_str.contains("\"resource_scope\""), "missing resource_scope");
    }
}

// ---------------------------------------------------------------------------
// Test 3: Evaluation determinism
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn evaluation_is_deterministic(
        _ in 0..10u8,
    ) {
        let grant_json = build_signed_json();

        let pipeline = VerificationPipeline::new();
        let artifacts = pipeline
            .verify_json_str(&grant_json, &FakeSignatureVerifier, verification_metadata_non_revocable())
            .unwrap_or_else(|error| panic!("verification should succeed: {error}"));
        let verified_grant = artifacts.verified_grant();

        let engine = EvaluationEngine::new();
        let request = build_recognize_request();

        let outcome1 = engine.evaluate(verified_grant, &request);
        let outcome2 = engine.evaluate(verified_grant, &request);

        prop_assert_eq!(outcome1.decision().is_allowed(), outcome2.decision().is_allowed());
        prop_assert_eq!(outcome1.decision().deny_reason(), outcome2.decision().deny_reason());
    }
}

proptest! {
    #[test]
    fn evaluation_of_identical_grants_gives_same_result(
        _ in 0..10u8,
    ) {
        // Two separate verification runs of the same JSON produce grants
        // that evaluate identically.
        let grant_json = build_signed_json();

        let pipeline = VerificationPipeline::new();
        let artifacts1 = pipeline
            .verify_json_str(&grant_json, &FakeSignatureVerifier, verification_metadata_non_revocable())
            .unwrap_or_else(|error| panic!("first verification should succeed: {error}"));
        let artifacts2 = pipeline
            .verify_json_str(&grant_json, &FakeSignatureVerifier, verification_metadata_non_revocable())
            .unwrap_or_else(|error| panic!("second verification should succeed: {error}"));

        let engine = EvaluationEngine::new();
        let request = build_recognize_request();

        let outcome1 = engine.evaluate(artifacts1.verified_grant(), &request);
        let outcome2 = engine.evaluate(artifacts2.verified_grant(), &request);

        prop_assert_eq!(outcome1.decision().is_allowed(), outcome2.decision().is_allowed());
        prop_assert_eq!(outcome1.decision().deny_reason(), outcome2.decision().deny_reason());
    }
}

// ---------------------------------------------------------------------------
// Formal property-based verification tests (spec §10–§13)
// ---------------------------------------------------------------------------

fn make_grant_json(overrides: &[(&str, serde_json::Value)]) -> String {
    let mut doc = serde_json::json!({
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
        "default_audience_scope": [{"authority_id": "https://audience.example.com", "scope": {"all": true, "allow": null, "deny": null}, "principal_scope": null}],
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
        "revocation": {
            "revocable": true,
            "revocation_endpoint": "https://issuer.example.com/revocation",
            "post_revocation_effect": "block_all"
        },
        "issued_at": "2026-06-01T12:00:00Z",
        "signature": "valid-signature",
        "issuer_principal": { "kind": "service", "id": "issuer-worker" }
    });
    let obj = doc.as_object_mut().unwrap();
    for (key, val) in overrides {
        obj.insert(key.to_string(), val.clone());
    }
    serde_json::to_string(&doc).unwrap()
}

fn ts(s: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(s)
        .unwrap()
        .with_timezone(&chrono::Utc)
}

fn make_metadata() -> VerificationMetadata {
    VerificationMetadata::new(
        ts("2026-06-15T12:00:00Z"),
        VerificationPosture::Online,
        ResolvedSignerBinding::new(
            AuthorityId::new("https://issuer.example.com").unwrap(),
            AuthorityKeyRecord::new(
                "root-key-1",
                "ed25519",
                "base64-public-key",
                ts("2026-01-01T00:00:00Z"),
                ts("2027-01-01T00:00:00Z"),
            )
            .unwrap(),
            SignatureProfile::new("jcs+ed25519", "RFC8785").unwrap(),
            Some(DelegatedPrincipalRef::new("service", "issuer-worker").unwrap()),
        ),
        OwnershipVerificationRecord::new(
            AuthorityId::new("https://issuer.example.com").unwrap(),
            AuthorityId::new("https://issuer.example.com").unwrap(),
            ts("2026-06-15T12:00:00Z"),
            OwnershipProofKind::StaticOwner,
            None,
        ),
        VerifiedRevocationState::Checked(
            RevocationRecord::new(
                RevocationStatus::Active,
                RevocationSourceKind::Api,
                ProofFinality::Observed,
                ts("2026-06-15T12:00:00Z"),
                ts("2026-06-15T12:00:00Z"),
            )
            .unwrap(),
        ),
    )
}

fn evaluate_json(json: &str, target: &str, namespace: &str) -> EvaluationOutcome {
    let validated =
        ValidatedTrustGrantDocument::try_from(RawTrustGrantDocument::parse_json_str(json).unwrap())
            .unwrap();
    let grant = VerifiedTrustGrant::new(validated, make_metadata());
    let mut resource = ResourceContext::new("item").unwrap();
    resource.insert_selector("namespace", namespace).unwrap();
    let request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(ResourceRef::new(
            AuthorityId::new("https://issuer.example.com").unwrap(),
            "item".to_owned(),
        )),
        AuthorityId::new(target).unwrap(),
        AuthorityId::new("https://audience.example.com").unwrap(),
        resource,
        ts("2026-06-15T12:00:00Z"),
    )
    .unwrap();
    EvaluationEngine::new().evaluate(&grant, &request)
}

fn evaluate_request_json(json: &str, request: &EvaluationRequest) -> EvaluationOutcome {
    let validated =
        ValidatedTrustGrantDocument::try_from(RawTrustGrantDocument::parse_json_str(json).unwrap())
            .unwrap();
    let grant = VerifiedTrustGrant::new(validated, make_metadata());
    EvaluationEngine::new().evaluate(&grant, request)
}

// ---------------------------------------------------------------------------
// Formal property 1: Deny is always subtractive (spec §10)
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn formal_deny_is_subtractive(
        _ in 0..10u8,
    ) {
        // When a target matches both allow AND deny selectors,
        // the result must always be Denied, never Allowed.
        let json = make_grant_json(&[
            ("target_scope", serde_json::json!({
                "all": false,
                "allow": [{"kind": "authority", "all": false, "values": ["https://target.example.com"], "expressions": null}],
                "deny": [{"kind": "authority", "all": false, "values": ["https://target.example.com"], "expressions": null}]
            })),
        ]);
        let outcome = evaluate_json(&json, "https://target.example.com", "weapons");
        prop_assert!(
            !outcome.decision().is_allowed(),
            "deny must be subtractive: when target is in both allow and deny, result must be denial"
        );
    }
}

// ---------------------------------------------------------------------------
// Formal property 2: Allow is always explicit (spec §10)
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn formal_allow_is_explicit(
        _ in 0..10u8,
    ) {
        // When a target is NOT in any allow selector, the result must
        // always be Denied, never Allowed.
        let json = make_grant_json(&[
            ("target_scope", serde_json::json!({
                "all": false,
                "allow": [{"kind": "authority", "all": false, "values": ["https://allowed.example.com"], "expressions": null}],
                "deny": null
            })),
        ]);
        let outcome = evaluate_json(&json, "https://other.example.com", "weapons");
        prop_assert!(
            !outcome.decision().is_allowed(),
            "allow must be explicit: non-matching target must be denied"
        );
    }
}

// ---------------------------------------------------------------------------
// Formal property 3: Fail-closed (spec §10)
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn formal_fail_closed(
        _ in 0..10u8,
    ) {
        // For ANY request, the default outcome is denial.
        // A request for a non-existent resource type should always be denied.
        let json = make_grant_json(&[]);
        let mut resource = ResourceContext::new("nonexistent_type").unwrap();
        resource.insert_selector("namespace", "anything").unwrap();
        let request = EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Recognize),
            ResourceBinding::Existing(ResourceRef::new(
                AuthorityId::new("https://issuer.example.com").unwrap(),
                "nonexistent_type".to_owned(),
            )),
            AuthorityId::new("https://target.example.com").unwrap(),
            AuthorityId::new("https://audience.example.com").unwrap(),
            resource,
            ts("2026-06-15T12:00:00Z"),
        ).unwrap();
        let outcome = evaluate_request_json(&json, &request);
        prop_assert!(
            !outcome.decision().is_allowed(),
            "fail-closed: non-matching resource type must be denied"
        );
    }
}

// ---------------------------------------------------------------------------
// Formal property 4: Capability inheritance (spec §11)
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn formal_capability_inheritance(
        _ in 0..10u8,
    ) {
        // Per-type capabilities must correctly override global capabilities.
        // Case 1: global mint=true, per-type mint=false → denied
        let json_disabled = make_grant_json(&[
            ("capabilities", serde_json::json!({ "recognize": false, "mint": true })),
            ("resource_scope", serde_json::json!({
                "types": {
                    "item": {
                        "all": false,
                        "allow": [{"kind": "namespace", "all": false, "values": ["weapons"], "expressions": null}],
                        "deny": null,
                        "capabilities": { "recognize": false, "mint": false },
                        "constraints": { "minting": { "max_total": null, "max_per_user": null }, "audience_scope": null },
                        "operations": { "all": false, "allow": ["create"], "deny": null }
                    }
                }
            })),
        ]);
        let mut resource = ResourceContext::new("item").unwrap();
        resource.insert_selector("namespace", "weapons").unwrap();
        let request = EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Mint),
            ResourceBinding::Mint(TemplateRef::new(
                AuthorityId::new("https://issuer.example.com").unwrap(),
            )),
            AuthorityId::new("https://target.example.com").unwrap(),
            AuthorityId::new("https://audience.example.com").unwrap(),
            resource,
            ts("2026-06-15T12:00:00Z"),
        ).unwrap().with_mint_context_for_testing(MintContext::new(0, 0)).verify_selectors();
        let outcome = evaluate_request_json(&json_disabled, &request);
        prop_assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::CapabilityDisabled),
            "per-type mint=false overrides global mint=true"
        );

        // Case 2: global mint=false, per-type mint=null → uses global (denied)
        let json_global = make_grant_json(&[
            ("capabilities", serde_json::json!({ "recognize": false, "mint": false })),
        ]);
        let mut resource2 = ResourceContext::new("item").unwrap();
        resource2.insert_selector("namespace", "weapons").unwrap();
        let request2 = EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Mint),
            ResourceBinding::Mint(TemplateRef::new(
                AuthorityId::new("https://issuer.example.com").unwrap(),
            )),
            AuthorityId::new("https://target.example.com").unwrap(),
            AuthorityId::new("https://audience.example.com").unwrap(),
            resource2,
            ts("2026-06-15T12:00:00Z"),
        ).unwrap().with_mint_context_for_testing(MintContext::new(0, 0)).verify_selectors();
        let outcome2 = evaluate_request_json(&json_global, &request2);
        prop_assert_eq!(
            outcome2.decision().deny_reason(),
            Some(EvaluationDenyReason::CapabilityDisabled),
            "per-type mint=null inherits global mint=false"
        );
    }
}

// ---------------------------------------------------------------------------
// Formal property 5: Evaluation order (spec §13)
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn formal_evaluation_order_expired_before_target(
        _ in 0..10u8,
    ) {
        // Spec §13: Expired check (step 2) happens BEFORE target scope check
        // (step 4). An expired grant must return Expired, not TargetNotAllowed.
        let json = make_grant_json(&[
            ("global_constraints", serde_json::json!({
                "time": { "not_before": "2025-01-01T00:00:00Z", "not_after": "2025-06-01T00:00:00Z" }
            })),
        ]);
        let outcome = evaluate_json(&json, "https://nonexistent.example.com", "weapons");
        prop_assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::Expired),
            "expired check must happen before target scope check"
        );
    }
}

// ---------------------------------------------------------------------------
// Formal property 6: Origin authority enforcement (spec §13 step 3)
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn formal_origin_authority_enforcement(
        _ in 0..10u8,
    ) {
        // Spec §13 step 3: origin authority mismatch must cause denial
        let json = make_grant_json(&[]);
        let mut resource = ResourceContext::new("item").unwrap();
        resource.insert_selector("namespace", "weapons").unwrap();
        let request = EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Recognize),
            ResourceBinding::Existing(ResourceRef::new(
                AuthorityId::new("https://other.example.com").unwrap(),
                "item".to_owned(),
            )),
            AuthorityId::new("https://target.example.com").unwrap(),
            AuthorityId::new("https://audience.example.com").unwrap(),
            resource,
            ts("2026-06-15T12:00:00Z"),
        ).unwrap();
        let outcome = evaluate_request_json(&json, &request);
        prop_assert_eq!(
            outcome.decision().deny_reason(),
            Some(EvaluationDenyReason::OriginAuthorityMismatch),
            "origin authority mismatch must be enforced"
        );
    }
}
