#![allow(clippy::panic)]

use std::collections::BTreeMap;

use chrono::{DateTime, TimeZone, Utc};
use trustgrant::{
    AuthorityDiscoverySource, AuthorityId, AuthorityKeyRecord, BundleRevocationProof,
    EvaluationDenyReason, EvaluationEngine, EvaluationRequest, GrantRevision, OwnershipChainVerifier,
    OwnershipProofKind, OwnershipResourceScope, OwnershipSelector, OwnershipTransitionLineage,
    OwnershipTransitionParties, OwnershipTransitionRecord, OwnershipTransitionVerifier,
    ProofFinality, RawOwnershipTransitionDocument, RawTrustGrantDocument, RequestedCapability,
    RequestedOperation, ResolvedSignerBinding, ResourceBinding, ResourceContext, ResourceRef,
    ResourceTypeName, RevocationFreshnessPolicy, RevocationSourceKind, SignatureProfile,
    SignatureVerificationRequest, SignatureVerifier, TransitionId, TransitionSeriesId,
    TrustGrantError, TrustGrantProofBundle, ValidatedPrincipal, ValidatedTrustGrantDocument,
    VerificationContext, VerificationPipeline, VerificationPosture,
    parse_authority_discovery_document, parse_revocation_status_proof,
};

#[derive(Debug, Default)]
struct FakeSignatureVerifier;

impl SignatureVerifier for FakeSignatureVerifier {
    fn verify_signature(
        &self,
        request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), TrustGrantError> {
        if request.signature_profile().format().as_str() == "jcs+ed25519"
            && request.signature_profile().canonicalization().as_str() == "RFC8785"
            && !request.signature().is_empty()
            && !request.canonical_bytes().is_empty()
        {
            Ok(())
        } else {
            Err(TrustGrantError::SignatureVerificationFailed)
        }
    }
}

const ORIGIN_DISCOVERY_JSON: &str = r#"{
  "authority_id":"https://origin.example.com",
  "keys":[
    {
      "key_id":"origin-key-1",
      "algorithm":"ed25519",
      "public_key":"base64-origin-public-key",
      "not_before":"2026-01-01T00:00:00Z",
      "not_after":"2027-01-01T00:00:00Z"
    }
  ],
  "signature_profile":{
    "format":"jcs+ed25519",
    "canonicalization":"RFC8785"
  },
  "issued_at":"2026-04-07T12:00:00Z"
}"#;

const SUCCESSOR_DISCOVERY_JSON: &str = r#"{
  "authority_id":"https://successor.example.com",
  "keys":[
    {
      "key_id":"successor-key-1",
      "algorithm":"ed25519",
      "public_key":"base64-successor-public-key",
      "not_before":"2026-01-01T00:00:00Z",
      "not_after":"2027-01-01T00:00:00Z"
    }
  ],
  "signature_profile":{
    "format":"jcs+ed25519",
    "canonicalization":"RFC8785"
  },
  "issued_at":"2026-04-07T12:00:00Z"
}"#;

const SUCCESSOR_TRUSTGRANT_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174300",
  "version":0,
  "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174301",
  "revision":1,
  "supersedes":null,
  "supersession_policy":"coexist",
  "issuer_authority":"https://successor.example.com",
  "origin_authority":"https://origin.example.com",
  "active_owning_authority":"https://successor.example.com",
  "key_id":"successor-key-1",
  "target_scope":{"all":false,"allow":[{"kind":"authority","all":false,"values":["https://target.example.com"],"expressions":null}],"deny":null},
  "capabilities":{"recognize":true,"mint":false},
  "default_audience_scope":[{"authority_id":"https://audience.example.com","scope":{"all":true,"allow":null,"deny":null},"principal_scope":null}],
  "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["weapon_alpha"],"expressions":null}],"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
  "global_constraints":null,
  "revocation":{"revocable":true,"revocation_endpoint":"https://successor.example.com/revocation","post_revocation_effect":"block_all"},
  "issued_at":"2026-04-07T12:30:00Z",
  "signature":"base64-signature",
  "issuer_principal":null
}"#;

const OWNERSHIP_TRANSITION_JSON: &str = r#"{
  "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174400",
  "version":0,
  "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174401",
  "revision":1,
  "supersedes_transition_id":null,
  "origin_authority":"https://origin.example.com",
  "from_authority":"https://origin.example.com",
  "to_authority":"https://successor.example.com",
  "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["weapon_alpha"],"expressions":null}],"deny":null}}},
  "global_constraints":{"time":{"not_before":"2026-04-07T11:00:00Z","not_after":"2026-04-07T14:00:00Z"}},
  "effective_at":"2026-04-07T12:00:00Z",
  "predecessor_signature":{"key_id":"origin-key-1","signature":"origin-signature"},
  "successor_acceptance":{"accepted_at":"2026-04-07T11:30:00Z","key_id":"successor-key-1","signature":"successor-signature"}
}"#;

const SUCCESSOR_REVOCATION_JSON: &str = r#"{
  "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174300",
  "status":"active",
  "checked_at":"2026-04-07T12:30:00Z"
}"#;

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

/// Helper: parse a trust grant JSON into a validated document.
fn validated_document_from_json(json: &str) -> ValidatedTrustGrantDocument {
    let raw = RawTrustGrantDocument::parse_json_str(json)
        .unwrap_or_else(|error| panic!("raw document should parse: {error}"));
    ValidatedTrustGrantDocument::try_from(raw)
        .unwrap_or_else(|error| panic!("document should validate: {error}"))
}

/// Helper: construct a validated [`AuthorityId`].
fn authority(value: &str) -> AuthorityId {
    AuthorityId::new(value)
        .unwrap_or_else(|error| panic!("authority should be valid: {error}"))
}

/// Helper: construct an [`OwnershipTransitionRecord`] for a single-hop transfer.
fn make_transition_record(
    transition_id: &str,
    series_id: &str,
    revision: u64,
    supersedes: Option<&str>,
    from_authority: &str,
    to_authority: &str,
    effective_at: DateTime<Utc>,
) -> OwnershipTransitionRecord {
    OwnershipTransitionRecord::new(
        OwnershipTransitionLineage::new(
            transition_id
                .parse::<TransitionId>()
                .unwrap_or_else(|error| panic!("transition id should parse: {error}")),
            series_id
                .parse::<TransitionSeriesId>()
                .unwrap_or_else(|error| panic!("series id should parse: {error}")),
            GrantRevision::new(revision)
                .unwrap_or_else(|error| panic!("revision should be valid: {error}")),
            supersedes
                .map(|s| {
                    s.parse::<TransitionId>()
                        .unwrap_or_else(|error| panic!("supersedes id should parse: {error}"))
                }),
        )
        .unwrap_or_else(|error| panic!("lineage should be valid: {error}")),
        OwnershipTransitionParties::new(
            authority("https://origin.example.com"),
            authority(from_authority),
            authority(to_authority),
        )
        .unwrap_or_else(|error| panic!("parties should be valid: {error}")),
        BTreeMap::from([(
            ResourceTypeName::new("item")
                .unwrap_or_else(|error| panic!("resource type should be valid: {error}")),
            OwnershipResourceScope::new(vec![
                OwnershipSelector::new("id", vec!["weapon_alpha".to_owned()])
                    .unwrap_or_else(|error| panic!("selector should be valid: {error}")),
            ])
            .unwrap_or_else(|error| panic!("resource scope should be valid: {error}")),
        )]),
        None,
        effective_at,
    )
    .unwrap_or_else(|error| panic!("transition record should be valid: {error}"))
}

/// A minimal discovery source that panics if called (used when the discovery
/// source path should never be reached).
#[derive(Debug, Default)]
struct UnreachableDiscoverySource;

impl AuthorityDiscoverySource for UnreachableDiscoverySource {
    fn resolve_signer_binding(
        &self,
        _issuer_authority: &AuthorityId,
        _key_id: &trustgrant::KeyId,
        _issuer_principal: Option<&ValidatedPrincipal>,
        _context: VerificationContext,
    ) -> Result<ResolvedSignerBinding, TrustGrantError> {
        panic!("UnreachableDiscoverySource should never be called")
    }
}

/// A discovery source that always returns a wrong authority, triggering
/// [`TrustGrantError::SignerAuthorityMismatch`].
#[derive(Debug, Default)]
struct WrongAuthorityDiscoverySource;

impl AuthorityDiscoverySource for WrongAuthorityDiscoverySource {
    fn resolve_signer_binding(
        &self,
        _issuer_authority: &AuthorityId,
        key_id: &trustgrant::KeyId,
        _issuer_principal: Option<&ValidatedPrincipal>,
        _context: VerificationContext,
    ) -> Result<ResolvedSignerBinding, TrustGrantError> {
        let wrong_authority = AuthorityId::new("https://wrong.example.com")
            .unwrap_or_else(|error| panic!("wrong authority should be valid: {error}"));
        let key_record = AuthorityKeyRecord::new(
            key_id.as_str().to_owned(),
            "ed25519",
            "public-key-material",
            fixed_timestamp(2026, 1, 1, 0, 0, 0),
            fixed_timestamp(2027, 1, 1, 0, 0, 0),
        )
        .unwrap_or_else(|error| panic!("key record should be valid: {error}"));
        let signature_profile = SignatureProfile::new("jcs+ed25519", "RFC8785")
            .unwrap_or_else(|error| panic!("signature profile should be valid: {error}"));
        Ok(ResolvedSignerBinding::new(
            wrong_authority,
            key_record,
            signature_profile,
            None,
        ))
    }
}

// ---------- OwnershipChainVerifier tests ----------

#[test]
fn ownership_chain_verifier_rejects_empty_chain() {
    let document = validated_document_from_json(SUCCESSOR_TRUSTGRANT_JSON);

    let result = OwnershipChainVerifier::new().verify_document_ownership(
        &document,
        &[],
        fixed_timestamp(2026, 4, 7, 12, 30, 0),
    );

    assert_eq!(result, Err(TrustGrantError::MissingOwnershipTransitionChain));
}

#[test]
fn ownership_chain_verifier_rejects_duplicate_transition_ids() {
    let document = validated_document_from_json(SUCCESSOR_TRUSTGRANT_JSON);
    let ts = fixed_timestamp(2026, 4, 7, 12, 0, 0);

    let common_id = "tgt_11111111-1111-4111-8111-111111111111";
    let series = "tgts_11111111-1111-4111-8111-111111111111";

    let record_a = make_transition_record(
        common_id,
        series,
        1,
        None,
        "https://origin.example.com",
        "https://intermediate.example.com",
        ts,
    );
    // Second record shares the same transition_id — will be caught by the
    // duplicate-ID check before any later chain invariant is evaluated.
    // The predecessor check would reject (origin != intermediate) but we
    // never reach it because duplicate detection fires first.
    let record_b = make_transition_record(
        common_id,
        series,
        2,
        Some("tgt_99999999-9999-4999-8999-999999999999"),
        "https://origin.example.com",
        "https://successor.example.com",
        ts,
    );

    let result = OwnershipChainVerifier::new().verify_document_ownership(
        &document,
        &[record_a, record_b],
        fixed_timestamp(2026, 4, 7, 12, 30, 0),
    );

    assert_eq!(result, Err(TrustGrantError::InvalidOwnershipTransitionChain));
}

#[test]
fn ownership_chain_verifier_rejects_wrong_series_id() {
    let document = validated_document_from_json(SUCCESSOR_TRUSTGRANT_JSON);
    let ts = fixed_timestamp(2026, 4, 7, 12, 0, 0);

    let record_a = make_transition_record(
        "tgt_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "tgts_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        1,
        None,
        "https://origin.example.com",
        "https://intermediate.example.com",
        ts,
    );
    // Second record uses a different series_id -> rejection
    let record_b = make_transition_record(
        "tgt_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "tgts_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        2,
        Some("tgt_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        "https://intermediate.example.com",
        "https://successor.example.com",
        ts,
    );

    let result = OwnershipChainVerifier::new().verify_document_ownership(
        &document,
        &[record_a, record_b],
        fixed_timestamp(2026, 4, 7, 12, 30, 0),
    );

    assert_eq!(result, Err(TrustGrantError::InvalidOwnershipTransitionChain));
}

// ---------- OwnershipTransitionVerifier tests ----------

#[test]
fn ownership_transition_verifier_rejects_invalid_json() {
    let result = OwnershipTransitionVerifier::new().verify_json_str(
        "not valid json at all",
        &FakeSignatureVerifier,
        &UnreachableDiscoverySource,
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
            VerificationPosture::Online,
        ),
    );

    assert_eq!(
        result.map(|_| ()),
        Err(TrustGrantError::InvalidOwnershipTransitionDocument)
    );
}

#[test]
fn ownership_transition_verifier_rejects_missing_successor_signature() {
    // Valid JSON structure but missing the required `successor_acceptance` field.
    let missing_acceptance = r#"{
      "transition_id":"tgt_cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      "version":0,
      "transition_series_id":"tgts_cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      "revision":1,
      "supersedes_transition_id":null,
      "origin_authority":"https://origin.example.com",
      "from_authority":"https://origin.example.com",
      "to_authority":"https://successor.example.com",
      "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["weapon_alpha"],"expressions":null}],"deny":null}}},
      "global_constraints":null,
      "effective_at":"2026-04-07T12:00:00Z",
      "predecessor_signature":{"key_id":"origin-key-1","signature":"origin-signature"}
    }"#;

    let result = OwnershipTransitionVerifier::new().verify_json_str(
        missing_acceptance,
        &FakeSignatureVerifier,
        &UnreachableDiscoverySource,
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
            VerificationPosture::Online,
        ),
    );

    assert_eq!(
        result.map(|_| ()),
        Err(TrustGrantError::InvalidOwnershipTransitionDocument)
    );
}

#[test]
fn ownership_transition_verifier_rejects_wrong_signer_authority() {
    // Use a valid transition JSON with a discovery source that returns a
    // mismatched authority, triggering SignerAuthorityMismatch.
    let result = OwnershipTransitionVerifier::new().verify_json_str(
        OWNERSHIP_TRANSITION_JSON,
        &FakeSignatureVerifier,
        &WrongAuthorityDiscoverySource,
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
            VerificationPosture::Online,
        ),
    );

    assert_eq!(
        result.map(|_| ()),
        Err(TrustGrantError::SignerAuthorityMismatch)
    );
}

// ---------- Multi-hop chain test ----------

#[test]
fn multi_hop_ownership_transition_evaluates_correctly() {
    // Grant document: origin → third, via an intermediate authority.
    let multi_hop_json = SUCCESSOR_TRUSTGRANT_JSON
        .replace(
            r#""active_owning_authority":"https://successor.example.com""#,
            r#""active_owning_authority":"https://third.example.com""#,
        );
    let document = validated_document_from_json(&multi_hop_json);

    // Chain: origin.example.com → intermediate.example.com → third.example.com
    let record_a = make_transition_record(
        "tgt_dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        "tgts_dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        1,
        None,
        "https://origin.example.com",
        "https://intermediate.example.com",
        fixed_timestamp(2026, 4, 7, 12, 0, 0),
    );
    let record_b = make_transition_record(
        "tgt_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        "tgts_dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        2,
        Some("tgt_dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
        "https://intermediate.example.com",
        "https://third.example.com",
        fixed_timestamp(2026, 4, 7, 12, 15, 0),
    );

    let result = OwnershipChainVerifier::new().verify_document_ownership(
        &document,
        &[record_a, record_b],
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    );

    let record = result
        .unwrap_or_else(|error| panic!("multi-hop chain verification should succeed: {error}"));

    assert_eq!(
        record.origin_authority().as_str(),
        "https://origin.example.com"
    );
    assert_eq!(
        record.active_owning_authority().as_str(),
        "https://third.example.com"
    );
    assert_eq!(record.proof_kind(), OwnershipProofKind::TransitionChain);
    assert!(record.transition_chain_tip().is_some());
}

/// Build a proof bundle containing both origin and successor discovery documents,
/// the revocation proof, and the ownership transition chain.
fn ownership_pipeline_bundle() -> TrustGrantProofBundle {
    let mut proof_bundle = TrustGrantProofBundle::new();
    proof_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(ORIGIN_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("origin discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("origin discovery should insert: {error}"));
    proof_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(SUCCESSOR_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("successor discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("successor discovery should insert: {error}"));
    proof_bundle
        .insert_revocation_proof(BundleRevocationProof::new(
            parse_revocation_status_proof(SUCCESSOR_REVOCATION_JSON)
                .unwrap_or_else(|error| panic!("revocation proof should parse: {error}")),
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            RevocationFreshnessPolicy::new(86400, 86400)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        ))
        .unwrap_or_else(|error| panic!("revocation proof should insert: {error}"));
    proof_bundle
        .insert_ownership_transition_chain(
            "tg_123e4567-e89b-12d3-a456-426614174300"
                .parse()
                .unwrap_or_else(|error| panic!("trustgrant id should parse: {error}")),
            vec![
                RawOwnershipTransitionDocument::parse_json_str(OWNERSHIP_TRANSITION_JSON)
                    .unwrap_or_else(|error| panic!("transition proof should parse: {error}")),
            ],
        )
        .unwrap_or_else(|error| panic!("ownership chain should insert: {error}"));
    proof_bundle
}

#[test]
fn full_ownership_transition_pipeline_verifies_and_evaluates() {
    let proof_bundle = ownership_pipeline_bundle();
    let verifier = FakeSignatureVerifier;

    // Step 1-3: Verify the successor trustgrant with ownership transition chain
    let artifacts = VerificationPipeline::new()
        .verify_json_str_with_sources(
            SUCCESSOR_TRUSTGRANT_JSON,
            &verifier,
            proof_bundle.as_sources(),
            VerificationContext::new(
                fixed_timestamp(2026, 4, 7, 12, 30, 0),
                VerificationPosture::Online,
            ),
        )
        .unwrap_or_else(|error| panic!("full pipeline verification should succeed: {error}"));

    // Step 4: Verify the trustgrant has the correct ownership chain metadata
    let verified = artifacts.verified_grant();
    assert_eq!(
        verified
            .metadata()
            .ownership()
            .active_owning_authority()
            .as_str(),
        "https://successor.example.com"
    );
    assert_eq!(
        verified.metadata().ownership().origin_authority().as_str(),
        "https://origin.example.com"
    );
    assert!(
        verified
            .metadata()
            .ownership()
            .transition_chain_tip()
            .is_some()
    );

    // Step 5: Evaluate the verified grant with a matching request
    let engine = EvaluationEngine::new();
    let mut resource = ResourceContext::new("item")
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("id", "weapon_alpha")
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));
    let request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(ResourceRef::new(
            AuthorityId::new("https://origin.example.com")
                .unwrap_or_else(|error| panic!("origin authority should be valid: {error}")),
            "item".to_owned(),
        )),
        AuthorityId::new("https://target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new("https://audience.example.com")
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));

    let outcome = engine.evaluate(verified, &request);
    assert!(outcome.decision().is_allowed());
}

#[test]
fn ownership_transition_pipeline_rejects_without_transition_chain() {
    let mut proof_bundle = TrustGrantProofBundle::new();
    proof_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(ORIGIN_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("origin discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("origin discovery should insert: {error}"));
    proof_bundle
        .insert_discovery_document(
            parse_authority_discovery_document(SUCCESSOR_DISCOVERY_JSON)
                .unwrap_or_else(|error| panic!("successor discovery should parse: {error}")),
        )
        .unwrap_or_else(|error| panic!("successor discovery should insert: {error}"));
    proof_bundle
        .insert_revocation_proof(BundleRevocationProof::new(
            parse_revocation_status_proof(SUCCESSOR_REVOCATION_JSON)
                .unwrap_or_else(|error| panic!("revocation proof should parse: {error}")),
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            RevocationFreshnessPolicy::new(86400, 86400)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        ))
        .unwrap_or_else(|error| panic!("revocation proof should insert: {error}"));
    // Intentionally omit the ownership transition chain

    let result = VerificationPipeline::new().verify_json_str_with_sources(
        SUCCESSOR_TRUSTGRANT_JSON,
        &FakeSignatureVerifier,
        proof_bundle.as_sources(),
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
            VerificationPosture::Online,
        ),
    );

    assert_eq!(
        result,
        Err(TrustGrantError::MissingOwnershipTransitionChain)
    );
}

#[test]
fn ownership_transition_pipeline_rejects_with_wrong_successor_authority() {
    // Build a successor trustgrant that claims a different successor authority
    let wrong_successor_json = SUCCESSOR_TRUSTGRANT_JSON
        .replace(
            r#""issuer_authority":"https://successor.example.com""#,
            r#""issuer_authority":"https://wrong.example.com""#,
        )
        .replace(
            r#""active_owning_authority":"https://successor.example.com""#,
            r#""active_owning_authority":"https://wrong.example.com""#,
        );

    let proof_bundle = ownership_pipeline_bundle();

    let result = VerificationPipeline::new().verify_json_str_with_sources(
        &wrong_successor_json,
        &FakeSignatureVerifier,
        proof_bundle.as_sources(),
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
            VerificationPosture::Online,
        ),
    );

    assert!(result.is_err());
}

#[test]
fn ownership_transition_pipeline_rejects_evaluation_with_audience_mismatch() {
    let proof_bundle = ownership_pipeline_bundle();
    let artifacts = VerificationPipeline::new()
        .verify_json_str_with_sources(
            SUCCESSOR_TRUSTGRANT_JSON,
            &FakeSignatureVerifier,
            proof_bundle.as_sources(),
            VerificationContext::new(
                fixed_timestamp(2026, 4, 7, 12, 30, 0),
                VerificationPosture::Online,
            ),
        )
        .unwrap_or_else(|error| panic!("verification should succeed: {error}"));

    let engine = EvaluationEngine::new();
    let mut resource = ResourceContext::new("item")
        .unwrap_or_else(|error| panic!("resource context should be valid: {error}"));
    resource
        .insert_selector("id", "weapon_alpha")
        .unwrap_or_else(|error| panic!("resource selector should be valid: {error}"));
    let request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(ResourceRef::new(
            AuthorityId::new("https://origin.example.com")
                .unwrap_or_else(|error| panic!("origin authority should be valid: {error}")),
            "item".to_owned(),
        )),
        AuthorityId::new("https://target.example.com")
            .unwrap_or_else(|error| panic!("target authority should be valid: {error}")),
        AuthorityId::new("https://wrong-audience.example.com")
            .unwrap_or_else(|error| panic!("audience authority should be valid: {error}")),
        resource,
        fixed_timestamp(2026, 4, 7, 13, 0, 0),
    )
    .unwrap_or_else(|error| panic!("evaluation request should be valid: {error}"));

    let outcome = engine.evaluate(artifacts.verified_grant(), &request);
    assert_eq!(
        outcome.decision().deny_reason(),
        Some(EvaluationDenyReason::AudienceNotAllowed)
    );
}

// ---------------------------------------------------------------------------
// G12: RawOwnershipTransitionDocument parsing validation errors
// ---------------------------------------------------------------------------

#[test]
fn ownership_transition_rejects_missing_required_fields() {
    // Missing transition_id
    assert_eq!(
        RawOwnershipTransitionDocument::parse_json_str(r#"{"version":0,"transition_series_id":"ts","revision":1,"origin_authority":"https://o.example.com","from_authority":"https://o.example.com","to_authority":"https://t.example.com","canonical_resource_scope":{"types":{}},"effective_at":"2026-04-07T12:00:00Z","predecessor_signature":{"key_id":"k","signature":"s"},"successor_acceptance":{"accepted_at":"2026-04-07T11:30:00Z","key_id":"k","signature":"s"}}"#),
        Err(TrustGrantError::InvalidOwnershipTransitionDocument),
    );

    // Missing effective_at
    assert_eq!(
        RawOwnershipTransitionDocument::parse_json_str(r#"{"transition_id":"tgt_1","version":0,"transition_series_id":"ts","revision":1,"origin_authority":"https://o.example.com","from_authority":"https://o.example.com","to_authority":"https://t.example.com","canonical_resource_scope":{"types":{}},"predecessor_signature":{"key_id":"k","signature":"s"},"successor_acceptance":{"accepted_at":"2026-04-07T11:30:00Z","key_id":"k","signature":"s"}}"#),
        Err(TrustGrantError::InvalidOwnershipTransitionDocument),
    );

    // Missing successor_acceptance
    assert_eq!(
        RawOwnershipTransitionDocument::parse_json_str(r#"{"transition_id":"tgt_1","version":0,"transition_series_id":"ts","revision":1,"origin_authority":"https://o.example.com","from_authority":"https://o.example.com","to_authority":"https://t.example.com","canonical_resource_scope":{"types":{}},"effective_at":"2026-04-07T12:00:00Z","predecessor_signature":{"key_id":"k","signature":"s"}}"#),
        Err(TrustGrantError::InvalidOwnershipTransitionDocument),
    );
}

#[test]
fn ownership_transition_rejects_invalid_selector_shapes() {
    // Selector with neither values nor expressions (both null) — valid at
    // the raw JSON level, but rejected during validation.
    let result = OwnershipTransitionVerifier::new().verify_json_str(
        r#"{"transition_id":"tgt_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","version":0,"transition_series_id":"tgts_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","revision":1,"origin_authority":"https://o.example.com","from_authority":"https://o.example.com","to_authority":"https://t.example.com","canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":null,"expressions":null}],"deny":null}}},"effective_at":"2026-04-07T12:00:00Z","predecessor_signature":{"key_id":"k","signature":"s"},"successor_acceptance":{"accepted_at":"2026-04-07T11:30:00Z","key_id":"k","signature":"s"}}"#,
        &FakeSignatureVerifier,
        &UnreachableDiscoverySource,
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
            VerificationPosture::Online,
        ),
    );
    assert_eq!(
        result.map(|_| ()),
        Err(TrustGrantError::InvalidOwnershipTransitionScope),
    );

    // Selector with all=false, empty allow list, and null deny — valid at the
    // raw JSON level, but rejected during validation.
    let result = OwnershipTransitionVerifier::new().verify_json_str(
        r#"{"transition_id":"tgt_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","version":0,"transition_series_id":"tgts_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","revision":1,"origin_authority":"https://o.example.com","from_authority":"https://o.example.com","to_authority":"https://t.example.com","canonical_resource_scope":{"types":{"item":{"all":false,"allow":[],"deny":null}}},"effective_at":"2026-04-07T12:00:00Z","predecessor_signature":{"key_id":"k","signature":"s"},"successor_acceptance":{"accepted_at":"2026-04-07T11:30:00Z","key_id":"k","signature":"s"}}"#,
        &FakeSignatureVerifier,
        &UnreachableDiscoverySource,
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
            VerificationPosture::Online,
        ),
    );
    assert_eq!(
        result.map(|_| ()),
        Err(TrustGrantError::InvalidOwnershipTransitionScope),
    );
}

#[test]
fn ownership_transition_rejects_invalid_authority_format() {
    // from_authority is not a valid URI — caught during validation.
    let result = OwnershipTransitionVerifier::new().verify_json_str(
        r#"{"transition_id":"tgt_cccccccc-cccc-4ccc-8ccc-cccccccccccc","version":0,"transition_series_id":"tgts_cccccccc-cccc-4ccc-8ccc-cccccccccccc","revision":1,"origin_authority":"https://o.example.com","from_authority":"not-a-valid-uri","to_authority":"https://t.example.com","canonical_resource_scope":{"types":{}},"effective_at":"2026-04-07T12:00:00Z","predecessor_signature":{"key_id":"k","signature":"s"},"successor_acceptance":{"accepted_at":"2026-04-07T11:30:00Z","key_id":"k","signature":"s"}}"#,
        &FakeSignatureVerifier,
        &UnreachableDiscoverySource,
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
            VerificationPosture::Online,
        ),
    );
    assert_eq!(
        result.map(|_| ()),
        Err(TrustGrantError::InvalidAuthorityIdMissingScheme),
    );

    // to_authority is not a valid URI
    let result = OwnershipTransitionVerifier::new().verify_json_str(
        r#"{"transition_id":"tgt_dddddddd-dddd-4ddd-8ddd-dddddddddddd","version":0,"transition_series_id":"tgts_dddddddd-dddd-4ddd-8ddd-dddddddddddd","revision":1,"origin_authority":"https://o.example.com","from_authority":"https://o.example.com","to_authority":"bad!authority","canonical_resource_scope":{"types":{}},"effective_at":"2026-04-07T12:00:00Z","predecessor_signature":{"key_id":"k","signature":"s"},"successor_acceptance":{"accepted_at":"2026-04-07T11:30:00Z","key_id":"k","signature":"s"}}"#,
        &FakeSignatureVerifier,
        &UnreachableDiscoverySource,
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
            VerificationPosture::Online,
        ),
    );
    assert_eq!(
        result.map(|_| ()),
        Err(TrustGrantError::InvalidAuthorityIdMissingScheme),
    );

    // origin_authority is an empty string
    let result = OwnershipTransitionVerifier::new().verify_json_str(
        r#"{"transition_id":"tgt_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee","version":0,"transition_series_id":"tgts_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee","revision":1,"origin_authority":"","from_authority":"https://o.example.com","to_authority":"https://t.example.com","canonical_resource_scope":{"types":{}},"effective_at":"2026-04-07T12:00:00Z","predecessor_signature":{"key_id":"k","signature":"s"},"successor_acceptance":{"accepted_at":"2026-04-07T11:30:00Z","key_id":"k","signature":"s"}}"#,
        &FakeSignatureVerifier,
        &UnreachableDiscoverySource,
        VerificationContext::new(
            fixed_timestamp(2026, 4, 7, 12, 30, 0),
            VerificationPosture::Online,
        ),
    );
    assert_eq!(
        result.map(|_| ()),
        Err(TrustGrantError::EmptyAuthorityId),
    );
}
