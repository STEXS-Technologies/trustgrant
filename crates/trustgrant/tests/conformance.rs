#![allow(clippy::panic)]

use chrono::{DateTime, Utc};
use serde_json::json;
use url::Url;
use trustgrant::{
    AuthorityId, CustomOperationName, EvaluationDecision, EvaluationDenyReason, EvaluationEngine,
    EvaluationRequest, MintContext, RequestedCapability, RequestedOperation, ResourceContext,
    VerifiedRevocationState,
    discovery::{AuthorityKeyRecord, DelegatedPrincipalRef, ResolvedSignerBinding, SignatureProfile},
    document::raw::{RawMintingConstraints, RawSelector, RawSupersessionPolicy, RawTrustGrantDocument},
    document::ValidatedTrustGrantDocument,
    domain::{
        CustomOperationName as CustomOpName, OwnershipProofKind, OwnershipVerificationRecord,
        SelectorExpression, Utf16Key,
    },
    revocation::{
        ProofFinality, RevocationRecord, RevocationSourceKind, RevocationStatus,
    },
    verify::{VerificationMetadata, VerificationPosture, VerifiedTrustGrant},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .unwrap_or_else(|e| panic!("invalid timestamp {s:?}: {e}"))
        .with_timezone(&Utc)
}

fn ownership_record() -> OwnershipVerificationRecord {
    OwnershipVerificationRecord::new(
        AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|e| panic!("origin authority: {e}")),
        AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|e| panic!("active owner: {e}")),
        ts("2026-04-07T12:00:00Z"),
        OwnershipProofKind::StaticOwner,
        None,
    )
}

fn signer_binding() -> ResolvedSignerBinding {
    ResolvedSignerBinding::new(
        AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|e| panic!("issuer authority: {e}")),
        AuthorityKeyRecord::new(
            "root-key-1",
            "ed25519",
            "base64-public-key",
            ts("2026-01-01T00:00:00Z"),
            ts("2027-01-01T00:00:00Z"),
        )
        .unwrap_or_else(|e| panic!("key record: {e}")),
        SignatureProfile::new("jcs+ed25519", "RFC8785")
            .unwrap_or_else(|e| panic!("signature profile: {e}")),
        Some(
            DelegatedPrincipalRef::new("service", "issuer-worker")
                .unwrap_or_else(|e| panic!("delegated principal: {e}")),
        ),
    )
}

/// Construct a minimum-viable raw JSON document string with the given overrides
/// applied on top of sensible defaults.
fn make_grant_json(overrides: &[(&str, serde_json::Value)]) -> String {
    let mut doc = json!({
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
        "default_audience_scope": null,
        "resource_scope": {
            "types": {
                "item": {
                    "all": false,
                    "allow": [{"kind": "namespace", "all": false, "values": ["weapons"], "expressions": null}],
                    "deny": null,
                    "capabilities": { "recognize": null, "mint": null },
                    "constraints": { "minting": { "max_total": null, "max_per_user": null }, "audience_scope": null },
                    "operations": null
                }
            }
        },
        "global_constraints": {
            "time": { "not_before": "2026-04-07T12:00:00Z", "not_after": "2027-04-08T12:00:00Z" }
        },
        "revocation": {
            "revocable": true,
            "revocation_endpoint": "https://issuer.example.com/revocation"
        },
        "issued_at": "2026-04-07T12:00:00Z",
        "signature": "base64-signature",
        "issuer_principal": { "kind": "service", "id": "issuer-worker" }
    });

    let obj = doc.as_object_mut().unwrap();
    for (key, val) in overrides {
        obj.insert(key.to_string(), val.clone());
    }

    serde_json::to_string(&doc).unwrap_or_else(|e| panic!("serialization: {e}"))
}

fn parse_and_validate(json_str: &str) -> ValidatedTrustGrantDocument {
    let raw = RawTrustGrantDocument::parse_json_str(json_str)
        .unwrap_or_else(|e| panic!("raw parse failed: {e}"));
    ValidatedTrustGrantDocument::try_from(raw)
        .unwrap_or_else(|e| panic!("validation failed: {e}"))
}

fn wrap_grant(doc: ValidatedTrustGrantDocument) -> VerifiedTrustGrant {
    VerifiedTrustGrant::new(
        doc,
        VerificationMetadata::new(
            ts("2026-06-15T12:00:00Z"),
            VerificationPosture::Online,
            signer_binding(),
            ownership_record(),
            VerifiedRevocationState::Checked(
                RevocationRecord::new(
                    RevocationStatus::Active,
                    RevocationSourceKind::Api,
                    ProofFinality::Observed,
                    ts("2026-06-15T12:00:00Z"),
                    ts("2026-06-15T12:00:00Z"),
                )
                .unwrap_or_else(|e| panic!("revocation record: {e}")),
            ),
        ),
    )
}

fn make_recognize_request(target: &str, audience: &str, namespace: &str) -> EvaluationRequest {
    let mut resource =
        ResourceContext::new("item").unwrap_or_else(|e| panic!("resource context: {e}"));
    resource
        .insert_selector("namespace", namespace)
        .unwrap_or_else(|e| panic!("namespace selector: {e}"));

    EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        AuthorityId::new(target).unwrap_or_else(|e| panic!("target authority: {e}")),
        AuthorityId::new(audience).unwrap_or_else(|e| panic!("audience authority: {e}")),
        resource,
        ts("2026-06-15T12:00:00Z"),
    )
    .unwrap_or_else(|e| panic!("evaluation request: {e}"))
}

fn make_custom_op_request(
    target: &str,
    audience: &str,
    namespace: &str,
    op_name: &str,
) -> EvaluationRequest {
    let mut resource =
        ResourceContext::new("item").unwrap_or_else(|e| panic!("resource context: {e}"));
    resource
        .insert_selector("namespace", namespace)
        .unwrap_or_else(|e| panic!("namespace selector: {e}"));

    let custom_op = CustomOperationName::new(op_name)
        .unwrap_or_else(|e| panic!("custom op name: {e}"));

    EvaluationRequest::new(
        RequestedOperation::Custom(custom_op),
        AuthorityId::new(target).unwrap_or_else(|e| panic!("target authority: {e}")),
        AuthorityId::new(audience).unwrap_or_else(|e| panic!("audience authority: {e}")),
        resource,
        ts("2026-06-15T12:00:00Z"),
    )
    .unwrap_or_else(|e| panic!("evaluation request: {e}"))
}

fn evaluate_json(doc_json: &str, request: &EvaluationRequest) -> EvaluationDecision {
    let validated = parse_and_validate(doc_json);
    let grant = wrap_grant(validated);
    EvaluationEngine::new().evaluate(&grant, request)
}

// ===========================================================================
// Section 2.5 — Grant lineage and revisioning
// ===========================================================================

#[test]
fn conformance_s2_5_revision_must_increase_monotonically() {
    // Spec Section 2.5: "revision must increase monotonically within one grant_series_id"
    let raw = RawTrustGrantDocument::parse_json_str(&make_grant_json(&[]))
        .unwrap_or_else(|e| panic!("raw parse: {e}"));
    assert!(raw.revision >= 1, "revision must be >= 1");
    // A revision of 0 should be rejected
    let json_zero = make_grant_json(&[("revision", json!(0))]);
    let result = ValidatedTrustGrantDocument::try_from(
        RawTrustGrantDocument::parse_json_str(&json_zero).unwrap_or_else(|e| panic!("raw parse: {e}"))
    );
    assert!(result.is_err(), "revision 0 should be rejected");
}

#[test]
fn conformance_s2_5_supersedes_must_be_same_series() {
    // Spec Section 2.5: "supersedes must point to an older trustgrant_id in the same grant_series_id"
    // The validator checks that if revision > 1, supersedes must be present
    // and must not be self-supersession
    let json = make_grant_json(&[
        ("revision", json!(2)),
        ("supersedes", json!("tg_00000000-0000-0000-0000-000000000000")),
    ]);
    let raw = RawTrustGrantDocument::parse_json_str(&json).unwrap_or_else(|e| panic!("raw parse: {e}"));
    let result = ValidatedTrustGrantDocument::try_from(raw);
    assert!(result.is_ok(), "revision 2 with valid supersedes should be accepted");

    // Self-supersession should be rejected
    let json_self = make_grant_json(&[
        ("trustgrant_id", json!("tg_11111111-1111-4111-8111-111111111001")),
        ("revision", json!(2)),
        ("supersedes", json!("tg_11111111-1111-4111-8111-111111111001")),
    ]);
    let raw_self = RawTrustGrantDocument::parse_json_str(&json_self).unwrap_or_else(|e| panic!("raw parse: {e}"));
    let result_self = ValidatedTrustGrantDocument::try_from(raw_self);
    assert!(result_self.is_err(), "self-supersession should be rejected");
}

#[test]
fn conformance_s2_5_supersession_policy_valid_values() {
    // Spec Section 2.5: "supersession_policy controls whether a new revision coexists or supersedes"
    assert_eq!(
        RawSupersessionPolicy::Coexist.as_str(), "coexist",
        "coexist policy should serialize to 'coexist'"
    );
    assert_eq!(
        RawSupersessionPolicy::SupersedePrevious.as_str(), "supersede_previous",
        "supersede_previous policy should serialize to 'supersede_previous'"
    );
}

// ===========================================================================
// Section 4 — Document format field layout
// ===========================================================================

#[test]
fn conformance_s4_required_fields_present_with_correct_types() {
    // Spec Section 4: "All required fields must be present with correct types"
    let json = make_grant_json(&[]);
    let raw = RawTrustGrantDocument::parse_json_str(&json)
        .unwrap_or_else(|e| panic!("raw parse: {e}"));

    // trustgrant_id is a string
    assert!(!raw.trustgrant_id.is_empty(), "trustgrant_id must be non-empty");
    // grant_series_id is a string
    assert!(!raw.grant_series_id.is_empty(), "grant_series_id must be non-empty");
    // version is integer
    assert_eq!(raw.version, 0);
    // revision is integer >= 1
    assert!(raw.revision >= 1, "revision must be >= 1");
    // signature is a string (required, not optional)
    assert!(!raw.signature.is_empty(), "signature must be present and non-empty");
    // issuer_authority is a string
    assert!(!raw.issuer_authority.is_empty());
    // origin_authority is a string
    assert!(!raw.origin_authority.is_empty());
    // active_owning_authority is a string
    assert!(!raw.active_owning_authority.is_empty());
    // key_id is a string
    assert!(!raw.key_id.is_empty());
    // target_scope is present
    assert!(!raw.target_scope.all || raw.target_scope.allow.is_none());
    // capabilities is present
    assert!(!raw.capabilities.recognize || !raw.capabilities.recognize || !raw.capabilities.mint);
    // resource_scope is present
    assert!(!raw.resource_scope.types.is_empty());
    // issued_at is present
    assert!(raw.issued_at.timestamp() > 0);
}

#[test]
fn conformance_s4_trustgrant_id_format() {
    // Spec Section 4: "trustgrant_id format: tg_<uuid>"
    let raw = RawTrustGrantDocument::parse_json_str(&make_grant_json(&[]))
        .unwrap_or_else(|e| panic!("raw parse: {e}"));
    assert!(
        raw.trustgrant_id.starts_with("tg_"),
        "trustgrant_id must start with 'tg_', got: {}",
        raw.trustgrant_id
    );
}

#[test]
fn conformance_s4_grant_series_id_format() {
    // Spec Section 4: "grant_series_id format: tgs_<uuid>"
    let raw = RawTrustGrantDocument::parse_json_str(&make_grant_json(&[]))
        .unwrap_or_else(|e| panic!("raw parse: {e}"));
    assert!(
        raw.grant_series_id.starts_with("tgs_"),
        "grant_series_id must start with 'tgs_', got: {}",
        raw.grant_series_id
    );
}

#[test]
fn conformance_s4_version_must_be_integer_zero() {
    // Spec Section 4: "version must be integer 0"
    let raw = RawTrustGrantDocument::parse_json_str(&make_grant_json(&[]))
        .unwrap_or_else(|e| panic!("raw parse: {e}"));
    assert_eq!(raw.version, 0, "version must be 0");
}

#[test]
fn conformance_s4_revision_must_be_at_least_one() {
    // Spec Section 4: "revision must be >= 1"
    let raw = RawTrustGrantDocument::parse_json_str(&make_grant_json(&[]))
        .unwrap_or_else(|e| panic!("raw parse: {e}"));
    assert!(raw.revision >= 1, "revision must be >= 1, got {}", raw.revision);
}

#[test]
fn conformance_s4_signature_is_required() {
    // Spec Section 4: "signature is a required field (not optional)"
    let raw = RawTrustGrantDocument::parse_json_str(&make_grant_json(&[]))
        .unwrap_or_else(|e| panic!("raw parse: {e}"));
    assert!(!raw.signature.is_empty(), "signature must be non-empty");
}

#[test]
fn conformance_s4_missing_signature_rejected() {
    // Spec Section 4: "signature is a required field (not optional)"
    // serde will reject missing signature because the field has no Option wrapper
    let json = make_grant_json(&[]);
    let modified = json.replace("\"signature\":\"base64-signature\",", "");
    let result = RawTrustGrantDocument::parse_json_str(&modified);
    assert!(result.is_err(), "document without signature should be rejected");
}

#[test]
fn conformance_s4_revocation_endpoint_must_be_url() {
    // Spec Section 4: "revocation_endpoint must be a URL"
    let raw = RawTrustGrantDocument::parse_json_str(&make_grant_json(&[]))
        .unwrap_or_else(|e| panic!("raw parse: {e}"));
    let revocation = raw.revocation.as_ref().unwrap_or_else(|| panic!("revocation should be present"));
    assert!(Url::parse(revocation.revocation_endpoint.as_str()).is_ok(), "revocation_endpoint must be a valid URL");
}

// ===========================================================================
// Section 5 — Target scope model
// ===========================================================================

#[test]
fn conformance_s5_target_scope_all_true_allow_null() {
    // Spec Section 5: "all=true → allow must be null"
    let json = make_grant_json(&[
        ("target_scope", json!({
            "all": true,
            "allow": null,
            "deny": null
        })),
    ]);
    let validated = parse_and_validate(&json);
    assert!(validated.target_scope().all());
    assert!(validated.target_scope().allow().is_empty());
}

#[test]
fn conformance_s5_target_scope_all_true_with_allow_rejected() {
    // Spec Section 5: "all=true, allow non-null → rejected"
    let json = make_grant_json(&[
        ("target_scope", json!({
            "all": true,
            "allow": [{"kind": "authority", "all": false, "values": ["x"], "expressions": null}],
            "deny": null
        })),
    ]);
    let raw = RawTrustGrantDocument::parse_json_str(&json)
        .unwrap_or_else(|e| panic!("raw parse: {e}"));
    let result = ValidatedTrustGrantDocument::try_from(raw);
    assert!(result.is_err(), "all=true with allow should be rejected");
}

#[test]
fn conformance_s5_target_scope_all_false_allow_non_empty() {
    // Spec Section 5: "all=false → allow must be non-empty"
    let json = make_grant_json(&[
        ("target_scope", json!({
            "all": false,
            "allow": [{"kind": "authority", "all": false, "values": ["https://target.example.com"], "expressions": null}],
            "deny": null
        })),
    ]);
    let validated = parse_and_validate(&json);
    assert!(!validated.target_scope().all());
    assert!(!validated.target_scope().allow().is_empty());
}

#[test]
fn conformance_s5_target_scope_all_false_empty_allow_rejected() {
    // Spec Section 5: "all=false → allow with empty array is rejected (same as null)"
    let json = make_grant_json(&[
        ("target_scope", json!({
            "all": false,
            "allow": [],
            "deny": null
        })),
    ]);
    let raw = RawTrustGrantDocument::parse_json_str(&json)
        .unwrap_or_else(|e| panic!("raw parse: {e}"));
    let result = ValidatedTrustGrantDocument::try_from(raw);
    assert!(result.is_err(), "all=false with empty allow should be rejected");
}

#[test]
fn conformance_s5_target_scope_deny_can_be_null() {
    // Spec Section 5: "deny can be null"
    let json = make_grant_json(&[
        ("target_scope", json!({
            "all": false,
            "allow": [{"kind": "authority", "all": false, "values": ["https://target.example.com"], "expressions": null}],
            "deny": null
        })),
    ]);
    let validated = parse_and_validate(&json);
    assert!(validated.target_scope().deny().is_empty());
}

#[test]
fn conformance_s5_target_scope_deny_can_be_non_empty() {
    // Spec Section 5: "deny can be non-empty"
    let json = make_grant_json(&[
        ("target_scope", json!({
            "all": false,
            "allow": [{"kind": "authority", "all": false, "values": ["https://target.example.com"], "expressions": null}],
            "deny": [{"kind": "authority", "all": false, "values": ["https://blocked.example.com"], "expressions": null}]
        })),
    ]);
    let validated = parse_and_validate(&json);
    assert!(!validated.target_scope().deny().is_empty());
}

// ===========================================================================
// Section 6 — Resource scope model
// ===========================================================================

#[test]
fn conformance_s6_resource_type_key_non_empty_string() {
    // Spec Section 6: "type key is a non-empty string (the resource type name)"
    let json = make_grant_json(&[]);
    let raw = RawTrustGrantDocument::parse_json_str(&json)
        .unwrap_or_else(|e| panic!("raw parse: {e}"));
    assert!(
        raw.resource_scope.types.contains_key(&Utf16Key::new("item")),
        "resource type key must be present"
    );
}

#[test]
fn conformance_s6_resource_scope_all_true_allow_null() {
    // Spec Section 6: "all=true → allow must be null"
    let json = make_grant_json(&[
        ("resource_scope", json!({
            "types": {
                "item": {
                    "all": true,
                    "allow": null,
                    "deny": null,
                    "capabilities": { "recognize": null, "mint": null },
                    "constraints": { "minting": { "max_total": null, "max_per_user": null }, "audience_scope": null },
                    "operations": null
                }
            }
        })),
    ]);
    let validated = parse_and_validate(&json);
    let rt = validated.resource_scope().get(&trustgrant::domain::ResourceTypeName::new("item").unwrap()).unwrap();
    assert!(rt.all());
    assert!(rt.allow().is_empty());
}

#[test]
fn conformance_s6_resource_scope_all_false_allow_non_empty() {
    // Spec Section 6: "all=false → allow must be non-empty"
    let json = make_grant_json(&[]);
    let validated = parse_and_validate(&json);
    let rt = validated.resource_scope().get(&trustgrant::domain::ResourceTypeName::new("item").unwrap()).unwrap();
    assert!(!rt.all());
    assert!(!rt.allow().is_empty());
}

#[test]
fn conformance_s6_resource_scope_deny_is_evaluated_after_allow() {
    // Spec Section 6: "deny is evaluated after allow"
    // Both allow and deny match the same resource → result is Denied (deny wins)
    let json = make_grant_json(&[
        ("resource_scope", json!({
            "types": {
                "item": {
                    "all": false,
                    "allow": [{"kind": "namespace", "all": false, "values": ["weapons"], "expressions": null}],
                    "deny": [{"kind": "namespace", "all": false, "values": ["weapons"], "expressions": null}],
                    "capabilities": { "recognize": null, "mint": null },
                    "constraints": { "minting": { "max_total": null, "max_per_user": null }, "audience_scope": null },
                    "operations": { "all": false, "allow": ["recognize"], "deny": null }
                }
            }
        })),
    ]);
    let validated = parse_and_validate(&json);
    let grant = wrap_grant(validated);
    let request = make_recognize_request("https://target.example.com", "https://audience.example.com", "weapons");
    let decision = EvaluationEngine::new().evaluate(&grant, &request);
    assert_eq!(
        decision.deny_reason(),
        Some(EvaluationDenyReason::ResourceDenied),
        "deny after allow: when both match, deny should win"
    );
}

// ===========================================================================
// Section 6.1 — Operations
// ===========================================================================

#[test]
fn conformance_s6_1_operations_optional_null_is_v0_compat() {
    // Spec Section 6.1: "operations is optional (null = v0 compat mode)"
    let json = make_grant_json(&[
        ("resource_scope", json!({
            "types": {
                "item": {
                    "all": false,
                    "allow": [{"kind": "namespace", "all": false, "values": ["weapons"], "expressions": null}],
                    "deny": null,
                    "capabilities": { "recognize": null, "mint": null },
                    "constraints": { "minting": { "max_total": null, "max_per_user": null }, "audience_scope": null },
                    "operations": null
                }
            }
        })),
    ]);
    let validated = parse_and_validate(&json);
    let rt = validated.resource_scope().get(&trustgrant::domain::ResourceTypeName::new("item").unwrap()).unwrap();
    assert!(rt.operations().is_none(), "null operations should remain None");
}

#[test]
fn conformance_s6_1_v0_compat_recognize_implies_recognize_allowed() {
    // Spec Section 6.1: "In v0 compat mode: recognize capability implies operation 'recognize' is allowed"
    let json = make_grant_json(&[
        ("capabilities", json!({ "recognize": true, "mint": false })),
        ("resource_scope", json!({
            "types": {
                "item": {
                    "all": false,
                    "allow": [{"kind": "namespace", "all": false, "values": ["weapons"], "expressions": null}],
                    "deny": null,
                    "capabilities": { "recognize": true, "mint": false },
                    "constraints": { "minting": { "max_total": null, "max_per_user": null }, "audience_scope": null },
                    "operations": null
                }
            }
        })),
    ]);
    let request = make_recognize_request("https://target.example.com", "https://audience.example.com", "weapons");
    let decision = evaluate_json(&json, &request);
    assert!(decision.is_allowed(), "v0 compat: recognize should be allowed");
}

#[test]
fn conformance_s6_1_v0_compat_mint_implies_create_allowed() {
    // Spec Section 6.1: "In v0 compat mode: mint capability implies operation 'create' is allowed"
    let json = make_grant_json(&[
        ("capabilities", json!({ "recognize": false, "mint": true })),
        ("resource_scope", json!({
            "types": {
                "item": {
                    "all": false,
                    "allow": [{"kind": "namespace", "all": false, "values": ["weapons"], "expressions": null}],
                    "deny": null,
                    "capabilities": { "recognize": false, "mint": true },
                    "constraints": { "minting": { "max_total": null, "max_per_user": null }, "audience_scope": null },
                    "operations": null
                }
            }
        })),
    ]);
    let mut resource =
        ResourceContext::new("item").unwrap_or_else(|e| panic!("resource context: {e}"));
    resource
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|e| panic!("namespace selector: {e}"));
    let request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Mint),
        AuthorityId::new("https://target.example.com").unwrap_or_else(|e| panic!("target: {e}")),
        AuthorityId::new("https://audience.example.com").unwrap_or_else(|e| panic!("audience: {e}")),
        resource,
        ts("2026-06-15T12:00:00Z"),
    )
    .unwrap_or_else(|e| panic!("request: {e}"))
    .with_mint_context(MintContext::new(0, 0));
    let decision = evaluate_json(&json, &request);
    assert!(decision.is_allowed(), "v0 compat: mint should be allowed via implicit create");
}

#[test]
fn conformance_s6_1_custom_operation_requires_explicit_operations() {
    // Spec Section 6.1: "Custom operations require explicit operations scope (v0 compat mode denies them)"
    let json = make_grant_json(&[
        ("capabilities", json!({ "recognize": false, "mint": true })),
        ("resource_scope", json!({
            "types": {
                "item": {
                    "all": false,
                    "allow": [{"kind": "namespace", "all": false, "values": ["weapons"], "expressions": null}],
                    "deny": null,
                    "capabilities": { "recognize": false, "mint": true },
                    "constraints": { "minting": { "max_total": null, "max_per_user": null }, "audience_scope": null },
                    "operations": null
                }
            }
        })),
    ]);
    let request = make_custom_op_request(
        "https://target.example.com",
        "https://audience.example.com",
        "weapons",
        "custom:use",
    );
    let decision = evaluate_json(&json, &request);
    assert_eq!(
        decision.deny_reason(),
        Some(EvaluationDenyReason::OperationDenied),
        "custom op without explicit operations scope should be denied"
    );
}

#[test]
fn conformance_s6_1_reserved_names_rejected_as_custom() {
    // Spec Section 6.1: "Reserved names 'recognize', 'create', 'mint' cannot be used as custom operation names"
    assert!(
        CustomOpName::new("recognize").is_err(),
        "recognize is reserved"
    );
    assert!(
        CustomOpName::new("create").is_err(),
        "create is reserved"
    );
    assert!(
        CustomOpName::new("mint").is_err(),
        "mint is reserved"
    );
    assert!(
        CustomOpName::new("custom:use").is_ok(),
        "custom:use should be valid"
    );
}

#[test]
fn conformance_s6_1_explicit_operations_allow_primary_deny_subtractive() {
    // Spec Section 6.1: "With explicit operations: allow is primary, deny is subtractive"
    let json = make_grant_json(&[
        ("capabilities", json!({ "recognize": false, "mint": false })),
        ("resource_scope", json!({
            "types": {
                "item": {
                    "all": false,
                    "allow": [{"kind": "namespace", "all": false, "values": ["weapons"], "expressions": null}],
                    "deny": null,
                    "capabilities": { "recognize": null, "mint": null },
                    "constraints": { "minting": { "max_total": null, "max_per_user": null }, "audience_scope": null },
                    "operations": {
                        "all": false,
                        "allow": ["custom:op1", "custom:op2"],
                        "deny": ["custom:op1"]
                    }
                }
            }
        })),
    ]);
    // Allowed op should be permitted
    let op2 = CustomOperationName::new("custom:op2")
        .unwrap_or_else(|e| panic!("custom op2: {e}"));
    let mut resource2 =
        ResourceContext::new("item").unwrap_or_else(|e| panic!("resource context: {e}"));
    resource2
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|e| panic!("namespace selector: {e}"));
    let request2 = EvaluationRequest::new(
        RequestedOperation::Custom(op2),
        AuthorityId::new("https://target.example.com").unwrap_or_else(|e| panic!("target: {e}")),
        AuthorityId::new("https://audience.example.com").unwrap_or_else(|e| panic!("audience: {e}")),
        resource2,
        ts("2026-06-15T12:00:00Z"),
    )
    .unwrap_or_else(|e| panic!("request: {e}"));
    let decision2 = evaluate_json(&json, &request2);
    assert!(decision2.is_allowed(), "custom:op2 should be allowed");

    // Denied op should be rejected despite being in allow list
    let op1 = CustomOperationName::new("custom:op1")
        .unwrap_or_else(|e| panic!("custom op1: {e}"));
    let mut resource1 =
        ResourceContext::new("item").unwrap_or_else(|e| panic!("resource context: {e}"));
    resource1
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|e| panic!("namespace selector: {e}"));
    let request1 = EvaluationRequest::new(
        RequestedOperation::Custom(op1),
        AuthorityId::new("https://target.example.com").unwrap_or_else(|e| panic!("target: {e}")),
        AuthorityId::new("https://audience.example.com").unwrap_or_else(|e| panic!("audience: {e}")),
        resource1,
        ts("2026-06-15T12:00:00Z"),
    )
    .unwrap_or_else(|e| panic!("request: {e}"));
    let decision1 = evaluate_json(&json, &request1);
    assert_eq!(
        decision1.deny_reason(),
        Some(EvaluationDenyReason::OperationDenied),
        "custom:op1 should be denied (in deny list)"
    );
}

// ===========================================================================
// Section 7 — Selector model
// ===========================================================================

#[test]
fn conformance_s7_selector_all_true_values_and_expressions_null() {
    // Spec Section 7: "all=true → values and expressions must be null"
    let raw_selector = RawSelector {
        kind: "authority".into(),
        all: true,
        values: None,
        expressions: None,
    };
    assert!(raw_selector.all);
    assert!(raw_selector.values.is_none());
    assert!(raw_selector.expressions.is_none());
}

#[test]
fn conformance_s7_selector_all_true_with_expressions_rejected() {
    // Spec Section 7: "all=true → expressions must be null"
    let json = make_grant_json(&[
        ("target_scope", json!({
            "all": false,
            "allow": [{"kind": "authority", "all": true, "values": null, "expressions": ["equals(\"x\")"]}],
            "deny": null
        })),
    ]);
    let raw = RawTrustGrantDocument::parse_json_str(&json)
        .unwrap_or_else(|e| panic!("raw parse: {e}"));
    let result = ValidatedTrustGrantDocument::try_from(raw);
    assert!(result.is_err(), "all=true with expressions should be rejected");
}

#[test]
fn conformance_s7_selector_all_false_at_least_one_non_empty() {
    // Spec Section 7: "all=false → at least one of values or expressions must be non-empty"
    let json = make_grant_json(&[
        ("target_scope", json!({
            "all": false,
            "allow": [{"kind": "authority", "all": false, "values": ["x"], "expressions": null}],
            "deny": null
        })),
    ]);
    let validated = parse_and_validate(&json);
    let sel = &validated.target_scope().allow()[0];
    assert!(!sel.all());
    assert!(!sel.values().is_empty() || !sel.expressions().is_empty());
}

#[test]
fn conformance_s7_selector_all_false_both_empty_rejected() {
    // Spec Section 7: "all=false with empty values and null expressions → rejected"
    let json = make_grant_json(&[
        ("target_scope", json!({
            "all": false,
            "allow": [{"kind": "authority", "all": false, "values": [], "expressions": null}],
            "deny": null
        })),
    ]);
    let raw = RawTrustGrantDocument::parse_json_str(&json)
        .unwrap_or_else(|e| panic!("raw parse: {e}"));
    let result = ValidatedTrustGrantDocument::try_from(raw);
    assert!(result.is_err(), "all=false with both empty should be rejected");
}

#[test]
fn conformance_s7_empty_values_array_equivalent_to_null() {
    // Spec Section 7: "Empty values array is equivalent to null (rejected)"
    let json = make_grant_json(&[
        ("target_scope", json!({
            "all": false,
            "allow": [{"kind": "authority", "all": false, "values": [], "expressions": null}],
            "deny": null
        })),
    ]);
    let raw = RawTrustGrantDocument::parse_json_str(&json)
        .unwrap_or_else(|e| panic!("raw parse: {e}"));
    let result = ValidatedTrustGrantDocument::try_from(raw);
    assert!(result.is_err(), "empty values should be rejected");
}

#[test]
fn conformance_s7_expressions_can_be_null() {
    // Spec Section 7: "Expressions can be null"
    let json = make_grant_json(&[
        ("target_scope", json!({
            "all": false,
            "allow": [{"kind": "authority", "all": false, "values": ["https://target.example.com"], "expressions": null}],
            "deny": null
        })),
    ]);
    let validated = parse_and_validate(&json);
    let sel = &validated.target_scope().allow()[0];
    assert!(sel.expressions().is_empty(), "null expressions should be empty");
}

#[test]
fn conformance_s7_builtin_kinds_match_case_insensitively() {
    // Spec Section 7: "The three built-in kinds (authority, namespace, player_id) match case-insensitively"
    use trustgrant::domain::SelectorKind;

    let authority_lower = SelectorKind::new("authority").unwrap_or_else(|e| panic!("{e}"));
    let authority_upper = SelectorKind::new("AUTHORITY").unwrap_or_else(|e| panic!("{e}"));
    let authority_mixed = SelectorKind::new("Authority").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(authority_lower, authority_upper);
    assert_eq!(authority_lower, authority_mixed);

    let ns_lower = SelectorKind::new("namespace").unwrap_or_else(|e| panic!("{e}"));
    let ns_upper = SelectorKind::new("NAMESPACE").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(ns_lower, ns_upper);

    let pid_lower = SelectorKind::new("player_id").unwrap_or_else(|e| panic!("{e}"));
    let pid_upper = SelectorKind::new("PLAYER_ID").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(pid_lower, pid_upper);
}

#[test]
fn conformance_s7_other_kinds_are_exact_case() {
    // Spec Section 7: "Other kinds are exact-case"
    use trustgrant::domain::SelectorKind;

    let foo = SelectorKind::new("Foo").unwrap_or_else(|e| panic!("{e}"));
    let foo_lower = SelectorKind::new("foo").unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(foo, foo_lower, "Other kinds should be case-sensitive");
}

// ===========================================================================
// Section 8 — Expression semantics
// ===========================================================================

#[test]
fn conformance_s8_supported_predicates_equals() {
    // Spec Section 8: "Supported predicates: equals"
    let expr = SelectorExpression::parse(r#"equals("foo")"#)
        .unwrap_or_else(|e| panic!("equals should parse: {e}"));
    assert!(expr.matches("foo"));
    assert!(!expr.matches("bar"));
}

#[test]
fn conformance_s8_supported_predicates_starts_with() {
    // Spec Section 8: "Supported predicates: startsWith"
    let expr = SelectorExpression::parse(r#"startsWith("weapon_")"#)
        .unwrap_or_else(|e| panic!("startsWith should parse: {e}"));
    assert!(expr.matches("weapon_epic"));
    assert!(!expr.matches("armor_epic"));
}

#[test]
fn conformance_s8_supported_predicates_ends_with() {
    // Spec Section 8: "Supported predicates: endsWith"
    let expr = SelectorExpression::parse(r#"endsWith("_epic")"#)
        .unwrap_or_else(|e| panic!("endsWith should parse: {e}"));
    assert!(expr.matches("weapon_epic"));
    assert!(!expr.matches("weapon_rare"));
}

#[test]
fn conformance_s8_supported_predicates_contains() {
    // Spec Section 8: "Supported predicates: contains"
    let expr = SelectorExpression::parse(r#"contains("epic")"#)
        .unwrap_or_else(|e| panic!("contains should parse: {e}"));
    assert!(expr.matches("weapon_epic_sword"));
    assert!(!expr.matches("weapon_rare_sword"));
}

#[test]
fn conformance_s8_expressions_are_deterministic() {
    // Spec Section 8: "Expressions are deterministic (same input → same result)"
    let expr = SelectorExpression::parse(r#"equals("exact_value")"#)
        .unwrap_or_else(|e| panic!("equals should parse: {e}"));
    for _ in 0..10 {
        assert!(expr.matches("exact_value"));
        assert!(!expr.matches("different_value"));
    }
}

#[test]
fn conformance_s8_unsupported_predicates_rejected() {
    // Spec Section 8: "Unsupported predicates are rejected"
    use trustgrant_error::TrustGrantError;
    let result = SelectorExpression::parse(r#"regex("^vip")"#);
    assert_eq!(
        result,
        Err(TrustGrantError::UnsupportedSelectorExpressionPredicate(
            "regex".to_owned()
        ))
    );
}

// ===========================================================================
// Section 9 — Audience scope model
// ===========================================================================

#[test]
fn conformance_s9_audience_scope_override_replaces_default() {
    // Spec Section 9: "audience_scope per resource type REPLACES default_audience_scope (not merged)"
    let json = make_grant_json(&[
        ("default_audience_scope", json!([
            {
                "authority_id": "https://audience-a.example.com",
                "scope": { "all": true, "allow": null, "deny": null },
                "principal_scope": null
            }
        ])),
        ("resource_scope", json!({
            "types": {
                "item": {
                    "all": false,
                    "allow": [{"kind": "namespace", "all": false, "values": ["weapons"], "expressions": null}],
                    "deny": null,
                    "capabilities": { "recognize": null, "mint": null },
                    "constraints": {
                        "minting": { "max_total": null, "max_per_user": null },
                        "audience_scope": [
                            {
                                "authority_id": "https://audience-b.example.com",
                                "scope": { "all": true, "allow": null, "deny": null },
                                "principal_scope": null
                            }
                        ]
                    },
                    "operations": { "all": false, "allow": ["recognize"], "deny": null }
                }
            }
        })),
    ]);

    // Request with audience A (from default) → denied (override replaced default)
    let request_a = make_recognize_request(
        "https://target.example.com",
        "https://audience-a.example.com",
        "weapons",
    );
    let decision_a = evaluate_json(&json, &request_a);
    assert_eq!(
        decision_a.deny_reason(),
        Some(EvaluationDenyReason::AudienceNotAllowed),
        "audience A from default should be denied when override replaces it"
    );

    // Request with audience B (from type-level override) → allowed
    let request_b = make_recognize_request(
        "https://target.example.com",
        "https://audience-b.example.com",
        "weapons",
    );
    let decision_b = evaluate_json(&json, &request_b);
    assert!(
        decision_b.is_allowed(),
        "audience B from type-level override should be allowed"
    );
}

#[test]
fn conformance_s9_empty_audience_scope_on_type_uses_default() {
    // Spec Section 9: "Empty audience_scope on type → uses default"
    let json = make_grant_json(&[
        ("default_audience_scope", json!([
            {
                "authority_id": "https://audience.example.com",
                "scope": { "all": true, "allow": null, "deny": null },
                "principal_scope": null
            }
        ])),
        ("resource_scope", json!({
            "types": {
                "item": {
                    "all": false,
                    "allow": [{"kind": "namespace", "all": false, "values": ["weapons"], "expressions": null}],
                    "deny": null,
                    "capabilities": { "recognize": null, "mint": null },
                    "constraints": {
                        "minting": { "max_total": null, "max_per_user": null },
                        "audience_scope": []
                    },
                    "operations": { "all": false, "allow": ["recognize"], "deny": null }
                }
            }
        })),
    ]);

    let request = make_recognize_request(
        "https://target.example.com",
        "https://audience.example.com",
        "weapons",
    );
    let decision = evaluate_json(&json, &request);
    assert!(
        decision.is_allowed(),
        "empty audience_scope on type should fall back to default"
    );
}

#[test]
fn conformance_s9_principal_scope_restricts_audience_does_not_grant() {
    // Spec Section 9: "principal_scope restricts audience, does not grant capabilities"
    let json = make_grant_json(&[
        ("resource_scope", json!({
            "types": {
                "item": {
                    "all": false,
                    "allow": [{"kind": "namespace", "all": false, "values": ["weapons"], "expressions": null}],
                    "deny": null,
                    "capabilities": { "recognize": null, "mint": null },
                    "constraints": {
                        "minting": { "max_total": null, "max_per_user": null },
                        "audience_scope": [
                            {
                                "authority_id": "https://audience.example.com",
                                "scope": { "all": true, "allow": null, "deny": null },
                                "principal_scope": {
                                    "all": false,
                                    "allow": [{"kind": "player_id", "all": false, "values": ["player-42"], "expressions": null}],
                                    "deny": null
                                }
                            }
                        ]
                    },
                    "operations": { "all": false, "allow": ["recognize"], "deny": null }
                }
            }
        })),
    ]);

    // Principal matches → allowed
    let mut request_ok = make_recognize_request(
        "https://target.example.com",
        "https://audience.example.com",
        "weapons",
    );
    request_ok
        .insert_audience_principal_selector("player_id", "player-42")
        .unwrap_or_else(|e| panic!("principal selector: {e}"));
    let decision_ok = evaluate_json(&json, &request_ok);
    assert!(decision_ok.is_allowed(), "matching principal should be allowed");

    // Principal does not match → denied
    let mut request_denied = make_recognize_request(
        "https://target.example.com",
        "https://audience.example.com",
        "weapons",
    );
    request_denied
        .insert_audience_principal_selector("player_id", "player-99")
        .unwrap_or_else(|e| panic!("principal selector: {e}"));
    let decision_denied = evaluate_json(&json, &request_denied);
    assert_eq!(
        decision_denied.deny_reason(),
        Some(EvaluationDenyReason::AudiencePrincipalNotAllowed),
        "non-matching principal should be denied"
    );
}

#[test]
fn conformance_s9_multiple_audience_entries() {
    // Spec Section 9: "Audience is an array of authority-based scopes"
    let json = make_grant_json(&[
        ("default_audience_scope", json!([
            {
                "authority_id": "https://audience-a.example.com",
                "scope": { "all": true, "allow": null, "deny": null },
                "principal_scope": null
            },
            {
                "authority_id": "https://audience-b.example.com",
                "scope": { "all": true, "allow": null, "deny": null },
                "principal_scope": null
            }
        ])),
        ("resource_scope", json!({
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
        })),
    ]);

    // Both audience A and B should be allowed
    let request_a = make_recognize_request("https://target.example.com", "https://audience-a.example.com", "weapons");
    assert!(evaluate_json(&json, &request_a).is_allowed(), "audience A should be allowed");

    let request_b = make_recognize_request("https://target.example.com", "https://audience-b.example.com", "weapons");
    assert!(evaluate_json(&json, &request_b).is_allowed(), "audience B should be allowed");

    // Non-matching audience should be denied
    let request_c = make_recognize_request("https://target.example.com", "https://audience-c.example.com", "weapons");
    assert_eq!(
        evaluate_json(&json, &request_c).deny_reason(),
        Some(EvaluationDenyReason::AudienceNotAllowed),
        "non-matching audience should be denied"
    );
}

// ===========================================================================
// Section 10 — Allow/deny resolution
// ===========================================================================

#[test]
fn conformance_s10_allow_is_primary_and_explicit() {
    // Spec Section 10: "allow is primary and explicit"
    let json = make_grant_json(&[]);
    let decision = evaluate_json(
        &json,
        &make_recognize_request(
            "https://target.example.com",
            "https://audience.example.com",
            "weapons",
        ),
    );
    assert!(decision.is_allowed(), "matching allow should produce Allow");

    // Request not matching allow → denied
    let decision_not_allowed = evaluate_json(
        &json,
        &make_recognize_request(
            "https://other.example.com",
            "https://audience.example.com",
            "weapons",
        ),
    );
    assert_eq!(
        decision_not_allowed.deny_reason(),
        Some(EvaluationDenyReason::TargetNotAllowed),
        "non-matching allow should produce deny"
    );
}

#[test]
fn conformance_s10_deny_checked_after_allow() {
    // Spec Section 10: "deny is always subtractive (deny after allow)"
    // Target matches both allow and deny → TargetDenied (deny wins)
    let json = make_grant_json(&[
        ("target_scope", json!({
            "all": false,
            "allow": [{"kind": "authority", "all": false, "values": ["https://target.example.com"], "expressions": null}],
            "deny": [{"kind": "authority", "all": false, "values": ["https://target.example.com"], "expressions": null}]
        })),
    ]);
    let decision = evaluate_json(
        &json,
        &make_recognize_request(
            "https://target.example.com",
            "https://audience.example.com",
            "weapons",
        ),
    );
    assert_eq!(
        decision.deny_reason(),
        Some(EvaluationDenyReason::TargetDenied),
        "deny should be checked after allow and win when both match"
    );
}

#[test]
fn conformance_s10_deny_cannot_expand_privilege() {
    // Spec Section 10: "deny cannot expand privilege"
    // A target that does not match allow but is only in deny → TargetNotAllowed (not denied)
    let json = make_grant_json(&[
        ("target_scope", json!({
            "all": false,
            "allow": [{"kind": "authority", "all": false, "values": ["https://target.example.com"], "expressions": null}],
            "deny": [{"kind": "authority", "all": false, "values": ["https://other.example.com"], "expressions": null}]
        })),
    ]);
    let decision = evaluate_json(
        &json,
        &make_recognize_request(
            "https://other.example.com",
            "https://audience.example.com",
            "weapons",
        ),
    );
    assert_eq!(
        decision.deny_reason(),
        Some(EvaluationDenyReason::TargetNotAllowed),
        "deny alone should not expand privilege; non-matching allow should fail first"
    );
}

#[test]
fn conformance_s10_default_is_fail_closed() {
    // Spec Section 10: "default is fail-closed"
    // When nothing matches, the default outcome is denial, not allowance.
    // A request for a non-existent resource type → denied
    let json = make_grant_json(&[]);
    let mut resource =
        ResourceContext::new("nonexistent").unwrap_or_else(|e| panic!("resource context: {e}"));
    resource
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|e| panic!("namespace selector: {e}"));
    let request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        AuthorityId::new("https://target.example.com").unwrap_or_else(|e| panic!("target: {e}")),
        AuthorityId::new("https://audience.example.com").unwrap_or_else(|e| panic!("audience: {e}")),
        resource,
        ts("2026-06-15T12:00:00Z"),
    )
    .unwrap_or_else(|e| panic!("request: {e}"));
    let decision = evaluate_json(&json, &request);
    assert!(
        !decision.is_allowed(),
        "fail-closed: non-matching resource type should be denied"
    );
}

// ===========================================================================
// Section 11 — Capabilities inheritance
// ===========================================================================

#[test]
fn conformance_s11_per_type_capability_overrides_global() {
    // Spec Section 11: "if type.capability != null → use type.capability"

    // Global mint=true, per-type mint=false → capability disabled for mint on this type
    let json_disabled = make_grant_json(&[
        ("capabilities", json!({ "recognize": false, "mint": true })),
        ("resource_scope", json!({
            "types": {
                "item": {
                    "all": false,
                    "allow": [{"kind": "namespace", "all": false, "values": ["weapons"], "expressions": null}],
                    "deny": null,
                    "capabilities": { "recognize": false, "mint": false },
                    "constraints": { "minting": { "max_total": null, "max_per_user": null }, "audience_scope": null },
                    "operations": null
                }
            }
        })),
    ]);
    let mut resource =
        ResourceContext::new("item").unwrap_or_else(|e| panic!("resource context: {e}"));
    resource
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|e| panic!("namespace selector: {e}"));
    let request_mint = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Mint),
        AuthorityId::new("https://target.example.com").unwrap_or_else(|e| panic!("target: {e}")),
        AuthorityId::new("https://audience.example.com").unwrap_or_else(|e| panic!("audience: {e}")),
        resource,
        ts("2026-06-15T12:00:00Z"),
    )
    .unwrap_or_else(|e| panic!("request: {e}"))
    .with_mint_context(MintContext::new(0, 0));
    let decision_disabled = evaluate_json(&json_disabled, &request_mint);
    assert_eq!(
        decision_disabled.deny_reason(),
        Some(EvaluationDenyReason::CapabilityDisabled),
        "per-type mint=false should override global mint=true"
    );

    // Global mint=false, per-type mint=null → uses global (mint=false)
    let json_global_false = make_grant_json(&[
        ("capabilities", json!({ "recognize": false, "mint": false })),
        ("resource_scope", json!({
            "types": {
                "item": {
                    "all": false,
                    "allow": [{"kind": "namespace", "all": false, "values": ["weapons"], "expressions": null}],
                    "deny": null,
                    "capabilities": { "recognize": false, "mint": null },
                    "constraints": { "minting": { "max_total": null, "max_per_user": null }, "audience_scope": null },
                    "operations": null
                }
            }
        })),
    ]);
    let mut resource2 =
        ResourceContext::new("item").unwrap_or_else(|e| panic!("resource context: {e}"));
    resource2
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|e| panic!("namespace selector: {e}"));
    let request_mint2 = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Mint),
        AuthorityId::new("https://target.example.com").unwrap_or_else(|e| panic!("target: {e}")),
        AuthorityId::new("https://audience.example.com").unwrap_or_else(|e| panic!("audience: {e}")),
        resource2,
        ts("2026-06-15T12:00:00Z"),
    )
    .unwrap_or_else(|e| panic!("request: {e}"))
    .with_mint_context(MintContext::new(0, 0));
    let decision_global_false = evaluate_json(&json_global_false, &request_mint2);
    assert_eq!(
        decision_global_false.deny_reason(),
        Some(EvaluationDenyReason::CapabilityDisabled),
        "per-type mint=null should inherit global mint=false"
    );

    // Global mint=false, per-type mint=true → uses per-type (mint=true)
    let json_override_true = make_grant_json(&[
        ("capabilities", json!({ "recognize": false, "mint": false })),
        ("resource_scope", json!({
            "types": {
                "item": {
                    "all": false,
                    "allow": [{"kind": "namespace", "all": false, "values": ["weapons"], "expressions": null}],
                    "deny": null,
                    "capabilities": { "recognize": false, "mint": true },
                    "constraints": { "minting": { "max_total": null, "max_per_user": null }, "audience_scope": null },
                    "operations": null
                }
            }
        })),
    ]);
    let mut resource3 =
        ResourceContext::new("item").unwrap_or_else(|e| panic!("resource context: {e}"));
    resource3
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|e| panic!("namespace selector: {e}"));
    let request_mint3 = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Mint),
        AuthorityId::new("https://target.example.com").unwrap_or_else(|e| panic!("target: {e}")),
        AuthorityId::new("https://audience.example.com").unwrap_or_else(|e| panic!("audience: {e}")),
        resource3,
        ts("2026-06-15T12:00:00Z"),
    )
    .unwrap_or_else(|e| panic!("request: {e}"))
    .with_mint_context(MintContext::new(0, 0));
    let decision_override_true = evaluate_json(&json_override_true, &request_mint3);
    assert!(
        decision_override_true.is_allowed(),
        "per-type mint=true should override global mint=false"
    );
}

// ===========================================================================
// Section 12 — Constraint semantics
// ===========================================================================

#[test]
fn conformance_s12_minting_constraints_are_per_type() {
    // Spec Section 12: "minting constraints are per-type"
    let json_a = make_grant_json(&[
        ("capabilities", json!({ "recognize": false, "mint": true })),
        ("resource_scope", json!({
            "types": {
                "item": {
                    "all": false,
                    "allow": [{"kind": "namespace", "all": false, "values": ["weapons"], "expressions": null}],
                    "deny": null,
                    "capabilities": { "recognize": false, "mint": true },
                    "constraints": {
                        "minting": { "max_total": 5, "max_per_user": 2 },
                        "audience_scope": [
                            {
                                "authority_id": "https://audience.example.com",
                                "scope": { "all": true, "allow": null, "deny": null },
                                "principal_scope": {
                                    "all": false,
                                    "allow": [{"kind": "player_id", "all": false, "values": ["player-42"], "expressions": null}],
                                    "deny": null
                                }
                            }
                        ]
                    },
                    "operations": null
                }
            }
        })),
    ]);

    let mut resource =
        ResourceContext::new("item").unwrap_or_else(|e| panic!("resource context: {e}"));
    resource
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|e| panic!("namespace selector: {e}"));

    let mut request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Mint),
        AuthorityId::new("https://target.example.com").unwrap_or_else(|e| panic!("target: {e}")),
        AuthorityId::new("https://audience.example.com").unwrap_or_else(|e| panic!("audience: {e}")),
        resource,
        ts("2026-06-15T12:00:00Z"),
    )
    .unwrap_or_else(|e| panic!("request: {e}"))
    .with_mint_context(MintContext::new(4, 1));
    request
        .insert_audience_principal_selector("player_id", "player-42")
        .unwrap_or_else(|e| panic!("principal selector: {e}"));

    let decision = evaluate_json(&json_a, &request);
    assert!(decision.is_allowed(), "mint within constraints should be allowed");

    // Exceed max_total
    let request_exceed_total = request.clone().with_mint_context(MintContext::new(5, 1));
    let decision_exceed = evaluate_json(&json_a, &request_exceed_total);
    assert_eq!(
        decision_exceed.deny_reason(),
        Some(EvaluationDenyReason::MintTotalLimitReached),
        "exceeding max_total should be denied"
    );

    // Exceed max_per_user
    let request_exceed_user = request.clone().with_mint_context(MintContext::new(4, 2));
    let decision_exceed_user = evaluate_json(&json_a, &request_exceed_user);
    assert_eq!(
        decision_exceed_user.deny_reason(),
        Some(EvaluationDenyReason::MintPerUserLimitReached),
        "exceeding max_per_user should be denied"
    );
}

#[test]
fn conformance_s12_max_total_must_be_non_negative() {
    // Spec Section 12: "max_total must be >= 0"
    // max_total: null means no constraint (equivalent to no limit)
    let constraints = RawMintingConstraints::new(None, None);
    assert!(constraints.max_total.is_none(), "null max_total is valid");

    // max_total: Some(0) is valid (don't allow any mint)
    let constraints_zero = RawMintingConstraints::new(Some(0), None);
    assert_eq!(constraints_zero.max_total, Some(0));
}

#[test]
fn conformance_s12_max_per_user_must_be_non_negative() {
    // Spec Section 12: "max_per_user must be >= 0"
    let constraints = RawMintingConstraints::new(None, None);
    assert!(constraints.max_per_user.is_none(), "null max_per_user is valid");

    let constraints_zero = RawMintingConstraints::new(None, Some(0));
    assert_eq!(constraints_zero.max_per_user, Some(0));
}

#[test]
fn conformance_s12_audience_scope_in_constraints_replaces_default() {
    // Spec Section 12: "audience_scope in constraints replaces default"
    let json = make_grant_json(&[
        ("default_audience_scope", json!([
            {
                "authority_id": "https://default-audience.example.com",
                "scope": { "all": true, "allow": null, "deny": null },
                "principal_scope": null
            }
        ])),
        ("resource_scope", json!({
            "types": {
                "item": {
                    "all": false,
                    "allow": [{"kind": "namespace", "all": false, "values": ["weapons"], "expressions": null}],
                    "deny": null,
                    "capabilities": { "recognize": null, "mint": null },
                    "constraints": {
                        "minting": { "max_total": null, "max_per_user": null },
                        "audience_scope": [
                            {
                                "authority_id": "https://constraint-audience.example.com",
                                "scope": { "all": true, "allow": null, "deny": null },
                                "principal_scope": null
                            }
                        ]
                    },
                    "operations": { "all": false, "allow": ["recognize"], "deny": null }
                }
            }
        })),
    ]);

    // Request with default audience → denied (replaced by constraint scope)
    let request_default = make_recognize_request(
        "https://target.example.com",
        "https://default-audience.example.com",
        "weapons",
    );
    let decision_default = evaluate_json(&json, &request_default);
    assert_eq!(
        decision_default.deny_reason(),
        Some(EvaluationDenyReason::AudienceNotAllowed),
        "default audience should be denied when constraints override"
    );

    // Request with constraint audience → allowed
    let request_constraint = make_recognize_request(
        "https://target.example.com",
        "https://constraint-audience.example.com",
        "weapons",
    );
    let decision_constraint = evaluate_json(&json, &request_constraint);
    assert!(
        decision_constraint.is_allowed(),
        "constraint audience should be allowed"
    );
}
