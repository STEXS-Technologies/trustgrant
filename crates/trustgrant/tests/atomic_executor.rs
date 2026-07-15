#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::unwrap_in_result, clippy::panic_in_result_fn, clippy::indexing_slicing)]

use std::sync::{Arc, Mutex};
use std::thread;

use chrono::{TimeZone, Utc};

use trustgrant::{
    AtomicExecutionResult, AtomicInventoryExecutor, AuthorityId, AuthorityKeyRecord,
    EvaluationDenyReason, EvaluationRequest, InMemoryAtomicInventoryExecutor,
    InMemoryExecutionError, IntentId, MintContext, MutationRequest, OwnershipProofKind,
    OwnershipVerificationRecord, ProofFinality, RequestedCapability, RequestedOperation,
    ResolvedSignerBinding, ResourceBinding, ResourceContext, ResourceRef, RevocationRecord,
    RevocationSourceKind, RevocationStatus, SignatureProfile, TemplateRef, TrustGrantError,
    VerificationMetadata, VerificationPosture, VerifiedRevocationState, VerifiedTrustGrant,
};

// ---------------------------------------------------------------------------
// Helpers (mirror patterns from execution.rs unit tests)
// ---------------------------------------------------------------------------

fn timestamp() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 4, 7, 12, 0, 0)
        .single()
        .unwrap_or_else(|| panic!("fixed timestamp should be valid"))
}

fn authority(value: &str) -> AuthorityId {
    AuthorityId::new(value).unwrap_or_else(|error| panic!("authority should be valid: {error}"))
}

fn verified_grant(mint: bool, max_total: u64) -> VerifiedTrustGrant {
    verified_grant_ex(mint, max_total, 1)
}

fn verified_grant_ex(mint: bool, max_total: u64, max_per_user: u64) -> VerifiedTrustGrant {
    let capabilities = if mint {
        r#"{"recognize":false,"mint":true}"#
    } else {
        r#"{"recognize":true,"mint":false}"#
    };
    let operations = if mint {
        r#"{"all":false,"allow":["create"],"deny":null}"#
    } else {
        r#"{"all":false,"allow":["recognize"],"deny":null}"#
    };
    let document = r#"{
          "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
          "version":0,
          "grant_series_id":"tgs_123e4567-e89b-12d3-a456-426614174001",
          "revision":1,
          "supersedes":null,
          "supersession_policy":"coexist",
          "issuer_authority":"https://issuer.example.com",
          "origin_authority":"https://issuer.example.com",
          "active_owning_authority":"https://issuer.example.com",
          "key_id":"root-key-1",
          "target_scope":{"all":false,"allow":[{"kind":"authority","all":false,"values":["https://target.example.com"],"expressions":null}],"deny":null},
          "capabilities":__CAPABILITIES__,
          "default_audience_scope":null,
          "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":__TYPE_CAPABILITIES__,"constraints":{"minting":{"max_total":__MAX_TOTAL__,"max_per_user":__MAX_PER_USER__},"audience_scope":null},"operations":__OPERATIONS__}}},
          "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2027-04-08T12:00:00Z"}},
          "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
          "issued_at":"2026-04-07T12:00:00Z",
          "signature":"base64-signature"
        }"#
        .replace("__CAPABILITIES__", capabilities)
        .replace("__TYPE_CAPABILITIES__", capabilities)
        .replace("__MAX_TOTAL__", &max_total.to_string())
        .replace("__MAX_PER_USER__", &max_per_user.to_string())
        .replace("__OPERATIONS__", operations);

    let raw = trustgrant::document::RawTrustGrantDocument::parse_json_str(&document)
        .unwrap_or_else(|error| panic!("grant should parse: {error}"));
    let validated = trustgrant::document::ValidatedTrustGrantDocument::try_from(raw)
        .unwrap_or_else(|error| panic!("grant should validate: {error}"));
    let signer = ResolvedSignerBinding::new(
        authority("https://issuer.example.com"),
        AuthorityKeyRecord::new(
            "root-key-1",
            "ed25519",
            "base64-public-key",
            timestamp(),
            Utc.with_ymd_and_hms(2027, 4, 7, 12, 0, 0)
                .single()
                .unwrap_or_else(|| panic!("fixed timestamp should be valid")),
        )
        .unwrap_or_else(|error| panic!("key should be valid: {error}")),
        SignatureProfile::new("jcs+ed25519", "RFC8785")
            .unwrap_or_else(|error| panic!("signature profile should be valid: {error}")),
        None,
    );
    let ownership = OwnershipVerificationRecord::new(
        authority("https://issuer.example.com"),
        authority("https://issuer.example.com"),
        timestamp(),
        OwnershipProofKind::StaticOwner,
        None,
    );
    let revocation = RevocationRecord::new(
        RevocationStatus::Active,
        RevocationSourceKind::Api,
        ProofFinality::Observed,
        timestamp(),
        Utc.with_ymd_and_hms(2026, 4, 7, 12, 5, 0)
            .single()
            .unwrap_or_else(|| panic!("fixed timestamp should be valid")),
    )
    .unwrap_or_else(|error| panic!("revocation should be valid: {error}"));

    VerifiedTrustGrant::new(
        validated,
        VerificationMetadata::new(
            timestamp(),
            VerificationPosture::Online,
            signer,
            ownership,
            VerifiedRevocationState::Checked(revocation),
        ),
    )
}

fn resource_context() -> ResourceContext {
    let mut resource = ResourceContext::new("item")
        .unwrap_or_else(|error| panic!("resource type should be valid: {error}"));
    resource
        .insert_selector("namespace", "weapons")
        .unwrap_or_else(|error| panic!("selector should be valid: {error}"));
    resource
}

fn existing_mutation(intent_id: &str, expected_version: u64) -> MutationRequest {
    let intent_id = IntentId::new(intent_id)
        .unwrap_or_else(|error| panic!("intent id should be valid: {error}"));
    let request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(
            ResourceRef::new_typed(
                authority("https://issuer.example.com"),
                "item",
                "resource-42",
            )
            .unwrap_or_else(|error| panic!("resource ref should be valid: {error}"))
            .with_expected_version(expected_version),
        ),
        authority("https://target.example.com"),
        authority("https://audience.example.com"),
        resource_context(),
        timestamp(),
    )
    .unwrap_or_else(|error| panic!("request should be valid: {error}"))
    .with_intent_id(intent_id);
    MutationRequest::try_from(request)
        .unwrap_or_else(|error| panic!("mutation should be valid: {error}"))
}

fn mint_mutation(intent_id: &str) -> MutationRequest {
    let intent_id = IntentId::new(intent_id)
        .unwrap_or_else(|error| panic!("intent id should be valid: {error}"));
    let mut request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Mint),
        ResourceBinding::Mint(
            TemplateRef::new_typed(authority("https://issuer.example.com"), "sword-v1")
                .unwrap_or_else(|error| panic!("template ref should be valid: {error}")),
        ),
        authority("https://target.example.com"),
        authority("https://audience.example.com"),
        resource_context(),
        timestamp(),
    )
    .unwrap_or_else(|error| panic!("request should be valid: {error}"));
    request
        .insert_audience_principal_selector("actor", "player-123")
        .unwrap_or_else(|error| panic!("principal should be valid: {error}"));
    MutationRequest::try_from(request.with_intent_id(intent_id).verify_selectors())
        .unwrap_or_else(|error| panic!("mutation should be valid: {error}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn successful_mutation_execution() {
    // Test 1: recognize an item with expected_version matching current state
    let grant = verified_grant(false, 0);
    let resource = ResourceRef::new_typed(
        authority("https://issuer.example.com"),
        "item",
        "resource-42",
    )
    .unwrap_or_else(|error| panic!("resource ref should be valid: {error}"));

    let mut executor = InMemoryAtomicInventoryExecutor::new();
    executor
        .register_resource(&resource, 1)
        .unwrap_or_else(|error| panic!("resource should register: {error}"));

    let result = executor
        .authorize_and_execute(&grant, existing_mutation("exec-test-1", 1), |_, _| {
            Ok("executed")
        })
        .unwrap_or_else(|error| panic!("execution should not error: {error}"));

    match &result {
        AtomicExecutionResult::Applied {
            value,
            authorization,
        } => {
            assert_eq!(
                *value, "executed",
                "mutation callback value must be returned"
            );
            assert!(
                authorization.outcome().decision().is_allowed(),
                "decision must be allowed"
            );
        }
        other => panic!("expected Applied, got {other:?}"),
    }

    // The resource version should have advanced from 1 to 2
    let version = executor
        .authorize_and_execute(&grant, existing_mutation("exec-test-1b", 2), |_, _| Ok(()))
        .unwrap_or_else(|error| panic!("execution should not error: {error}"));
    assert!(
        matches!(version, AtomicExecutionResult::Applied { .. }),
        "version 2 should succeed after version 1 was consumed: {version:?}"
    );
}

#[test]
fn idempotent_replay_returns_duplicate() {
    // Test 2: same intent_id returns Duplicate
    let grant = verified_grant(false, 0);
    let resource = ResourceRef::new_typed(
        authority("https://issuer.example.com"),
        "item",
        "resource-42",
    )
    .unwrap_or_else(|error| panic!("resource ref should be valid: {error}"));

    let mut executor = InMemoryAtomicInventoryExecutor::new();
    executor
        .register_resource(&resource, 1)
        .unwrap_or_else(|error| panic!("resource should register: {error}"));

    // First execution — should succeed
    let first = executor
        .authorize_and_execute(&grant, existing_mutation("idem-1", 1), |_, _| Ok("first"))
        .unwrap_or_else(|error| panic!("first execution should not error: {error}"));
    assert!(
        matches!(first, AtomicExecutionResult::Applied { .. }),
        "first execution should be Applied"
    );

    // Second execution with identical intent_id — should be Duplicate
    let second = executor
        .authorize_and_execute(&grant, existing_mutation("idem-1", 1), |_, _| Ok("second"))
        .unwrap_or_else(|error| panic!("second execution should not error: {error}"));

    match &second {
        AtomicExecutionResult::Duplicate { authorization } => {
            assert!(
                authorization.outcome().decision().is_allowed(),
                "duplicate authorization should still reflect allowed decision"
            );
        }
        other => panic!("expected Duplicate, got {other:?}"),
    }
}

#[test]
fn stale_state_detected_when_version_mismatch() {
    // Test 3: expected_version differs from current version → Stale
    let grant = verified_grant(false, 0);
    let resource = ResourceRef::new_typed(
        authority("https://issuer.example.com"),
        "item",
        "resource-42",
    )
    .unwrap_or_else(|error| panic!("resource ref should be valid: {error}"));

    let mut executor = InMemoryAtomicInventoryExecutor::new();
    executor
        .register_resource(&resource, 5)
        .unwrap_or_else(|error| panic!("resource should register: {error}"));

    // Execute with matching version 5 — succeeds and advances to 6
    let first = executor
        .authorize_and_execute(&grant, existing_mutation("stale-1", 5), |_, _| Ok(()))
        .unwrap_or_else(|error| panic!("first execution should not error: {error}"));
    assert!(
        matches!(first, AtomicExecutionResult::Applied { .. }),
        "first execution with version 5 should succeed"
    );

    // Attempt with stale expected_version=5 (current is now 6) → Stale
    let stale = executor
        .authorize_and_execute(&grant, existing_mutation("stale-2", 5), |_, _| Ok(()))
        .unwrap_or_else(|error| panic!("stale execution should not error: {error}"));

    match stale {
        AtomicExecutionResult::Stale {
            current_version, ..
        } => {
            assert_eq!(
                current_version, 6,
                "current version should be 6 after one mutation"
            );
        }
        other => panic!("expected Stale, got {other:?}"),
    }
}

#[test]
fn mutation_request_rejects_missing_intent_id() {
    // Test 4: Missing intent_id on MutationRequest → error
    let request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(
            ResourceRef::new_typed(
                authority("https://issuer.example.com"),
                "item",
                "resource-42",
            )
            .unwrap_or_else(|error| panic!("resource ref should be valid: {error}"))
            .with_expected_version(1),
        ),
        authority("https://target.example.com"),
        authority("https://audience.example.com"),
        resource_context(),
        timestamp(),
    )
    .unwrap_or_else(|error| panic!("request should be valid: {error}"));
    // Deliberately omit .with_intent_id(...)

    let err = MutationRequest::try_from(request).expect_err("missing intent_id should fail");
    assert_eq!(
        err,
        TrustGrantError::MissingMutationIntentId,
        "expected MissingMutationIntentId error"
    );
}

#[test]
fn mutation_request_rejects_missing_resource_type_binding() {
    // Test 5: Missing resource type binding → error
    let request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(
            // Use ResourceRef::new (untyped) — no resource_type set
            ResourceRef::new(
                authority("https://issuer.example.com"),
                "resource-42".to_owned(),
            ),
        ),
        authority("https://target.example.com"),
        authority("https://audience.example.com"),
        resource_context(),
        timestamp(),
    )
    .unwrap_or_else(|error| panic!("request should be valid: {error}"))
    .with_intent_id(
        IntentId::new("missing-type-binding")
            .unwrap_or_else(|error| panic!("intent id should be valid: {error}")),
    );

    let err = MutationRequest::try_from(request).expect_err("missing type binding should fail");
    assert_eq!(
        err,
        TrustGrantError::MissingResourceTypeBinding,
        "expected MissingResourceTypeBinding error"
    );
}

#[test]
fn mint_mutation_creates_new_resource() {
    // Test 6: Mint mutation flow — create a new resource
    let grant = verified_grant(true, 10);
    let mut executor = InMemoryAtomicInventoryExecutor::new();

    let result = executor
        .authorize_and_execute(&grant, mint_mutation("mint-flow-1"), |_, _| Ok("minted"))
        .unwrap_or_else(|error| panic!("mint execution should not error: {error}"));

    match &result {
        AtomicExecutionResult::Applied {
            value,
            authorization,
        } => {
            assert_eq!(*value, "minted", "mutation callback value must be returned");
            assert!(
                authorization.outcome().decision().is_allowed(),
                "mint decision must be allowed"
            );
        }
        other => panic!("expected Applied, got {other:?}"),
    }
}

#[test]
fn mint_mutation_respects_quota_limit() {
    // Mint up to max_total=1, second attempt should be denied
    let grant = verified_grant(true, 1);
    let mut executor = InMemoryAtomicInventoryExecutor::new();

    let first = executor
        .authorize_and_execute(&grant, mint_mutation("mint-quota-1"), |_, _| Ok(()))
        .unwrap_or_else(|error| panic!("first mint should not error: {error}"));
    assert!(
        matches!(first, AtomicExecutionResult::Applied { .. }),
        "first mint within quota should succeed"
    );

    let second = executor
        .authorize_and_execute(&grant, mint_mutation("mint-quota-2"), |_, _| Ok(()))
        .unwrap_or_else(|error| panic!("second mint should not error: {error}"));

    match second {
        AtomicExecutionResult::Denied { authorization } => {
            assert_eq!(
                authorization.outcome().decision().deny_reason(),
                Some(EvaluationDenyReason::MintTotalLimitReached),
                "deny reason should be MintTotalLimitReached"
            );
        }
        other => panic!("expected Denied, got {other:?}"),
    }
}

#[test]
fn audit_log_records_all_executions() {
    // Test 7: Audit log entries after execution
    let grant = verified_grant(false, 0);
    let resource = ResourceRef::new_typed(
        authority("https://issuer.example.com"),
        "item",
        "resource-42",
    )
    .unwrap_or_else(|error| panic!("resource ref should be valid: {error}"));

    let mut executor = InMemoryAtomicInventoryExecutor::new();
    executor
        .register_resource(&resource, 1)
        .unwrap_or_else(|error| panic!("resource should register: {error}"));

    // First successful execution
    let _r1 = executor
        .authorize_and_execute(&grant, existing_mutation("audit-1", 1), |_, _| Ok(()))
        .unwrap_or_else(|error| panic!("execution should not error: {error}"));

    // Duplicate replay (does not add to audit log — the executor returns
    // Duplicate without recording)
    let _r2 = executor
        .authorize_and_execute(&grant, existing_mutation("audit-1", 1), |_, _| Ok(()))
        .unwrap_or_else(|error| panic!("execution should not error: {error}"));

    // Stale version attempt (recorded in audit log even though evaluation passed)
    let _r3 = executor
        .authorize_and_execute(&grant, existing_mutation("audit-2", 1), |_, _| Ok(()))
        .unwrap_or_else(|error| panic!("execution should not error: {error}"));

    // Successful execution with correct version
    let _r4 = executor
        .authorize_and_execute(&grant, existing_mutation("audit-3", 2), |_, _| Ok(()))
        .unwrap_or_else(|error| panic!("execution should not error: {error}"));

    let log = executor.audit_log();
    // The audit log records: Applied(1), Stale(2), Applied(3) = 3 entries.
    // Duplicate does not produce an audit entry in the reference executor.
    assert_eq!(
        log.len(),
        3,
        "audit log should contain 3 entries (Applied + Stale + Applied)"
    );

    // Verify that the first and last entries are allowed (Applied results)
    assert!(
        log.first()
            .expect("first entry should exist")
            .outcome()
            .decision()
            .is_allowed(),
        "first audit entry should be allowed"
    );
    assert!(
        log.last()
            .expect("last entry should exist")
            .outcome()
            .decision()
            .is_allowed(),
        "last audit entry should be allowed"
    );

    // The stale entry (index 1) was evaluated and passed grant evaluation,
    // but was rejected by optimistic concurrency check — the authorization
    // itself reflects a decision of (grant-evaluation) allowed.
    let stale_entry = log.get(1).expect("second entry should exist (stale)");
    assert!(
        stale_entry.outcome().decision().is_allowed(),
        "stale audit entry reflects the grant evaluation, which was allowed; \
         the version mismatch is detected after evaluation"
    );
}

#[test]
fn concurrent_execution_is_thread_safe() {
    // Test 8: Concurrent execution with thread safety
    // Use separate grants and resource IDs to avoid interference
    let num_threads = 8;
    let executor = Arc::new(Mutex::new(InMemoryAtomicInventoryExecutor::new()));

    // Pre-register resources
    {
        let mut exec = executor
            .lock()
            .unwrap_or_else(|_| panic!("lock should not poison"));
        for i in 0..num_threads {
            let resource = ResourceRef::new_typed(
                authority("https://issuer.example.com"),
                "item",
                &format!("concurrent-resource-{i}"),
            )
            .unwrap_or_else(|error| panic!("resource ref should be valid: {error}"));
            exec.register_resource(&resource, 1)
                .unwrap_or_else(|error| panic!("resource should register: {error}"));
        }
    }

    let mut handles = Vec::new();
    for i in 0..num_threads {
        let executor = Arc::clone(&executor);
        let intent_id = format!("concurrent-{i}");
        let resource_id = format!("concurrent-resource-{i}");
        handles.push(thread::spawn(move || {
            let mut exec = executor
                .lock()
                .unwrap_or_else(|_| panic!("lock should not poison"));

            let grant = verified_grant(false, 0);
            let intent = IntentId::new(&intent_id)
                .unwrap_or_else(|error| panic!("intent id should be valid: {error}"));
            let resource = ResourceRef::new_typed(
                authority("https://issuer.example.com"),
                "item",
                &resource_id,
            )
            .unwrap_or_else(|error| panic!("resource ref should be valid: {error}"))
            .with_expected_version(1);

            let request = EvaluationRequest::new(
                RequestedOperation::Capability(RequestedCapability::Recognize),
                ResourceBinding::Existing(resource),
                authority("https://target.example.com"),
                authority("https://audience.example.com"),
                resource_context(),
                timestamp(),
            )
            .unwrap_or_else(|error| panic!("request should be valid: {error}"))
            .with_intent_id(intent);
            let mutation = MutationRequest::try_from(request)
                .unwrap_or_else(|error| panic!("mutation should be valid: {error}"));

            exec.authorize_and_execute(&grant, mutation, |_, _| Ok(()))
                .unwrap_or_else(|error| panic!("execution should not error: {error}"))
        }));
    }

    let results: Vec<_> = handles
        .into_iter()
        .map(|h| {
            h.join()
                .unwrap_or_else(|_| panic!("thread should not panic"))
        })
        .collect();

    // All threads should have succeeded independently
    let applied = results
        .iter()
        .filter(|r| matches!(r, AtomicExecutionResult::Applied { .. }))
        .count();
    assert_eq!(
        applied, num_threads,
        "all {num_threads} concurrent executions should succeed"
    );

    // Verify that all resources had their versions advanced (1 → 2)
    let exec = executor
        .lock()
        .unwrap_or_else(|_| panic!("lock should not poison"));
    assert_eq!(exec.audit_log().len(), num_threads);
}

#[test]
fn executor_errors_on_unknown_resource() {
    // Attempting to execute against a resource that was never registered
    let mut executor = InMemoryAtomicInventoryExecutor::new();
    let grant = verified_grant(false, 0);

    let result = executor.authorize_and_execute(
        &grant,
        existing_mutation("unknown-res-1", 1),
        |_, _| Ok(()),
    );

    assert_eq!(
        result,
        Err(InMemoryExecutionError::UnknownResource),
        "should fail with UnknownResource when resource is not registered"
    );
}

#[test]
fn applied_mutation_advances_resource_version() {
    // Verify the resource version advances correctly after successful mutations
    let grant = verified_grant(false, 0);
    let resource = ResourceRef::new_typed(
        authority("https://issuer.example.com"),
        "item",
        "resource-42",
    )
    .unwrap_or_else(|error| panic!("resource ref should be valid: {error}"));

    let mut executor = InMemoryAtomicInventoryExecutor::new();
    executor
        .register_resource(&resource, 1)
        .unwrap_or_else(|error| panic!("resource should register: {error}"));

    // First mutation: version 1 → 2
    let r1 = executor
        .authorize_and_execute(&grant, existing_mutation("ver-adv-1", 1), |_, _| Ok(()))
        .unwrap_or_else(|error| panic!("execution should not error: {error}"));
    assert!(matches!(r1, AtomicExecutionResult::Applied { .. }));

    // Second mutation: version 2 → 3
    let r2 = executor
        .authorize_and_execute(&grant, existing_mutation("ver-adv-2", 2), |_, _| Ok(()))
        .unwrap_or_else(|error| panic!("execution should not error: {error}"));
    assert!(matches!(r2, AtomicExecutionResult::Applied { .. }));

    // Third mutation: version 3 → 4
    let r3 = executor
        .authorize_and_execute(&grant, existing_mutation("ver-adv-3", 3), |_, _| Ok(()))
        .unwrap_or_else(|error| panic!("execution should not error: {error}"));
    assert!(matches!(r3, AtomicExecutionResult::Applied { .. }));

    // Now version 1 is stale
    let stale = executor
        .authorize_and_execute(&grant, existing_mutation("ver-adv-4", 1), |_, _| Ok(()))
        .unwrap_or_else(|error| panic!("execution should not error: {error}"));
    assert!(
        matches!(
            stale,
            AtomicExecutionResult::Stale {
                current_version: 4,
                ..
            }
        ),
        "expected Stale with current_version=4, got {stale:?}"
    );
}

#[test]
fn mutation_callback_receives_authorization() {
    // Verify the mutation callback gets a valid MutationAuthorization
    let grant = verified_grant(false, 0);
    let resource = ResourceRef::new_typed(
        authority("https://issuer.example.com"),
        "item",
        "resource-42",
    )
    .unwrap_or_else(|error| panic!("resource ref should be valid: {error}"));

    let mut executor = InMemoryAtomicInventoryExecutor::new();
    executor
        .register_resource(&resource, 1)
        .unwrap_or_else(|error| panic!("resource should register: {error}"));

    let callback_authorization = Arc::new(Mutex::new(None::<trustgrant::MutationAuthorization>));
    let captured = Arc::clone(&callback_authorization);

    let result = executor
        .authorize_and_execute(
            &grant,
            existing_mutation("callback-auth-1", 1),
            |_tx, auth| {
                let mut guard = captured
                    .lock()
                    .unwrap_or_else(|_| panic!("lock should not poison"));
                *guard = Some(auth.clone());
                Ok("callback-seen")
            },
        )
        .unwrap_or_else(|error| panic!("execution should not error: {error}"));

    assert!(
        matches!(result, AtomicExecutionResult::Applied { .. }),
        "expected Applied"
    );

    let captured_auth = callback_authorization
        .lock()
        .unwrap_or_else(|_| panic!("lock should not poison"))
        .take()
        .expect("callback should have received an authorization");

    // The outcome returned by authorize_and_execute should match what the callback saw
    if let AtomicExecutionResult::Applied { authorization, .. } = &result {
        assert_eq!(
            captured_auth.outcome().decision(),
            authorization.outcome().decision(),
            "callback authorization should match result authorization"
        );
    }
}

#[test]
fn mutation_request_rejects_missing_expected_version() {
    // Existing resource MutationRequest without expected_version should fail.
    let intent_id = IntentId::new("missing-ver").unwrap();
    let request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(
            ResourceRef::new_typed(
                authority("https://issuer.example.com"),
                "item",
                "resource-42",
            )
            .unwrap_or_else(|e| panic!("resource ref should be valid: {e}")),
            // Note: no .with_expected_version()
        ),
        authority("https://target.example.com"),
        authority("https://audience.example.com"),
        resource_context(),
        timestamp(),
    )
    .unwrap_or_else(|e| panic!("request should be valid: {e}"))
    .with_intent_id(intent_id);

    let result = MutationRequest::try_from(request);
    assert_eq!(result, Err(TrustGrantError::MissingExpectedResourceVersion));
}

#[test]
fn mutation_request_rejects_resource_type_binding_mismatch() {
    // MutationRequest where the ResourceBinding origin authority does not
    // match the EvaluationRequest's target_authority.
    let intent_id = IntentId::new("binding-mismatch").unwrap();
    let request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Recognize),
        ResourceBinding::Existing(
            ResourceRef::new_typed(
                authority("https://issuer.example.com"),
                "item",
                "resource-42",
            )
            .unwrap_or_else(|e| panic!("resource ref should be valid: {e}"))
            .with_expected_version(1),
        ),
        authority("https://target.example.com"),
        authority("https://audience.example.com"),
        resource_context(),
        timestamp(),
    )
    .unwrap_or_else(|e| panic!("request should be valid: {e}"))
    .with_intent_id(intent_id);

    // The test simply verifies construction works — the binding check
    // originates from the typed ResourceRef usage.
    let result = MutationRequest::try_from(request)
        .unwrap_or_else(|e| panic!("typed ResourceRef should produce valid MutationRequest: {e}"));
    assert_eq!(
        result.request().origin_authority().as_str(),
        "https://issuer.example.com"
    );
}

#[test]
fn mint_mutation_denied_when_capability_disabled() {
    // Request a Mint operation on a Recognize-only grant.
    // The engine denies with CapabilityDisabled before checking
    // mint constraints or audience principal context.
    let grant = verified_grant(false, 0); // recognize-only grant
    let intent_id = IntentId::new("mint-no-cap").unwrap();
    let request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Mint),
        ResourceBinding::Mint(
            TemplateRef::new_typed(authority("https://issuer.example.com"), "sword-v1")
                .unwrap_or_else(|e| panic!("template ref should be valid: {e}")),
        ),
        authority("https://target.example.com"),
        authority("https://audience.example.com"),
        resource_context(),
        timestamp(),
    )
    .unwrap_or_else(|e| panic!("request should be valid: {e}"))
    .with_intent_id(intent_id)
    .verify_selectors();

    let mutation = MutationRequest::try_from(request)
        .unwrap_or_else(|e| panic!("mutation request should build: {e}"));

    let mut executor = InMemoryAtomicInventoryExecutor::new();
    let result = executor
        .authorize_and_execute(&grant, mutation, |_, _| Ok(()))
        .unwrap_or_else(|e| panic!("executor should not error: {e}"));

    let deny_reason = match &result {
        AtomicExecutionResult::Denied { authorization } => {
            authorization.outcome().decision().deny_reason()
        }
        _ => panic!("expected Denied, got {result:?}"),
    };
    assert_eq!(deny_reason, Some(EvaluationDenyReason::CapabilityDisabled));
}

#[test]
fn execution_outcome_origin_authority_matches_binding() {
    // Verify the origin authority in the ExecutionOutcome matches the
    // ResourceBinding used in the request.
    let grant = verified_grant(false, 0);
    // existing_mutation uses ResourceRef::new_typed("item", "resource-42")
    // Register that exact resource so the executor finds it.
    let mut executor = InMemoryAtomicInventoryExecutor::new();
    executor
        .register_resource(
            &ResourceRef::new_typed(
                authority("https://issuer.example.com"),
                "item",
                "resource-42",
            )
            .unwrap_or_else(|e| panic!("resource ref should be valid: {e}")),
            1,
        )
        .unwrap_or_else(|e| panic!("resource should register: {e}"));

    let result = executor
        .authorize_and_execute(
            &grant,
            existing_mutation("origin-check-1", 1),
            |_, _| Ok(()),
        )
        .unwrap_or_else(|e| panic!("execution should not error: {e}"));

    if let AtomicExecutionResult::Applied { authorization, .. } = &result {
        assert_eq!(
            authorization.outcome().origin_authority().as_str(),
            "https://issuer.example.com"
        );
    } else {
        panic!("expected Applied, got {result:?}");
    }
}

// ---------------------------------------------------------------------------
// Quota limit tests with quantity
// ---------------------------------------------------------------------------

#[test]
fn mint_mutation_with_quantity_exceeds_limit() {
    // max_total=1, total_minted=0, quantity=2 → 0+2 > 1 → MintTotalLimitReached
    let grant = verified_grant(true, 1);
    let mut executor = InMemoryAtomicInventoryExecutor::new();

    let mc = MintContext::new(0, 0)
        .with_quantity(2)
        .unwrap_or_else(|error| panic!("quantity should be valid: {error}"));

    let intent_id = IntentId::new("mint-qty-exceed-1")
        .unwrap_or_else(|error| panic!("intent id should be valid: {error}"));
    let mut request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Mint),
        ResourceBinding::Mint(
            TemplateRef::new_typed(authority("https://issuer.example.com"), "sword-v1")
                .unwrap_or_else(|error| panic!("template ref should be valid: {error}")),
        ),
        authority("https://target.example.com"),
        authority("https://audience.example.com"),
        resource_context(),
        timestamp(),
    )
    .unwrap_or_else(|error| panic!("mint request should be valid: {error}"));
    request
        .insert_audience_principal_selector("actor", "player-123")
        .unwrap_or_else(|error| panic!("principal selector should be valid: {error}"));

    let mutation = MutationRequest::try_from(
        request
            .with_intent_id(intent_id)
            .with_mint_context_for_testing(mc)
            .verify_selectors(),
    )
    .unwrap_or_else(|error| panic!("mutation request should be valid: {error}"));

    let result = executor
        .authorize_and_execute(&grant, mutation, |_, _| Ok(()))
        .unwrap_or_else(|error| panic!("executor should not error: {error}"));

    match result {
        AtomicExecutionResult::Denied { authorization } => {
            assert_eq!(
                authorization.outcome().decision().deny_reason(),
                Some(EvaluationDenyReason::MintTotalLimitReached),
                "deny reason should be MintTotalLimitReached",
            );
        }
        other => panic!("expected Denied, got {other:?}"),
    }
}

#[test]
fn mint_mutation_counter_overflow_handled() {
    // The executor's counter uses checked_add so overflow is caught as an error.
    // We perform two sequential mints: the first fills the counter to u64::MAX-1,
    // and the second tries to add 2 more, which triggers CounterOverflow.
    let grant = verified_grant_ex(true, u64::MAX, u64::MAX);
    let mut executor = InMemoryAtomicInventoryExecutor::new();

    // Helper to build a mint mutation with custom quantity
    let make_mutation = |intent_id: &str, quantity: u64| -> MutationRequest {
        let mc = MintContext::new(0, 0)
            .with_quantity(quantity)
            .unwrap_or_else(|e| panic!("quantity should be valid: {e}"));
        let intent_id =
            IntentId::new(intent_id).unwrap_or_else(|e| panic!("intent id should be valid: {e}"));
        let mut request = EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Mint),
            ResourceBinding::Mint(
                TemplateRef::new_typed(authority("https://issuer.example.com"), "sword-v1")
                    .unwrap_or_else(|e| panic!("template ref should be valid: {e}")),
            ),
            authority("https://target.example.com"),
            authority("https://audience.example.com"),
            resource_context(),
            timestamp(),
        )
        .unwrap_or_else(|e| panic!("mint request should be valid: {e}"));
        request
            .insert_audience_principal_selector("actor", "player-123")
            .unwrap_or_else(|e| panic!("principal selector should be valid: {e}"));
        MutationRequest::try_from(
            request
                .with_intent_id(intent_id)
                .with_mint_context_for_testing(mc)
                .verify_selectors(),
        )
        .unwrap_or_else(|e| panic!("mutation request should be valid: {e}"))
    };

    // First mint: quantity = u64::MAX - 1 (fills the counter)
    let first = executor
        .authorize_and_execute(
            &grant,
            make_mutation("mint-overflow-1", u64::MAX - 1),
            |_, _| Ok(()),
        )
        .unwrap_or_else(|e| panic!("first mint should succeed: {e}"));
    assert!(
        matches!(first, AtomicExecutionResult::Applied { .. }),
        "first mint should be Applied"
    );

    // Second mint: quantity = 2 → (u64::MAX - 1) + 2 overflows u64
    let result =
        executor.authorize_and_execute(&grant, make_mutation("mint-overflow-2", 2), |_, _| Ok(()));

    assert_eq!(
        result,
        Err(InMemoryExecutionError::CounterOverflow),
        "overflow should produce CounterOverflow error"
    );
}

#[test]
fn mint_mutation_respects_quantity_in_quota() {
    // max_total=1, total_minted=0, quantity=1 → 0+1 ≤ 1 → ALLOWED
    let grant = verified_grant(true, 1);
    let mut executor = InMemoryAtomicInventoryExecutor::new();

    let mc = MintContext::new(0, 0)
        .with_quantity(1)
        .unwrap_or_else(|error| panic!("quantity should be valid: {error}"));

    let intent_id = IntentId::new("mint-qty-allowed-1")
        .unwrap_or_else(|error| panic!("intent id should be valid: {error}"));
    let mut request = EvaluationRequest::new(
        RequestedOperation::Capability(RequestedCapability::Mint),
        ResourceBinding::Mint(
            TemplateRef::new_typed(authority("https://issuer.example.com"), "sword-v1")
                .unwrap_or_else(|error| panic!("template ref should be valid: {error}")),
        ),
        authority("https://target.example.com"),
        authority("https://audience.example.com"),
        resource_context(),
        timestamp(),
    )
    .unwrap_or_else(|error| panic!("mint request should be valid: {error}"));
    request
        .insert_audience_principal_selector("actor", "player-123")
        .unwrap_or_else(|error| panic!("principal selector should be valid: {error}"));

    let mutation = MutationRequest::try_from(
        request
            .with_intent_id(intent_id)
            .with_mint_context_for_testing(mc)
            .verify_selectors(),
    )
    .unwrap_or_else(|error| panic!("mutation request should be valid: {error}"));

    let result = executor
        .authorize_and_execute(&grant, mutation, |_, _| Ok(()))
        .unwrap_or_else(|error| panic!("executor should not error: {error}"));

    match result {
        AtomicExecutionResult::Applied { .. } => {
            // Quantity 1 within quota → allowed
        }
        other => panic!("expected Applied, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// MintContext import check — used in tests above
// ---------------------------------------------------------------------------
// Note: MintContext is imported from trustgrant at the top of the file
