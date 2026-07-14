//! Atomic execution contracts for state-changing TrustGrant operations.
//!
//! The evaluator is intentionally stateless. A deployment must execute an
//! allowed mutation against its authoritative inventory inside one database
//! transaction, ledger transaction, or compare-and-swap boundary. This module
//! makes the inputs to that boundary explicit and provides an in-memory
//! reference implementation for integration tests.

use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result as FmtResult};

use chrono::{DateTime, Utc};

use trustgrant_domain::{AuthorityId, ResourceTypeName, TrustGrantId};
use trustgrant_error::TrustGrantError;
use trustgrant_verify::VerifiedTrustGrant;

use crate::{
    EvaluationEngine, EvaluationOutcome, EvaluationRequest, IntentId, MintContext,
    RequestedCapability, ResourceBinding, ResourceRef,
};

/// A validated state-changing request suitable for atomic execution.
///
/// Carries an intent ID for idempotency, an authenticated actor identity
/// for audit, an envelope expiry for time-bounded authorization, and a
/// typed resource reference or template reference. Read-only recognition
/// should use [`EvaluationEngine::evaluate`] directly instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationRequest {
    request: EvaluationRequest,
    intent_id: IntentId,
    actor: Option<AuthorityId>,
    envelope_expires_at: Option<DateTime<Utc>>,
}

impl TryFrom<EvaluationRequest> for MutationRequest {
    type Error = TrustGrantError;

    fn try_from(request: EvaluationRequest) -> Result<Self, Self::Error> {
        let intent_id = request
            .intent_id()
            .cloned()
            .ok_or(TrustGrantError::MissingMutationIntentId)?;

        match (request.operation(), request.resource_binding()) {
            (
                crate::RequestedOperation::Capability(RequestedCapability::Mint),
                ResourceBinding::Mint(template),
            ) => {
                if template.template_id().is_none() {
                    return Err(TrustGrantError::MissingTemplateId);
                }
            }
            (crate::RequestedOperation::Capability(RequestedCapability::Mint), _) => {
                return Err(TrustGrantError::InvalidMutationResourceBinding);
            }
            (_, ResourceBinding::Mint(_)) => {
                return Err(TrustGrantError::InvalidMutationResourceBinding);
            }
            (_, ResourceBinding::Existing(resource)) => {
                let Some(resource_type) = resource.resource_type() else {
                    return Err(TrustGrantError::MissingResourceTypeBinding);
                };

                if resource_type != request.resource().resource_type() {
                    return Err(TrustGrantError::ResourceTypeBindingMismatch);
                }

                if resource.expected_version().is_none() {
                    return Err(TrustGrantError::MissingExpectedResourceVersion);
                }
            }
        }

        // Actor and envelope expiry are intentionally None —
        // callers MUST set them explicitly via [`with_actor`] and
        // [`with_envelope_expiry`] before execution.
        Ok(Self {
            request,
            intent_id,
            actor: None,
            envelope_expires_at: None,
        })
    }
}

impl MutationRequest {
    /// Returns the validated evaluation request.
    #[must_use]
    pub const fn request(&self) -> &EvaluationRequest {
        &self.request
    }

    /// Returns the mandatory idempotency identifier.
    #[must_use]
    pub const fn intent_id(&self) -> &IntentId {
        &self.intent_id
    }

    /// The authenticated actor performing this operation.
    ///
    /// Must be set explicitly via [`with_actor`] before execution.
    /// When `None`, the executor should reject the mutation.
    #[must_use]
    pub const fn actor(&self) -> &Option<AuthorityId> {
        &self.actor
    }

    /// Sets the authenticated actor for this mutation request.
    #[must_use]
    pub fn with_actor(mut self, actor: AuthorityId) -> Self {
        self.actor = Some(actor);
        self
    }

    /// When this operation envelope expires.
    ///
    /// Must be set explicitly via [`with_envelope_expiry`] before execution.
    /// When `None`, the executor should reject the mutation.
    #[must_use]
    pub const fn envelope_expires_at(&self) -> Option<DateTime<Utc>> {
        self.envelope_expires_at
    }

    /// Sets the envelope expiry for this mutation request.
    #[must_use]
    pub fn with_envelope_expiry(mut self, expires_at: DateTime<Utc>) -> Self {
        self.envelope_expires_at = Some(expires_at);
        self
    }

    /// Whether this request creates new resources.
    #[must_use]
    pub const fn is_mint(&self) -> bool {
        matches!(
            self.request.operation(),
            crate::RequestedOperation::Capability(RequestedCapability::Mint)
        )
    }

    fn with_runtime_mint_context(&self, mint_context: MintContext) -> EvaluationRequest {
        self.request.clone().with_runtime_mint_context(mint_context)
    }

    const fn existing_resource(&self) -> Option<&ResourceRef> {
        match self.request.resource_binding() {
            ResourceBinding::Existing(resource) => Some(resource),
            ResourceBinding::Mint(_) => None,
        }
    }
}

/// A decision and its full state-changing request binding.
///
/// Persist this record, or a lossless authenticated representation of it,
/// alongside the mutation. An allow never authorizes a different request that
/// happens to reuse the same intent identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationAuthorization {
    outcome: EvaluationOutcome,
    actor: Option<AuthorityId>,
    intent_id: IntentId,
    envelope_expires_at: Option<DateTime<Utc>>,
}

impl MutationAuthorization {
    pub(crate) fn new(request: &MutationRequest, outcome: EvaluationOutcome) -> Self {
        Self {
            outcome,
            actor: request.actor.clone(),
            intent_id: request.intent_id.clone(),
            envelope_expires_at: request.envelope_expires_at,
        }
    }

    /// The complete evaluation outcome to record in the mutation audit trail.
    #[must_use]
    pub const fn outcome(&self) -> &EvaluationOutcome {
        &self.outcome
    }

    /// The exact request evaluated inside the transaction boundary.
    #[must_use]
    pub const fn request(&self) -> &EvaluationRequest {
        self.outcome.request()
    }

    /// The authenticated actor that performed this mutation.
    #[must_use]
    pub const fn actor(&self) -> &Option<AuthorityId> {
        &self.actor
    }

    /// The idempotency key for this mutation.
    #[must_use]
    pub const fn intent_id(&self) -> &IntentId {
        &self.intent_id
    }

    /// When this transaction envelope expires.
    #[must_use]
    pub const fn envelope_expires_at(&self) -> Option<DateTime<Utc>> {
        self.envelope_expires_at
    }

    fn matches(&self, grant_id: TrustGrantId, request: &MutationRequest) -> bool {
        self.outcome.decision().trustgrant_id() == grant_id
            && self
                .outcome
                .request()
                .same_mutation_intent(request.request())
    }
}

impl EvaluationEngine {
    /// Evaluates a state-changing request after it has passed mutation-binding
    /// validation. Atomic executors must invoke this within their transaction.
    #[must_use]
    pub fn authorize_mutation(
        self,
        grant: &VerifiedTrustGrant,
        request: &MutationRequest,
    ) -> MutationAuthorization {
        MutationAuthorization::new(request, self.evaluate(grant, request.request()))
    }
}

/// Result of attempting one mutation in an atomic execution boundary.
#[derive(Debug, PartialEq, Eq)]
pub enum AtomicExecutionResult<T> {
    /// Evaluation passed, the supplied mutation committed, and the request was
    /// recorded as processed.
    Applied {
        authorization: MutationAuthorization,
        value: T,
    },
    /// Grant evaluation denied the request. No mutation was applied.
    Denied {
        authorization: MutationAuthorization,
    },
    /// The same intent was already committed with the same complete binding.
    /// The original authorization is returned and the mutation is not run.
    Duplicate {
        authorization: MutationAuthorization,
    },
    /// An existing resource changed after the caller observed its version.
    Stale {
        authorization: MutationAuthorization,
        current_version: u64,
    },
    /// The intent ID was reused for a different grant or request binding.
    IntentConflict { intent_id: IntentId },
}

/// Adapter contract for a deployment's authoritative inventory transaction.
///
/// Implementations must evaluate the grant, check idempotency and optimistic
/// concurrency, apply the mutation callback, update mint counters or resource
/// version, and persist the authorization record in one atomic boundary.
/// `Transaction` must represent the adapter's real transaction context; the
/// callback must not mutate inventory state outside it.
pub trait AtomicInventoryExecutor {
    /// The transaction context supplied to the mutation callback.
    type Transaction;
    /// Adapter-specific transactional failure.
    type Error;

    /// Authorizes and executes one state-changing operation atomically.
    ///
    /// # Errors
    ///
    /// Returns the adapter's transaction error if loading, evaluating,
    /// applying, recording, or committing the operation fails. The adapter
    /// must roll back all mutations for any returned error.
    fn authorize_and_execute<T, F>(
        &mut self,
        grant: &VerifiedTrustGrant,
        request: MutationRequest,
        apply: F,
    ) -> Result<AtomicExecutionResult<T>, Self::Error>
    where
        F: FnOnce(&mut Self::Transaction, &MutationAuthorization) -> Result<T, Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ResourceKey {
    origin_authority: trustgrant_domain::AuthorityId,
    resource_type: ResourceTypeName,
    resource_id: String,
}

impl TryFrom<&ResourceRef> for ResourceKey {
    type Error = InMemoryExecutionError;

    fn try_from(resource: &ResourceRef) -> Result<Self, Self::Error> {
        let Some(resource_type) = resource.resource_type() else {
            return Err(InMemoryExecutionError::MissingTypedResourceReference);
        };

        Ok(Self {
            origin_authority: resource.origin_authority().clone(),
            resource_type: resource_type.clone(),
            resource_id: resource.resource_id().to_owned(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MintTotalKey {
    grant_id: TrustGrantId,
    resource_type: ResourceTypeName,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MintPrincipalKey {
    total_key: MintTotalKey,
    principal_context: String,
}

#[derive(Debug, Clone, Default)]
struct InMemoryExecutionState {
    resource_versions: HashMap<ResourceKey, u64>,
    total_mints: HashMap<MintTotalKey, u64>,
    mints_for_principal: HashMap<MintPrincipalKey, u64>,
    processed: HashMap<IntentId, MutationAuthorization>,
    audit_log: Vec<MutationAuthorization>,
}

/// Mutable state passed to the in-memory reference executor's callback.
///
/// Production adapters should expose their own transaction object instead.
#[derive(Debug, Clone, Default)]
pub struct InMemoryExecutionTransaction {
    state: InMemoryExecutionState,
}

impl InMemoryExecutionTransaction {
    /// Returns the current version for one registered resource.
    #[must_use]
    pub fn resource_version(&self, resource: &ResourceRef) -> Option<u64> {
        ResourceKey::try_from(resource)
            .ok()
            .and_then(|key| self.state.resource_versions.get(&key).copied())
    }
}

/// Failure from the in-memory reference executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InMemoryExecutionError {
    /// A state-changing request referenced a resource absent from the reference ledger.
    UnknownResource,
    /// A caller attempted to register a resource without all canonical identity fields.
    MissingTypedResourceReference,
    /// A counter or resource version cannot be advanced without overflowing.
    CounterOverflow,
}

impl Display for InMemoryExecutionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::UnknownResource => formatter.write_str("resource is not registered"),
            Self::MissingTypedResourceReference => {
                formatter.write_str("resource reference is missing canonical type binding")
            }
            Self::CounterOverflow => formatter.write_str("execution counter overflow"),
        }
    }
}

impl std::error::Error for InMemoryExecutionError {}

/// In-memory reference implementation of the atomic execution contract.
///
/// It is suitable for tests and examples, not as a multi-process production
/// ledger. A production adapter should implement [`AtomicInventoryExecutor`]
/// using a database transaction, ledger transaction, or compare-and-swap
/// primitive with equivalent isolation.
#[derive(Debug, Clone, Default)]
pub struct InMemoryAtomicInventoryExecutor {
    state: InMemoryExecutionState,
}

impl InMemoryAtomicInventoryExecutor {
    /// Creates an empty reference executor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a current canonical resource state for mutation tests.
    ///
    /// # Errors
    ///
    /// Returns [`InMemoryExecutionError`] when the reference is not typed.
    pub fn register_resource(
        &mut self,
        resource: &ResourceRef,
        version: u64,
    ) -> Result<(), InMemoryExecutionError> {
        self.state
            .resource_versions
            .insert(ResourceKey::try_from(resource)?, version);
        Ok(())
    }

    /// Returns the committed audit records in execution order.
    #[must_use]
    pub fn audit_log(&self) -> &[MutationAuthorization] {
        &self.state.audit_log
    }

    fn mint_keys(
        grant: &VerifiedTrustGrant,
        request: &MutationRequest,
    ) -> (MintTotalKey, MintPrincipalKey) {
        let total_key = MintTotalKey {
            grant_id: grant.lineage().trustgrant_id(),
            resource_type: request.request().resource().resource_type().clone(),
        };
        let principal_key = MintPrincipalKey {
            total_key: total_key.clone(),
            principal_context: request.request().audience_principal_context().stable_key(),
        };
        (total_key, principal_key)
    }

    fn advance(value: u64, delta: u64) -> Result<u64, InMemoryExecutionError> {
        value
            .checked_add(delta)
            .ok_or(InMemoryExecutionError::CounterOverflow)
    }
}

impl AtomicInventoryExecutor for InMemoryAtomicInventoryExecutor {
    type Transaction = InMemoryExecutionTransaction;
    type Error = InMemoryExecutionError;

    fn authorize_and_execute<T, F>(
        &mut self,
        grant: &VerifiedTrustGrant,
        request: MutationRequest,
        apply: F,
    ) -> Result<AtomicExecutionResult<T>, Self::Error>
    where
        F: FnOnce(&mut Self::Transaction, &MutationAuthorization) -> Result<T, Self::Error>,
    {
        let grant_id = grant.lineage().trustgrant_id();
        let intent_id = request.intent_id().clone();

        if let Some(previous) = self.state.processed.get(&intent_id) {
            if previous.matches(grant_id, &request) {
                return Ok(AtomicExecutionResult::Duplicate {
                    authorization: previous.clone(),
                });
            }

            return Ok(AtomicExecutionResult::IntentConflict { intent_id });
        }

        let (mint_total_key, mint_principal_key) = Self::mint_keys(grant, &request);
        let evaluation_request = if request.is_mint() {
            request.with_runtime_mint_context(MintContext::new(
                self.state
                    .total_mints
                    .get(&mint_total_key)
                    .copied()
                    .unwrap_or(0),
                self.state
                    .mints_for_principal
                    .get(&mint_principal_key)
                    .copied()
                    .unwrap_or(0),
            ))
        } else {
            request.request().clone()
        };
        let authorization = MutationAuthorization::new(
            &request,
            EvaluationEngine::new().evaluate(grant, &evaluation_request),
        );

        if !authorization.outcome().decision().is_allowed() {
            self.state.audit_log.push(authorization.clone());
            return Ok(AtomicExecutionResult::Denied { authorization });
        }

        let existing_key = request
            .existing_resource()
            .map(ResourceKey::try_from)
            .transpose()?;
        if let Some(resource_key) = existing_key.as_ref() {
            let current_version = self
                .state
                .resource_versions
                .get(resource_key)
                .copied()
                .ok_or(InMemoryExecutionError::UnknownResource)?;
            let expected_version = request
                .existing_resource()
                .and_then(ResourceRef::expected_version)
                .ok_or(InMemoryExecutionError::MissingTypedResourceReference)?;

            if expected_version != current_version {
                self.state.audit_log.push(authorization.clone());
                return Ok(AtomicExecutionResult::Stale {
                    authorization,
                    current_version,
                });
            }
        }

        let mut transaction = InMemoryExecutionTransaction {
            state: self.state.clone(),
        };
        transaction.state.audit_log.push(authorization.clone());
        let value = apply(&mut transaction, &authorization)?;

        if request.is_mint() {
            // The mint context should always have been injected by the
            // executor before reaching this point. If it's missing, that's
            // a programming error — default to 1 as a safe fallback.
            let quantity = evaluation_request
                .mint_context()
                .map(|ctx| ctx.requested_quantity())
                .unwrap_or(1);
            let total = transaction
                .state
                .total_mints
                .get(&mint_total_key)
                .copied()
                .unwrap_or(0);
            transaction
                .state
                .total_mints
                .insert(mint_total_key, Self::advance(total, quantity)?);

            let per_principal = transaction
                .state
                .mints_for_principal
                .get(&mint_principal_key)
                .copied()
                .unwrap_or(0);
            transaction
                .state
                .mints_for_principal
                .insert(mint_principal_key, Self::advance(per_principal, quantity)?);
        } else if let Some(resource_key) = existing_key {
            let current_version = transaction
                .state
                .resource_versions
                .get(&resource_key)
                .copied()
                .ok_or(InMemoryExecutionError::UnknownResource)?;
            transaction
                .state
                .resource_versions
                .insert(resource_key, Self::advance(current_version, 1)?);
        }

        transaction
            .state
            .processed
            .insert(intent_id, authorization.clone());
        self.state = transaction.state;

        Ok(AtomicExecutionResult::Applied {
            authorization,
            value,
        })
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::thread;

    use chrono::{TimeZone, Utc};
    use trustgrant_discovery::{AuthorityKeyRecord, ResolvedSignerBinding, SignatureProfile};
    use trustgrant_document::ValidatedTrustGrantDocument;
    use trustgrant_document::raw::RawTrustGrantDocument;
    use trustgrant_domain::{AuthorityId, OwnershipProofKind, OwnershipVerificationRecord};
    use trustgrant_error::TrustGrantError;
    use trustgrant_ports::VerificationPosture;
    use trustgrant_revocation::{
        ProofFinality, RevocationRecord, RevocationSourceKind, RevocationStatus,
        VerifiedRevocationState,
    };
    use trustgrant_verify::{VerificationMetadata, VerifiedTrustGrant};

    use super::{
        AtomicExecutionResult, AtomicInventoryExecutor, InMemoryAtomicInventoryExecutor,
        InMemoryExecutionError, MutationRequest,
    };
    use crate::{
        EvaluationDenyReason, EvaluationRequest, IntentId, RequestedCapability,
        RequestedOperation, ResourceBinding, ResourceContext, ResourceRef, TemplateRef,
    };

    fn timestamp() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 7, 12, 0, 0)
            .single()
            .unwrap_or_else(|| panic!("fixed timestamp should be valid"))
    }

    fn authority(value: &str) -> AuthorityId {
        AuthorityId::new(value).unwrap_or_else(|error| panic!("authority should be valid: {error}"))
    }

    fn verified_grant(mint: bool, max_total: u64) -> VerifiedTrustGrant {
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
              "resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"namespace","all":false,"values":["weapons"],"expressions":null}],"deny":null,"capabilities":__TYPE_CAPABILITIES__,"constraints":{"minting":{"max_total":__MAX_TOTAL__,"max_per_user":1},"audience_scope":null},"operations":__OPERATIONS__}}},
              "global_constraints":{"time":{"not_before":"2026-04-07T12:00:00Z","not_after":"2027-04-08T12:00:00Z"}},
              "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation","post_revocation_effect":"block_all"},
              "issued_at":"2026-04-07T12:00:00Z",
              "signature":"base64-signature"
            }"#
            .replace("__CAPABILITIES__", capabilities)
            .replace("__TYPE_CAPABILITIES__", capabilities)
            .replace("__MAX_TOTAL__", &max_total.to_string())
            .replace("__OPERATIONS__", operations);

        let raw = RawTrustGrantDocument::parse_json_str(&document)
            .unwrap_or_else(|error| panic!("grant should parse: {error}"));
        let validated = ValidatedTrustGrantDocument::try_from(raw)
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

    #[test]
    fn mutation_request_requires_complete_binding() {
        let untyped = EvaluationRequest::new(
            RequestedOperation::Capability(RequestedCapability::Recognize),
            ResourceBinding::Existing(ResourceRef::new(
                authority("https://issuer.example.com"),
                "resource-42".to_owned(),
            )),
            authority("https://target.example.com"),
            authority("https://audience.example.com"),
            resource_context(),
            timestamp(),
        )
        .unwrap_or_else(|error| panic!("request should be valid: {error}"))
        .with_intent_id(IntentId::new("mutation-1").unwrap());

        assert_eq!(
            MutationRequest::try_from(untyped),
            Err(TrustGrantError::MissingResourceTypeBinding)
        );

        let missing_intent = EvaluationRequest::new(
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
        assert_eq!(
            MutationRequest::try_from(missing_intent),
            Err(TrustGrantError::MissingMutationIntentId)
        );
    }

    #[test]
    fn reference_executor_is_idempotent_and_detects_stale_state() {
        let grant = verified_grant(false, 0);
        let resource = ResourceRef::new_typed(
            authority("https://issuer.example.com"),
            "item",
            "resource-42",
        )
        .unwrap_or_else(|error| panic!("resource ref should be valid: {error}"));
        let mut executor = InMemoryAtomicInventoryExecutor::new();
        executor
            .register_resource(&resource, 7)
            .unwrap_or_else(|error| panic!("resource should register: {error}"));

        let first = executor
            .authorize_and_execute(&grant, existing_mutation("intent-1", 7), |_, _| Ok(()))
            .unwrap_or_else(|error| panic!("execution should not error: {error}"));
        assert!(matches!(first, AtomicExecutionResult::Applied { .. }));

        let duplicate = executor
            .authorize_and_execute(&grant, existing_mutation("intent-1", 7), |_, _| Ok(()))
            .unwrap_or_else(|error| panic!("execution should not error: {error}"));
        assert!(matches!(duplicate, AtomicExecutionResult::Duplicate { .. }));

        let stale = executor
            .authorize_and_execute(&grant, existing_mutation("intent-2", 7), |_, _| Ok(()))
            .unwrap_or_else(|error| panic!("execution should not error: {error}"));
        assert!(matches!(
            stale,
            AtomicExecutionResult::Stale {
                current_version: 8,
                ..
            }
        ));
        assert_eq!(executor.audit_log().len(), 2);
    }

    #[test]
    fn reference_executor_serializes_concurrent_mint_quota_checks() {
        let grant = Arc::new(verified_grant(true, 1));
        let executor = Arc::new(Mutex::new(InMemoryAtomicInventoryExecutor::new()));

        let mut handles = Vec::new();
        for intent_id in ["mint-1", "mint-2"] {
            let grant = Arc::clone(&grant);
            let executor = Arc::clone(&executor);
            handles.push(thread::spawn(move || {
                let mut executor = executor
                    .lock()
                    .unwrap_or_else(|_| panic!("reference executor lock should not poison"));
                executor
                    .authorize_and_execute(&grant, mint_mutation(intent_id), |_, _| Ok(()))
                    .unwrap_or_else(|error| panic!("execution should not error: {error}"))
            }));
        }

        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|_| panic!("mint thread should not panic"))
            })
            .collect();
        let applied = results
            .iter()
            .filter(|result| matches!(result, AtomicExecutionResult::Applied { .. }))
            .count();
        let denied = results
            .iter()
            .filter(|result| {
                matches!(
                    result,
                    AtomicExecutionResult::Denied { authorization }
                        if authorization.outcome().decision().deny_reason()
                            == Some(EvaluationDenyReason::MintTotalLimitReached)
                )
            })
            .count();

        assert_eq!(applied, 1);
        assert_eq!(denied, 1);
    }

    #[test]
    fn executor_rejects_unknown_resource_without_running_mutation() {
        let mut executor = InMemoryAtomicInventoryExecutor::new();
        let grant = verified_grant(false, 0);
        let result =
            executor.authorize_and_execute(&grant, existing_mutation("intent-1", 7), |_, _| Ok(()));

        assert_eq!(result, Err(InMemoryExecutionError::UnknownResource));
    }
}
