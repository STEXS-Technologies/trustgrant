use std::collections::BTreeMap;

use trustgrant_discovery::{
    AuthorityDiscoveryDocument, DelegatedPrincipalKeyDocument, ResolvedSignerBinding,
};
use trustgrant_document::RawOwnershipTransitionDocument;
use trustgrant_document::{ValidatedPrincipal, ValidatedTrustGrantDocument};
use trustgrant_domain::{AuthorityId, KeyId, PrincipalId, PrincipalKind, TrustGrantId};
use trustgrant_error::TrustGrantError;
use trustgrant_error::limits::{
    MAX_BUNDLE_DELEGATED_PRINCIPAL_DOCUMENTS, MAX_BUNDLE_DISCOVERY_DOCUMENTS,
    MAX_BUNDLE_OWNERSHIP_TRANSITION_CHAINS, MAX_BUNDLE_REVOCATION_PROOFS,
    MAX_OWNERSHIP_CHAIN_LENGTH, ensure_collection_limit,
};
use trustgrant_ports::{
    AuthorityDiscoverySource, OwnershipTransitionProofSource, RevocationProofSource,
    VerificationContext, VerificationSources,
};
use trustgrant_revocation::{
    ProofFinality, RevocationFreshnessPolicy, RevocationRecord, RevocationSourceKind,
    RevocationStatusProof,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleRevocationProof {
    proof: RevocationStatusProof,
    source_kind: RevocationSourceKind,
    finality: ProofFinality,
    freshness_policy: RevocationFreshnessPolicy,
}

impl BundleRevocationProof {
    #[must_use = "bundle revocation proof should be assembled before verification"]
    pub const fn new(
        proof: RevocationStatusProof,
        source_kind: RevocationSourceKind,
        finality: ProofFinality,
        freshness_policy: RevocationFreshnessPolicy,
    ) -> Self {
        Self {
            proof,
            source_kind,
            finality,
            freshness_policy,
        }
    }

    /// Normalizes one bundled proof into the runtime revocation record used by
    /// the verification pipeline.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the bundled proof does not match the
    /// requested grant or the freshness policy cannot be applied.
    pub fn to_record_for(
        &self,
        trustgrant_id: TrustGrantId,
    ) -> Result<RevocationRecord, TrustGrantError> {
        if self.proof.trustgrant_id() != trustgrant_id {
            return Err(TrustGrantError::RevocationProofGrantMismatch);
        }

        self.proof
            .into_record(self.source_kind, self.finality, self.freshness_policy)
    }
}

#[derive(Debug, Default, Clone)]
pub struct TrustGrantProofBundle {
    discovery_documents: BTreeMap<AuthorityId, AuthorityDiscoveryDocument>,
    delegated_documents: BTreeMap<
        AuthorityId,
        BTreeMap<PrincipalKind, BTreeMap<PrincipalId, DelegatedPrincipalKeyDocument>>,
    >,
    revocation_proofs: BTreeMap<TrustGrantId, BundleRevocationProof>,
    ownership_transition_chains: BTreeMap<TrustGrantId, Vec<RawOwnershipTransitionDocument>>,
}

impl TrustGrantProofBundle {
    #[must_use = "empty proof bundles may be populated incrementally"]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use = "proof bundles may be assembled fluently before verification"]
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the new document conflicts with an
    /// existing entry or would exceed bundle limits.
    pub fn with_discovery_document(
        mut self,
        document: AuthorityDiscoveryDocument,
    ) -> Result<Self, TrustGrantError> {
        self.insert_discovery_document(document)?;
        Ok(self)
    }

    #[must_use = "proof bundles may be assembled fluently before verification"]
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the new document conflicts with an
    /// existing entry or would exceed bundle limits.
    pub fn with_delegated_principal_document(
        mut self,
        document: DelegatedPrincipalKeyDocument,
    ) -> Result<Self, TrustGrantError> {
        self.insert_delegated_principal_document(document)?;
        Ok(self)
    }

    #[must_use = "proof bundles may be assembled fluently before verification"]
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the new proof conflicts with an
    /// existing entry or would exceed bundle limits.
    pub fn with_revocation_proof(
        mut self,
        proof: BundleRevocationProof,
    ) -> Result<Self, TrustGrantError> {
        self.insert_revocation_proof(proof)?;
        Ok(self)
    }

    #[must_use = "proof bundles may be assembled fluently before verification"]
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the new chain conflicts with an
    /// existing entry or would exceed bundle limits.
    pub fn with_ownership_transition_chain(
        mut self,
        trustgrant_id: TrustGrantId,
        chain: Vec<RawOwnershipTransitionDocument>,
    ) -> Result<Self, TrustGrantError> {
        self.insert_ownership_transition_chain(trustgrant_id, chain)?;
        Ok(self)
    }

    #[must_use = "shared proof bundles may act as all source types"]
    pub fn as_sources(&self) -> VerificationSources<'_> {
        VerificationSources::new(self, self, self)
    }

    /// Inserts one authority discovery document into the bundle.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the document conflicts with an
    /// existing entry or would exceed bundle limits.
    pub fn insert_discovery_document(
        &mut self,
        document: AuthorityDiscoveryDocument,
    ) -> Result<(), TrustGrantError> {
        if let Some(existing) = self.discovery_documents.get(document.authority_id()) {
            if existing == &document {
                return Ok(());
            }

            return Err(TrustGrantError::ConflictingProofBundleEntry(
                "discovery_document",
            ));
        }

        let next_count = self.discovery_documents.len().saturating_add(1);
        ensure_collection_limit(
            "proof_bundle.discovery_documents",
            next_count,
            MAX_BUNDLE_DISCOVERY_DOCUMENTS,
        )?;
        self.discovery_documents
            .insert(document.authority_id().clone(), document);
        Ok(())
    }

    /// Inserts one delegated-principal key document into the bundle.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the document conflicts with an
    /// existing entry or would exceed bundle limits.
    pub fn insert_delegated_principal_document(
        &mut self,
        document: DelegatedPrincipalKeyDocument,
    ) -> Result<(), TrustGrantError> {
        if let Some(existing) = self
            .delegated_documents
            .get(document.authority_id())
            .and_then(|principal_kinds| principal_kinds.get(document.principal().kind()))
            .and_then(|principal_ids| principal_ids.get(document.principal().id()))
        {
            if existing == &document {
                return Ok(());
            }

            return Err(TrustGrantError::ConflictingProofBundleEntry(
                "delegated_principal_document",
            ));
        }

        let next_count = delegated_document_count(&self.delegated_documents).saturating_add(1);
        ensure_collection_limit(
            "proof_bundle.delegated_principal_documents",
            next_count,
            MAX_BUNDLE_DELEGATED_PRINCIPAL_DOCUMENTS,
        )?;
        self.delegated_documents
            .entry(document.authority_id().clone())
            .or_default()
            .entry(document.principal().kind().clone())
            .or_default()
            .insert(document.principal().id().clone(), document);
        Ok(())
    }

    /// Inserts one revocation proof into the bundle.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the proof conflicts with an existing
    /// entry or would exceed bundle limits.
    pub fn insert_revocation_proof(
        &mut self,
        proof: BundleRevocationProof,
    ) -> Result<(), TrustGrantError> {
        let trustgrant_id = proof.proof.trustgrant_id();

        if let Some(existing) = self.revocation_proofs.get(&trustgrant_id) {
            if existing == &proof {
                return Ok(());
            }

            return Err(TrustGrantError::ConflictingProofBundleEntry(
                "revocation_proof",
            ));
        }

        let next_count = self.revocation_proofs.len().saturating_add(1);
        ensure_collection_limit(
            "proof_bundle.revocation_proofs",
            next_count,
            MAX_BUNDLE_REVOCATION_PROOFS,
        )?;
        self.revocation_proofs.insert(trustgrant_id, proof);
        Ok(())
    }

    /// Inserts one ownership-transition chain into the bundle.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the chain conflicts with an existing
    /// entry, exceeds the per-chain limit, or would exceed bundle limits.
    pub fn insert_ownership_transition_chain(
        &mut self,
        trustgrant_id: TrustGrantId,
        chain: Vec<RawOwnershipTransitionDocument>,
    ) -> Result<(), TrustGrantError> {
        ensure_collection_limit(
            "ownership_transition.chain",
            chain.len(),
            MAX_OWNERSHIP_CHAIN_LENGTH,
        )?;

        if let Some(existing) = self.ownership_transition_chains.get(&trustgrant_id) {
            if existing == &chain {
                return Ok(());
            }

            return Err(TrustGrantError::ConflictingProofBundleEntry(
                "ownership_transition_chain",
            ));
        }

        let next_count = self.ownership_transition_chains.len().saturating_add(1);
        ensure_collection_limit(
            "proof_bundle.ownership_transition_chains",
            next_count,
            MAX_BUNDLE_OWNERSHIP_TRANSITION_CHAINS,
        )?;
        self.ownership_transition_chains
            .insert(trustgrant_id, chain);
        Ok(())
    }
}

fn delegated_document_count(
    delegated_documents: &BTreeMap<
        AuthorityId,
        BTreeMap<PrincipalKind, BTreeMap<PrincipalId, DelegatedPrincipalKeyDocument>>,
    >,
) -> usize {
    delegated_documents
        .values()
        .flat_map(BTreeMap::values)
        .map(BTreeMap::len)
        .sum()
}

impl AuthorityDiscoverySource for TrustGrantProofBundle {
    fn resolve_signer_binding(
        &self,
        issuer_authority: &AuthorityId,
        key_id: &KeyId,
        issuer_principal: Option<&ValidatedPrincipal>,
        _context: VerificationContext,
    ) -> Result<ResolvedSignerBinding, TrustGrantError> {
        let discovery_document = self
            .discovery_documents
            .get(issuer_authority)
            .ok_or(TrustGrantError::MissingAuthorityDiscoveryDocument)?;

        match issuer_principal {
            None => discovery_document.resolve_root_signer_binding(issuer_authority, key_id),
            Some(issuer_principal) => {
                if discovery_document.delegation().is_none() {
                    return Err(TrustGrantError::DelegationNotSupported);
                }

                let delegated_document = self
                    .delegated_documents
                    .get(issuer_authority)
                    .and_then(|principal_kinds| principal_kinds.get(issuer_principal.kind()))
                    .and_then(|principal_ids| principal_ids.get(issuer_principal.id()))
                    .ok_or(TrustGrantError::MissingDelegatedPrincipalDocument)?;

                delegated_document.resolve_signer_binding(
                    issuer_authority,
                    issuer_principal,
                    key_id,
                    discovery_document.signature_profile(),
                )
            }
        }
    }
}

impl RevocationProofSource for TrustGrantProofBundle {
    fn resolve_revocation_record(
        &self,
        document: &ValidatedTrustGrantDocument,
        _signer_binding: &ResolvedSignerBinding,
        _context: VerificationContext,
    ) -> Result<RevocationRecord, TrustGrantError> {
        self.revocation_proofs
            .get(&document.lineage().trustgrant_id())
            .ok_or(TrustGrantError::MissingRevocationProof)?
            .to_record_for(document.lineage().trustgrant_id())
    }
}

impl OwnershipTransitionProofSource for TrustGrantProofBundle {
    fn resolve_ownership_transition_chain(
        &self,
        document: &ValidatedTrustGrantDocument,
        _context: VerificationContext,
    ) -> Result<Vec<RawOwnershipTransitionDocument>, TrustGrantError> {
        let chain = self
            .ownership_transition_chains
            .get(&document.lineage().trustgrant_id())
            .cloned()
            .unwrap_or_default();
        ensure_collection_limit(
            "ownership_transition.chain",
            chain.len(),
            MAX_OWNERSHIP_CHAIN_LENGTH,
        )?;

        Ok(chain)
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::{BundleRevocationProof, TrustGrantProofBundle};
    use trustgrant_discovery::{
        parse_authority_discovery_document, parse_delegated_principal_key_document,
    };
    use trustgrant_document::RawOwnershipTransitionDocument;
    use trustgrant_error::TrustGrantError;
    use trustgrant_error::limits::{
        MAX_BUNDLE_DELEGATED_PRINCIPAL_DOCUMENTS, MAX_BUNDLE_DISCOVERY_DOCUMENTS,
        MAX_BUNDLE_OWNERSHIP_TRANSITION_CHAINS, MAX_BUNDLE_REVOCATION_PROOFS,
        MAX_OWNERSHIP_CHAIN_LENGTH,
    };
    use trustgrant_revocation::{
        ProofFinality, RevocationFreshnessPolicy, RevocationSourceKind,
        parse_revocation_status_proof,
    };
    // ── idempotent insert tests ────────────────────────────────────

    #[test]
    fn bundle_revocation_proof_to_record_rejects_grant_mismatch() {
        let proof = BundleRevocationProof::new(
            parse_revocation_status_proof(
                r#"{"trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000","status":"active","checked_at":"2026-04-07T12:00:00Z"}"#,
            )
            .unwrap_or_else(|error| panic!("proof should parse: {error}")),
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            RevocationFreshnessPolicy::new(120, 900)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        );

        let different_id: trustgrant_domain::TrustGrantId =
            "tg_123e4567-e89b-12d3-a456-426614179999"
                .parse()
                .unwrap_or_else(|error| panic!("trustgrant id should parse: {error}"));

        let result = proof.to_record_for(different_id);

        assert_eq!(result, Err(TrustGrantError::RevocationProofGrantMismatch),);
    }

    #[test]
    fn bundle_insert_same_discovery_document_twice_is_idempotent() {
        let mut bundle = TrustGrantProofBundle::new();
        let doc = parse_authority_discovery_document(TEST_DISCOVERY_JSON)
            .unwrap_or_else(|error| panic!("discovery should parse: {error}"));
        assert!(bundle.insert_discovery_document(doc.clone()).is_ok());
        assert!(bundle.insert_discovery_document(doc).is_ok());
    }

    #[test]
    fn bundle_insert_same_delegated_document_twice_is_idempotent() {
        let mut bundle = TrustGrantProofBundle::new();
        let doc = parse_delegated_principal_key_document(TEST_DELEGATED_PRINCIPAL_JSON)
            .unwrap_or_else(|error| panic!("delegated should parse: {error}"));
        assert!(
            bundle
                .insert_delegated_principal_document(doc.clone())
                .is_ok()
        );
        assert!(bundle.insert_delegated_principal_document(doc).is_ok());
    }

    #[test]
    fn bundle_insert_same_revocation_proof_twice_is_idempotent() {
        let mut bundle = TrustGrantProofBundle::new();
        let proof = BundleRevocationProof::new(
            parse_revocation_status_proof(TEST_REVOCATION_JSON)
                .unwrap_or_else(|error| panic!("proof should parse: {error}")),
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            RevocationFreshnessPolicy::new(120, 900)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        );
        assert!(bundle.insert_revocation_proof(proof.clone()).is_ok());
        assert!(bundle.insert_revocation_proof(proof).is_ok());
    }

    #[test]
    fn bundle_insert_same_transition_chain_twice_is_idempotent() {
        let mut bundle = TrustGrantProofBundle::new();
        let trustgrant_id: trustgrant_domain::TrustGrantId =
            "tg_123e4567-e89b-12d3-a456-426614174000"
                .parse()
                .unwrap_or_else(|error| panic!("trustgrant id should parse: {error}"));
        let chain = vec![
            RawOwnershipTransitionDocument::parse_json_str(
                r#"{
                  "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174200",
                  "version":0,
                  "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174201",
                  "revision":1,
                  "supersedes_transition_id":null,
                  "origin_authority":"https://origin.example.com",
                  "from_authority":"https://origin.example.com",
                  "to_authority":"https://successor.example.com",
                  "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":null}],"deny":null}}},
                  "global_constraints":null,
                  "effective_at":"2026-04-07T12:00:00Z",
                  "predecessor_signature":{"key_id":"origin-key-1","signature":"origin-signature"},
                  "successor_acceptance":{"accepted_at":"2026-04-07T11:30:00Z","key_id":"successor-key-1","signature":"successor-signature"}
                }"#,
            )
            .unwrap_or_else(|error| panic!("transition should parse: {error}")),
        ];
        assert!(
            bundle
                .insert_ownership_transition_chain(trustgrant_id, chain.clone())
                .is_ok()
        );
        assert!(
            bundle
                .insert_ownership_transition_chain(trustgrant_id, chain)
                .is_ok()
        );
    }

    #[test]
    fn proof_bundle_rejects_conflicting_discovery_document() {
        let first = parse_authority_discovery_document(
            r#"{
              "authority_id":"https://issuer.example.com",
              "keys":[{"key_id":"root-key-1","algorithm":"ed25519","public_key":"base64-a","not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}],
              "signature_profile":{"format":"jcs+ed25519","canonicalization":"RFC8785"},
              "issued_at":"2026-04-07T12:00:00Z"
            }"#,
        )
        .unwrap_or_else(|error| panic!("first discovery should parse: {error}"));
        let second = parse_authority_discovery_document(
            r#"{
              "authority_id":"https://issuer.example.com",
              "keys":[{"key_id":"root-key-1","algorithm":"ed25519","public_key":"base64-b","not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}],
              "signature_profile":{"format":"jcs+ed25519","canonicalization":"RFC8785"},
              "issued_at":"2026-04-07T12:00:00Z"
            }"#,
        )
        .unwrap_or_else(|error| panic!("second discovery should parse: {error}"));

        let mut bundle = TrustGrantProofBundle::new();
        bundle
            .insert_discovery_document(first)
            .unwrap_or_else(|error| panic!("first insert should succeed: {error}"));

        let result = bundle.insert_discovery_document(second);

        assert_eq!(
            result,
            Err(TrustGrantError::ConflictingProofBundleEntry(
                "discovery_document",
            ))
        );
    }

    #[test]
    fn proof_bundle_rejects_too_many_discovery_documents() {
        let mut bundle = TrustGrantProofBundle::new();

        for index in 0..MAX_BUNDLE_DISCOVERY_DOCUMENTS {
            let document = parse_authority_discovery_document(&format!(
                r#"{{
                  "authority_id":"https://issuer-{index}.example.com",
                  "keys":[{{"key_id":"root-key-1","algorithm":"ed25519","public_key":"base64-key","not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}}],
                  "signature_profile":{{"format":"jcs+ed25519","canonicalization":"RFC8785"}},
                  "issued_at":"2026-04-07T12:00:00Z"
                }}"#
            ))
            .unwrap_or_else(|error| panic!("discovery should parse: {error}"));
            bundle
                .insert_discovery_document(document)
                .unwrap_or_else(|error| panic!("insert should succeed: {error}"));
        }

        let overflow = parse_authority_discovery_document(
            r#"{
              "authority_id":"https://overflow.example.com",
              "keys":[{"key_id":"root-key-1","algorithm":"ed25519","public_key":"base64-key","not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z"}],
              "signature_profile":{"format":"jcs+ed25519","canonicalization":"RFC8785"},
              "issued_at":"2026-04-07T12:00:00Z"
            }"#,
        )
        .unwrap_or_else(|error| panic!("overflow discovery should parse: {error}"));

        let result = bundle.insert_discovery_document(overflow);

        assert_eq!(
            result,
            Err(TrustGrantError::CollectionTooLarge {
                field: "proof_bundle.discovery_documents",
                max_items: MAX_BUNDLE_DISCOVERY_DOCUMENTS,
            })
        );
    }

    #[test]
    fn proof_bundle_rejects_too_many_delegated_documents() {
        let mut bundle = TrustGrantProofBundle::new();

        for index in 0..MAX_BUNDLE_DELEGATED_PRINCIPAL_DOCUMENTS {
            let document = parse_delegated_principal_key_document(&format!(
                r#"{{
                  "authority_id":"https://issuer.example.com",
                  "principal":{{"kind":"service","id":"worker-{index}"}},
                  "keys":[{{"key_id":"delegated-key","algorithm":"ed25519","public_key":"base64-key","not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z","revoked":false}}]
                }}"#
            ))
            .unwrap_or_else(|error| panic!("delegated principal should parse: {error}"));
            bundle
                .insert_delegated_principal_document(document)
                .unwrap_or_else(|error| panic!("insert should succeed: {error}"));
        }

        let overflow = parse_delegated_principal_key_document(
            r#"{
              "authority_id":"https://issuer.example.com",
              "principal":{"kind":"service","id":"overflow"},
              "keys":[{"key_id":"delegated-key","algorithm":"ed25519","public_key":"base64-key","not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z","revoked":false}]
            }"#,
        )
        .unwrap_or_else(|error| panic!("overflow delegated principal should parse: {error}"));

        let result = bundle.insert_delegated_principal_document(overflow);

        assert_eq!(
            result,
            Err(TrustGrantError::CollectionTooLarge {
                field: "proof_bundle.delegated_principal_documents",
                max_items: MAX_BUNDLE_DELEGATED_PRINCIPAL_DOCUMENTS,
            })
        );
    }

    #[test]
    fn proof_bundle_rejects_conflicting_delegated_document() {
        let first = parse_delegated_principal_key_document(
            r#"{
              "authority_id":"https://issuer.example.com",
              "principal":{"kind":"service","id":"issuer-worker"},
              "keys":[{"key_id":"delegated-key","algorithm":"ed25519","public_key":"base64-a","not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z","revoked":false}]
            }"#,
        )
        .unwrap_or_else(|error| panic!("first delegated document should parse: {error}"));
        let second = parse_delegated_principal_key_document(
            r#"{
              "authority_id":"https://issuer.example.com",
              "principal":{"kind":"service","id":"issuer-worker"},
              "keys":[{"key_id":"delegated-key","algorithm":"ed25519","public_key":"base64-b","not_before":"2026-04-07T12:00:00Z","not_after":"2026-04-08T12:00:00Z","revoked":false}]
            }"#,
        )
        .unwrap_or_else(|error| panic!("second delegated document should parse: {error}"));

        let mut bundle = TrustGrantProofBundle::new();
        bundle
            .insert_delegated_principal_document(first)
            .unwrap_or_else(|error| panic!("first insert should succeed: {error}"));

        let result = bundle.insert_delegated_principal_document(second);

        assert_eq!(
            result,
            Err(TrustGrantError::ConflictingProofBundleEntry(
                "delegated_principal_document",
            ))
        );
    }

    #[test]
    fn proof_bundle_rejects_too_many_revocation_proofs() {
        let mut bundle = TrustGrantProofBundle::new();

        for index in 0..MAX_BUNDLE_REVOCATION_PROOFS {
            let proof = BundleRevocationProof::new(
                parse_revocation_status_proof(&format!(
                    r#"{{"trustgrant_id":"tg_123e4567-e89b-12d3-a456-42661417{:04}","status":"active","checked_at":"2026-04-07T12:00:00Z"}}"#,
                    index
                ))
                .unwrap_or_else(|error| panic!("proof should parse: {error}")),
                RevocationSourceKind::Api,
                ProofFinality::Observed,
                RevocationFreshnessPolicy::new(120, 900)
                    .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
            );
            bundle
                .insert_revocation_proof(proof)
                .unwrap_or_else(|error| panic!("insert should succeed: {error}"));
        }

        let overflow = BundleRevocationProof::new(
            parse_revocation_status_proof(
                r#"{"trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614179999","status":"active","checked_at":"2026-04-07T12:00:00Z"}"#,
            )
            .unwrap_or_else(|error| panic!("overflow proof should parse: {error}")),
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            RevocationFreshnessPolicy::new(120, 900)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        );

        let result = bundle.insert_revocation_proof(overflow);

        assert_eq!(
            result,
            Err(TrustGrantError::CollectionTooLarge {
                field: "proof_bundle.revocation_proofs",
                max_items: MAX_BUNDLE_REVOCATION_PROOFS,
            })
        );
    }

    #[test]
    fn proof_bundle_rejects_conflicting_revocation_proof() {
        let first = BundleRevocationProof::new(
            parse_revocation_status_proof(
                r#"{"trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000","status":"active","checked_at":"2026-04-07T12:00:00Z"}"#,
            )
            .unwrap_or_else(|error| panic!("first revocation proof should parse: {error}")),
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            RevocationFreshnessPolicy::new(120, 900)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        );
        let second = BundleRevocationProof::new(
            parse_revocation_status_proof(
                r#"{"trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000","status":"revoked","checked_at":"2026-04-07T12:00:00Z"}"#,
            )
            .unwrap_or_else(|error| panic!("second revocation proof should parse: {error}")),
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            RevocationFreshnessPolicy::new(120, 900)
                .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
        );

        let mut bundle = TrustGrantProofBundle::new();
        bundle
            .insert_revocation_proof(first)
            .unwrap_or_else(|error| panic!("first insert should succeed: {error}"));

        let result = bundle.insert_revocation_proof(second);

        assert_eq!(
            result,
            Err(TrustGrantError::ConflictingProofBundleEntry(
                "revocation_proof",
            ))
        );
    }

    #[test]
    fn proof_bundle_rejects_too_many_transition_chains() {
        let mut bundle = TrustGrantProofBundle::new();
        let empty_chain = Vec::<RawOwnershipTransitionDocument>::new();

        for index in 0..MAX_BUNDLE_OWNERSHIP_TRANSITION_CHAINS {
            let trustgrant_id = format!("tg_123e4567-e89b-12d3-a456-42661417{index:04}")
                .parse()
                .unwrap_or_else(|error| panic!("trustgrant id should parse: {error}"));
            bundle
                .insert_ownership_transition_chain(trustgrant_id, empty_chain.clone())
                .unwrap_or_else(|error| panic!("insert should succeed: {error}"));
        }

        let overflow_id = "tg_123e4567-e89b-12d3-a456-426614179999"
            .parse()
            .unwrap_or_else(|error| panic!("overflow trustgrant id should parse: {error}"));
        let result = bundle.insert_ownership_transition_chain(overflow_id, empty_chain);

        assert_eq!(
            result,
            Err(TrustGrantError::CollectionTooLarge {
                field: "proof_bundle.ownership_transition_chains",
                max_items: MAX_BUNDLE_OWNERSHIP_TRANSITION_CHAINS,
            })
        );
    }

    #[test]
    fn proof_bundle_rejects_conflicting_transition_chain() {
        let trustgrant_id: trustgrant_domain::TrustGrantId =
            "tg_123e4567-e89b-12d3-a456-426614174100"
                .parse()
                .unwrap_or_else(|error| panic!("trustgrant id should parse: {error}"));
        let first = vec![
            RawOwnershipTransitionDocument::parse_json_str(
                r#"{
                  "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174200",
                  "version":0,
                  "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174201",
                  "revision":1,
                  "supersedes_transition_id":null,
                  "origin_authority":"https://origin.example.com",
                  "from_authority":"https://origin.example.com",
                  "to_authority":"https://successor.example.com",
                  "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":null}],"deny":null}}},
                  "global_constraints":null,
                  "effective_at":"2026-04-07T12:00:00Z",
                  "predecessor_signature":{"key_id":"root-key-1","signature":"predecessor-signature-a"},
                  "successor_acceptance":{"accepted_at":"2026-04-07T11:00:00Z","key_id":"successor-key-1","signature":"successor-signature-a"}
                }"#,
            )
            .unwrap_or_else(|error| panic!("first transition should parse: {error}")),
        ];
        let second = vec![
            RawOwnershipTransitionDocument::parse_json_str(
                r#"{
                  "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174200",
                  "version":0,
                  "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174201",
                  "revision":1,
                  "supersedes_transition_id":null,
                  "origin_authority":"https://origin.example.com",
                  "from_authority":"https://origin.example.com",
                  "to_authority":"https://successor.example.com",
                  "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":null}],"deny":null}}},
                  "global_constraints":null,
                  "effective_at":"2026-04-07T12:00:00Z",
                  "predecessor_signature":{"key_id":"root-key-1","signature":"predecessor-signature-b"},
                  "successor_acceptance":{"accepted_at":"2026-04-07T11:00:00Z","key_id":"successor-key-1","signature":"successor-signature-b"}
                }"#,
            )
            .unwrap_or_else(|error| panic!("second transition should parse: {error}")),
        ];

        let mut bundle = TrustGrantProofBundle::new();
        bundle
            .insert_ownership_transition_chain(trustgrant_id, first)
            .unwrap_or_else(|error| panic!("first insert should succeed: {error}"));

        let result = bundle.insert_ownership_transition_chain(trustgrant_id, second);

        assert_eq!(
            result,
            Err(TrustGrantError::ConflictingProofBundleEntry(
                "ownership_transition_chain",
            ))
        );
    }

    #[test]
    fn proof_bundle_rejects_transition_chain_that_exceeds_chain_limit() {
        let mut bundle = TrustGrantProofBundle::new();
        let trustgrant_id = "tg_123e4567-e89b-12d3-a456-426614174100"
            .parse()
            .unwrap_or_else(|error| panic!("trustgrant id should parse: {error}"));
        let chain = (0..=MAX_OWNERSHIP_CHAIN_LENGTH)
            .map(|index| {
                RawOwnershipTransitionDocument::parse_json_str(&format!(
                    r#"{{
                      "transition_id":"tgt_123e4567-e89b-12d3-a456-42661417{index:04}",
                      "version":0,
                      "transition_series_id":"tgts_123e4567-e89b-12d3-a456-42661417{index:04}",
                      "revision":1,
                      "supersedes_transition_id":null,
                      "origin_authority":"https://origin.example.com",
                      "from_authority":"https://origin.example.com",
                      "to_authority":"https://successor.example.com",
                      "canonical_resource_scope":{{"types":{{"item":{{"all":false,"allow":[{{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":null}}],"deny":null}}}}}},
                      "global_constraints":null,
                      "effective_at":"2026-04-07T12:00:00Z",
                      "predecessor_signature":{{"key_id":"root-key-1","signature":"predecessor-signature"}},
                      "successor_acceptance":{{"accepted_at":"2026-04-07T11:00:00Z","key_id":"successor-key-1","signature":"successor-signature"}}
                    }}"#
                ))
                .unwrap_or_else(|error| panic!("transition should parse: {error}"))
            })
            .collect::<Vec<_>>();

        let result = bundle.insert_ownership_transition_chain(trustgrant_id, chain);

        assert_eq!(
            result,
            Err(TrustGrantError::CollectionTooLarge {
                field: "ownership_transition.chain",
                max_items: MAX_OWNERSHIP_CHAIN_LENGTH,
            })
        );
    }

    // ── with_* fluent builder tests ────────────────────────────────

    #[test]
    fn with_delegated_principal_document_adds_to_bundle() {
        let bundle = TrustGrantProofBundle::new()
            .with_discovery_document(
                parse_authority_discovery_document(TEST_DISCOVERY_JSON)
                    .unwrap_or_else(|error| panic!("discovery should parse: {error}")),
            )
            .unwrap_or_else(|error| panic!("with_discovery should succeed: {error}"))
            .with_delegated_principal_document(
                parse_delegated_principal_key_document(TEST_DELEGATED_PRINCIPAL_JSON)
                    .unwrap_or_else(|error| panic!("delegated should parse: {error}")),
            )
            .unwrap_or_else(|error| panic!("with_delegated should succeed: {error}"));

        let authority = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("authority id should be valid: {error}"));
        let key_id = KeyId::new("project-key-1")
            .unwrap_or_else(|error| panic!("key id should be valid: {error}"));
        let principal = ValidatedPrincipal::new(
            PrincipalKind::new("service")
                .unwrap_or_else(|error| panic!("kind should be valid: {error}")),
            PrincipalId::new("issuer-worker")
                .unwrap_or_else(|error| panic!("id should be valid: {error}")),
        );
        let ctx = test_context();

        let binding = bundle
            .as_sources()
            .discovery_source()
            .resolve_signer_binding(&authority, &key_id, Some(&principal), ctx);

        let binding =
            binding.unwrap_or_else(|error| panic!("delegated signer should resolve: {error}"));
        assert_eq!(binding.issuer_authority(), &authority);
        assert_eq!(binding.key_record().key_id(), &key_id);
        assert!(binding.delegated_principal().is_some());
    }

    #[test]
    fn with_ownership_transition_chain_adds_to_bundle() {
        let trustgrant_id: trustgrant_domain::TrustGrantId =
            "tg_123e4567-e89b-12d3-a456-426614174000"
                .parse()
                .unwrap_or_else(|error| panic!("trustgrant id should parse: {error}"));
        let chain = vec![
            RawOwnershipTransitionDocument::parse_json_str(
                r#"{
                  "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174200",
                  "version":0,
                  "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174201",
                  "revision":1,
                  "supersedes_transition_id":null,
                  "origin_authority":"https://origin.example.com",
                  "from_authority":"https://origin.example.com",
                  "to_authority":"https://successor.example.com",
                  "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":null}],"deny":null}}},
                  "global_constraints":null,
                  "effective_at":"2026-04-07T12:00:00Z",
                  "predecessor_signature":{"key_id":"origin-key-1","signature":"origin-signature"},
                  "successor_acceptance":{"accepted_at":"2026-04-07T11:30:00Z","key_id":"successor-key-1","signature":"successor-signature"}
                }"#,
            )
            .unwrap_or_else(|error| panic!("transition should parse: {error}")),
        ];

        let bundle = TrustGrantProofBundle::new()
            .with_ownership_transition_chain(trustgrant_id, chain)
            .unwrap_or_else(|error| {
                panic!("with_ownership_transition_chain should succeed: {error}")
            });

        let document = parse_test_document();
        let ctx = test_context();
        let resolved = bundle
            .as_sources()
            .ownership_source()
            .resolve_ownership_transition_chain(&document, ctx)
            .unwrap_or_else(|error| panic!("ownership chain should resolve: {error}"));
        assert_eq!(resolved.len(), 1);
        assert_eq!(
            resolved
                .first()
                .unwrap_or_else(|| panic!("expected at least one transition"))
                .transition_id,
            "tgt_123e4567-e89b-12d3-a456-426614174200"
        );
    }

    // ── Helper functions for trait implementation tests ─────────────

    use chrono::{TimeZone, Utc};
    use trustgrant_document::{
        RawTrustGrantDocument, ValidatedPrincipal, ValidatedTrustGrantDocument,
    };
    use trustgrant_domain::{AuthorityId, KeyId, PrincipalId, PrincipalKind};
    use trustgrant_ports::{
        AuthorityDiscoverySource, OwnershipTransitionProofSource, RevocationProofSource,
        VerificationContext,
    };

    const TEST_DISCOVERY_JSON: &str = r#"{
      "authority_id":"https://issuer.example.com",
      "keys":[
        {
          "key_id":"root-key-1",
          "algorithm":"ed25519",
          "public_key":"base64-root-public-key",
          "not_before":"2026-01-01T00:00:00Z",
          "not_after":"2027-01-01T00:00:00Z"
        }
      ],
      "signature_profile":{
        "format":"jcs+ed25519",
        "canonicalization":"RFC8785"
      },
      "delegation":{
        "principals_supported":true,
        "principal_key_endpoint":"https://issuer.example.com/.well-known/trustgrant/principals/{kind}/{id}"
      },
      "issued_at":"2026-04-07T12:00:00Z"
    }"#;

    const TEST_NO_DELEGATION_DISCOVERY_JSON: &str = r#"{
      "authority_id":"https://issuer.example.com",
      "keys":[
        {
          "key_id":"root-key-1",
          "algorithm":"ed25519",
          "public_key":"base64-root-public-key",
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

    const TEST_DELEGATED_PRINCIPAL_JSON: &str = r#"{
      "authority_id":"https://issuer.example.com",
      "principal":{"kind":"service","id":"issuer-worker"},
      "keys":[
        {
          "key_id":"project-key-1",
          "algorithm":"ed25519",
          "public_key":"base64-delegated-public-key",
          "not_before":"2026-01-01T00:00:00Z",
          "not_after":"2027-01-01T00:00:00Z",
          "revoked":false
        }
      ]
    }"#;

    const TEST_TRUSTGRANT_JSON: &str = r#"{
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
      "target_scope":{"all":true,"allow":null,"deny":null},
      "capabilities":{"recognize":true,"mint":false},
      "default_audience_scope":null,
      "resource_scope":{"types":{"item":{"all":true,"allow":null,"deny":null,"capabilities":{"recognize":true,"mint":false},"constraints":{"minting":{"max_total":null,"max_per_user":null},"audience_scope":null},"operations":{"all":false,"allow":["recognize"],"deny":null}}}},
      "global_constraints":null,
      "revocation":{"revocable":true,"revocation_endpoint":"https://issuer.example.com/revocation"},
      "issued_at":"2026-04-07T12:00:00Z",
      "signature":"base64-signature",
      "issuer_principal":null
    }"#;

    const TEST_REVOCATION_JSON: &str = r#"{
      "trustgrant_id":"tg_123e4567-e89b-12d3-a456-426614174000",
      "status":"active",
      "checked_at":"2026-04-07T12:00:00Z"
    }"#;

    fn test_context() -> VerificationContext {
        let ts = Utc
            .with_ymd_and_hms(2026, 4, 7, 12, 0, 0)
            .single()
            .unwrap_or_else(|| panic!("fixed timestamp should be valid"));
        VerificationContext::new(ts, trustgrant_ports::VerificationPosture::Online)
    }

    fn parse_test_document() -> ValidatedTrustGrantDocument {
        let raw = RawTrustGrantDocument::parse_json_str(TEST_TRUSTGRANT_JSON)
            .unwrap_or_else(|error| panic!("raw document should parse: {error}"));
        ValidatedTrustGrantDocument::try_from(raw)
            .unwrap_or_else(|error| panic!("validated document should succeed: {error}"))
    }

    // ── as_sources() tests ─────────────────────────────────────────

    #[test]
    fn as_sources_returns_verification_sources() {
        let bundle = TrustGrantProofBundle::new();
        let _sources = bundle.as_sources();
    }

    #[test]
    fn as_sources_all_three_providers_point_to_bundle() {
        let bundle = TrustGrantProofBundle::new();
        let sources = bundle.as_sources();

        // Verify all three sources resolve to the same bundle by testing
        // they exhibit the same error behavior for a missing authority.
        let authority = AuthorityId::new("https://missing.example.com")
            .unwrap_or_else(|error| panic!("authority id should be valid: {error}"));
        let key_id = KeyId::new("missing-key")
            .unwrap_or_else(|error| panic!("key id should be valid: {error}"));
        let ctx = test_context();

        let discovery_err = sources
            .discovery_source()
            .resolve_signer_binding(&authority, &key_id, None, ctx);
        assert_eq!(
            discovery_err,
            Err(TrustGrantError::MissingAuthorityDiscoveryDocument)
        );

        let document = parse_test_document();
        let signer_binding = trustgrant_discovery::ResolvedSignerBinding::new(
            authority,
            trustgrant_discovery::AuthorityKeyRecord::new(
                "root-key-1",
                "ed25519",
                "base64-key",
                Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
                    .single()
                    .unwrap_or_else(|| panic!("valid timestamp")),
                Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0)
                    .single()
                    .unwrap_or_else(|| panic!("valid timestamp")),
            )
            .unwrap_or_else(|e| panic!("authority key record should be valid: {e}")),
            trustgrant_discovery::SignatureProfile::new("jcs+ed25519", "RFC8785")
                .unwrap_or_else(|e| panic!("signature profile should be valid: {e}")),
            None,
        );

        let revocation_err =
            sources
                .revocation_source()
                .resolve_revocation_record(&document, &signer_binding, ctx);
        assert_eq!(revocation_err, Err(TrustGrantError::MissingRevocationProof));

        let ownership_err = sources
            .ownership_source()
            .resolve_ownership_transition_chain(&document, ctx);
        assert!(ownership_err.unwrap_or_default().is_empty());
    }

    // ── AuthorityDiscoverySource trait tests ────────────────────────

    #[test]
    fn authority_discovery_source_resolves_root_signer_binding() {
        let mut bundle = TrustGrantProofBundle::new();
        bundle
            .insert_discovery_document(
                parse_authority_discovery_document(TEST_DISCOVERY_JSON)
                    .unwrap_or_else(|error| panic!("discovery should parse: {error}")),
            )
            .unwrap_or_else(|error| panic!("discovery should insert: {error}"));

        let authority = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("authority id should be valid: {error}"));
        let key_id = KeyId::new("root-key-1")
            .unwrap_or_else(|error| panic!("key id should be valid: {error}"));
        let ctx = test_context();

        let binding = bundle.resolve_signer_binding(&authority, &key_id, None, ctx);

        let binding = binding.unwrap_or_else(|error| panic!("root signer should resolve: {error}"));
        assert_eq!(binding.issuer_authority(), &authority);
        assert_eq!(binding.key_record().key_id(), &key_id);
        assert!(binding.delegated_principal().is_none());
    }

    #[test]
    fn authority_discovery_source_resolves_delegated_signer_binding() {
        let mut bundle = TrustGrantProofBundle::new();
        bundle
            .insert_discovery_document(
                parse_authority_discovery_document(TEST_DISCOVERY_JSON)
                    .unwrap_or_else(|error| panic!("discovery should parse: {error}")),
            )
            .unwrap_or_else(|error| panic!("discovery should insert: {error}"));
        bundle
            .insert_delegated_principal_document(
                parse_delegated_principal_key_document(TEST_DELEGATED_PRINCIPAL_JSON)
                    .unwrap_or_else(|error| panic!("delegated should parse: {error}")),
            )
            .unwrap_or_else(|error| panic!("delegated should insert: {error}"));

        let authority = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("authority id should be valid: {error}"));
        let key_id = KeyId::new("project-key-1")
            .unwrap_or_else(|error| panic!("key id should be valid: {error}"));
        let principal = ValidatedPrincipal::new(
            PrincipalKind::new("service")
                .unwrap_or_else(|error| panic!("kind should be valid: {error}")),
            PrincipalId::new("issuer-worker")
                .unwrap_or_else(|error| panic!("id should be valid: {error}")),
        );
        let ctx = test_context();

        let binding = bundle.resolve_signer_binding(&authority, &key_id, Some(&principal), ctx);

        let binding =
            binding.unwrap_or_else(|error| panic!("delegated signer should resolve: {error}"));
        assert_eq!(binding.issuer_authority(), &authority);
        assert_eq!(binding.key_record().key_id(), &key_id);
        assert!(binding.delegated_principal().is_some());
    }

    #[test]
    fn authority_discovery_source_returns_error_when_discovery_document_missing() {
        let bundle = TrustGrantProofBundle::new();
        let authority = AuthorityId::new("https://missing.example.com")
            .unwrap_or_else(|error| panic!("authority id should be valid: {error}"));
        let key_id = KeyId::new("root-key-1")
            .unwrap_or_else(|error| panic!("key id should be valid: {error}"));
        let ctx = test_context();

        let result = bundle.resolve_signer_binding(&authority, &key_id, None, ctx);

        assert_eq!(
            result,
            Err(TrustGrantError::MissingAuthorityDiscoveryDocument)
        );
    }

    #[test]
    fn authority_discovery_source_returns_error_when_key_not_found() {
        let mut bundle = TrustGrantProofBundle::new();
        bundle
            .insert_discovery_document(
                parse_authority_discovery_document(TEST_DISCOVERY_JSON)
                    .unwrap_or_else(|error| panic!("discovery should parse: {error}")),
            )
            .unwrap_or_else(|error| panic!("discovery should insert: {error}"));

        let authority = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("authority id should be valid: {error}"));
        let key_id = KeyId::new("nonexistent-key")
            .unwrap_or_else(|error| panic!("key id should be valid: {error}"));
        let ctx = test_context();

        let result = bundle.resolve_signer_binding(&authority, &key_id, None, ctx);

        assert_eq!(result, Err(TrustGrantError::MissingSigningKey));
    }

    #[test]
    fn authority_discovery_source_returns_error_when_delegation_not_supported() {
        let mut bundle = TrustGrantProofBundle::new();
        bundle
            .insert_discovery_document(
                parse_authority_discovery_document(TEST_NO_DELEGATION_DISCOVERY_JSON)
                    .unwrap_or_else(|error| panic!("discovery should parse: {error}")),
            )
            .unwrap_or_else(|error| panic!("discovery should insert: {error}"));

        let authority = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("authority id should be valid: {error}"));
        let key_id = KeyId::new("root-key-1")
            .unwrap_or_else(|error| panic!("key id should be valid: {error}"));
        let principal = ValidatedPrincipal::new(
            PrincipalKind::new("service")
                .unwrap_or_else(|error| panic!("kind should be valid: {error}")),
            PrincipalId::new("issuer-worker")
                .unwrap_or_else(|error| panic!("id should be valid: {error}")),
        );
        let ctx = test_context();

        let result = bundle.resolve_signer_binding(&authority, &key_id, Some(&principal), ctx);

        assert_eq!(result, Err(TrustGrantError::DelegationNotSupported));
    }

    #[test]
    fn authority_discovery_source_returns_error_when_delegated_document_missing() {
        let mut bundle = TrustGrantProofBundle::new();
        bundle
            .insert_discovery_document(
                parse_authority_discovery_document(TEST_DISCOVERY_JSON)
                    .unwrap_or_else(|error| panic!("discovery should parse: {error}")),
            )
            .unwrap_or_else(|error| panic!("discovery should insert: {error}"));

        let authority = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("authority id should be valid: {error}"));
        let key_id = KeyId::new("project-key-1")
            .unwrap_or_else(|error| panic!("key id should be valid: {error}"));
        let principal = ValidatedPrincipal::new(
            PrincipalKind::new("service")
                .unwrap_or_else(|error| panic!("kind should be valid: {error}")),
            PrincipalId::new("missing-worker")
                .unwrap_or_else(|error| panic!("id should be valid: {error}")),
        );
        let ctx = test_context();

        let result = bundle.resolve_signer_binding(&authority, &key_id, Some(&principal), ctx);

        assert_eq!(
            result,
            Err(TrustGrantError::MissingDelegatedPrincipalDocument)
        );
    }

    // ── RevocationProofSource trait tests ───────────────────────────

    #[test]
    fn revocation_proof_source_resolves_revocation_record() {
        let mut bundle = TrustGrantProofBundle::new();
        bundle
            .insert_revocation_proof(BundleRevocationProof::new(
                parse_revocation_status_proof(TEST_REVOCATION_JSON)
                    .unwrap_or_else(|error| panic!("revocation proof should parse: {error}")),
                RevocationSourceKind::Api,
                ProofFinality::Observed,
                RevocationFreshnessPolicy::new(120, 900)
                    .unwrap_or_else(|error| panic!("policy should be valid: {error}")),
            ))
            .unwrap_or_else(|error| panic!("revocation proof should insert: {error}"));

        let document = parse_test_document();
        let authority = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("authority id should be valid: {error}"));
        let signer_binding = trustgrant_discovery::ResolvedSignerBinding::new(
            authority,
            trustgrant_discovery::AuthorityKeyRecord::new(
                "root-key-1",
                "ed25519",
                "base64-key",
                Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
                    .single()
                    .unwrap_or_else(|| panic!("valid timestamp")),
                Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0)
                    .single()
                    .unwrap_or_else(|| panic!("valid timestamp")),
            )
            .unwrap_or_else(|e| panic!("authority key record should be valid: {e}")),
            trustgrant_discovery::SignatureProfile::new("jcs+ed25519", "RFC8785")
                .unwrap_or_else(|e| panic!("signature profile should be valid: {e}")),
            None,
        );
        let ctx = test_context();

        let result = bundle.resolve_revocation_record(&document, &signer_binding, ctx);

        let record =
            result.unwrap_or_else(|error| panic!("revocation record should resolve: {error}"));
        assert_eq!(
            record.status(),
            trustgrant_revocation::RevocationStatus::Active
        );
    }

    #[test]
    fn revocation_proof_source_returns_error_when_proof_missing() {
        let bundle = TrustGrantProofBundle::new();
        let document = parse_test_document();
        let authority = AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("authority id should be valid: {error}"));
        let signer_binding = trustgrant_discovery::ResolvedSignerBinding::new(
            authority,
            trustgrant_discovery::AuthorityKeyRecord::new(
                "root-key-1",
                "ed25519",
                "base64-key",
                Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
                    .single()
                    .unwrap_or_else(|| panic!("valid timestamp")),
                Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0)
                    .single()
                    .unwrap_or_else(|| panic!("valid timestamp")),
            )
            .unwrap_or_else(|e| panic!("authority key record should be valid: {e}")),
            trustgrant_discovery::SignatureProfile::new("jcs+ed25519", "RFC8785")
                .unwrap_or_else(|e| panic!("signature profile should be valid: {e}")),
            None,
        );
        let ctx = test_context();

        let result = bundle.resolve_revocation_record(&document, &signer_binding, ctx);

        assert_eq!(result, Err(TrustGrantError::MissingRevocationProof));
    }

    // ── OwnershipTransitionProofSource trait tests ──────────────────

    #[test]
    fn ownership_transition_source_returns_empty_chain_when_no_chain_present() {
        let bundle = TrustGrantProofBundle::new();
        let document = parse_test_document();
        let ctx = test_context();

        let result = bundle.resolve_ownership_transition_chain(&document, ctx);

        let chain =
            result.unwrap_or_else(|error| panic!("ownership chain should resolve: {error}"));
        assert!(chain.is_empty());
    }

    #[test]
    fn ownership_transition_source_resolves_chain() {
        let mut bundle = TrustGrantProofBundle::new();
        let trustgrant_id: trustgrant_domain::TrustGrantId =
            "tg_123e4567-e89b-12d3-a456-426614174000"
                .parse()
                .unwrap_or_else(|error| panic!("trustgrant id should parse: {error}"));
        let chain = vec![
            RawOwnershipTransitionDocument::parse_json_str(
                r#"{
                  "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174200",
                  "version":0,
                  "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174201",
                  "revision":1,
                  "supersedes_transition_id":null,
                  "origin_authority":"https://origin.example.com",
                  "from_authority":"https://origin.example.com",
                  "to_authority":"https://successor.example.com",
                  "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":null}],"deny":null}}},
                  "global_constraints":null,
                  "effective_at":"2026-04-07T12:00:00Z",
                  "predecessor_signature":{"key_id":"origin-key-1","signature":"origin-signature"},
                  "successor_acceptance":{"accepted_at":"2026-04-07T11:30:00Z","key_id":"successor-key-1","signature":"successor-signature"}
                }"#,
            )
            .unwrap_or_else(|error| panic!("transition should parse: {error}")),
        ];
        bundle
            .insert_ownership_transition_chain(trustgrant_id, chain)
            .unwrap_or_else(|error| panic!("ownership chain should insert: {error}"));

        let document = parse_test_document();
        let ctx = test_context();

        let result = bundle.resolve_ownership_transition_chain(&document, ctx);

        let resolved_chain =
            result.unwrap_or_else(|error| panic!("ownership chain should resolve: {error}"));
        assert_eq!(resolved_chain.len(), 1);
        assert_eq!(
            resolved_chain
                .first()
                .unwrap_or_else(|| panic!("expected at least one transition"))
                .transition_id,
            "tgt_123e4567-e89b-12d3-a456-426614174200"
        );
    }

    #[test]
    fn ownership_transition_source_returns_chain_for_different_grant_when_no_match() {
        let mut bundle = TrustGrantProofBundle::new();
        let other_grant_id: trustgrant_domain::TrustGrantId =
            "tg_123e4567-e89b-12d3-a456-426614179999"
                .parse()
                .unwrap_or_else(|error| panic!("trustgrant id should parse: {error}"));
        let chain = vec![
            RawOwnershipTransitionDocument::parse_json_str(
                r#"{
                  "transition_id":"tgt_123e4567-e89b-12d3-a456-426614174200",
                  "version":0,
                  "transition_series_id":"tgts_123e4567-e89b-12d3-a456-426614174201",
                  "revision":1,
                  "supersedes_transition_id":null,
                  "origin_authority":"https://origin.example.com",
                  "from_authority":"https://origin.example.com",
                  "to_authority":"https://successor.example.com",
                  "canonical_resource_scope":{"types":{"item":{"all":false,"allow":[{"kind":"id","all":false,"values":["canonical_item_1"],"expressions":null}],"deny":null}}},
                  "global_constraints":null,
                  "effective_at":"2026-04-07T12:00:00Z",
                  "predecessor_signature":{"key_id":"origin-key-1","signature":"origin-signature"},
                  "successor_acceptance":{"accepted_at":"2026-04-07T11:30:00Z","key_id":"successor-key-1","signature":"successor-signature"}
                }"#,
            )
            .unwrap_or_else(|error| panic!("transition should parse: {error}")),
        ];
        bundle
            .insert_ownership_transition_chain(other_grant_id, chain)
            .unwrap_or_else(|error| panic!("ownership chain should insert: {error}"));

        let document = parse_test_document();
        let ctx = test_context();

        let result = bundle.resolve_ownership_transition_chain(&document, ctx);

        let resolved_chain =
            result.unwrap_or_else(|error| panic!("ownership chain should resolve: {error}"));
        assert!(resolved_chain.is_empty());
    }
}
