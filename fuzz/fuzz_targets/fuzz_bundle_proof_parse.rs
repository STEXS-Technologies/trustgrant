#![no_main]
use libfuzzer_sys::fuzz_target;

use trustgrant::{
    BundleRevocationProof, ProofFinality, RevocationFreshnessPolicy, RevocationSourceKind,
    TrustGrantId, TrustGrantProofBundle, document::RawOwnershipTransitionDocument,
    parse_authority_discovery_document, parse_delegated_principal_key_document,
    parse_revocation_status_proof,
};

// Fuzz the proof bundle assembly path by parsing random bytes as each
// supported document type and inserting into the bundle. Ensures that
// the builder methods never panic on any input.
fuzz_target!(|data: &[u8]| {
    let json_str = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Use the mutating insert_* API so the bundle reference remains valid
    // across all operations, avoiding move issues with the builder API.
    let mut bundle = TrustGrantProofBundle::new();

    // 1. Authority discovery document
    if let Ok(doc) = parse_authority_discovery_document(json_str) {
        let _ = bundle.insert_discovery_document(doc);
    }

    // 2. Delegated principal key document
    if let Ok(doc) = parse_delegated_principal_key_document(json_str) {
        let _ = bundle.insert_delegated_principal_document(doc);
    }

    // 3. Revocation status proof (wrapped in BundleRevocationProof)
    if let Ok(proof) = parse_revocation_status_proof(json_str) {
        let policy = match RevocationFreshnessPolicy::new(1, 3600) {
            Ok(p) => p,
            Err(_) => RevocationFreshnessPolicy::new(3600, 86400).unwrap(),
        };
        let bundle_proof = BundleRevocationProof::new(
            proof,
            RevocationSourceKind::Api,
            ProofFinality::Observed,
            policy,
        );
        let _ = bundle.insert_revocation_proof(bundle_proof);
    }

    // 4. Ownership transition document (raw parse then insert chain)
    if let Ok(raw_doc) = RawOwnershipTransitionDocument::parse_json_bytes(data) {
        let stub_id = TrustGrantId::generate();
        let _ = bundle.insert_ownership_transition_chain(stub_id, vec![raw_doc]);
    }
});
