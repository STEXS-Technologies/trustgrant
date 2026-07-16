#![no_main]
use libfuzzer_sys::fuzz_target;
use trustgrant::{
    ProofFinality, RevocationFreshnessPolicy, RevocationSourceKind,
    revocation::parse_revocation_status_proof,
};

fuzz_target!(|data: &[u8]| {
    let json_str = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Try parsing a revocation status proof
    let Ok(proof) = parse_revocation_status_proof(json_str) else {
        return;
    };

    let source_kinds = [
        RevocationSourceKind::Api,
        RevocationSourceKind::Snapshot,
        RevocationSourceKind::ProofBundle,
        RevocationSourceKind::ChainState,
        RevocationSourceKind::Other,
    ];

    let finalities = [
        ProofFinality::Unknown,
        ProofFinality::Observed,
        ProofFinality::TrustedSnapshot,
        ProofFinality::Finalized,
    ];

    // Use first two bytes to select source_kind and finality
    let source_idx = if !data.is_empty() {
        (data[0] as usize) % source_kinds.len()
    } else {
        0
    };
    let finality_idx = if data.len() > 1 {
        (data[1] as usize) % finalities.len()
    } else {
        0
    };

    let source_kind = source_kinds[source_idx];
    let finality = finalities[finality_idx];

    // Try various TTL combinations
    let ttl_pairs = [
        (1u64, 3600u64),
        (3600, 86400),
        (0, 1), // zero non_revoked_ttl — should error
        (1, 0), // zero max_stale — should error
        (u64::MAX, u64::MAX),
    ];

    for &(non_revoked, max_stale) in &ttl_pairs {
        if let Ok(policy) = RevocationFreshnessPolicy::new(non_revoked, max_stale) {
            // into_record must never panic — Result is fine
            let _ = proof.into_record(source_kind, finality, policy);
        }
    }
});
