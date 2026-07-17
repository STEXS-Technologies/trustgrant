#![no_main]
use libfuzzer_sys::fuzz_target;
use trustgrant::{ProofFinality, RevocationSourceKind, VerificationPolicy, VerificationPosture};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Derive postures, finalities, and source kinds from fuzzer bytes
    let postures = [
        VerificationPosture::Online,
        VerificationPosture::Cached,
        VerificationPosture::Offline,
    ];

    let finalities = [
        ProofFinality::Unknown,
        ProofFinality::Observed,
        ProofFinality::TrustedSnapshot,
        ProofFinality::Finalized,
    ];

    let source_kinds = [
        RevocationSourceKind::Api,
        RevocationSourceKind::Snapshot,
        RevocationSourceKind::ProofBundle,
        RevocationSourceKind::ChainState,
        RevocationSourceKind::Other,
    ];

    // Use first byte to index into postures, second into finalities, third into source_kinds
    let posture_idx = (data[0] as usize) % postures.len();
    let finality_idx = if data.len() > 1 {
        (data[1] as usize) % finalities.len()
    } else {
        0
    };
    let source_idx = if data.len() > 2 {
        (data[2] as usize) % source_kinds.len()
    } else {
        0
    };

    let posture = postures[posture_idx];
    let finality = finalities[finality_idx];
    let source_kind = source_kinds[source_idx];

    // Build policy from posture — must never panic
    let policy = VerificationPolicy::for_posture(posture);

    // Test accepts_revocation_finality — must never panic
    let _accepts_finality = policy.accepts_revocation_finality(finality);

    // Test accepts_revocation_source_kind — must never panic
    let _accepts_source = policy.accepts_revocation_source_kind(source_kind);
});
