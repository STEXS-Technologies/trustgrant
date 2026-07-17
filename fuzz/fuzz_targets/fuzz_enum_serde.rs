#![no_main]
use libfuzzer_sys::fuzz_target;
use trustgrant::{
    OwnershipProofKind, ProofFinality, RevocationSourceKind, RevocationStatus, VerificationPosture,
};

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let s = input.as_ref();

    // Try deserializing each enum from the fuzzer string as JSON
    // This tests both valid roundtrips and unknown variant rejection

    // OwnershipProofKind
    if let Ok(value) = serde_json::from_str::<OwnershipProofKind>(&format!("\"{}\"", s)) {
        let serialized = serde_json::to_string(&value).unwrap();
        let reparsed: OwnershipProofKind = serde_json::from_str(&serialized).unwrap();
        assert_eq!(value, reparsed);
    }

    // ProofFinality
    if let Ok(value) = serde_json::from_str::<ProofFinality>(&format!("\"{}\"", s)) {
        let serialized = serde_json::to_string(&value).unwrap();
        let reparsed: ProofFinality = serde_json::from_str(&serialized).unwrap();
        assert_eq!(value, reparsed);
    }

    // RevocationStatus
    if let Ok(value) = serde_json::from_str::<RevocationStatus>(&format!("\"{}\"", s)) {
        let serialized = serde_json::to_string(&value).unwrap();
        let reparsed: RevocationStatus = serde_json::from_str(&serialized).unwrap();
        assert_eq!(value, reparsed);
    }

    // RevocationSourceKind
    if let Ok(value) = serde_json::from_str::<RevocationSourceKind>(&format!("\"{}\"", s)) {
        let serialized = serde_json::to_string(&value).unwrap();
        let reparsed: RevocationSourceKind = serde_json::from_str(&serialized).unwrap();
        assert_eq!(value, reparsed);
    }

    // VerificationPosture
    if let Ok(value) = serde_json::from_str::<VerificationPosture>(&format!("\"{}\"", s)) {
        let serialized = serde_json::to_string(&value).unwrap();
        let reparsed: VerificationPosture = serde_json::from_str(&serialized).unwrap();
        assert_eq!(value, reparsed);
    }
});
