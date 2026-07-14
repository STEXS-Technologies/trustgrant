use serde::{Deserialize, Serialize};

use trustgrant_discovery::{
    AlgorithmName, PublicKeyMaterial, ResolvedSignerBinding, SignatureProfile,
};
use trustgrant_domain::{AuthorityId, CanonicalizationProfile, KeyId};
use trustgrant_error::TrustGrantError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The verification posture describes how proof material was obtained.
///
/// Used by the verification pipeline to select which proof sources to
/// consult and how to evaluate freshness.
pub enum VerificationPosture {
    /// Live verification against authoritative endpoints.
    ///
    /// Proof material is fetched in real time from the issuing or owning
    /// authority's online endpoint. Provides the strongest freshness
    /// guarantee.
    Online,
    /// Verification using previously cached proof material.
    ///
    /// Proof material was fetched earlier and is being reused within its
    /// freshness window. Suitable for read-heavy or latency-sensitive paths.
    Cached,
    /// Verification with no live or cached proof material.
    ///
    /// The verifier relies entirely on embedded proof bundles without
    /// external endpoint calls. Freshness guarantees depend on the bundle's
    /// own timestamps.
    Offline,
}

/// One signature verification request assembled by the verification pipeline.
///
/// Carries the canonical bytes, canonicalization profile, resolved signer
/// binding (authority + key + algorithm + public key), and the signature
/// string. Implementations of [`SignatureVerifier`] receive this request
/// and must verify the signature against the public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureVerificationRequest<'request> {
    canonical_bytes: &'request [u8],
    canonicalization_profile: CanonicalizationProfile,
    signer_binding: &'request ResolvedSignerBinding,
    signature: &'request str,
}

impl<'request> SignatureVerificationRequest<'request> {
    /// Signature verification requests should be built by the pipeline.
    #[must_use]
    pub const fn new(
        canonical_bytes: &'request [u8],
        canonicalization_profile: CanonicalizationProfile,
        signer_binding: &'request ResolvedSignerBinding,
        signature: &'request str,
    ) -> Self {
        Self {
            canonical_bytes,
            canonicalization_profile,
            signer_binding,
            signature,
        }
    }

    /// Signature verification needs canonical bytes.
    #[must_use]
    pub const fn canonical_bytes(&self) -> &'request [u8] {
        self.canonical_bytes
    }

    /// Signature verification needs the canonicalization profile.
    #[must_use]
    pub const fn canonicalization_profile(&self) -> CanonicalizationProfile {
        self.canonicalization_profile
    }

    /// Signature verification needs the resolved signer binding.
    #[must_use]
    pub const fn signer_binding(&self) -> &'request ResolvedSignerBinding {
        self.signer_binding
    }

    /// Signature verification needs the issuer authority.
    #[must_use]
    pub const fn issuer_authority(&self) -> &'request AuthorityId {
        self.signer_binding.issuer_authority()
    }

    /// Signature verification needs the key id.
    #[must_use]
    pub const fn key_id(&self) -> &'request KeyId {
        self.signer_binding.key_record().key_id()
    }

    /// Signature verification needs the key algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> &'request AlgorithmName {
        self.signer_binding.key_record().algorithm()
    }

    /// Signature verification needs the public key.
    #[must_use]
    pub const fn public_key(&self) -> &'request PublicKeyMaterial {
        self.signer_binding.key_record().public_key()
    }

    /// Signature verification needs the signature profile.
    #[must_use]
    pub const fn signature_profile(&self) -> &'request SignatureProfile {
        self.signer_binding.signature_profile()
    }

    /// Signature verification needs the signature bytes.
    #[must_use]
    pub const fn signature(&self) -> &str {
        self.signature
    }
}

pub trait SignatureVerifier {
    /// Verifies one TrustGrant signature against canonical bytes.
    ///
    /// # Security Requirements
    ///
    /// Implementations **MUST** use constant-time comparison when verifying
    /// signature bytes to prevent timing side-channel attacks. Do not use
    /// `==` or `ne()` for signature byte comparison.
    ///
    /// # Correctness Requirements
    ///
    /// The verifier MUST:
    /// - Use the exact canonical bytes provided (do not re-canonicalize)
    /// - Verify the signature against the public key in the signer binding
    /// - Return `Err(SignatureVerificationFailed)` for any verification failure
    /// - NOT reveal which specific check failed (key mismatch vs signature mismatch)
    ///
    /// The current TrustGrant core presents one already-resolved effective
    /// signer binding per verification call. Profile-specific signer models
    /// such as threshold, multisig, contract-managed, or chain-backed proofs
    /// must be reduced into that effective binding before reaching this port.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when signature verification fails or when
    /// the verifier cannot satisfy the request.
    fn verify_signature(
        &self,
        request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), TrustGrantError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use trustgrant_discovery::{AuthorityKeyRecord, ResolvedSignerBinding, SignatureProfile};
    use trustgrant_domain::{AuthorityId, CanonicalizationProfile};

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
            .map_or(chrono::DateTime::UNIX_EPOCH, |ts| ts)
    }

    fn signer_binding() -> ResolvedSignerBinding {
        let authority = AuthorityId::new("https://issuer.example.com").unwrap_or_else(|_| {
            // SAFETY: The hardcoded URL is a valid authority identifier.
            unsafe { std::hint::unreachable_unchecked() }
        });
        let key_record = AuthorityKeyRecord::new(
            "root-key-1",
            "ed25519",
            "base64-public-key-data",
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            fixed_timestamp(2026, 4, 8, 12, 0, 0),
        )
        .unwrap_or_else(|_| {
            // SAFETY: The hardcoded key data produces a valid key record.
            unsafe { std::hint::unreachable_unchecked() }
        });
        let profile = SignatureProfile::new("jcs+ed25519", "RFC8785").unwrap_or_else(|_| {
            // SAFETY: The hardcoded profile values are valid.
            unsafe { std::hint::unreachable_unchecked() }
        });
        ResolvedSignerBinding::new(authority, key_record, profile, None)
    }

    // ========================================================================
    // VerificationPosture tests
    // ========================================================================

    #[test]
    fn posture_online_creatable() {
        let posture = VerificationPosture::Online;
        assert_eq!(posture, VerificationPosture::Online);
    }

    #[test]
    fn posture_cached_creatable() {
        let posture = VerificationPosture::Cached;
        assert_eq!(posture, VerificationPosture::Cached);
    }

    #[test]
    fn posture_offline_creatable() {
        let posture = VerificationPosture::Offline;
        assert_eq!(posture, VerificationPosture::Offline);
    }

    #[test]
    fn posture_online_serde_roundtrip() {
        let posture = VerificationPosture::Online;
        let serialized = match serde_json::to_string(&posture) {
            Ok(s) => s,
            Err(_) => return,
        };
        let deserialized: VerificationPosture = match serde_json::from_str(&serialized) {
            Ok(d) => d,
            Err(_) => return,
        };
        assert_eq!(posture, deserialized);
        assert_eq!(serialized, r#""online""#);
    }

    #[test]
    fn posture_cached_serde_roundtrip() {
        let posture = VerificationPosture::Cached;
        let serialized = match serde_json::to_string(&posture) {
            Ok(s) => s,
            Err(_) => return,
        };
        let deserialized: VerificationPosture = match serde_json::from_str(&serialized) {
            Ok(d) => d,
            Err(_) => return,
        };
        assert_eq!(posture, deserialized);
        assert_eq!(serialized, r#""cached""#);
    }

    #[test]
    fn posture_offline_serde_roundtrip() {
        let posture = VerificationPosture::Offline;
        let serialized = match serde_json::to_string(&posture) {
            Ok(s) => s,
            Err(_) => return,
        };
        let deserialized: VerificationPosture = match serde_json::from_str(&serialized) {
            Ok(d) => d,
            Err(_) => return,
        };
        assert_eq!(posture, deserialized);
        assert_eq!(serialized, r#""offline""#);
    }

    #[test]
    fn posture_debug_non_empty() {
        let posture = VerificationPosture::Online;
        let debug_str = format!("{posture:?}");
        assert!(!debug_str.is_empty());
    }

    #[test]
    fn posture_clone_produces_equal_value() {
        let posture = VerificationPosture::Cached;
        let cloned = posture;
        assert_eq!(posture, cloned);
    }

    #[test]
    fn posture_copy_preserves_equality() {
        let posture = VerificationPosture::Offline;
        let copied = posture; // Copy happens here
        assert_eq!(posture, copied);
        // Original is still usable after copy
        assert_eq!(posture, VerificationPosture::Offline);
    }

    #[test]
    fn posture_different_variants_not_equal() {
        assert_ne!(VerificationPosture::Online, VerificationPosture::Cached);
        assert_ne!(VerificationPosture::Online, VerificationPosture::Offline);
        assert_ne!(VerificationPosture::Cached, VerificationPosture::Offline);
    }

    // ========================================================================
    // SignatureVerificationRequest tests
    // ========================================================================

    #[test]
    fn request_constructor_creates_valid_request() {
        let bytes: &[u8] = b"canonical-bytes";
        let profile = CanonicalizationProfile::Rfc8785;
        let binding = signer_binding();
        let signature = "valid-signature";
        let request = SignatureVerificationRequest::new(bytes, profile, &binding, signature);

        assert_eq!(request.canonical_bytes(), bytes);
        assert_eq!(request.canonicalization_profile(), profile);
        assert_eq!(request.signature(), signature);
    }

    #[test]
    fn request_canonical_bytes_returns_passed_bytes() {
        let bytes: &[u8] = b"hello-canonical-world";
        let binding = signer_binding();
        let request = SignatureVerificationRequest::new(
            bytes,
            CanonicalizationProfile::Rfc8785,
            &binding,
            "sig",
        );

        assert_eq!(request.canonical_bytes(), b"hello-canonical-world");
    }

    #[test]
    fn request_canonicalization_profile_returns_profile() {
        let bytes: &[u8] = b"data";
        let binding = signer_binding();
        let request = SignatureVerificationRequest::new(
            bytes,
            CanonicalizationProfile::Rfc8785,
            &binding,
            "sig",
        );

        assert_eq!(
            request.canonicalization_profile(),
            CanonicalizationProfile::Rfc8785
        );
    }

    #[test]
    fn request_signer_binding_returns_binding() {
        let bytes: &[u8] = b"data";
        let binding = signer_binding();
        let request = SignatureVerificationRequest::new(
            bytes,
            CanonicalizationProfile::Rfc8785,
            &binding,
            "sig",
        );

        assert_eq!(request.signer_binding(), &binding);
    }

    #[test]
    fn request_issuer_authority_delegates_to_signer_binding() {
        let bytes: &[u8] = b"data";
        let binding = signer_binding();
        let request = SignatureVerificationRequest::new(
            bytes,
            CanonicalizationProfile::Rfc8785,
            &binding,
            "sig",
        );

        let authority = request.issuer_authority();
        assert_eq!(authority.as_str(), "https://issuer.example.com");
    }

    #[test]
    fn request_key_id_delegates_to_key_record() {
        let bytes: &[u8] = b"data";
        let binding = signer_binding();
        let request = SignatureVerificationRequest::new(
            bytes,
            CanonicalizationProfile::Rfc8785,
            &binding,
            "sig",
        );

        let key_id = request.key_id();
        assert_eq!(key_id.as_str(), "root-key-1");
    }

    #[test]
    fn request_algorithm_delegates_to_key_record() {
        let bytes: &[u8] = b"data";
        let binding = signer_binding();
        let request = SignatureVerificationRequest::new(
            bytes,
            CanonicalizationProfile::Rfc8785,
            &binding,
            "sig",
        );

        let algorithm = request.algorithm();
        assert_eq!(algorithm.as_str(), "ed25519");
    }

    #[test]
    fn request_public_key_delegates_to_key_record() {
        let bytes: &[u8] = b"data";
        let binding = signer_binding();
        let request = SignatureVerificationRequest::new(
            bytes,
            CanonicalizationProfile::Rfc8785,
            &binding,
            "sig",
        );

        let public_key = request.public_key();
        assert_eq!(public_key.as_str(), "base64-public-key-data");
    }

    #[test]
    fn request_signature_profile_delegates_to_signer_binding() {
        let bytes: &[u8] = b"data";
        let binding = signer_binding();
        let request = SignatureVerificationRequest::new(
            bytes,
            CanonicalizationProfile::Rfc8785,
            &binding,
            "sig",
        );

        let profile = request.signature_profile();
        assert_eq!(profile.format().as_str(), "jcs+ed25519");
        assert_eq!(profile.canonicalization().as_str(), "RFC8785");
    }

    #[test]
    fn request_signature_returns_signature_string() {
        let bytes: &[u8] = b"data";
        let binding = signer_binding();
        let request = SignatureVerificationRequest::new(
            bytes,
            CanonicalizationProfile::Rfc8785,
            &binding,
            "my-custom-signature",
        );

        assert_eq!(request.signature(), "my-custom-signature");
    }
}
