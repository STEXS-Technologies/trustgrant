use std::borrow::Borrow;

use chrono::{DateTime, Utc};

use trustgrant_domain::{AuthorityId, KeyId, PrincipalId, PrincipalKind};
use trustgrant_error::TrustGrantError;
use trustgrant_error::limits::{
    MAX_ALGORITHM_NAME_BYTES, MAX_CANONICALIZATION_NAME_BYTES, MAX_PUBLIC_KEY_MATERIAL_BYTES,
    MAX_SIGNATURE_PROFILE_FORMAT_BYTES, ensure_string_limit,
};

/// A validated signature algorithm name (e.g. `ed25519`, `ecdsa-p256`).
///
/// Algorithm names are non-empty token strings with no whitespace or
/// control characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AlgorithmName(String);

impl AlgorithmName {
    /// Creates a validated signature algorithm name.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the value is empty after trimming.
    pub fn new(value: impl Into<String>) -> Result<Self, TrustGrantError> {
        let value = value.into();
        Ok(Self(
            normalize_non_empty_token("algorithm", &value, MAX_ALGORITHM_NAME_BYTES)?.to_owned(),
        ))
    }

    /// Algorithm name should be used during verification.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for AlgorithmName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for AlgorithmName {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

/// Validated raw public-key material (e.g. a base64-encoded key).
///
/// Unlike token types, control characters are accepted because key material
/// may be encoded in formats that include non-printable bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKeyMaterial(String);

impl PublicKeyMaterial {
    /// Creates validated public-key material.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the value is empty after trimming.
    pub fn new(value: impl Into<String>) -> Result<Self, TrustGrantError> {
        let value = value.into();
        Ok(Self(
            normalize_non_empty("public_key", &value, MAX_PUBLIC_KEY_MATERIAL_BYTES)?.to_owned(),
        ))
    }

    /// Public-key material should be forwarded to crypto adapters.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for PublicKeyMaterial {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for PublicKeyMaterial {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

/// A validated signature-profile format name (e.g. `jcs+ed25519`).
///
/// Format names are non-empty token strings with no whitespace or control
/// characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignatureFormat(String);

impl SignatureFormat {
    /// Creates a validated signature-profile format name.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the value is empty after trimming.
    pub fn new(value: impl Into<String>) -> Result<Self, TrustGrantError> {
        let value = value.into();
        Ok(Self(
            normalize_non_empty_token(
                "signature_profile.format",
                &value,
                MAX_SIGNATURE_PROFILE_FORMAT_BYTES,
            )?
            .to_owned(),
        ))
    }

    /// Signature-profile format should be inspected by adapters.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for SignatureFormat {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for SignatureFormat {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

/// A validated canonicalization-profile name (e.g. `RFC8785`).
///
/// Canonicalization names are non-empty token strings with no whitespace or
/// control characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalizationName(String);

impl CanonicalizationName {
    /// Creates a validated canonicalization-profile name.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the value is empty after trimming.
    pub fn new(value: impl Into<String>) -> Result<Self, TrustGrantError> {
        let value = value.into();
        Ok(Self(
            normalize_non_empty_token(
                "signature_profile.canonicalization",
                &value,
                MAX_CANONICALIZATION_NAME_BYTES,
            )?
            .to_owned(),
        ))
    }

    /// Canonicalization name should be inspected during verification.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for CanonicalizationName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for CanonicalizationName {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureProfile {
    format: SignatureFormat,
    canonicalization: CanonicalizationName,
}

impl SignatureProfile {
    /// Creates one validated signature profile.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when one of the string components is empty
    /// after trimming.
    pub fn new(
        format: impl Into<String>,
        canonicalization: impl Into<String>,
    ) -> Result<Self, TrustGrantError> {
        Ok(Self {
            format: SignatureFormat::new(format)?,
            canonicalization: CanonicalizationName::new(canonicalization)?,
        })
    }

    /// Signature format participates in verifier dispatch.
    pub const fn format(&self) -> &SignatureFormat {
        &self.format
    }

    /// Canonicalization participates in payload verification.
    #[must_use]
    pub const fn canonicalization(&self) -> &CanonicalizationName {
        &self.canonicalization
    }
}

/// A validated signing-key record from an authority discovery document.
///
/// Contains the key identifier, algorithm, public-key material, and the
/// time window during which the key is valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityKeyRecord {
    key_id: KeyId,
    algorithm: AlgorithmName,
    public_key: PublicKeyMaterial,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

impl AuthorityKeyRecord {
    /// Creates one validated authority signing-key record.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when string fields are invalid or the key
    /// validity window is inverted.
    pub fn new(
        key_id: impl Into<String>,
        algorithm: impl Into<String>,
        public_key: impl Into<String>,
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
    ) -> Result<Self, TrustGrantError> {
        if not_before > not_after {
            return Err(TrustGrantError::InvalidKeyValidityWindow);
        }

        Ok(Self {
            key_id: KeyId::new(key_id)?,
            algorithm: AlgorithmName::new(algorithm)?,
            public_key: PublicKeyMaterial::new(public_key)?,
            not_before,
            not_after,
        })
    }

    /// Key id participates in key selection.
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// Algorithm participates in verifier dispatch.
    #[must_use]
    pub const fn algorithm(&self) -> &AlgorithmName {
        &self.algorithm
    }

    /// Public-key material participates in signature verification.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKeyMaterial {
        &self.public_key
    }

    /// Not_before participates in key-validity checks.
    #[must_use]
    pub const fn not_before(&self) -> DateTime<Utc> {
        self.not_before
    }

    /// Not_after participates in key-validity checks.
    #[must_use]
    pub const fn not_after(&self) -> DateTime<Utc> {
        self.not_after
    }

    /// Signature verification must know whether a key is active.
    #[must_use]
    pub fn is_active_at(&self, timestamp: DateTime<Utc>) -> bool {
        timestamp >= self.not_before && timestamp <= self.not_after
    }
}

/// A reference to a delegated principal (kind + id) within an authority's
/// delegation system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedPrincipalRef {
    kind: PrincipalKind,
    id: PrincipalId,
}

impl DelegatedPrincipalRef {
    /// Creates one delegated-principal reference.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the principal kind or id is empty
    /// after trimming.
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Result<Self, TrustGrantError> {
        Ok(Self {
            kind: PrincipalKind::new(kind)?,
            id: PrincipalId::new(id)?,
        })
    }

    /// Principal kind participates in signer attribution.
    pub const fn kind(&self) -> &PrincipalKind {
        &self.kind
    }

    /// Principal id participates in signer attribution.
    #[must_use]
    pub const fn id(&self) -> &PrincipalId {
        &self.id
    }
}

/// The resolved signer binding after authority discovery.
///
/// Collapses the issuer authority, key record, signature profile, and
/// optional delegated-principal reference into a single verification
/// input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSignerBinding {
    issuer_authority: AuthorityId,
    key_record: AuthorityKeyRecord,
    signature_profile: SignatureProfile,
    delegated_principal: Option<DelegatedPrincipalRef>,
}

impl ResolvedSignerBinding {
    /// Creates one resolved signer binding for pipeline verification.
    ///
    /// This is the current TrustGrant core's signer-proof normalization
    /// boundary: richer signer models from deployment profiles must be
    /// collapsed into one effective binding before verification enters the
    /// core.
    #[must_use]
    pub const fn new(
        issuer_authority: AuthorityId,
        key_record: AuthorityKeyRecord,
        signature_profile: SignatureProfile,
        delegated_principal: Option<DelegatedPrincipalRef>,
    ) -> Self {
        Self {
            issuer_authority,
            key_record,
            signature_profile,
            delegated_principal,
        }
    }

    /// Issuer authority participates in trust and signature checks.
    #[must_use]
    pub const fn issuer_authority(&self) -> &AuthorityId {
        &self.issuer_authority
    }

    /// Resolved key record participates in verification.
    #[must_use]
    pub const fn key_record(&self) -> &AuthorityKeyRecord {
        &self.key_record
    }

    /// Signature profile participates in canonical verification.
    #[must_use]
    pub const fn signature_profile(&self) -> &SignatureProfile {
        &self.signature_profile
    }

    /// Delegated principal may participate in signer attribution.
    #[must_use]
    pub const fn delegated_principal(&self) -> Option<&DelegatedPrincipalRef> {
        self.delegated_principal.as_ref()
    }
}

fn normalize_non_empty<'value>(
    field_name: &'static str,
    value: &'value str,
    max_bytes: usize,
) -> Result<&'value str, TrustGrantError> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(TrustGrantError::EmptyStringField(field_name));
    }

    ensure_string_limit(field_name, trimmed, max_bytes)?;

    Ok(trimmed)
}

fn normalize_non_empty_token<'value>(
    field_name: &'static str,
    value: &'value str,
    max_bytes: usize,
) -> Result<&'value str, TrustGrantError> {
    let trimmed = normalize_non_empty(field_name, value, max_bytes)?;

    if let Some(character) = trimmed
        .chars()
        .find(|character| character.is_control() || character.is_whitespace())
    {
        return Err(TrustGrantError::InvalidStringFieldCharacter {
            field: field_name,
            character,
        });
    }

    Ok(trimmed)
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use std::borrow::Borrow;

    use chrono::{TimeZone, Utc};

    use super::{
        AlgorithmName, AuthorityKeyRecord, CanonicalizationName, DelegatedPrincipalRef,
        PublicKeyMaterial, ResolvedSignerBinding, SignatureFormat, SignatureProfile,
    };
    use trustgrant_domain::AuthorityId;
    use trustgrant_error::TrustGrantError;
    use trustgrant_error::limits::{
        MAX_ALGORITHM_NAME_BYTES, MAX_CANONICALIZATION_NAME_BYTES, MAX_PUBLIC_KEY_MATERIAL_BYTES,
        MAX_SIGNATURE_PROFILE_FORMAT_BYTES,
    };

    #[test]
    fn authority_key_record_rejects_inverted_validity_window() {
        let result = AuthorityKeyRecord::new(
            "root-key-1",
            "ed25519",
            "base64-public-key",
            fixed_timestamp(2026, 4, 8, 12, 0, 0),
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
        );

        assert!(result.is_err());
    }

    #[test]
    fn resolved_signer_binding_keeps_key_and_profile() {
        let binding = ResolvedSignerBinding::new(
            match AuthorityId::new("https://issuer.example.com") {
                Ok(value) => value,
                Err(error) => panic!("authority should be valid: {error}"),
            },
            match AuthorityKeyRecord::new(
                "root-key-1",
                "ed25519",
                "base64-public-key",
                fixed_timestamp(2026, 4, 7, 12, 0, 0),
                fixed_timestamp(2026, 4, 8, 12, 0, 0),
            ) {
                Ok(value) => value,
                Err(error) => panic!("key record should be valid: {error}"),
            },
            match SignatureProfile::new("jcs+ed25519", "RFC8785") {
                Ok(value) => value,
                Err(error) => panic!("profile should be valid: {error}"),
            },
            None,
        );

        assert_eq!(binding.key_record().key_id().as_str(), "root-key-1");
        assert_eq!(
            binding.signature_profile().canonicalization().as_str(),
            "RFC8785"
        );
        assert!(
            binding
                .key_record()
                .is_active_at(fixed_timestamp(2026, 4, 7, 18, 0, 0))
        );
    }

    #[test]
    fn authority_key_record_rejects_control_characters_in_algorithm() {
        let result = AuthorityKeyRecord::new(
            "root-key-1",
            "ed25519\nv2",
            "base64-public-key",
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            fixed_timestamp(2026, 4, 8, 12, 0, 0),
        );

        assert!(result.is_err());
    }

    #[test]
    fn authority_key_record_rejects_oversized_public_key_material() {
        let result = AuthorityKeyRecord::new(
            "root-key-1",
            "ed25519",
            "a".repeat(MAX_PUBLIC_KEY_MATERIAL_BYTES + 1),
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            fixed_timestamp(2026, 4, 8, 12, 0, 0),
        );

        assert!(result.is_err());
    }

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

    // ============================================================
    // AlgorithmName – individual constructor edge-case tests
    // ============================================================

    #[test]
    fn algorithm_name_valid_construction() {
        let alg = match AlgorithmName::new("ed25519") {
            Ok(value) => value,
            Err(error) => panic!("should be valid: {error}"),
        };
        assert_eq!(alg.as_str(), "ed25519");
    }

    #[test]
    fn algorithm_name_trims_and_accepts_leading_trailing_whitespace() {
        let alg = match AlgorithmName::new("  ed25519  ") {
            Ok(value) => value,
            Err(error) => panic!("should trim and be valid: {error}"),
        };
        assert_eq!(alg.as_str(), "ed25519");
    }

    #[test]
    fn algorithm_name_rejects_empty_string() {
        let result = AlgorithmName::new("");
        assert!(matches!(
            result,
            Err(TrustGrantError::EmptyStringField("algorithm"))
        ));
    }

    #[test]
    fn algorithm_name_rejects_whitespace_only() {
        let result = AlgorithmName::new("   ");
        assert!(matches!(
            result,
            Err(TrustGrantError::EmptyStringField("algorithm"))
        ));
    }

    #[test]
    fn algorithm_name_rejects_control_characters() {
        let result = AlgorithmName::new("ed25519\nv2");
        assert!(matches!(
            result,
            Err(TrustGrantError::InvalidStringFieldCharacter { .. })
        ));
    }

    #[test]
    fn algorithm_name_rejects_null_byte() {
        let result = AlgorithmName::new("ed25519\0v2");
        assert!(matches!(
            result,
            Err(TrustGrantError::InvalidStringFieldCharacter { .. })
        ));
    }

    #[test]
    fn algorithm_name_rejects_internal_whitespace() {
        let result = AlgorithmName::new("ed25519 v2");
        assert!(matches!(
            result,
            Err(TrustGrantError::InvalidStringFieldCharacter { .. })
        ));
    }

    #[test]
    fn algorithm_name_at_exact_length_limit() {
        let valid = "a".repeat(MAX_ALGORITHM_NAME_BYTES);
        let alg = match AlgorithmName::new(&valid) {
            Ok(value) => value,
            Err(error) => panic!("should be valid at limit: {error}"),
        };
        assert_eq!(alg.as_str(), &valid);
    }

    #[test]
    fn algorithm_name_rejects_one_over_length_limit() {
        let too_long = "a".repeat(MAX_ALGORITHM_NAME_BYTES + 1);
        let result = AlgorithmName::new(&too_long);
        assert!(matches!(result, Err(TrustGrantError::StringTooLong { .. })));
    }

    // ============================================================
    // PublicKeyMaterial – individual constructor edge-case tests
    // ============================================================

    #[test]
    fn public_key_material_valid_construction() {
        let pk = match PublicKeyMaterial::new("abc123base64") {
            Ok(value) => value,
            Err(error) => panic!("should be valid: {error}"),
        };
        assert_eq!(pk.as_str(), "abc123base64");
    }

    #[test]
    fn public_key_material_trims_whitespace() {
        let pk = match PublicKeyMaterial::new("  abc123  ") {
            Ok(value) => value,
            Err(error) => panic!("should trim and be valid: {error}"),
        };
        assert_eq!(pk.as_str(), "abc123");
    }

    #[test]
    fn public_key_material_rejects_empty_string() {
        let result = PublicKeyMaterial::new("");
        assert!(matches!(
            result,
            Err(TrustGrantError::EmptyStringField("public_key"))
        ));
    }

    #[test]
    fn public_key_material_rejects_whitespace_only() {
        let result = PublicKeyMaterial::new("   ");
        assert!(matches!(
            result,
            Err(TrustGrantError::EmptyStringField("public_key"))
        ));
    }

    #[test]
    fn public_key_material_accepts_control_characters() {
        // normalize_non_empty only checks emptiness and length; control
        // characters are not rejected for raw binary material.
        let pk = match PublicKeyMaterial::new("abc\tdef\nghi") {
            Ok(value) => value,
            Err(error) => panic!("control chars should be accepted: {error}"),
        };
        assert_eq!(pk.as_str(), "abc\tdef\nghi");
    }

    #[test]
    fn public_key_material_rejects_exceeding_length_limit() {
        let too_long = "a".repeat(MAX_PUBLIC_KEY_MATERIAL_BYTES + 1);
        let result = PublicKeyMaterial::new(&too_long);
        assert!(matches!(result, Err(TrustGrantError::StringTooLong { .. })));
    }

    // ============================================================
    // SignatureFormat – individual constructor edge-case tests
    // ============================================================

    #[test]
    fn signature_format_valid_construction() {
        let fmt = match SignatureFormat::new("jcs+ed25519") {
            Ok(value) => value,
            Err(error) => panic!("should be valid: {error}"),
        };
        assert_eq!(fmt.as_str(), "jcs+ed25519");
    }

    #[test]
    fn signature_format_rejects_empty_string() {
        let result = SignatureFormat::new("");
        assert!(matches!(
            result,
            Err(TrustGrantError::EmptyStringField(
                "signature_profile.format"
            ))
        ));
    }

    #[test]
    fn signature_format_rejects_whitespace_only() {
        let result = SignatureFormat::new("   ");
        assert!(matches!(
            result,
            Err(TrustGrantError::EmptyStringField(
                "signature_profile.format"
            ))
        ));
    }

    #[test]
    fn signature_format_rejects_control_characters() {
        let result = SignatureFormat::new("jcs\ned25519");
        assert!(matches!(
            result,
            Err(TrustGrantError::InvalidStringFieldCharacter { .. })
        ));
    }

    #[test]
    fn signature_format_at_exact_length_limit() {
        let valid = "f".repeat(MAX_SIGNATURE_PROFILE_FORMAT_BYTES);
        let fmt = match SignatureFormat::new(&valid) {
            Ok(value) => value,
            Err(error) => panic!("should be valid at limit: {error}"),
        };
        assert_eq!(fmt.as_str(), &valid);
    }

    #[test]
    fn signature_format_rejects_one_over_length_limit() {
        let too_long = "f".repeat(MAX_SIGNATURE_PROFILE_FORMAT_BYTES + 1);
        let result = SignatureFormat::new(&too_long);
        assert!(matches!(result, Err(TrustGrantError::StringTooLong { .. })));
    }

    // ============================================================
    // CanonicalizationName – individual constructor edge-case tests
    // ============================================================

    #[test]
    fn canonicalization_name_valid_construction() {
        let name = match CanonicalizationName::new("RFC8785") {
            Ok(value) => value,
            Err(error) => panic!("should be valid: {error}"),
        };
        assert_eq!(name.as_str(), "RFC8785");
    }

    #[test]
    fn canonicalization_name_rejects_empty_string() {
        let result = CanonicalizationName::new("");
        assert!(matches!(
            result,
            Err(TrustGrantError::EmptyStringField(
                "signature_profile.canonicalization"
            ))
        ));
    }

    #[test]
    fn canonicalization_name_rejects_whitespace_only() {
        let result = CanonicalizationName::new("   ");
        assert!(matches!(
            result,
            Err(TrustGrantError::EmptyStringField(
                "signature_profile.canonicalization"
            ))
        ));
    }

    #[test]
    fn canonicalization_name_rejects_control_characters() {
        let result = CanonicalizationName::new("RFC8785\nv2");
        assert!(matches!(
            result,
            Err(TrustGrantError::InvalidStringFieldCharacter { .. })
        ));
    }

    #[test]
    fn canonicalization_name_at_exact_length_limit() {
        let valid = "c".repeat(MAX_CANONICALIZATION_NAME_BYTES);
        let name = match CanonicalizationName::new(&valid) {
            Ok(value) => value,
            Err(error) => panic!("should be valid at limit: {error}"),
        };
        assert_eq!(name.as_str(), &valid);
    }

    #[test]
    fn canonicalization_name_rejects_one_over_length_limit() {
        let too_long = "c".repeat(MAX_CANONICALIZATION_NAME_BYTES + 1);
        let result = CanonicalizationName::new(&too_long);
        assert!(matches!(result, Err(TrustGrantError::StringTooLong { .. })));
    }

    // ============================================================
    // SignatureProfile – composite constructor edge-case tests
    // ============================================================

    #[test]
    fn signature_profile_valid_construction() {
        let profile = match SignatureProfile::new("jcs+ed25519", "RFC8785") {
            Ok(value) => value,
            Err(error) => panic!("should be valid: {error}"),
        };
        assert_eq!(profile.format().as_str(), "jcs+ed25519");
        assert_eq!(profile.canonicalization().as_str(), "RFC8785");
    }

    #[test]
    fn signature_profile_rejects_empty_format_name() {
        let result = SignatureProfile::new("", "RFC8785");
        assert!(matches!(
            result,
            Err(TrustGrantError::EmptyStringField(
                "signature_profile.format"
            ))
        ));
    }

    #[test]
    fn signature_profile_rejects_empty_canonicalization_name() {
        let result = SignatureProfile::new("jcs+ed25519", "");
        assert!(matches!(
            result,
            Err(TrustGrantError::EmptyStringField(
                "signature_profile.canonicalization"
            ))
        ));
    }

    #[test]
    fn signature_profile_rejects_both_empty() {
        let result = SignatureProfile::new("", "");
        assert!(result.is_err());
    }

    // ============================================================
    // DelegatedPrincipalRef – composite constructor edge-case tests
    // ============================================================

    #[test]
    fn delegated_principal_ref_valid_construction() {
        let dp = match DelegatedPrincipalRef::new("user", "alice") {
            Ok(value) => value,
            Err(error) => panic!("should be valid: {error}"),
        };
        assert_eq!(dp.kind().as_str(), "user");
        assert_eq!(dp.id().as_str(), "alice");
    }

    #[test]
    fn delegated_principal_ref_rejects_invalid_kind() {
        let result = DelegatedPrincipalRef::new("", "alice");
        assert!(matches!(
            result,
            Err(TrustGrantError::EmptyStringField("issuer_principal.kind"))
        ));
    }

    #[test]
    fn delegated_principal_ref_rejects_invalid_id() {
        let result = DelegatedPrincipalRef::new("user", "");
        assert!(matches!(
            result,
            Err(TrustGrantError::EmptyStringField("issuer_principal.id"))
        ));
    }

    #[test]
    fn delegated_principal_ref_rejects_both_invalid() {
        let result = DelegatedPrincipalRef::new("", "");
        assert!(result.is_err());
    }

    // ============================================================
    // AuthorityKeyRecord::is_active_at – boundary tests
    // ============================================================

    #[test]
    fn authority_key_record_is_active_at_exact_not_before() {
        let key = make_test_key_record();
        // At the exact not_before boundary the key should be active.
        assert!(key.is_active_at(key.not_before()));
    }

    #[test]
    fn authority_key_record_is_active_at_exact_not_after() {
        let key = make_test_key_record();
        // At the exact not_after boundary the key should be active.
        assert!(key.is_active_at(key.not_after()));
    }

    #[test]
    fn authority_key_record_is_inactive_just_before_not_before() {
        let key = make_test_key_record();
        let not_before = key.not_before();
        let just_before = make_fixed_timestamp_minus_1s(not_before);
        assert!(!key.is_active_at(just_before));
    }

    #[test]
    fn authority_key_record_is_inactive_just_after_not_after() {
        let key = make_test_key_record();
        let not_after = key.not_after();
        let just_after = make_fixed_timestamp_plus_1s(not_after);
        assert!(!key.is_active_at(just_after));
    }

    // ============================================================
    // AsRef<str> / Borrow<str> impls
    // ============================================================

    #[test]
    fn algorithm_name_as_ref_and_borrow() {
        let name = AlgorithmName::new("sha-256")
            .unwrap_or_else(|e| panic!("AlgorithmName::new failed: {e}"));
        assert_eq!(name.as_ref(), "sha-256");
        let borrowed: &str = name.borrow();
        assert_eq!(borrowed, "sha-256");
    }

    #[test]
    fn public_key_material_as_ref_and_borrow() {
        let pk = PublicKeyMaterial::new("base64-key")
            .unwrap_or_else(|e| panic!("PublicKeyMaterial::new failed: {e}"));
        assert_eq!(pk.as_ref(), "base64-key");
        let borrowed: &str = pk.borrow();
        assert_eq!(borrowed, "base64-key");
    }

    #[test]
    fn signature_format_as_ref_and_borrow() {
        let fmt = SignatureFormat::new("jcs+ed25519")
            .unwrap_or_else(|e| panic!("SignatureFormat::new failed: {e}"));
        assert_eq!(fmt.as_ref(), "jcs+ed25519");
        let borrowed: &str = fmt.borrow();
        assert_eq!(borrowed, "jcs+ed25519");
    }

    #[test]
    fn canonicalization_name_as_ref_and_borrow() {
        let name = CanonicalizationName::new("RFC8785")
            .unwrap_or_else(|e| panic!("CanonicalizationName::new failed: {e}"));
        assert_eq!(name.as_ref(), "RFC8785");
        let borrowed: &str = name.borrow();
        assert_eq!(borrowed, "RFC8785");
    }

    // ============================================================
    // SignatureFormat oversized value
    // ============================================================

    #[test]
    fn signature_format_rejects_oversized_values() {
        let oversized = "a".repeat(256);
        assert!(SignatureFormat::new(&oversized).is_err());
    }

    // ============================================================
    // AuthorityKeyRecord zero-width validity window
    // ============================================================

    #[test]
    fn authority_key_record_accepts_zero_width_validity_window() {
        // When not_before == not_after, the key is valid for exactly one
        // instant.
        let ts = fixed_timestamp(2026, 4, 7, 12, 0, 0);
        let key = AuthorityKeyRecord::new("root-key-1", "ed25519", "base64-key", ts, ts)
            .unwrap_or_else(|error| panic!("key should be valid: {error}"));

        assert!(key.is_active_at(ts));
        assert!(!key.is_active_at(make_fixed_timestamp_minus_1s(ts)));
        assert!(!key.is_active_at(make_fixed_timestamp_plus_1s(ts)));
    }

    // ---- is_active_at helpers ---------------------------------

    fn make_test_key_record() -> AuthorityKeyRecord {
        match AuthorityKeyRecord::new(
            "test-key",
            "ed25519",
            "base64-public-key",
            fixed_timestamp(2026, 4, 7, 12, 0, 0),
            fixed_timestamp(2026, 4, 8, 12, 0, 0),
        ) {
            Ok(value) => value,
            Err(error) => panic!("test key record should be valid: {error}"),
        }
    }

    /// Subtract one second from a fixed-style timestamp by rebuilding it.
    /// This avoids depending on chrono::Duration / TimeDelta arithmetic.
    fn make_fixed_timestamp_minus_1s(ts: chrono::DateTime<Utc>) -> chrono::DateTime<Utc> {
        use chrono::{Datelike, Timelike};
        let (y, m, d, h, min, s) = (
            ts.year(),
            ts.month(),
            ts.day(),
            ts.hour(),
            ts.minute(),
            ts.second(),
        );
        if s > 0 {
            fixed_timestamp(y, m, d, h, min, s.wrapping_sub(1))
        } else if min > 0 {
            fixed_timestamp(y, m, d, h, min.wrapping_sub(1), 59)
        } else if h > 0 {
            fixed_timestamp(y, m, d, h.wrapping_sub(1), 59, 59)
        } else {
            // Edge: wrap to previous day (not needed for our test data).
            fixed_timestamp(y, m, d.wrapping_sub(1), 23, 59, 59)
        }
    }

    fn make_fixed_timestamp_plus_1s(ts: chrono::DateTime<Utc>) -> chrono::DateTime<Utc> {
        use chrono::{Datelike, Timelike};
        let (y, m, d, h, min, s) = (
            ts.year(),
            ts.month(),
            ts.day(),
            ts.hour(),
            ts.minute(),
            ts.second(),
        );
        if s < 59 {
            fixed_timestamp(y, m, d, h, min, s.wrapping_add(1))
        } else if min < 59 {
            fixed_timestamp(y, m, d, h, min.wrapping_add(1), 0)
        } else if h < 23 {
            fixed_timestamp(y, m, d, h.wrapping_add(1), 0, 0)
        } else {
            fixed_timestamp(y, m, d.wrapping_add(1), 0, 0, 0)
        }
    }
}
