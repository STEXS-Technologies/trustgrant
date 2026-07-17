use std::borrow::Borrow;
use std::fmt::{Display, Formatter, Result as FmtResult};

use trustgrant_error::TrustGrantError;
use trustgrant_error::limits::{MAX_AUTHORITY_ID_BYTES, ensure_string_limit};

/// Identifies the URI scheme of an authority identifier.
///
/// # Variants
///
/// * `Https` — `https://` scheme (web-based authority).
/// * `Did` — `did:` scheme (decentralized identifier).
/// * `Chain` — `chain:` scheme (blockchain/ledger authority).
/// * `Other` — Any other explicitly-declared scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthorityScheme {
    /// `https://` scheme (web-based authority).
    Https,
    /// `did:` scheme (decentralized identifier).
    Did,
    /// `chain:` scheme (blockchain/ledger authority).
    Chain,
    /// Any other explicitly-declared scheme.
    Other,
}

/// A validated authority identifier with an explicit URI scheme.
///
/// Authority identifiers carry a mandatory scheme prefix (e.g. `https://`,
/// `did:`, `chain:`) and are normalized to lowercase for equality
/// comparisons.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorityId {
    value: String,
    scheme_end: usize,
    scheme: AuthorityScheme,
}

impl AuthorityId {
    /// Creates a validated authority identifier.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use trustgrant_domain::AuthorityId;
    ///
    /// let id = AuthorityId::new("https://issuer.example.com")
    ///     .expect("valid HTTPS authority");
    /// assert_eq!(id.scheme_name(), "https");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the identifier is empty, does not carry
    /// an explicit scheme, or contains disallowed whitespace/control
    /// characters.
    pub fn new(value: impl Into<String>) -> Result<Self, TrustGrantError> {
        let value = value.into();
        let trimmed = value.trim();

        if trimmed.is_empty() {
            return Err(TrustGrantError::EmptyAuthorityId);
        }

        ensure_string_limit("authority_id", trimmed, MAX_AUTHORITY_ID_BYTES)?;

        if let Some(character) = trimmed
            .chars()
            .find(|character| character.is_control() || character.is_whitespace())
        {
            return Err(TrustGrantError::InvalidAuthorityIdCharacter(character));
        }

        let lowercased = trimmed.to_lowercase();

        ensure_string_limit("authority_id", &lowercased, MAX_AUTHORITY_ID_BYTES)?;

        let scheme_end = lowercased
            .find(':')
            .ok_or(TrustGrantError::InvalidAuthorityIdMissingScheme)?;

        if scheme_end == 0 {
            return Err(TrustGrantError::InvalidAuthorityIdMissingScheme);
        }

        let scheme_name = &lowercased[..scheme_end];
        let scheme = if scheme_name.eq_ignore_ascii_case("https") {
            AuthorityScheme::Https
        } else if scheme_name.eq_ignore_ascii_case("did") {
            AuthorityScheme::Did
        } else if scheme_name.eq_ignore_ascii_case("chain") {
            AuthorityScheme::Chain
        } else {
            AuthorityScheme::Other
        };

        Ok(Self {
            value: lowercased,
            scheme_end,
            scheme,
        })
    }

    /// Authority identifier should be inspected or persisted.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Authority scheme should be inspectable without reparsing.
    #[must_use]
    pub const fn scheme(&self) -> AuthorityScheme {
        self.scheme
    }

    /// Authority scheme name should be inspectable without reparsing.
    #[must_use]
    pub fn scheme_name(&self) -> &str {
        &self.value[..self.scheme_end]
    }
}

impl Display for AuthorityId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str(self.as_str())
    }
}

impl AsRef<str> for AuthorityId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for AuthorityId {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

/// Tracks ownership state across grant transitions.
///
/// Carries the original (origin) authority and the current active owning
/// authority so that the evaluation engine can enforce owner-level checks
/// after ownership transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipAuthorityState {
    origin_authority: AuthorityId,
    active_owning_authority: AuthorityId,
}

impl OwnershipAuthorityState {
    /// Ownership authority state should be used for evaluation or persistence.
    #[must_use]
    pub const fn new(origin_authority: AuthorityId, active_owning_authority: AuthorityId) -> Self {
        Self {
            origin_authority,
            active_owning_authority,
        }
    }

    /// Origin authority is part of canonical resource identity.
    #[must_use]
    pub const fn origin_authority(&self) -> &AuthorityId {
        &self.origin_authority
    }

    /// Active owning authority is required for owner-level evaluation.
    #[must_use]
    pub const fn active_owning_authority(&self) -> &AuthorityId {
        &self.active_owning_authority
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use trustgrant_error::limits::MAX_AUTHORITY_ID_BYTES;

    use super::{AuthorityId, AuthorityScheme, OwnershipAuthorityState};

    #[test]
    fn authority_id_rejects_empty_values() {
        assert!(AuthorityId::new("").is_err());
        assert!(AuthorityId::new("   ").is_err());
    }

    #[test]
    fn authority_id_rejects_whitespace() {
        assert!(AuthorityId::new("authority example").is_err());
    }

    #[test]
    fn authority_id_rejects_empty_scheme() {
        assert!(AuthorityId::new(":authority").is_err());
    }

    #[test]
    fn authority_id_rejects_missing_scheme() {
        assert!(AuthorityId::new("authority-example").is_err());
    }

    #[test]
    fn authority_id_rejects_oversized_values() {
        let oversized = format!("https://{}", "a".repeat(MAX_AUTHORITY_ID_BYTES));

        assert!(AuthorityId::new(oversized).is_err());
    }

    #[test]
    fn authority_id_accepts_scheme_like_values() {
        let authority = match AuthorityId::new("https://authority.example.com") {
            Ok(value) => value,
            Err(error) => panic!("scheme-like authority ID should be valid: {error}"),
        };

        assert_eq!(authority.as_str(), "https://authority.example.com");
        assert_eq!(authority.scheme(), AuthorityScheme::Https);
        assert_eq!(authority.scheme_name(), "https");
    }

    #[test]
    fn authority_id_classifies_known_non_https_schemes() {
        let did = match AuthorityId::new("did:example:issuer") {
            Ok(value) => value,
            Err(error) => panic!("did authority should be valid: {error}"),
        };
        let chain = match AuthorityId::new("chain:ethereum:0x1234") {
            Ok(value) => value,
            Err(error) => panic!("chain authority should be valid: {error}"),
        };
        let custom = match AuthorityId::new("custom-scheme:issuer-123") {
            Ok(value) => value,
            Err(error) => panic!("custom authority should be valid: {error}"),
        };

        assert_eq!(did.scheme(), AuthorityScheme::Did);
        assert_eq!(chain.scheme(), AuthorityScheme::Chain);
        assert_eq!(custom.scheme(), AuthorityScheme::Other);
        assert_eq!(custom.scheme_name(), "custom-scheme");
    }

    #[test]
    fn authority_id_classifies_known_schemes_case_insensitively() {
        let https = match AuthorityId::new("HTTPS://authority.example.com") {
            Ok(value) => value,
            Err(error) => panic!("uppercase https authority should be valid: {error}"),
        };
        let did = match AuthorityId::new("DiD:example:issuer") {
            Ok(value) => value,
            Err(error) => panic!("mixed-case did authority should be valid: {error}"),
        };
        let chain = match AuthorityId::new("CHAIN:ethereum:0x1234") {
            Ok(value) => value,
            Err(error) => panic!("uppercase chain authority should be valid: {error}"),
        };

        assert_eq!(https.scheme(), AuthorityScheme::Https);
        assert_eq!(did.scheme(), AuthorityScheme::Did);
        assert_eq!(chain.scheme(), AuthorityScheme::Chain);
        assert_eq!(https.scheme_name(), "https");
        assert_eq!(did.scheme_name(), "did");
        assert_eq!(chain.scheme_name(), "chain");
    }

    #[test]
    fn authority_id_normalizes_case_for_equality() {
        let lower = match AuthorityId::new("https://audience.example.com") {
            Ok(value) => value,
            Err(error) => panic!("lowercase authority should be valid: {error}"),
        };
        let upper = match AuthorityId::new("HTTPS://AUDIENCE.EXAMPLE.COM") {
            Ok(value) => value,
            Err(error) => panic!("uppercase authority should be valid: {error}"),
        };
        let mixed = match AuthorityId::new("Https://Audience.Example.Com") {
            Ok(value) => value,
            Err(error) => panic!("mixed-case authority should be valid: {error}"),
        };

        assert_eq!(lower, upper);
        assert_eq!(lower, mixed);
        assert_eq!(upper, mixed);
        assert_eq!(lower.as_str(), "https://audience.example.com");
    }

    #[test]
    fn authority_id_display_format() {
        let id = AuthorityId::new("https://example.com")
            .unwrap_or_else(|e| panic!("AuthorityId::new failed: {e}"));
        assert_eq!(format!("{id}"), "https://example.com");
    }

    #[test]
    fn authority_id_as_ref_str() {
        let id = AuthorityId::new("https://example.com")
            .unwrap_or_else(|e| panic!("AuthorityId::new failed: {e}"));
        assert_eq!(id.as_ref(), "https://example.com");
    }

    #[test]
    fn ownership_state_keeps_both_authorities() {
        let origin = match AuthorityId::new("https://origin.example.com") {
            Ok(value) => value,
            Err(error) => panic!("origin authority should be valid: {error}"),
        };
        let active = match AuthorityId::new("https://active.example.com") {
            Ok(value) => value,
            Err(error) => panic!("active authority should be valid: {error}"),
        };
        let state = OwnershipAuthorityState::new(origin.clone(), active.clone());

        assert_eq!(state.origin_authority(), &origin);
        assert_eq!(state.active_owning_authority(), &active);
    }
}
