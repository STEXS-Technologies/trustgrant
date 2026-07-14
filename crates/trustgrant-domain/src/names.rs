use std::borrow::Borrow;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use trustgrant_error::TrustGrantError;
use trustgrant_error::limits::{
    MAX_KEY_ID_BYTES, MAX_OPERATION_NAME_BYTES, MAX_PRINCIPAL_ID_BYTES, MAX_PRINCIPAL_KIND_BYTES,
    MAX_RESOURCE_TYPE_NAME_BYTES, MAX_SELECTOR_KIND_BYTES, ensure_string_limit,
};

/// A validated operation name used in grant capability scopes.
///
/// Operation names are non-empty token strings (no whitespace or control
/// characters) subject to a maximum byte limit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OperationName(String);

impl OperationName {
    /// Creates a validated operation name.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the name is empty after trimming.
    pub fn new(value: impl Into<String>) -> Result<Self, TrustGrantError> {
        let value = value.into();
        Ok(Self(
            normalize_non_empty_token("operation", &value, MAX_OPERATION_NAME_BYTES)?.to_owned(),
        ))
    }

    #[must_use = "operation name should be inspected or matched"]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for OperationName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for OperationName {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

/// A validated custom (application-defined) operation name.
///
/// Custom operation names reserve the built-in capability names
/// (`recognize`, `mint`, `create`) and reject them at construction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CustomOperationName(OperationName);

impl CustomOperationName {
    /// Creates a validated custom operation name.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the name is empty or reuses a reserved
    /// built-in capability or operation name.
    pub fn new(value: impl Into<String>) -> Result<Self, TrustGrantError> {
        let operation = OperationName::new(value)?;

        if matches!(operation.as_str(), "recognize" | "mint" | "create") {
            return Err(TrustGrantError::ReservedOperationName);
        }

        Ok(Self(operation))
    }

    #[must_use = "custom operation name should be inspected or matched"]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    #[must_use = "wrapped operation name should be available for comparisons"]
    pub const fn operation_name(&self) -> &OperationName {
        &self.0
    }
}

impl AsRef<str> for CustomOperationName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for CustomOperationName {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

/// A validated resource type name.
///
/// Resource type names are non-empty token strings (no whitespace or control
/// characters) that identify the kind of resource a grant applies to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceTypeName(String);

impl ResourceTypeName {
    /// Creates a validated resource type name.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the name is empty after trimming.
    pub fn new(value: impl Into<String>) -> Result<Self, TrustGrantError> {
        let value = value.into();
        Ok(Self(
            normalize_non_empty_token("resource_type", &value, MAX_RESOURCE_TYPE_NAME_BYTES)?
                .to_owned(),
        ))
    }

    #[must_use = "resource type name should be inspected or matched"]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ResourceTypeName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for ResourceTypeName {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

/// A validated key identifier used to select a specific signing key.
///
/// Key identifiers are non-empty token strings (no whitespace or control
/// characters) that reference a key record in an authority discovery
/// document.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(String);

impl KeyId {
    /// Creates a validated key identifier.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the identifier is empty after trimming.
    pub fn new(value: impl Into<String>) -> Result<Self, TrustGrantError> {
        let value = value.into();
        Ok(Self(
            normalize_non_empty_token("key_id", &value, MAX_KEY_ID_BYTES)?.to_owned(),
        ))
    }

    #[must_use = "key identifier should be inspected or matched"]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for KeyId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for KeyId {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

/// A validated selector kind that classifies selector values into built-in
/// categories or user-defined groups.
///
/// Built-in kinds (`authority`, `namespace`, `actor`) are recognized
/// case-insensitively and provide fast O(1) lookup indices. User-defined
/// kinds are treated as opaque strings with case-sensitive equality.
#[derive(Debug, Clone)]
pub struct SelectorKind {
    classification: SelectorKindClassification,
    value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum SelectorKindClassification {
    Authority,
    Namespace,
    Actor,
    Other,
}

impl SelectorKind {
    /// Creates a validated selector kind.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use trustgrant_domain::SelectorKind;
    ///
    /// let authority = SelectorKind::new("authority")
    ///     .expect("built-in authority kind");
    /// assert_eq!(authority.kind_index(), Some(0));
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the kind is empty after trimming.
    pub fn new(value: impl Into<String>) -> Result<Self, TrustGrantError> {
        let value = value.into();
        let value =
            normalize_non_empty_token("selector.kind", &value, MAX_SELECTOR_KIND_BYTES)?.to_owned();

        Ok(Self {
            classification: SelectorKindClassification::from_normalized(&value),
            value,
        })
    }

    #[must_use = "selector kind should be inspected or matched"]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    #[must_use = "hot-path selector lookup should avoid redundant string equality when possible"]
    pub fn same_kind(&self, other: &Self) -> bool {
        match (self.classification, other.classification) {
            (SelectorKindClassification::Other, SelectorKindClassification::Other) => {
                self.value == other.value
            }
            (left, right) => left == right,
        }
    }

    /// Returns a fixed index for built-in selector kinds, or `None` for
    /// user-defined kinds.  The mapping is stable across the process lifetime:
    ///
    /// | Kind        | Index |
    /// |-------------|-------|
    /// | Authority   | 0     |
    /// | Namespace   | 1     |
    /// | Actor       | 2     |
    /// | Other       | None  |
    #[must_use = "selector kind index enables O(1) lookup in SelectorContext"]
    pub const fn kind_index(&self) -> Option<usize> {
        match self.classification {
            SelectorKindClassification::Authority => Some(0),
            SelectorKindClassification::Namespace => Some(1),
            SelectorKindClassification::Actor => Some(2),
            SelectorKindClassification::Other => None,
        }
    }
}

impl AsRef<str> for SelectorKind {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for SelectorKind {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq for SelectorKind {
    fn eq(&self, other: &Self) -> bool {
        self.same_kind(other)
    }
}

impl Eq for SelectorKind {}

impl PartialOrd for SelectorKind {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SelectorKind {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.classification.cmp(&other.classification) {
            Ordering::Equal => match self.classification {
                SelectorKindClassification::Other => self.value.cmp(&other.value),
                SelectorKindClassification::Authority
                | SelectorKindClassification::Namespace
                | SelectorKindClassification::Actor => Ordering::Equal,
            },
            ordering @ Ordering::Less | ordering @ Ordering::Greater => ordering,
        }
    }
}

impl Hash for SelectorKind {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.classification.hash(state);

        if self.classification == SelectorKindClassification::Other {
            self.value.hash(state);
        }
    }
}

impl SelectorKindClassification {
    fn from_normalized(value: &str) -> Self {
        match value.to_lowercase().as_str() {
            "authority" => Self::Authority,
            "namespace" => Self::Namespace,
            "actor" => Self::Actor,
            _ => Self::Other,
        }
    }
}

/// A validated principal kind that classifies the type of issuer principal
/// (e.g. `service`, `user`, `bot`).
///
/// Principal kinds are non-empty token strings with no whitespace or
/// control characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrincipalKind(String);

impl PrincipalKind {
    /// Creates a validated principal kind.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the kind is empty after trimming.
    pub fn new(value: impl Into<String>) -> Result<Self, TrustGrantError> {
        let value = value.into();
        Ok(Self(
            normalize_non_empty_token("issuer_principal.kind", &value, MAX_PRINCIPAL_KIND_BYTES)?
                .to_owned(),
        ))
    }

    #[must_use = "principal kind should be inspected or matched"]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for PrincipalKind {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for PrincipalKind {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

/// A validated principal identifier that uniquely identifies an issuer
/// principal within its kind.
///
/// Principal identifiers are non-empty token strings with no whitespace or
/// control characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrincipalId(String);

impl PrincipalId {
    /// Creates a validated principal identifier.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the identifier is empty after trimming.
    pub fn new(value: impl Into<String>) -> Result<Self, TrustGrantError> {
        let value = value.into();
        Ok(Self(
            normalize_non_empty_token("issuer_principal.id", &value, MAX_PRINCIPAL_ID_BYTES)?
                .to_owned(),
        ))
    }

    #[must_use = "principal identifier should be inspected or matched"]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for PrincipalId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for PrincipalId {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

fn normalize_non_empty<'value>(
    field_name: &'static str,
    value: &'value str,
) -> Result<&'value str, TrustGrantError> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(TrustGrantError::EmptyStringField(field_name));
    }

    Ok(trimmed)
}

fn normalize_non_empty_token<'value>(
    field_name: &'static str,
    value: &'value str,
    max_bytes: usize,
) -> Result<&'value str, TrustGrantError> {
    let trimmed = normalize_non_empty(field_name, value)?;
    ensure_string_limit(field_name, trimmed, max_bytes)?;

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
    use std::collections::{BTreeSet, HashSet};

    use super::{
        CustomOperationName, KeyId, OperationName, PrincipalId, PrincipalKind, ResourceTypeName,
        SelectorKind,
    };

    #[test]
    fn operation_name_rejects_empty_values() {
        assert!(OperationName::new("").is_err());
        assert!(OperationName::new("   ").is_err());
    }

    #[test]
    fn resource_type_name_rejects_empty_values() {
        assert!(ResourceTypeName::new("").is_err());
        assert!(ResourceTypeName::new("   ").is_err());
    }

    #[test]
    fn custom_operation_name_rejects_reserved_builtin_names() {
        assert!(CustomOperationName::new("recognize").is_err());
        assert!(CustomOperationName::new("mint").is_err());
        assert!(CustomOperationName::new("create").is_err());
    }

    #[test]
    fn names_trim_input() {
        let operation = match CustomOperationName::new(" inspect ") {
            Ok(value) => value,
            Err(error) => panic!("operation name should be valid: {error}"),
        };
        let resource_type = match ResourceTypeName::new(" item ") {
            Ok(value) => value,
            Err(error) => panic!("resource type name should be valid: {error}"),
        };
        let key_id = match KeyId::new(" root-key-1 ") {
            Ok(value) => value,
            Err(error) => panic!("key id should be valid: {error}"),
        };
        let selector_kind = match SelectorKind::new(" namespace ") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let principal_kind = match PrincipalKind::new(" service ") {
            Ok(value) => value,
            Err(error) => panic!("principal kind should be valid: {error}"),
        };
        let principal_id = match PrincipalId::new(" issuer-worker ") {
            Ok(value) => value,
            Err(error) => panic!("principal id should be valid: {error}"),
        };

        assert_eq!(operation.as_str(), "inspect");
        assert_eq!(resource_type.as_str(), "item");
        assert_eq!(key_id.as_str(), "root-key-1");
        assert_eq!(selector_kind.as_str(), "namespace");
        assert_eq!(principal_kind.as_str(), "service");
        assert_eq!(principal_id.as_str(), "issuer-worker");
    }

    #[test]
    fn token_like_names_reject_whitespace_and_control_characters() {
        assert!(OperationName::new("read audit").is_err());
        assert!(ResourceTypeName::new("item\tclass").is_err());
        assert!(KeyId::new("root\nkey").is_err());
        assert!(SelectorKind::new("namespace value").is_err());
        assert!(PrincipalKind::new("service\rworker").is_err());
        assert!(PrincipalId::new("issuer worker").is_err());
    }

    #[test]
    fn selector_kind_equality_preserves_builtin_and_other_semantics() {
        let authority_left = match SelectorKind::new("authority") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let authority_right = match SelectorKind::new(" authority ") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let namespace = match SelectorKind::new("namespace") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let shard_left = match SelectorKind::new("shard") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let shard_right = match SelectorKind::new("shard") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let region = match SelectorKind::new("region") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };

        assert_eq!(authority_left, authority_right);
        assert_ne!(authority_left, namespace);
        assert_eq!(shard_left, shard_right);
        assert_ne!(shard_left, region);
    }

    #[test]
    fn selector_kind_hash_and_ordering_remain_consistent() {
        let authority = match SelectorKind::new("authority") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let authority_duplicate = match SelectorKind::new("authority") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let namespace = match SelectorKind::new("namespace") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };

        let mut hash_set = HashSet::new();
        assert!(hash_set.insert(authority.clone()));
        assert!(!hash_set.insert(authority_duplicate));
        assert!(hash_set.insert(namespace.clone()));

        let mut tree_set = BTreeSet::new();
        assert!(tree_set.insert(authority));
        assert!(!tree_set.insert(match SelectorKind::new("authority") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        }));
        assert!(tree_set.insert(namespace));
    }

    #[test]
    fn names_preserve_exact_case_for_interoperability_profiles() {
        let operation_lower = match OperationName::new("read") {
            Ok(value) => value,
            Err(error) => panic!("lowercase operation should be valid: {error}"),
        };
        let operation_upper = match OperationName::new("Read") {
            Ok(value) => value,
            Err(error) => panic!("mixed-case operation should be valid: {error}"),
        };
        let principal_lower = match PrincipalKind::new("service") {
            Ok(value) => value,
            Err(error) => panic!("lowercase principal should be valid: {error}"),
        };
        let principal_upper = match PrincipalKind::new("Service") {
            Ok(value) => value,
            Err(error) => panic!("mixed-case principal should be valid: {error}"),
        };

        assert_ne!(operation_lower.as_str(), operation_upper.as_str());
        assert_ne!(principal_lower.as_str(), principal_upper.as_str());
    }

    // ── SelectorKind: case insensitivity for built-in kinds ──────────────

    #[test]
    fn selector_kind_builtin_lowercase_recognized_as_builtins() {
        let authority = match SelectorKind::new("authority") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let namespace = match SelectorKind::new("namespace") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let actor = match SelectorKind::new("actor") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };

        // same built-in equals itself via Eq
        assert_eq!(
            authority,
            match SelectorKind::new("authority") {
                Ok(value) => value,
                Err(error) => panic!("selector kind should be valid: {error}"),
            }
        );
        assert_eq!(
            namespace,
            match SelectorKind::new("namespace") {
                Ok(value) => value,
                Err(error) => panic!("selector kind should be valid: {error}"),
            }
        );
        assert_eq!(
            actor,
            match SelectorKind::new("actor") {
                Ok(value) => value,
                Err(error) => panic!("selector kind should be valid: {error}"),
            }
        );

        // same_kind returns true for identical built-in kinds
        let authority2 = match SelectorKind::new("authority") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        assert!(authority.same_kind(&authority2));

        // different built-in kinds are not equal
        assert!(!authority.same_kind(&namespace));
        assert_ne!(authority, namespace);
        assert_ne!(authority, actor);
        assert_ne!(namespace, actor);
    }

    #[test]
    fn selector_kind_uppercase_recognized_as_builtins() {
        // The from_normalized function lowercases before matching, so
        // uppercase/mixed-case variants are classified as the same built-in
        // kind as their lowercase counterparts.
        let authority = match SelectorKind::new("authority") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let authority_upper = match SelectorKind::new("AUTHORITY") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let authority_mixed = match SelectorKind::new("Authority") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let authority_funky = match SelectorKind::new("AuThOrItY") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };

        // Uppercase variants are equal to the lowercase built-in
        assert_eq!(authority, authority_upper);
        assert_eq!(authority, authority_mixed);
        assert_eq!(authority, authority_funky);
        assert!(authority.same_kind(&authority_upper));

        // Different uppercase variants of the same built-in are all equal
        assert_eq!(
            authority_upper,
            match SelectorKind::new("AUTHORITY") {
                Ok(value) => value,
                Err(error) => panic!("selector kind should be valid: {error}"),
            }
        );
        assert_eq!(authority_upper, authority_funky);

        // Namespace built-in also works with case variations
        let namespace = match SelectorKind::new("namespace") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let namespace_upper = match SelectorKind::new("NAMESPACE") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let namespace_mixed = match SelectorKind::new("NameSpace") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        assert_eq!(namespace, namespace_upper);
        assert_eq!(namespace, namespace_mixed);

        // Actor built-in also works with case variations
        let actor = match SelectorKind::new("actor") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let actor_upper = match SelectorKind::new("ACTOR") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let actor_mixed = match SelectorKind::new("Actor") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        assert_eq!(actor, actor_upper);
        assert_eq!(actor, actor_mixed);
    }

    #[test]
    fn selector_kind_builtin_hash_and_ordering_consistent() {
        let a1 = match SelectorKind::new("authority") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let a2 = match SelectorKind::new("authority") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let ns = match SelectorKind::new("namespace") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let pid = match SelectorKind::new("actor") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };

        // Hash: same built-in occupies single slot
        let mut hash_set = HashSet::new();
        assert!(hash_set.insert(a1.clone()));
        assert!(!hash_set.insert(a2.clone()));
        assert!(hash_set.insert(ns));
        assert!(hash_set.insert(pid));
        assert_eq!(hash_set.len(), 3); // authority, namespace, actor

        // Ord: built-ins of same classification sort equal
        let mut tree_set = BTreeSet::new();
        assert!(tree_set.insert(a1));
        assert!(!tree_set.insert(a2));

        // Built-in ordering is deterministic: Authority < Namespace < Actor
        let authority = match SelectorKind::new("authority") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let namespace = match SelectorKind::new("namespace") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        assert!(authority < namespace);
    }

    // ── SelectorKind: Other is case-sensitive ────────────────────────────

    #[test]
    fn selector_kind_other_case_sensitive() {
        let foo = match SelectorKind::new("Foo") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let foo_lower = match SelectorKind::new("foo") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let foo_upper = match SelectorKind::new("FOO") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };

        // Other kinds use string equality — case matters
        assert_ne!(foo, foo_lower);
        assert_ne!(foo, foo_upper);
        assert_ne!(foo_lower, foo_upper);

        // same_kind for Other uses string equality too
        assert!(!foo.same_kind(&foo_lower));
        assert!(!foo.same_kind(&foo_upper));

        // Same string equals itself
        assert_eq!(
            foo,
            match SelectorKind::new("Foo") {
                Ok(value) => value,
                Err(error) => panic!("selector kind should be valid: {error}"),
            }
        );
        assert!(foo.same_kind(&match SelectorKind::new("Foo") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        }));

        // Hash: different cases = different slots
        let mut hash_set = HashSet::new();
        assert!(hash_set.insert(foo));
        assert!(hash_set.insert(foo_lower));
        assert!(hash_set.insert(foo_upper));
        assert_eq!(hash_set.len(), 3);
    }

    // ── SelectorKind: Other vs built-in boundary ─────────────────────────

    #[test]
    fn selector_kind_other_vs_builtin() {
        // A built-in Authority kind
        let authority = match SelectorKind::new("authority") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };

        // An Other kind whose value is NOT a built-in keyword
        let custom = match SelectorKind::new("custom-kind") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        assert_ne!(authority, custom);
        assert!(!authority.same_kind(&custom));

        // A mixed-case variant of a built-in IS recognized as the built-in
        let authority_mixed = match SelectorKind::new("Authority") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        assert_eq!(authority, authority_mixed);
        assert!(authority.same_kind(&authority_mixed));

        // Built-in classification is distinct: Authority != Other even when
        // the Other string is unrelated.
        assert!(!authority.same_kind(&custom));
        assert!(!custom.same_kind(&authority));
    }

    // ── SelectorKind: Unicode edge cases ─────────────────────────────────

    #[test]
    fn selector_kind_unicode_normalization_forms_are_distinct() {
        // NFC: 'é' as single codepoint U+00E9
        let nfc = match SelectorKind::new("\u{00E9}") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        // NFD: 'e' (U+0065) + combining acute accent (U+0301)
        let nfd = match SelectorKind::new("e\u{0301}") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };

        // Custom (Other) kinds use string equality, so NFC != NFD
        assert_ne!(nfc, nfd);
        assert!(!nfc.same_kind(&nfd));

        // They are both Other kinds, so as_str() returns different byte sequences
        assert_ne!(nfc.as_str(), nfd.as_str());

        // Hash: different byte sequences = different slots
        let mut hash_set = HashSet::new();
        assert!(hash_set.insert(nfc));
        assert!(hash_set.insert(nfd));
        assert_eq!(hash_set.len(), 2);
    }

    #[test]
    fn selector_kind_unicode_non_ascii_not_confused_with_builtins() {
        // Strings that look visually like built-in names but contain
        // non-ASCII characters are classified as Other, not built-in.
        let authority = match SelectorKind::new("authority") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };

        // 'а' is Cyrillic small letter a (U+0430), not ASCII 'a' (U+0061)
        let cyrillic_lookalike = match SelectorKind::new("\u{0430}uthority") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };

        assert_ne!(authority, cyrillic_lookalike);
        assert!(!authority.same_kind(&cyrillic_lookalike));
    }

    #[test]
    fn selector_kind_unicode_special_characters_are_accepted() {
        // Non-control, non-whitespace Unicode characters pass validation
        let emoji = match SelectorKind::new("role-\u{1f600}") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let cjk = match SelectorKind::new("种类") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        let zero_width = match SelectorKind::new("a\u{200B}b") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };

        // Zero-width space is not whitespace -> passes validation
        assert_eq!(emoji.as_str(), "role-\u{1f600}");
        assert_eq!(cjk.as_str(), "种类");
        assert_eq!(zero_width.as_str(), "a\u{200B}b");

        // Zero-width joiner is accepted but distinguishes strings
        let without_zwj = match SelectorKind::new("ab") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        assert_ne!(without_zwj, zero_width);
    }

    // ── SelectorKind: kind_index() hot-path regression ───────────────────

    #[test]
    fn selector_kind_kind_index_authority_is_zero() {
        let kind = match SelectorKind::new("authority") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        assert_eq!(kind.kind_index(), Some(0));
    }

    #[test]
    fn selector_kind_kind_index_namespace_is_one() {
        let kind = match SelectorKind::new("namespace") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        assert_eq!(kind.kind_index(), Some(1));
    }

    #[test]
    fn selector_kind_kind_index_actor_is_two() {
        let kind = match SelectorKind::new("actor") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        assert_eq!(kind.kind_index(), Some(2));
    }

    #[test]
    fn selector_kind_kind_index_other_is_none() {
        let kind = match SelectorKind::new("custom") {
            Ok(value) => value,
            Err(error) => panic!("selector kind should be valid: {error}"),
        };
        assert_eq!(kind.kind_index(), None);
    }

    // ── SelectorKind: empty string rejection ─────────────────────────────

    #[test]
    fn selector_kind_rejects_empty_strings() {
        assert!(SelectorKind::new("").is_err());
        assert!(SelectorKind::new("   ").is_err());
        assert!(SelectorKind::new("\t").is_err());
        assert!(SelectorKind::new("\n").is_err());
        assert!(SelectorKind::new("\u{00A0}").is_err()); // non-breaking space (whitespace)
    }

    #[test]
    fn operation_name_as_ref_str() {
        let name = OperationName::new("test_op")
            .unwrap_or_else(|e| panic!("OperationName::new failed: {e}"));
        assert_eq!(name.as_ref(), "test_op");
    }

    // ── SelectorKind: as_str() roundtrip ─────────────────────────────────

    #[test]
    fn selector_kind_as_str_roundtrip() {
        let inputs = [
            "authority",
            "namespace",
            "actor",
            "custom",
            "Foo",
            "shard-1",
            "种类",
            "role-\u{1f600}",
        ];

        for input in &inputs {
            let original = match SelectorKind::new(*input) {
                Ok(value) => value,
                Err(error) => panic!("selector kind should be valid for {input:?}: {error}"),
            };

            let roundtripped = match SelectorKind::new(original.as_str()) {
                Ok(value) => value,
                Err(error) => panic!("roundtrip should succeed for {input:?}: {error}"),
            };

            assert_eq!(original, roundtripped, "roundtrip mismatch for {input:?}");
            assert_eq!(
                original.as_str(),
                roundtripped.as_str(),
                "as_str mismatch for {input:?}"
            );
            assert!(
                original.same_kind(&roundtripped),
                "same_kind false after roundtrip for {input:?}"
            );
        }
    }

    // ── Borrow<str> and AsRef<str> for OperationName ────────────────────

    #[test]
    fn operation_name_borrow_str() {
        use std::borrow::Borrow;
        let name = OperationName::new("read_audit")
            .unwrap_or_else(|e| panic!("OperationName::new failed: {e}"));
        let borrowed: &str = name.borrow();
        assert_eq!(borrowed, "read_audit");
    }

    // ── Borrow<str> and AsRef<str> for CustomOperationName ──────────────

    #[test]
    fn custom_operation_name_as_ref_str() {
        let name = CustomOperationName::new("deploy")
            .unwrap_or_else(|e| panic!("CustomOperationName::new failed: {e}"));
        let r: &str = name.as_ref();
        assert_eq!(r, "deploy");
    }

    #[test]
    fn custom_operation_name_borrow_str() {
        use std::borrow::Borrow;
        let name = CustomOperationName::new("deploy")
            .unwrap_or_else(|e| panic!("CustomOperationName::new failed: {e}"));
        let borrowed: &str = name.borrow();
        assert_eq!(borrowed, "deploy");
    }

    // ── Accessor: CustomOperationName::operation_name() ─────────────────

    #[test]
    fn custom_operation_name_operation_name_accessor() {
        let name = CustomOperationName::new("deploy")
            .unwrap_or_else(|e| panic!("CustomOperationName::new failed: {e}"));
        assert_eq!(name.operation_name().as_str(), "deploy");
    }

    // ── Borrow<str> and AsRef<str> for ResourceTypeName ─────────────────

    #[test]
    fn resource_type_name_as_ref_str() {
        let name = ResourceTypeName::new("item")
            .unwrap_or_else(|e| panic!("ResourceTypeName::new failed: {e}"));
        let r: &str = name.as_ref();
        assert_eq!(r, "item");
    }

    #[test]
    fn resource_type_name_borrow_str() {
        use std::borrow::Borrow;
        let name = ResourceTypeName::new("item")
            .unwrap_or_else(|e| panic!("ResourceTypeName::new failed: {e}"));
        let borrowed: &str = name.borrow();
        assert_eq!(borrowed, "item");
    }

    // ── Borrow<str> and AsRef<str> for KeyId ────────────────────────────

    #[test]
    fn key_id_as_ref_str() {
        use std::convert::AsRef;
        let name = KeyId::new("root-key-1").unwrap_or_else(|e| panic!("KeyId::new failed: {e}"));
        let r: &str = AsRef::as_ref(&name);
        assert_eq!(r, "root-key-1");
    }

    #[test]
    fn key_id_borrow_str() {
        use std::borrow::Borrow;
        let name = KeyId::new("root-key-1").unwrap_or_else(|e| panic!("KeyId::new failed: {e}"));
        let borrowed: &str = name.borrow();
        assert_eq!(borrowed, "root-key-1");
    }

    // ── Borrow<str> and AsRef<str> for SelectorKind ─────────────────────

    #[test]
    fn selector_kind_as_ref_str() {
        fn accepts_as_ref(val: &impl AsRef<str>) -> &str {
            val.as_ref()
        }
        let kind = SelectorKind::new("authority")
            .unwrap_or_else(|e| panic!("SelectorKind::new failed: {e}"));
        assert_eq!(accepts_as_ref(&kind), "authority");
    }

    #[test]
    fn selector_kind_borrow_str() {
        use std::borrow::Borrow;
        let kind = SelectorKind::new("authority")
            .unwrap_or_else(|e| panic!("SelectorKind::new failed: {e}"));
        let borrowed: &str = kind.borrow();
        assert_eq!(borrowed, "authority");
    }

    // ── Borrow<str> and AsRef<str> for PrincipalKind ────────────────────

    #[test]
    fn principal_kind_as_ref_str() {
        fn accepts_as_ref(val: &impl AsRef<str>) -> &str {
            val.as_ref()
        }
        let kind = PrincipalKind::new("service")
            .unwrap_or_else(|e| panic!("PrincipalKind::new failed: {e}"));
        assert_eq!(accepts_as_ref(&kind), "service");
    }

    #[test]
    fn principal_kind_borrow_str() {
        use std::borrow::Borrow;
        let kind = PrincipalKind::new("service")
            .unwrap_or_else(|e| panic!("PrincipalKind::new failed: {e}"));
        let borrowed: &str = kind.borrow();
        assert_eq!(borrowed, "service");
    }

    // ── Borrow<str> and AsRef<str> for PrincipalId ──────────────────────

    #[test]
    fn principal_id_as_ref_str() {
        fn accepts_as_ref(val: &impl AsRef<str>) -> &str {
            val.as_ref()
        }
        let id =
            PrincipalId::new("alice").unwrap_or_else(|e| panic!("PrincipalId::new failed: {e}"));
        assert_eq!(accepts_as_ref(&id), "alice");
    }

    #[test]
    fn principal_id_borrow_str() {
        use std::borrow::Borrow;
        let id =
            PrincipalId::new("alice").unwrap_or_else(|e| panic!("PrincipalId::new failed: {e}"));
        let borrowed: &str = id.borrow();
        assert_eq!(borrowed, "alice");
    }

    // ── SelectorKind: Ord for Other classification (line 253) ───────────

    #[test]
    fn selector_kind_ord_other_values_compare_by_string() {
        let a =
            SelectorKind::new("bar").unwrap_or_else(|e| panic!("SelectorKind::new failed: {e}"));
        let b =
            SelectorKind::new("bar").unwrap_or_else(|e| panic!("SelectorKind::new failed: {e}"));
        let c =
            SelectorKind::new("aaa").unwrap_or_else(|e| panic!("SelectorKind::new failed: {e}"));
        let d =
            SelectorKind::new("zzz").unwrap_or_else(|e| panic!("SelectorKind::new failed: {e}"));

        assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
        assert_eq!(c.cmp(&a), std::cmp::Ordering::Less);
        assert_eq!(d.cmp(&a), std::cmp::Ordering::Greater);
    }

    // ── SelectorKind: Empty rejection via normalize_non_empty_token ─────

    #[test]
    fn selector_kind_rejects_whitespace_only_trimmed_empty() {
        assert!(SelectorKind::new("   ").is_err());
    }
}
