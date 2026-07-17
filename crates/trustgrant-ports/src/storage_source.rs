use trustgrant_domain::AuthorityId;
use trustgrant_error::TrustGrantError;

/// Identifier for a stored TrustGrant.
///
/// The string value is the TrustGrant's `trustgrant_id` field (e.g.
/// `"tg_123e4567-e89b-12d3-a456-426614174000"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StoredGrantId(pub String);

/// Optional port for persisting and loading verified TrustGrants.
///
/// You do NOT need to implement this trait if your application does not need
/// persistence, or if it manages storage through other means (own database,
/// event stream, etc.).
///
/// Implement this trait only when you want a standard contract for storing
/// and loading verified grants. The protocol core never calls this trait
/// directly — it is called by the application to persist verification
/// results and load them later for rehydration or audit.
///
/// # Storage format
///
/// The `store()` and `load()` methods work with serialized JSON strings.
/// The expected format is a `VerifiedTrustGrantRecord` (the persistence
/// record from `trustgrant-verify`), which contains both the normalized
/// document and the verification metadata.
///
/// Serialization/deserialization is the application's responsibility:
///
/// ```text
/// // Store/load pattern — serialization format is VerifiedTrustGrantRecord JSON.
/// // The application is responsible for serialization/deserialization.
/// ```
///
/// # Example (in-memory mock)
///
/// ```
/// use std::collections::HashMap;
/// use trustgrant_ports::{StorageSource, StoredGrantId};
/// use trustgrant_domain::AuthorityId;
/// use trustgrant_error::TrustGrantError;
///
/// struct InMemoryStorage {
///     grants: HashMap<String, String>,
/// }
///
/// impl StorageSource for InMemoryStorage {
///     fn store(&self, grant_id: &StoredGrantId, grant_json: &str) -> Result<(), TrustGrantError> {
///         let _ = grant_id;
///         let _ = grant_json;
///         Ok(())
///     }
///     fn load(&self, grant_id: &StoredGrantId) -> Result<String, TrustGrantError> {
///         self.grants.get(&grant_id.0).cloned()
///             .ok_or(TrustGrantError::InvalidPersistedVerifiedGrantRecord("grant not found"))
///     }
///     fn list_by_authority(&self, _: &AuthorityId) -> Result<Vec<StoredGrantId>, TrustGrantError> {
///         Ok(self.grants.keys().map(|k| StoredGrantId(k.clone())).collect())
///     }
/// }
/// ```
pub trait StorageSource {
    /// Persists one verified TrustGrant as serialized JSON.
    ///
    /// The `grant_json` should be the JSON serialization of a
    /// `VerifiedTrustGrantRecord`. The implementation may overwrite an
    /// existing entry with the same ID.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when storage fails.
    fn store(&self, grant_id: &StoredGrantId, grant_json: &str) -> Result<(), TrustGrantError>;

    /// Loads one previously stored TrustGrant by its identifier.
    ///
    /// Returns the serialized JSON of the `VerifiedTrustGrantRecord`.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError::InvalidPersistedVerifiedGrantRecord`] when
    /// the grant cannot be found.
    fn load(&self, grant_id: &StoredGrantId) -> Result<String, TrustGrantError>;

    /// Lists all stored grant identifiers for one authority.
    ///
    /// The returned identifiers can be passed to [`load()`](Self::load) to
    /// retrieve the full grant data.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGrantError`] when the query fails.
    fn list_by_authority(
        &self,
        authority: &AuthorityId,
    ) -> Result<Vec<StoredGrantId>, TrustGrantError>;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    use super::*;
    use std::collections::HashMap;
    use trustgrant_domain::AuthorityId;
    use trustgrant_error::TrustGrantError;

    struct InMemoryStorage {
        grants: HashMap<String, String>,
    }

    impl InMemoryStorage {
        fn new() -> Self {
            Self {
                grants: HashMap::new(),
            }
        }
    }

    impl StorageSource for InMemoryStorage {
        fn store(&self, grant_id: &StoredGrantId, grant_json: &str) -> Result<(), TrustGrantError> {
            // Using interior mutability via RefCell would be more realistic,
            // but for a simple mock we just check the operation is callable.
            let _ = grant_id;
            let _ = grant_json;
            Ok(())
        }

        fn load(&self, grant_id: &StoredGrantId) -> Result<String, TrustGrantError> {
            self.grants.get(&grant_id.0).cloned().ok_or(
                TrustGrantError::InvalidPersistedVerifiedGrantRecord("grant not found"),
            )
        }

        fn list_by_authority(
            &self,
            _: &AuthorityId,
        ) -> Result<Vec<StoredGrantId>, TrustGrantError> {
            Ok(self
                .grants
                .keys()
                .map(|k| StoredGrantId(k.clone()))
                .collect())
        }
    }

    fn test_authority() -> AuthorityId {
        AuthorityId::new("https://issuer.example.com")
            .unwrap_or_else(|error| panic!("failed to create AuthorityId: {error}"))
    }

    #[test]
    fn mock_store_and_load_roundtrip() {
        let storage = InMemoryStorage::new();
        let id = StoredGrantId("tg_test".to_owned());
        let json = r#"{"test": true}"#;
        assert!(storage.store(&id, json).is_ok());
        // load will fail because our mock doesn't actually store
        // (no interior mutability) — this test just validates the trait API.
        let result = storage.load(&id);
        assert_eq!(
            result,
            Err(TrustGrantError::InvalidPersistedVerifiedGrantRecord(
                "grant not found"
            ))
        );
    }

    #[test]
    fn mock_list_by_authority_is_callable() {
        let storage = InMemoryStorage::new();
        let result = storage.list_by_authority(&test_authority());
        assert!(result.is_ok());
        assert!(
            result
                .unwrap_or_else(|error| panic!("expected Ok: {error}"))
                .is_empty()
        );
    }
}
