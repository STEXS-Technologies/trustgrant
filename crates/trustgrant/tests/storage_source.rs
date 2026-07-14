#![allow(clippy::panic)]

use std::cell::RefCell;
use std::collections::HashMap;

use trustgrant::{
    AuthorityId, StorageSource, StoredGrantId, TrustGrantError,
};

/// In-memory storage implementing `StorageSource` with interior mutability
/// so the store/load round-trip actually persists data.
struct InMemoryStorage {
    grants: RefCell<HashMap<String, String>>,
    authority_index: RefCell<HashMap<AuthorityId, Vec<String>>>,
}

impl InMemoryStorage {
    fn new() -> Self {
        Self {
            grants: RefCell::new(HashMap::new()),
            authority_index: RefCell::new(HashMap::new()),
        }
    }
}

impl StorageSource for InMemoryStorage {
    fn store(&self, grant_id: &StoredGrantId, grant_json: &str) -> Result<(), TrustGrantError> {
        self.grants
            .borrow_mut()
            .insert(grant_id.0.clone(), grant_json.to_owned());
        Ok(())
    }

    fn load(&self, grant_id: &StoredGrantId) -> Result<String, TrustGrantError> {
        self.grants.borrow().get(&grant_id.0).cloned().ok_or(
            TrustGrantError::InvalidPersistedVerifiedGrantRecord("grant not found"),
        )
    }

    fn list_by_authority(
        &self,
        authority: &AuthorityId,
    ) -> Result<Vec<StoredGrantId>, TrustGrantError> {
        let index = self.authority_index.borrow();
        Ok(index
            .get(authority)
            .map(|ids| ids.iter().map(|id| StoredGrantId(id.clone())).collect())
            .unwrap_or_default())
    }
}

/// Convenience wrapper that also indexes grant IDs by authority.
struct IndexedStorage {
    inner: InMemoryStorage,
}

impl IndexedStorage {
    fn new() -> Self {
        Self {
            inner: InMemoryStorage::new(),
        }
    }

    fn store_grant_for_authority(
        &self,
        grant_id: &StoredGrantId,
        authority: &AuthorityId,
        grant_json: &str,
    ) -> Result<(), TrustGrantError> {
        self.inner.store(grant_id, grant_json)?;
        self.inner
            .authority_index
            .borrow_mut()
            .entry(authority.clone())
            .or_default()
            .push(grant_id.0.clone());
        Ok(())
    }
}

impl StorageSource for IndexedStorage {
    fn store(&self, grant_id: &StoredGrantId, grant_json: &str) -> Result<(), TrustGrantError> {
        self.inner.store(grant_id, grant_json)
    }

    fn load(&self, grant_id: &StoredGrantId) -> Result<String, TrustGrantError> {
        self.inner.load(grant_id)
    }

    fn list_by_authority(
        &self,
        authority: &AuthorityId,
    ) -> Result<Vec<StoredGrantId>, TrustGrantError> {
        self.inner.list_by_authority(authority)
    }
}

fn test_authority() -> AuthorityId {
    AuthorityId::new("https://issuer.example.com")
        .unwrap_or_else(|e| panic!("AuthorityId: {e}"))
}

fn other_authority() -> AuthorityId {
    AuthorityId::new("https://other.example.com")
        .unwrap_or_else(|e| panic!("AuthorityId: {e}"))
}

const GRANT_JSON: &str = r#"{
  "trustgrant_id": "tg_123e4567-e89b-12d3-a456-426614174000",
  "record_version": 1,
  "document": {
    "trustgrant_id": "tg_123e4567-e89b-12d3-a456-426614174000",
    "grant_series_id": "tgs_123e4567-e89b-12d3-a456-426614174001",
    "revision": 1,
    "supersedes": null,
    "supersession_policy": "coexist",
    "issuer_authority": "https://issuer.example.com",
    "origin_authority": "https://issuer.example.com",
    "active_owning_authority": "https://issuer.example.com",
    "key_id": "root-key-1",
    "target_scope": {"all": true, "allow": [], "deny": []},
    "capabilities": {"recognize": true, "mint": false},
    "default_audience_scope": [],
    "resource_scope": {},
    "global_time_window": null,
    "revocation": null,
    "issued_at": "2026-04-07T12:00:00Z",
    "issuer_principal": null
  },
  "metadata": {
    "verified_at": "2026-04-07T12:00:00Z",
    "posture": "online",
    "signer_binding": {
      "issuer_authority": "https://issuer.example.com",
      "key_record": {
        "key_id": "root-key-1",
        "algorithm": "ed25519",
        "public_key": "base64-public-key",
        "not_before": "2026-04-07T12:00:00Z",
        "not_after": "2026-04-08T12:00:00Z"
      },
      "signature_profile": {
        "format": "jcs+ed25519",
        "canonicalization": "RFC8785"
      },
      "delegated_principal": null
    },
    "ownership": {
      "origin_authority": "https://issuer.example.com",
      "active_owning_authority": "https://issuer.example.com",
      "checked_at": "2026-04-07T12:00:00Z",
      "proof_kind": "static_owner",
      "transition_chain_tip": null
    },
    "revocation": "NonRevocable"
  }
}"#;

#[test]
fn store_and_load_round_trip() {
    let storage = InMemoryStorage::new();
    let grant_id = StoredGrantId("tg_123e4567-e89b-12d3-a456-426614174000".to_owned());

    assert!(storage.store(&grant_id, GRANT_JSON).is_ok());

    let loaded = storage
        .load(&grant_id)
        .unwrap_or_else(|e| panic!("should load stored grant: {e}"));
    assert_eq!(loaded, GRANT_JSON);
}

#[test]
fn load_nonexistent_grant_returns_error() {
    let storage = InMemoryStorage::new();
    let grant_id = StoredGrantId("tg_nonexistent".to_owned());

    let result = storage.load(&grant_id);
    assert_eq!(
        result,
        Err(TrustGrantError::InvalidPersistedVerifiedGrantRecord(
            "grant not found"
        ))
    );
}

#[test]
fn list_by_authority_returns_matching_grants() {
    let storage = IndexedStorage::new();
    let auth = test_authority();
    let id1 = StoredGrantId("tg_grant_001".to_owned());
    let id2 = StoredGrantId("tg_grant_002".to_owned());

    storage
        .store_grant_for_authority(&id1, &auth, GRANT_JSON)
        .unwrap_or_else(|e| panic!("should store: {e}"));
    storage
        .store_grant_for_authority(&id2, &auth, GRANT_JSON)
        .unwrap_or_else(|e| panic!("should store: {e}"));

    let ids = storage
        .list_by_authority(&auth)
        .unwrap_or_else(|e| panic!("should list: {e}"));
    assert_eq!(ids.len(), 2);
    assert!(ids.iter().any(|id| id.0 == "tg_grant_001"));
    assert!(ids.iter().any(|id| id.0 == "tg_grant_002"));
}

#[test]
fn list_by_authority_returns_empty_for_unknown_authority() {
    let storage = InMemoryStorage::new();
    let ids = storage
        .list_by_authority(&other_authority())
        .unwrap_or_else(|e| panic!("should list: {e}"));
    assert!(ids.is_empty());
}

#[test]
fn store_grant_for_authority_and_lookup() {
    let storage = IndexedStorage::new();
    let auth = test_authority();
    let grant_id = StoredGrantId("tg_123e4567-e89b-12d3-a456-426614174000".to_owned());

    storage
        .store_grant_for_authority(&grant_id, &auth, GRANT_JSON)
        .unwrap_or_else(|e| panic!("should store for authority: {e}"));

    // Load by ID works
    let loaded = storage
        .load(&grant_id)
        .unwrap_or_else(|e| panic!("should load: {e}"));
    assert_eq!(loaded, GRANT_JSON);

    // List by authority returns the grant
    let ids = storage
        .list_by_authority(&auth)
        .unwrap_or_else(|e| panic!("should list: {e}"));
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].0, grant_id.0);
}

#[test]
fn store_overwrites_existing_entry() {
    let storage = InMemoryStorage::new();
    let grant_id = StoredGrantId("tg_overwrite_test".to_owned());
    let json_v1 = r#"{"version":1}"#;
    let json_v2 = r#"{"version":2}"#;

    storage
        .store(&grant_id, json_v1)
        .unwrap_or_else(|e| panic!("first store: {e}"));
    storage
        .store(&grant_id, json_v2)
        .unwrap_or_else(|e| panic!("second store: {e}"));

    let loaded = storage
        .load(&grant_id)
        .unwrap_or_else(|e| panic!("should load: {e}"));
    assert_eq!(loaded, json_v2);
}
