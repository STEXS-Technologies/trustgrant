use crate::TrustGrantError;

pub const MAX_TRUSTGRANT_JSON_BYTES: usize = 64 * 1024;
pub const MAX_OWNERSHIP_TRANSITION_JSON_BYTES: usize = 32 * 1024;
pub const MAX_DISCOVERY_JSON_BYTES: usize = 64 * 1024;
pub const MAX_DELEGATED_PRINCIPAL_JSON_BYTES: usize = 32 * 1024;
pub const MAX_REVOCATION_PROOF_JSON_BYTES: usize = 4 * 1024;

pub const MAX_RESOURCE_TYPES: usize = 64;
pub const MAX_AUDIENCE_ENTRIES: usize = 64;
pub const MAX_SELECTORS_PER_SCOPE: usize = 32;
pub const MAX_SELECTOR_VALUES_PER_SELECTOR: usize = 32;
pub const MAX_SELECTOR_EXPRESSIONS_PER_SELECTOR: usize = 16;
pub const MAX_OPERATIONS_PER_SCOPE: usize = 32;
pub const MAX_DISCOVERY_KEYS: usize = 64;
pub const MAX_REVOCATION_ENDPOINTS: usize = 16;
pub const MAX_OWNERSHIP_CHAIN_LENGTH: usize = 32;
pub const MAX_BUNDLE_DISCOVERY_DOCUMENTS: usize = 64;
pub const MAX_BUNDLE_DELEGATED_PRINCIPAL_DOCUMENTS: usize = 128;
pub const MAX_BUNDLE_REVOCATION_PROOFS: usize = 64;
pub const MAX_BUNDLE_OWNERSHIP_TRANSITION_CHAINS: usize = 64;
pub const MAX_REQUEST_SELECTOR_KINDS: usize = 32;
pub const MAX_REQUEST_VALUES_PER_KIND: usize = 32;

pub const MAX_AUTHORITY_ID_BYTES: usize = 1024;
pub const MAX_OPERATION_NAME_BYTES: usize = 128;
pub const MAX_RESOURCE_TYPE_NAME_BYTES: usize = 128;
pub const MAX_KEY_ID_BYTES: usize = 128;
pub const MAX_SELECTOR_KIND_BYTES: usize = 128;
pub const MAX_PRINCIPAL_KIND_BYTES: usize = 128;
pub const MAX_PRINCIPAL_ID_BYTES: usize = 256;
pub const MAX_ALGORITHM_NAME_BYTES: usize = 64;
pub const MAX_PUBLIC_KEY_MATERIAL_BYTES: usize = 4096;
pub const MAX_SIGNATURE_PROFILE_FORMAT_BYTES: usize = 64;
pub const MAX_CANONICALIZATION_NAME_BYTES: usize = 64;

pub const MAX_SELECTOR_VALUE_BYTES: usize = 256;
pub const MAX_SELECTOR_EXPRESSION_BYTES: usize = 512;
pub const MAX_REQUEST_SELECTOR_VALUE_BYTES: usize = 256;

/// Validates that a JSON document does not exceed the maximum allowed size.
///
/// # Errors
///
/// Returns [`TrustGrantError::DocumentTooLarge`] if `actual_bytes` exceeds `max_bytes`.
pub const fn ensure_json_size(
    document: &'static str,
    actual_bytes: usize,
    max_bytes: usize,
) -> Result<(), TrustGrantError> {
    if actual_bytes > max_bytes {
        return Err(TrustGrantError::DocumentTooLarge {
            document,
            max_bytes,
        });
    }

    Ok(())
}

/// Validates that a collection does not exceed the maximum allowed item count.
///
/// # Errors
///
/// Returns [`TrustGrantError::CollectionTooLarge`] if `actual_items` exceeds `max_items`.
pub const fn ensure_collection_limit(
    field: &'static str,
    actual_items: usize,
    max_items: usize,
) -> Result<(), TrustGrantError> {
    if actual_items > max_items {
        return Err(TrustGrantError::CollectionTooLarge { field, max_items });
    }

    Ok(())
}

/// Validates that a string value does not exceed the maximum allowed byte length.
///
/// # Errors
///
/// Returns [`TrustGrantError::StringTooLong`] if `value.len()` exceeds `max_bytes`.
pub const fn ensure_string_limit(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), TrustGrantError> {
    if value.len() > max_bytes {
        return Err(TrustGrantError::StringTooLong { field, max_bytes });
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn ensure_json_size_passes_at_exact_limit() {
        let result = ensure_json_size("test_doc", 100, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn ensure_json_size_fails_one_over_limit() {
        let result = ensure_json_size("test_doc", 101, 100);
        assert_eq!(
            result,
            Err(TrustGrantError::DocumentTooLarge {
                document: "test_doc",
                max_bytes: 100,
            })
        );
    }

    #[test]
    fn ensure_collection_limit_passes_at_exact_limit() {
        let result = ensure_collection_limit("test_field", 10, 10);
        assert!(result.is_ok());
    }

    #[test]
    fn ensure_collection_limit_fails_one_over_limit() {
        let result = ensure_collection_limit("test_field", 11, 10);
        assert_eq!(
            result,
            Err(TrustGrantError::CollectionTooLarge {
                field: "test_field",
                max_items: 10,
            })
        );
    }

    #[test]
    fn ensure_string_limit_passes_at_exact_limit() {
        let value = "a".repeat(100);
        let result = ensure_string_limit("test_field", &value, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn ensure_string_limit_fails_one_over_limit() {
        let value = "a".repeat(101);
        let result = ensure_string_limit("test_field", &value, 100);
        assert_eq!(
            result,
            Err(TrustGrantError::StringTooLong {
                field: "test_field",
                max_bytes: 100,
            })
        );
    }
}
