#![allow(clippy::must_use_candidate)]

pub mod document;
pub mod source_document;

pub use document::{
    AlgorithmName, AuthorityKeyRecord, CanonicalizationName, DelegatedPrincipalRef,
    PublicKeyMaterial, ResolvedSignerBinding, SignatureFormat, SignatureProfile,
};
pub use source_document::{
    AuthorityDiscoveryDocument, DelegatedPrincipalKeyDocument, DiscoveryDelegation,
    DiscoveryRevocationPolicy, parse_authority_discovery_document,
    parse_delegated_principal_key_document,
};
