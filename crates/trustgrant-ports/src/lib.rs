//! Backend-agnostic port traits for the TrustGrant protocol.
//!
//! # Architecture
//!
//! The protocol core works with **already-assembled domain types** directly.
//! It never calls these port traits — they exist for the **application layer**
//! to standardise how raw material is fetched from authority endpoints.
//!
//! # Optional traits
//!
//! You only implement the traits your deployment needs:
//!
//! - **Already have the data?** Skip the traits entirely. Construct
//!   `AuthorityDiscoveryDocument`, `RevocationRecord`, etc. directly from your
//!   existing data and insert them into a `TrustGrantProofBundle`.
//! - **Fetching from endpoints?** Implement [`DiscoverySource`],
//!   [`RevocationSource`], or [`StorageSource`] as needed. The application
//!   calls these, assembles the bundle, then calls the verification pipeline.
//!
//! ```text
//! // Skip traits entirely — data already in hand:
//! // Construct domain types directly, insert into a TrustGrantProofBundle,
//! // then call the verification pipeline's bundle-based entry point.
//! ```

pub mod discovery_source;
pub mod revocation_source;
pub mod signature;
pub mod storage_source;
pub mod verification;

pub use discovery_source::DiscoverySource;
pub use revocation_source::RevocationSource;
pub use signature::{SignatureVerificationRequest, SignatureVerifier, VerificationPosture};
pub use storage_source::{StorageSource, StoredGrantId};
pub use verification::{
    AuthorityDiscoverySource, OwnershipTransitionProofSource, RevocationProofSource,
    VerificationContext, VerificationSources,
};
