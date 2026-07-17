#![allow(clippy::must_use_candidate)]

pub mod canonicalize;
pub mod chain;
pub mod verify;

pub use canonicalize::{
    CanonicalOwnershipTransitionBytes, canonicalize_transition_acceptance,
    canonicalize_transition_proposal,
};
pub use chain::OwnershipChainVerifier;
pub use verify::{
    OwnershipTransitionVerificationMetadata, OwnershipTransitionVerifier,
    VerifiedOwnershipTransition,
};
