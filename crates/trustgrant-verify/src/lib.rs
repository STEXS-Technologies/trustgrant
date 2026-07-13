pub mod bundle;
pub mod canonicalize;
mod consistency;
pub mod pipeline;
pub mod policy;
mod record;
pub mod signature;
pub mod verified_grant;

pub use bundle::{BundleRevocationProof, TrustGrantProofBundle};
pub use canonicalize::{CanonicalTrustGrantBytes, canonicalize_trustgrant};
pub use consistency::ensure_metadata_matches_document;
pub use pipeline::{VerificationArtifacts, VerificationPipeline};
pub use policy::VerificationPolicy;
pub use record::VerifiedTrustGrantRecord;
pub use trustgrant_domain::CanonicalizationProfile;
pub use trustgrant_ports::{SignatureVerificationRequest, SignatureVerifier, VerificationPosture};
pub use verified_grant::{NormalizedTrustGrantDocument, VerificationMetadata, VerifiedTrustGrant};
