# TrustGrant Verify

Cold-path verification pipeline for the [TrustGrant](https://github.com/STEXS-Technologies/trustgrant) delegation protocol.

Verifies signed grant documents end-to-end: JSON parsing, signature verification,
signer binding resolution, metadata consistency checks, revocation state
verification, ownership chain verification, and hydration into verified
grant records ready for evaluation.

See the [trustgrant] crate for full documentation and integration guide.
