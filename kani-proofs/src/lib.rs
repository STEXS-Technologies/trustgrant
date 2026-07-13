#![allow(dead_code, unused_imports)]

//! Kani proof harnesses for TrustGrant core algorithms.
//!
//! These harnesses verify panic-freedom of key protocol functions
//! that don't depend on the ICU/unicode dependency chain (url/idna).
//!
//! When Kani's zerovec support improves, expand verification to the
//! full evaluation engine.

#[cfg(kani)]
mod selector_match;
