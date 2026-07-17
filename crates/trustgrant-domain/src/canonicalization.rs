use std::borrow::Borrow;
use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

/// A string key that orders by UTF-16 code units (as required by
/// RFC 8785 JSON canonicalization) rather than by byte value.
///
/// Wrapping a `String` with `Utf16Key` in a `BTreeMap` allows iteration
/// in the correct key order without a temporary sort step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Utf16Key(String);

impl Utf16Key {
    /// Wraps an owned string.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the inner string reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper, returning the inner string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Ord for Utf16Key {
    fn cmp(&self, other: &Self) -> Ordering {
        let mut left = self.0.encode_utf16();
        let mut right = other.0.encode_utf16();
        loop {
            match (left.next(), right.next()) {
                (Some(l), Some(r)) => match l.cmp(&r) {
                    Ordering::Equal => {}
                    Ordering::Less => return Ordering::Less,
                    Ordering::Greater => return Ordering::Greater,
                },
                (None, Some(_)) => return Ordering::Less,
                (Some(_), None) => return Ordering::Greater,
                (None, None) => return Ordering::Equal,
            }
        }
    }
}

impl PartialOrd for Utf16Key {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for Utf16Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::ops::Deref for Utf16Key {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl From<String> for Utf16Key {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Utf16Key {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<Utf16Key> for String {
    fn from(value: Utf16Key) -> Self {
        value.0
    }
}

impl Borrow<str> for Utf16Key {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// Identifies the JSON canonicalization algorithm used for deterministic
/// signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalizationProfile {
    /// RFC 8785 JSON Canonicalization Scheme (JCS).
    Rfc8785,
}

impl CanonicalizationProfile {
    /// Canonicalization profile names are required for discovery-profile matching.
    #[must_use]
    pub const fn discovery_name(self) -> &'static str {
        match self {
            Self::Rfc8785 => "RFC8785",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_name_returns_rfc8785() {
        let profile = CanonicalizationProfile::Rfc8785;
        assert_eq!(profile.discovery_name(), "RFC8785");
    }

    #[test]
    fn debug_output_is_non_empty() {
        let profile = CanonicalizationProfile::Rfc8785;
        let debug_str = format!("{profile:?}");
        assert!(!debug_str.is_empty());
    }

    #[test]
    fn clone_produces_equal_value() {
        let profile = CanonicalizationProfile::Rfc8785;
        let cloned = profile;
        assert_eq!(profile, cloned);
    }

    #[test]
    fn equality_comparison() {
        let a = CanonicalizationProfile::Rfc8785;
        let b = CanonicalizationProfile::Rfc8785;
        assert_eq!(a, b);
    }

    // ── Utf16Key tests ──────────────────────────────────────────────

    #[test]
    fn construction_new() {
        let key = Utf16Key::new("hello");
        assert_eq!(key.as_str(), "hello");
    }

    #[test]
    fn construction_from_string() {
        let key: Utf16Key = String::from("world").into();
        assert_eq!(key.as_str(), "world");
    }

    #[test]
    fn construction_from_str() {
        let key: Utf16Key = "foo".into();
        assert_eq!(key.as_str(), "foo");
    }

    #[test]
    fn accessor_as_str() {
        let key = Utf16Key::new("accessor test");
        assert_eq!(key.as_str(), "accessor test");
    }

    #[test]
    fn accessor_into_inner() {
        let key = Utf16Key::new("into_inner value");
        let s: String = key.into_inner();
        assert_eq!(s, "into_inner value");
    }

    #[test]
    fn display_format_matches_content() {
        let key = Utf16Key::new("display me");
        assert_eq!(format!("{}", key), "display me");
    }

    #[test]
    fn deref_yields_str() {
        let key = Utf16Key::new("deref str");
        let s: &str = &key;
        assert_eq!(s, "deref str");
    }

    // ── Ord / UTF‑16 ordering tests ─────────────────────────────────

    #[test]
    fn ord_ascii_normal() {
        // ASCII strings compare by UTF‑16 code unit (same as byte order for ASCII)
        assert!(Utf16Key::new("a") < Utf16Key::new("b"));
    }

    #[test]
    fn ord_shorter_prefix_is_less() {
        assert!(Utf16Key::new("a") < Utf16Key::new("ab"));
    }

    #[test]
    fn ord_equal_strings_are_equal() {
        assert_eq!(
            Utf16Key::new("same").cmp(&Utf16Key::new("same")),
            Ordering::Equal
        );
    }

    #[test]
    fn ord_utf16_code_unit_order_differs_from_byte_order() {
        // U+E000 (Private Use Area, BMP)        → one   UTF‑16 code unit: 0xE000
        //                                        → UTF‑8: [0xEE, 0x80, 0x80]
        // U+10000 (LINEAR B SYLLABLE B008 A,     → two   UTF‑16 code units (surrogate
        //          supplementary plane)             pair): 0xD800, 0xDC00
        //                                        → UTF‑8: [0xF0, 0x90, 0x80, 0x80]
        //
        // UTF‑16 ordering: compare first code unit:
        //   0xD800 < 0xE000  ⇒  U+10000 < U+E000
        //
        // Byte ordering (UTF‑8): compare first byte:
        //   0xEE < 0xF0      ⇒  U+E000 < U+10000   (OPPOSITE!)
        let bmp = Utf16Key::new("\u{E000}");
        let supplementary = Utf16Key::new("\u{10000}");
        // UTF‑16 ordering (what Utf16Key implements)
        assert!(
            supplementary < bmp,
            "UTF‑16: U+10000 < U+E000 because 0xD800 < 0xE000"
        );
        // Byte ordering (what plain &str gives) would be the opposite
        assert!(
            bmp.as_str().as_bytes() < supplementary.as_str().as_bytes(),
            "byte / UTF‑8 ordering: U+E000 < U+10000 (opposite of UTF‑16)"
        );
    }

    #[test]
    fn ord_longer_string_can_be_less_when_prefix_differs() {
        // "ab" starts with 0x0061,0x0062; "b" starts with 0x0062
        // 0x0061 < 0x0062 → "ab" < "b"
        assert!(Utf16Key::new("ab") < Utf16Key::new("b"));
    }

    #[test]
    fn ord_non_bmp_chars() {
        // U+10400 (DESERET CAPITAL LETTER LONG I) is a surrogate pair:
        // 0xD801, 0xDC00 in UTF‑16.
        // U+10300 (OLD ITALIC LETTER A) is 0xD800, 0xDF00.
        // 0xD800 < 0xD801, so old_italic < deseret
        let deseret = Utf16Key::new("\u{10400}");
        let old_italic = Utf16Key::new("\u{10300}");
        assert!(
            old_italic < deseret,
            "expected UTF‑16 ordering: U+10300 < U+10400"
        );
    }

    // ── PartialOrd ──────────────────────────────────────────────────

    #[test]
    fn partial_ord_consistent_with_ord() {
        let a = Utf16Key::new("alpha");
        let b = Utf16Key::new("beta");
        assert_eq!(a.partial_cmp(&b), Some(a.cmp(&b)));
        assert_eq!(b.partial_cmp(&a), Some(b.cmp(&a)));
        assert_eq!(a.partial_cmp(&a), Some(a.cmp(&a)));
    }

    // ── Eq ──────────────────────────────────────────────────────────

    #[test]
    fn eq_equal_strings() {
        assert_eq!(Utf16Key::new("equal"), Utf16Key::new("equal"));
    }

    #[test]
    fn eq_unequal_strings() {
        assert_ne!(Utf16Key::new("not"), Utf16Key::new("equal"));
    }

    // ── From<Utf16Key> for String ───────────────────────────────────

    #[test]
    fn from_utf16key_to_string() {
        let key = Utf16Key::new("owned");
        let s: String = key.into();
        assert_eq!(s, "owned");
    }

    // ── Clone ───────────────────────────────────────────────────────

    #[test]
    fn clone_equals_original() {
        let key = Utf16Key::new("clone me");
        assert_eq!(key.clone(), key);
    }

    // ── Borrow<str> ─────────────────────────────────────────────────

    #[test]
    fn borrow_str_returns_str() {
        use std::borrow::Borrow;
        let key = Utf16Key::new("borrowed");
        let borrowed: &str = key.borrow();
        assert_eq!(borrowed, "borrowed");
    }

    // ── Serialize / Deserialize ────────────────────────────────────

    #[test]
    fn serde_round_trip_json() {
        let key = Utf16Key::new("json round-trip");
        let json = match serde_json::to_string(&key) {
            Ok(j) => j,
            Err(_) => return,
        };
        assert_eq!(json, r#""json round-trip""#);
        let deserialized: Utf16Key = match serde_json::from_str(&json) {
            Ok(d) => d,
            Err(_) => return,
        };
        assert_eq!(deserialized, key);
    }

    #[test]
    fn serde_round_trip_json_with_unicode() {
        let key = Utf16Key::new("héllo wörld 🎉");
        let json = match serde_json::to_string(&key) {
            Ok(j) => j,
            Err(_) => return,
        };
        let deserialized: Utf16Key = match serde_json::from_str(&json) {
            Ok(d) => d,
            Err(_) => return,
        };
        assert_eq!(deserialized, key);
    }
}
