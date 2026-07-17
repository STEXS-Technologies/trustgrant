use std::fmt::{Display, Formatter, Result as FmtResult};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use trustgrant_error::TrustGrantError;

fn parse_prefixed_uuid(
    value: &str,
    expected_prefix: &'static str,
) -> Result<Uuid, TrustGrantError> {
    let (prefix, raw_uuid) = value
        .split_once('_')
        .ok_or(TrustGrantError::MissingIdSeparator)?;

    if prefix != expected_prefix {
        return Err(TrustGrantError::InvalidIdPrefix { expected_prefix });
    }

    Uuid::parse_str(raw_uuid).map_err(|uuid_error| {
        let _ = uuid_error;
        TrustGrantError::InvalidIdUuid
    })
}

macro_rules! prefixed_uuid_newtype {
    ($(#[$attr:meta])* $name:ident, $prefix:literal) => {
        $(#[$attr])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        pub struct $name(Uuid);

        impl $name {
            /// Generated protocol ID should be used in a signable document.
            #[must_use]
            pub fn generate() -> Self {
                Self(Uuid::new_v4())
            }

            /// UUID-backed protocol ID should be used for storage or comparison.
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// UUID should be used for storage or comparison.
            #[must_use]
            pub const fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
                write!(formatter, "{}_{}", $prefix, self.0)
            }
        }

        impl FromStr for $name {
            type Err = TrustGrantError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Ok(Self(parse_prefixed_uuid(value, $prefix)?))
            }
        }
    };
}

prefixed_uuid_newtype!(
    /// A protocol-level identifier for one TrustGrant document.
    ///
    /// Uses a UUIDv4 with the `tg_` prefix (e.g. `tg_123e4567-e89b-12d3-a456-426614174000`).
    TrustGrantId, "tg");
prefixed_uuid_newtype!(
    /// Identifies a grant series — all revisions of a grant share the same
    /// series ID.
    ///
    /// Uses a UUIDv4 with the `tgs_` prefix (e.g. `tgs_123e4567-e89b-12d3-a456-426614174001`).
    GrantSeriesId, "tgs");
prefixed_uuid_newtype!(
    /// Identifies one ownership transition document.
    ///
    /// Uses a UUIDv4 with the `tgt_` prefix (e.g. `tgt_123e4567-e89b-12d3-a456-426614174002`).
    TransitionId, "tgt");
prefixed_uuid_newtype!(
    /// Identifies a transition series — all revisions of an ownership
    /// transition share the same series ID.
    ///
    /// Uses a UUIDv4 with the `tgts_` prefix.
    TransitionSeriesId, "tgts");

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use std::str::FromStr;

    use uuid::Uuid;

    use super::{GrantSeriesId, TransitionId, TransitionSeriesId, TrustGrantId};
    use trustgrant_error::TrustGrantError;

    #[test]
    fn trustgrant_id_roundtrips_with_prefix() {
        let id = TrustGrantId::generate();
        let reparsed = match TrustGrantId::from_str(&id.to_string()) {
            Ok(value) => value,
            Err(error) => panic!("generated TrustGrant ID should roundtrip: {error}"),
        };

        assert_eq!(reparsed, id);
    }

    #[test]
    fn prefixed_ids_reject_wrong_prefix() {
        let raw = format!("wrong_{}", Uuid::new_v4());

        assert!(TrustGrantId::from_str(&raw).is_err());
        assert!(GrantSeriesId::from_str(&raw).is_err());
        assert!(TransitionId::from_str(&raw).is_err());
        assert!(TransitionSeriesId::from_str(&raw).is_err());
    }

    #[test]
    fn prefixed_ids_reject_no_separator() {
        assert_eq!(
            TrustGrantId::from_str("noseparatoratall"),
            Err(TrustGrantError::MissingIdSeparator)
        );
        assert_eq!(
            GrantSeriesId::from_str("noseparatoratall"),
            Err(TrustGrantError::MissingIdSeparator)
        );
        assert_eq!(
            TransitionId::from_str("noseparatoratall"),
            Err(TrustGrantError::MissingIdSeparator)
        );
        assert_eq!(
            TransitionSeriesId::from_str("noseparatoratall"),
            Err(TrustGrantError::MissingIdSeparator)
        );
    }

    #[test]
    fn prefixed_ids_reject_invalid_uuid() {
        assert_eq!(
            TrustGrantId::from_str("tg_not-a-uuid"),
            Err(TrustGrantError::InvalidIdUuid)
        );
        assert_eq!(
            GrantSeriesId::from_str("tgs_not-a-uuid"),
            Err(TrustGrantError::InvalidIdUuid)
        );
        assert_eq!(
            TransitionId::from_str("tgt_not-a-uuid"),
            Err(TrustGrantError::InvalidIdUuid)
        );
        assert_eq!(
            TransitionSeriesId::from_str("tgts_not-a-uuid"),
            Err(TrustGrantError::InvalidIdUuid)
        );
    }

    #[test]
    fn trustgrant_id_from_uuid_round_trips() {
        let uuid = Uuid::new_v4();
        let id = TrustGrantId::from_uuid(uuid);
        assert_eq!(id.as_uuid(), uuid);
        assert!(id.to_string().starts_with("tg_"));
    }

    #[test]
    fn grant_series_id_from_uuid_round_trips() {
        let uuid = Uuid::new_v4();
        let id = GrantSeriesId::from_uuid(uuid);
        assert_eq!(id.as_uuid(), uuid);
        assert!(id.to_string().starts_with("tgs_"));
    }

    #[test]
    fn transition_id_from_uuid_round_trips() {
        let uuid = Uuid::new_v4();
        let id = TransitionId::from_uuid(uuid);
        assert_eq!(id.as_uuid(), uuid);
        assert!(id.to_string().starts_with("tgt_"));
    }

    #[test]
    fn transition_series_id_from_uuid_round_trips() {
        let uuid = Uuid::new_v4();
        let id = TransitionSeriesId::from_uuid(uuid);
        assert_eq!(id.as_uuid(), uuid);
        assert!(id.to_string().starts_with("tgts_"));
    }

    #[test]
    fn prefixed_id_accepts_uppercase_uuid() {
        // UUIDs are case-insensitive per RFC 4122
        let id = "tg_123E4567-E89B-12D3-A456-426614174000".parse::<TrustGrantId>();
        assert!(
            id.is_ok(),
            "uppercase UUID should be accepted in a prefixed TrustGrantId"
        );
        let id = id.unwrap_or_else(|e| panic!("ID should be Ok: {e}"));
        assert!(
            id.to_string()
                .contains("123e4567-e89b-12d3-a456-426614174000"),
            "displayed ID should use lowercase hex"
        );
    }

    #[test]
    fn prefixed_id_accepts_lowercase_uuid() {
        let id = "tg_123e4567-e89b-12d3-a456-426614174000".parse::<TrustGrantId>();
        assert!(id.is_ok(), "lowercase UUID should be accepted");
    }

    #[test]
    fn prefixed_id_accepts_mixed_case_uuid() {
        let id = "tgs_ABCDef01-2345-6789-ABCD-EF0123456789".parse::<GrantSeriesId>();
        assert!(
            id.is_ok(),
            "mixed-case UUID should be accepted in GrantSeriesId"
        );
    }

    #[test]
    fn prefixed_ids_reject_valid_uuid_wrong_prefix() {
        let raw_uuid = format!("{}", Uuid::new_v4());

        assert_eq!(
            TrustGrantId::from_str(&format!("tgs_{raw_uuid}")),
            Err(TrustGrantError::InvalidIdPrefix {
                expected_prefix: "tg"
            })
        );
        assert_eq!(
            GrantSeriesId::from_str(&format!("tg_{raw_uuid}")),
            Err(TrustGrantError::InvalidIdPrefix {
                expected_prefix: "tgs"
            })
        );
        assert_eq!(
            TransitionId::from_str(&format!("tgts_{raw_uuid}")),
            Err(TrustGrantError::InvalidIdPrefix {
                expected_prefix: "tgt"
            })
        );
        assert_eq!(
            TransitionSeriesId::from_str(&format!("tgt_{raw_uuid}")),
            Err(TrustGrantError::InvalidIdPrefix {
                expected_prefix: "tgts"
            })
        );
    }
}
