//! Serde helpers that encode fixed-size byte arrays as lowercase hex strings.

use serde::{Deserialize, Deserializer, Serializer};

/// Serialize `[u8; N]` as hex.
///
/// # Errors
/// Propagates serializer errors.
pub fn serialize<S: Serializer, const N: usize>(
    bytes: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex::encode(bytes))
}

/// Deserialize `[u8; N]` from a hex string.
///
/// # Errors
/// Fails on non-hex input or wrong length.
pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    let s = String::deserialize(deserializer)?;
    let raw = hex::decode(&s).map_err(serde::de::Error::custom)?;
    <[u8; N]>::try_from(raw.as_slice())
        .map_err(|_| serde::de::Error::custom(format!("expected {N} bytes, got {}", raw.len())))
}

/// Same as the parent module but for `Option<[u8; N]>`.
pub mod option {
    use super::{Deserialize, Deserializer, Serializer};

    /// Serialize `Option<[u8; N]>` as hex or null.
    ///
    /// # Errors
    /// Propagates serializer errors.
    pub fn serialize<S: Serializer, const N: usize>(
        bytes: &Option<[u8; N]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => serializer.serialize_some(&hex::encode(b)),
            None => serializer.serialize_none(),
        }
    }

    /// Deserialize `Option<[u8; N]>` from hex or null.
    ///
    /// # Errors
    /// Fails on non-hex input or wrong length.
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<Option<[u8; N]>, D::Error> {
        let Some(s) = Option::<String>::deserialize(deserializer)? else {
            return Ok(None);
        };
        let raw = hex::decode(&s).map_err(serde::de::Error::custom)?;
        <[u8; N]>::try_from(raw.as_slice())
            .map(Some)
            .map_err(|_| serde::de::Error::custom(format!("expected {N} bytes, got {}", raw.len())))
    }
}
