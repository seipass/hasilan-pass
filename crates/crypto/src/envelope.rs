use std::str::FromStr;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::{Zeroize, Zeroizing};

use crate::{CompositeKey, EncString, Result};

/// Current whole-item encrypted envelope sent to the untrusted server.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedEnvelope {
    /// Versioned envelope identifier.
    pub format: String,
    /// Random item key encrypted by a user or organization key.
    pub wrapped_key: String,
    /// Complete private JSON item encrypted by the random item key.
    pub payload: String,
}

/// Encrypts a serializable item under a fresh per-item key.
///
/// # Errors
///
/// Returns an error if serialization, random generation, or encryption fails.
pub fn encrypt_json<T: Serialize>(
    value: &T,
    owner_key: &CompositeKey,
) -> Result<EncryptedEnvelope> {
    let item_key = CompositeKey::generate()?;
    let mut plaintext = Zeroizing::new(serde_json::to_vec(value)?);
    let payload = EncString::encrypt(&plaintext, &item_key)?;
    plaintext.zeroize();
    let wrapped_key = EncString::encrypt(item_key.as_bytes(), owner_key)?;

    Ok(EncryptedEnvelope {
        format: "hp.v1".to_owned(),
        wrapped_key: wrapped_key.to_string(),
        payload: payload.to_string(),
    })
}

/// Decrypts and parses an encrypted item envelope.
///
/// # Errors
///
/// Returns an error for an unsupported format, invalid wrapped key, failed
/// authentication, or malformed plaintext JSON.
pub fn decrypt_json<T: DeserializeOwned>(
    envelope: &EncryptedEnvelope,
    owner_key: &CompositeKey,
) -> Result<T> {
    if envelope.format != "hp.v1" {
        return Err(crate::CryptoError::InvalidEncString(
            "unsupported envelope format",
        ));
    }
    let wrapped = EncString::from_str(&envelope.wrapped_key)?;
    let item_key_bytes = wrapped.decrypt(owner_key)?;
    let item_key = CompositeKey::from_slice(&item_key_bytes)?;
    let payload = EncString::from_str(&envelope.payload)?;
    let plaintext = payload.decrypt(&item_key)?;
    Ok(serde_json::from_slice(&plaintext)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
    struct Example {
        marker: String,
    }

    #[test]
    fn envelope_round_trip() {
        let owner_key = CompositeKey::generate().unwrap_or_else(|error| panic!("{error}"));
        let input = Example {
            marker: "not-on-server".to_owned(),
        };
        let encrypted = encrypt_json(&input, &owner_key).unwrap_or_else(|error| panic!("{error}"));
        assert!(!encrypted.payload.contains(&input.marker));
        let output: Example =
            decrypt_json(&encrypted, &owner_key).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(input, output);
    }
}
