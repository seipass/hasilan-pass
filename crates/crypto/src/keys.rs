use std::fmt;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, Result};

/// A 32-byte password-derived key. Its debug representation is always redacted.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[cfg(test)]
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Expands the master key into independent encryption and MAC subkeys.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Hkdf`] if expansion fails.
    pub fn stretch(&self) -> Result<CompositeKey> {
        let hkdf = Hkdf::<Sha256>::from_prk(&self.0).map_err(|_| CryptoError::Hkdf)?;
        let mut encryption = [0_u8; 32];
        let mut authentication = [0_u8; 32];
        hkdf.expand(b"enc", &mut encryption)
            .map_err(|_| CryptoError::Hkdf)?;
        hkdf.expand(b"mac", &mut authentication)
            .map_err(|_| CryptoError::Hkdf)?;

        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&encryption);
        bytes[32..].copy_from_slice(&authentication);
        encryption.zeroize();
        authentication.zeroize();
        Ok(CompositeKey(bytes))
    }

    /// Produces the Bitwarden-compatible server authorization proof.
    #[must_use]
    pub fn authentication_proof(&self, master_password: &[u8]) -> [u8; 32] {
        let mut output = [0_u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(&self.0, master_password, 1, &mut output);
        output
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MasterKey([REDACTED])")
    }
}

/// A 64-byte AES-256-CBC/HMAC-SHA256 composite key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CompositeKey([u8; 64]);

impl CompositeKey {
    /// Generates a fresh key with the operating-system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating-system CSPRNG fails.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0_u8; 64];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Constructs a key from its stable `encryption || MAC` byte encoding.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKeyLength`] unless `bytes` is 64 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: [u8; 64] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        Ok(Self(value))
    }

    /// Exposes the encoded key only to wrapping operations and explicit client storage.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub(crate) fn encryption_key(&self) -> &[u8; 32] {
        self.0[..32]
            .try_into()
            .unwrap_or_else(|_| unreachable!("fixed-size key slice"))
    }

    pub(crate) fn mac_key(&self) -> &[u8; 32] {
        self.0[32..]
            .try_into()
            .unwrap_or_else(|_| unreachable!("fixed-size key slice"))
    }
}

impl fmt::Debug for CompositeKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompositeKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitwarden_hkdf_vector() {
        let master = MasterKey::from_bytes([
            31, 79, 104, 226, 150, 71, 177, 90, 194, 80, 172, 209, 17, 129, 132, 81, 138, 167, 69,
            167, 254, 149, 2, 27, 39, 197, 64, 42, 22, 195, 86, 75,
        ]);
        let stretched = master.stretch().unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            &stretched.as_bytes()[..32],
            &[
                111, 31, 178, 45, 238, 152, 37, 114, 143, 215, 124, 83, 135, 173, 195, 23, 142,
                134, 120, 249, 61, 132, 163, 182, 113, 197, 189, 204, 188, 21, 237, 96,
            ]
        );
        assert_eq!(
            &stretched.as_bytes()[32..],
            &[
                221, 127, 206, 234, 101, 27, 202, 38, 86, 52, 34, 28, 78, 28, 185, 16, 48, 61, 127,
                166, 209, 247, 194, 87, 232, 26, 48, 85, 193, 249, 179, 155,
            ]
        );
    }
}
