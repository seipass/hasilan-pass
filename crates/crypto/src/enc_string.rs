use std::{fmt, str::FromStr};

use aes::Aes256;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{CompositeKey, CryptoError, Result};

type Aes256CbcEncryptor = cbc::Encryptor<Aes256>;
type Aes256CbcDecryptor = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

const MAX_CIPHERTEXT_BYTES: usize = 16 * 1024 * 1024;

/// A parsed Bitwarden-compatible encrypted string.
#[derive(Clone, Eq, PartialEq)]
pub enum EncString {
    /// Legacy unauthenticated AES-256-CBC. This variant is decrypt-only.
    Type0 {
        /// AES-CBC initialization vector.
        iv: [u8; 16],
        /// PKCS#7-padded AES ciphertext.
        ciphertext: Vec<u8>,
    },
    /// AES-256-CBC with encrypt-then-HMAC-SHA256.
    Type2 {
        /// AES-CBC initialization vector.
        iv: [u8; 16],
        /// PKCS#7-padded AES ciphertext.
        ciphertext: Vec<u8>,
        /// HMAC-SHA256 over `iv || ciphertext`.
        mac: [u8; 32],
    },
}

impl EncString {
    /// Encrypts plaintext as authenticated type 2 using a fresh IV.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating-system CSPRNG fails.
    pub fn encrypt(plaintext: &[u8], key: &CompositeKey) -> Result<Self> {
        let mut iv = [0_u8; 16];
        getrandom::fill(&mut iv)?;
        Ok(Self::encrypt_with_iv(plaintext, key, iv))
    }

    fn encrypt_with_iv(plaintext: &[u8], key: &CompositeKey, iv: [u8; 16]) -> Self {
        let ciphertext = Aes256CbcEncryptor::new(key.encryption_key().into(), (&iv).into())
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
        let mac = calculate_mac(&iv, &ciphertext, key.mac_key());
        Self::Type2 {
            iv,
            ciphertext,
            mac,
        }
    }

    /// Authenticates and decrypts this value. Type 0 remains available only for migration.
    ///
    /// # Errors
    ///
    /// Returns an authentication error for an invalid MAC or padding.
    pub fn decrypt(&self, key: &CompositeKey) -> Result<Zeroizing<Vec<u8>>> {
        let (iv, ciphertext) = match self {
            Self::Type2 {
                iv,
                ciphertext,
                mac,
            } => {
                let expected = calculate_mac(iv, ciphertext, key.mac_key());
                if expected.as_slice().ct_eq(mac.as_slice()).unwrap_u8() != 1 {
                    return Err(CryptoError::AuthenticationFailed);
                }
                (iv, ciphertext)
            }
            Self::Type0 { iv, ciphertext } => (iv, ciphertext),
        };

        let mut buffer = Zeroizing::new(ciphertext.clone());
        let plaintext = Aes256CbcDecryptor::new(key.encryption_key().into(), iv.into())
            .decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        let length = plaintext.len();
        buffer.truncate(length);
        Ok(buffer)
    }

    /// Serializes the stable textual representation.
    #[must_use]
    pub fn expose_ciphertext(&self) -> String {
        self.to_string()
    }
}

fn calculate_mac(iv: &[u8], ciphertext: &[u8], key: &[u8]) -> [u8; 32] {
    let mut hmac = <HmacSha256 as Mac>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC accepts a 32-byte key"));
    hmac.update(iv);
    hmac.update(ciphertext);
    hmac.finalize().into_bytes().into()
}

impl FromStr for EncString {
    type Err = CryptoError;

    fn from_str(value: &str) -> Result<Self> {
        if value.len() > MAX_CIPHERTEXT_BYTES.saturating_mul(2) {
            return Err(CryptoError::InvalidEncString("value too large"));
        }
        let (kind, body) = value
            .split_once('.')
            .ok_or(CryptoError::InvalidEncString("missing type"))?;
        let parts: Vec<&str> = body.split('|').collect();
        match (kind, parts.as_slice()) {
            ("0", [iv, ciphertext]) => Ok(Self::Type0 {
                iv: decode_array(iv)?,
                ciphertext: decode_ciphertext(ciphertext)?,
            }),
            ("2", [iv, ciphertext, mac]) => Ok(Self::Type2 {
                iv: decode_array(iv)?,
                ciphertext: decode_ciphertext(ciphertext)?,
                mac: decode_array(mac)?,
            }),
            ("7", _) => Err(CryptoError::InvalidEncString(
                "COSE type 7 is not supported by hp.v1",
            )),
            _ => Err(CryptoError::InvalidEncString(
                "unsupported type or part count",
            )),
        }
    }
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    let decoded = STANDARD.decode(value)?;
    decoded
        .try_into()
        .map_err(|_| CryptoError::InvalidEncString("invalid component length"))
}

fn decode_ciphertext(value: &str) -> Result<Vec<u8>> {
    let decoded = STANDARD.decode(value)?;
    if decoded.is_empty()
        || decoded.len() > MAX_CIPHERTEXT_BYTES
        || !decoded.len().is_multiple_of(16)
    {
        return Err(CryptoError::InvalidEncString("invalid ciphertext length"));
    }
    Ok(decoded)
}

impl fmt::Display for EncString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type0 { iv, ciphertext } => write!(
                formatter,
                "0.{}|{}",
                STANDARD.encode(iv),
                STANDARD.encode(ciphertext)
            ),
            Self::Type2 {
                iv,
                ciphertext,
                mac,
            } => write!(
                formatter,
                "2.{}|{}|{}",
                STANDARD.encode(iv),
                STANDARD.encode(ciphertext),
                STANDARD.encode(mac)
            ),
        }
    }
}

impl fmt::Debug for EncString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type0 { ciphertext, .. } => formatter
                .debug_struct("EncString::Type0")
                .field("ciphertext_bytes", &ciphertext.len())
                .finish(),
            Self::Type2 { ciphertext, .. } => formatter
                .debug_struct("EncString::Type2")
                .field("ciphertext_bytes", &ciphertext.len())
                .finish(),
        }
    }
}

impl Drop for EncString {
    fn drop(&mut self) {
        match self {
            Self::Type0 { iv, ciphertext } => {
                iv.zeroize();
                ciphertext.zeroize();
            }
            Self::Type2 {
                iv,
                ciphertext,
                mac,
            } => {
                iv.zeroize();
                ciphertext.zeroize();
                mac.zeroize();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> CompositeKey {
        CompositeKey::from_slice(&(0_u8..64).collect::<Vec<_>>())
            .unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn matches_reviewed_bitwarden_type2_vector() {
        let encrypted = EncString::encrypt_with_iv(
            b"Bitwarden SDK test vector",
            &test_key(),
            [
                216, 218, 36, 0, 196, 186, 150, 85, 49, 147, 110, 168, 185, 227, 42, 172,
            ],
        );
        let EncString::Type2 {
            ciphertext, mac, ..
        } = &encrypted
        else {
            panic!("type 2 expected");
        };
        assert_eq!(
            ciphertext,
            &[
                234, 77, 16, 15, 189, 82, 36, 188, 182, 88, 64, 67, 145, 94, 30, 178, 36, 235, 130,
                67, 255, 207, 183, 168, 73, 231, 82, 122, 193, 139, 25, 129,
            ]
        );
        assert_eq!(
            mac,
            &[
                60, 78, 44, 111, 72, 233, 3, 6, 86, 250, 217, 242, 62, 229, 184, 221, 231, 150,
                189, 44, 99, 189, 220, 55, 196, 194, 101, 60, 102, 195, 149, 130,
            ]
        );
        assert_eq!(
            encrypted
                .decrypt(&test_key())
                .unwrap_or_else(|error| panic!("{error}"))
                .as_slice(),
            b"Bitwarden SDK test vector"
        );
    }

    #[test]
    fn rejects_tampering_before_decryption() {
        let mut encrypted =
            EncString::encrypt(b"secret", &test_key()).unwrap_or_else(|error| panic!("{error}"));
        if let EncString::Type2 { ciphertext, .. } = &mut encrypted {
            ciphertext[0] ^= 1;
        }
        assert!(matches!(
            encrypted.decrypt(&test_key()),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn text_round_trip_is_stable() {
        let encrypted =
            EncString::encrypt(b"hello", &test_key()).unwrap_or_else(|error| panic!("{error}"));
        let text = encrypted.to_string();
        let parsed: EncString = text.parse().unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(encrypted, parsed);
    }
}
