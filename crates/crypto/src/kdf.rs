use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{CryptoError, MasterKey, Result};

const MIN_PBKDF2_ITERATIONS: u32 = 600_000;
const MAX_PBKDF2_ITERATIONS: u32 = 5_000_000;
const MIN_ARGON2_MEMORY_MIB: u32 = 16;
const MAX_ARGON2_MEMORY_MIB: u32 = 256;
const MIN_ARGON2_ITERATIONS: u32 = 2;
const MAX_ARGON2_ITERATIONS: u32 = 20;
const MAX_ARGON2_PARALLELISM: u32 = 16;

/// Supported account key-derivation settings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum KdfConfig {
    /// PBKDF2-HMAC-SHA256 compatibility mode.
    Pbkdf2 {
        /// PBKDF2 iteration count.
        iterations: u32,
    },
    /// Argon2id with memory expressed in MiB.
    Argon2id {
        /// Argon2 time cost.
        iterations: u32,
        /// Argon2 memory cost in MiB.
        memory_mib: u32,
        /// Argon2 lane count.
        parallelism: u32,
    },
}

impl Default for KdfConfig {
    fn default() -> Self {
        Self::Argon2id {
            iterations: 6,
            memory_mib: 32,
            parallelism: 4,
        }
    }
}

impl KdfConfig {
    /// Rejects weak settings and hostile resource allocations before derivation.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKdfParameters`] outside supported bounds.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Pbkdf2 { iterations }
                if (MIN_PBKDF2_ITERATIONS..=MAX_PBKDF2_ITERATIONS).contains(iterations) =>
            {
                Ok(())
            }
            Self::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } if (MIN_ARGON2_ITERATIONS..=MAX_ARGON2_ITERATIONS).contains(iterations)
                && (MIN_ARGON2_MEMORY_MIB..=MAX_ARGON2_MEMORY_MIB).contains(memory_mib)
                && (1..=MAX_ARGON2_PARALLELISM).contains(parallelism) =>
            {
                Ok(())
            }
            _ => Err(CryptoError::InvalidKdfParameters),
        }
    }
}

/// Derives the account master key without retaining a password copy.
///
/// # Errors
///
/// Returns an error for empty identity material, unsafe parameters, or an
/// Argon2 derivation failure.
pub fn derive_master_key(password: &[u8], email: &str, config: &KdfConfig) -> Result<MasterKey> {
    config.validate()?;
    let normalized_email = email.trim().to_lowercase();
    if normalized_email.is_empty() || password.is_empty() {
        return Err(CryptoError::InvalidKdfParameters);
    }

    let mut output = Zeroizing::new([0_u8; 32]);
    match config {
        KdfConfig::Pbkdf2 { iterations } => {
            pbkdf2::pbkdf2_hmac::<Sha256>(
                password,
                normalized_email.as_bytes(),
                *iterations,
                output.as_mut(),
            );
        }
        KdfConfig::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => {
            let salt = Sha256::digest(normalized_email.as_bytes());
            let memory_kib = memory_mib
                .checked_mul(1024)
                .ok_or(CryptoError::InvalidKdfParameters)?;
            let params = Params::new(memory_kib, *iterations, *parallelism, Some(32))
                .map_err(|_| CryptoError::Argon2)?;
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(password, &salt, output.as_mut())
                .map_err(|_| CryptoError::Argon2)?;
        }
    }

    Ok(MasterKey::from_bytes(*output))
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    use super::*;

    #[test]
    fn bitwarden_pbkdf2_master_and_auth_hash_vector() {
        let password = b"asdfasdf";
        let key = derive_master_key(
            password,
            " TEST@bitwarden.com ",
            &KdfConfig::Pbkdf2 {
                iterations: 600_000,
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let proof = key.authentication_proof(password);

        // Independently reproduced with Python's `hashlib.pbkdf2_hmac` using the
        // Bitwarden SDK construction and the current 600,000-iteration policy.
        assert_eq!(
            STANDARD.encode(proof),
            "l0j2NrfATaQS7IyFlGBFN83wWcrTOcriYjNJbo+VC2M="
        );
    }

    #[test]
    fn bitwarden_argon2_vector() {
        let key = derive_master_key(
            b"67t9b5g67$%Dh89n",
            "test_key",
            &KdfConfig::Argon2id {
                iterations: 4,
                memory_mib: 32,
                parallelism: 2,
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            key.bytes(),
            &[
                207, 240, 225, 177, 162, 19, 163, 76, 98, 106, 179, 175, 224, 9, 17, 240, 20, 147,
                237, 47, 246, 150, 141, 184, 62, 225, 131, 242, 51, 53, 225, 242,
            ]
        );
    }

    #[test]
    fn rejects_hostile_parameters() {
        assert!(
            KdfConfig::Argon2id {
                iterations: 6,
                memory_mib: 4096,
                parallelism: 4,
            }
            .validate()
            .is_err()
        );
        assert!(KdfConfig::Pbkdf2 { iterations: 5 }.validate().is_err());
    }
}
