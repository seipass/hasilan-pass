use zeroize::Zeroizing;

use crate::{CompositeKey, EncString, KdfConfig, Result, derive_master_key};

/// Password-derived registration material shared by every first-party client.
pub struct RegistrationPreparation {
    /// Bitwarden-compatible server authorization proof bytes.
    pub authentication_proof: [u8; 32],
    /// Random user key protected by the stretched password-derived key.
    pub protected_user_key: String,
    /// Unwrapped user key retained only by the unlocked client runtime.
    pub user_key: CompositeKey,
}

/// Intermediate login material retained only until the server returns the wrapped user key.
pub struct LoginPreparation {
    /// Bitwarden-compatible server authorization proof bytes.
    pub authentication_proof: [u8; 32],
    unlock_key: CompositeKey,
}

impl LoginPreparation {
    /// Consumes the pending unlock key and authenticates/decrypts a protected user key.
    ///
    /// # Errors
    ///
    /// Returns an authentication error for a wrong master password or malformed key envelope.
    pub fn finish(self, protected_user_key: &str) -> Result<CompositeKey> {
        unwrap_user_key(protected_user_key, &self.unlock_key)
    }
}

/// Derives a new account's authorization proof and wrapped random user key.
///
/// # Errors
///
/// Returns an error for unsafe KDF parameters or a cryptographic/random-source failure.
pub fn prepare_registration(
    email: &str,
    master_password: &[u8],
    kdf: &KdfConfig,
) -> Result<RegistrationPreparation> {
    let master = derive_master_key(master_password, email, kdf)?;
    let authentication_proof = master.authentication_proof(master_password);
    let unlock_key = master.stretch()?;
    let user_key = CompositeKey::generate()?;
    let protected_user_key = EncString::encrypt(user_key.as_bytes(), &unlock_key)?.to_string();
    Ok(RegistrationPreparation {
        authentication_proof,
        protected_user_key,
        user_key,
    })
}

/// Derives an authorization proof and a short-lived key used after server login.
///
/// # Errors
///
/// Returns an error for unsafe KDF parameters or a key-derivation failure.
pub fn prepare_login(
    email: &str,
    master_password: &[u8],
    kdf: &KdfConfig,
) -> Result<LoginPreparation> {
    let master = derive_master_key(master_password, email, kdf)?;
    Ok(LoginPreparation {
        authentication_proof: master.authentication_proof(master_password),
        unlock_key: master.stretch()?,
    })
}

/// Authenticates and unwraps a user key using a password-derived unlock key.
///
/// # Errors
///
/// Returns an authentication error for a wrong key or malformed protected material.
pub fn unwrap_user_key(
    protected_user_key: &str,
    unlock_key: &CompositeKey,
) -> Result<CompositeKey> {
    let protected: EncString = protected_user_key.parse()?;
    let bytes = Zeroizing::new(protected.decrypt(unlock_key)?);
    CompositeKey::from_slice(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_and_login_share_the_same_user_key() {
        let kdf = KdfConfig::Argon2id {
            iterations: 2,
            memory_mib: 16,
            parallelism: 1,
        };
        let password = b"a long test master password";
        let registration = prepare_registration("alice@example.test", password, &kdf)
            .unwrap_or_else(|error| panic!("{error}"));
        let expected = registration.user_key.as_bytes().to_vec();
        let login = prepare_login("alice@example.test", password, &kdf)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            registration.authentication_proof,
            login.authentication_proof
        );
        let actual = login
            .finish(&registration.protected_user_key)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(actual.as_bytes(), expected.as_slice());
    }

    #[test]
    fn wrong_password_cannot_unwrap_the_user_key() {
        let kdf = KdfConfig::Pbkdf2 {
            iterations: 600_000,
        };
        let registration = prepare_registration("alice@example.test", b"correct password", &kdf)
            .unwrap_or_else(|error| panic!("{error}"));
        let wrong = prepare_login("alice@example.test", b"wrong password", &kdf)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(wrong.finish(&registration.protected_user_key).is_err());
    }
}
