use std::{collections::BTreeMap, sync::Mutex};

use thiserror::Error;

/// An OS-backed secret store used for refresh tokens and future biometric unlock material.
pub trait SecretStore: Send + Sync {
    /// Loads one secret, returning `None` when it has not been stored.
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretStoreError>;
    /// Replaces one secret atomically according to the platform credential store.
    fn set(&self, key: &str, value: &[u8]) -> Result<(), SecretStoreError>;
    /// Removes one secret. Removing an absent entry succeeds.
    fn delete(&self, key: &str) -> Result<(), SecretStoreError>;
}

/// A deliberately detail-free credential-store failure safe to show in UI.
#[derive(Debug, Error)]
#[error("the operating-system credential store is unavailable")]
pub struct SecretStoreError;

/// System Keychain / Credential Manager / Secret Service implementation.
pub struct KeyringSecretStore {
    service: String,
}

impl KeyringSecretStore {
    /// Creates a namespaced native credential-store adapter.
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, key: &str) -> Result<keyring::Entry, SecretStoreError> {
        keyring::Entry::new(&self.service, key).map_err(|_| SecretStoreError)
    }
}

impl SecretStore for KeyringSecretStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretStoreError> {
        match self.entry(key)?.get_secret() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(SecretStoreError),
        }
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<(), SecretStoreError> {
        self.entry(key)?
            .set_secret(value)
            .map_err(|_| SecretStoreError)
    }

    fn delete(&self, key: &str) -> Result<(), SecretStoreError> {
        match self.entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(SecretStoreError),
        }
    }
}

/// In-memory implementation for deterministic tests; never used by production startup.
#[derive(Default)]
pub struct MemorySecretStore {
    values: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl SecretStore for MemorySecretStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretStoreError> {
        Ok(self
            .values
            .lock()
            .map_err(|_| SecretStoreError)?
            .get(key)
            .cloned())
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<(), SecretStoreError> {
        self.values
            .lock()
            .map_err(|_| SecretStoreError)?
            .insert(key.to_owned(), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), SecretStoreError> {
        self.values
            .lock()
            .map_err(|_| SecretStoreError)?
            .remove(key);
        Ok(())
    }
}
