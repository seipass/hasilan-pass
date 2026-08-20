//! Shared client-side cryptographic operations.
//!
//! The server must never call the decrypt functions in this crate in production. Browser
//! clients compile the same implementation to WebAssembly.

mod account;
mod attachment;
mod enc_string;
mod envelope;
mod kdf;
mod keys;
mod sharing;

pub use attachment::{
    ATTACHMENT_FORMAT, AttachmentMetadata, DEFAULT_ATTACHMENT_CHUNK_SIZE,
    MAX_ATTACHMENT_PLAINTEXT_BYTES, decrypt_attachment_chunk, encrypt_attachment_chunk,
};
pub use enc_string::EncString;
pub use envelope::{EncryptedEnvelope, decrypt_json, encrypt_json};
pub use kdf::{KdfConfig, derive_master_key};
pub use keys::{CompositeKey, MasterKey};
pub use sharing::{
    SharingKeyMaterial, SharingPrivateKey, generate_sharing_key, open_organization_key,
    seal_organization_key, unwrap_sharing_private_key,
};

use thiserror::Error;

/// Errors returned by cryptographic parsing and operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// An encoded encrypted string was malformed or unsupported.
    #[error("invalid encrypted string: {0}")]
    InvalidEncString(&'static str),
    /// Base64 data was malformed.
    #[error("invalid base64 data")]
    InvalidBase64(#[from] base64::DecodeError),
    /// Key material had an unexpected length.
    #[error("invalid key length")]
    InvalidKeyLength,
    /// KDF parameters were unsafe or outside client resource bounds.
    #[error("invalid KDF parameters")]
    InvalidKdfParameters,
    /// Authentication failed. This intentionally does not distinguish MAC and padding.
    #[error("ciphertext authentication failed")]
    AuthenticationFailed,
    /// Plaintext could not be decoded as the expected JSON structure.
    #[error("invalid encrypted payload")]
    InvalidPayload(#[from] serde_json::Error),
    /// The operating system random source failed.
    #[error("secure random generation failed")]
    Random(#[from] getrandom::Error),
    /// HKDF expansion failed.
    #[error("key expansion failed")]
    Hkdf,
    /// Argon2 rejected the supplied parameters.
    #[error("key derivation failed")]
    Argon2,
    /// A sharing public key, protected private key, or sealed organization key was invalid.
    #[error("invalid organization sharing key material")]
    InvalidSharingKey,
    /// Attachment metadata or a framed chunk violated the authenticated format.
    #[error("invalid encrypted attachment")]
    InvalidAttachment,
}

/// Crate-local result alias.
pub type Result<T> = std::result::Result<T, CryptoError>;
pub use account::{
    LoginPreparation, RegistrationPreparation, prepare_login, prepare_registration, unwrap_user_key,
};
