//! Shared decrypted vault domain behavior.

mod generator;
mod model;
mod passkey;
mod search;
mod totp;
mod uri;

pub use generator::{
    GeneratorError, PassphraseOptions, PasswordOptions, UsernameOptions, generate_passphrase,
    generate_password, generate_username,
};
pub use model::*;
pub use passkey::{
    PasskeyAssertionOptions, PasskeyAssertionResult, PasskeyCandidate, PasskeyCreationOptions,
    PasskeyCreationResult, PasskeyError, assert_passkey, create_passkey, passkey_credential_id,
    passkey_matches_request, validate_passkey_assertion, validate_passkey_creation,
};
pub use search::{SearchHit, search};
pub use totp::{TotpAlgorithm, TotpCode, TotpConfig, TotpError};
pub use uri::{UriMatchError, UriMatchType, uri_matches};
