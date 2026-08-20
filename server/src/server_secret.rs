//! Authenticated encryption for the small set of server-verifiable MFA secrets.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{config::MfaEncryptionKey, error::AppError};

const FORMAT: &str = "mfa1";
const AAD_DOMAIN: &[u8] = b"hasilan-pass:account-totp:v1";

/// Encrypts an account TOTP seed using a fresh 192-bit nonce and account-bound AAD.
pub fn encrypt_mfa_secret(
    plaintext: &[u8],
    account_id: Uuid,
    key: &MfaEncryptionKey,
) -> Result<String, AppError> {
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| AppError::internal())?;
    let aad = account_aad(account_id);
    let cipher = XChaCha20Poly1305::new(key.bytes().into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| AppError::internal())?;
    Ok(format!(
        "{FORMAT}.{}.{}",
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(ciphertext)
    ))
}

/// Authenticates and decrypts an account TOTP seed loaded from server storage.
pub fn decrypt_mfa_secret(
    encoded: &str,
    account_id: Uuid,
    key: &MfaEncryptionKey,
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    let mut parts = encoded.split('.');
    let format = parts.next();
    let nonce = parts.next();
    let ciphertext = parts.next();
    if format != Some(FORMAT) || parts.next().is_some() {
        return Err(AppError::internal());
    }
    let nonce = URL_SAFE_NO_PAD
        .decode(nonce.unwrap_or_default())
        .map_err(|_| AppError::internal())?;
    let nonce: [u8; 24] = nonce.try_into().map_err(|_| AppError::internal())?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(ciphertext.unwrap_or_default())
        .map_err(|_| AppError::internal())?;
    let aad = account_aad(account_id);
    let cipher = XChaCha20Poly1305::new(key.bytes().into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| AppError::internal())?;
    Ok(Zeroizing::new(plaintext))
}

fn account_aad(account_id: Uuid) -> [u8; AAD_DOMAIN.len() + 16] {
    let mut aad = [0_u8; AAD_DOMAIN.len() + 16];
    aad[..AAD_DOMAIN.len()].copy_from_slice(AAD_DOMAIN);
    aad[AAD_DOMAIN.len()..].copy_from_slice(account_id.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciphertext_is_account_bound_and_authenticated() {
        let key = MfaEncryptionKey::from_bytes([41; 32]);
        let account = Uuid::new_v4();
        let encrypted = encrypt_mfa_secret(b"JBSWY3DPEHPK3PXP", account, &key)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!encrypted.contains("JBSWY3DPEHPK3PXP"));
        assert_eq!(
            decrypt_mfa_secret(&encrypted, account, &key)
                .unwrap_or_else(|error| panic!("{error}"))
                .as_slice(),
            b"JBSWY3DPEHPK3PXP"
        );
        assert!(decrypt_mfa_secret(&encrypted, Uuid::new_v4(), &key).is_err());

        let mut tampered = encrypted.into_bytes();
        if let Some(last) = tampered.last_mut() {
            *last = if *last == b'A' { b'B' } else { b'A' };
        }
        let tampered = String::from_utf8(tampered).unwrap_or_default();
        assert!(decrypt_mfa_secret(&tampered, account, &key).is_err());
    }
}
