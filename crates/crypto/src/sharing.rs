use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{CompositeKey, CryptoError, EncString, Result};

const CONTEXT: &[u8] = b"hasilan-pass:organization-key:v1";
const ENVELOPE_PREFIX: &str = "hp-share.v1";

/// Public account sharing key and its user-key-encrypted private counterpart.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharingKeyMaterial {
    /// Canonical unpadded base64url X25519 public key.
    pub public_key: String,
    /// Bitwarden-compatible type-2 encryption of the raw private key under the user key.
    pub protected_private_key: String,
}

/// Decrypted account sharing private key retained only in an unlocked client.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharingPrivateKey {
    bytes: [u8; 32],
    public: [u8; 32],
}

impl std::fmt::Debug for SharingPrivateKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SharingPrivateKey([REDACTED])")
    }
}

/// Generates a new X25519 account key and protects the private half under the user key.
///
/// # Errors
///
/// Returns an error if secure randomness or authenticated encryption fails.
pub fn generate_sharing_key(user_key: &CompositeKey) -> Result<SharingKeyMaterial> {
    let mut private = Zeroizing::new([0_u8; 32]);
    getrandom::fill(private.as_mut())?;
    let secret = StaticSecret::from(*private);
    let public = PublicKey::from(&secret).to_bytes();
    let protected = EncString::encrypt(private.as_ref(), user_key)?;
    Ok(SharingKeyMaterial {
        public_key: URL_SAFE_NO_PAD.encode(public),
        protected_private_key: protected.to_string(),
    })
}

/// Decrypts an account sharing private key and verifies it matches the advertised public key.
///
/// # Errors
///
/// Returns an indistinguishable sharing-key error for malformed or mismatched key material.
pub fn unwrap_sharing_private_key(
    public_key: &str,
    protected_private_key: &str,
    user_key: &CompositeKey,
) -> Result<SharingPrivateKey> {
    let expected_public: [u8; 32] = decode_array(public_key)?;
    let protected =
        EncString::from_str(protected_private_key).map_err(|_| CryptoError::InvalidSharingKey)?;
    let decrypted = protected
        .decrypt(user_key)
        .map_err(|_| CryptoError::InvalidSharingKey)?;
    let bytes: [u8; 32] = decrypted
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidSharingKey)?;
    let calculated = PublicKey::from(&StaticSecret::from(bytes)).to_bytes();
    if calculated.ct_eq(&expected_public).unwrap_u8() != 1 {
        return Err(CryptoError::InvalidSharingKey);
    }
    Ok(SharingPrivateKey {
        bytes,
        public: calculated,
    })
}

/// Encrypts a 64-byte organization composite key to one account sharing public key.
///
/// The wrapper uses ephemeral X25519, HKDF-SHA256, and XChaCha20-Poly1305. Its associated
/// data binds the organization UUID, recipient public key, and ephemeral public key.
///
/// # Errors
///
/// Returns an error for malformed recipient keys, low-order points, or CSPRNG failure.
pub fn seal_organization_key(
    organization_id: Uuid,
    recipient_public_key: &str,
    organization_key: &CompositeKey,
) -> Result<String> {
    let recipient_bytes = decode_array(recipient_public_key)?;
    let recipient = PublicKey::from(recipient_bytes);
    let mut ephemeral_bytes = Zeroizing::new([0_u8; 32]);
    getrandom::fill(ephemeral_bytes.as_mut())?;
    let ephemeral_secret = StaticSecret::from(*ephemeral_bytes);
    let ephemeral_public = PublicKey::from(&ephemeral_secret).to_bytes();
    let mut shared = Zeroizing::new(ephemeral_secret.diffie_hellman(&recipient).to_bytes());
    reject_low_order(&shared)?;
    let key = derive_sealing_key(
        &shared,
        organization_id,
        &recipient_bytes,
        &ephemeral_public,
    )?;
    shared.zeroize();
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce)?;
    let aad = associated_data(organization_id, &recipient_bytes, &ephemeral_public);
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: organization_key.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    Ok(format!(
        "{ENVELOPE_PREFIX}.{}.{}.{}",
        URL_SAFE_NO_PAD.encode(ephemeral_public),
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(ciphertext)
    ))
}

/// Opens a recipient-bound organization key wrapper inside an unlocked client.
///
/// # Errors
///
/// Returns a uniform authentication error for wrong accounts, organization IDs, or tampering.
pub fn open_organization_key(
    private_key: &SharingPrivateKey,
    organization_id: Uuid,
    envelope: &str,
) -> Result<CompositeKey> {
    let (ephemeral_public, nonce, ciphertext) = parse_envelope(envelope)?;
    let secret = StaticSecret::from(private_key.bytes);
    let ephemeral = PublicKey::from(ephemeral_public);
    let mut shared = Zeroizing::new(secret.diffie_hellman(&ephemeral).to_bytes());
    reject_low_order(&shared)?;
    let key = derive_sealing_key(
        &shared,
        organization_id,
        &private_key.public,
        &ephemeral_public,
    )?;
    shared.zeroize();
    let aad = associated_data(organization_id, &private_key.public, &ephemeral_public);
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?,
    );
    CompositeKey::from_slice(&plaintext).map_err(|_| CryptoError::AuthenticationFailed)
}

fn derive_sealing_key(
    shared: &[u8; 32],
    organization_id: Uuid,
    recipient_public: &[u8; 32],
    ephemeral_public: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(organization_id.as_bytes()), shared);
    let mut info = Vec::with_capacity(CONTEXT.len() + 64);
    info.extend_from_slice(CONTEXT);
    info.extend_from_slice(recipient_public);
    info.extend_from_slice(ephemeral_public);
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| CryptoError::Hkdf)?;
    info.zeroize();
    Ok(key)
}

fn associated_data(
    organization_id: Uuid,
    recipient_public: &[u8; 32],
    ephemeral_public: &[u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CONTEXT.len() + 16 + 64);
    aad.extend_from_slice(CONTEXT);
    aad.extend_from_slice(organization_id.as_bytes());
    aad.extend_from_slice(recipient_public);
    aad.extend_from_slice(ephemeral_public);
    aad
}

fn parse_envelope(envelope: &str) -> Result<([u8; 32], [u8; 24], Vec<u8>)> {
    if envelope.len() > 1024 {
        return Err(CryptoError::InvalidSharingKey);
    }
    let mut parts = envelope.split('.');
    if parts.next() != Some("hp-share") || parts.next() != Some("v1") {
        return Err(CryptoError::InvalidSharingKey);
    }
    let ephemeral = parts.next().ok_or(CryptoError::InvalidSharingKey)?;
    let nonce = parts.next().ok_or(CryptoError::InvalidSharingKey)?;
    let ciphertext = parts.next().ok_or(CryptoError::InvalidSharingKey)?;
    if parts.next().is_some() {
        return Err(CryptoError::InvalidSharingKey);
    }
    let ephemeral = decode_array(ephemeral)?;
    let nonce = decode_array(nonce)?;
    let ciphertext = decode_canonical(ciphertext)?;
    if ciphertext.len() != 80 {
        return Err(CryptoError::InvalidSharingKey);
    }
    Ok((ephemeral, nonce, ciphertext))
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    decode_canonical(value)?
        .try_into()
        .map_err(|_| CryptoError::InvalidSharingKey)
}

fn decode_canonical(value: &str) -> Result<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CryptoError::InvalidSharingKey)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(CryptoError::InvalidSharingKey);
    }
    Ok(decoded)
}

fn reject_low_order(shared: &[u8; 32]) -> Result<()> {
    if shared.ct_eq(&[0_u8; 32]).unwrap_u8() == 1 {
        Err(CryptoError::InvalidSharingKey)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sharing_keys_and_organization_wrapper_round_trip() {
        let user_key = CompositeKey::generate().unwrap_or_else(|error| panic!("{error}"));
        let material = generate_sharing_key(&user_key).unwrap_or_else(|error| panic!("{error}"));
        assert!(
            !material
                .protected_private_key
                .contains(&material.public_key)
        );
        let private = unwrap_sharing_private_key(
            &material.public_key,
            &material.protected_private_key,
            &user_key,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let organization_id = Uuid::new_v4();
        let organization_key = CompositeKey::generate().unwrap_or_else(|error| panic!("{error}"));
        let sealed =
            seal_organization_key(organization_id, &material.public_key, &organization_key)
                .unwrap_or_else(|error| panic!("{error}"));
        assert!(sealed.starts_with("hp-share.v1."));
        assert!(!sealed.contains(&URL_SAFE_NO_PAD.encode(organization_key.as_bytes())));
        let opened = open_organization_key(&private, organization_id, &sealed)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(opened.as_bytes(), organization_key.as_bytes());
    }

    #[test]
    fn wrapper_is_bound_to_account_organization_and_ciphertext() {
        let user_key = CompositeKey::generate().unwrap_or_else(|error| panic!("{error}"));
        let first = generate_sharing_key(&user_key).unwrap_or_else(|error| panic!("{error}"));
        let second = generate_sharing_key(&user_key).unwrap_or_else(|error| panic!("{error}"));
        let first_private =
            unwrap_sharing_private_key(&first.public_key, &first.protected_private_key, &user_key)
                .unwrap_or_else(|error| panic!("{error}"));
        let second_private = unwrap_sharing_private_key(
            &second.public_key,
            &second.protected_private_key,
            &user_key,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let organization_id = Uuid::new_v4();
        let key = CompositeKey::generate().unwrap_or_else(|error| panic!("{error}"));
        let sealed = seal_organization_key(organization_id, &first.public_key, &key)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(open_organization_key(&second_private, organization_id, &sealed).is_err());
        assert!(open_organization_key(&first_private, Uuid::new_v4(), &sealed).is_err());
        let mut tampered = sealed.into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap_or_else(|error| panic!("{error}"));
        assert!(open_organization_key(&first_private, organization_id, &tampered).is_err());
    }
}
