use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{CryptoError, Result};

const CONTEXT: &[u8] = b"hasilan-pass:attachment:v1";
const TAG_BYTES: u64 = 16;
const MIN_CHUNK_SIZE: u32 = 64 * 1024;
const MAX_CHUNK_SIZE: u32 = 2 * 1024 * 1024;
const MAX_CHUNKS: u32 = 100_000;

/// Version label sent with opaque attachment upload metadata.
pub const ATTACHMENT_FORMAT: &str = "hp-attachment.v1";
/// Default plaintext bytes in one independently authenticated frame.
pub const DEFAULT_ATTACHMENT_CHUNK_SIZE: u32 = 1024 * 1024;
/// Client-side hard limit independent of a deployment's lower quota.
pub const MAX_ATTACHMENT_PLAINTEXT_BYTES: u64 = 64 * 1024 * 1024 * 1024;

#[derive(Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
struct AttachmentKey([u8; 64]);

/// Private attachment metadata stored only inside the encrypted parent vault item.
///
/// The key and file nonce serialize so the encrypted item can synchronize them, but its
/// `Debug` representation never exposes file metadata or key material.
#[derive(Clone, PartialEq)]
pub struct AttachmentMetadata {
    /// Client-generated stable attachment ID.
    pub id: Uuid,
    /// Safe leaf filename presented on download.
    pub file_name: String,
    /// Client-provided media type, never trusted for execution.
    pub media_type: String,
    /// Exact plaintext byte length.
    pub size: u64,
    /// Plaintext frame size except for the final frame.
    pub chunk_size: u32,
    /// Number of independently authenticated frames; empty files use one frame.
    pub chunk_count: u32,
    /// Total ciphertext bytes across all frames.
    pub ciphertext_size: u64,
    key: AttachmentKey,
    file_nonce: [u8; 16],
}

impl std::fmt::Debug for AttachmentMetadata {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AttachmentMetadata")
            .field("id", &self.id)
            .field("private", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl AttachmentMetadata {
    /// Creates metadata and fresh key material for a streaming upload.
    ///
    /// # Errors
    ///
    /// Rejects unsafe filenames, oversized files, invalid chunk sizes, or CSPRNG failure.
    pub fn generate(
        file_name: impl Into<String>,
        media_type: impl Into<String>,
        size: u64,
        chunk_size: u32,
    ) -> Result<Self> {
        let mut key = [0_u8; 64];
        let mut file_nonce = [0_u8; 16];
        getrandom::fill(&mut key)?;
        getrandom::fill(&mut file_nonce)?;
        Self::from_parts(
            Uuid::new_v4(),
            file_name.into(),
            media_type.into(),
            size,
            chunk_size,
            AttachmentKey(key),
            file_nonce,
        )
    }

    /// Returns the fixed attachment wire-format label.
    #[must_use]
    pub const fn format(&self) -> &'static str {
        ATTACHMENT_FORMAT
    }

    /// Returns the exact expected plaintext length for one frame.
    ///
    /// # Errors
    ///
    /// Rejects an index outside this attachment's declared frame range.
    pub fn plaintext_chunk_len(&self, index: u32) -> Result<usize> {
        if index >= self.chunk_count {
            return Err(CryptoError::InvalidAttachment);
        }
        let preceding = u64::from(index)
            .checked_mul(u64::from(self.chunk_size))
            .ok_or(CryptoError::InvalidAttachment)?;
        let remaining = self
            .size
            .checked_sub(preceding)
            .ok_or(CryptoError::InvalidAttachment)?;
        usize::try_from(remaining.min(u64::from(self.chunk_size)))
            .map_err(|_| CryptoError::InvalidAttachment)
    }

    fn from_parts(
        id: Uuid,
        file_name: String,
        media_type: String,
        size: u64,
        chunk_size: u32,
        key: AttachmentKey,
        file_nonce: [u8; 16],
    ) -> Result<Self> {
        validate_file_name(&file_name)?;
        validate_media_type(&media_type)?;
        if id.is_nil()
            || size > MAX_ATTACHMENT_PLAINTEXT_BYTES
            || !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size)
        {
            return Err(CryptoError::InvalidAttachment);
        }
        let chunk_count_u64 = if size == 0 {
            1
        } else {
            size.checked_add(u64::from(chunk_size) - 1)
                .ok_or(CryptoError::InvalidAttachment)?
                / u64::from(chunk_size)
        };
        let chunk_count =
            u32::try_from(chunk_count_u64).map_err(|_| CryptoError::InvalidAttachment)?;
        if chunk_count > MAX_CHUNKS {
            return Err(CryptoError::InvalidAttachment);
        }
        let ciphertext_size = size
            .checked_add(
                TAG_BYTES
                    .checked_mul(u64::from(chunk_count))
                    .ok_or(CryptoError::InvalidAttachment)?,
            )
            .ok_or(CryptoError::InvalidAttachment)?;
        Ok(Self {
            id,
            file_name,
            media_type,
            size,
            chunk_size,
            chunk_count,
            ciphertext_size,
            key,
            file_nonce,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttachmentWire {
    id: Uuid,
    file_name: String,
    media_type: String,
    size: u64,
    chunk_size: u32,
    chunk_count: u32,
    ciphertext_size: u64,
    format: String,
    key: String,
    file_nonce: String,
}

impl Serialize for AttachmentMetadata {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        AttachmentWire {
            id: self.id,
            file_name: self.file_name.clone(),
            media_type: self.media_type.clone(),
            size: self.size,
            chunk_size: self.chunk_size,
            chunk_count: self.chunk_count,
            ciphertext_size: self.ciphertext_size,
            format: ATTACHMENT_FORMAT.to_owned(),
            key: URL_SAFE_NO_PAD.encode(self.key.0),
            file_nonce: URL_SAFE_NO_PAD.encode(self.file_nonce),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AttachmentMetadata {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AttachmentWire::deserialize(deserializer)?;
        if wire.format != ATTACHMENT_FORMAT {
            return Err(serde::de::Error::custom("invalid attachment format"));
        }
        let key = decode_canonical::<64>(&wire.key)
            .map_err(|_| serde::de::Error::custom("invalid attachment key"))?;
        let file_nonce = decode_canonical::<16>(&wire.file_nonce)
            .map_err(|_| serde::de::Error::custom("invalid attachment nonce"))?;
        let metadata = Self::from_parts(
            wire.id,
            wire.file_name,
            wire.media_type,
            wire.size,
            wire.chunk_size,
            AttachmentKey(key),
            file_nonce,
        )
        .map_err(|_| serde::de::Error::custom("invalid attachment metadata"))?;
        if metadata.chunk_count != wire.chunk_count
            || metadata.ciphertext_size != wire.ciphertext_size
        {
            return Err(serde::de::Error::custom(
                "inconsistent attachment dimensions",
            ));
        }
        Ok(metadata)
    }
}

/// Encrypts exactly one independently authenticated plaintext frame.
///
/// # Errors
///
/// Rejects wrong frame lengths or indices and returns an error if key expansion fails.
pub fn encrypt_attachment_chunk(
    metadata: &AttachmentMetadata,
    item_id: Uuid,
    index: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let expected = metadata.plaintext_chunk_len(index)?;
    if item_id.is_nil() || plaintext.len() != expected {
        return Err(CryptoError::InvalidAttachment);
    }
    let key = derive_key(metadata, item_id)?;
    let nonce = chunk_nonce(metadata, index);
    let aad = chunk_aad(metadata, item_id, index, expected)?;
    XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Authenticates and decrypts exactly one attachment frame.
///
/// # Errors
///
/// Rejects wrong dimensions, metadata, item IDs, indices, or modified ciphertext.
pub fn decrypt_attachment_chunk(
    metadata: &AttachmentMetadata,
    item_id: Uuid,
    index: u32,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let expected = metadata.plaintext_chunk_len(index)?;
    if item_id.is_nil() || ciphertext.len() != expected + usize::try_from(TAG_BYTES).unwrap_or(16) {
        return Err(CryptoError::InvalidAttachment);
    }
    let key = derive_key(metadata, item_id)?;
    let nonce = chunk_nonce(metadata, index);
    let aad = chunk_aad(metadata, item_id, index, expected)?;
    XChaCha20Poly1305::new((&*key).into())
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

fn derive_key(metadata: &AttachmentMetadata, item_id: Uuid) -> Result<Zeroizing<[u8; 32]>> {
    let mut salt = [0_u8; 32];
    salt[..16].copy_from_slice(item_id.as_bytes());
    salt[16..].copy_from_slice(metadata.id.as_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &metadata.key.0);
    let mut info = Vec::with_capacity(CONTEXT.len() + metadata.file_nonce.len());
    info.extend_from_slice(CONTEXT);
    info.extend_from_slice(&metadata.file_nonce);
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| CryptoError::Hkdf)?;
    info.zeroize();
    Ok(key)
}

fn chunk_nonce(metadata: &AttachmentMetadata, index: u32) -> [u8; 24] {
    let mut nonce = [0_u8; 24];
    nonce[..16].copy_from_slice(&metadata.file_nonce);
    nonce[16..].copy_from_slice(&u64::from(index).to_be_bytes());
    nonce
}

fn chunk_aad(
    metadata: &AttachmentMetadata,
    item_id: Uuid,
    index: u32,
    plaintext_len: usize,
) -> Result<Vec<u8>> {
    let plaintext_len = u32::try_from(plaintext_len).map_err(|_| CryptoError::InvalidAttachment)?;
    let mut aad = Vec::with_capacity(CONTEXT.len() + 16 + 16 + 16 + 8 + 4 * 5 + 1);
    aad.extend_from_slice(CONTEXT);
    aad.extend_from_slice(item_id.as_bytes());
    aad.extend_from_slice(metadata.id.as_bytes());
    aad.extend_from_slice(&metadata.file_nonce);
    aad.extend_from_slice(&metadata.size.to_be_bytes());
    aad.extend_from_slice(&metadata.chunk_size.to_be_bytes());
    aad.extend_from_slice(&metadata.chunk_count.to_be_bytes());
    aad.extend_from_slice(&metadata.ciphertext_size.to_be_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    aad.push(u8::from(index + 1 == metadata.chunk_count));
    Ok(aad)
}

fn validate_file_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 1024
        || matches!(value, "." | "..")
        || value.chars().any(|character| {
            character == '/' || character == '\\' || character == '\0' || character.is_control()
        })
    {
        return Err(CryptoError::InvalidAttachment);
    }
    Ok(())
}

fn validate_media_type(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 255
        || value
            .chars()
            .any(|character| character.is_control() || !character.is_ascii())
    {
        return Err(CryptoError::InvalidAttachment);
    }
    Ok(())
}

fn decode_canonical<const N: usize>(value: &str) -> Result<[u8; N]> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CryptoError::InvalidAttachment)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(CryptoError::InvalidAttachment);
    }
    decoded
        .try_into()
        .map_err(|_| CryptoError::InvalidAttachment)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_metadata(size: u64, chunk_size: u32) -> AttachmentMetadata {
        AttachmentMetadata::from_parts(
            Uuid::parse_str("11111111-1111-4111-8111-111111111111")
                .unwrap_or_else(|error| panic!("{error}")),
            "evidence.bin".to_owned(),
            "application/octet-stream".to_owned(),
            size,
            chunk_size,
            AttachmentKey([0x42; 64]),
            [0x24; 16],
        )
        .unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn framed_attachment_round_trip_and_tamper_rejection() {
        let item_id = Uuid::parse_str("22222222-2222-4222-8222-222222222222")
            .unwrap_or_else(|error| panic!("{error}"));
        let metadata = fixed_metadata(70_000, MIN_CHUNK_SIZE);
        assert_eq!(metadata.chunk_count, 2);
        let first = vec![0x61; usize::try_from(MIN_CHUNK_SIZE).unwrap_or(65_536)];
        let second = vec![0x62; 4_464];
        let first_cipher = encrypt_attachment_chunk(&metadata, item_id, 0, &first)
            .unwrap_or_else(|error| panic!("{error}"));
        let second_cipher = encrypt_attachment_chunk(&metadata, item_id, 1, &second)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            decrypt_attachment_chunk(&metadata, item_id, 0, &first_cipher)
                .unwrap_or_else(|error| panic!("{error}"))
                .as_slice(),
            first
        );
        assert_eq!(
            decrypt_attachment_chunk(&metadata, item_id, 1, &second_cipher)
                .unwrap_or_else(|error| panic!("{error}"))
                .as_slice(),
            second
        );
        assert!(decrypt_attachment_chunk(&metadata, Uuid::new_v4(), 0, &first_cipher).is_err());
        assert!(decrypt_attachment_chunk(&metadata, item_id, 1, &first_cipher).is_err());
        let mut tampered = second_cipher;
        tampered[0] ^= 1;
        assert!(decrypt_attachment_chunk(&metadata, item_id, 1, &tampered).is_err());
    }

    #[test]
    fn metadata_serialization_is_canonical_and_dimension_checked() {
        let metadata = fixed_metadata(0, DEFAULT_ATTACHMENT_CHUNK_SIZE);
        let encoded = serde_json::to_vec(&metadata).unwrap_or_else(|error| panic!("{error}"));
        let decoded: AttachmentMetadata =
            serde_json::from_slice(&encoded).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(decoded, metadata);
        let mut value: serde_json::Value =
            serde_json::from_slice(&encoded).unwrap_or_else(|error| panic!("{error}"));
        value["ciphertextSize"] = serde_json::json!(15);
        assert!(serde_json::from_value::<AttachmentMetadata>(value).is_err());
    }

    #[test]
    fn filenames_and_chunk_dimensions_fail_closed() {
        for name in ["", ".", "..", "../secret", "nested/file", "bad\0name"] {
            assert!(
                AttachmentMetadata::generate(name, "application/octet-stream", 1, MIN_CHUNK_SIZE)
                    .is_err()
            );
        }
        assert!(AttachmentMetadata::generate("ok", "application/octet-stream", 1, 1024).is_err());
    }
}
