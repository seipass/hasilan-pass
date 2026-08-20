use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{config::TokenPepper, error::AppError};

type HmacSha256 = Hmac<Sha256>;

pub fn generate_token() -> Result<String, AppError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| AppError::internal())?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[must_use]
pub fn hash_token(token: &str, pepper: &TokenPepper) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(pepper.bytes())
        .unwrap_or_else(|_| unreachable!("HMAC accepts a 32-byte key"));
    mac.update(token.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

pub fn encode_cursor(account_id: uuid::Uuid, revision: i64, pepper: &TokenPepper) -> String {
    let payload = format!("v1|{account_id}|{revision}");
    let signature = hash_token(&payload, pepper);
    URL_SAFE_NO_PAD.encode([payload.as_bytes(), signature.as_slice()].concat())
}

pub fn decode_cursor(
    cursor: &str,
    expected_account: uuid::Uuid,
    pepper: &TokenPepper,
) -> Result<i64, AppError> {
    use subtle::ConstantTimeEq;

    let decoded = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| AppError::invalid("invalid_cursor", "The sync cursor is invalid."))?;
    if decoded.len() <= 32 {
        return Err(AppError::invalid(
            "invalid_cursor",
            "The sync cursor is invalid.",
        ));
    }
    let (payload, signature) = decoded.split_at(decoded.len() - 32);
    let payload_text = std::str::from_utf8(payload)
        .map_err(|_| AppError::invalid("invalid_cursor", "The sync cursor is invalid."))?;
    let expected = hash_token(payload_text, pepper);
    if expected.as_slice().ct_eq(signature).unwrap_u8() != 1 {
        return Err(AppError::invalid(
            "invalid_cursor",
            "The sync cursor is invalid.",
        ));
    }
    let mut parts = payload_text.split('|');
    let version = parts.next();
    let account = parts.next().and_then(|value| value.parse().ok());
    let revision = parts.next().and_then(|value| value.parse::<i64>().ok());
    if version != Some("v1")
        || account != Some(expected_account)
        || parts.next().is_some()
        || revision.is_none_or(|value| value < 0)
    {
        return Err(AppError::invalid(
            "invalid_cursor",
            "The sync cursor is invalid.",
        ));
    }
    revision.ok_or_else(|| AppError::invalid("invalid_cursor", "The sync cursor is invalid."))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test assertions intentionally fail fast"
)]
mod tests {
    use super::*;

    #[test]
    fn cursor_is_account_bound_and_tamper_evident() {
        let pepper = TokenPepper::from_bytes([7_u8; 32]);
        let account = uuid::Uuid::new_v4();
        let cursor = encode_cursor(account, 42, &pepper);
        assert_eq!(decode_cursor(&cursor, account, &pepper).unwrap(), 42);
        assert!(decode_cursor(&cursor, uuid::Uuid::new_v4(), &pepper).is_err());
        let mut tampered = cursor.into_bytes();
        let index = tampered.len() / 2;
        tampered[index] = if tampered[index] == b'A' { b'B' } else { b'A' };
        assert!(decode_cursor(std::str::from_utf8(&tampered).unwrap(), account, &pepper).is_err());
    }
}
