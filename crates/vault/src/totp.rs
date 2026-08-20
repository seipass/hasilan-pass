use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use thiserror::Error;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::SecretString;

/// Supported RFC 6238 HMAC algorithms.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum TotpAlgorithm {
    /// HMAC-SHA-1, the interoperable default.
    #[default]
    #[serde(rename = "SHA1")]
    Sha1,
    /// HMAC-SHA-256.
    #[serde(rename = "SHA256")]
    Sha256,
    /// HMAC-SHA-512.
    #[serde(rename = "SHA512")]
    Sha512,
}

/// Parsed TOTP settings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpConfig {
    secret: SecretString,
    /// Provider name displayed alongside the code.
    pub issuer: Option<String>,
    /// Account label displayed alongside the code.
    pub account_name: Option<String>,
    /// Counter period in seconds.
    pub period: u32,
    /// Number of decimal digits in the code.
    pub digits: u32,
    /// HMAC digest algorithm.
    pub algorithm: TotpAlgorithm,
}

/// A generated code and display timing metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpCode {
    /// Zero-padded decimal one-time password.
    pub code: String,
    /// Whole seconds until the current code rolls over.
    pub remaining_seconds: u32,
    /// Provider name parsed from the label or issuer query parameter.
    pub issuer: Option<String>,
    /// Account name parsed from the credential label.
    pub account_name: Option<String>,
    /// Configured counter period in seconds.
    pub period: u32,
    /// Configured decimal code width.
    pub digits: u32,
    /// Configured HMAC digest algorithm.
    pub algorithm: TotpAlgorithm,
}

/// TOTP parsing or generation error.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum TotpError {
    /// The URI could not be parsed safely.
    #[error("invalid otpauth URI")]
    InvalidUri,
    /// The URI describes HOTP or another unsupported credential type.
    #[error("only otpauth TOTP credentials are supported")]
    UnsupportedType,
    /// The Base32 secret is absent, malformed, or too short.
    #[error("TOTP secret is invalid")]
    InvalidSecret,
    /// Period, digits, or digest selection is outside supported bounds.
    #[error("TOTP parameters are outside safe bounds")]
    InvalidParameters,
}

impl TotpConfig {
    /// Parses an `otpauth://totp/...` URI or a raw Base32 secret.
    ///
    /// # Errors
    ///
    /// Returns [`TotpError`] when the URI, seed, or parameters are invalid.
    pub fn parse(value: &str) -> Result<Self, TotpError> {
        if !value.to_ascii_lowercase().starts_with("otpauth://") {
            let config = Self {
                secret: SecretString::new(value),
                issuer: None,
                account_name: None,
                period: 30,
                digits: 6,
                algorithm: TotpAlgorithm::Sha1,
            };
            config.decoded_secret()?;
            return Ok(config);
        }

        let url = Url::parse(value).map_err(|_| TotpError::InvalidUri)?;
        if url.scheme() != "otpauth" {
            return Err(TotpError::InvalidUri);
        }
        if url.host_str() != Some("totp") {
            return Err(TotpError::UnsupportedType);
        }

        let label = percent_decode_str(url.path().trim_start_matches('/'))
            .decode_utf8()
            .map_err(|_| TotpError::InvalidUri)?;
        let mut label_issuer = None;
        let mut account_name = None;
        if !label.is_empty() {
            if let Some((issuer, account)) = label.split_once(':') {
                label_issuer = Some(issuer.trim().to_owned()).filter(|part| !part.is_empty());
                account_name = Some(account.trim().to_owned()).filter(|part| !part.is_empty());
            } else {
                account_name = Some(label.into_owned());
            }
        }

        let mut secret = None;
        let mut query_issuer = None;
        let mut period = 30;
        let mut digits = 6;
        let mut algorithm = TotpAlgorithm::Sha1;
        for (name, value) in url.query_pairs() {
            match name.as_ref().to_ascii_lowercase().as_str() {
                "secret" => secret = Some(value.into_owned()),
                "issuer" => query_issuer = Some(value.into_owned()),
                "period" => period = value.parse().map_err(|_| TotpError::InvalidParameters)?,
                "digits" => digits = value.parse().map_err(|_| TotpError::InvalidParameters)?,
                "algorithm" => {
                    algorithm = match value.to_ascii_uppercase().as_str() {
                        "SHA1" => TotpAlgorithm::Sha1,
                        "SHA256" => TotpAlgorithm::Sha256,
                        "SHA512" => TotpAlgorithm::Sha512,
                        _ => return Err(TotpError::InvalidParameters),
                    };
                }
                _ => {}
            }
        }
        let config = Self {
            secret: SecretString::new(secret.ok_or(TotpError::InvalidSecret)?),
            issuer: query_issuer.or(label_issuer),
            account_name,
            period,
            digits,
            algorithm,
        };
        config.validate()?;
        config.decoded_secret()?;
        Ok(config)
    }

    /// Generates a code for a Unix timestamp without consulting the wall clock.
    ///
    /// # Errors
    ///
    /// Returns [`TotpError`] when the seed or configured parameters are invalid.
    pub fn generate_at(&self, unix_seconds: u64) -> Result<TotpCode, TotpError> {
        self.validate()?;
        let secret = self.decoded_secret()?;
        let counter = unix_seconds / u64::from(self.period);
        let message = counter.to_be_bytes();
        let digest = match self.algorithm {
            TotpAlgorithm::Sha1 => calculate_hmac::<Hmac<Sha1>>(&secret, &message),
            TotpAlgorithm::Sha256 => calculate_hmac::<Hmac<Sha256>>(&secret, &message),
            TotpAlgorithm::Sha512 => calculate_hmac::<Hmac<Sha512>>(&secret, &message),
        };
        let offset = usize::from(digest[digest.len() - 1] & 0x0f);
        let binary = (u32::from(digest[offset] & 0x7f) << 24)
            | (u32::from(digest[offset + 1]) << 16)
            | (u32::from(digest[offset + 2]) << 8)
            | u32::from(digest[offset + 3]);
        let modulus = 10_u32.pow(self.digits);
        let code = format!("{:0width$}", binary % modulus, width = self.digits as usize);
        let elapsed = u32::try_from(unix_seconds % u64::from(self.period))
            .map_err(|_| TotpError::InvalidParameters)?;
        Ok(TotpCode {
            code,
            remaining_seconds: self.period - elapsed,
            issuer: self.issuer.clone(),
            account_name: self.account_name.clone(),
            period: self.period,
            digits: self.digits,
            algorithm: self.algorithm,
        })
    }

    /// Exposes the normalized Base32 seed only for an explicit export/edit operation.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.secret.expose()
    }

    fn validate(&self) -> Result<(), TotpError> {
        if !(5..=300).contains(&self.period) || !(6..=9).contains(&self.digits) {
            return Err(TotpError::InvalidParameters);
        }
        Ok(())
    }

    fn decoded_secret(&self) -> Result<Zeroizing<Vec<u8>>, TotpError> {
        let mut normalized: String = self
            .secret
            .expose()
            .chars()
            .filter(|character| !character.is_ascii_whitespace() && *character != '-')
            .collect::<String>()
            .trim_end_matches('=')
            .to_ascii_uppercase();
        let result = BASE32_NOPAD
            .decode(normalized.as_bytes())
            .map_err(|_| TotpError::InvalidSecret)?;
        normalized.zeroize();
        if result.len() < 10 {
            return Err(TotpError::InvalidSecret);
        }
        Ok(Zeroizing::new(result))
    }
}

fn calculate_hmac<M>(key: &[u8], data: &[u8]) -> Vec<u8>
where
    M: Mac + hmac::digest::KeyInit,
{
    let mut hmac = <M as Mac>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC accepts arbitrary key lengths"));
    hmac.update(data);
    hmac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test assertions intentionally fail fast"
)]
mod tests {
    use super::*;

    fn config(secret: &str, algorithm: TotpAlgorithm) -> TotpConfig {
        TotpConfig {
            secret: SecretString::new(secret),
            issuer: None,
            account_name: None,
            period: 30,
            digits: 8,
            algorithm,
        }
    }

    #[test]
    fn rfc_6238_vectors() {
        // Appendix B secrets encoded as Base32.
        let sha1 = config("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", TotpAlgorithm::Sha1);
        let sha256 = config(
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
            TotpAlgorithm::Sha256,
        );
        let sha512 = config(
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA",
            TotpAlgorithm::Sha512,
        );
        let vectors = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        for (timestamp, expected_sha1, expected_sha256, expected_sha512) in vectors {
            assert_eq!(sha1.generate_at(timestamp).unwrap().code, expected_sha1);
            assert_eq!(sha256.generate_at(timestamp).unwrap().code, expected_sha256);
            assert_eq!(sha512.generate_at(timestamp).unwrap().code, expected_sha512);
        }
    }

    #[test]
    fn parses_otpauth_uri() {
        let value = "otpauth://totp/Example%20Co:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Co&algorithm=SHA256&digits=8&period=45";
        let config = TotpConfig::parse(value).unwrap();
        assert_eq!(config.issuer.as_deref(), Some("Example Co"));
        assert_eq!(config.account_name.as_deref(), Some("alice@example.com"));
        assert_eq!(config.period, 45);
        assert_eq!(config.digits, 8);
        assert_eq!(config.algorithm, TotpAlgorithm::Sha256);
    }
}
