use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

/// Bitwarden-compatible login URI matching strategies.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum UriMatchType {
    /// Registrable/base domain.
    #[default]
    Domain = 0,
    /// Exact hostname, with subdomain significant.
    Host = 1,
    /// Candidate URL starts with the stored value.
    StartsWith = 2,
    /// Exact normalized URL.
    Exact = 3,
    /// Stored value is a Rust-regex expression.
    RegularExpression = 4,
    /// Never offer this URI.
    Never = 5,
}

impl TryFrom<u8> for UriMatchType {
    type Error = UriMatchError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Domain),
            1 => Ok(Self::Host),
            2 => Ok(Self::StartsWith),
            3 => Ok(Self::Exact),
            4 => Ok(Self::RegularExpression),
            5 => Ok(Self::Never),
            _ => Err(UriMatchError::InvalidStrategy),
        }
    }
}

/// URI parsing or matching failure.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum UriMatchError {
    /// Either URI is invalid, unsupported, or over the resource limit.
    #[error("invalid URI")]
    InvalidUri,
    /// The numeric strategy is not part of the compatible set.
    #[error("invalid URI match strategy")]
    InvalidStrategy,
    /// The configured regular expression is invalid or exceeds safe limits.
    #[error("unsafe or invalid regular expression")]
    InvalidRegex,
}

/// Tests a saved URI against the active frame URL without weakening HTTPS expectations.
///
/// # Errors
///
/// Returns [`UriMatchError`] when an input or regular expression cannot be
/// validated within the configured resource limits.
pub fn uri_matches(
    saved: &str,
    candidate: &str,
    strategy: UriMatchType,
) -> Result<bool, UriMatchError> {
    if saved.len() > 4096 || candidate.len() > 4096 {
        return Err(UriMatchError::InvalidUri);
    }
    if strategy == UriMatchType::Never {
        return Ok(false);
    }
    if strategy == UriMatchType::RegularExpression {
        let regex = RegexBuilder::new(saved)
            .size_limit(256 * 1024)
            .dfa_size_limit(512 * 1024)
            .build()
            .map_err(|_| UriMatchError::InvalidRegex)?;
        return Ok(regex.is_match(candidate));
    }

    let saved_url = Url::parse(saved).map_err(|_| UriMatchError::InvalidUri)?;
    let candidate_url = Url::parse(candidate).map_err(|_| UriMatchError::InvalidUri)?;
    if !matches!(saved_url.scheme(), "http" | "https")
        || !matches!(candidate_url.scheme(), "http" | "https")
    {
        return Ok(false);
    }
    // Never fill an HTTP page from an HTTPS-only saved origin.
    if saved_url.scheme() == "https" && candidate_url.scheme() != "https" {
        return Ok(false);
    }

    match strategy {
        UriMatchType::Domain => {
            let saved_host = saved_url.host_str().ok_or(UriMatchError::InvalidUri)?;
            let candidate_host = candidate_url.host_str().ok_or(UriMatchError::InvalidUri)?;
            match (
                registrable_domain(saved_host),
                registrable_domain(candidate_host),
            ) {
                (Some(saved), Some(candidate)) => Ok(saved == candidate),
                _ => Ok(saved_host.eq_ignore_ascii_case(candidate_host)),
            }
        }
        UriMatchType::Host => Ok(saved_url.host_str() == candidate_url.host_str()),
        UriMatchType::StartsWith => Ok(candidate.starts_with(saved)),
        UriMatchType::Exact => Ok(normalize_exact(saved_url) == normalize_exact(candidate_url)),
        UriMatchType::RegularExpression | UriMatchType::Never => unreachable!(),
    }
}

fn registrable_domain(host: &str) -> Option<String> {
    psl::domain_str(host).map(str::to_ascii_lowercase)
}

fn normalize_exact(mut url: Url) -> String {
    url.set_fragment(None);
    url.to_string()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test assertions intentionally fail fast"
)]
mod tests {
    use super::*;

    #[test]
    fn base_domain_uses_public_suffix_list() {
        assert!(
            uri_matches(
                "https://login.example.co.jp",
                "https://account.example.co.jp/sign-in",
                UriMatchType::Domain,
            )
            .unwrap()
        );
        assert!(
            !uri_matches(
                "https://example.co.jp",
                "https://example.co.jp.attacker.test",
                UriMatchType::Domain,
            )
            .unwrap()
        );
    }

    #[test]
    fn blocks_https_to_http_downgrade() {
        assert!(
            !uri_matches(
                "https://example.com/login",
                "http://example.com/login",
                UriMatchType::Host,
            )
            .unwrap()
        );
    }

    #[test]
    fn domain_matching_does_not_equate_unrelated_ip_or_local_hosts() {
        assert!(
            uri_matches(
                "http://127.0.0.1:8080/login",
                "http://127.0.0.1:9090/account",
                UriMatchType::Domain,
            )
            .unwrap()
        );
        assert!(
            !uri_matches(
                "http://127.0.0.1/login",
                "http://192.0.2.44/account",
                UriMatchType::Domain,
            )
            .unwrap()
        );
        assert!(
            !uri_matches(
                "http://localhost/login",
                "http://internal/account",
                UriMatchType::Domain,
            )
            .unwrap()
        );
    }

    #[test]
    fn strategies_are_distinct() {
        assert!(
            uri_matches(
                "https://example.com/login",
                "https://example.com/login/step2",
                UriMatchType::StartsWith,
            )
            .unwrap()
        );
        assert!(
            !uri_matches(
                "https://example.com/login",
                "https://example.com/login/step2",
                UriMatchType::Exact,
            )
            .unwrap()
        );
    }
}
