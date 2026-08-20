use std::{env, fs, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Validated server configuration.
#[derive(Clone)]
pub struct Config {
    /// `PostgreSQL` connection URL.
    pub database_url: String,
    /// HTTP listen address.
    pub bind: SocketAddr,
    /// Externally visible HTTPS URL used for validation and links.
    pub public_url: Url,
    /// Exact browser origins permitted by CORS.
    pub allowed_origins: Arc<[String]>,
    /// Server-only secret for hashing tokens and authenticating cursors.
    pub token_pepper: Arc<TokenPepper>,
    /// Independent server-only key encrypting account-MFA seeds at rest.
    pub mfa_encryption_key: Arc<MfaEncryptionKey>,
    /// `WebAuthn` relying-party identifier, normally the Web Vault host.
    pub webauthn_rp_id: String,
    /// Exact browser origin accepted in `WebAuthn` client data.
    pub webauthn_origin: Url,
    /// Additional exact browser-extension or Android APK-bound origins accepted for account
    /// `WebAuthn` ceremonies.
    pub webauthn_additional_origins: Arc<[Url]>,
    /// Human-readable relying-party name shown by authenticators.
    pub webauthn_rp_name: String,
    /// Enables strict production-only validation and hides Swagger UI.
    pub production: bool,
    /// Short-lived access-token lifetime.
    pub access_token_ttl: Duration,
    /// Rotating refresh-token lifetime.
    pub refresh_token_ttl: Duration,
    /// Lifetime of a trusted-device MFA bypass token.
    pub trusted_device_ttl: Duration,
    /// Maximum opaque attachment ciphertext accepted per upload.
    pub attachment_max_bytes: u64,
    /// Configured organization-invitation delivery adapter.
    pub invitation_delivery: InvitationDeliveryConfig,
}

/// Organization-invitation delivery selected at server startup.
#[derive(Clone)]
pub enum InvitationDeliveryConfig {
    /// Return the token once to the administrator for trusted out-of-band delivery.
    Manual,
    /// Deliver the token through a TLS-authenticated SMTP relay.
    Smtp(SmtpConfig),
}

/// TLS-only SMTP relay configuration.
#[derive(Clone)]
pub struct SmtpConfig {
    /// DNS hostname used for both the connection and certificate validation.
    pub host: String,
    /// Relay submission port.
    pub port: u16,
    /// Required TLS negotiation mode.
    pub tls: SmtpTls,
    /// Valid RFC mailbox used for the From header.
    pub from: String,
    /// Optional SMTP authentication username.
    pub username: Option<String>,
    /// Optional SMTP authentication password retained in zeroizing storage.
    pub password: Option<Arc<SmtpPassword>>,
    /// Per-command network timeout.
    pub timeout: Duration,
}

/// Secure SMTP connection mode. Plain and opportunistic modes are intentionally absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmtpTls {
    /// TLS from the first byte, normally on port 465.
    Implicit,
    /// Plain greeting followed by mandatory STARTTLS, normally on port 587.
    StartTls,
}

/// Server-only token/auth pepper.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TokenPepper([u8; 32]);

/// Dedicated encryption key for server-verifiable account MFA secrets.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MfaEncryptionKey([u8; 32]);

/// SMTP credential secret that is zeroized when the final configuration clone is dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SmtpPassword(String);

impl TokenPepper {
    /// Constructs a pepper from bytes supplied by a deployment secret store.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the key bytes for token hashing without copying them.
    #[must_use]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl MfaEncryptionKey {
    /// Constructs a key from bytes supplied by a deployment secret store.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the key only for authenticated encryption operations.
    #[must_use]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl SmtpPassword {
    /// Borrows the password only when constructing the SMTP transport.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl Config {
    /// Reads environment variables and refuses unsafe production combinations.
    ///
    /// # Errors
    ///
    /// Returns an error when a required value is absent, malformed, or unsafe.
    pub fn from_env() -> anyhow::Result<Self> {
        let database_url = required("DATABASE_URL")?;
        let bind = env::var("HP_BIND")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_owned())
            .parse()
            .context("HP_BIND must be a socket address")?;
        let public_url = Url::parse(
            &env::var("HP_PUBLIC_URL").unwrap_or_else(|_| "http://localhost:8080".to_owned()),
        )
        .context("HP_PUBLIC_URL must be an absolute URL")?;
        let production = parse_bool("HP_PRODUCTION", false)?;
        if production && public_url.scheme() != "https" {
            bail!("HP_PUBLIC_URL must use https in production");
        }
        if public_url.host_str().is_none() || !matches!(public_url.scheme(), "http" | "https") {
            bail!("HP_PUBLIC_URL must be an http(s) origin");
        }

        let allowed_origins = parse_allowed_origins(&public_url, production)?;
        let pepper = decode_server_secret("HP_TOKEN_PEPPER", production)?;
        let mfa_encryption_key = decode_server_secret("HP_MFA_ENCRYPTION_KEY", production)?;
        let (webauthn_rp_id, webauthn_origin, webauthn_rp_name) =
            parse_webauthn_config(&public_url, production)?;
        let webauthn_additional_origins = parse_webauthn_additional_origins(production)?;

        let access_token_ttl =
            Duration::from_secs(parse_u64("HP_ACCESS_TOKEN_TTL_SECONDS", 900, 60, 3600)?);
        let refresh_token_ttl = Duration::from_secs(parse_u64(
            "HP_REFRESH_TOKEN_TTL_SECONDS",
            2_592_000,
            3600,
            31_536_000,
        )?);
        let trusted_device_ttl = Duration::from_secs(parse_u64(
            "HP_TRUSTED_DEVICE_TTL_SECONDS",
            2_592_000,
            86_400,
            31_536_000,
        )?);
        let attachment_max_bytes = parse_u64(
            "HP_ATTACHMENT_MAX_BYTES",
            1024 * 1024 * 1024,
            1024 * 1024,
            64 * 1024 * 1024 * 1024,
        )?;
        let invitation_delivery = parse_invitation_delivery()?;

        Ok(Self {
            database_url,
            bind,
            public_url,
            allowed_origins: allowed_origins.into(),
            token_pepper: Arc::new(TokenPepper(pepper)),
            mfa_encryption_key: Arc::new(MfaEncryptionKey(mfa_encryption_key)),
            webauthn_rp_id,
            webauthn_origin,
            webauthn_additional_origins: webauthn_additional_origins.into(),
            webauthn_rp_name,
            production,
            access_token_ttl,
            refresh_token_ttl,
            trusted_device_ttl,
            attachment_max_bytes,
            invitation_delivery,
        })
    }
}

fn parse_invitation_delivery() -> anyhow::Result<InvitationDeliveryConfig> {
    let adapter = env::var("HP_INVITATION_DELIVERY")
        .unwrap_or_else(|_| "manual".to_owned())
        .trim()
        .to_ascii_lowercase();
    match adapter.as_str() {
        "manual" => Ok(InvitationDeliveryConfig::Manual),
        "smtp" => {
            let host = required("HP_SMTP_HOST")?.trim().to_ascii_lowercase();
            validate_smtp_host(&host)?;
            let tls = match env::var("HP_SMTP_TLS")
                .unwrap_or_else(|_| "starttls".to_owned())
                .trim()
                .to_ascii_lowercase()
                .as_str()
            {
                "implicit" => SmtpTls::Implicit,
                "starttls" => SmtpTls::StartTls,
                _ => bail!("HP_SMTP_TLS must be implicit or starttls"),
            };
            let default_port = match tls {
                SmtpTls::Implicit => 465,
                SmtpTls::StartTls => 587,
            };
            let port = parse_optional_port("HP_SMTP_PORT", default_port)?;
            let from = required("HP_SMTP_FROM")?;
            from.parse::<lettre::message::Mailbox>()
                .context("HP_SMTP_FROM must be a valid email mailbox")?;
            let username = optional_nonempty_env("HP_SMTP_USERNAME")?;
            let password = optional_secret("HP_SMTP_PASSWORD", "HP_SMTP_PASSWORD_FILE")?;
            if username.is_some() != password.is_some() {
                bail!(
                    "HP_SMTP_USERNAME and exactly one of HP_SMTP_PASSWORD or HP_SMTP_PASSWORD_FILE must be configured together"
                );
            }
            let timeout = Duration::from_secs(parse_u64("HP_SMTP_TIMEOUT_SECONDS", 10, 1, 60)?);
            Ok(InvitationDeliveryConfig::Smtp(SmtpConfig {
                host,
                port,
                tls,
                from,
                username,
                password: password.map(|value| Arc::new(SmtpPassword(value.to_string()))),
                timeout,
            }))
        }
        _ => bail!("HP_INVITATION_DELIVERY must be manual or smtp"),
    }
}

fn validate_smtp_host(host: &str) -> anyhow::Result<()> {
    if host.is_empty()
        || host.len() > 253
        || !host.is_ascii()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        bail!("HP_SMTP_HOST must be a valid ASCII DNS hostname");
    }
    Ok(())
}

fn optional_nonempty_env(name: &str) -> anyhow::Result<Option<String>> {
    match env::var(name) {
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) if value.len() <= 16 * 1024 && !value.chars().any(char::is_control) => {
            Ok(Some(value))
        }
        Ok(_) => bail!("{name} is invalid or too long"),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error).with_context(|| format!("cannot read {name}")),
    }
}

fn parse_optional_port(name: &str, default: u16) -> anyhow::Result<u16> {
    let Some(value) = optional_nonempty_env(name)? else {
        return Ok(default);
    };
    let port = value
        .parse::<u16>()
        .with_context(|| format!("{name} must be an integer in 1..=65535"))?;
    if port == 0 {
        bail!("{name} must be in 1..=65535");
    }
    Ok(port)
}

fn optional_secret(value_name: &str, file_name: &str) -> anyhow::Result<Option<Zeroizing<String>>> {
    let direct = match env::var(value_name) {
        Ok(value) if value.is_empty() => None,
        Ok(value) => Some(value),
        Err(env::VarError::NotPresent) => None,
        Err(error) => return Err(error).with_context(|| format!("cannot read {value_name}")),
    };
    let path = match env::var(file_name) {
        Ok(value) if value.trim().is_empty() => None,
        Ok(value) => Some(value),
        Err(env::VarError::NotPresent) => None,
        Err(error) => return Err(error).with_context(|| format!("cannot read {file_name}")),
    };
    if direct.is_some() && path.is_some() {
        bail!("configure only one of {value_name} and {file_name}");
    }
    let value = match (direct, path) {
        (Some(value), None) => value,
        (None, Some(path)) => {
            let metadata =
                fs::metadata(&path).with_context(|| format!("{file_name} is not readable"))?;
            if metadata.len() > 16 * 1024 {
                bail!("{file_name} exceeds 16 KiB");
            }
            fs::read_to_string(&path)
                .with_context(|| format!("{file_name} is not valid UTF-8"))?
                .trim_end_matches(['\r', '\n'])
                .to_owned()
        }
        (None, None) => return Ok(None),
        (Some(_), Some(_)) => unreachable!("handled above"),
    };
    if value.is_empty() || value.len() > 16 * 1024 || value.contains(['\r', '\n', '\0']) {
        bail!("SMTP password is empty, contains a forbidden control, or exceeds 16 KiB");
    }
    Ok(Some(Zeroizing::new(value)))
}

fn required(name: &str) -> anyhow::Result<String> {
    env::var(name).with_context(|| format!("{name} is required"))
}

fn parse_allowed_origins(public_url: &Url, production: bool) -> anyhow::Result<Vec<String>> {
    let allowed_origins: Vec<String> = env::var("HP_ALLOWED_ORIGINS")
        .unwrap_or_else(|_| public_url.origin().ascii_serialization())
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .map(str::to_owned)
        .collect();
    if allowed_origins.is_empty() || allowed_origins.iter().any(|origin| origin == "*") {
        bail!("HP_ALLOWED_ORIGINS must be a non-wildcard origin allowlist");
    }
    for origin in &allowed_origins {
        let parsed = Url::parse(origin).context("invalid HP_ALLOWED_ORIGINS entry")?;
        if parsed.origin().ascii_serialization() != *origin || parsed.path() != "/" {
            bail!("HP_ALLOWED_ORIGINS entries must be bare origins");
        }
        if production && parsed.scheme() != "https" {
            bail!("HP_ALLOWED_ORIGINS entries must use https in production");
        }
    }
    Ok(allowed_origins)
}

fn decode_server_secret(name: &str, production: bool) -> anyhow::Result<[u8; 32]> {
    let encoded = Zeroizing::new(required(name)?);
    if production && encoded.starts_with("CHANGE_ME") {
        bail!("{name} is still a placeholder");
    }
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .with_context(|| format!("{name} must be unpadded base64url"))?,
    );
    decoded
        .as_slice()
        .try_into()
        .with_context(|| format!("{name} must decode to exactly 32 bytes"))
}

fn parse_webauthn_config(
    public_url: &Url,
    production: bool,
) -> anyhow::Result<(String, Url, String)> {
    let origin = Url::parse(
        &env::var("HP_WEBAUTHN_ORIGIN")
            .unwrap_or_else(|_| public_url.origin().ascii_serialization()),
    )
    .context("HP_WEBAUTHN_ORIGIN must be an absolute origin")?;
    if origin.origin().ascii_serialization() != origin.as_str().trim_end_matches('/')
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        bail!("HP_WEBAUTHN_ORIGIN must be a bare origin");
    }
    if production && origin.scheme() != "https" {
        bail!("HP_WEBAUTHN_ORIGIN must use https in production");
    }
    let rp_id = env::var("HP_WEBAUTHN_RP_ID")
        .unwrap_or_else(|_| origin.host_str().unwrap_or_default().to_owned());
    if rp_id.is_empty()
        || rp_id.contains('/')
        || rp_id.contains(':')
        || rp_id.chars().any(char::is_whitespace)
    {
        bail!("HP_WEBAUTHN_RP_ID must be a hostname without scheme, port, or path");
    }
    let rp_name = env::var("HP_WEBAUTHN_RP_NAME").unwrap_or_else(|_| "Hasilan Pass".to_owned());
    if rp_name.trim().is_empty() || rp_name.len() > 128 {
        bail!("HP_WEBAUTHN_RP_NAME must contain 1..=128 bytes");
    }
    Ok((rp_id, origin, rp_name))
}

fn parse_webauthn_additional_origins(production: bool) -> anyhow::Result<Vec<Url>> {
    let mut origins = Vec::new();
    for value in env::var("HP_WEBAUTHN_ADDITIONAL_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let origin = Url::parse(value).context("invalid HP_WEBAUTHN_ADDITIONAL_ORIGINS entry")?;
        let extension_origin = matches!(origin.scheme(), "chrome-extension" | "moz-extension")
            && origin.host_str().is_some()
            && origin.port().is_none();
        let web_origin = matches!(origin.scheme(), "https" | "http")
            && origin.host_str().is_some()
            && (!production || origin.scheme() == "https");
        // Credential Manager uses an opaque origin bound to the SHA-256 certificate digest of
        // the calling Android package. It is deliberately exact: a deployment has to opt in to
        // every signing certificate (debug, Play App Signing, or an enterprise build) it trusts.
        let android_origin = is_android_webauthn_origin(&origin);
        if (!extension_origin && !web_origin && !android_origin)
            || origin.username() != ""
            || origin.password().is_some()
            || (!android_origin && !matches!(origin.path(), "" | "/"))
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            bail!(
                "HP_WEBAUTHN_ADDITIONAL_ORIGINS entries must be exact https, browser-extension, or Android APK-bound origins"
            );
        }
        if origins.iter().any(|existing| existing == &origin) {
            bail!("HP_WEBAUTHN_ADDITIONAL_ORIGINS contains a duplicate");
        }
        origins.push(origin);
    }
    Ok(origins)
}

fn is_android_webauthn_origin(origin: &Url) -> bool {
    let Some(encoded) = origin.as_str().strip_prefix("android:apk-key-hash:") else {
        return false;
    };
    if encoded.is_empty() || encoded.len() > 128 || encoded.contains('=') {
        return false;
    }
    URL_SAFE_NO_PAD
        .decode(encoded)
        .is_ok_and(|digest| digest.len() == 32)
}

fn parse_bool(name: &str, default: bool) -> anyhow::Result<bool> {
    match env::var(name) {
        Ok(value) => value
            .parse()
            .with_context(|| format!("{name} must be true or false")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error).with_context(|| format!("cannot read {name}")),
    }
}

fn parse_u64(name: &str, default: u64, minimum: u64, maximum: u64) -> anyhow::Result<u64> {
    let value = match env::var(name) {
        Ok(value) => value
            .parse()
            .with_context(|| format!("{name} must be an integer"))?,
        Err(env::VarError::NotPresent) => default,
        Err(error) => return Err(error).with_context(|| format!("cannot read {name}")),
    };
    if !(minimum..=maximum).contains(&value) {
        bail!("{name} must be in {minimum}..={maximum}");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_exact_android_certificate_origins() {
        let digest = URL_SAFE_NO_PAD.encode([0_u8; 32]);
        let origin = Url::parse(&format!("android:apk-key-hash:{digest}"))
            .unwrap_or_else(|error| panic!("test URL is invalid: {error}"));
        assert!(is_android_webauthn_origin(&origin));

        for value in [
            "android:apk-key-hash:too-short",
            "android:apk-key-hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "android:other-origin:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "https://example.test",
        ] {
            let origin =
                Url::parse(value).unwrap_or_else(|error| panic!("test URL is invalid: {error}"));
            assert!(!is_android_webauthn_origin(&origin), "accepted {value}");
        }
    }
}
