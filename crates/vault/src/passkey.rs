use std::net::IpAddr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use p256::{
    SecretKey,
    ecdsa::{Signature, SigningKey, signature::Signer as _},
    elliptic_curve::sec1::ToEncodedPoint as _,
    pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _, EncodePublicKey as _},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{Fido2Credential, SecretString};

const MAX_CHALLENGE_BYTES: usize = 1_024;
const MAX_CREDENTIAL_ID_BYTES: usize = 1_024;
const MAX_CREDENTIAL_DESCRIPTORS: usize = 128;
const HASILAN_AAGUID: [u8; 16] = [
    0x7e, 0x92, 0x4c, 0x91, 0xdf, 0x6b, 0x4a, 0x66, 0xbc, 0xa4, 0x9e, 0x27, 0x4c, 0xe6, 0xbe, 0x5c,
];

/// A validation or cryptographic failure in the software `WebAuthn` authenticator.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum PasskeyError {
    /// The request is malformed, unsafe for the active origin, or outside limits.
    #[error("invalid WebAuthn request")]
    InvalidRequest,
    /// The relying party requested a capability this authenticator does not implement.
    #[error("unsupported WebAuthn request")]
    Unsupported,
    /// An excluded credential already exists.
    #[error("an excluded passkey already exists")]
    ExcludedCredential,
    /// No selected credential matches the relying party request.
    #[error("no matching passkey")]
    NoMatchingCredential,
    /// Key generation, decoding, or signing failed.
    #[error("passkey cryptographic operation failed")]
    Crypto,
}

/// JSON-safe options captured from `navigator.credentials.create`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCreationOptions {
    /// Browser-derived calling origin. Callers must not trust a page-supplied value.
    pub origin: String,
    /// Base64url challenge supplied by the relying party.
    pub challenge: String,
    /// Relying-party identity.
    pub rp: PasskeyRpEntity,
    /// User identity scoped to the relying party.
    pub user: PasskeyUserEntity,
    /// Ordered COSE algorithm preferences.
    #[serde(default)]
    pub pub_key_cred_params: Vec<PasskeyCredentialParameter>,
    /// Credential IDs which must prevent creation.
    #[serde(default)]
    pub exclude_credentials: Vec<PasskeyCredentialDescriptor>,
    /// Authenticator constraints.
    #[serde(default)]
    pub authenticator_selection: Option<PasskeyAuthenticatorSelection>,
    /// Requested attestation conveyance.
    #[serde(default)]
    pub attestation: Option<String>,
    /// Supported extension requests.
    #[serde(default)]
    pub extensions: PasskeyCreationExtensions,
}

/// JSON-safe options captured from `navigator.credentials.get`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAssertionOptions {
    /// Browser-derived calling origin.
    pub origin: String,
    /// Base64url challenge supplied by the relying party.
    pub challenge: String,
    /// Optional RP ID; the origin host is used when absent.
    pub rp_id: Option<String>,
    /// Allowed credential IDs, or empty for discoverable credential selection.
    #[serde(default)]
    pub allow_credentials: Vec<PasskeyCredentialDescriptor>,
    /// Requested verification policy.
    pub user_verification: Option<String>,
    /// Credential mediation mode.
    pub mediation: Option<String>,
}

/// A relying-party entity.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRpEntity {
    /// Optional RP ID; defaults to the calling host.
    pub id: Option<String>,
    /// Human-readable RP name.
    pub name: String,
}

/// A `WebAuthn` user entity.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyUserEntity {
    /// Base64url opaque user handle, 1 to 64 bytes.
    pub id: String,
    /// RP-scoped account name.
    pub name: String,
    /// RP-scoped display name.
    pub display_name: String,
}

/// A public-key credential algorithm preference.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PasskeyCredentialParameter {
    /// COSE algorithm identifier; this version supports ES256 (`-7`).
    pub alg: i32,
    /// Must be `public-key`.
    pub r#type: String,
}

/// A base64url credential descriptor.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PasskeyCredentialDescriptor {
    /// Credential ID.
    pub id: String,
    /// Must be `public-key` when present.
    #[serde(default)]
    pub r#type: Option<String>,
    /// Transport hints.
    #[serde(default)]
    pub transports: Vec<String>,
}

/// Authenticator-selection inputs relevant to the vault authenticator.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAuthenticatorSelection {
    /// Requested attachment modality.
    pub authenticator_attachment: Option<String>,
    /// Legacy resident-key requirement.
    #[serde(default)]
    pub require_resident_key: bool,
    /// Resident-key preference.
    pub resident_key: Option<String>,
    /// User-verification preference.
    pub user_verification: Option<String>,
}

/// Creation extensions implemented by this version.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCreationExtensions {
    /// Request the discoverability result.
    #[serde(default)]
    pub cred_props: bool,
}

/// Secret-free candidate data safe to show in an extension-owned confirmation UI.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCandidate {
    /// Vault item ID containing the passkey.
    pub item_id: Uuid,
    /// Base64url `WebAuthn` credential ID.
    pub credential_id: String,
    /// Vault item display name.
    pub item_name: String,
    /// RP-scoped user name.
    pub user_name: Option<String>,
    /// RP-scoped display name.
    pub user_display_name: Option<String>,
}

/// Public result returned to `navigator.credentials.create` plus the encrypted model entry.
pub struct PasskeyCreationResult {
    /// New private credential to persist inside the encrypted item.
    pub credential: Fido2Credential,
    /// Base64url credential ID exposed to the relying party.
    pub credential_id: String,
    /// Base64url serialized collected client data.
    pub client_data_json: String,
    /// Base64url CBOR attestation object.
    pub attestation_object: String,
    /// Base64url authenticator data.
    pub authenticator_data: String,
    /// Base64url DER `SubjectPublicKeyInfo`.
    pub public_key: String,
    /// COSE algorithm identifier (`-7`, ES256).
    pub public_key_algorithm: i32,
    /// Authenticator transports advertised to the RP.
    pub transports: Vec<String>,
    /// Whether the created credential is discoverable.
    pub discoverable: bool,
}

/// Public assertion response returned to `navigator.credentials.get`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAssertionResult {
    /// Base64url credential ID.
    pub credential_id: String,
    /// Base64url serialized collected client data.
    pub client_data_json: String,
    /// Base64url authenticator data.
    pub authenticator_data: String,
    /// Base64url DER ECDSA signature.
    pub signature: String,
    /// Base64url RP-scoped user handle, if retained.
    pub user_handle: Option<String>,
    /// Whether a non-zero imported signature counter changed and must be synced.
    pub counter_changed: bool,
}

/// Validates creation inputs and resolves the canonical RP ID.
///
/// # Errors
///
/// Returns a closed failure for invalid origins, RP IDs, algorithms, lengths, or unsupported
/// authenticator requirements.
pub fn validate_passkey_creation(options: &PasskeyCreationOptions) -> Result<String, PasskeyError> {
    validate_challenge(&options.challenge)?;
    validate_text(&options.rp.name, 1, 256)?;
    validate_text(&options.user.name, 1, 256)?;
    validate_text(&options.user.display_name, 1, 256)?;
    let user_handle = decode_b64url(&options.user.id)?;
    if !(1..=64).contains(&user_handle.len()) {
        return Err(PasskeyError::InvalidRequest);
    }
    validate_descriptors(&options.exclude_credentials)?;
    if options.pub_key_cred_params.is_empty()
        || !options
            .pub_key_cred_params
            .iter()
            .any(|parameter| parameter.alg == -7 && parameter.r#type == "public-key")
    {
        return Err(PasskeyError::Unsupported);
    }
    if options
        .authenticator_selection
        .as_ref()
        .and_then(|selection| selection.authenticator_attachment.as_deref())
        .is_some_and(|attachment| attachment == "cross-platform")
    {
        return Err(PasskeyError::Unsupported);
    }
    if options
        .attestation
        .as_deref()
        .is_some_and(|attestation| attestation == "enterprise")
    {
        return Err(PasskeyError::Unsupported);
    }
    canonical_rp_id(&options.origin, options.rp.id.as_deref())
}

/// Creates an ES256 credential and `WebAuthn` `none` attestation.
///
/// # Errors
///
/// Returns an error when validation, CSPRNG access, key encoding, or attestation construction
/// fails. `user_verified` must be backed by an extension-owned reauthentication ceremony.
pub fn create_passkey(
    options: &PasskeyCreationOptions,
    user_verified: bool,
) -> Result<PasskeyCreationResult, PasskeyError> {
    let rp_id = validate_passkey_creation(options)?;
    let discoverable = options
        .authenticator_selection
        .as_ref()
        .is_some_and(|selection| {
            selection.require_resident_key
                || matches!(
                    selection.resident_key.as_deref(),
                    Some("required" | "preferred")
                )
        });

    let credential_uuid = Uuid::new_v4();
    let credential_raw = credential_uuid.as_bytes();
    let credential_id = URL_SAFE_NO_PAD.encode(credential_raw);
    let secret = generate_secret_key()?;
    let signing = SigningKey::from(&secret);
    let public = secret.public_key();
    let encoded_point = public.to_encoded_point(false);
    let x = encoded_point.x().ok_or(PasskeyError::Crypto)?;
    let y = encoded_point.y().ok_or(PasskeyError::Crypto)?;
    let private_der = secret.to_pkcs8_der().map_err(|_| PasskeyError::Crypto)?;
    let public_der = public
        .to_public_key_der()
        .map_err(|_| PasskeyError::Crypto)?;

    let auth_data =
        authenticator_data(&rp_id, 0, true, user_verified, Some((credential_raw, x, y)))?;
    let attestation_object = none_attestation(&auth_data)?;
    let client_data =
        collected_client_data("webauthn.create", &options.challenge, &options.origin)?;

    let credential = Fido2Credential {
        credential_id: credential_uuid.to_string(),
        key_type: "public-key".to_owned(),
        key_algorithm: "ECDSA".to_owned(),
        key_curve: "P-256".to_owned(),
        key_value: SecretString::new(URL_SAFE_NO_PAD.encode(private_der.as_bytes())),
        public_key: Some(URL_SAFE_NO_PAD.encode(public_der.as_bytes())),
        rp_id,
        user_handle: Some(options.user.id.clone()),
        user_name: Some(options.user.name.clone()),
        counter: 0,
        rp_name: Some(options.rp.name.clone()),
        user_display_name: Some(options.user.display_name.clone()),
        discoverable,
        transports: vec!["internal".to_owned(), "hybrid".to_owned()],
        creation_date: Utc::now(),
        extra: serde_json::Map::new(),
    };
    drop(signing);

    Ok(PasskeyCreationResult {
        credential,
        credential_id,
        client_data_json: URL_SAFE_NO_PAD.encode(client_data),
        attestation_object: URL_SAFE_NO_PAD.encode(attestation_object),
        authenticator_data: URL_SAFE_NO_PAD.encode(auth_data),
        public_key: URL_SAFE_NO_PAD.encode(public_der.as_bytes()),
        public_key_algorithm: -7,
        transports: vec!["internal".to_owned(), "hybrid".to_owned()],
        discoverable,
    })
}

/// Returns whether an encrypted model credential is eligible for an assertion request.
#[must_use]
pub fn passkey_matches_request(
    credential: &Fido2Credential,
    options: &PasskeyAssertionOptions,
) -> bool {
    let Ok(rp_id) = validate_passkey_assertion(options) else {
        return false;
    };
    if credential.rp_id != rp_id {
        return false;
    }
    if options.allow_credentials.is_empty() {
        return credential.discoverable;
    }
    let Ok(raw_id) = stored_credential_id(&credential.credential_id) else {
        return false;
    };
    options.allow_credentials.iter().any(|descriptor| {
        descriptor_transport_supported(descriptor)
            && decode_b64url(&descriptor.id).is_ok_and(|allowed| allowed == raw_id)
    })
}

/// Signs an assertion with a selected encrypted vault credential.
///
/// # Errors
///
/// Returns an error if the selected credential does not match the origin/RP/allow-list, its key
/// is malformed, or signing fails.
pub fn assert_passkey(
    credential: &mut Fido2Credential,
    options: &PasskeyAssertionOptions,
    user_verified: bool,
) -> Result<PasskeyAssertionResult, PasskeyError> {
    let rp_id = validate_passkey_assertion(options)?;
    if !passkey_matches_request(credential, options) {
        return Err(PasskeyError::NoMatchingCredential);
    }
    let raw_id = stored_credential_id(&credential.credential_id)?;
    let credential_id = URL_SAFE_NO_PAD.encode(&raw_id);
    let private_bytes = Zeroizing::new(decode_b64url(credential.key_value.expose())?);
    let secret = SecretKey::from_pkcs8_der(&private_bytes).map_err(|_| PasskeyError::Crypto)?;
    let signing = SigningKey::from(secret);

    let counter_changed = credential.counter > 0;
    if counter_changed {
        credential.counter = credential
            .counter
            .checked_add(1)
            .ok_or(PasskeyError::Crypto)?;
    }
    let auth_data = authenticator_data(&rp_id, credential.counter, true, user_verified, None)?;
    let client_data = collected_client_data("webauthn.get", &options.challenge, &options.origin)?;
    let client_hash = Sha256::digest(&client_data);
    let mut signed_data = Zeroizing::new(Vec::with_capacity(auth_data.len() + client_hash.len()));
    signed_data.extend_from_slice(&auth_data);
    signed_data.extend_from_slice(&client_hash);
    let signature: Signature = signing.sign(&signed_data);

    Ok(PasskeyAssertionResult {
        credential_id,
        client_data_json: URL_SAFE_NO_PAD.encode(client_data),
        authenticator_data: URL_SAFE_NO_PAD.encode(auth_data),
        signature: URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
        user_handle: credential.user_handle.clone(),
        counter_changed,
    })
}

/// Validates assertion inputs and resolves the canonical RP ID.
///
/// # Errors
///
/// Returns a closed failure for invalid origin, RP ID, challenge, descriptors, or unsupported
/// conditional mediation.
pub fn validate_passkey_assertion(
    options: &PasskeyAssertionOptions,
) -> Result<String, PasskeyError> {
    validate_challenge(&options.challenge)?;
    validate_descriptors(&options.allow_credentials)?;
    if options.mediation.as_deref() == Some("conditional") {
        return Err(PasskeyError::Unsupported);
    }
    canonical_rp_id(&options.origin, options.rp_id.as_deref())
}

/// Converts a compatible stored credential ID to `WebAuthn` base64url form.
///
/// # Errors
///
/// Returns an error for malformed UUID or `b64.` credential encodings.
pub fn passkey_credential_id(credential: &Fido2Credential) -> Result<String, PasskeyError> {
    stored_credential_id(&credential.credential_id).map(|value| URL_SAFE_NO_PAD.encode(value))
}

fn canonical_rp_id(origin: &str, requested: Option<&str>) -> Result<String, PasskeyError> {
    if origin.len() > 2_048 {
        return Err(PasskeyError::InvalidRequest);
    }
    let parsed = Url::parse(origin).map_err(|_| PasskeyError::InvalidRequest)?;
    if parsed.username() != ""
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.origin().ascii_serialization() != origin
    {
        return Err(PasskeyError::InvalidRequest);
    }
    let host = parsed
        .host_str()
        .ok_or(PasskeyError::InvalidRequest)?
        .to_ascii_lowercase();
    let local = host == "localhost"
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && local) {
        return Err(PasskeyError::InvalidRequest);
    }
    let rp_id = requested
        .unwrap_or(&host)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if rp_id.is_empty()
        || rp_id.len() > 253
        || rp_id.contains(['/', ':'])
        || rp_id.chars().any(char::is_whitespace)
        || !(host == rp_id || host.ends_with(&format!(".{rp_id}")))
    {
        return Err(PasskeyError::InvalidRequest);
    }
    if host.parse::<IpAddr>().is_ok() || local {
        return (rp_id == host)
            .then_some(rp_id)
            .ok_or(PasskeyError::InvalidRequest);
    }
    if psl::domain_str(&rp_id).is_none() {
        return Err(PasskeyError::InvalidRequest);
    }
    Ok(rp_id)
}

fn validate_challenge(value: &str) -> Result<(), PasskeyError> {
    let bytes = decode_b64url(value)?;
    if !(16..=MAX_CHALLENGE_BYTES).contains(&bytes.len()) {
        return Err(PasskeyError::InvalidRequest);
    }
    Ok(())
}

fn validate_descriptors(values: &[PasskeyCredentialDescriptor]) -> Result<(), PasskeyError> {
    if values.len() > MAX_CREDENTIAL_DESCRIPTORS {
        return Err(PasskeyError::InvalidRequest);
    }
    for value in values {
        if value
            .r#type
            .as_deref()
            .is_some_and(|kind| kind != "public-key")
        {
            return Err(PasskeyError::InvalidRequest);
        }
        let bytes = decode_b64url(&value.id)?;
        if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_ID_BYTES {
            return Err(PasskeyError::InvalidRequest);
        }
    }
    Ok(())
}

fn descriptor_transport_supported(descriptor: &PasskeyCredentialDescriptor) -> bool {
    descriptor.transports.is_empty()
        || descriptor
            .transports
            .iter()
            .any(|transport| matches!(transport.as_str(), "internal" | "hybrid"))
}

fn validate_text(value: &str, minimum: usize, maximum: usize) -> Result<(), PasskeyError> {
    if !(minimum..=maximum).contains(&value.len()) || value.chars().any(char::is_control) {
        return Err(PasskeyError::InvalidRequest);
    }
    Ok(())
}

fn decode_b64url(value: &str) -> Result<Vec<u8>, PasskeyError> {
    if value.len() > MAX_CHALLENGE_BYTES.saturating_mul(4) {
        return Err(PasskeyError::InvalidRequest);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| PasskeyError::InvalidRequest)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(PasskeyError::InvalidRequest);
    }
    Ok(bytes)
}

fn stored_credential_id(value: &str) -> Result<Vec<u8>, PasskeyError> {
    if let Ok(uuid) = Uuid::parse_str(value) {
        return Ok(uuid.as_bytes().to_vec());
    }
    let encoded = value.strip_prefix("b64.").unwrap_or(value);
    let bytes = decode_b64url(encoded)?;
    if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_ID_BYTES {
        return Err(PasskeyError::InvalidRequest);
    }
    Ok(bytes)
}

fn generate_secret_key() -> Result<SecretKey, PasskeyError> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    for _ in 0..128 {
        getrandom::fill(bytes.as_mut()).map_err(|_| PasskeyError::Crypto)?;
        if let Ok(secret) = SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
    Err(PasskeyError::Crypto)
}

fn collected_client_data(
    operation: &str,
    challenge: &str,
    origin: &str,
) -> Result<Vec<u8>, PasskeyError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct CollectedClientData<'a> {
        r#type: &'a str,
        challenge: &'a str,
        origin: &'a str,
        cross_origin: bool,
    }
    serde_json::to_vec(&CollectedClientData {
        r#type: operation,
        challenge,
        origin,
        cross_origin: false,
    })
    .map_err(|_| PasskeyError::Crypto)
}

#[allow(
    clippy::type_complexity,
    reason = "the optional attested tuple directly mirrors credential-id/x/y WebAuthn fields"
)]
fn authenticator_data(
    rp_id: &str,
    counter: u32,
    user_present: bool,
    user_verified: bool,
    attested: Option<(&[u8], &[u8], &[u8])>,
) -> Result<Vec<u8>, PasskeyError> {
    let mut output = Vec::with_capacity(if attested.is_some() { 192 } else { 37 });
    output.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    let mut flags = 0b0001_1000; // BE + BS: vault credentials are synchronizable.
    if user_present {
        flags |= 0b0000_0001;
    }
    if user_verified {
        flags |= 0b0000_0100;
    }
    if attested.is_some() {
        flags |= 0b0100_0000;
    }
    output.push(flags);
    output.extend_from_slice(&counter.to_be_bytes());
    if let Some((credential_id, x, y)) = attested {
        if credential_id.len() > usize::from(u16::MAX) || x.len() != 32 || y.len() != 32 {
            return Err(PasskeyError::Crypto);
        }
        output.extend_from_slice(&HASILAN_AAGUID);
        output.extend_from_slice(
            &u16::try_from(credential_id.len())
                .map_err(|_| PasskeyError::Crypto)?
                .to_be_bytes(),
        );
        output.extend_from_slice(credential_id);
        // CTAP2 canonical COSE_Key: {1:2, 3:-7, -1:1, -2:x, -3:y}.
        output.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
        output.extend_from_slice(x);
        output.extend_from_slice(&[0x22, 0x58, 0x20]);
        output.extend_from_slice(y);
    }
    Ok(output)
}

fn none_attestation(auth_data: &[u8]) -> Result<Vec<u8>, PasskeyError> {
    let mut output = Vec::with_capacity(auth_data.len() + 32);
    // Canonically ordered map: "fmt", "attStmt", "authData".
    output.extend_from_slice(&[0xa3, 0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e']);
    output.extend_from_slice(&[
        0x67, b'a', b't', b't', b'S', b't', b'm', b't', 0xa0, 0x68, b'a', b'u', b't', b'h', b'D',
        b'a', b't', b'a',
    ]);
    encode_cbor_byte_length(auth_data.len(), &mut output)?;
    output.extend_from_slice(auth_data);
    Ok(output)
}

fn encode_cbor_byte_length(length: usize, output: &mut Vec<u8>) -> Result<(), PasskeyError> {
    match length {
        0..=23 => output.push(0x40 | u8::try_from(length).map_err(|_| PasskeyError::Crypto)?),
        24..=255 => {
            output.push(0x58);
            output.push(u8::try_from(length).map_err(|_| PasskeyError::Crypto)?);
        }
        256..=65_535 => {
            output.push(0x59);
            output.extend_from_slice(
                &u16::try_from(length)
                    .map_err(|_| PasskeyError::Crypto)?
                    .to_be_bytes(),
            );
        }
        _ => return Err(PasskeyError::Crypto),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::{VerifyingKey, signature::Verifier as _};

    use super::*;

    fn creation() -> PasskeyCreationOptions {
        PasskeyCreationOptions {
            origin: "https://login.example.com".to_owned(),
            challenge: URL_SAFE_NO_PAD.encode([42_u8; 32]),
            rp: PasskeyRpEntity {
                id: Some("example.com".to_owned()),
                name: "Example".to_owned(),
            },
            user: PasskeyUserEntity {
                id: URL_SAFE_NO_PAD.encode(b"alice-user-handle"),
                name: "alice@example.com".to_owned(),
                display_name: "Alice".to_owned(),
            },
            pub_key_cred_params: vec![PasskeyCredentialParameter {
                alg: -7,
                r#type: "public-key".to_owned(),
            }],
            exclude_credentials: Vec::new(),
            authenticator_selection: Some(PasskeyAuthenticatorSelection {
                resident_key: Some("required".to_owned()),
                user_verification: Some("required".to_owned()),
                ..PasskeyAuthenticatorSelection::default()
            }),
            attestation: Some("none".to_owned()),
            extensions: PasskeyCreationExtensions { cred_props: true },
        }
    }

    #[test]
    fn creates_bitwarden_compatible_key_and_verifiable_assertion() {
        let created = create_passkey(&creation(), true).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.credential.key_type, "public-key");
        assert_eq!(created.credential.key_algorithm, "ECDSA");
        assert_eq!(created.credential.key_curve, "P-256");
        assert!(created.discoverable);

        let mut credential = created.credential;
        let options = PasskeyAssertionOptions {
            origin: "https://login.example.com".to_owned(),
            challenge: URL_SAFE_NO_PAD.encode([7_u8; 32]),
            rp_id: Some("example.com".to_owned()),
            allow_credentials: vec![PasskeyCredentialDescriptor {
                id: created.credential_id,
                r#type: Some("public-key".to_owned()),
                transports: vec!["internal".to_owned()],
            }],
            user_verification: Some("required".to_owned()),
            mediation: None,
        };
        let asserted = assert_passkey(&mut credential, &options, true)
            .unwrap_or_else(|error| panic!("{error}"));
        let private = URL_SAFE_NO_PAD
            .decode(credential.key_value.expose())
            .unwrap_or_else(|error| panic!("{error}"));
        let signing =
            SigningKey::from_pkcs8_der(&private).unwrap_or_else(|error| panic!("{error}"));
        let verifying = VerifyingKey::from(&signing);
        let auth_data = URL_SAFE_NO_PAD
            .decode(asserted.authenticator_data)
            .unwrap_or_else(|error| panic!("{error}"));
        let client_data = URL_SAFE_NO_PAD
            .decode(asserted.client_data_json)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut signed = auth_data;
        signed.extend_from_slice(&Sha256::digest(client_data));
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(asserted.signature)
            .unwrap_or_else(|error| panic!("{error}"));
        let signature =
            Signature::from_der(&signature_bytes).unwrap_or_else(|error| panic!("{error}"));
        verifying
            .verify(&signed, &signature)
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn origin_and_rp_validation_fail_closed() {
        let mut value = creation();
        value.rp.id = Some("com".to_owned());
        assert_eq!(
            validate_passkey_creation(&value),
            Err(PasskeyError::InvalidRequest)
        );
        value.rp.id = Some("example.com.attacker.test".to_owned());
        assert_eq!(
            validate_passkey_creation(&value),
            Err(PasskeyError::InvalidRequest)
        );
        value.rp.id = Some("example.com".to_owned());
        value.origin = "http://login.example.com".to_owned();
        assert_eq!(
            validate_passkey_creation(&value),
            Err(PasskeyError::InvalidRequest)
        );
    }

    #[test]
    fn localhost_is_the_only_plain_http_exception() {
        let mut value = creation();
        value.origin = "http://localhost:19090".to_owned();
        value.rp.id = Some("localhost".to_owned());
        assert_eq!(
            validate_passkey_creation(&value).as_deref(),
            Ok("localhost")
        );
    }
}
