#![allow(
    missing_docs,
    reason = "item field names intentionally mirror the documented Bitwarden JSON model"
)]

use std::fmt;

use chrono::{DateTime, Utc};
use hasilan_core::VAULT_SCHEMA_VERSION;
use hasilan_crypto::AttachmentMetadata;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A string whose memory is cleared on drop and whose debug form is redacted.
#[derive(Clone, Default, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    /// Wraps a secret owned string.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Exposes the secret to an explicit consumer.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self)
    }
}

/// A complete private vault item. The whole structure is encrypted before synchronization.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultItem {
    /// Payload schema, independently of the outer crypto envelope version.
    pub schema_version: u32,
    /// Stable client-generated ID.
    pub id: Uuid,
    /// Personal folder, if any.
    pub folder_id: Option<Uuid>,
    /// Organization owner, if any.
    pub organization_id: Option<Uuid>,
    /// Organization collection memberships.
    #[serde(default)]
    pub collection_ids: Vec<Uuid>,
    /// Display name.
    pub name: String,
    /// Private notes.
    pub notes: Option<String>,
    /// Favorite marker.
    #[serde(default)]
    pub favorite: bool,
    /// Master-password reprompt setting (`0` none, `1` password).
    #[serde(default)]
    pub reprompt: u8,
    /// Custom fields.
    #[serde(default)]
    pub fields: Vec<CustomField>,
    /// Previous passwords.
    #[serde(default)]
    pub password_history: Vec<PasswordHistory>,
    /// Private attachment names, dimensions, nonces, and encryption keys.
    #[serde(default)]
    pub attachments: Vec<AttachmentMetadata>,
    /// Type-specific content.
    pub data: ItemData,
    /// Client creation timestamp.
    pub creation_date: DateTime<Utc>,
    /// Client content timestamp.
    pub revision_date: DateTime<Utc>,
    /// Trash timestamp.
    pub deleted_date: Option<DateTime<Utc>>,
    /// Archive timestamp used by current Bitwarden exports.
    pub archived_date: Option<DateTime<Utc>>,
    /// Forward-compatible fields that have no current editor.
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl VaultItem {
    /// Creates a new typed vault item with secure common defaults.
    #[must_use]
    pub fn new(name: impl Into<String>, data: ItemData) -> Self {
        let now = Utc::now();
        Self {
            schema_version: VAULT_SCHEMA_VERSION,
            id: Uuid::new_v4(),
            folder_id: None,
            organization_id: None,
            collection_ids: Vec::new(),
            name: name.into(),
            notes: None,
            favorite: false,
            reprompt: 0,
            fields: Vec::new(),
            password_history: Vec::new(),
            attachments: Vec::new(),
            data,
            creation_date: now,
            revision_date: now,
            deleted_date: None,
            archived_date: None,
            extra: serde_json::Map::new(),
        }
    }

    /// Creates a new login with secure defaults and client-generated identity.
    #[must_use]
    pub fn new_login(name: impl Into<String>, login: Login) -> Self {
        Self::new(name, ItemData::Login(login))
    }

    /// Returns the Bitwarden-compatible numeric item type.
    #[must_use]
    pub fn item_type(&self) -> u8 {
        self.data.item_type()
    }
}

impl fmt::Debug for VaultItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultItem")
            .field("id", &self.id)
            .field("type", &self.item_type())
            .field("private", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Type-specific vault data.
#[allow(
    clippy::large_enum_variant,
    reason = "keeping external item variants direct avoids schema-breaking indirection"
)]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
pub enum ItemData {
    /// Website/application credential.
    Login(Login),
    /// Secure note (`note_type` is currently zero).
    SecureNote(SecureNote),
    /// Payment card.
    Card(Card),
    /// Personal identity.
    Identity(Identity),
    /// SSH key item.
    SshKey(SshKey),
    /// A newer or unknown Bitwarden item retained losslessly.
    Unsupported { item_type: u8, raw: Value },
}

impl ItemData {
    /// Returns the external numeric type.
    #[must_use]
    pub fn item_type(&self) -> u8 {
        match self {
            Self::Login(_) => 1,
            Self::SecureNote(_) => 2,
            Self::Card(_) => 3,
            Self::Identity(_) => 4,
            Self::SshKey(_) => 5,
            Self::Unsupported { item_type, .. } => *item_type,
        }
    }
}

/// Login credential data.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Login {
    pub username: Option<String>,
    pub password: Option<SecretString>,
    #[serde(default)]
    pub uris: Vec<LoginUri>,
    pub totp: Option<SecretString>,
    #[serde(default)]
    pub fido2_credentials: Vec<Fido2Credential>,
    pub password_revision_date: Option<DateTime<Utc>>,
    pub autofill_on_page_load: Option<bool>,
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// A saved URI and its matching policy.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginUri {
    pub uri: String,
    pub r#match: Option<crate::UriMatchType>,
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Encrypted vault passkey metadata and private material.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fido2Credential {
    pub credential_id: String,
    pub key_type: String,
    pub key_algorithm: String,
    pub key_curve: String,
    pub key_value: SecretString,
    pub public_key: Option<String>,
    pub rp_id: String,
    pub user_handle: Option<String>,
    pub user_name: Option<String>,
    pub counter: u32,
    pub rp_name: Option<String>,
    pub user_display_name: Option<String>,
    pub discoverable: bool,
    #[serde(default)]
    pub transports: Vec<String>,
    pub creation_date: DateTime<Utc>,
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Generic secure note subtype.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureNote {
    #[serde(default)]
    pub note_type: u8,
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Payment-card fields.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Card {
    pub cardholder_name: Option<String>,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub code: Option<SecretString>,
    pub brand: Option<String>,
    pub number: Option<SecretString>,
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Identity fields compatible with Bitwarden JSON.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub title: Option<String>,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub address3: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub company: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub ssn: Option<SecretString>,
    pub username: Option<String>,
    pub passport_number: Option<SecretString>,
    pub license_number: Option<SecretString>,
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// SSH key item fields.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshKey {
    pub private_key: SecretString,
    pub public_key: String,
    pub key_fingerprint: String,
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Bitwarden-compatible custom field.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomField {
    pub name: Option<String>,
    pub value: Option<SecretString>,
    pub field_type: u8,
    pub linked_id: Option<u32>,
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Historical password entry.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHistory {
    pub password: SecretString,
    pub last_used_date: DateTime<Utc>,
}
