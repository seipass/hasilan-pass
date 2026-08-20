//! Import/export compatibility with the documented Bitwarden JSON format.
#![allow(
    missing_docs,
    reason = "compatibility DTO field names intentionally mirror the external Bitwarden JSON schema"
)]

use chrono::{DateTime, Utc};
use hasilan_vault::{
    Card, CustomField, Fido2Credential, Identity, ItemData, Login, LoginUri, PasswordHistory,
    SecretString, SecureNote, SshKey, UriMatchType, VaultItem,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;
use uuid::Uuid;

const MAX_EXPORT_BYTES: usize = 64 * 1024 * 1024;
const MAX_ITEMS: usize = 40_000;
const MAX_FOLDERS: usize = 2_000;
const MAX_COLLECTIONS: usize = 2_000;

/// Compatibility parse/conversion error without plaintext payloads.
#[derive(Debug, Error)]
pub enum CompatibilityError {
    #[error("Bitwarden JSON is malformed")]
    Json(#[from] serde_json::Error),
    #[error("encrypted Bitwarden JSON requires the encrypted-export decoder")]
    EncryptedExport,
    #[error("Bitwarden export exceeds safe limits")]
    LimitExceeded,
    #[error("Bitwarden item type {0} has invalid or missing data")]
    InvalidItem(u8),
    #[error("Bitwarden URI match strategy is unsupported")]
    InvalidUriMatch,
}

/// Imported folders, collections, and private items.
#[derive(Clone, PartialEq)]
pub struct ImportedVault {
    pub folders: Vec<BitwardenFolder>,
    pub collections: Vec<BitwardenCollection>,
    pub items: Vec<VaultItem>,
}

/// Parses a plaintext Bitwarden JSON export with resource limits.
///
/// # Errors
///
/// Returns [`CompatibilityError`] for malformed, encrypted, oversized, or
/// semantically invalid input. No partial vault is returned.
pub fn import_json(input: &[u8]) -> Result<ImportedVault, CompatibilityError> {
    if input.len() > MAX_EXPORT_BYTES {
        return Err(CompatibilityError::LimitExceeded);
    }
    let export: BitwardenExport = serde_json::from_slice(input)?;
    if export.encrypted {
        return Err(CompatibilityError::EncryptedExport);
    }
    let folders = export.folders.unwrap_or_default();
    let collections = export.collections.unwrap_or_default();
    if export.items.len() > MAX_ITEMS
        || folders.len() > MAX_FOLDERS
        || collections.len() > MAX_COLLECTIONS
    {
        return Err(CompatibilityError::LimitExceeded);
    }
    let items = export
        .items
        .into_iter()
        .map(VaultItem::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ImportedVault {
        folders,
        collections,
        items,
    })
}

/// Produces canonical, plaintext Bitwarden JSON entirely in the client.
///
/// # Errors
///
/// Returns [`CompatibilityError::LimitExceeded`] if the vault exceeds safe
/// export bounds or a JSON serialization error occurs.
pub fn export_json(vault: &ImportedVault) -> Result<Vec<u8>, CompatibilityError> {
    if vault.items.len() > MAX_ITEMS
        || vault.folders.len() > MAX_FOLDERS
        || vault.collections.len() > MAX_COLLECTIONS
    {
        return Err(CompatibilityError::LimitExceeded);
    }
    let output = BitwardenExport {
        encrypted: false,
        folders: (!vault.folders.is_empty()).then(|| vault.folders.clone()),
        collections: (!vault.collections.is_empty()).then(|| vault.collections.clone()),
        items: vault.items.iter().map(BitwardenCipher::from).collect(),
        extra: Map::new(),
    };
    Ok(serde_json::to_vec_pretty(&output)?)
}

/// Top-level plaintext Bitwarden export.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitwardenExport {
    #[serde(default)]
    pub encrypted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folders: Option<Vec<BitwardenFolder>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collections: Option<Vec<BitwardenCollection>>,
    #[serde(default)]
    pub items: Vec<BitwardenCipher>,
    #[serde(default, flatten)]
    pub extra: Map<String, Value>,
}

/// Bitwarden folder export entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitwardenFolder {
    pub id: Uuid,
    pub name: String,
}

/// Bitwarden organization collection export entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitwardenCollection {
    pub id: Uuid,
    pub organization_id: Option<Uuid>,
    pub name: String,
    #[serde(default, flatten)]
    pub extra: Map<String, Value>,
}

/// Bitwarden JSON Cipher in decrypted export form.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitwardenCipher {
    pub id: Option<Uuid>,
    pub folder_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub collection_ids: Option<Vec<Uuid>>,
    pub name: String,
    pub notes: Option<String>,
    pub r#type: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<BitwardenLogin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure_note: Option<BitwardenSecureNote>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card: Option<BitwardenCard>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<BitwardenIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<BitwardenSshKey>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub reprompt: u8,
    pub fields: Option<Vec<BitwardenField>>,
    pub password_history: Option<Vec<BitwardenPasswordHistory>>,
    pub revision_date: Option<DateTime<Utc>>,
    pub creation_date: Option<DateTime<Utc>>,
    pub deleted_date: Option<DateTime<Utc>>,
    pub archived_date: Option<DateTime<Utc>>,
    #[serde(default, flatten)]
    pub extra: Map<String, Value>,
}

/// Decrypted Bitwarden Login export.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitwardenLogin {
    pub username: Option<String>,
    pub password: Option<String>,
    pub password_revision_date: Option<DateTime<Utc>>,
    pub uris: Option<Vec<BitwardenLoginUri>>,
    pub totp: Option<String>,
    pub autofill_on_page_load: Option<bool>,
    pub fido2_credentials: Option<Vec<BitwardenFido2Credential>>,
    #[serde(default, flatten)]
    pub extra: Map<String, Value>,
}

/// Decrypted Bitwarden Login URI export.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitwardenLoginUri {
    pub uri: Option<String>,
    pub r#match: Option<u8>,
    #[serde(default, flatten)]
    pub extra: Map<String, Value>,
}

/// Decrypted Bitwarden vault passkey export fields.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitwardenFido2Credential {
    pub credential_id: String,
    pub key_type: String,
    pub key_algorithm: String,
    pub key_curve: String,
    pub key_value: String,
    pub rp_id: String,
    pub user_handle: Option<String>,
    pub user_name: Option<String>,
    pub counter: String,
    pub rp_name: Option<String>,
    pub user_display_name: Option<String>,
    pub discoverable: String,
    pub creation_date: DateTime<Utc>,
    #[serde(default, flatten)]
    pub extra: Map<String, Value>,
}

/// Bitwarden secure-note subtype.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BitwardenSecureNote {
    #[serde(rename = "type", default)]
    pub note_type: u8,
    #[serde(default, flatten)]
    pub extra: Map<String, Value>,
}

/// Bitwarden payment-card fields.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitwardenCard {
    pub cardholder_name: Option<String>,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub code: Option<String>,
    pub brand: Option<String>,
    pub number: Option<String>,
    #[serde(default, flatten)]
    pub extra: Map<String, Value>,
}

/// Bitwarden identity fields.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitwardenIdentity {
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
    pub ssn: Option<String>,
    pub username: Option<String>,
    pub passport_number: Option<String>,
    pub license_number: Option<String>,
    #[serde(default, flatten)]
    pub extra: Map<String, Value>,
}

/// Bitwarden SSH key fields.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitwardenSshKey {
    pub private_key: String,
    pub public_key: String,
    #[serde(alias = "fingerprint")]
    pub key_fingerprint: String,
    #[serde(default, flatten)]
    pub extra: Map<String, Value>,
}

/// Bitwarden custom field.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitwardenField {
    pub name: Option<String>,
    pub value: Option<String>,
    #[serde(rename = "type")]
    pub field_type: u8,
    pub linked_id: Option<u32>,
    #[serde(default, flatten)]
    pub extra: Map<String, Value>,
}

/// Bitwarden password history entry.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitwardenPasswordHistory {
    pub password: String,
    pub last_used_date: DateTime<Utc>,
}

impl TryFrom<BitwardenCipher> for VaultItem {
    type Error = CompatibilityError;

    fn try_from(cipher: BitwardenCipher) -> Result<Self, Self::Error> {
        let item_type = cipher.r#type;
        let data = match item_type {
            1 => ItemData::Login(login_from_export(
                cipher.login.ok_or(CompatibilityError::InvalidItem(1))?,
            )?),
            2 => {
                let note = cipher.secure_note.unwrap_or_default();
                ItemData::SecureNote(SecureNote {
                    note_type: note.note_type,
                    extra: note.extra,
                })
            }
            3 => {
                let card = cipher.card.ok_or(CompatibilityError::InvalidItem(3))?;
                ItemData::Card(Card {
                    cardholder_name: card.cardholder_name,
                    exp_month: card.exp_month,
                    exp_year: card.exp_year,
                    code: card.code.map(SecretString::new),
                    brand: card.brand,
                    number: card.number.map(SecretString::new),
                    extra: card.extra,
                })
            }
            4 => {
                let identity = cipher.identity.ok_or(CompatibilityError::InvalidItem(4))?;
                ItemData::Identity(identity_from_export(identity))
            }
            5 => {
                let key = cipher.ssh_key.ok_or(CompatibilityError::InvalidItem(5))?;
                ItemData::SshKey(SshKey {
                    private_key: SecretString::new(key.private_key),
                    public_key: key.public_key,
                    key_fingerprint: key.key_fingerprint,
                    extra: key.extra,
                })
            }
            other => ItemData::Unsupported {
                item_type: other,
                raw: Value::Object(cipher.extra.clone()),
            },
        };
        let now = Utc::now();
        Ok(VaultItem {
            schema_version: 1,
            id: cipher.id.unwrap_or_else(Uuid::new_v4),
            folder_id: cipher.folder_id,
            organization_id: cipher.organization_id,
            collection_ids: cipher.collection_ids.unwrap_or_default(),
            name: cipher.name,
            notes: cipher.notes,
            favorite: cipher.favorite,
            reprompt: cipher.reprompt,
            fields: cipher
                .fields
                .unwrap_or_default()
                .into_iter()
                .map(|field| CustomField {
                    name: field.name,
                    value: field.value.map(SecretString::new),
                    field_type: field.field_type,
                    linked_id: field.linked_id,
                    extra: field.extra,
                })
                .collect(),
            password_history: cipher
                .password_history
                .unwrap_or_default()
                .into_iter()
                .map(|history| PasswordHistory {
                    password: SecretString::new(history.password),
                    last_used_date: history.last_used_date,
                })
                .collect(),
            attachments: Vec::new(),
            data,
            creation_date: cipher.creation_date.unwrap_or(now),
            revision_date: cipher.revision_date.unwrap_or(now),
            deleted_date: cipher.deleted_date,
            archived_date: cipher.archived_date,
            extra: if item_type > 5 {
                Map::new()
            } else {
                cipher.extra
            },
        })
    }
}

fn login_from_export(login: BitwardenLogin) -> Result<Login, CompatibilityError> {
    Ok(Login {
        username: login.username,
        password: login.password.map(SecretString::new),
        uris: login
            .uris
            .unwrap_or_default()
            .into_iter()
            .filter_map(|uri| uri.uri.map(|value| (value, uri.r#match, uri.extra)))
            .map(|(uri, strategy, extra)| {
                Ok(LoginUri {
                    uri,
                    r#match: strategy
                        .map(UriMatchType::try_from)
                        .transpose()
                        .map_err(|_| CompatibilityError::InvalidUriMatch)?,
                    extra,
                })
            })
            .collect::<Result<Vec<_>, CompatibilityError>>()?,
        totp: login.totp.map(SecretString::new),
        fido2_credentials: login
            .fido2_credentials
            .unwrap_or_default()
            .into_iter()
            .map(|credential| Fido2Credential {
                credential_id: credential.credential_id,
                key_type: credential.key_type,
                key_algorithm: credential.key_algorithm,
                key_curve: credential.key_curve,
                key_value: SecretString::new(credential.key_value),
                public_key: None,
                rp_id: credential.rp_id,
                user_handle: credential.user_handle,
                user_name: credential.user_name,
                counter: credential.counter.parse().unwrap_or(0),
                rp_name: credential.rp_name,
                user_display_name: credential.user_display_name,
                discoverable: credential.discoverable.eq_ignore_ascii_case("true"),
                transports: Vec::new(),
                creation_date: credential.creation_date,
                extra: credential.extra,
            })
            .collect(),
        password_revision_date: login.password_revision_date,
        autofill_on_page_load: login.autofill_on_page_load,
        extra: login.extra,
    })
}

fn identity_from_export(identity: BitwardenIdentity) -> Identity {
    Identity {
        title: identity.title,
        first_name: identity.first_name,
        middle_name: identity.middle_name,
        last_name: identity.last_name,
        address1: identity.address1,
        address2: identity.address2,
        address3: identity.address3,
        city: identity.city,
        state: identity.state,
        postal_code: identity.postal_code,
        country: identity.country,
        company: identity.company,
        email: identity.email,
        phone: identity.phone,
        ssn: identity.ssn.map(SecretString::new),
        username: identity.username,
        passport_number: identity.passport_number.map(SecretString::new),
        license_number: identity.license_number.map(SecretString::new),
        extra: identity.extra,
    }
}

impl From<&VaultItem> for BitwardenCipher {
    fn from(item: &VaultItem) -> Self {
        let mut output = Self {
            id: Some(item.id),
            folder_id: item.folder_id,
            organization_id: item.organization_id,
            collection_ids: (!item.collection_ids.is_empty()).then(|| item.collection_ids.clone()),
            name: item.name.clone(),
            notes: item.notes.clone(),
            r#type: item.item_type(),
            login: None,
            secure_note: None,
            card: None,
            identity: None,
            ssh_key: None,
            favorite: item.favorite,
            reprompt: item.reprompt,
            fields: (!item.fields.is_empty()).then(|| {
                item.fields
                    .iter()
                    .map(|field| BitwardenField {
                        name: field.name.clone(),
                        value: field.value.as_ref().map(|value| value.expose().to_owned()),
                        field_type: field.field_type,
                        linked_id: field.linked_id,
                        extra: field.extra.clone(),
                    })
                    .collect()
            }),
            password_history: (!item.password_history.is_empty()).then(|| {
                item.password_history
                    .iter()
                    .map(|history| BitwardenPasswordHistory {
                        password: history.password.expose().to_owned(),
                        last_used_date: history.last_used_date,
                    })
                    .collect()
            }),
            revision_date: Some(item.revision_date),
            creation_date: Some(item.creation_date),
            deleted_date: item.deleted_date,
            archived_date: item.archived_date,
            extra: item.extra.clone(),
        };
        match &item.data {
            ItemData::Login(login) => output.login = Some(login_to_export(login)),
            ItemData::SecureNote(note) => {
                output.secure_note = Some(BitwardenSecureNote {
                    note_type: note.note_type,
                    extra: note.extra.clone(),
                });
            }
            ItemData::Card(card) => {
                output.card = Some(BitwardenCard {
                    cardholder_name: card.cardholder_name.clone(),
                    exp_month: card.exp_month.clone(),
                    exp_year: card.exp_year.clone(),
                    code: card.code.as_ref().map(|value| value.expose().to_owned()),
                    brand: card.brand.clone(),
                    number: card.number.as_ref().map(|value| value.expose().to_owned()),
                    extra: card.extra.clone(),
                });
            }
            ItemData::Identity(identity) => {
                output.identity = Some(identity_to_export(identity));
            }
            ItemData::SshKey(key) => {
                output.ssh_key = Some(BitwardenSshKey {
                    private_key: key.private_key.expose().to_owned(),
                    public_key: key.public_key.clone(),
                    key_fingerprint: key.key_fingerprint.clone(),
                    extra: key.extra.clone(),
                });
            }
            ItemData::Unsupported { raw, .. } => {
                if let Value::Object(properties) = raw {
                    output.extra.extend(properties.clone());
                }
            }
        }
        output
    }
}

fn login_to_export(login: &Login) -> BitwardenLogin {
    BitwardenLogin {
        username: login.username.clone(),
        password: login
            .password
            .as_ref()
            .map(|value| value.expose().to_owned()),
        password_revision_date: login.password_revision_date,
        uris: (!login.uris.is_empty()).then(|| {
            login
                .uris
                .iter()
                .map(|uri| BitwardenLoginUri {
                    uri: Some(uri.uri.clone()),
                    r#match: uri.r#match.map(|value| value as u8),
                    extra: uri.extra.clone(),
                })
                .collect()
        }),
        totp: login.totp.as_ref().map(|value| value.expose().to_owned()),
        autofill_on_page_load: login.autofill_on_page_load,
        fido2_credentials: (!login.fido2_credentials.is_empty()).then(|| {
            login
                .fido2_credentials
                .iter()
                .map(|credential| BitwardenFido2Credential {
                    credential_id: credential.credential_id.clone(),
                    key_type: credential.key_type.clone(),
                    key_algorithm: credential.key_algorithm.clone(),
                    key_curve: credential.key_curve.clone(),
                    key_value: credential.key_value.expose().to_owned(),
                    rp_id: credential.rp_id.clone(),
                    user_handle: credential.user_handle.clone(),
                    user_name: credential.user_name.clone(),
                    counter: credential.counter.to_string(),
                    rp_name: credential.rp_name.clone(),
                    user_display_name: credential.user_display_name.clone(),
                    discoverable: credential.discoverable.to_string(),
                    creation_date: credential.creation_date,
                    extra: credential.extra.clone(),
                })
                .collect()
        }),
        extra: login.extra.clone(),
    }
}

fn identity_to_export(identity: &Identity) -> BitwardenIdentity {
    BitwardenIdentity {
        title: identity.title.clone(),
        first_name: identity.first_name.clone(),
        middle_name: identity.middle_name.clone(),
        last_name: identity.last_name.clone(),
        address1: identity.address1.clone(),
        address2: identity.address2.clone(),
        address3: identity.address3.clone(),
        city: identity.city.clone(),
        state: identity.state.clone(),
        postal_code: identity.postal_code.clone(),
        country: identity.country.clone(),
        company: identity.company.clone(),
        email: identity.email.clone(),
        phone: identity.phone.clone(),
        ssn: identity.ssn.as_ref().map(|value| value.expose().to_owned()),
        username: identity.username.clone(),
        passport_number: identity
            .passport_number
            .as_ref()
            .map(|value| value.expose().to_owned()),
        license_number: identity
            .license_number
            .as_ref()
            .map(|value| value.expose().to_owned()),
        extra: identity.extra.clone(),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test assertions intentionally fail fast"
)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../../../tests/fixtures/bitwarden/plain.json");

    #[test]
    fn bitwarden_export_imports_expected_fields() {
        let vault = import_json(FIXTURE).unwrap();
        assert_eq!(vault.folders.len(), 1);
        assert_eq!(vault.items.len(), 5);
        let login = &vault.items[0];
        assert_eq!(login.name, "Example login");
        let ItemData::Login(login) = &login.data else {
            panic!("login expected");
        };
        assert_eq!(login.username.as_deref(), Some("alice@example.com"));
        assert_eq!(
            login.password.as_ref().map(SecretString::expose),
            Some("correct horse")
        );
        assert_eq!(login.fido2_credentials.len(), 1);
        assert_eq!(login.fido2_credentials[0].rp_id, "example.com");
        let ItemData::SshKey(ssh_key) = &vault.items[4].data else {
            panic!("SSH key expected");
        };
        assert_eq!(ssh_key.key_fingerprint, "SHA256:synthetic-fixture");
    }

    #[test]
    fn import_export_import_is_semantically_stable() {
        let first = import_json(FIXTURE).unwrap();
        let exported = export_json(&first).unwrap();
        let second = import_json(&exported).unwrap();
        assert_eq!(first.items, second.items);
        assert_eq!(first.folders, second.folders);
        assert_eq!(first.collections, second.collections);
    }

    #[test]
    fn hasilan_export_uses_bitwarden_shape() {
        let vault = import_json(FIXTURE).unwrap();
        let exported = export_json(&vault).unwrap();
        let json: Value = serde_json::from_slice(&exported).unwrap();
        assert_eq!(json["encrypted"], false);
        assert_eq!(json["items"][0]["type"], 1);
        assert_eq!(json["items"][0]["login"]["totp"], "JBSWY3DPEHPK3PXP");
        assert_eq!(
            json["items"][0]["login"]["fido2Credentials"][0]["credentialId"],
            "synthetic-credential-id"
        );
    }

    #[test]
    fn malformed_and_oversized_inputs_fail_without_partial_import() {
        assert!(import_json(br#"{"encrypted":false,"items":["#).is_err());
        let oversized = vec![b' '; MAX_EXPORT_BYTES + 1];
        assert!(matches!(
            import_json(&oversized),
            Err(CompatibilityError::LimitExceeded)
        ));
    }

    #[test]
    fn newer_and_unknown_item_payloads_round_trip_without_interpretation() {
        let input = serde_json::json!({
            "encrypted": false,
            "items": [
                {
                    "id": "9f13c163-4f2a-4262-a54d-b6d0191f7db7",
                    "folderId": null,
                    "organizationId": null,
                    "collectionIds": null,
                    "name": "Synthetic bank account",
                    "notes": null,
                    "type": 6,
                    "bankAccount": { "accountType": "checking", "routingNumber": "fixture" },
                    "favorite": false,
                    "reprompt": 0,
                    "revisionDate": "2026-08-11T03:04:05Z",
                    "creationDate": "2026-08-01T03:04:05Z",
                    "deletedDate": null
                },
                {
                    "id": "47d33df4-0cbb-4e9e-a8d4-fba6a559dd51",
                    "folderId": null,
                    "organizationId": null,
                    "collectionIds": null,
                    "name": "Synthetic license",
                    "notes": "opaque payload fixture",
                    "type": 7,
                    "driversLicense": { "licenseNumber": "fixture-license", "state": "ZZ" },
                    "favorite": true,
                    "reprompt": 1,
                    "revisionDate": "2026-08-11T03:04:05Z",
                    "creationDate": "2026-08-01T03:04:05Z",
                    "deletedDate": null
                },
                {
                    "id": "6a507cab-3630-410f-a0de-55c2849dfb7d",
                    "folderId": null,
                    "organizationId": null,
                    "collectionIds": null,
                    "name": "Synthetic passport",
                    "notes": null,
                    "type": 8,
                    "passport": { "number": "fixture-passport", "country": "ZZ" },
                    "favorite": false,
                    "reprompt": 0,
                    "revisionDate": "2026-08-11T03:04:05Z",
                    "creationDate": "2026-08-01T03:04:05Z",
                    "deletedDate": "2026-08-12T03:04:05Z"
                },
                {
                    "id": "ee9298aa-fad6-433c-a6b3-0e57b8181c80",
                    "folderId": null,
                    "organizationId": null,
                    "collectionIds": null,
                    "name": "Future synthetic type",
                    "notes": null,
                    "type": 42,
                    "futurePayload": { "nested": [1, "two", true] },
                    "favorite": false,
                    "reprompt": 0,
                    "revisionDate": "2026-08-11T03:04:05Z",
                    "creationDate": "2026-08-01T03:04:05Z",
                    "deletedDate": null
                }
            ]
        });
        let first = import_json(&serde_json::to_vec(&input).unwrap()).unwrap();
        let exported = export_json(&first).unwrap();
        let output: Value = serde_json::from_slice(&exported).unwrap();
        assert_eq!(
            output["items"][0]["bankAccount"],
            input["items"][0]["bankAccount"]
        );
        assert_eq!(
            output["items"][1]["driversLicense"],
            input["items"][1]["driversLicense"]
        );
        assert_eq!(
            output["items"][2]["passport"],
            input["items"][2]["passport"]
        );
        assert_eq!(
            output["items"][3]["futurePayload"],
            input["items"][3]["futurePayload"]
        );
        assert_eq!(first.items, import_json(&exported).unwrap().items);
    }
}
