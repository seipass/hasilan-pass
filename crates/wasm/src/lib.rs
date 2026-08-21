//! Shared WebAssembly trust boundary for browser-based Hasilan Pass clients.
//!
//! A [`VaultRuntime`] owns password-derived and vault keys inside WebAssembly
//! memory. TypeScript is responsible for UI, transport, and durable ciphertext;
//! it never implements cryptography or serializes domain objects itself.
#![allow(
    clippy::missing_errors_doc,
    reason = "wasm-bindgen converts every exported Result failure to the JavaScript exception boundary"
)]

use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use hasilan_bitwarden_compat::{
    BitwardenCollection, BitwardenFolder, ImportedVault, export_json, import_json,
};
use hasilan_crypto::{
    AttachmentMetadata, CompositeKey, EncryptedEnvelope, KdfConfig, LoginPreparation,
    SharingPrivateKey, decrypt_attachment_chunk, decrypt_json, encrypt_attachment_chunk,
    encrypt_json, generate_sharing_key, open_organization_key, prepare_login, prepare_registration,
    seal_organization_key, unwrap_sharing_private_key,
};
use hasilan_protocol::{
    AttachmentInitiateRequest, ChangeOperation, DeleteObjectRequest, EncryptedObject, KdfSettings,
    KdfType, ObjectKind, OwnerType, PutObjectRequest, SyncResponse,
};
use hasilan_vault::{
    Card, Identity, ItemData, Login, LoginUri, PasskeyAssertionOptions, PasskeyCandidate,
    PasskeyCreationOptions, PasskeyError, PassphraseOptions, PasswordHistory, PasswordOptions,
    SecretString, SecureNote, SshKey, TotpConfig, UriMatchType, UsernameOptions, VaultItem,
    assert_passkey, create_passkey, generate_passphrase, generate_password, generate_username,
    passkey_credential_id, passkey_matches_request, search, uri_matches,
    validate_passkey_assertion, validate_passkey_creation,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use uuid::Uuid;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

const MAX_RUNTIME_ITEMS: usize = 40_000;
const MAX_ATTACHMENTS_PER_ITEM: usize = 100;
const MAX_COLLECTIONS_PER_ITEM: usize = 100;
const MAX_COMMON_TEXT_BYTES: usize = 64 * 1024;
const MAX_PRIVATE_KEY_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy)]
enum AttachmentChunkAction {
    Encrypt,
    Decrypt,
}

/// Errors crossing the Rust/WASM trust boundary.
#[derive(Debug, Error)]
enum RuntimeError {
    #[error("vault is locked")]
    Locked,
    #[error("login preparation is missing or expired")]
    MissingPreparation,
    #[error("invalid request data")]
    InvalidInput,
    #[error("vault item not found")]
    NotFound,
    #[error("the requested credential does not match this page")]
    OriginMismatch,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("vault data could not be decoded")]
    Decode,
    #[error("vault capacity limit exceeded")]
    Capacity,
    #[error("the organization key is not available in this unlocked vault")]
    MissingOrganizationKey,
    #[error(transparent)]
    Passkey(#[from] PasskeyError),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationMaterial {
    auth_proof: String,
    protected_user_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ItemSummary {
    id: Uuid,
    name: String,
    item_type: u8,
    username: Option<String>,
    primary_uri: Option<String>,
    favorite: bool,
    deleted_date: Option<DateTime<Utc>>,
    has_totp: bool,
    passkey_count: usize,
    object_revision: Option<i64>,
    organization_id: Option<Uuid>,
    collection_ids: Vec<Uuid>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialSummary {
    id: Uuid,
    name: String,
    username: Option<String>,
    has_password: bool,
    has_totp: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FillCredential {
    id: Uuid,
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginDraft {
    name: String,
    username: Option<String>,
    password: Option<String>,
    uri: Option<String>,
    totp: Option<String>,
    notes: Option<String>,
    #[serde(default)]
    favorite: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ItemDraft {
    name: String,
    notes: Option<String>,
    #[serde(default)]
    favorite: bool,
    data: EditableItemData,
}

#[derive(Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
enum EditableItemData {
    SecureNote(SecureNoteDraft),
    Card(CardDraft),
    Identity(Box<IdentityDraft>),
    SshKey(SshKeyDraft),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecureNoteDraft {}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CardDraft {
    cardholder_name: Option<String>,
    exp_month: Option<String>,
    exp_year: Option<String>,
    code: Option<String>,
    brand: Option<String>,
    number: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IdentityDraft {
    title: Option<String>,
    first_name: Option<String>,
    middle_name: Option<String>,
    last_name: Option<String>,
    address1: Option<String>,
    address2: Option<String>,
    address3: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    company: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    ssn: Option<String>,
    username: Option<String>,
    passport_number: Option<String>,
    license_number: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SshKeyDraft {
    private_key: String,
    public_key: String,
    key_fingerprint: String,
}

#[allow(
    clippy::struct_field_names,
    reason = "the count suffix makes the JavaScript import summary self-describing"
)]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportResult {
    item_count: usize,
    folder_count: usize,
    collection_count: usize,
    item_ids: Vec<Uuid>,
    folder_ids: Vec<Uuid>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyTarget {
    item_id: Uuid,
    name: String,
    username: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserPasskeyCreationResult {
    item_id: Uuid,
    credential_id: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    attestation_object: String,
    authenticator_data: String,
    public_key: String,
    public_key_algorithm: i32,
    transports: Vec<String>,
    extensions: BrowserPasskeyCreationExtensions,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserPasskeyCreationExtensions {
    cred_props: BrowserCredentialProperties,
}

#[derive(Serialize)]
struct BrowserCredentialProperties {
    rk: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserPasskeyAssertionResult {
    item_id: Uuid,
    credential_id: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    authenticator_data: String,
    signature: String,
    user_handle: Option<String>,
    counter_changed: bool,
}

/// In-memory unlocked vault shared by the Web Vault and browser extension.
///
/// This type is intentionally not serializable. Durable storage contains only
/// [`EncryptedObject`] values and opaque sync metadata.
#[derive(Default)]
#[wasm_bindgen]
pub struct VaultRuntime {
    pending_login: Option<LoginPreparation>,
    user_key: Option<CompositeKey>,
    sharing_private_key: Option<SharingPrivateKey>,
    organization_keys: BTreeMap<Uuid, CompositeKey>,
    items: BTreeMap<Uuid, VaultItem>,
    objects: BTreeMap<Uuid, EncryptedObject>,
    folders: Vec<BitwardenFolder>,
    collections: Vec<BitwardenCollection>,
}

#[wasm_bindgen]
impl VaultRuntime {
    /// Creates a locked, empty runtime.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Derives account material, generates a random user key, and unlocks a new vault.
    ///
    /// The returned JSON contains only the authentication proof and the user key
    /// encrypted under the password-derived key.
    #[wasm_bindgen(js_name = prepareRegistration)]
    pub fn prepare_registration(
        &mut self,
        email: &str,
        mut master_password: String,
        kdf_json: &str,
    ) -> Result<String, JsValue> {
        let result = self.prepare_registration_inner(email, &master_password, kdf_json);
        master_password.zeroize();
        result.map_err(js_error)
    }

    /// Derives an authentication proof and retains only the stretched unlock key.
    #[wasm_bindgen(js_name = prepareLogin)]
    pub fn prepare_login(
        &mut self,
        email: &str,
        mut master_password: String,
        kdf_json: &str,
    ) -> Result<String, JsValue> {
        let result = self.prepare_login_inner(email, &master_password, kdf_json);
        master_password.zeroize();
        result.map_err(js_error)
    }

    /// Unwraps the user key returned by a successful login response.
    #[wasm_bindgen(js_name = finishLogin)]
    pub fn finish_login(&mut self, protected_user_key: &str) -> Result<(), JsValue> {
        self.finish_login_inner(protected_user_key)
            .map_err(js_error)
    }

    /// Installs a 64-byte user key that was decrypted by a device-bound
    /// storage layer. The caller must clear the input buffer immediately after
    /// this call; the runtime owns the zeroizing key in WebAssembly memory.
    #[wasm_bindgen(js_name = unlockWithUserKey)]
    pub fn unlock_with_user_key(&mut self, key: &[u8]) -> Result<(), JsValue> {
        self.lock();
        self.user_key =
            Some(CompositeKey::from_slice(key).map_err(|_| js_error(RuntimeError::InvalidInput))?);
        Ok(())
    }

    /// Returns a transient copy for an explicitly opted-in device wrapping
    /// operation. Clients must encrypt it immediately and zero the returned
    /// buffer; it is never persisted by the runtime.
    #[wasm_bindgen(js_name = exportUserKey)]
    pub fn export_user_key(&self) -> Result<Vec<u8>, JsValue> {
        Ok(self
            .require_unlocked()
            .map_err(js_error)?
            .as_bytes()
            .to_vec())
    }

    /// Locally verifies a master password against the already-unlocked user key.
    ///
    /// The protected user key and password remain inside this call; no server request is made.
    #[wasm_bindgen(js_name = verifyMasterPassword)]
    #[must_use]
    pub fn verify_master_password(
        &self,
        email: &str,
        mut master_password: String,
        kdf_json: &str,
        protected_user_key: &str,
    ) -> bool {
        let verified = self.verify_master_password_inner(
            email,
            &master_password,
            kdf_json,
            protected_user_key,
        );
        master_password.zeroize();
        verified
    }

    /// Irreversibly clears all decrypted state and keys from this runtime.
    pub fn lock(&mut self) {
        self.pending_login = None;
        self.user_key = None;
        self.sharing_private_key = None;
        self.organization_keys.clear();
        self.items.clear();
        self.objects.clear();
        self.folders.clear();
        self.collections.clear();
    }

    /// Reports whether a user key is present in WebAssembly memory.
    #[wasm_bindgen(getter, js_name = isUnlocked)]
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.user_key.is_some()
    }

    /// Generates and retains a fresh account sharing key protected by the unlocked user key.
    #[wasm_bindgen(js_name = generateSharingKey)]
    pub fn generate_sharing_key(&mut self) -> Result<String, JsValue> {
        self.generate_sharing_key_inner().map_err(js_error)
    }

    /// Installs an existing user-key-protected account sharing private key.
    #[wasm_bindgen(js_name = installSharingKey)]
    pub fn install_sharing_key(
        &mut self,
        public_key: &str,
        protected_private_key: &str,
    ) -> Result<(), JsValue> {
        self.install_sharing_key_inner(public_key, protected_private_key)
            .map_err(js_error)
    }

    /// Generates a fresh organization key, retains it in memory, and seals it to the owner.
    #[wasm_bindgen(js_name = createOrganizationKey)]
    pub fn create_organization_key(
        &mut self,
        organization_id: &str,
        recipient_public_key: &str,
    ) -> Result<String, JsValue> {
        self.create_organization_key_inner(organization_id, recipient_public_key)
            .map_err(js_error)
    }

    /// Seals an already-open organization key to another account public key.
    #[wasm_bindgen(js_name = sealOrganizationKey)]
    pub fn seal_organization_key(
        &self,
        organization_id: &str,
        recipient_public_key: &str,
    ) -> Result<String, JsValue> {
        self.seal_organization_key_inner(organization_id, recipient_public_key)
            .map_err(js_error)
    }

    /// Opens and retains the current account's recipient-bound organization key wrapper.
    #[wasm_bindgen(js_name = openOrganizationKey)]
    pub fn open_organization_key(
        &mut self,
        organization_id: &str,
        encrypted_organization_key: &str,
    ) -> Result<(), JsValue> {
        self.open_organization_key_inner(organization_id, encrypted_organization_key)
            .map_err(js_error)
    }

    /// Reports whether this unlocked runtime can decrypt a given organization.
    #[wasm_bindgen(js_name = hasOrganizationKey)]
    #[must_use]
    pub fn has_organization_key(&self, organization_id: &str) -> bool {
        Uuid::parse_str(organization_id)
            .ok()
            .is_some_and(|id| self.organization_keys.contains_key(&id))
    }

    /// Clears all decrypted organization keys while retaining the account sharing private key.
    #[wasm_bindgen(js_name = clearOrganizationKeys)]
    pub fn clear_organization_keys(&mut self) {
        self.organization_keys.clear();
    }

    /// Purges decrypted objects and keys for organizations no longer active on this account.
    #[wasm_bindgen(js_name = retainOrganizationAccess)]
    pub fn retain_organization_access(
        &mut self,
        organization_ids_json: &str,
    ) -> Result<(), JsValue> {
        let ids: BTreeSet<Uuid> = parse_json::<Vec<Uuid>>(organization_ids_json)
            .map_err(js_error)?
            .into_iter()
            .collect();
        self.organization_keys.retain(|id, _| ids.contains(id));
        let removed: Vec<Uuid> = self
            .objects
            .iter()
            .filter_map(|(id, object)| {
                (object.owner_type == OwnerType::Organization && !ids.contains(&object.owner_id))
                    .then_some(*id)
            })
            .collect();
        for id in removed {
            self.objects.remove(&id);
            self.items.remove(&id);
        }
        Ok(())
    }

    /// Decrypts and atomically applies an ordered server sync page.
    #[wasm_bindgen(js_name = applySyncPage)]
    pub fn apply_sync_page(&mut self, page_json: &str) -> Result<(), JsValue> {
        self.apply_sync_page_inner(page_json).map_err(js_error)
    }

    /// Applies one authoritative server response after an upload.
    #[wasm_bindgen(js_name = acceptObject)]
    pub fn accept_object(&mut self, object_json: &str) -> Result<(), JsValue> {
        let object: EncryptedObject = parse_json(object_json).map_err(js_error)?;
        self.apply_object(object).map_err(js_error)
    }

    /// Returns secret-free summaries matching a local query and category.
    #[wasm_bindgen(js_name = listItems)]
    pub fn list_items(&self, query: &str, category: &str) -> Result<String, JsValue> {
        self.list_items_inner(query, category).map_err(js_error)
    }

    /// Returns one complete item for an explicit detail/editor view.
    #[wasm_bindgen(js_name = getItem)]
    pub fn get_item(&self, id: &str) -> Result<String, JsValue> {
        let id = parse_uuid(id).map_err(js_error)?;
        let item = self
            .items
            .get(&id)
            .ok_or(RuntimeError::NotFound)
            .map_err(js_error)?;
        encode_json(item).map_err(js_error)
    }

    /// Creates a login item from a compact editor draft and returns its ID.
    #[wasm_bindgen(js_name = createLogin)]
    pub fn create_login(&mut self, draft_json: &str) -> Result<String, JsValue> {
        self.create_login_inner(draft_json).map_err(js_error)
    }

    /// Updates the editable login fields while retaining compatible metadata and history.
    #[wasm_bindgen(js_name = updateLogin)]
    pub fn update_login(&mut self, id: &str, draft_json: &str) -> Result<(), JsValue> {
        self.update_login_inner(id, draft_json).map_err(js_error)
    }

    /// Creates a validated Secure Note, Card, Identity, or SSH Key and returns its ID.
    #[wasm_bindgen(js_name = createItem)]
    pub fn create_item(&mut self, draft_json: &str) -> Result<String, JsValue> {
        self.create_item_inner(draft_json).map_err(js_error)
    }

    /// Updates one editable non-Login item while preserving unknown compatible metadata.
    #[wasm_bindgen(js_name = updateItem)]
    pub fn update_item(&mut self, id: &str, draft_json: &str) -> Result<(), JsValue> {
        self.update_item_inner(id, draft_json).map_err(js_error)
    }

    /// Assigns immutable personal/organization ownership before the first upload.
    #[wasm_bindgen(js_name = assignItemDestination)]
    pub fn assign_item_destination(
        &mut self,
        item_id: &str,
        organization_id: Option<String>,
        collection_ids_json: &str,
    ) -> Result<(), JsValue> {
        self.assign_item_destination_inner(item_id, organization_id, collection_ids_json)
            .map_err(js_error)
    }

    /// Applies a user-confirmed captured credential after revalidating the saved URI policy.
    #[wasm_bindgen(js_name = updateCredentialFromPage)]
    pub fn update_credential_from_page(
        &mut self,
        id: &str,
        page_url: &str,
        username: Option<String>,
        mut password: String,
    ) -> Result<(), JsValue> {
        let result = self.update_credential_from_page_inner(id, page_url, username, &password);
        password.zeroize();
        result.map_err(js_error)
    }

    /// Replaces an item after validating its stable domain representation.
    #[wasm_bindgen(js_name = saveItem)]
    pub fn save_item(&mut self, item_json: &str) -> Result<(), JsValue> {
        self.require_unlocked().map_err(js_error)?;
        let item: VaultItem = parse_json(item_json).map_err(js_error)?;
        if item.name.trim().is_empty() || item.name.len() > 2_000 {
            return Err(js_error(RuntimeError::InvalidInput));
        }
        self.ensure_capacity(item.id).map_err(js_error)?;
        self.items.insert(item.id, item);
        Ok(())
    }

    /// Lists decrypted personal folder names while the vault is unlocked.
    #[wasm_bindgen(js_name = listFolders)]
    pub fn list_folders(&self) -> Result<String, JsValue> {
        self.require_unlocked().map_err(js_error)?;
        let mut folders = self.folders.clone();
        folders.sort_by(|left, right| {
            left.name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then(left.id.cmp(&right.id))
        });
        encode_json(&folders).map_err(js_error)
    }

    /// Creates a personal folder locally and returns its client-generated ID.
    #[wasm_bindgen(js_name = createFolder)]
    pub fn create_folder(&mut self, name: String) -> Result<String, JsValue> {
        self.require_unlocked().map_err(js_error)?;
        if self.folders.len() >= 2_000 {
            return Err(js_error(RuntimeError::Capacity));
        }
        let name = validate_folder_name(name).map_err(js_error)?;
        let id = Uuid::new_v4();
        self.folders.push(BitwardenFolder { id, name });
        Ok(id.to_string())
    }

    /// Renames a personal folder locally before an encrypted upload.
    #[wasm_bindgen(js_name = updateFolder)]
    pub fn update_folder(&mut self, id: &str, name: String) -> Result<(), JsValue> {
        self.require_unlocked().map_err(js_error)?;
        let id = parse_uuid(id).map_err(js_error)?;
        let name = validate_folder_name(name).map_err(js_error)?;
        let folder = self
            .folders
            .iter_mut()
            .find(|folder| folder.id == id)
            .ok_or(RuntimeError::NotFound)
            .map_err(js_error)?;
        folder.name = name;
        Ok(())
    }

    /// Assigns a personal item to a known folder, or clears its folder.
    #[wasm_bindgen(js_name = assignItemFolder)]
    pub fn assign_item_folder(
        &mut self,
        item_id: &str,
        folder_id: Option<String>,
    ) -> Result<(), JsValue> {
        self.require_unlocked().map_err(js_error)?;
        let item_id = parse_uuid(item_id).map_err(js_error)?;
        let folder_id = folder_id
            .map(|value| parse_uuid(&value))
            .transpose()
            .map_err(js_error)?;
        if folder_id.is_some_and(|id| !self.folders.iter().any(|folder| folder.id == id)) {
            return Err(js_error(RuntimeError::NotFound));
        }
        let item = self
            .items
            .get_mut(&item_id)
            .ok_or(RuntimeError::NotFound)
            .map_err(js_error)?;
        if item.organization_id.is_some() && folder_id.is_some() {
            return Err(js_error(RuntimeError::InvalidInput));
        }
        item.folder_id = folder_id;
        item.revision_date = Utc::now();
        Ok(())
    }

    /// Clears a folder from local items and returns IDs that must be uploaded first.
    #[wasm_bindgen(js_name = detachFolder)]
    pub fn detach_folder(&mut self, folder_id: &str) -> Result<String, JsValue> {
        self.require_unlocked().map_err(js_error)?;
        let folder_id = parse_uuid(folder_id).map_err(js_error)?;
        if !self.folders.iter().any(|folder| folder.id == folder_id) {
            return Err(js_error(RuntimeError::NotFound));
        }
        let mut changed = Vec::new();
        for item in self.items.values_mut() {
            if item.folder_id == Some(folder_id) {
                item.folder_id = None;
                item.revision_date = Utc::now();
                changed.push(item.id);
            }
        }
        encode_json(&changed).map_err(js_error)
    }

    /// Builds an encrypted personal Folder create/update request.
    #[wasm_bindgen(js_name = buildFolderPutRequest)]
    pub fn build_folder_put_request(&self, id: &str, account_id: &str) -> Result<String, JsValue> {
        self.build_folder_put_request_inner(id, account_id)
            .map_err(js_error)
    }

    /// Restores one folder from authoritative ciphertext, or removes an unsynced create.
    #[wasm_bindgen(js_name = discardFolderChanges)]
    pub fn discard_folder_changes(&mut self, id: &str) -> Result<(), JsValue> {
        self.require_unlocked().map_err(js_error)?;
        let id = parse_uuid(id).map_err(js_error)?;
        if let Some(object) = self.objects.get(&id) {
            if object.kind != ObjectKind::Folder || object.deleted_at.is_some() {
                return Err(js_error(RuntimeError::NotFound));
            }
            let folder = self.decrypt_folder_object(object).map_err(js_error)?;
            merge_by_id(&mut self.folders, vec![folder], |value| value.id);
        } else {
            self.folders.retain(|folder| folder.id != id);
        }
        Ok(())
    }

    /// Generates private attachment metadata and adds it to an already-synchronized item.
    #[wasm_bindgen(js_name = createAttachment)]
    pub fn create_attachment(
        &mut self,
        item_id: &str,
        file_name: String,
        media_type: String,
        size: u64,
        chunk_size: u32,
    ) -> Result<String, JsValue> {
        self.create_attachment_inner(item_id, file_name, media_type, size, chunk_size)
            .map_err(js_error)
    }

    /// Builds the public resumable-upload dimensions after the parent metadata is synchronized.
    #[wasm_bindgen(js_name = attachmentInitiateRequest)]
    pub fn attachment_initiate_request(
        &self,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<String, JsValue> {
        self.attachment_initiate_request_inner(item_id, attachment_id)
            .map_err(js_error)
    }

    /// Encrypts one exact file slice as an independently authenticated frame.
    #[wasm_bindgen(js_name = encryptAttachmentChunk)]
    pub fn encrypt_attachment_chunk(
        &self,
        item_id: &str,
        attachment_id: &str,
        index: u32,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        self.attachment_chunk_inner(
            item_id,
            attachment_id,
            index,
            plaintext,
            AttachmentChunkAction::Encrypt,
        )
        .map_err(js_error)
    }

    /// Authenticates and decrypts one downloaded attachment frame.
    #[wasm_bindgen(js_name = decryptAttachmentChunk)]
    pub fn decrypt_attachment_chunk(
        &self,
        item_id: &str,
        attachment_id: &str,
        index: u32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        self.attachment_chunk_inner(
            item_id,
            attachment_id,
            index,
            ciphertext,
            AttachmentChunkAction::Decrypt,
        )
        .map_err(js_error)
    }

    /// Removes private attachment metadata before synchronizing the parent item.
    #[wasm_bindgen(js_name = removeAttachment)]
    pub fn remove_attachment(&mut self, item_id: &str, attachment_id: &str) -> Result<(), JsValue> {
        self.remove_attachment_inner(item_id, attachment_id)
            .map_err(js_error)
    }

    /// Builds an idempotent encrypted create/update body for `/vault/objects/{id}`.
    #[wasm_bindgen(js_name = buildPutRequest)]
    pub fn build_put_request(&self, id: &str, account_id: &str) -> Result<String, JsValue> {
        self.build_put_request_inner(id, account_id)
            .map_err(js_error)
    }

    /// Builds an idempotent optimistic tombstone request.
    #[wasm_bindgen(js_name = buildDeleteRequest)]
    pub fn build_delete_request(&self, id: &str) -> Result<String, JsValue> {
        let id = parse_uuid(id).map_err(js_error)?;
        let revision = self
            .objects
            .get(&id)
            .map(|object| object.object_revision)
            .ok_or(RuntimeError::NotFound)
            .map_err(js_error)?;
        encode_json(&DeleteObjectRequest {
            base_revision: revision,
            idempotency_key: Uuid::new_v4(),
        })
        .map_err(js_error)
    }

    /// Lists only credentials whose Rust URI policy matches the supplied page URL.
    #[wasm_bindgen(js_name = credentialsForUrl)]
    pub fn credentials_for_url(&self, page_url: &str) -> Result<String, JsValue> {
        self.credentials_for_url_inner(page_url).map_err(js_error)
    }

    /// Returns exactly one credential after revalidating the target page origin.
    #[wasm_bindgen(js_name = credentialForFill)]
    pub fn credential_for_fill(
        &self,
        id: &str,
        page_url: &str,
        unix_seconds: u64,
    ) -> Result<String, JsValue> {
        self.credential_for_fill_inner(id, page_url, unix_seconds)
            .map_err(js_error)
    }

    /// Returns login targets eligible to receive a new RP-scoped passkey.
    #[wasm_bindgen(js_name = passkeyCreationTargets)]
    pub fn passkey_creation_targets(&self, options_json: &str) -> Result<String, JsValue> {
        self.passkey_creation_targets_inner(options_json)
            .map_err(js_error)
    }

    /// Generates and inserts an ES256 passkey after extension-owned user verification.
    #[wasm_bindgen(js_name = createVaultPasskey)]
    pub fn create_vault_passkey(
        &mut self,
        options_json: &str,
        target_item_id: Option<String>,
        user_verified: bool,
    ) -> Result<String, JsValue> {
        self.create_vault_passkey_inner(options_json, target_item_id, user_verified)
            .map_err(js_error)
    }

    /// Lists only passkeys eligible for the active RP and allow-credentials list.
    #[wasm_bindgen(js_name = passkeyAssertionCandidates)]
    pub fn passkey_assertion_candidates(&self, options_json: &str) -> Result<String, JsValue> {
        self.passkey_assertion_candidates_inner(options_json)
            .map_err(js_error)
    }

    /// Signs a `WebAuthn` assertion with one explicitly selected encrypted passkey.
    #[wasm_bindgen(js_name = assertVaultPasskey)]
    pub fn assert_vault_passkey(
        &mut self,
        options_json: &str,
        item_id: &str,
        credential_id: &str,
        user_verified: bool,
    ) -> Result<String, JsValue> {
        self.assert_vault_passkey_inner(options_json, item_id, credential_id, user_verified)
            .map_err(js_error)
    }

    /// Restores the last authoritative ciphertext after a failed optimistic passkey upload.
    #[wasm_bindgen(js_name = discardItemChanges)]
    pub fn discard_item_changes(&mut self, id: &str) -> Result<(), JsValue> {
        self.discard_item_changes_inner(id).map_err(js_error)
    }

    /// Generates an RFC 6238 code for a login item.
    #[wasm_bindgen(js_name = totpForItem)]
    pub fn totp_for_item(&self, id: &str, unix_seconds: u64) -> Result<String, JsValue> {
        let id = parse_uuid(id).map_err(js_error)?;
        let item = self
            .items
            .get(&id)
            .ok_or(RuntimeError::NotFound)
            .map_err(js_error)?;
        let ItemData::Login(login) = &item.data else {
            return Err(js_error(RuntimeError::InvalidInput));
        };
        let secret = login
            .totp
            .as_ref()
            .ok_or(RuntimeError::NotFound)
            .map_err(js_error)?;
        let code = TotpConfig::parse(secret.expose())
            .and_then(|config| config.generate_at(unix_seconds))
            .map_err(|_| js_error(RuntimeError::InvalidInput))?;
        encode_json(&code).map_err(js_error)
    }

    /// Generates a CSPRNG password from JSON [`PasswordOptions`].
    #[wasm_bindgen(js_name = generatePassword)]
    pub fn generate_password(&self, options_json: &str) -> Result<String, JsValue> {
        let options: PasswordOptions = parse_json(options_json).map_err(js_error)?;
        generate_password(&options).map_err(|_| js_error(RuntimeError::InvalidInput))
    }

    /// Generates a CSPRNG passphrase from JSON [`PassphraseOptions`].
    #[wasm_bindgen(js_name = generatePassphrase)]
    pub fn generate_passphrase(&self, options_json: &str) -> Result<String, JsValue> {
        let options: PassphraseOptions = parse_json(options_json).map_err(js_error)?;
        generate_passphrase(&options).map_err(|_| js_error(RuntimeError::InvalidInput))
    }

    /// Generates an identifier-safe CSPRNG username from JSON [`UsernameOptions`].
    #[wasm_bindgen(js_name = generateUsername)]
    pub fn generate_username(&self, options_json: &str) -> Result<String, JsValue> {
        let options: UsernameOptions = parse_json(options_json).map_err(js_error)?;
        generate_username(&options).map_err(|_| js_error(RuntimeError::InvalidInput))
    }

    /// Imports a plaintext Bitwarden JSON export into the unlocked runtime.
    #[wasm_bindgen(js_name = importBitwardenJson)]
    pub fn import_bitwarden_json(&mut self, input: &str) -> Result<String, JsValue> {
        self.import_bitwarden_inner(input).map_err(js_error)
    }

    /// Exports the current vault as plaintext Bitwarden JSON.
    ///
    /// Callers must show an explicit plaintext warning before invoking this method.
    #[wasm_bindgen(js_name = exportBitwardenJson)]
    pub fn export_bitwarden_json(&self) -> Result<String, JsValue> {
        self.require_unlocked().map_err(js_error)?;
        let bytes = export_json(&ImportedVault {
            folders: self.folders.clone(),
            collections: self.collections.clone(),
            items: self.items.values().cloned().collect(),
        })
        .map_err(|_| js_error(RuntimeError::Decode))?;
        String::from_utf8(bytes).map_err(|_| js_error(RuntimeError::Decode))
    }
}

impl VaultRuntime {
    fn prepare_registration_inner(
        &mut self,
        email: &str,
        master_password: &str,
        kdf_json: &str,
    ) -> Result<String, RuntimeError> {
        self.lock();
        let kdf = parse_kdf(kdf_json)?;
        let prepared = prepare_registration(email, master_password.as_bytes(), &kdf)
            .map_err(|_| RuntimeError::Crypto)?;
        let auth_proof = STANDARD.encode(prepared.authentication_proof);
        self.user_key = Some(prepared.user_key);
        encode_json(&RegistrationMaterial {
            auth_proof,
            protected_user_key: prepared.protected_user_key,
        })
    }

    fn prepare_login_inner(
        &mut self,
        email: &str,
        master_password: &str,
        kdf_json: &str,
    ) -> Result<String, RuntimeError> {
        self.lock();
        let kdf = parse_kdf(kdf_json)?;
        let prepared = prepare_login(email, master_password.as_bytes(), &kdf)
            .map_err(|_| RuntimeError::Crypto)?;
        let proof = STANDARD.encode(prepared.authentication_proof);
        self.pending_login = Some(prepared);
        Ok(proof)
    }

    fn finish_login_inner(&mut self, protected_user_key: &str) -> Result<(), RuntimeError> {
        let pending = self
            .pending_login
            .take()
            .ok_or(RuntimeError::MissingPreparation)?;
        self.user_key = Some(
            pending
                .finish(protected_user_key)
                .map_err(|_| RuntimeError::Crypto)?,
        );
        Ok(())
    }

    fn verify_master_password_inner(
        &self,
        email: &str,
        master_password: &str,
        kdf_json: &str,
        protected_user_key: &str,
    ) -> bool {
        let Some(current) = self.user_key.as_ref() else {
            return false;
        };
        let Ok(kdf) = parse_kdf(kdf_json) else {
            return false;
        };
        let Ok(prepared) = prepare_login(email, master_password.as_bytes(), &kdf) else {
            return false;
        };
        let Ok(candidate) = prepared.finish(protected_user_key) else {
            return false;
        };
        bool::from(candidate.as_bytes().ct_eq(current.as_bytes()))
    }

    fn generate_sharing_key_inner(&mut self) -> Result<String, RuntimeError> {
        let user_key = self.require_unlocked()?;
        let material = generate_sharing_key(user_key).map_err(|_| RuntimeError::Crypto)?;
        let private = unwrap_sharing_private_key(
            &material.public_key,
            &material.protected_private_key,
            user_key,
        )
        .map_err(|_| RuntimeError::Crypto)?;
        self.sharing_private_key = Some(private);
        encode_json(&material)
    }

    fn install_sharing_key_inner(
        &mut self,
        public_key: &str,
        protected_private_key: &str,
    ) -> Result<(), RuntimeError> {
        let user_key = self.require_unlocked()?;
        let private = unwrap_sharing_private_key(public_key, protected_private_key, user_key)
            .map_err(|_| RuntimeError::Crypto)?;
        self.sharing_private_key = Some(private);
        Ok(())
    }

    fn create_organization_key_inner(
        &mut self,
        organization_id: &str,
        recipient_public_key: &str,
    ) -> Result<String, RuntimeError> {
        self.require_unlocked()?;
        let organization_id = parse_uuid(organization_id)?;
        if self.organization_keys.contains_key(&organization_id) {
            return Err(RuntimeError::InvalidInput);
        }
        let key = CompositeKey::generate().map_err(|_| RuntimeError::Crypto)?;
        let wrapper = seal_organization_key(organization_id, recipient_public_key, &key)
            .map_err(|_| RuntimeError::Crypto)?;
        self.organization_keys.insert(organization_id, key);
        Ok(wrapper)
    }

    fn seal_organization_key_inner(
        &self,
        organization_id: &str,
        recipient_public_key: &str,
    ) -> Result<String, RuntimeError> {
        self.require_unlocked()?;
        let organization_id = parse_uuid(organization_id)?;
        let key = self
            .organization_keys
            .get(&organization_id)
            .ok_or(RuntimeError::MissingOrganizationKey)?;
        seal_organization_key(organization_id, recipient_public_key, key)
            .map_err(|_| RuntimeError::Crypto)
    }

    fn open_organization_key_inner(
        &mut self,
        organization_id: &str,
        encrypted_organization_key: &str,
    ) -> Result<(), RuntimeError> {
        self.require_unlocked()?;
        let organization_id = parse_uuid(organization_id)?;
        let private = self
            .sharing_private_key
            .as_ref()
            .ok_or(RuntimeError::MissingOrganizationKey)?;
        let key = open_organization_key(private, organization_id, encrypted_organization_key)
            .map_err(|_| RuntimeError::Crypto)?;
        self.organization_keys.insert(organization_id, key);
        Ok(())
    }

    fn apply_sync_page_inner(&mut self, page_json: &str) -> Result<(), RuntimeError> {
        self.require_unlocked()?;
        let page: SyncResponse = parse_json(page_json)?;
        let mut next_items = self.items.clone();
        let mut next_folders = self.folders.clone();
        let mut next_objects = self.objects.clone();
        for change in page.changes {
            match (change.operation, change.object) {
                (ChangeOperation::Upsert | ChangeOperation::Delete, Some(object))
                    if object.id == change.object_id
                        && object.account_revision == change.revision =>
                {
                    match object.kind {
                        ObjectKind::Cipher => {
                            let mut item = self.decrypt_item_object(&object)?;
                            item.deleted_date = object.deleted_at;
                            next_items.insert(object.id, item);
                        }
                        ObjectKind::Folder => {
                            if object.deleted_at.is_some() {
                                remove_folder_projection(
                                    &mut next_folders,
                                    &mut next_items,
                                    object.id,
                                );
                            } else {
                                let folder = self.decrypt_folder_object(&object)?;
                                merge_by_id(&mut next_folders, vec![folder], |value| value.id);
                            }
                        }
                        ObjectKind::OrganizationKey => return Err(RuntimeError::Decode),
                    }
                    next_objects.insert(object.id, object);
                }
                (ChangeOperation::Delete, None) => {
                    next_items.remove(&change.object_id);
                    remove_folder_projection(&mut next_folders, &mut next_items, change.object_id);
                    next_objects.remove(&change.object_id);
                }
                _ => return Err(RuntimeError::Decode),
            }
        }
        if next_items.len() > MAX_RUNTIME_ITEMS {
            return Err(RuntimeError::Capacity);
        }
        self.items = next_items;
        self.folders = next_folders;
        self.objects = next_objects;
        Ok(())
    }

    fn apply_object(&mut self, object: EncryptedObject) -> Result<(), RuntimeError> {
        self.require_unlocked()?;
        match object.kind {
            ObjectKind::Cipher => {
                let mut item = self.decrypt_item_object(&object)?;
                item.deleted_date = object.deleted_at;
                self.ensure_capacity(item.id)?;
                self.items.insert(item.id, item);
            }
            ObjectKind::Folder => {
                if object.deleted_at.is_some() {
                    remove_folder_projection(&mut self.folders, &mut self.items, object.id);
                } else {
                    let folder = self.decrypt_folder_object(&object)?;
                    merge_by_id(&mut self.folders, vec![folder], |value| value.id);
                }
            }
            ObjectKind::OrganizationKey => return Err(RuntimeError::Decode),
        }
        self.objects.insert(object.id, object);
        Ok(())
    }

    fn decrypt_item_object(&self, object: &EncryptedObject) -> Result<VaultItem, RuntimeError> {
        let key = match object.owner_type {
            OwnerType::User => self.require_unlocked()?,
            OwnerType::Organization => self
                .organization_keys
                .get(&object.owner_id)
                .ok_or(RuntimeError::MissingOrganizationKey)?,
        };
        let item: VaultItem = decrypt_json(
            &EncryptedEnvelope {
                format: object.format.clone(),
                wrapped_key: object.wrapped_key.clone(),
                payload: object.payload.clone(),
            },
            key,
        )
        .map_err(|_| RuntimeError::Crypto)?;
        let metadata_matches = item.id == object.id
            && item.collection_ids == object.collection_ids
            && match object.owner_type {
                OwnerType::User => item.organization_id.is_none() && item.collection_ids.is_empty(),
                OwnerType::Organization => item.organization_id == Some(object.owner_id),
            };
        if object.kind != ObjectKind::Cipher || !metadata_matches {
            return Err(RuntimeError::Decode);
        }
        Ok(item)
    }

    fn decrypt_folder_object(
        &self,
        object: &EncryptedObject,
    ) -> Result<BitwardenFolder, RuntimeError> {
        if object.kind != ObjectKind::Folder
            || object.owner_type != OwnerType::User
            || !object.collection_ids.is_empty()
        {
            return Err(RuntimeError::Decode);
        }
        let folder: BitwardenFolder = decrypt_json(
            &EncryptedEnvelope {
                format: object.format.clone(),
                wrapped_key: object.wrapped_key.clone(),
                payload: object.payload.clone(),
            },
            self.require_unlocked()?,
        )
        .map_err(|_| RuntimeError::Crypto)?;
        if folder.id != object.id || validate_folder_name(folder.name.clone()).is_err() {
            return Err(RuntimeError::Decode);
        }
        Ok(folder)
    }

    fn list_items_inner(&self, query: &str, category: &str) -> Result<String, RuntimeError> {
        self.require_unlocked()?;
        let ordered_ids: Vec<Uuid> = if query.trim().is_empty() {
            let mut ids: Vec<Uuid> = self.items.keys().copied().collect();
            ids.sort_by(|left, right| {
                self.items[left]
                    .name
                    .to_lowercase()
                    .cmp(&self.items[right].name.to_lowercase())
                    .then(left.cmp(right))
            });
            ids
        } else {
            search(&self.items.values().cloned().collect::<Vec<_>>(), query)
                .into_iter()
                .map(|hit| hit.id)
                .collect()
        };
        let summaries: Vec<ItemSummary> = ordered_ids
            .into_iter()
            .filter_map(|id| self.items.get(&id))
            .filter(|item| category_matches(item, category))
            .map(|item| summary(item, self.objects.get(&item.id)))
            .collect();
        encode_json(&summaries)
    }

    fn create_login_inner(&mut self, draft_json: &str) -> Result<String, RuntimeError> {
        self.require_unlocked()?;
        let mut draft: LoginDraft = parse_json(draft_json)?;
        validate_login_draft(&mut draft)?;
        let mut item = VaultItem::new_login(
            draft.name,
            Login {
                username: nonempty(draft.username),
                password: nonempty(draft.password).map(SecretString::new),
                uris: nonempty(draft.uri)
                    .map(|uri| LoginUri {
                        uri,
                        r#match: Some(UriMatchType::Domain),
                        extra: serde_json::Map::new(),
                    })
                    .into_iter()
                    .collect(),
                totp: nonempty(draft.totp).map(SecretString::new),
                ..Login::default()
            },
        );
        item.notes = nonempty(draft.notes);
        item.favorite = draft.favorite;
        let id = item.id;
        self.ensure_capacity(id)?;
        self.items.insert(id, item);
        Ok(id.to_string())
    }

    fn update_login_inner(&mut self, id: &str, draft_json: &str) -> Result<(), RuntimeError> {
        self.require_unlocked()?;
        let id = parse_uuid(id)?;
        let mut draft: LoginDraft = parse_json(draft_json)?;
        validate_login_draft(&mut draft)?;
        let item = self.items.get_mut(&id).ok_or(RuntimeError::NotFound)?;
        let ItemData::Login(login) = &mut item.data else {
            return Err(RuntimeError::InvalidInput);
        };

        let next_password = nonempty(draft.password).map(SecretString::new);
        if login.password != next_password {
            if let Some(previous) = login.password.take() {
                item.password_history.push(PasswordHistory {
                    password: previous,
                    last_used_date: Utc::now(),
                });
                if item.password_history.len() > 20 {
                    item.password_history.remove(0);
                }
            }
            login.password = next_password;
            login.password_revision_date = Some(Utc::now());
        }
        login.username = nonempty(draft.username);
        login.totp = nonempty(draft.totp).map(SecretString::new);
        match nonempty(draft.uri) {
            Some(uri) => {
                if let Some(existing) = login.uris.first_mut() {
                    existing.uri = uri;
                } else {
                    login.uris.push(LoginUri {
                        uri,
                        r#match: Some(UriMatchType::Domain),
                        extra: serde_json::Map::new(),
                    });
                }
            }
            None => login.uris.clear(),
        }
        item.name = draft.name;
        item.notes = nonempty(draft.notes);
        item.favorite = draft.favorite;
        item.revision_date = Utc::now();
        Ok(())
    }

    fn create_item_inner(&mut self, draft_json: &str) -> Result<String, RuntimeError> {
        self.require_unlocked()?;
        let draft: ItemDraft = parse_json(draft_json)?;
        let (name, notes, favorite) =
            validate_item_common(&draft.name, draft.notes, draft.favorite)?;
        let data = build_editable_item_data(draft.data, None)?;
        let mut item = VaultItem::new(name, data);
        item.notes = notes;
        item.favorite = favorite;
        let id = item.id;
        self.ensure_capacity(id)?;
        self.items.insert(id, item);
        Ok(id.to_string())
    }

    fn update_item_inner(&mut self, id: &str, draft_json: &str) -> Result<(), RuntimeError> {
        self.require_unlocked()?;
        let id = parse_uuid(id)?;
        let draft: ItemDraft = parse_json(draft_json)?;
        let (name, notes, favorite) =
            validate_item_common(&draft.name, draft.notes, draft.favorite)?;
        let current = self.items.get(&id).ok_or(RuntimeError::NotFound)?;
        if current.deleted_date.is_some() {
            return Err(RuntimeError::NotFound);
        }
        let data = build_editable_item_data(draft.data, Some(&current.data))?;
        let item = self.items.get_mut(&id).ok_or(RuntimeError::NotFound)?;
        item.name = name;
        item.notes = notes;
        item.favorite = favorite;
        item.data = data;
        item.revision_date = Utc::now();
        Ok(())
    }

    fn assign_item_destination_inner(
        &mut self,
        item_id: &str,
        organization_id: Option<String>,
        collection_ids_json: &str,
    ) -> Result<(), RuntimeError> {
        self.require_unlocked()?;
        let item_id = parse_uuid(item_id)?;
        let organization_id = organization_id
            .map(|value| parse_uuid(&value))
            .transpose()?;
        let collection_ids: Vec<Uuid> = parse_json(collection_ids_json)?;
        let unique: BTreeSet<Uuid> = collection_ids.iter().copied().collect();
        if collection_ids.len() > MAX_COLLECTIONS_PER_ITEM
            || unique.len() != collection_ids.len()
            || collection_ids.iter().any(Uuid::is_nil)
            || (organization_id.is_none() && !collection_ids.is_empty())
            || organization_id
                .is_some_and(|id| id.is_nil() || !self.organization_keys.contains_key(&id))
        {
            return Err(RuntimeError::InvalidInput);
        }
        if let Some(object) = self.objects.get(&item_id) {
            let expected_owner = organization_id.unwrap_or(object.owner_id);
            let expected_type = if organization_id.is_some() {
                OwnerType::Organization
            } else {
                OwnerType::User
            };
            if object.owner_type != expected_type || object.owner_id != expected_owner {
                return Err(RuntimeError::InvalidInput);
            }
        }
        let item = self.items.get_mut(&item_id).ok_or(RuntimeError::NotFound)?;
        item.organization_id = organization_id;
        item.collection_ids = collection_ids;
        if organization_id.is_some() {
            item.folder_id = None;
        }
        item.revision_date = Utc::now();
        Ok(())
    }

    fn create_attachment_inner(
        &mut self,
        item_id: &str,
        file_name: String,
        media_type: String,
        size: u64,
        chunk_size: u32,
    ) -> Result<String, RuntimeError> {
        self.require_unlocked()?;
        let item_id = parse_uuid(item_id)?;
        let object = self.objects.get(&item_id).ok_or(RuntimeError::NotFound)?;
        if object.deleted_at.is_some() {
            return Err(RuntimeError::NotFound);
        }
        let metadata = AttachmentMetadata::generate(file_name, media_type, size, chunk_size)
            .map_err(|_| RuntimeError::Crypto)?;
        if self
            .items
            .values()
            .flat_map(|item| &item.attachments)
            .any(|attachment| attachment.id == metadata.id)
        {
            return Err(RuntimeError::Crypto);
        }
        let item = self.items.get_mut(&item_id).ok_or(RuntimeError::NotFound)?;
        if item.attachments.len() >= MAX_ATTACHMENTS_PER_ITEM {
            return Err(RuntimeError::Capacity);
        }
        item.attachments.push(metadata.clone());
        item.revision_date = Utc::now();
        encode_json(&metadata)
    }

    fn attachment_initiate_request_inner(
        &self,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<String, RuntimeError> {
        self.require_unlocked()?;
        let item_id = parse_uuid(item_id)?;
        let attachment_id = parse_uuid(attachment_id)?;
        let metadata = self.attachment(item_id, attachment_id)?;
        let object = self.objects.get(&item_id).ok_or(RuntimeError::NotFound)?;
        if object.deleted_at.is_some() {
            return Err(RuntimeError::NotFound);
        }
        encode_json(&AttachmentInitiateRequest {
            id: metadata.id,
            object_id: item_id,
            object_revision: object.object_revision,
            format: metadata.format().to_owned(),
            chunk_size: metadata.chunk_size,
            chunk_count: metadata.chunk_count,
            ciphertext_size: metadata.ciphertext_size,
        })
    }

    fn attachment_chunk_inner(
        &self,
        item_id: &str,
        attachment_id: &str,
        index: u32,
        input: &[u8],
        action: AttachmentChunkAction,
    ) -> Result<Vec<u8>, RuntimeError> {
        self.require_unlocked()?;
        let item_id = parse_uuid(item_id)?;
        let attachment_id = parse_uuid(attachment_id)?;
        let metadata = self.attachment(item_id, attachment_id)?;
        match action {
            AttachmentChunkAction::Encrypt => {
                encrypt_attachment_chunk(metadata, item_id, index, input)
                    .map_err(|_| RuntimeError::Crypto)
            }
            AttachmentChunkAction::Decrypt => {
                decrypt_attachment_chunk(metadata, item_id, index, input)
                    .map(|plaintext| plaintext.to_vec())
                    .map_err(|_| RuntimeError::Crypto)
            }
        }
    }

    fn remove_attachment_inner(
        &mut self,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<(), RuntimeError> {
        self.require_unlocked()?;
        let item_id = parse_uuid(item_id)?;
        let attachment_id = parse_uuid(attachment_id)?;
        let item = self.items.get_mut(&item_id).ok_or(RuntimeError::NotFound)?;
        let original_len = item.attachments.len();
        item.attachments
            .retain(|attachment| attachment.id != attachment_id);
        if item.attachments.len() == original_len {
            return Err(RuntimeError::NotFound);
        }
        item.revision_date = Utc::now();
        Ok(())
    }

    fn attachment(
        &self,
        item_id: Uuid,
        attachment_id: Uuid,
    ) -> Result<&AttachmentMetadata, RuntimeError> {
        self.items
            .get(&item_id)
            .and_then(|item| {
                item.attachments
                    .iter()
                    .find(|attachment| attachment.id == attachment_id)
            })
            .ok_or(RuntimeError::NotFound)
    }

    fn update_credential_from_page_inner(
        &mut self,
        id: &str,
        page_url: &str,
        username: Option<String>,
        password: &str,
    ) -> Result<(), RuntimeError> {
        self.require_unlocked()?;
        validate_page_url(page_url)?;
        if password.is_empty() || password.len() > 16_384 {
            return Err(RuntimeError::InvalidInput);
        }
        let username = nonempty(username);
        if username.as_ref().is_some_and(|value| value.len() > 2_000) {
            return Err(RuntimeError::InvalidInput);
        }
        let id = parse_uuid(id)?;
        let item = self.items.get_mut(&id).ok_or(RuntimeError::NotFound)?;
        let ItemData::Login(login) = &mut item.data else {
            return Err(RuntimeError::InvalidInput);
        };
        if item.deleted_date.is_some() || !login_matches(login, page_url) {
            return Err(RuntimeError::OriginMismatch);
        }
        let next_password = SecretString::new(password);
        if login.password.as_ref() != Some(&next_password) {
            if let Some(previous) = login.password.replace(next_password) {
                item.password_history.push(PasswordHistory {
                    password: previous,
                    last_used_date: Utc::now(),
                });
                if item.password_history.len() > 20 {
                    item.password_history.remove(0);
                }
            }
            login.password_revision_date = Some(Utc::now());
        }
        if let Some(username) = username {
            login.username = Some(username);
        }
        item.revision_date = Utc::now();
        Ok(())
    }

    fn build_put_request_inner(&self, id: &str, account_id: &str) -> Result<String, RuntimeError> {
        let id = parse_uuid(id)?;
        let account_id = parse_uuid(account_id)?;
        let item = self.items.get(&id).ok_or(RuntimeError::NotFound)?;
        let (owner_type, owner_id, key) = if let Some(organization_id) = item.organization_id {
            (
                OwnerType::Organization,
                organization_id,
                self.organization_keys
                    .get(&organization_id)
                    .ok_or(RuntimeError::MissingOrganizationKey)?,
            )
        } else {
            (OwnerType::User, account_id, self.require_unlocked()?)
        };
        let envelope = encrypt_json(item, key).map_err(|_| RuntimeError::Crypto)?;
        encode_json(&PutObjectRequest {
            kind: ObjectKind::Cipher,
            owner_type,
            owner_id,
            collection_ids: item.collection_ids.clone(),
            format: envelope.format,
            wrapped_key: envelope.wrapped_key,
            payload: envelope.payload,
            base_revision: self.objects.get(&id).map(|object| object.object_revision),
            idempotency_key: Uuid::new_v4(),
        })
    }

    fn build_folder_put_request_inner(
        &self,
        id: &str,
        account_id: &str,
    ) -> Result<String, RuntimeError> {
        let id = parse_uuid(id)?;
        let account_id = parse_uuid(account_id)?;
        let folder = self
            .folders
            .iter()
            .find(|folder| folder.id == id)
            .ok_or(RuntimeError::NotFound)?;
        let envelope =
            encrypt_json(folder, self.require_unlocked()?).map_err(|_| RuntimeError::Crypto)?;
        encode_json(&PutObjectRequest {
            kind: ObjectKind::Folder,
            owner_type: OwnerType::User,
            owner_id: account_id,
            collection_ids: Vec::new(),
            format: envelope.format,
            wrapped_key: envelope.wrapped_key,
            payload: envelope.payload,
            base_revision: self.objects.get(&id).map(|object| object.object_revision),
            idempotency_key: Uuid::new_v4(),
        })
    }

    fn credentials_for_url_inner(&self, page_url: &str) -> Result<String, RuntimeError> {
        self.require_unlocked()?;
        validate_page_url(page_url)?;
        let mut credentials: Vec<CredentialSummary> = self
            .items
            .values()
            .filter(|item| item.deleted_date.is_none())
            .filter_map(|item| {
                let ItemData::Login(login) = &item.data else {
                    return None;
                };
                login_matches(login, page_url).then(|| CredentialSummary {
                    id: item.id,
                    name: item.name.clone(),
                    username: login.username.clone(),
                    has_password: login.password.is_some(),
                    has_totp: login.totp.is_some(),
                })
            })
            .collect();
        credentials.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
        encode_json(&credentials)
    }

    fn credential_for_fill_inner(
        &self,
        id: &str,
        page_url: &str,
        unix_seconds: u64,
    ) -> Result<String, RuntimeError> {
        self.require_unlocked()?;
        validate_page_url(page_url)?;
        let id = parse_uuid(id)?;
        let item = self.items.get(&id).ok_or(RuntimeError::NotFound)?;
        let ItemData::Login(login) = &item.data else {
            return Err(RuntimeError::InvalidInput);
        };
        if item.deleted_date.is_some() || !login_matches(login, page_url) {
            return Err(RuntimeError::OriginMismatch);
        }
        let totp = login
            .totp
            .as_ref()
            .map(|secret| {
                TotpConfig::parse(secret.expose())
                    .and_then(|config| config.generate_at(unix_seconds))
                    .map(|code| code.code)
                    .map_err(|_| RuntimeError::InvalidInput)
            })
            .transpose()?;
        encode_json(&FillCredential {
            id,
            username: login.username.clone(),
            password: login
                .password
                .as_ref()
                .map(|password| password.expose().to_owned()),
            totp,
        })
    }

    fn passkey_creation_targets_inner(&self, options_json: &str) -> Result<String, RuntimeError> {
        self.require_unlocked()?;
        let options: PasskeyCreationOptions = parse_json(options_json)?;
        let rp_id = validate_passkey_creation(&options)?;
        if !options.exclude_credentials.is_empty() {
            let exclusion = PasskeyAssertionOptions {
                origin: options.origin.clone(),
                challenge: options.challenge.clone(),
                rp_id: Some(rp_id),
                allow_credentials: options.exclude_credentials.clone(),
                user_verification: None,
                mediation: None,
            };
            if self.items.values().any(|item| {
                matches!(&item.data, ItemData::Login(login) if login.fido2_credentials.iter().any(|credential| passkey_matches_request(credential, &exclusion)))
            }) {
                return Err(PasskeyError::ExcludedCredential.into());
            }
        }
        let mut targets: Vec<PasskeyTarget> = self
            .items
            .values()
            .filter(|item| item.deleted_date.is_none())
            .filter_map(|item| {
                let ItemData::Login(login) = &item.data else {
                    return None;
                };
                login_matches(login, &options.origin).then(|| PasskeyTarget {
                    item_id: item.id,
                    name: item.name.clone(),
                    username: login.username.clone(),
                })
            })
            .collect();
        targets.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then(left.item_id.cmp(&right.item_id))
        });
        encode_json(&targets)
    }

    fn create_vault_passkey_inner(
        &mut self,
        options_json: &str,
        target_item_id: Option<String>,
        user_verified: bool,
    ) -> Result<String, RuntimeError> {
        self.require_unlocked()?;
        if !user_verified {
            return Err(RuntimeError::InvalidInput);
        }
        let options: PasskeyCreationOptions = parse_json(options_json)?;
        // This also checks exclusions before mutation.
        self.passkey_creation_targets_inner(options_json)?;
        let created = create_passkey(&options, true)?;
        let item_id = if let Some(target) = target_item_id {
            let id = parse_uuid(&target)?;
            let item = self.items.get_mut(&id).ok_or(RuntimeError::NotFound)?;
            let ItemData::Login(login) = &mut item.data else {
                return Err(RuntimeError::InvalidInput);
            };
            if item.deleted_date.is_some() || !login_matches(login, &options.origin) {
                return Err(RuntimeError::OriginMismatch);
            }
            login.fido2_credentials.push(created.credential);
            item.revision_date = Utc::now();
            id
        } else {
            let name = options.rp.name.trim().to_owned();
            let mut item = VaultItem::new_login(
                name,
                Login {
                    username: Some(options.user.name.clone()),
                    uris: vec![LoginUri {
                        uri: options.origin.clone(),
                        r#match: Some(UriMatchType::Host),
                        extra: serde_json::Map::new(),
                    }],
                    fido2_credentials: vec![created.credential],
                    ..Login::default()
                },
            );
            item.revision_date = Utc::now();
            let id = item.id;
            self.ensure_capacity(id)?;
            self.items.insert(id, item);
            id
        };
        encode_json(&BrowserPasskeyCreationResult {
            item_id,
            credential_id: created.credential_id,
            client_data_json: created.client_data_json,
            attestation_object: created.attestation_object,
            authenticator_data: created.authenticator_data,
            public_key: created.public_key,
            public_key_algorithm: created.public_key_algorithm,
            transports: created.transports,
            extensions: BrowserPasskeyCreationExtensions {
                cred_props: BrowserCredentialProperties {
                    rk: created.discoverable,
                },
            },
        })
    }

    fn passkey_assertion_candidates_inner(
        &self,
        options_json: &str,
    ) -> Result<String, RuntimeError> {
        self.require_unlocked()?;
        let options: PasskeyAssertionOptions = parse_json(options_json)?;
        validate_passkey_assertion(&options)?;
        let mut candidates = Vec::new();
        for item in self
            .items
            .values()
            .filter(|item| item.deleted_date.is_none())
        {
            let ItemData::Login(login) = &item.data else {
                continue;
            };
            for credential in &login.fido2_credentials {
                if !passkey_matches_request(credential, &options) {
                    continue;
                }
                candidates.push(PasskeyCandidate {
                    item_id: item.id,
                    credential_id: passkey_credential_id(credential)?,
                    item_name: item.name.clone(),
                    user_name: credential.user_name.clone(),
                    user_display_name: credential.user_display_name.clone(),
                });
            }
        }
        candidates.sort_by(|left, right| {
            left.item_name
                .cmp(&right.item_name)
                .then(left.credential_id.cmp(&right.credential_id))
        });
        encode_json(&candidates)
    }

    fn assert_vault_passkey_inner(
        &mut self,
        options_json: &str,
        item_id: &str,
        credential_id: &str,
        user_verified: bool,
    ) -> Result<String, RuntimeError> {
        self.require_unlocked()?;
        if !user_verified {
            return Err(RuntimeError::InvalidInput);
        }
        let options: PasskeyAssertionOptions = parse_json(options_json)?;
        validate_passkey_assertion(&options)?;
        let item_id = parse_uuid(item_id)?;
        let item = self.items.get_mut(&item_id).ok_or(RuntimeError::NotFound)?;
        let ItemData::Login(login) = &mut item.data else {
            return Err(RuntimeError::InvalidInput);
        };
        if item.deleted_date.is_some() {
            return Err(RuntimeError::NotFound);
        }
        let credential = login
            .fido2_credentials
            .iter_mut()
            .find(|candidate| {
                passkey_matches_request(candidate, &options)
                    && passkey_credential_id(candidate).as_deref() == Ok(credential_id)
            })
            .ok_or(PasskeyError::NoMatchingCredential)?;
        let result = assert_passkey(credential, &options, true)?;
        if result.counter_changed {
            item.revision_date = Utc::now();
        }
        encode_json(&BrowserPasskeyAssertionResult {
            item_id,
            credential_id: result.credential_id,
            client_data_json: result.client_data_json,
            authenticator_data: result.authenticator_data,
            signature: result.signature,
            user_handle: result.user_handle,
            counter_changed: result.counter_changed,
        })
    }

    fn discard_item_changes_inner(&mut self, id: &str) -> Result<(), RuntimeError> {
        self.require_unlocked()?;
        let id = parse_uuid(id)?;
        if let Some(object) = self.objects.get(&id) {
            let mut restored = self.decrypt_item_object(object)?;
            restored.deleted_date = object.deleted_at;
            self.items.insert(id, restored);
        } else {
            self.items.remove(&id);
        }
        Ok(())
    }

    fn import_bitwarden_inner(&mut self, input: &str) -> Result<String, RuntimeError> {
        self.require_unlocked()?;
        let imported = import_json(input.as_bytes()).map_err(|_| RuntimeError::Decode)?;
        let resulting_count = self
            .items
            .len()
            .checked_add(imported.items.len())
            .ok_or(RuntimeError::Capacity)?;
        if resulting_count > MAX_RUNTIME_ITEMS {
            return Err(RuntimeError::Capacity);
        }
        let result = ImportResult {
            item_count: imported.items.len(),
            folder_count: imported.folders.len(),
            collection_count: imported.collections.len(),
            item_ids: imported.items.iter().map(|item| item.id).collect(),
            folder_ids: imported.folders.iter().map(|folder| folder.id).collect(),
        };
        for item in imported.items {
            self.items.insert(item.id, item);
        }
        merge_by_id(&mut self.folders, imported.folders, |folder| folder.id);
        merge_by_id(&mut self.collections, imported.collections, |collection| {
            collection.id
        });
        encode_json(&result)
    }

    fn require_unlocked(&self) -> Result<&CompositeKey, RuntimeError> {
        self.user_key.as_ref().ok_or(RuntimeError::Locked)
    }

    fn ensure_capacity(&self, id: Uuid) -> Result<(), RuntimeError> {
        if !self.items.contains_key(&id) && self.items.len() >= MAX_RUNTIME_ITEMS {
            return Err(RuntimeError::Capacity);
        }
        Ok(())
    }
}

fn parse_kdf(value: &str) -> Result<KdfConfig, RuntimeError> {
    let settings: KdfSettings = parse_json(value)?;
    let config = match settings.kdf_type {
        KdfType::Pbkdf2 => KdfConfig::Pbkdf2 {
            iterations: settings.iterations,
        },
        KdfType::Argon2id => KdfConfig::Argon2id {
            iterations: settings.iterations,
            memory_mib: settings.memory_mib.ok_or(RuntimeError::InvalidInput)?,
            parallelism: settings.parallelism.ok_or(RuntimeError::InvalidInput)?,
        },
    };
    config.validate().map_err(|_| RuntimeError::InvalidInput)?;
    Ok(config)
}

fn summary(item: &VaultItem, object: Option<&EncryptedObject>) -> ItemSummary {
    let (username, primary_uri, has_totp, passkey_count) = match &item.data {
        ItemData::Login(login) => (
            login.username.clone(),
            login.uris.first().map(|uri| uri.uri.clone()),
            login.totp.is_some(),
            login.fido2_credentials.len(),
        ),
        _ => (None, None, false, 0),
    };
    ItemSummary {
        id: item.id,
        name: item.name.clone(),
        item_type: item.item_type(),
        username,
        primary_uri,
        favorite: item.favorite,
        deleted_date: item.deleted_date,
        has_totp,
        passkey_count,
        object_revision: object.map(|value| value.object_revision),
        organization_id: item.organization_id,
        collection_ids: item.collection_ids.clone(),
    }
}

fn category_matches(item: &VaultItem, category: &str) -> bool {
    if let Some(folder_id) = category.strip_prefix("folder:") {
        return Uuid::parse_str(folder_id).is_ok_and(|folder_id| {
            item.deleted_date.is_none() && item.folder_id == Some(folder_id)
        });
    }
    match category {
        "all" => item.deleted_date.is_none(),
        "logins" => item.deleted_date.is_none() && matches!(item.data, ItemData::Login(_)),
        "passkeys" => {
            item.deleted_date.is_none()
                && matches!(&item.data, ItemData::Login(login) if !login.fido2_credentials.is_empty())
        }
        "cards" => item.deleted_date.is_none() && matches!(item.data, ItemData::Card(_)),
        "identities" => item.deleted_date.is_none() && matches!(item.data, ItemData::Identity(_)),
        "notes" => item.deleted_date.is_none() && matches!(item.data, ItemData::SecureNote(_)),
        "favorites" => item.deleted_date.is_none() && item.favorite,
        "trash" => item.deleted_date.is_some(),
        _ => false,
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "folder names cross an ownership boundary and this function returns the normalized owned value"
)]
fn validate_folder_name(name: String) -> Result<String, RuntimeError> {
    let name = name.trim().to_owned();
    if name.is_empty() || name.len() > 1_000 || name.chars().any(char::is_control) {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(name)
}

fn remove_folder_projection(
    folders: &mut Vec<BitwardenFolder>,
    items: &mut BTreeMap<Uuid, VaultItem>,
    folder_id: Uuid,
) {
    folders.retain(|folder| folder.id != folder_id);
    for item in items.values_mut() {
        if item.folder_id == Some(folder_id) {
            item.folder_id = None;
        }
    }
}

fn login_matches(login: &Login, page_url: &str) -> bool {
    login.uris.iter().any(|uri| {
        uri_matches(
            &uri.uri,
            page_url,
            uri.r#match.unwrap_or(UriMatchType::Domain),
        )
        .unwrap_or(false)
    })
}

fn validate_page_url(page_url: &str) -> Result<(), RuntimeError> {
    let parsed = url::Url::parse(page_url).map_err(|_| RuntimeError::InvalidInput)?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(())
}

fn validate_login_draft(draft: &mut LoginDraft) -> Result<(), RuntimeError> {
    draft.name = draft.name.trim().to_owned();
    if draft.name.is_empty() || draft.name.len() > 2_000 {
        return Err(RuntimeError::InvalidInput);
    }
    if let Some(uri) = draft
        .uri
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        let parsed = url::Url::parse(uri).map_err(|_| RuntimeError::InvalidInput)?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            return Err(RuntimeError::InvalidInput);
        }
    }
    if let Some(totp) = draft
        .totp
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        TotpConfig::parse(totp).map_err(|_| RuntimeError::InvalidInput)?;
    }
    Ok(())
}

fn validate_item_common(
    name: &str,
    notes: Option<String>,
    favorite: bool,
) -> Result<(String, Option<String>, bool), RuntimeError> {
    let name = name.trim().to_owned();
    if name.is_empty() || name.len() > 2_000 || name.chars().any(char::is_control) {
        return Err(RuntimeError::InvalidInput);
    }
    let notes = optional_verbatim_bounded(notes, MAX_COMMON_TEXT_BYTES)?;
    Ok((name, notes, favorite))
}

fn build_editable_item_data(
    draft: EditableItemData,
    existing: Option<&ItemData>,
) -> Result<ItemData, RuntimeError> {
    match draft {
        EditableItemData::SecureNote(_) => {
            let (note_type, extra) = match existing {
                None => (0, serde_json::Map::new()),
                Some(ItemData::SecureNote(note)) => (note.note_type, note.extra.clone()),
                Some(_) => return Err(RuntimeError::InvalidInput),
            };
            Ok(ItemData::SecureNote(SecureNote { note_type, extra }))
        }
        EditableItemData::Card(draft) => {
            let extra = match existing {
                None => serde_json::Map::new(),
                Some(ItemData::Card(card)) => card.extra.clone(),
                Some(_) => return Err(RuntimeError::InvalidInput),
            };
            Ok(ItemData::Card(Card {
                cardholder_name: optional_trimmed_bounded(draft.cardholder_name, 4_000)?,
                exp_month: optional_trimmed_bounded(draft.exp_month, 32)?,
                exp_year: optional_trimmed_bounded(draft.exp_year, 32)?,
                code: optional_verbatim_bounded(draft.code, 1_024)?.map(SecretString::new),
                brand: optional_trimmed_bounded(draft.brand, 256)?,
                number: optional_verbatim_bounded(draft.number, 4_096)?.map(SecretString::new),
                extra,
            }))
        }
        EditableItemData::Identity(draft) => {
            let extra = match existing {
                None => serde_json::Map::new(),
                Some(ItemData::Identity(identity)) => identity.extra.clone(),
                Some(_) => return Err(RuntimeError::InvalidInput),
            };
            Ok(ItemData::Identity(Identity {
                title: optional_trimmed_bounded(draft.title, 512)?,
                first_name: optional_trimmed_bounded(draft.first_name, 2_000)?,
                middle_name: optional_trimmed_bounded(draft.middle_name, 2_000)?,
                last_name: optional_trimmed_bounded(draft.last_name, 2_000)?,
                address1: optional_trimmed_bounded(draft.address1, 4_000)?,
                address2: optional_trimmed_bounded(draft.address2, 4_000)?,
                address3: optional_trimmed_bounded(draft.address3, 4_000)?,
                city: optional_trimmed_bounded(draft.city, 2_000)?,
                state: optional_trimmed_bounded(draft.state, 2_000)?,
                postal_code: optional_trimmed_bounded(draft.postal_code, 512)?,
                country: optional_trimmed_bounded(draft.country, 512)?,
                company: optional_trimmed_bounded(draft.company, 4_000)?,
                email: optional_trimmed_bounded(draft.email, 2_000)?,
                phone: optional_trimmed_bounded(draft.phone, 2_000)?,
                ssn: optional_verbatim_bounded(draft.ssn, 2_000)?.map(SecretString::new),
                username: optional_trimmed_bounded(draft.username, 2_000)?,
                passport_number: optional_verbatim_bounded(draft.passport_number, 2_000)?
                    .map(SecretString::new),
                license_number: optional_verbatim_bounded(draft.license_number, 2_000)?
                    .map(SecretString::new),
                extra,
            }))
        }
        EditableItemData::SshKey(draft) => {
            let extra = match existing {
                None => serde_json::Map::new(),
                Some(ItemData::SshKey(key)) => key.extra.clone(),
                Some(_) => return Err(RuntimeError::InvalidInput),
            };
            Ok(ItemData::SshKey(SshKey {
                private_key: SecretString::new(required_nonempty_verbatim_bounded(
                    draft.private_key,
                    MAX_PRIVATE_KEY_BYTES,
                )?),
                public_key: required_nonempty_verbatim_bounded(
                    draft.public_key,
                    MAX_COMMON_TEXT_BYTES,
                )?,
                key_fingerprint: required_nonempty_trimmed_bounded(&draft.key_fingerprint, 4_000)?,
                extra,
            }))
        }
    }
}

fn optional_trimmed_bounded(
    value: Option<String>,
    maximum: usize,
) -> Result<Option<String>, RuntimeError> {
    value
        .map(|value| required_trimmed_bounded(&value, maximum))
        .transpose()
        .map(|value| value.filter(|value| !value.is_empty()))
}

fn required_trimmed_bounded(value: &str, maximum: usize) -> Result<String, RuntimeError> {
    let value = value.trim().to_owned();
    if value.len() > maximum || has_forbidden_control(&value) {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(value)
}

fn required_nonempty_trimmed_bounded(value: &str, maximum: usize) -> Result<String, RuntimeError> {
    let value = required_trimmed_bounded(value, maximum)?;
    if value.is_empty() {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(value)
}

fn optional_verbatim_bounded(
    value: Option<String>,
    maximum: usize,
) -> Result<Option<String>, RuntimeError> {
    value
        .map(|value| required_verbatim_bounded(value, maximum))
        .transpose()
        .map(|value| value.filter(|value| !value.trim().is_empty()))
}

fn required_verbatim_bounded(value: String, maximum: usize) -> Result<String, RuntimeError> {
    if value.len() > maximum || has_forbidden_control(&value) {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(value)
}

fn required_nonempty_verbatim_bounded(
    value: String,
    maximum: usize,
) -> Result<String, RuntimeError> {
    let value = required_verbatim_bounded(value, maximum)?;
    if value.trim().is_empty() {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(value)
}

fn has_forbidden_control(value: &str) -> bool {
    value.chars().any(|character| {
        character == '\0' || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    })
}

fn nonempty(value: Option<String>) -> Option<String> {
    value.and_then(|value| (!value.trim().is_empty()).then_some(value))
}

fn merge_by_id<T, F>(target: &mut Vec<T>, incoming: Vec<T>, id: F)
where
    F: Fn(&T) -> Uuid,
{
    let incoming_ids: BTreeSet<Uuid> = incoming.iter().map(&id).collect();
    target.retain(|value| !incoming_ids.contains(&id(value)));
    target.extend(incoming);
}

fn parse_uuid(value: &str) -> Result<Uuid, RuntimeError> {
    Uuid::parse_str(value).map_err(|_| RuntimeError::InvalidInput)
}

fn parse_json<T: DeserializeOwned>(value: &str) -> Result<T, RuntimeError> {
    serde_json::from_str(value).map_err(|_| RuntimeError::Decode)
}

fn encode_json<T: Serialize>(value: &T) -> Result<String, RuntimeError> {
    serde_json::to_string(value).map_err(|_| RuntimeError::Decode)
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "Result::map_err owns the error at this single WASM conversion point"
)]
fn js_error(error: RuntimeError) -> JsValue {
    JsValue::from_str(&error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kdf_json() -> String {
        serde_json::to_string(&KdfSettings::default()).unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn registration_never_returns_the_user_key() {
        let mut runtime = VaultRuntime::default();
        let material = runtime
            .prepare_registration_inner("alice@example.test", "long master password", &kdf_json())
            .unwrap_or_else(|error| panic!("{error}"));
        let parsed: serde_json::Value =
            serde_json::from_str(&material).unwrap_or_else(|error| panic!("{error}"));
        assert!(parsed.get("authProof").is_some());
        assert!(parsed.get("protectedUserKey").is_some());
        assert!(parsed.get("userKey").is_none());
        assert!(runtime.user_key.is_some());
    }

    #[test]
    fn login_item_encrypts_and_origin_scopes_fill() {
        let mut runtime = VaultRuntime {
            user_key: Some(CompositeKey::generate().unwrap_or_else(|error| panic!("{error}"))),
            ..VaultRuntime::default()
        };
        let id = runtime
            .create_login_inner(
                r#"{"name":"Example","username":"alice","password":"secret","uri":"https://login.example.com","totp":"JBSWY3DPEHPK3PXP"}"#,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let account_id = Uuid::new_v4();
        let request = runtime
            .build_put_request_inner(&id, &account_id.to_string())
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!request.contains("alice"));
        assert!(!request.contains("secret"));
        assert!(
            runtime
                .credential_for_fill_inner(&id, "https://account.example.com/login", 59)
                .is_ok()
        );
        assert!(matches!(
            runtime.credential_for_fill_inner(&id, "https://example.com.attacker.test", 59),
            Err(RuntimeError::OriginMismatch)
        ));
    }

    #[test]
    fn login_update_retains_exact_secret_and_password_history() {
        let mut runtime = VaultRuntime {
            user_key: Some(CompositeKey::generate().unwrap_or_else(|error| panic!("{error}"))),
            ..VaultRuntime::default()
        };
        let id = runtime
            .create_login_inner(
                r#"{"name":"Example","password":"  old secret  ","uri":"https://example.com"}"#,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        runtime
            .update_login_inner(
                &id,
                r#"{"name":"Updated","password":"  new secret  ","uri":"https://example.com/login"}"#,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let item = runtime
            .items
            .values()
            .next()
            .unwrap_or_else(|| panic!("missing item"));
        let ItemData::Login(login) = &item.data else {
            panic!("not a login");
        };
        assert_eq!(
            login.password.as_ref().map(SecretString::expose),
            Some("  new secret  ")
        );
        assert_eq!(item.password_history.len(), 1);
        assert_eq!(item.password_history[0].password.expose(), "  old secret  ");
    }

    #[test]
    fn typed_item_editors_validate_encrypt_and_preserve_forward_fields() {
        let mut runtime = VaultRuntime {
            user_key: Some(CompositeKey::generate().unwrap_or_else(|error| panic!("{error}"))),
            ..VaultRuntime::default()
        };
        let drafts = [
            r#"{"name":"Private note","notes":"note plaintext","data":{"kind":"secureNote","value":{}}}"#,
            r#"{"name":"Payment","notes":"card notes","favorite":true,"data":{"kind":"card","value":{"cardholderName":"Alice","expMonth":"12","expYear":"2032","code":"987","brand":"Fixture","number":"5555555555554444"}}}"#,
            r#"{"name":"Identity","data":{"kind":"identity","value":{"title":"Dr","firstName":"Alice","middleName":null,"lastName":"Example","address1":"1 Test Road","address2":null,"address3":null,"city":"Tokyo","state":"Tokyo","postalCode":"100-0001","country":"Japan","company":"Example","email":"alice@example.test","phone":"+81 00","ssn":"fixture-ssn","username":"alice","passportNumber":"fixture-passport","licenseNumber":"fixture-license"}}}"#,
            r#"{"name":"SSH","data":{"kind":"sshKey","value":{"privateKey":"-----BEGIN PRIVATE KEY-----\nfixture-private\n-----END PRIVATE KEY-----","publicKey":"ssh-ed25519 fixture-public","keyFingerprint":"SHA256:fixture"}}}"#,
        ];
        let account_id = Uuid::new_v4();
        let mut ids = Vec::new();
        for draft in drafts {
            let id = runtime
                .create_item_inner(draft)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = runtime
                .build_put_request_inner(&id, &account_id.to_string())
                .unwrap_or_else(|error| panic!("{error}"));
            for plaintext in [
                "note plaintext",
                "5555555555554444",
                "fixture-ssn",
                "fixture-private",
            ] {
                assert!(!request.contains(plaintext));
            }
            ids.push(Uuid::parse_str(&id).unwrap_or_else(|error| panic!("{error}")));
        }
        assert!(matches!(
            runtime.items[&ids[0]].data,
            ItemData::SecureNote(_)
        ));
        assert!(matches!(runtime.items[&ids[1]].data, ItemData::Card(_)));
        assert!(matches!(runtime.items[&ids[2]].data, ItemData::Identity(_)));
        assert!(matches!(runtime.items[&ids[3]].data, ItemData::SshKey(_)));

        let ItemData::Card(card) = &mut runtime
            .items
            .get_mut(&ids[1])
            .unwrap_or_else(|| panic!("missing card"))
            .data
        else {
            panic!("card expected");
        };
        card.extra.insert(
            "futureCardField".to_owned(),
            serde_json::json!({ "kept": true }),
        );
        runtime
            .update_item_inner(
                &ids[1].to_string(),
                r#"{"name":"Payment updated","notes":null,"data":{"kind":"card","value":{"cardholderName":"Alice B","expMonth":"01","expYear":"2035","code":"654","brand":"Fixture","number":"4000000000000002"}}}"#,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let ItemData::Card(card) = &runtime.items[&ids[1]].data else {
            panic!("card expected");
        };
        assert_eq!(
            card.number.as_ref().map(SecretString::expose),
            Some("4000000000000002")
        );
        assert_eq!(
            card.extra["futureCardField"],
            serde_json::json!({ "kept": true })
        );
        assert!(runtime
            .update_item_inner(
                &ids[1].to_string(),
                r#"{"name":"Wrong type","data":{"kind":"identity","value":{"title":null,"firstName":null,"middleName":null,"lastName":null,"address1":null,"address2":null,"address3":null,"city":null,"state":null,"postalCode":null,"country":null,"company":null,"email":null,"phone":null,"ssn":null,"username":null,"passportNumber":null,"licenseNumber":null}}}"#,
            )
            .is_err());
    }

    #[test]
    fn item_destination_is_validated_in_rust_and_immutable_after_upload() {
        let mut runtime = VaultRuntime {
            user_key: Some(CompositeKey::generate().unwrap_or_else(|error| panic!("{error}"))),
            ..VaultRuntime::default()
        };
        let organization_id = Uuid::new_v4();
        let collection_id = Uuid::new_v4();
        runtime.organization_keys.insert(
            organization_id,
            CompositeKey::generate().unwrap_or_else(|error| panic!("{error}")),
        );
        let item_id = runtime
            .create_item_inner(
                r#"{"name":"Shared note","notes":"secret","data":{"kind":"secureNote","value":{}}}"#,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        runtime
            .assign_item_destination_inner(
                &item_id,
                Some(organization_id.to_string()),
                &serde_json::to_string(&vec![collection_id])
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let item_uuid = Uuid::parse_str(&item_id).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            runtime.items[&item_uuid].organization_id,
            Some(organization_id)
        );
        let request: PutObjectRequest = serde_json::from_str(
            &runtime
                .build_put_request_inner(&item_id, &Uuid::new_v4().to_string())
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        runtime.objects.insert(
            item_uuid,
            EncryptedObject {
                id: item_uuid,
                kind: request.kind,
                owner_type: request.owner_type,
                owner_id: request.owner_id,
                collection_ids: request.collection_ids,
                format: request.format,
                wrapped_key: request.wrapped_key,
                payload: request.payload,
                object_revision: 1,
                account_revision: 1,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                deleted_at: None,
            },
        );
        assert!(
            runtime
                .assign_item_destination_inner(&item_id, None, "[]")
                .is_err()
        );
    }

    #[test]
    fn folder_names_are_encrypted_synced_and_detached_before_delete() {
        let user_key = CompositeKey::generate().unwrap_or_else(|error| panic!("{error}"));
        let mut owner = VaultRuntime {
            user_key: Some(user_key.clone()),
            ..VaultRuntime::default()
        };
        let account_id = Uuid::new_v4();
        let folder_id = owner
            .create_folder("Finance secrets".to_owned())
            .unwrap_or_else(|error| panic!("{error:?}"));
        let request_json = owner
            .build_folder_put_request_inner(&folder_id, &account_id.to_string())
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!request_json.contains("Finance secrets"));
        let request: PutObjectRequest =
            serde_json::from_str(&request_json).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(request.kind, ObjectKind::Folder);

        let object = EncryptedObject {
            id: Uuid::parse_str(&folder_id).unwrap_or_else(|error| panic!("{error}")),
            kind: request.kind,
            owner_type: request.owner_type,
            owner_id: request.owner_id,
            collection_ids: request.collection_ids,
            format: request.format,
            wrapped_key: request.wrapped_key,
            payload: request.payload,
            object_revision: 1,
            account_revision: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        };
        let mut member = VaultRuntime {
            user_key: Some(user_key),
            ..VaultRuntime::default()
        };
        member
            .apply_object(object)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(member.folders[0].name, "Finance secrets");

        let item_id = member
            .create_login_inner(r#"{"name":"Bank"}"#)
            .unwrap_or_else(|error| panic!("{error}"));
        member
            .assign_item_folder(&item_id, Some(folder_id.clone()))
            .unwrap_or_else(|error| panic!("{error:?}"));
        let changed: Vec<Uuid> = serde_json::from_str(
            &member
                .detach_folder(&folder_id)
                .unwrap_or_else(|error| panic!("{error:?}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            changed,
            vec![Uuid::parse_str(&item_id).unwrap_or_else(|error| panic!("{error}"))]
        );
        assert!(member.items.values().all(|item| item.folder_id.is_none()));
    }

    #[test]
    fn captured_password_update_rechecks_origin() {
        let mut runtime = VaultRuntime {
            user_key: Some(CompositeKey::generate().unwrap_or_else(|error| panic!("{error}"))),
            ..VaultRuntime::default()
        };
        let id = runtime
            .create_login_inner(
                r#"{"name":"Example","password":"old","uri":"https://example.com"}"#,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            runtime.update_credential_from_page_inner(
                &id,
                "https://example.com.attacker.test",
                None,
                "stolen"
            ),
            Err(RuntimeError::OriginMismatch)
        ));
        runtime
            .update_credential_from_page_inner(
                &id,
                "https://login.example.com/account",
                Some("alice".to_owned()),
                "new",
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let item = runtime
            .items
            .values()
            .next()
            .unwrap_or_else(|| panic!("missing item"));
        let ItemData::Login(login) = &item.data else {
            panic!("not a login");
        };
        assert_eq!(login.username.as_deref(), Some("alice"));
        assert_eq!(
            login.password.as_ref().map(SecretString::expose),
            Some("new")
        );
    }

    #[test]
    fn sync_page_application_is_atomic_on_bad_ciphertext() {
        let mut runtime = VaultRuntime {
            user_key: Some(CompositeKey::generate().unwrap_or_else(|error| panic!("{error}"))),
            ..VaultRuntime::default()
        };
        let object = EncryptedObject {
            id: Uuid::new_v4(),
            kind: ObjectKind::Cipher,
            owner_type: OwnerType::User,
            owner_id: Uuid::new_v4(),
            collection_ids: Vec::new(),
            format: "hp.v1".to_owned(),
            wrapped_key: "2.bad|bad|bad".to_owned(),
            payload: "2.bad|bad|bad".to_owned(),
            object_revision: 1,
            account_revision: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        };
        let page = SyncResponse {
            changes: vec![hasilan_protocol::SyncChange {
                revision: 1,
                operation: ChangeOperation::Upsert,
                object_id: object.id,
                object: Some(object),
            }],
            next_cursor: "opaque".to_owned(),
            has_more: false,
        };
        let json = serde_json::to_string(&page).unwrap_or_else(|error| panic!("{error}"));
        assert!(runtime.apply_sync_page_inner(&json).is_err());
        assert!(runtime.items.is_empty());
        assert!(runtime.objects.is_empty());
    }

    #[test]
    fn organization_keys_stay_in_memory_and_acl_deletes_purge_items() {
        let member_user_key = CompositeKey::generate().unwrap_or_else(|error| panic!("{error}"));
        let mut member = VaultRuntime {
            user_key: Some(member_user_key),
            ..VaultRuntime::default()
        };
        let sharing_json = member
            .generate_sharing_key_inner()
            .unwrap_or_else(|error| panic!("{error}"));
        let sharing: hasilan_crypto::SharingKeyMaterial =
            serde_json::from_str(&sharing_json).unwrap_or_else(|error| panic!("{error}"));

        let mut owner = VaultRuntime {
            user_key: Some(CompositeKey::generate().unwrap_or_else(|error| panic!("{error}"))),
            ..VaultRuntime::default()
        };
        let organization_id = Uuid::new_v4();
        let collection_id = Uuid::new_v4();
        let wrapper = owner
            .create_organization_key_inner(&organization_id.to_string(), &sharing.public_key)
            .unwrap_or_else(|error| panic!("{error}"));
        member
            .open_organization_key_inner(&organization_id.to_string(), &wrapper)
            .unwrap_or_else(|error| panic!("{error}"));

        let mut item = VaultItem::new_login(
            "Shared login",
            Login {
                password: Some(SecretString::new("organization secret")),
                ..Login::default()
            },
        );
        item.organization_id = Some(organization_id);
        item.collection_ids = vec![collection_id];
        let item_id = item.id;
        owner.items.insert(item_id, item);
        let request_json = owner
            .build_put_request_inner(&item_id.to_string(), &Uuid::new_v4().to_string())
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!request_json.contains("organization secret"));
        let request: PutObjectRequest =
            serde_json::from_str(&request_json).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(request.owner_type, OwnerType::Organization);
        let object = EncryptedObject {
            id: item_id,
            kind: request.kind,
            owner_type: request.owner_type,
            owner_id: request.owner_id,
            collection_ids: request.collection_ids,
            format: request.format,
            wrapped_key: request.wrapped_key,
            payload: request.payload,
            object_revision: 1,
            account_revision: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        };
        member
            .apply_object(object)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(member.items[&item_id].name, "Shared login");

        let deletion = SyncResponse {
            changes: vec![hasilan_protocol::SyncChange {
                revision: 2,
                operation: ChangeOperation::Delete,
                object_id: item_id,
                object: None,
            }],
            next_cursor: "opaque".to_owned(),
            has_more: false,
        };
        member
            .apply_sync_page_inner(
                &serde_json::to_string(&deletion).unwrap_or_else(|error| panic!("{error}")),
            )
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!member.items.contains_key(&item_id));
        assert!(!member.objects.contains_key(&item_id));
        member.lock();
        assert!(!member.has_organization_key(&organization_id.to_string()));
    }
}
