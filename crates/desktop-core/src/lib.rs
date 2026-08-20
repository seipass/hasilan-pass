//! Native, offline-first vault runtime used by the Tauri desktop shell.
//!
//! Decrypted items and session tokens exist only in this process's memory. The durable
//! cache serializes [`hasilan_sync::Replica`], which contains opaque encrypted objects,
//! mutations, conflicts, and an authenticated sync cursor.
#![allow(
    clippy::missing_errors_doc,
    reason = "the public boundary returns one redacted DesktopError enum documented centrally"
)]

mod secrets;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
pub use hasilan_bitwarden_compat::BitwardenFolder;
use hasilan_bitwarden_compat::{BitwardenCollection, ImportedVault, export_json, import_json};
use hasilan_client::{ApiClient, ClientError};
use hasilan_crypto::{
    AttachmentMetadata, CompositeKey, DEFAULT_ATTACHMENT_CHUNK_SIZE, EncryptedEnvelope, KdfConfig,
    SharingPrivateKey, decrypt_attachment_chunk, decrypt_json, encrypt_attachment_chunk,
    encrypt_json, generate_sharing_key, open_organization_key, prepare_login, prepare_registration,
    unwrap_sharing_private_key,
};
use hasilan_protocol::{
    AttachmentCompleteRequest, AttachmentInitiateRequest, AttachmentResponse, AttachmentState,
    CollectionResponse, DeleteObjectRequest, DeviceRequest, DeviceResponse, EncryptedObject,
    KdfSettings, KdfType, LoginRequest, MembershipStatus, MfaEnableResponse, MfaStatusResponse,
    ObjectKind, OrganizationResponse, OrganizationRole, OwnerType, PasskeyLoginStartRequest,
    PreloginRequest, PutObjectRequest, ReauthenticationRequest, RecoveryCodesResponse,
    RegisterRequest, SessionResponse, SharingKeyRequest, SharingKeyResponse, TokenResponse,
    TotpSetupFinishRequest, TotpSetupStartResponse, WebauthnChallengeResponse,
    WebauthnLoginFinishRequest, WebauthnRegistrationFinishRequest,
    WebauthnRegistrationStartRequest,
};
use hasilan_sync::{PendingMutation, Replica};
use hasilan_vault::{
    CustomField, ItemData, Login, LoginUri, PasskeyAssertionOptions, PasskeyAssertionResult,
    PasskeyCreationOptions, PasskeyCreationResult, PassphraseOptions, PasswordHistory,
    PasswordOptions, SecretString, TotpConfig, UriMatchType, VaultItem, assert_passkey,
    create_passkey, generate_passphrase, generate_password, passkey_credential_id, search,
    uri_matches,
};
pub use secrets::{KeyringSecretStore, MemorySecretStore, SecretStore, SecretStoreError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const CACHE_VERSION: u32 = 1;
const MAX_CACHE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_PROFILES: usize = 10;
const MAX_ITEMS: usize = 40_000;
const MAX_FOLDERS: usize = 2_000;
const DEFAULT_AUTO_LOCK_MINUTES: u32 = 15;

/// A UI-safe native runtime failure. Secret-bearing source errors are never formatted.
#[derive(Debug, Error)]
pub enum DesktopError {
    /// An operation requires an unlocked user key.
    #[error("vault is locked")]
    Locked,
    /// User input failed bounded validation.
    #[error("invalid input")]
    InvalidInput,
    /// A requested item or profile does not exist.
    #[error("vault item was not found")]
    NotFound,
    /// Cached unlock material could not be authenticated by the supplied password.
    #[error("the master password is incorrect or the encrypted cache is damaged")]
    UnlockFailed,
    /// Durable ciphertext state was malformed, oversized, or could not be committed.
    #[error("the encrypted desktop cache could not be used")]
    Cache,
    /// Encryption, decryption, or key derivation failed.
    #[error("cryptographic operation failed")]
    Crypto,
    /// The remote API could not be reached.
    #[error("the server is unavailable; local changes remain queued")]
    Offline,
    /// The remote API rejected an operation with a stable, non-secret code.
    #[error("server rejected the request: {0}")]
    Server(String),
    /// The refresh credential is unavailable and online authentication is required.
    #[error("unlock online again to renew this device session")]
    AuthenticationRequired,
    /// Ordered replica validation failed.
    #[error("encrypted synchronization state is inconsistent")]
    Sync,
    /// Native credential storage failed.
    #[error(transparent)]
    SecretStore(#[from] SecretStoreError),
    /// A compatibility import/export was rejected.
    #[error("the import or export is malformed or exceeds safe limits")]
    Compatibility,
    /// A selected native attachment path could not be read or committed safely.
    #[error("the attachment file could not be read or written safely")]
    AttachmentFile,
    /// The selected item has an unresolved concurrent edit.
    #[error("resolve the concurrent edit before synchronizing this item")]
    Conflict,
}

/// Login editor payload shared with the desktop UI.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginDraft {
    /// Existing ID for an edit, or `None` for creation.
    pub id: Option<Uuid>,
    /// Display name.
    pub name: String,
    /// Optional username.
    pub username: Option<String>,
    /// Optional password, preserved byte-for-byte when non-empty.
    pub password: Option<String>,
    /// Optional HTTP(S) URI.
    pub uri: Option<String>,
    /// Base32 secret or `otpauth://` URI.
    pub totp: Option<String>,
    /// Private notes.
    pub notes: Option<String>,
    /// Favorite flag.
    #[serde(default)]
    pub favorite: bool,
    /// Optional personal folder. An existing item's organization ownership remains immutable.
    #[serde(default)]
    pub folder_id: Option<Uuid>,
    /// Custom private fields retained in the encrypted vault model.
    #[serde(default)]
    pub fields: Vec<CustomField>,
    /// Organization owner for a new item. Existing ownership is immutable.
    #[serde(default)]
    pub organization_id: Option<Uuid>,
    /// Organization collections for a new item.
    #[serde(default)]
    pub collection_ids: Vec<Uuid>,
}

/// Typed non-login item editor payload shared by desktop and Android UIs.
///
/// Login records intentionally retain their dedicated [`LoginDraft`] path so password history,
/// URI policy, TOTP parsing, and Autofill saves keep their stricter validation behavior.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemDraft {
    /// Existing ID for an edit, or `None` for creation.
    pub id: Option<Uuid>,
    /// Display name.
    pub name: String,
    /// Optional private notes.
    pub notes: Option<String>,
    /// Favorite flag.
    #[serde(default)]
    pub favorite: bool,
    /// Optional personal folder for a new or edited personal item.
    #[serde(default)]
    pub folder_id: Option<Uuid>,
    /// Custom private fields.
    #[serde(default)]
    pub fields: Vec<CustomField>,
    /// Type-specific content. Only secure notes, cards, and identities are editable here.
    pub data: ItemData,
    /// Organization owner for a new item. Existing ownership is immutable.
    #[serde(default)]
    pub organization_id: Option<Uuid>,
    /// Organization collections for a new item. Existing memberships are immutable.
    #[serde(default)]
    pub collection_ids: Vec<Uuid>,
}

/// Secret-free vault row returned to the system `WebView`.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent serialized UI state flags are clearer than a combinatorial enum"
)]
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemSummary {
    /// Stable item ID.
    pub id: Uuid,
    /// Display name.
    pub name: String,
    /// Bitwarden numeric item type.
    pub item_type: u8,
    /// Login username when applicable.
    pub username: Option<String>,
    /// First saved URI when applicable.
    pub primary_uri: Option<String>,
    /// Favorite flag.
    pub favorite: bool,
    /// Trash marker.
    pub deleted_date: Option<DateTime<Utc>>,
    /// Whether a TOTP seed exists.
    pub has_totp: bool,
    /// Number of encrypted passkeys on this login.
    pub passkey_count: usize,
    /// Current authoritative server revision, if synchronized.
    pub object_revision: Option<i64>,
    /// Whether a local upload remains queued.
    pub pending: bool,
    /// Whether a concurrent server version needs a decision.
    pub conflicted: bool,
    /// Organization owner, if this is a shared item.
    pub organization_id: Option<Uuid>,
    /// Server-visible organization collection memberships.
    pub collection_ids: Vec<Uuid>,
}

/// One unresolved local/server pair represented without secret fields.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictSummary {
    /// Shared object ID.
    pub id: Uuid,
    /// Locally edited item name.
    pub local_name: String,
    /// Concurrent server item name.
    pub server_name: String,
}

/// Current desktop client state.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopStatus {
    /// Whether a user key is held in memory.
    pub unlocked: bool,
    /// Whether the most recent server operation succeeded.
    pub online: bool,
    /// Active self-hosted server.
    pub server_url: Option<String>,
    /// Active account email.
    pub email: Option<String>,
    /// Decrypted item count while unlocked.
    pub item_count: usize,
    /// Durable mutations waiting for upload.
    pub pending_count: usize,
    /// Concurrent edits waiting for a decision.
    pub conflict_count: usize,
    /// Current automatic-lock delay.
    pub auto_lock_minutes: u32,
    /// Time of the most recent successful pull.
    pub last_sync_at: Option<DateTime<Utc>>,
    /// Other cached account profiles available for switching.
    pub profiles: Vec<ProfileSummary>,
}

/// Non-secret cached account selector.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSummary {
    /// Canonical profile scope identifier.
    pub scope: String,
    /// Server origin.
    pub server_url: String,
    /// Normalized email.
    pub email: String,
    /// Whether this is the selected profile.
    pub active: bool,
}

/// Secret-free organization and collection metadata exposed to the desktop editor.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationCatalog {
    /// Confirmed organizations for which the client currently holds a decrypted key.
    pub organizations: Vec<OrganizationSummary>,
    /// Collections visible to the active member, including effective UI permissions.
    pub collections: Vec<OrganizationCollectionSummary>,
    /// Personal folder labels decrypted locally from encrypted Folder objects.
    pub folders: Vec<BitwardenFolder>,
}

/// Folder editor payload. Folder names are encrypted before synchronization.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderDraft {
    /// Existing ID for a rename, or `None` for creation.
    pub id: Option<Uuid>,
    /// Private folder name.
    pub name: String,
}

/// Organization label and effective role safe to expose to the desktop webview.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationSummary {
    /// Stable organization ID.
    pub id: Uuid,
    /// Server-visible organization name.
    pub name: String,
    /// Effective role of the active account.
    pub role: OrganizationRole,
}

/// Collection label and effective access safe to expose to the desktop webview.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationCollectionSummary {
    /// Stable collection ID.
    pub id: Uuid,
    /// Owning organization ID.
    pub organization_id: Uuid,
    /// Server-visible collection name.
    pub name: String,
    /// Whether official clients must reject edits through this collection.
    pub read_only: bool,
    /// Whether official clients should conceal password display and copying.
    pub hide_passwords: bool,
    /// Whether this member may manage collection access.
    pub manage: bool,
}

/// RFC 6238 code and countdown.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpView {
    /// Zero-padded one-time code.
    pub code: String,
    /// Seconds until the next code period.
    pub remaining_seconds: u64,
}

/// A login selected by the Android system autofill and credential-provider bridges.
///
/// This is intentionally only available from the native client coordinator after it has
/// unlocked the shared encrypted vault. It is never persisted separately and is not exposed
/// through the ordinary Tauri webview command surface.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutofillCandidate {
    /// Stable vault item identifier used for an explicit save / selection flow.
    pub id: Uuid,
    /// Non-secret label shown in the Android system selector.
    pub name: String,
    /// Login user name, when stored.
    pub username: Option<String>,
    /// Login password returned only after Android user verification.
    pub password: Option<String>,
    /// Current TOTP code returned only after Android user verification.
    pub totp: Option<String>,
}

/// Non-secret passkey selector record for Android Credential Manager.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialPasskeyCandidate {
    /// Encrypted vault item that owns the credential.
    pub item_id: Uuid,
    /// `WebAuthn` base64url credential ID.
    pub credential_id: String,
    /// Relying party identifier.
    pub rp_id: String,
    /// RP-scoped account name when available.
    pub user_name: Option<String>,
    /// Safe selector label.
    pub display_name: String,
}

/// Summary returned after a compatibility import.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportSummary {
    /// Number of imported items.
    pub item_count: usize,
    /// Number of imported folders.
    pub folder_count: usize,
    /// Number of imported collections.
    pub collection_count: usize,
}

/// Result of a metadata-first encrypted attachment removal.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentRemoval {
    /// Updated decrypted item for the explicit detail view.
    pub item: VaultItem,
    /// Whether opaque server storage cleanup remains durably queued.
    pub cleanup_pending: bool,
}

/// Non-secret account-security state used by the native settings surface.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSecuritySnapshot {
    /// Configured second factors and public account-passkey labels.
    pub mfa: MfaStatusResponse,
    /// Revocable authenticated sessions.
    pub sessions: Vec<SessionResponse>,
    /// Known devices and their trusted-device state.
    pub devices: Vec<DeviceResponse>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PendingAttachmentDeletion {
    id: Uuid,
    object_id: Uuid,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CachedProfile {
    scope: String,
    server_url: String,
    email: String,
    account_id: Uuid,
    device_identifier: Uuid,
    kdf: KdfSettings,
    protected_user_key: String,
    replica: Replica,
    #[serde(default)]
    folders: Vec<BitwardenFolder>,
    #[serde(default)]
    collections: Vec<BitwardenCollection>,
    #[serde(default)]
    sharing_key: Option<SharingKeyResponse>,
    #[serde(default)]
    organizations: Vec<OrganizationResponse>,
    #[serde(default)]
    organization_collections: Vec<CollectionResponse>,
    #[serde(default)]
    pending_attachment_deletions: Vec<PendingAttachmentDeletion>,
    last_sync_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CacheDocument {
    version: u32,
    #[serde(default = "default_auto_lock_minutes")]
    auto_lock_minutes: u32,
    active_scope: Option<String>,
    #[serde(default)]
    profiles: Vec<CachedProfile>,
}

impl Default for CacheDocument {
    fn default() -> Self {
        Self {
            version: CACHE_VERSION,
            auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES,
            active_scope: None,
            profiles: Vec::new(),
        }
    }
}

struct UnlockedVault {
    user_key: CompositeKey,
    sharing_private_key: Option<SharingPrivateKey>,
    organization_keys: BTreeMap<Uuid, CompositeKey>,
    items: BTreeMap<Uuid, VaultItem>,
    folders: Vec<BitwardenFolder>,
}

/// A server-issued, one-use account-passkey ceremony. It contains no master-password material
/// and is dropped after completion, expiry, logout, or a vault lock.
struct PendingAccountPasskeyLogin {
    ceremony_id: Uuid,
    expires_at: DateTime<Utc>,
    server_url: String,
    email: String,
    device_identifier: Uuid,
    api: ApiClient,
}

/// Full native client coordinator. The Tauri shell owns this behind one async mutex.
pub struct DesktopClient {
    cache_path: PathBuf,
    document: CacheDocument,
    active: Option<usize>,
    api: Option<ApiClient>,
    session: Option<TokenResponse>,
    pending_account_passkey_login: Option<PendingAccountPasskeyLogin>,
    vault: Option<UnlockedVault>,
    secret_store: Arc<dyn SecretStore>,
    online: bool,
    last_activity: Instant,
}

impl DesktopClient {
    /// Loads the ciphertext-only cache and starts in a locked state.
    ///
    /// # Errors
    ///
    /// Returns [`DesktopError::Cache`] for oversized or malformed durable state.
    pub fn open(
        cache_path: impl Into<PathBuf>,
        secret_store: Arc<dyn SecretStore>,
    ) -> Result<Self, DesktopError> {
        let cache_path = cache_path.into();
        let document = load_document(&cache_path)?;
        let active = document.active_scope.as_ref().and_then(|scope| {
            document
                .profiles
                .iter()
                .position(|profile| &profile.scope == scope)
        });
        Ok(Self {
            cache_path,
            document,
            active,
            api: None,
            session: None,
            pending_account_passkey_login: None,
            vault: None,
            secret_store,
            online: false,
            last_activity: Instant::now(),
        })
    }

    /// Returns a secret-free snapshot for initial rendering and status refreshes.
    #[must_use]
    pub fn status(&self) -> DesktopStatus {
        let profile = self
            .active
            .and_then(|index| self.document.profiles.get(index));
        let active_scope = profile.map(|value| value.scope.as_str());
        DesktopStatus {
            unlocked: self.vault.is_some(),
            online: self.online,
            server_url: profile.map(|value| value.server_url.clone()),
            email: profile.map(|value| value.email.clone()),
            item_count: self.vault.as_ref().map_or(0, |vault| vault.items.len()),
            pending_count: profile.map_or(0, |value| value.replica.outbox().len()),
            conflict_count: profile.map_or(0, |value| value.replica.conflicts().len()),
            auto_lock_minutes: self.document.auto_lock_minutes,
            last_sync_at: profile.and_then(|value| value.last_sync_at),
            profiles: self
                .document
                .profiles
                .iter()
                .map(|value| ProfileSummary {
                    scope: value.scope.clone(),
                    server_url: value.server_url.clone(),
                    email: value.email.clone(),
                    active: Some(value.scope.as_str()) == active_scope,
                })
                .collect(),
        }
    }

    /// Registers and unlocks a new account without sending the master password.
    pub async fn register(
        &mut self,
        server_url: String,
        email: String,
        mut master_password: String,
    ) -> Result<DesktopStatus, DesktopError> {
        let result = self
            .register_inner(server_url, email, &master_password)
            .await;
        master_password.zeroize();
        result
    }

    /// Authenticates online, or unlocks a previously synchronized profile offline.
    pub async fn login(
        &mut self,
        server_url: String,
        email: String,
        mut master_password: String,
        totp_code: Option<String>,
        recovery_code: Option<String>,
    ) -> Result<DesktopStatus, DesktopError> {
        let result = self
            .login_inner(
                server_url,
                email,
                &master_password,
                totp_code,
                recovery_code,
            )
            .await;
        master_password.zeroize();
        result
    }

    /// Starts an account-passkey login using the existing server `WebAuthn` ceremony.
    ///
    /// This authenticates the account with Credential Manager while the master password remains
    /// needed locally to unwrap the zero-knowledge vault key after the ceremony succeeds.
    pub async fn begin_account_passkey_login(
        &mut self,
        server_url: String,
        email: String,
        device: DeviceRequest,
    ) -> Result<WebauthnChallengeResponse, DesktopError> {
        let (server_url, api) = canonical_server(&server_url)?;
        let email = normalize_email(&email)?;
        let device_identifier = self
            .find_profile(&server_url, &email)
            .map_or(device.identifier, |index| {
                self.document.profiles[index].device_identifier
            });
        let device = DeviceRequest {
            identifier: device_identifier,
            name: device.name,
            device_type: device.device_type,
        };
        let challenge = api
            .start_passkey_login(&PasskeyLoginStartRequest {
                email: email.clone(),
                device,
            })
            .await
            .map_err(map_client_error)?;
        self.pending_account_passkey_login = Some(PendingAccountPasskeyLogin {
            ceremony_id: challenge.ceremony_id,
            expires_at: challenge.expires_at,
            server_url,
            email,
            device_identifier,
            api,
        });
        Ok(challenge)
    }

    /// Completes the one-use passkey ceremony then unlocks the vault locally with the supplied
    /// master password. The password is never included in the server request.
    pub async fn finish_account_passkey_login(
        &mut self,
        ceremony_id: Uuid,
        credential: Value,
        mut master_password: String,
    ) -> Result<DesktopStatus, DesktopError> {
        let result = self
            .finish_account_passkey_login_inner(ceremony_id, credential, &master_password)
            .await;
        master_password.zeroize();
        result
    }

    async fn finish_account_passkey_login_inner(
        &mut self,
        ceremony_id: Uuid,
        credential: Value,
        master_password: &str,
    ) -> Result<DesktopStatus, DesktopError> {
        if master_password.is_empty()
            || master_password.len() > 16_384
            || credential_size(&credential)? > 262_144
        {
            return Err(DesktopError::InvalidInput);
        }
        let pending = self
            .pending_account_passkey_login
            .take()
            .filter(|pending| pending.ceremony_id == ceremony_id && pending.expires_at > Utc::now())
            .ok_or(DesktopError::AuthenticationRequired)?;
        let token = pending
            .api
            .finish_webauthn_login(&WebauthnLoginFinishRequest {
                ceremony_id,
                credential,
                remember_device: false,
            })
            .await
            .map_err(map_client_error)?;
        let prepared = prepare_login(
            &pending.email,
            master_password.as_bytes(),
            &kdf_config(&token.kdf)?,
        )
        .map_err(|_| DesktopError::Crypto)?;
        let user_key = prepared
            .finish(&token.protected_user_key)
            .map_err(|_| DesktopError::UnlockFailed)?;
        let cached_index = self.find_profile(&pending.server_url, &pending.email);
        let replica = cached_index
            .map(|index| self.document.profiles[index].replica.clone())
            .unwrap_or_default();
        let index = self.upsert_profile(
            pending.server_url,
            pending.email,
            pending.device_identifier,
            &token,
            replica,
        )?;
        self.activate_online(index, pending.api, token, user_key)?;
        self.persist()?;
        self.sync_now().await
    }

    /// Fetches revocable account sessions, known devices, and public MFA/passkey metadata.
    pub async fn account_security_snapshot(
        &mut self,
    ) -> Result<AccountSecuritySnapshot, DesktopError> {
        let (api, access) = self.account_api_access().await?;
        let mfa = api
            .account_security(&access)
            .await
            .map_err(map_client_error)?;
        let sessions = api.sessions(&access).await.map_err(map_client_error)?;
        let devices = api.devices(&access).await.map_err(map_client_error)?;
        Ok(AccountSecuritySnapshot {
            mfa,
            sessions,
            devices,
        })
    }

    /// Starts TOTP account-factor enrollment after deriving a local reauthentication proof.
    pub async fn start_account_totp_setup(
        &mut self,
        mut master_password: String,
    ) -> Result<TotpSetupStartResponse, DesktopError> {
        let proof = self.reauthentication_request(&master_password);
        master_password.zeroize();
        let (api, access) = self.account_api_access().await?;
        api.start_totp_setup(&access, &proof?)
            .await
            .map_err(map_client_error)
    }

    /// Confirms the current authenticator code and returns one-time recovery codes if created.
    pub async fn finish_account_totp_setup(
        &mut self,
        setup_id: Uuid,
        code: String,
    ) -> Result<MfaEnableResponse, DesktopError> {
        if code.trim().len() > 32 {
            return Err(DesktopError::InvalidInput);
        }
        let (api, access) = self.account_api_access().await?;
        api.finish_totp_setup(&access, &TotpSetupFinishRequest { setup_id, code })
            .await
            .map_err(map_client_error)
    }

    /// Disables the account TOTP factor after a local reauthentication proof.
    pub async fn disable_account_totp(
        &mut self,
        mut master_password: String,
    ) -> Result<(), DesktopError> {
        let proof = self.reauthentication_request(&master_password);
        master_password.zeroize();
        let (api, access) = self.account_api_access().await?;
        api.disable_totp(&access, &proof?)
            .await
            .map_err(map_client_error)
    }

    /// Replaces every account recovery code after a local reauthentication proof.
    pub async fn rotate_account_recovery_codes(
        &mut self,
        mut master_password: String,
    ) -> Result<RecoveryCodesResponse, DesktopError> {
        let proof = self.reauthentication_request(&master_password);
        master_password.zeroize();
        let (api, access) = self.account_api_access().await?;
        api.rotate_recovery_codes(&access, &proof?)
            .await
            .map_err(map_client_error)
    }

    /// Starts an account passkey registration ceremony after local reauthentication.
    pub async fn start_account_passkey_registration(
        &mut self,
        mut master_password: String,
        name: String,
    ) -> Result<WebauthnChallengeResponse, DesktopError> {
        if name.trim().is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
            master_password.zeroize();
            return Err(DesktopError::InvalidInput);
        }
        let proof = self.reauthentication_request(&master_password);
        master_password.zeroize();
        let (api, access) = self.account_api_access().await?;
        api.start_webauthn_registration(
            &access,
            &WebauthnRegistrationStartRequest {
                auth_proof: proof?.auth_proof,
                name: name.trim().to_owned(),
            },
        )
        .await
        .map_err(map_client_error)
    }

    /// Finishes account passkey registration with the raw Credential Manager response.
    pub async fn finish_account_passkey_registration(
        &mut self,
        ceremony_id: Uuid,
        credential: Value,
    ) -> Result<MfaEnableResponse, DesktopError> {
        if credential_size(&credential)? > 262_144 {
            return Err(DesktopError::InvalidInput);
        }
        let (api, access) = self.account_api_access().await?;
        api.finish_webauthn_registration(
            &access,
            &WebauthnRegistrationFinishRequest {
                ceremony_id,
                credential,
            },
        )
        .await
        .map_err(map_client_error)
    }

    /// Removes a public account passkey record and revokes remembered-device grants server-side.
    pub async fn remove_account_passkey(&mut self, id: Uuid) -> Result<(), DesktopError> {
        let (api, access) = self.account_api_access().await?;
        api.delete_webauthn_credential(&access, id)
            .await
            .map_err(map_client_error)
    }

    /// Revokes a remembered-device MFA bypass grant.
    pub async fn revoke_account_device_trust(&mut self, id: Uuid) -> Result<(), DesktopError> {
        let (api, access) = self.account_api_access().await?;
        api.revoke_device_trust(&access, id)
            .await
            .map_err(map_client_error)
    }

    /// Revokes an account session. Revoking this session also clears its local refresh credential
    /// and immediately drops the decrypted vault.
    pub async fn revoke_account_session(
        &mut self,
        id: Uuid,
    ) -> Result<DesktopStatus, DesktopError> {
        let (api, access) = self.account_api_access().await?;
        api.revoke_session(&access, id)
            .await
            .map_err(map_client_error)?;
        if self
            .session
            .as_ref()
            .is_some_and(|session| session.session_id == id)
        {
            if let Some(profile) = self.active_profile() {
                self.secret_store.delete(&refresh_secret_key(profile))?;
            }
            return Ok(self.lock());
        }
        Ok(self.status())
    }

    /// Removes every decrypted item and key from memory without deleting ciphertext.
    pub fn lock(&mut self) -> DesktopStatus {
        self.vault = None;
        self.session = None;
        self.pending_account_passkey_login = None;
        self.online = false;
        self.last_activity = Instant::now();
        self.status()
    }

    /// Returns the current in-memory user key for an operating-system biometric wrapper.
    ///
    /// Callers must keep the returned bytes transient and wrap them immediately with a
    /// hardware-backed, user-authentication-bound operating-system key. The desktop shell has
    /// no caller for this API; it exists for the Android Keystore bridge only.
    pub fn biometric_unlock_key(&mut self) -> Result<[u8; 64], DesktopError> {
        self.touch();
        Ok(*self.require_unlocked()?.user_key.as_bytes())
    }

    /// Unlocks the active encrypted cache with a key that has just been released by the
    /// platform biometric wrapper.
    ///
    /// No network session is restored here. This is deliberately offline-only: the cache is
    /// still authenticated and decrypted by the existing Rust vault implementation, while any
    /// access-token refresh continues to require the normal online authentication path.
    pub fn unlock_with_biometric_key(&mut self, key: &[u8]) -> Result<DesktopStatus, DesktopError> {
        if self.vault.is_some() {
            self.touch();
            return Ok(self.status());
        }
        let profile = self.active_profile().ok_or(DesktopError::NotFound)?;
        let api = ApiClient::new(&profile.server_url).map_err(map_client_error)?;
        let user_key = CompositeKey::from_slice(key).map_err(|_| DesktopError::Crypto)?;
        self.api = Some(api);
        self.session = None;
        self.online = false;
        self.load_unlocked(user_key)?;
        self.touch();
        Ok(self.status())
    }

    /// Revokes the current session when online, deletes its keychain refresh token, and locks.
    pub async fn logout(&mut self) -> Result<DesktopStatus, DesktopError> {
        if let (Some(api), Some(session)) = (&self.api, &self.session) {
            api.logout(&session.access_token, Some(session.refresh_token.clone()))
                .await
                .map_err(map_client_error)?;
        }
        if let Some(profile) = self.active_profile() {
            self.secret_store.delete(&refresh_secret_key(profile))?;
        }
        Ok(self.lock())
    }

    /// Updates activity used by the native automatic-lock monitor.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Locks when the configured idle interval has elapsed.
    pub fn lock_if_idle(&mut self) -> bool {
        if self.vault.is_none() {
            return false;
        }
        let duration = Duration::from_secs(u64::from(self.document.auto_lock_minutes) * 60);
        if self.last_activity.elapsed() >= duration {
            self.lock();
            true
        } else {
            false
        }
    }

    /// Persists a bounded automatic-lock delay.
    pub fn set_auto_lock_minutes(&mut self, minutes: u32) -> Result<DesktopStatus, DesktopError> {
        if !(1..=240).contains(&minutes) {
            return Err(DesktopError::InvalidInput);
        }
        self.document.auto_lock_minutes = minutes;
        self.persist()?;
        self.touch();
        Ok(self.status())
    }

    async fn register_inner(
        &mut self,
        server_url: String,
        email: String,
        master_password: &str,
    ) -> Result<DesktopStatus, DesktopError> {
        if master_password.len() < 12 || master_password.len() > 16_384 {
            return Err(DesktopError::InvalidInput);
        }
        let (server_url, api) = canonical_server(&server_url)?;
        let email = normalize_email(&email)?;
        let kdf = KdfSettings::default();
        let prepared = prepare_registration(&email, master_password.as_bytes(), &kdf_config(&kdf)?)
            .map_err(|_| DesktopError::Crypto)?;
        let device_identifier = self
            .find_profile(&server_url, &email)
            .map_or_else(Uuid::new_v4, |index| {
                self.document.profiles[index].device_identifier
            });
        let device = desktop_device(device_identifier);
        let auth_proof = STANDARD.encode(prepared.authentication_proof);
        api.register(&RegisterRequest {
            email: email.clone(),
            auth_proof: auth_proof.clone(),
            protected_user_key: prepared.protected_user_key.clone(),
            kdf: kdf.clone(),
            device: device.clone(),
        })
        .await
        .map_err(map_client_error)?;
        let token = api
            .login(&LoginRequest {
                email: email.clone(),
                auth_proof,
                device,
                totp_code: None,
                recovery_code: None,
                trusted_device_token: None,
                remember_device: false,
            })
            .await
            .map_err(map_client_error)?;

        let index = self.upsert_profile(
            server_url,
            email,
            device_identifier,
            &token,
            Replica::default(),
        )?;
        self.activate_online(index, api, token, prepared.user_key)?;
        self.persist()?;
        self.sync_now().await
    }

    async fn login_inner(
        &mut self,
        server_url: String,
        email: String,
        master_password: &str,
        totp_code: Option<String>,
        recovery_code: Option<String>,
    ) -> Result<DesktopStatus, DesktopError> {
        if master_password.is_empty() || master_password.len() > 16_384 {
            return Err(DesktopError::InvalidInput);
        }
        let (server_url, api) = canonical_server(&server_url)?;
        let email = normalize_email(&email)?;
        let totp_code = normalize_optional(totp_code);
        let recovery_code = normalize_optional(recovery_code);
        if totp_code.is_some() && recovery_code.is_some() {
            return Err(DesktopError::InvalidInput);
        }
        let cached_index = self.find_profile(&server_url, &email);
        let prelogin = api
            .prelogin(&PreloginRequest {
                email: email.clone(),
            })
            .await;
        let kdf = match prelogin {
            Ok(response) => response.kdf,
            Err(ClientError::Network(_)) => {
                return self.unlock_offline(cached_index, api, master_password);
            }
            Err(error) => return Err(map_client_error(error)),
        };
        let prepared = prepare_login(&email, master_password.as_bytes(), &kdf_config(&kdf)?)
            .map_err(|_| DesktopError::Crypto)?;
        let device_identifier = cached_index.map_or_else(Uuid::new_v4, |index| {
            self.document.profiles[index].device_identifier
        });
        let token = match api
            .login(&LoginRequest {
                email: email.clone(),
                auth_proof: STANDARD.encode(prepared.authentication_proof),
                device: desktop_device(device_identifier),
                totp_code,
                recovery_code,
                trusted_device_token: None,
                remember_device: false,
            })
            .await
        {
            Ok(token) => token,
            Err(ClientError::Network(_)) => {
                return self.unlock_offline(cached_index, api, master_password);
            }
            Err(error) => return Err(map_client_error(error)),
        };
        let user_key = prepared
            .finish(&token.protected_user_key)
            .map_err(|_| DesktopError::UnlockFailed)?;
        let replica = cached_index
            .map(|index| self.document.profiles[index].replica.clone())
            .unwrap_or_default();
        let index = self.upsert_profile(server_url, email, device_identifier, &token, replica)?;
        self.activate_online(index, api, token, user_key)?;
        self.persist()?;
        self.sync_now().await
    }

    fn unlock_offline(
        &mut self,
        cached_index: Option<usize>,
        api: ApiClient,
        master_password: &str,
    ) -> Result<DesktopStatus, DesktopError> {
        let index = cached_index.ok_or(DesktopError::Offline)?;
        let profile = &self.document.profiles[index];
        let prepared = prepare_login(
            &profile.email,
            master_password.as_bytes(),
            &kdf_config(&profile.kdf)?,
        )
        .map_err(|_| DesktopError::UnlockFailed)?;
        let user_key = prepared
            .finish(&profile.protected_user_key)
            .map_err(|_| DesktopError::UnlockFailed)?;
        self.active = Some(index);
        self.document.active_scope = Some(profile.scope.clone());
        self.api = Some(api);
        self.session = None;
        self.online = false;
        self.load_unlocked(user_key)?;
        self.touch();
        self.persist()?;
        Ok(self.status())
    }

    fn upsert_profile(
        &mut self,
        server_url: String,
        email: String,
        device_identifier: Uuid,
        token: &TokenResponse,
        replica: Replica,
    ) -> Result<usize, DesktopError> {
        let scope = profile_scope(&server_url, &email);
        let profile = CachedProfile {
            scope: scope.clone(),
            server_url,
            email,
            account_id: token.account_id,
            device_identifier,
            kdf: token.kdf.clone(),
            protected_user_key: token.protected_user_key.clone(),
            replica,
            folders: Vec::new(),
            collections: Vec::new(),
            sharing_key: None,
            organizations: Vec::new(),
            organization_collections: Vec::new(),
            pending_attachment_deletions: Vec::new(),
            last_sync_at: None,
        };
        let index = if let Some(index) = self
            .document
            .profiles
            .iter()
            .position(|existing| existing.scope == scope)
        {
            let folders = std::mem::take(&mut self.document.profiles[index].folders);
            let collections = std::mem::take(&mut self.document.profiles[index].collections);
            let sharing_key = self.document.profiles[index].sharing_key.take();
            let organizations = std::mem::take(&mut self.document.profiles[index].organizations);
            let organization_collections =
                std::mem::take(&mut self.document.profiles[index].organization_collections);
            let pending_attachment_deletions =
                std::mem::take(&mut self.document.profiles[index].pending_attachment_deletions);
            let last_sync_at = self.document.profiles[index].last_sync_at;
            self.document.profiles[index] = CachedProfile {
                folders,
                collections,
                sharing_key,
                organizations,
                organization_collections,
                pending_attachment_deletions,
                last_sync_at,
                ..profile
            };
            index
        } else {
            if self.document.profiles.len() >= MAX_PROFILES {
                return Err(DesktopError::Cache);
            }
            self.document.profiles.push(profile);
            self.document.profiles.len() - 1
        };
        self.document.active_scope = Some(scope);
        Ok(index)
    }

    fn activate_online(
        &mut self,
        index: usize,
        api: ApiClient,
        token: TokenResponse,
        user_key: CompositeKey,
    ) -> Result<(), DesktopError> {
        self.active = Some(index);
        self.document.active_scope = Some(self.document.profiles[index].scope.clone());
        self.store_session_secrets(index, &token)?;
        self.api = Some(api);
        self.session = Some(token);
        self.online = true;
        self.load_unlocked(user_key)?;
        self.touch();
        Ok(())
    }

    fn store_session_secrets(
        &self,
        profile_index: usize,
        token: &TokenResponse,
    ) -> Result<(), DesktopError> {
        let profile = &self.document.profiles[profile_index];
        self.secret_store
            .set(&refresh_secret_key(profile), token.refresh_token.as_bytes())?;
        let device_key = device_secret_key(profile);
        if self.secret_store.get(&device_key)?.is_none() {
            let mut secret = [0_u8; 32];
            getrandom::fill(&mut secret).map_err(|_| DesktopError::Crypto)?;
            let result = self.secret_store.set(&device_key, &secret);
            secret.zeroize();
            result?;
        }
        Ok(())
    }

    fn load_unlocked(&mut self, user_key: CompositeKey) -> Result<(), DesktopError> {
        let profile = self.active_profile().ok_or(DesktopError::NotFound)?;
        let (sharing_private_key, organization_keys) =
            open_cached_organization_keys(profile, &user_key)?;
        let (items, mut folders) =
            decrypt_replica(&profile.replica, &user_key, &organization_keys)?;
        // Pre-folder-object desktop caches retained imported folder labels separately. Keep only
        // IDs that have never acquired a Folder object: an authoritative tombstone must not be
        // resurrected from the legacy projection after an upgrade.
        let legacy_folders = profile
            .folders
            .iter()
            .filter(|folder| {
                !profile
                    .replica
                    .objects()
                    .get(&folder.id)
                    .is_some_and(|object| object.kind == ObjectKind::Folder)
            })
            .cloned()
            .collect();
        merge_by_id(&mut folders, legacy_folders, |folder| folder.id);
        self.vault = Some(UnlockedVault {
            user_key,
            sharing_private_key,
            organization_keys,
            items,
            folders,
        });
        Ok(())
    }

    /// Pulls ordered changes, flushes durable encrypted mutations, then pulls acknowledgements.
    /// Network failure keeps the vault usable and every mutation queued.
    pub async fn sync_now(&mut self) -> Result<DesktopStatus, DesktopError> {
        self.require_unlocked()?;
        let result = self.sync_online().await;
        match result {
            Ok(()) => self.online = true,
            Err(DesktopError::Offline | DesktopError::AuthenticationRequired) => {
                self.online = false;
                self.persist()?;
                self.touch();
                return Ok(self.status());
            }
            Err(error) => return Err(error),
        }
        self.touch();
        Ok(self.status())
    }

    async fn sync_online(&mut self) -> Result<(), DesktopError> {
        if self.session.is_none() {
            self.rotate_session().await?;
        }
        self.refresh_organization_keys().await?;
        self.pull_pages().await?;
        self.flush_outbox().await?;
        self.flush_attachment_deletions().await?;
        self.pull_pages().await?;
        if let Some(profile) = self.active_profile_mut() {
            profile.last_sync_at = Some(Utc::now());
        }
        self.persist()?;
        self.reload_unlocked()?;
        Ok(())
    }

    async fn refresh_organization_keys(&mut self) -> Result<(), DesktopError> {
        let api = self.api.clone().ok_or(DesktopError::Offline)?;
        let mut access = self
            .session
            .as_ref()
            .map(|session| session.access_token.clone())
            .ok_or(DesktopError::AuthenticationRequired)?;
        let mut sharing_result = api.sharing_key(&access).await;
        if sharing_result.as_ref().is_err_and(is_unauthorized) {
            self.rotate_session().await?;
            access = self
                .session
                .as_ref()
                .map(|session| session.access_token.clone())
                .ok_or(DesktopError::AuthenticationRequired)?;
            sharing_result = api.sharing_key(&access).await;
        }
        let user_key = self.require_unlocked()?.user_key.clone();
        let sharing_key = match sharing_result {
            Ok(response) => response,
            Err(ClientError::Api { code, .. }) if code == "sharing_key_not_found" => {
                let material = generate_sharing_key(&user_key).map_err(|_| DesktopError::Crypto)?;
                match api
                    .put_sharing_key(
                        &access,
                        &SharingKeyRequest {
                            public_key: material.public_key,
                            protected_private_key: material.protected_private_key,
                        },
                    )
                    .await
                {
                    Ok(response) => response,
                    Err(ClientError::Api { code, .. }) if code == "sharing_key_exists" => {
                        api.sharing_key(&access).await.map_err(map_client_error)?
                    }
                    Err(error) => return Err(map_client_error(error)),
                }
            }
            Err(error) => return Err(map_client_error(error)),
        };
        let protected_private_key = sharing_key
            .protected_private_key
            .as_deref()
            .ok_or(DesktopError::Crypto)?;
        let private_key =
            unwrap_sharing_private_key(&sharing_key.public_key, protected_private_key, &user_key)
                .map_err(|_| DesktopError::Crypto)?;
        let organizations = api.organizations(&access).await.map_err(map_client_error)?;
        let mut organization_keys = BTreeMap::new();
        let mut organization_collections = Vec::new();
        for organization in &organizations {
            if matches!(
                organization.status,
                MembershipStatus::Accepted | MembershipStatus::Confirmed
            ) {
                let wrapper = organization
                    .encrypted_organization_key
                    .as_deref()
                    .ok_or(DesktopError::Crypto)?;
                let key = open_organization_key(&private_key, organization.id, wrapper)
                    .map_err(|_| DesktopError::Crypto)?;
                organization_keys.insert(organization.id, key);
            }
            if organization.status == MembershipStatus::Confirmed {
                organization_collections.extend(
                    api.collections(&access, organization.id)
                        .await
                        .map_err(map_client_error)?,
                );
            }
        }
        let vault = self.require_unlocked_mut()?;
        vault.sharing_private_key = Some(private_key);
        vault.organization_keys = organization_keys;
        let profile = self.active_profile_mut().ok_or(DesktopError::NotFound)?;
        profile.sharing_key = Some(sharing_key);
        profile.organizations = organizations;
        profile.organization_collections = organization_collections;
        Ok(())
    }

    async fn pull_pages(&mut self) -> Result<(), DesktopError> {
        for _ in 0..1_000 {
            let cursor = self
                .active_profile()
                .and_then(|profile| profile.replica.cursor().map(str::to_owned));
            let page = self.fetch_sync(cursor.as_deref()).await?;
            let has_more = page.has_more;
            self.active_profile_mut()
                .ok_or(DesktopError::NotFound)?
                .replica
                .apply_page(&page)
                .map_err(|_| DesktopError::Sync)?;
            self.persist()?;
            self.reload_unlocked()?;
            if !has_more {
                return Ok(());
            }
        }
        Err(DesktopError::Sync)
    }

    async fn fetch_sync(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<hasilan_protocol::SyncResponse, DesktopError> {
        let api = self.api.clone().ok_or(DesktopError::Offline)?;
        let access = self
            .session
            .as_ref()
            .map(|session| session.access_token.clone())
            .ok_or(DesktopError::AuthenticationRequired)?;
        match api.sync(&access, cursor, 500).await {
            Ok(page) => Ok(page),
            Err(error) if is_unauthorized(&error) => {
                self.rotate_session().await?;
                let access = self
                    .session
                    .as_ref()
                    .map(|session| session.access_token.clone())
                    .ok_or(DesktopError::AuthenticationRequired)?;
                api.sync(&access, cursor, 500)
                    .await
                    .map_err(map_client_error)
            }
            Err(error) => Err(map_client_error(error)),
        }
    }

    async fn rotate_session(&mut self) -> Result<(), DesktopError> {
        let profile = self.active_profile().ok_or(DesktopError::NotFound)?;
        let refresh_key = refresh_secret_key(profile);
        let mut refresh_token = self
            .session
            .as_ref()
            .map(|session| session.refresh_token.clone())
            .or_else(|| {
                self.secret_store
                    .get(&refresh_key)
                    .ok()
                    .flatten()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
            })
            .ok_or(DesktopError::AuthenticationRequired)?;
        let api = self.api.clone().ok_or(DesktopError::Offline)?;
        let result = api.refresh(refresh_token.clone()).await;
        refresh_token.zeroize();
        let token = result.map_err(map_client_error)?;
        let index = self.active.ok_or(DesktopError::NotFound)?;
        self.document.profiles[index]
            .protected_user_key
            .clone_from(&token.protected_user_key);
        self.document.profiles[index].kdf = token.kdf.clone();
        self.store_session_secrets(index, &token)?;
        self.session = Some(token);
        Ok(())
    }

    async fn flush_outbox(&mut self) -> Result<(), DesktopError> {
        let pending: Vec<PendingMutation> = self
            .active_profile()
            .ok_or(DesktopError::NotFound)?
            .replica
            .outbox()
            .iter()
            .cloned()
            .collect();
        let conflicted: BTreeSet<Uuid> = self
            .active_profile()
            .ok_or(DesktopError::NotFound)?
            .replica
            .conflicts()
            .keys()
            .copied()
            .collect();
        for mutation in pending {
            if conflicted.contains(&mutation.object.id) {
                continue;
            }
            match self.upload_mutation(&mutation).await {
                Ok(authoritative) => {
                    self.active_profile_mut()
                        .ok_or(DesktopError::NotFound)?
                        .replica
                        .acknowledge(mutation.idempotency_key, authoritative)
                        .map_err(|_| DesktopError::Sync)?;
                    self.persist()?;
                }
                Err(DesktopError::Server(code)) if code == "revision_conflict" => {
                    let current = self.fetch_object(mutation.object.id).await?;
                    self.active_profile_mut()
                        .ok_or(DesktopError::NotFound)?
                        .replica
                        .record_upload_conflict(current);
                    self.persist()?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    async fn flush_attachment_deletions(&mut self) -> Result<(), DesktopError> {
        let pending = self
            .active_profile()
            .ok_or(DesktopError::NotFound)?
            .pending_attachment_deletions
            .clone();
        for deletion in pending {
            let ready = self.active_profile().is_some_and(|profile| {
                !profile
                    .replica
                    .outbox()
                    .iter()
                    .any(|mutation| mutation.object.id == deletion.object_id)
                    && !profile
                        .replica
                        .conflicts()
                        .contains_key(&deletion.object_id)
            }) && self
                .require_unlocked()?
                .items
                .get(&deletion.object_id)
                .is_some_and(|item| {
                    !item
                        .attachments
                        .iter()
                        .any(|attachment| attachment.id == deletion.id)
                });
            if !ready {
                continue;
            }
            self.delete_attachment_online(deletion.id).await?;
            self.active_profile_mut()
                .ok_or(DesktopError::NotFound)?
                .pending_attachment_deletions
                .retain(|pending| pending.id != deletion.id);
            self.persist()?;
        }
        Ok(())
    }

    async fn upload_mutation(
        &mut self,
        mutation: &PendingMutation,
    ) -> Result<EncryptedObject, DesktopError> {
        let api = self.api.clone().ok_or(DesktopError::Offline)?;
        let access = self
            .session
            .as_ref()
            .map(|session| session.access_token.clone())
            .ok_or(DesktopError::AuthenticationRequired)?;
        let first = if mutation.delete {
            let base_revision = mutation.base_revision.ok_or(DesktopError::Sync)?;
            api.delete_object(
                &access,
                mutation.object.id,
                &DeleteObjectRequest {
                    base_revision,
                    idempotency_key: mutation.idempotency_key,
                },
            )
            .await
        } else {
            api.put_object(&access, mutation.object.id, &put_request(mutation))
                .await
        };
        match first {
            Ok(object) => Ok(object),
            Err(error) if is_unauthorized(&error) => {
                self.rotate_session().await?;
                let access = self
                    .session
                    .as_ref()
                    .map(|session| session.access_token.clone())
                    .ok_or(DesktopError::AuthenticationRequired)?;
                if mutation.delete {
                    api.delete_object(
                        &access,
                        mutation.object.id,
                        &DeleteObjectRequest {
                            base_revision: mutation.base_revision.ok_or(DesktopError::Sync)?,
                            idempotency_key: mutation.idempotency_key,
                        },
                    )
                    .await
                    .map_err(map_client_error)
                } else {
                    api.put_object(&access, mutation.object.id, &put_request(mutation))
                        .await
                        .map_err(map_client_error)
                }
            }
            Err(error) => Err(map_client_error(error)),
        }
    }

    async fn fetch_object(&mut self, id: Uuid) -> Result<EncryptedObject, DesktopError> {
        let api = self.api.clone().ok_or(DesktopError::Offline)?;
        let access = self
            .session
            .as_ref()
            .map(|session| session.access_token.clone())
            .ok_or(DesktopError::AuthenticationRequired)?;
        match api.get_object(&access, id).await {
            Ok(object) => Ok(object),
            Err(error) if is_unauthorized(&error) => {
                self.rotate_session().await?;
                let access = self
                    .session
                    .as_ref()
                    .map(|session| session.access_token.clone())
                    .ok_or(DesktopError::AuthenticationRequired)?;
                api.get_object(&access, id).await.map_err(map_client_error)
            }
            Err(error) => Err(map_client_error(error)),
        }
    }

    async fn attachment_api_access(&mut self) -> Result<(ApiClient, String), DesktopError> {
        if self.session.is_none() {
            self.rotate_session().await?;
        }
        let api = self.api.clone().ok_or(DesktopError::Offline)?;
        let access = self
            .session
            .as_ref()
            .map(|session| session.access_token.clone())
            .ok_or(DesktopError::AuthenticationRequired)?;
        Ok((api, access))
    }

    /// Obtains an authenticated account-management transport. Security changes are available
    /// only while the local vault is unlocked, so an access token alone cannot become a second
    /// UI path around the lock boundary.
    async fn account_api_access(&mut self) -> Result<(ApiClient, String), DesktopError> {
        self.require_unlocked()?;
        self.attachment_api_access().await
    }

    fn reauthentication_request(
        &self,
        master_password: &str,
    ) -> Result<ReauthenticationRequest, DesktopError> {
        self.require_unlocked()?;
        if master_password.is_empty() || master_password.len() > 16_384 {
            return Err(DesktopError::InvalidInput);
        }
        let profile = self.active_profile().ok_or(DesktopError::NotFound)?;
        let prepared = prepare_login(
            &profile.email,
            master_password.as_bytes(),
            &kdf_config(&profile.kdf)?,
        )
        .map_err(|_| DesktopError::Crypto)?;
        Ok(ReauthenticationRequest {
            auth_proof: STANDARD.encode(prepared.authentication_proof),
        })
    }

    async fn attachment_status_online(
        &mut self,
        id: Uuid,
    ) -> Result<Option<AttachmentResponse>, DesktopError> {
        let (api, access) = self.attachment_api_access().await?;
        match api.attachment_status(&access, id).await {
            Ok(response) => Ok(Some(response)),
            Err(error) if is_not_found(&error) => Ok(None),
            Err(error) if is_unauthorized(&error) => {
                self.rotate_session().await?;
                let access = self
                    .session
                    .as_ref()
                    .map(|session| session.access_token.clone())
                    .ok_or(DesktopError::AuthenticationRequired)?;
                match api.attachment_status(&access, id).await {
                    Ok(response) => Ok(Some(response)),
                    Err(error) if is_not_found(&error) => Ok(None),
                    Err(error) => Err(map_client_error(error)),
                }
            }
            Err(error) => Err(map_client_error(error)),
        }
    }

    async fn initiate_attachment_online(
        &mut self,
        request: &AttachmentInitiateRequest,
    ) -> Result<AttachmentResponse, DesktopError> {
        let (api, access) = self.attachment_api_access().await?;
        match api.initiate_attachment(&access, request).await {
            Ok(response) => Ok(response),
            Err(error) if is_unauthorized(&error) => {
                self.rotate_session().await?;
                let access = self
                    .session
                    .as_ref()
                    .map(|session| session.access_token.clone())
                    .ok_or(DesktopError::AuthenticationRequired)?;
                api.initiate_attachment(&access, request)
                    .await
                    .map_err(map_client_error)
            }
            Err(error) => Err(map_client_error(error)),
        }
    }

    async fn put_attachment_chunk_online(
        &mut self,
        id: Uuid,
        index: u32,
        ciphertext: Vec<u8>,
    ) -> Result<(), DesktopError> {
        let (api, access) = self.attachment_api_access().await?;
        match api
            .put_attachment_chunk(&access, id, index, ciphertext.clone())
            .await
        {
            Ok(()) => Ok(()),
            Err(error) if is_unauthorized(&error) => {
                self.rotate_session().await?;
                let access = self
                    .session
                    .as_ref()
                    .map(|session| session.access_token.clone())
                    .ok_or(DesktopError::AuthenticationRequired)?;
                api.put_attachment_chunk(&access, id, index, ciphertext)
                    .await
                    .map_err(map_client_error)
            }
            Err(error) => Err(map_client_error(error)),
        }
    }

    async fn complete_attachment_online(
        &mut self,
        id: Uuid,
        request: &AttachmentCompleteRequest,
    ) -> Result<AttachmentResponse, DesktopError> {
        let (api, access) = self.attachment_api_access().await?;
        match api.complete_attachment(&access, id, request).await {
            Ok(response) => Ok(response),
            Err(error) if is_unauthorized(&error) => {
                self.rotate_session().await?;
                let access = self
                    .session
                    .as_ref()
                    .map(|session| session.access_token.clone())
                    .ok_or(DesktopError::AuthenticationRequired)?;
                api.complete_attachment(&access, id, request)
                    .await
                    .map_err(map_client_error)
            }
            Err(error) => Err(map_client_error(error)),
        }
    }

    async fn attachment_chunk_online(
        &mut self,
        id: Uuid,
        index: u32,
    ) -> Result<Vec<u8>, DesktopError> {
        let (api, access) = self.attachment_api_access().await?;
        match api.attachment_chunk(&access, id, index).await {
            Ok(ciphertext) => Ok(ciphertext),
            Err(error) if is_unauthorized(&error) => {
                self.rotate_session().await?;
                let access = self
                    .session
                    .as_ref()
                    .map(|session| session.access_token.clone())
                    .ok_or(DesktopError::AuthenticationRequired)?;
                api.attachment_chunk(&access, id, index)
                    .await
                    .map_err(map_client_error)
            }
            Err(error) => Err(map_client_error(error)),
        }
    }

    async fn delete_attachment_online(&mut self, id: Uuid) -> Result<(), DesktopError> {
        let (api, access) = self.attachment_api_access().await?;
        match api.delete_attachment(&access, id).await {
            Ok(()) => Ok(()),
            Err(error) if is_not_found(&error) => Ok(()),
            Err(error) if is_unauthorized(&error) => {
                self.rotate_session().await?;
                let access = self
                    .session
                    .as_ref()
                    .map(|session| session.access_token.clone())
                    .ok_or(DesktopError::AuthenticationRequired)?;
                match api.delete_attachment(&access, id).await {
                    Ok(()) => Ok(()),
                    Err(error) if is_not_found(&error) => Ok(()),
                    Err(error) => Err(map_client_error(error)),
                }
            }
            Err(error) => Err(map_client_error(error)),
        }
    }

    /// Lists and searches decrypted items locally. No search text reaches the server.
    pub fn list_items(
        &mut self,
        query: &str,
        category: &str,
    ) -> Result<Vec<ItemSummary>, DesktopError> {
        self.touch();
        let vault = self.require_unlocked()?;
        let profile = self.active_profile().ok_or(DesktopError::NotFound)?;
        let ordered: Vec<Uuid> = if query.trim().is_empty() {
            let mut ids: Vec<Uuid> = vault.items.keys().copied().collect();
            ids.sort_by(|left, right| {
                vault.items[left]
                    .name
                    .to_lowercase()
                    .cmp(&vault.items[right].name.to_lowercase())
                    .then(left.cmp(right))
            });
            ids
        } else {
            search(&vault.items.values().cloned().collect::<Vec<_>>(), query)
                .into_iter()
                .map(|hit| hit.id)
                .collect()
        };
        Ok(ordered
            .into_iter()
            .filter_map(|id| vault.items.get(&id))
            .filter(|item| category_matches(item, category))
            .map(|item| item_summary(item, profile))
            .collect())
    }

    /// Returns only the organization metadata needed to label and validate vault destinations.
    pub fn organization_catalog(&mut self) -> Result<OrganizationCatalog, DesktopError> {
        self.touch();
        let mut folders = self.require_unlocked()?.folders.clone();
        folders.sort_by(|left, right| {
            left.name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then(left.id.cmp(&right.id))
        });
        let profile = self.active_profile().ok_or(DesktopError::NotFound)?;
        let confirmed_ids: BTreeSet<Uuid> = profile
            .organizations
            .iter()
            .filter(|organization| organization.status == MembershipStatus::Confirmed)
            .map(|organization| organization.id)
            .collect();
        let mut organizations: Vec<_> = profile
            .organizations
            .iter()
            .filter(|organization| confirmed_ids.contains(&organization.id))
            .map(|organization| OrganizationSummary {
                id: organization.id,
                name: organization.name.clone(),
                role: organization.role,
            })
            .collect();
        organizations.sort_by(|left, right| {
            left.name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then(left.id.cmp(&right.id))
        });
        let mut collections: Vec<_> = profile
            .organization_collections
            .iter()
            .filter(|collection| confirmed_ids.contains(&collection.organization_id))
            .map(|collection| OrganizationCollectionSummary {
                id: collection.id,
                organization_id: collection.organization_id,
                name: collection.name.clone(),
                read_only: collection.read_only,
                hide_passwords: collection.hide_passwords,
                manage: collection.manage,
            })
            .collect();
        collections.sort_by(|left, right| {
            left.organization_id
                .cmp(&right.organization_id)
                .then(left.name.to_lowercase().cmp(&right.name.to_lowercase()))
                .then(left.id.cmp(&right.id))
        });
        Ok(OrganizationCatalog {
            organizations,
            collections,
            folders,
        })
    }

    /// Returns a full decrypted item for an explicit detail/editor view.
    pub fn get_item(&mut self, id: Uuid) -> Result<VaultItem, DesktopError> {
        self.touch();
        self.require_unlocked()?
            .items
            .get(&id)
            .cloned()
            .ok_or(DesktopError::NotFound)
    }

    /// Finds logins eligible to autofill a verified Android app or web origin.
    ///
    /// URI matching is shared with every other official client and honours `Never`, HTTPS
    /// downgrade protection, and the configured domain / host / exact strategy. Collection
    /// policies that hide passwords are also enforced before secret values leave the core.
    pub fn autofill_candidates(
        &mut self,
        origin: &str,
    ) -> Result<Vec<AutofillCandidate>, DesktopError> {
        if origin.len() > 4_096 {
            return Err(DesktopError::InvalidInput);
        }
        self.touch();
        let profile = self.active_profile().ok_or(DesktopError::NotFound)?;
        let hidden_collections: BTreeSet<Uuid> = profile
            .organization_collections
            .iter()
            .filter(|collection| collection.hide_passwords)
            .map(|collection| collection.id)
            .collect();
        let vault = self.require_unlocked()?;
        let unix_seconds = u64::try_from(Utc::now().timestamp()).unwrap_or_default();
        let mut candidates = vault
            .items
            .values()
            .filter(|item| item.deleted_date.is_none())
            .filter(|item| {
                !item
                    .collection_ids
                    .iter()
                    .any(|id| hidden_collections.contains(id))
            })
            .filter_map(|item| {
                let ItemData::Login(login) = &item.data else {
                    return None;
                };
                let matches = login.uris.iter().any(|uri| {
                    uri_matches(
                        &uri.uri,
                        origin,
                        uri.r#match.unwrap_or(UriMatchType::Domain),
                    )
                    .unwrap_or(false)
                });
                matches.then(|| AutofillCandidate {
                    id: item.id,
                    name: item.name.clone(),
                    username: login.username.clone(),
                    password: login
                        .password
                        .as_ref()
                        .map(|value| value.expose().to_owned()),
                    totp: login
                        .totp
                        .as_ref()
                        .and_then(|value| TotpConfig::parse(value.expose()).ok())
                        .and_then(|config| config.generate_at(unix_seconds).ok())
                        .map(|code| code.code),
                })
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            left.name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then(left.id.cmp(&right.id))
        });
        // Android system selectors must never receive an unbounded vault projection, even after
        // the user has authenticated. More-specific URI matches remain deterministic because
        // rows are sorted before this bound is applied.
        candidates.truncate(50);
        Ok(candidates)
    }

    /// Returns unlocked password candidates for Android Credential Manager.
    ///
    /// The Android framework only invokes this after an explicit biometric authentication action;
    /// this method deliberately has no webview command. Password values remain within the
    /// provider activity and are returned directly to the requesting system API.
    pub fn credential_password_candidates(
        &mut self,
    ) -> Result<Vec<AutofillCandidate>, DesktopError> {
        self.touch();
        let profile = self.active_profile().ok_or(DesktopError::NotFound)?;
        let hidden_collections: BTreeSet<Uuid> = profile
            .organization_collections
            .iter()
            .filter(|collection| collection.hide_passwords)
            .map(|collection| collection.id)
            .collect();
        let vault = self.require_unlocked()?;
        let mut candidates = vault
            .items
            .values()
            .filter(|item| item.deleted_date.is_none())
            .filter(|item| {
                !item
                    .collection_ids
                    .iter()
                    .any(|id| hidden_collections.contains(id))
            })
            .filter_map(|item| {
                let ItemData::Login(login) = &item.data else {
                    return None;
                };
                let (Some(username), Some(password)) = (&login.username, &login.password) else {
                    return None;
                };
                Some(AutofillCandidate {
                    id: item.id,
                    name: item.name.clone(),
                    username: Some(username.clone()),
                    password: Some(password.expose().to_owned()),
                    totp: None,
                })
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            left.name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then(left.id.cmp(&right.id))
        });
        Ok(candidates)
    }

    /// Lists discoverable passkeys for one RP after Android Credential Manager authentication.
    pub fn credential_passkey_candidates(
        &mut self,
        rp_id: &str,
    ) -> Result<Vec<CredentialPasskeyCandidate>, DesktopError> {
        if rp_id.is_empty() || rp_id.len() > 253 {
            return Err(DesktopError::InvalidInput);
        }
        self.touch();
        let profile = self.active_profile().ok_or(DesktopError::NotFound)?;
        let hidden_collections: BTreeSet<Uuid> = profile
            .organization_collections
            .iter()
            .filter(|collection| collection.hide_passwords)
            .map(|collection| collection.id)
            .collect();
        let vault = self.require_unlocked()?;
        let mut candidates = Vec::new();
        for item in vault
            .items
            .values()
            .filter(|item| item.deleted_date.is_none())
            .filter(|item| {
                !item
                    .collection_ids
                    .iter()
                    .any(|id| hidden_collections.contains(id))
            })
        {
            let ItemData::Login(login) = &item.data else {
                continue;
            };
            for credential in &login.fido2_credentials {
                if credential.rp_id != rp_id || !credential.discoverable {
                    continue;
                }
                let credential_id =
                    passkey_credential_id(credential).map_err(|_| DesktopError::Crypto)?;
                candidates.push(CredentialPasskeyCandidate {
                    item_id: item.id,
                    credential_id,
                    rp_id: credential.rp_id.clone(),
                    user_name: credential.user_name.clone(),
                    display_name: credential
                        .user_display_name
                        .clone()
                        .unwrap_or_else(|| item.name.clone()),
                });
            }
        }
        candidates.sort_by(|left, right| {
            left.display_name
                .to_lowercase()
                .cmp(&right.display_name.to_lowercase())
                .then(left.credential_id.cmp(&right.credential_id))
        });
        Ok(candidates)
    }

    /// Lists existing login items eligible to receive a newly created RP-scoped passkey.
    pub fn credential_passkey_creation_targets(
        &mut self,
        rp_id: &str,
    ) -> Result<Vec<AutofillCandidate>, DesktopError> {
        if rp_id.is_empty() || rp_id.len() > 253 {
            return Err(DesktopError::InvalidInput);
        }
        self.touch();
        let vault = self.require_unlocked()?;
        let origin = format!("https://{rp_id}");
        let mut targets = vault
            .items
            .values()
            .filter(|item| item.deleted_date.is_none())
            .filter_map(|item| {
                let ItemData::Login(login) = &item.data else {
                    return None;
                };
                let matches = login.uris.iter().any(|uri| {
                    uri_matches(&uri.uri, &origin, UriMatchType::Domain).unwrap_or(false)
                });
                matches.then(|| AutofillCandidate {
                    id: item.id,
                    name: item.name.clone(),
                    username: login.username.clone(),
                    password: None,
                    totp: None,
                })
            })
            .collect::<Vec<_>>();
        targets.sort_by_key(|item| item.name.to_lowercase());
        Ok(targets)
    }

    /// Creates a passkey in an existing matching login and queues the encrypted update.
    pub fn create_credential_passkey(
        &mut self,
        item_id: Uuid,
        options: &PasskeyCreationOptions,
    ) -> Result<PasskeyCreationResult, DesktopError> {
        let mut item = self.get_item(item_id)?;
        let ItemData::Login(login) = &mut item.data else {
            return Err(DesktopError::InvalidInput);
        };
        let rp_id = options.rp.id.as_deref().unwrap_or_default();
        let eligible = login.uris.iter().any(|uri| {
            uri_matches(&uri.uri, &format!("https://{rp_id}"), UriMatchType::Domain)
                .unwrap_or(false)
        });
        if !eligible {
            return Err(DesktopError::InvalidInput);
        }
        let created = create_passkey(options, true).map_err(|_| DesktopError::Crypto)?;
        login.fido2_credentials.push(created.credential.clone());
        item.revision_date = Utc::now();
        self.queue_item(item, false)?;
        self.touch();
        Ok(created)
    }

    /// Performs a user-verified `WebAuthn` assertion using an encrypted vault passkey.
    pub fn assert_credential_passkey(
        &mut self,
        item_id: Uuid,
        credential_id: &str,
        options: &PasskeyAssertionOptions,
    ) -> Result<PasskeyAssertionResult, DesktopError> {
        if credential_id.is_empty() || credential_id.len() > 2_000 {
            return Err(DesktopError::InvalidInput);
        }
        let mut item = self.get_item(item_id)?;
        let ItemData::Login(login) = &mut item.data else {
            return Err(DesktopError::InvalidInput);
        };
        let credential = login
            .fido2_credentials
            .iter_mut()
            .find(|candidate| passkey_credential_id(candidate).as_deref() == Ok(credential_id))
            .ok_or(DesktopError::NotFound)?;
        let assertion =
            assert_passkey(credential, options, true).map_err(|_| DesktopError::Crypto)?;
        if assertion.counter_changed {
            item.revision_date = Utc::now();
            self.queue_item(item, false)?;
        }
        self.touch();
        Ok(assertion)
    }

    /// Creates or updates a login, persists its encrypted mutation, and opportunistically syncs.
    pub async fn save_login(&mut self, draft: LoginDraft) -> Result<VaultItem, DesktopError> {
        let item = self.save_login_local(draft)?;
        self.sync_now().await?;
        Ok(item)
    }

    /// Creates or updates a login in the encrypted local replica without requiring an active
    /// network session.
    ///
    /// Android's authenticated Autofill save flow uses this after a Keystore biometric unlock.
    /// It is intentionally the same validation, encryption, mutation queue, and cache path as
    /// [`Self::save_login`]; the normal sync command uploads the durable mutation later.
    pub fn save_login_local(&mut self, mut draft: LoginDraft) -> Result<VaultItem, DesktopError> {
        validate_login_draft(&mut draft)?;
        if draft.folder_id.is_some_and(|folder_id| {
            !self
                .require_unlocked()
                .is_ok_and(|vault| vault.folders.iter().any(|folder| folder.id == folder_id))
        }) || (draft.organization_id.is_some() && draft.folder_id.is_some())
        {
            return Err(DesktopError::InvalidInput);
        }
        let existing = if let Some(id) = draft.id {
            let item = self
                .require_unlocked()?
                .items
                .get(&id)
                .cloned()
                .ok_or(DesktopError::NotFound)?;
            if item.organization_id != draft.organization_id
                || item.collection_ids != draft.collection_ids
            {
                return Err(DesktopError::InvalidInput);
            }
            validate_organization_write(
                self.active_profile().ok_or(DesktopError::NotFound)?,
                item.organization_id,
                &item.collection_ids,
            )?;
            Some(item)
        } else {
            validate_organization_write(
                self.active_profile().ok_or(DesktopError::NotFound)?,
                draft.organization_id,
                &draft.collection_ids,
            )?;
            None
        };
        let item = apply_login_draft(existing, draft, Utc::now())?;
        self.queue_item(item.clone(), false)?;
        self.touch();
        Ok(item)
    }

    /// Creates or updates a secure note, payment card, or identity, then opportunistically
    /// synchronizes it through the same encrypted replica and outbox as every other vault item.
    pub async fn save_item(&mut self, draft: ItemDraft) -> Result<VaultItem, DesktopError> {
        let item = self.save_item_local(draft)?;
        self.sync_now().await?;
        Ok(item)
    }

    /// Local-only counterpart for an offline secure note, payment card, or identity edit.
    ///
    /// It deliberately does not accept a Login payload: login mutations use [`Self::save_login`]
    /// to preserve password history and URI/TOTP validation. Kotlin never implements this logic;
    /// Android and desktop use this shared encrypted mutation path.
    pub fn save_item_local(&mut self, mut draft: ItemDraft) -> Result<VaultItem, DesktopError> {
        validate_item_draft(&mut draft)?;
        let existing = if let Some(id) = draft.id {
            let item = self
                .require_unlocked()?
                .items
                .get(&id)
                .cloned()
                .ok_or(DesktopError::NotFound)?;
            if item.organization_id != draft.organization_id
                || item.collection_ids != draft.collection_ids
                || item.data.item_type() != draft.data.item_type()
            {
                return Err(DesktopError::InvalidInput);
            }
            validate_organization_write(
                self.active_profile().ok_or(DesktopError::NotFound)?,
                item.organization_id,
                &item.collection_ids,
            )?;
            Some(item)
        } else {
            validate_organization_write(
                self.active_profile().ok_or(DesktopError::NotFound)?,
                draft.organization_id,
                &draft.collection_ids,
            )?;
            None
        };
        if draft.folder_id.is_some_and(|folder_id| {
            !self
                .require_unlocked()
                .is_ok_and(|vault| vault.folders.iter().any(|folder| folder.id == folder_id))
        }) || (draft.organization_id.is_some() && draft.folder_id.is_some())
        {
            return Err(DesktopError::InvalidInput);
        }
        let now = Utc::now();
        let item = if let Some(mut item) = existing {
            item.name = draft.name;
            item.notes = draft.notes;
            item.favorite = draft.favorite;
            item.folder_id = draft.folder_id;
            item.fields = draft.fields;
            item.data = draft.data;
            item.revision_date = now;
            item
        } else {
            let mut item = VaultItem::new(draft.name, draft.data);
            item.notes = draft.notes;
            item.favorite = draft.favorite;
            item.folder_id = draft.folder_id;
            item.fields = draft.fields;
            item.organization_id = draft.organization_id;
            item.collection_ids = draft.collection_ids;
            item
        };
        self.queue_item(item.clone(), false)?;
        self.touch();
        Ok(item)
    }

    /// Creates or renames an encrypted personal folder and opportunistically synchronizes it.
    pub async fn save_folder(
        &mut self,
        draft: FolderDraft,
    ) -> Result<BitwardenFolder, DesktopError> {
        let folder = self.save_folder_local(&draft)?;
        self.sync_now().await?;
        Ok(folder)
    }

    /// Local-only counterpart for an offline folder create or rename.
    pub fn save_folder_local(
        &mut self,
        draft: &FolderDraft,
    ) -> Result<BitwardenFolder, DesktopError> {
        self.touch();
        let name = validate_folder_name(&draft.name)?;
        let folder = if let Some(id) = draft.id {
            let existing = self
                .require_unlocked()?
                .folders
                .iter()
                .find(|folder| folder.id == id)
                .cloned()
                .ok_or(DesktopError::NotFound)?;
            BitwardenFolder {
                id: existing.id,
                name,
            }
        } else {
            if self.require_unlocked()?.folders.len() >= MAX_FOLDERS {
                return Err(DesktopError::InvalidInput);
            }
            BitwardenFolder {
                id: Uuid::new_v4(),
                name,
            }
        };
        self.queue_folder(folder.clone(), false)?;
        Ok(folder)
    }

    /// Deletes an encrypted folder after detaching all of its personal items. The item edits and
    /// folder tombstone share the same durable outbox, so an offline delete cannot leave a
    /// dangling local folder reference after the next sync.
    pub async fn delete_folder(&mut self, id: Uuid) -> Result<DesktopStatus, DesktopError> {
        self.require_unlocked()?
            .folders
            .iter()
            .any(|folder| folder.id == id)
            .then_some(())
            .ok_or(DesktopError::NotFound)?;
        let affected: Vec<_> = self
            .require_unlocked()?
            .items
            .values()
            .filter(|item| item.folder_id == Some(id) && item.deleted_date.is_none())
            .cloned()
            .collect();
        for mut item in affected {
            item.folder_id = None;
            item.revision_date = Utc::now();
            self.queue_item_without_persist(item, false)?;
        }
        let has_server_object = self.active_profile().is_some_and(|profile| {
            profile
                .replica
                .objects()
                .get(&id)
                .is_some_and(|object| object.kind == ObjectKind::Folder)
        });
        if has_server_object {
            let folder = self
                .require_unlocked()?
                .folders
                .iter()
                .find(|folder| folder.id == id)
                .cloned()
                .ok_or(DesktopError::NotFound)?;
            self.queue_folder_without_persist(folder, true)?;
        } else {
            self.active_profile_mut()
                .ok_or(DesktopError::NotFound)?
                .replica
                .discard_local(id);
            self.require_unlocked_mut()?
                .folders
                .retain(|folder| folder.id != id);
        }
        self.persist()?;
        self.touch();
        self.sync_now().await
    }

    /// Moves an authoritative item to trash, or discards a never-synchronized local create.
    pub async fn delete_item(&mut self, id: Uuid) -> Result<DesktopStatus, DesktopError> {
        let mut item = self
            .require_unlocked()?
            .items
            .get(&id)
            .cloned()
            .ok_or(DesktopError::NotFound)?;
        let has_server_object = self
            .active_profile()
            .is_some_and(|profile| profile.replica.objects().contains_key(&id));
        if !has_server_object {
            self.active_profile_mut()
                .ok_or(DesktopError::NotFound)?
                .replica
                .discard_local(id);
            self.require_unlocked_mut()?.items.remove(&id);
            self.persist()?;
            self.touch();
            return Ok(self.status());
        }
        item.deleted_date = Some(Utc::now());
        item.revision_date = Utc::now();
        self.queue_item(item, true)?;
        self.touch();
        self.sync_now().await
    }

    /// Removes one encrypted passkey entry after a user confirmation in the UI.
    pub async fn remove_passkey(
        &mut self,
        item_id: Uuid,
        credential_id: &str,
    ) -> Result<VaultItem, DesktopError> {
        if credential_id.is_empty() || credential_id.len() > 2_000 {
            return Err(DesktopError::InvalidInput);
        }
        let mut item = self.get_item(item_id)?;
        let ItemData::Login(login) = &mut item.data else {
            return Err(DesktopError::InvalidInput);
        };
        let previous = login.fido2_credentials.len();
        login
            .fido2_credentials
            .retain(|credential| credential.credential_id != credential_id);
        if previous == login.fido2_credentials.len() {
            return Err(DesktopError::NotFound);
        }
        item.revision_date = Utc::now();
        self.queue_item(item.clone(), false)?;
        let _ = self.sync_now().await?;
        Ok(item)
    }

    /// Returns the authenticated private filename used to seed a native save dialog.
    pub fn attachment_file_name(
        &mut self,
        item_id: Uuid,
        attachment_id: Uuid,
    ) -> Result<String, DesktopError> {
        let item = self.get_item(item_id)?;
        item.attachments
            .iter()
            .find(|attachment| attachment.id == attachment_id)
            .map(|attachment| attachment.file_name.clone())
            .ok_or(DesktopError::NotFound)
    }

    /// Encrypts a native file frame by frame and uploads only opaque authenticated chunks.
    /// Reselecting an existing attachment re-submits every prior frame idempotently so a
    /// same-name, same-length but different file cannot produce a mixed upload.
    pub async fn upload_attachment_from_path(
        &mut self,
        item_id: Uuid,
        attachment_id: Option<Uuid>,
        path: &Path,
    ) -> Result<VaultItem, DesktopError> {
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(DesktopError::InvalidInput)?
            .to_owned();
        let file_attributes = tokio::fs::metadata(path)
            .await
            .map_err(|_| DesktopError::AttachmentFile)?;
        if !file_attributes.is_file() {
            return Err(DesktopError::InvalidInput);
        }
        let metadata = self.prepare_attachment_metadata(
            item_id,
            attachment_id,
            path,
            file_name,
            file_attributes.len(),
        )?;

        let _ = self.sync_now().await?;
        if !self.online {
            return Err(DesktopError::Offline);
        }
        let current_item = self.get_item(item_id)?;
        let current_metadata = current_item
            .attachments
            .iter()
            .find(|attachment| attachment.id == metadata.id)
            .cloned()
            .ok_or(DesktopError::Conflict)?;
        if current_metadata != metadata {
            return Err(DesktopError::Conflict);
        }
        let request = attachment_initiate_request(
            self.active_profile().ok_or(DesktopError::NotFound)?,
            item_id,
            &metadata,
        )?;
        let status = match self.attachment_status_online(metadata.id).await? {
            Some(status) => status,
            None => self.initiate_attachment_online(&request).await?,
        };
        validate_attachment_response(
            &status,
            item_id,
            &metadata,
            (status.state == AttachmentState::Uploading).then_some(request.object_revision),
        )?;
        if status.state == AttachmentState::Complete {
            self.online = true;
            self.touch();
            return self.get_item(item_id);
        }
        self.upload_attachment_frames(item_id, path, &metadata, request.object_revision)
            .await?;
        self.online = true;
        self.touch();
        self.get_item(item_id)
    }

    fn prepare_attachment_metadata(
        &mut self,
        item_id: Uuid,
        attachment_id: Option<Uuid>,
        path: &Path,
        file_name: String,
        size: u64,
    ) -> Result<AttachmentMetadata, DesktopError> {
        let mut item = self.get_item(item_id)?;
        if item.deleted_date.is_some() {
            return Err(DesktopError::InvalidInput);
        }
        validate_organization_write(
            self.active_profile().ok_or(DesktopError::NotFound)?,
            item.organization_id,
            &item.collection_ids,
        )?;
        if let Some(attachment_id) = attachment_id {
            let metadata = item
                .attachments
                .iter()
                .find(|attachment| attachment.id == attachment_id)
                .cloned()
                .ok_or(DesktopError::NotFound)?;
            if metadata.file_name != file_name || metadata.size != size {
                return Err(DesktopError::InvalidInput);
            }
            return Ok(metadata);
        }
        if item.attachments.len() >= 100 {
            return Err(DesktopError::InvalidInput);
        }
        let metadata = AttachmentMetadata::generate(
            file_name,
            media_type_for_path(path),
            size,
            DEFAULT_ATTACHMENT_CHUNK_SIZE,
        )
        .map_err(|_| DesktopError::InvalidInput)?;
        item.attachments.push(metadata.clone());
        item.revision_date = Utc::now();
        self.queue_item(item, false)?;
        Ok(metadata)
    }

    async fn upload_attachment_frames(
        &mut self,
        item_id: Uuid,
        path: &Path,
        metadata: &AttachmentMetadata,
        object_revision: i64,
    ) -> Result<(), DesktopError> {
        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|_| DesktopError::AttachmentFile)?;
        for index in 0..metadata.chunk_count {
            let length = metadata
                .plaintext_chunk_len(index)
                .map_err(|_| DesktopError::Crypto)?;
            let mut plaintext = Zeroizing::new(vec![0_u8; length]);
            file.read_exact(&mut plaintext)
                .await
                .map_err(|_| DesktopError::AttachmentFile)?;
            let ciphertext = encrypt_attachment_chunk(metadata, item_id, index, &plaintext)
                .map_err(|_| DesktopError::Crypto)?;
            self.put_attachment_chunk_online(metadata.id, index, ciphertext)
                .await?;
        }
        let mut extra = [0_u8; 1];
        if file
            .read(&mut extra)
            .await
            .map_err(|_| DesktopError::AttachmentFile)?
            != 0
        {
            return Err(DesktopError::AttachmentFile);
        }
        let completed = self
            .complete_attachment_online(metadata.id, &AttachmentCompleteRequest { object_revision })
            .await?;
        validate_attachment_response(&completed, item_id, metadata, Some(object_revision))?;
        if completed.state != AttachmentState::Complete {
            return Err(DesktopError::Server("attachment_incomplete".to_owned()));
        }
        Ok(())
    }

    /// Authenticates and writes a complete attachment to an atomic native temporary file.
    pub async fn download_attachment_to_path(
        &mut self,
        item_id: Uuid,
        attachment_id: Uuid,
        destination: &Path,
    ) -> Result<(), DesktopError> {
        if !destination.is_absolute() || destination.file_name().is_none() {
            return Err(DesktopError::InvalidInput);
        }
        let item = self.get_item(item_id)?;
        if item.deleted_date.is_some() {
            return Err(DesktopError::NotFound);
        }
        let metadata = item
            .attachments
            .iter()
            .find(|attachment| attachment.id == attachment_id)
            .cloned()
            .ok_or(DesktopError::NotFound)?;
        let status = self
            .attachment_status_online(attachment_id)
            .await?
            .ok_or(DesktopError::NotFound)?;
        validate_attachment_response(&status, item_id, &metadata, None)?;
        if status.state != AttachmentState::Complete {
            return Err(DesktopError::Server("attachment_incomplete".to_owned()));
        }

        let parent = destination.parent().ok_or(DesktopError::InvalidInput)?;
        if !parent.is_dir() {
            return Err(DesktopError::AttachmentFile);
        }
        let temporary = NamedTempFile::new_in(parent).map_err(|_| DesktopError::AttachmentFile)?;
        let (temporary_file, temporary_path) = temporary.into_parts();
        let mut writer = tokio::fs::File::from_std(temporary_file);
        let mut total = 0_u64;
        for index in 0..metadata.chunk_count {
            let mut ciphertext = self.attachment_chunk_online(attachment_id, index).await?;
            let plaintext = decrypt_attachment_chunk(&metadata, item_id, index, &ciphertext)
                .map_err(|_| DesktopError::Crypto)?;
            ciphertext.zeroize();
            writer
                .write_all(&plaintext)
                .await
                .map_err(|_| DesktopError::AttachmentFile)?;
            total = total
                .checked_add(u64::try_from(plaintext.len()).map_err(|_| DesktopError::Crypto)?)
                .ok_or(DesktopError::Crypto)?;
        }
        if total != metadata.size {
            return Err(DesktopError::Crypto);
        }
        writer
            .flush()
            .await
            .map_err(|_| DesktopError::AttachmentFile)?;
        writer
            .sync_all()
            .await
            .map_err(|_| DesktopError::AttachmentFile)?;
        drop(writer);
        temporary_path
            .persist(destination)
            .map_err(|_| DesktopError::AttachmentFile)?;
        self.online = true;
        self.touch();
        Ok(())
    }

    /// Removes private metadata first and durably queues opaque blob cleanup after sync.
    pub async fn remove_attachment(
        &mut self,
        item_id: Uuid,
        attachment_id: Uuid,
    ) -> Result<AttachmentRemoval, DesktopError> {
        let mut item = self.get_item(item_id)?;
        validate_organization_write(
            self.active_profile().ok_or(DesktopError::NotFound)?,
            item.organization_id,
            &item.collection_ids,
        )?;
        let previous = item.attachments.len();
        item.attachments
            .retain(|attachment| attachment.id != attachment_id);
        if previous == item.attachments.len() {
            return Err(DesktopError::NotFound);
        }
        item.revision_date = Utc::now();
        self.queue_item_without_persist(item.clone(), false)?;
        let profile = self.active_profile_mut().ok_or(DesktopError::NotFound)?;
        if !profile
            .pending_attachment_deletions
            .iter()
            .any(|pending| pending.id == attachment_id)
        {
            profile
                .pending_attachment_deletions
                .push(PendingAttachmentDeletion {
                    id: attachment_id,
                    object_id: item_id,
                });
        }
        self.persist()?;
        let _ = self.sync_now().await?;
        let cleanup_pending = self.active_profile().is_some_and(|profile| {
            profile
                .pending_attachment_deletions
                .iter()
                .any(|pending| pending.id == attachment_id)
        });
        Ok(AttachmentRemoval {
            item: self.get_item(item_id)?,
            cleanup_pending,
        })
    }

    /// Generates a CSPRNG password using the shared Rust vault implementation.
    pub fn generate_password(&mut self, options: &PasswordOptions) -> Result<String, DesktopError> {
        self.touch();
        generate_password(options).map_err(|_| DesktopError::InvalidInput)
    }

    /// Generates a CSPRNG passphrase using the shared Rust vault implementation.
    pub fn generate_passphrase(
        &mut self,
        options: &PassphraseOptions,
    ) -> Result<String, DesktopError> {
        self.touch();
        generate_passphrase(options).map_err(|_| DesktopError::InvalidInput)
    }

    /// Computes an RFC 6238 code locally for one explicit item.
    pub fn totp_for_item(&mut self, id: Uuid, unix_seconds: u64) -> Result<TotpView, DesktopError> {
        self.touch();
        let item = self
            .require_unlocked()?
            .items
            .get(&id)
            .ok_or(DesktopError::NotFound)?;
        let ItemData::Login(login) = &item.data else {
            return Err(DesktopError::InvalidInput);
        };
        let secret = login.totp.as_ref().ok_or(DesktopError::NotFound)?;
        let code = TotpConfig::parse(secret.expose())
            .and_then(|config| config.generate_at(unix_seconds))
            .map_err(|_| DesktopError::InvalidInput)?;
        Ok(TotpView {
            code: code.code,
            remaining_seconds: u64::from(code.remaining_seconds),
        })
    }

    /// Imports a bounded plaintext Bitwarden JSON export and queues encrypted uploads.
    pub fn import_bitwarden_json(&mut self, input: &[u8]) -> Result<ImportSummary, DesktopError> {
        let imported = import_json(input).map_err(|_| DesktopError::Compatibility)?;
        let count = self
            .require_unlocked()?
            .items
            .len()
            .checked_add(imported.items.len())
            .ok_or(DesktopError::InvalidInput)?;
        if count > MAX_ITEMS {
            return Err(DesktopError::InvalidInput);
        }
        let summary = ImportSummary {
            item_count: imported.items.len(),
            folder_count: imported.folders.len(),
            collection_count: imported.collections.len(),
        };
        for item in imported.items {
            self.queue_item_without_persist(item, false)?;
        }
        for folder in imported.folders.clone() {
            self.queue_folder_without_persist(folder, false)?;
        }
        let profile = self.active_profile_mut().ok_or(DesktopError::NotFound)?;
        merge_by_id(&mut profile.folders, imported.folders, |folder| folder.id);
        merge_by_id(
            &mut profile.collections,
            imported.collections,
            |collection| collection.id,
        );
        self.persist()?;
        self.touch();
        Ok(summary)
    }

    /// Produces a plaintext Bitwarden-compatible JSON export entirely in the native client.
    /// The caller must show a plaintext warning before invoking this method.
    pub fn export_bitwarden_json(&mut self) -> Result<Vec<u8>, DesktopError> {
        self.touch();
        let vault = self.require_unlocked()?;
        let profile = self.active_profile().ok_or(DesktopError::NotFound)?;
        export_json(&ImportedVault {
            folders: vault.folders.clone(),
            collections: profile.collections.clone(),
            items: vault.items.values().cloned().collect(),
        })
        .map_err(|_| DesktopError::Compatibility)
    }

    /// Returns all concurrent edits with both names decrypted locally.
    pub fn list_conflicts(&mut self) -> Result<Vec<ConflictSummary>, DesktopError> {
        self.touch();
        let vault = self.require_unlocked()?;
        let profile = self.active_profile().ok_or(DesktopError::NotFound)?;
        profile
            .replica
            .conflicts()
            .values()
            .map(|conflict| {
                let local: VaultItem = decrypt_object(
                    &conflict.local.object,
                    &vault.user_key,
                    &vault.organization_keys,
                )?;
                let server: VaultItem =
                    decrypt_object(&conflict.server, &vault.user_key, &vault.organization_keys)?;
                Ok(ConflictSummary {
                    id: conflict.object_id,
                    local_name: local.name,
                    server_name: server.name,
                })
            })
            .collect()
    }

    /// Resolves a conflict by retaining either the encrypted local edit or server version.
    pub async fn resolve_conflict(
        &mut self,
        id: Uuid,
        keep_local: bool,
    ) -> Result<DesktopStatus, DesktopError> {
        let profile = self.active_profile_mut().ok_or(DesktopError::NotFound)?;
        if keep_local {
            profile
                .replica
                .resolve_with_local(id)
                .map_err(|_| DesktopError::NotFound)?;
        } else {
            profile
                .replica
                .resolve_with_server(id)
                .map_err(|_| DesktopError::NotFound)?;
            self.reload_unlocked()?;
        }
        self.persist()?;
        self.touch();
        self.sync_now().await
    }

    /// Selects a cached account profile and leaves it locked pending its master password.
    pub fn select_profile(&mut self, scope: &str) -> Result<DesktopStatus, DesktopError> {
        let index = self
            .document
            .profiles
            .iter()
            .position(|profile| profile.scope == scope)
            .ok_or(DesktopError::NotFound)?;
        self.vault = None;
        self.session = None;
        self.api = None;
        self.online = false;
        self.active = Some(index);
        self.document.active_scope = Some(scope.to_owned());
        self.persist()?;
        Ok(self.status())
    }

    fn queue_item(&mut self, item: VaultItem, delete: bool) -> Result<(), DesktopError> {
        self.queue_item_without_persist(item, delete)?;
        self.persist()
    }

    fn queue_item_without_persist(
        &mut self,
        item: VaultItem,
        delete: bool,
    ) -> Result<(), DesktopError> {
        let profile_index = self.active.ok_or(DesktopError::NotFound)?;
        let profile = &self.document.profiles[profile_index];
        if profile.replica.conflicts().contains_key(&item.id) {
            return Err(DesktopError::Conflict);
        }
        let existing = profile.replica.objects().get(&item.id).cloned();
        let vault = self.require_unlocked()?;
        let owner_key = item
            .organization_id
            .map_or(Ok(&vault.user_key), |organization_id| {
                vault
                    .organization_keys
                    .get(&organization_id)
                    .ok_or(DesktopError::Crypto)
            })?;
        if (item.organization_id.is_none() && !item.collection_ids.is_empty())
            || item.collection_ids.len() > 100
            || item.collection_ids.iter().collect::<BTreeSet<_>>().len()
                != item.collection_ids.len()
        {
            return Err(DesktopError::InvalidInput);
        }
        let envelope = encrypt_json(&item, owner_key).map_err(|_| DesktopError::Crypto)?;
        let now = Utc::now();
        let owner_type = if item.organization_id.is_some() {
            OwnerType::Organization
        } else {
            OwnerType::User
        };
        let object = EncryptedObject {
            id: item.id,
            kind: ObjectKind::Cipher,
            owner_type,
            owner_id: item.organization_id.unwrap_or(profile.account_id),
            collection_ids: item.collection_ids.clone(),
            format: envelope.format,
            wrapped_key: envelope.wrapped_key,
            payload: envelope.payload,
            object_revision: existing.as_ref().map_or(0, |value| value.object_revision),
            account_revision: profile.replica.last_revision(),
            created_at: existing
                .as_ref()
                .map_or(item.creation_date, |value| value.created_at),
            updated_at: now,
            deleted_at: delete.then_some(now),
        };
        let mutation = PendingMutation {
            object,
            base_revision: existing.as_ref().map(|value| value.object_revision),
            idempotency_key: Uuid::new_v4(),
            delete,
        };
        self.document.profiles[profile_index]
            .replica
            .enqueue(mutation);
        let mut item = item;
        if delete {
            item.deleted_date = Some(now);
        }
        self.require_unlocked_mut()?.items.insert(item.id, item);
        Ok(())
    }

    fn queue_folder(&mut self, folder: BitwardenFolder, delete: bool) -> Result<(), DesktopError> {
        self.queue_folder_without_persist(folder, delete)?;
        self.persist()
    }

    fn queue_folder_without_persist(
        &mut self,
        folder: BitwardenFolder,
        delete: bool,
    ) -> Result<(), DesktopError> {
        let profile_index = self.active.ok_or(DesktopError::NotFound)?;
        let profile = &self.document.profiles[profile_index];
        if profile.replica.conflicts().contains_key(&folder.id) {
            return Err(DesktopError::Conflict);
        }
        let existing = profile.replica.objects().get(&folder.id).cloned();
        if existing
            .as_ref()
            .is_some_and(|object| object.kind != ObjectKind::Folder)
        {
            return Err(DesktopError::InvalidInput);
        }
        let envelope = encrypt_json(&folder, &self.require_unlocked()?.user_key)
            .map_err(|_| DesktopError::Crypto)?;
        let now = Utc::now();
        let object = EncryptedObject {
            id: folder.id,
            kind: ObjectKind::Folder,
            owner_type: OwnerType::User,
            owner_id: profile.account_id,
            collection_ids: Vec::new(),
            format: envelope.format,
            wrapped_key: envelope.wrapped_key,
            payload: envelope.payload,
            object_revision: existing.as_ref().map_or(0, |value| value.object_revision),
            account_revision: profile.replica.last_revision(),
            created_at: existing.as_ref().map_or(now, |value| value.created_at),
            updated_at: now,
            deleted_at: delete.then_some(now),
        };
        let mutation = PendingMutation {
            object,
            base_revision: existing.as_ref().map(|value| value.object_revision),
            idempotency_key: Uuid::new_v4(),
            delete,
        };
        self.document.profiles[profile_index]
            .replica
            .enqueue(mutation);
        let folders = &mut self.require_unlocked_mut()?.folders;
        if delete {
            folders.retain(|candidate| candidate.id != folder.id);
        } else {
            merge_by_id(folders, vec![folder], |candidate| candidate.id);
        }
        Ok(())
    }

    fn reload_unlocked(&mut self) -> Result<(), DesktopError> {
        let key = self
            .vault
            .as_ref()
            .map(|vault| vault.user_key.clone())
            .ok_or(DesktopError::Locked)?;
        self.load_unlocked(key)
    }

    fn require_unlocked(&self) -> Result<&UnlockedVault, DesktopError> {
        self.vault.as_ref().ok_or(DesktopError::Locked)
    }

    fn require_unlocked_mut(&mut self) -> Result<&mut UnlockedVault, DesktopError> {
        self.vault.as_mut().ok_or(DesktopError::Locked)
    }

    fn active_profile(&self) -> Option<&CachedProfile> {
        self.active
            .and_then(|index| self.document.profiles.get(index))
    }

    fn active_profile_mut(&mut self) -> Option<&mut CachedProfile> {
        self.active
            .and_then(|index| self.document.profiles.get_mut(index))
    }

    fn find_profile(&self, server_url: &str, email: &str) -> Option<usize> {
        let scope = profile_scope(server_url, email);
        self.document
            .profiles
            .iter()
            .position(|profile| profile.scope == scope)
    }

    fn persist(&self) -> Result<(), DesktopError> {
        persist_document(&self.cache_path, &self.document)
    }
}

fn load_document(path: &Path) -> Result<CacheDocument, DesktopError> {
    if !path.exists() {
        return Ok(CacheDocument::default());
    }
    let metadata = fs::metadata(path).map_err(|_| DesktopError::Cache)?;
    if metadata.len() > MAX_CACHE_BYTES {
        return Err(DesktopError::Cache);
    }
    let bytes = fs::read(path).map_err(|_| DesktopError::Cache)?;
    let document: CacheDocument =
        serde_json::from_slice(&bytes).map_err(|_| DesktopError::Cache)?;
    if document.version != CACHE_VERSION
        || !(1..=240).contains(&document.auto_lock_minutes)
        || document.profiles.len() > MAX_PROFILES
        || document
            .profiles
            .iter()
            .any(|profile| profile.replica.objects().len() > MAX_ITEMS)
    {
        return Err(DesktopError::Cache);
    }
    Ok(document)
}

fn persist_document(path: &Path, document: &CacheDocument) -> Result<(), DesktopError> {
    let parent = path.parent().ok_or(DesktopError::Cache)?;
    fs::create_dir_all(parent).map_err(|_| DesktopError::Cache)?;
    let bytes = serde_json::to_vec(document).map_err(|_| DesktopError::Cache)?;
    if u64::try_from(bytes.len()).map_err(|_| DesktopError::Cache)? > MAX_CACHE_BYTES {
        return Err(DesktopError::Cache);
    }
    let mut temporary = NamedTempFile::new_in(parent).map_err(|_| DesktopError::Cache)?;
    temporary
        .write_all(&bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| DesktopError::Cache)?;
    temporary.persist(path).map_err(|_| DesktopError::Cache)?;
    Ok(())
}

fn credential_size(credential: &Value) -> Result<usize, DesktopError> {
    serde_json::to_vec(credential)
        .map(|value| value.len())
        .map_err(|_| DesktopError::InvalidInput)
}

fn canonical_server(value: &str) -> Result<(String, ApiClient), DesktopError> {
    let client = ApiClient::new(value).map_err(map_client_error)?;
    let url = Url::parse(value.trim()).map_err(|_| DesktopError::InvalidInput)?;
    Ok((url.origin().ascii_serialization(), client))
}

fn normalize_email(value: &str) -> Result<String, DesktopError> {
    let email = value.trim().to_lowercase();
    if email.is_empty()
        || email.len() > 320
        || !email.contains('@')
        || email.chars().any(char::is_control)
    {
        return Err(DesktopError::InvalidInput);
    }
    Ok(email)
}

fn profile_scope(server_url: &str, email: &str) -> String {
    let digest = Sha256::digest(format!("{server_url}\0{email}").as_bytes());
    hex::encode(digest)
}

fn refresh_secret_key(profile: &CachedProfile) -> String {
    format!("refresh-{}", profile.scope)
}

fn device_secret_key(profile: &CachedProfile) -> String {
    format!("device-{}", profile.scope)
}

fn desktop_device(identifier: Uuid) -> DeviceRequest {
    DeviceRequest {
        identifier,
        name: "Hasilan Pass Desktop".to_owned(),
        device_type: "desktop".to_owned(),
    }
}

fn kdf_config(settings: &KdfSettings) -> Result<KdfConfig, DesktopError> {
    let config = match settings.kdf_type {
        KdfType::Pbkdf2 => KdfConfig::Pbkdf2 {
            iterations: settings.iterations,
        },
        KdfType::Argon2id => KdfConfig::Argon2id {
            iterations: settings.iterations,
            memory_mib: settings.memory_mib.ok_or(DesktopError::InvalidInput)?,
            parallelism: settings.parallelism.ok_or(DesktopError::InvalidInput)?,
        },
    };
    config.validate().map_err(|_| DesktopError::InvalidInput)?;
    Ok(config)
}

fn decrypt_replica(
    replica: &Replica,
    user_key: &CompositeKey,
    organization_keys: &BTreeMap<Uuid, CompositeKey>,
) -> Result<(BTreeMap<Uuid, VaultItem>, Vec<BitwardenFolder>), DesktopError> {
    let mut items = BTreeMap::new();
    let mut folders = Vec::new();
    for object in replica.objects().values() {
        match object.kind {
            ObjectKind::Cipher => {
                let mut item = decrypt_object(object, user_key, organization_keys)?;
                item.deleted_date = object.deleted_at;
                items.insert(item.id, item);
            }
            ObjectKind::Folder => {
                if object.deleted_at.is_some() {
                    remove_folder_projection(&mut folders, &mut items, object.id);
                } else {
                    merge_by_id(
                        &mut folders,
                        vec![decrypt_folder_object(object, user_key)?],
                        |folder| folder.id,
                    );
                }
            }
            ObjectKind::OrganizationKey => return Err(DesktopError::Crypto),
        }
    }
    for mutation in replica.outbox() {
        match mutation.object.kind {
            ObjectKind::Cipher => {
                let mut item = decrypt_object(&mutation.object, user_key, organization_keys)?;
                if mutation.delete {
                    item.deleted_date = mutation.object.deleted_at.or(Some(Utc::now()));
                }
                items.insert(item.id, item);
            }
            ObjectKind::Folder => {
                if mutation.delete {
                    remove_folder_projection(&mut folders, &mut items, mutation.object.id);
                } else {
                    merge_by_id(
                        &mut folders,
                        vec![decrypt_folder_object(&mutation.object, user_key)?],
                        |folder| folder.id,
                    );
                }
            }
            ObjectKind::OrganizationKey => return Err(DesktopError::Crypto),
        }
    }
    if items.len() > MAX_ITEMS || folders.len() > MAX_FOLDERS {
        return Err(DesktopError::Cache);
    }
    let folder_ids: BTreeSet<_> = folders.iter().map(|folder| folder.id).collect();
    for item in items.values_mut() {
        if item.folder_id.is_some_and(|id| !folder_ids.contains(&id)) {
            item.folder_id = None;
        }
    }
    Ok((items, folders))
}

fn decrypt_object(
    object: &EncryptedObject,
    user_key: &CompositeKey,
    organization_keys: &BTreeMap<Uuid, CompositeKey>,
) -> Result<VaultItem, DesktopError> {
    let key = match object.owner_type {
        OwnerType::User => user_key,
        OwnerType::Organization => organization_keys
            .get(&object.owner_id)
            .ok_or(DesktopError::Crypto)?,
    };
    let item: VaultItem = decrypt_json(
        &EncryptedEnvelope {
            format: object.format.clone(),
            wrapped_key: object.wrapped_key.clone(),
            payload: object.payload.clone(),
        },
        key,
    )
    .map_err(|_| DesktopError::Crypto)?;
    let metadata_matches = item.id == object.id
        && item.collection_ids == object.collection_ids
        && match object.owner_type {
            OwnerType::User => item.organization_id.is_none() && item.collection_ids.is_empty(),
            OwnerType::Organization => item.organization_id == Some(object.owner_id),
        };
    if object.kind != ObjectKind::Cipher || !metadata_matches {
        return Err(DesktopError::Crypto);
    }
    Ok(item)
}

fn decrypt_folder_object(
    object: &EncryptedObject,
    user_key: &CompositeKey,
) -> Result<BitwardenFolder, DesktopError> {
    if object.kind != ObjectKind::Folder
        || object.owner_type != OwnerType::User
        || !object.collection_ids.is_empty()
    {
        return Err(DesktopError::Crypto);
    }
    let folder: BitwardenFolder = decrypt_json(
        &EncryptedEnvelope {
            format: object.format.clone(),
            wrapped_key: object.wrapped_key.clone(),
            payload: object.payload.clone(),
        },
        user_key,
    )
    .map_err(|_| DesktopError::Crypto)?;
    if folder.id != object.id || validate_folder_name(&folder.name).is_err() {
        return Err(DesktopError::Crypto);
    }
    Ok(folder)
}

fn open_cached_organization_keys(
    profile: &CachedProfile,
    user_key: &CompositeKey,
) -> Result<(Option<SharingPrivateKey>, BTreeMap<Uuid, CompositeKey>), DesktopError> {
    let Some(sharing) = &profile.sharing_key else {
        return Ok((None, BTreeMap::new()));
    };
    let protected_private_key = sharing
        .protected_private_key
        .as_deref()
        .ok_or(DesktopError::Crypto)?;
    let private = unwrap_sharing_private_key(&sharing.public_key, protected_private_key, user_key)
        .map_err(|_| DesktopError::Crypto)?;
    let mut keys = BTreeMap::new();
    for organization in &profile.organizations {
        if matches!(
            organization.status,
            MembershipStatus::Accepted | MembershipStatus::Confirmed
        ) {
            let wrapper = organization
                .encrypted_organization_key
                .as_deref()
                .ok_or(DesktopError::Crypto)?;
            let key = open_organization_key(&private, organization.id, wrapper)
                .map_err(|_| DesktopError::Crypto)?;
            keys.insert(organization.id, key);
        }
    }
    Ok((Some(private), keys))
}

fn put_request(mutation: &PendingMutation) -> PutObjectRequest {
    PutObjectRequest {
        kind: mutation.object.kind,
        owner_type: mutation.object.owner_type,
        owner_id: mutation.object.owner_id,
        collection_ids: mutation.object.collection_ids.clone(),
        format: mutation.object.format.clone(),
        wrapped_key: mutation.object.wrapped_key.clone(),
        payload: mutation.object.payload.clone(),
        base_revision: mutation.base_revision,
        idempotency_key: mutation.idempotency_key,
    }
}

fn attachment_initiate_request(
    profile: &CachedProfile,
    item_id: Uuid,
    metadata: &AttachmentMetadata,
) -> Result<AttachmentInitiateRequest, DesktopError> {
    if profile.replica.conflicts().contains_key(&item_id) {
        return Err(DesktopError::Conflict);
    }
    if profile
        .replica
        .outbox()
        .iter()
        .any(|mutation| mutation.object.id == item_id)
    {
        return Err(DesktopError::Sync);
    }
    let object = profile
        .replica
        .objects()
        .get(&item_id)
        .filter(|object| object.kind == ObjectKind::Cipher && object.deleted_at.is_none())
        .ok_or(DesktopError::NotFound)?;
    if object.object_revision <= 0 {
        return Err(DesktopError::Sync);
    }
    Ok(AttachmentInitiateRequest {
        id: metadata.id,
        object_id: item_id,
        object_revision: object.object_revision,
        format: metadata.format().to_owned(),
        chunk_size: metadata.chunk_size,
        chunk_count: metadata.chunk_count,
        ciphertext_size: metadata.ciphertext_size,
    })
}

fn validate_attachment_response(
    response: &AttachmentResponse,
    item_id: Uuid,
    metadata: &AttachmentMetadata,
    expected_revision: Option<i64>,
) -> Result<(), DesktopError> {
    if response.id != metadata.id
        || response.object_id != item_id
        || response.format != metadata.format()
        || response.chunk_size != metadata.chunk_size
        || response.chunk_count != metadata.chunk_count
        || response.ciphertext_size != metadata.ciphertext_size
    {
        return Err(DesktopError::Server(
            "attachment_metadata_mismatch".to_owned(),
        ));
    }
    if expected_revision.is_some_and(|revision| response.object_revision != revision) {
        return Err(DesktopError::Server("attachment_parent_changed".to_owned()));
    }
    Ok(())
}

fn media_type_for_path(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("txt" | "log" | "md") => "text/plain",
        Some("csv") => "text/csv",
        Some("json") => "application/json",
        Some("pdf") => "application/pdf",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("svg") => "image/svg+xml",
        Some("zip") => "application/zip",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some("xlsx") => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        _ => "application/octet-stream",
    }
}

fn item_summary(item: &VaultItem, profile: &CachedProfile) -> ItemSummary {
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
        object_revision: profile
            .replica
            .objects()
            .get(&item.id)
            .map(|object| object.object_revision),
        pending: profile
            .replica
            .outbox()
            .iter()
            .any(|mutation| mutation.object.id == item.id),
        conflicted: profile.replica.conflicts().contains_key(&item.id),
        organization_id: item.organization_id,
        collection_ids: item.collection_ids.clone(),
    }
}

fn category_matches(item: &VaultItem, category: &str) -> bool {
    if let Some(folder_id) = category.strip_prefix("folder:") {
        return item.deleted_date.is_none()
            && item.folder_id.is_some_and(|id| id.to_string() == folder_id);
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

fn validate_folder_name(name: &str) -> Result<String, DesktopError> {
    let name = name.trim().to_owned();
    if name.is_empty() || name.len() > 1_000 || name.chars().any(char::is_control) {
        return Err(DesktopError::InvalidInput);
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

fn validate_organization_write(
    profile: &CachedProfile,
    organization_id: Option<Uuid>,
    collection_ids: &[Uuid],
) -> Result<(), DesktopError> {
    let Some(organization_id) = organization_id else {
        return collection_ids
            .is_empty()
            .then_some(())
            .ok_or(DesktopError::InvalidInput);
    };
    let organization = profile
        .organizations
        .iter()
        .find(|organization| {
            organization.id == organization_id && organization.status == MembershipStatus::Confirmed
        })
        .ok_or(DesktopError::InvalidInput)?;
    let elevated = matches!(
        organization.role,
        OrganizationRole::Owner | OrganizationRole::Admin
    );
    if collection_ids.is_empty() {
        return elevated.then_some(()).ok_or(DesktopError::InvalidInput);
    }
    let writable = collection_ids.iter().all(|id| {
        profile.organization_collections.iter().any(|collection| {
            collection.id == *id
                && collection.organization_id == organization_id
                && (elevated || !collection.read_only)
        })
    });
    writable.then_some(()).ok_or(DesktopError::InvalidInput)
}

fn apply_login_draft(
    existing: Option<VaultItem>,
    draft: LoginDraft,
    now: DateTime<Utc>,
) -> Result<VaultItem, DesktopError> {
    let LoginDraft {
        id: _,
        name,
        username,
        password,
        uri,
        totp,
        notes,
        favorite,
        folder_id,
        fields,
        organization_id,
        collection_ids,
    } = draft;
    let Some(mut item) = existing else {
        let mut item = VaultItem::new_login(
            name,
            Login {
                username: normalize_optional(username),
                password: normalize_secret(password),
                uris: normalize_optional(uri)
                    .map(|uri| LoginUri {
                        uri,
                        r#match: Some(UriMatchType::Domain),
                        extra: serde_json::Map::new(),
                    })
                    .into_iter()
                    .collect(),
                totp: normalize_secret(totp),
                ..Login::default()
            },
        );
        item.notes = normalize_optional_verbatim(notes);
        item.favorite = favorite;
        item.folder_id = folder_id;
        item.fields = fields;
        item.organization_id = organization_id;
        item.collection_ids = collection_ids;
        return Ok(item);
    };
    {
        let ItemData::Login(login) = &mut item.data else {
            return Err(DesktopError::InvalidInput);
        };
        let next_password = normalize_secret(password);
        if login.password != next_password {
            if let Some(previous) = login.password.take() {
                item.password_history.push(PasswordHistory {
                    password: previous,
                    last_used_date: now,
                });
                if item.password_history.len() > 20 {
                    item.password_history.remove(0);
                }
            }
            login.password = next_password;
            login.password_revision_date = Some(now);
        }
        login.username = normalize_optional(username);
        login.totp = normalize_secret(totp);
        match normalize_optional(uri) {
            Some(uri) => {
                if let Some(existing_uri) = login.uris.first_mut() {
                    existing_uri.uri = uri;
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
    }
    item.name = name;
    item.notes = normalize_optional_verbatim(notes);
    item.favorite = favorite;
    item.folder_id = folder_id;
    item.fields = fields;
    item.revision_date = now;
    Ok(item)
}

fn validate_login_draft(draft: &mut LoginDraft) -> Result<(), DesktopError> {
    draft.name = draft.name.trim().to_owned();
    if draft.name.is_empty() || draft.name.len() > 2_000 {
        return Err(DesktopError::InvalidInput);
    }
    if (draft.organization_id.is_none() && !draft.collection_ids.is_empty())
        || draft.collection_ids.len() > 100
        || draft.collection_ids.iter().collect::<BTreeSet<_>>().len() != draft.collection_ids.len()
        || !valid_custom_fields(&draft.fields)
    {
        return Err(DesktopError::InvalidInput);
    }
    if draft
        .username
        .as_ref()
        .is_some_and(|value| value.len() > 2_000)
        || draft
            .password
            .as_ref()
            .is_some_and(|value| value.len() > 16_384)
        || draft
            .notes
            .as_ref()
            .is_some_and(|value| value.len() > 1_000_000)
    {
        return Err(DesktopError::InvalidInput);
    }
    if let Some(uri) = draft
        .uri
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        let parsed = Url::parse(uri).map_err(|_| DesktopError::InvalidInput)?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            return Err(DesktopError::InvalidInput);
        }
    }
    if let Some(totp) = draft
        .totp
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        TotpConfig::parse(totp).map_err(|_| DesktopError::InvalidInput)?;
    }
    Ok(())
}

fn validate_item_draft(draft: &mut ItemDraft) -> Result<(), DesktopError> {
    draft.name = draft.name.trim().to_owned();
    if draft.name.is_empty()
        || draft.name.len() > 2_000
        || draft
            .notes
            .as_ref()
            .is_some_and(|value| value.len() > 1_000_000)
        || draft.fields.len() > 100
        || (draft.organization_id.is_none() && !draft.collection_ids.is_empty())
        || draft.collection_ids.len() > 100
        || draft.collection_ids.iter().collect::<BTreeSet<_>>().len() != draft.collection_ids.len()
    {
        return Err(DesktopError::InvalidInput);
    }
    if !valid_custom_fields(&draft.fields) {
        return Err(DesktopError::InvalidInput);
    }
    if !matches!(
        draft.data,
        ItemData::SecureNote(_) | ItemData::Card(_) | ItemData::Identity(_)
    ) {
        return Err(DesktopError::InvalidInput);
    }
    let serialized = serde_json::to_vec(&draft.data).map_err(|_| DesktopError::InvalidInput)?;
    if serialized.len() > 1_000_000 {
        return Err(DesktopError::InvalidInput);
    }
    Ok(())
}

fn valid_custom_fields(fields: &[CustomField]) -> bool {
    fields.len() <= 100
        && fields.iter().all(|field| {
            field.name.as_ref().is_none_or(|value| value.len() <= 2_000)
                && field
                    .value
                    .as_ref()
                    .is_none_or(|value| value.expose().len() <= 16_384)
                && field.field_type <= 2
        })
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| (!value.trim().is_empty()).then(|| value.trim().to_owned()))
}

fn normalize_optional_verbatim(value: Option<String>) -> Option<String> {
    value.and_then(|value| (!value.trim().is_empty()).then_some(value))
}

fn normalize_secret(value: Option<String>) -> Option<SecretString> {
    normalize_optional_verbatim(value).map(SecretString::new)
}

fn merge_by_id<T, F>(target: &mut Vec<T>, incoming: Vec<T>, id: F)
where
    F: Fn(&T) -> Uuid,
{
    let incoming_ids: BTreeSet<Uuid> = incoming.iter().map(&id).collect();
    target.retain(|value| !incoming_ids.contains(&id(value)));
    target.extend(incoming);
}

fn default_auto_lock_minutes() -> u32 {
    DEFAULT_AUTO_LOCK_MINUTES
}

fn is_unauthorized(error: &ClientError) -> bool {
    matches!(error, ClientError::Api { status, .. } if status.as_u16() == 401)
}

fn is_not_found(error: &ClientError) -> bool {
    matches!(error, ClientError::Api { status, .. } if status.as_u16() == 404)
}

fn map_client_error(error: ClientError) -> DesktopError {
    match error {
        ClientError::Network(_) => DesktopError::Offline,
        ClientError::Api { code, .. } => DesktopError::Server(code),
        ClientError::InvalidUrl | ClientError::InsecureUrl => DesktopError::InvalidInput,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test assertions intentionally fail fast"
)]
mod tests {
    use hasilan_crypto::seal_organization_key;
    use hasilan_vault::{Card, SecretString};
    use tempfile::tempdir;

    use super::*;

    const MASTER_PASSWORD: &str = "a long offline master password!";

    fn token(account_id: Uuid, protected_user_key: String) -> TokenResponse {
        TokenResponse {
            account_id,
            access_token: "memory-only-access-token".to_owned(),
            refresh_token: "keychain-only-refresh-token".to_owned(),
            token_type: "Bearer".to_owned(),
            expires_in: 900,
            protected_user_key,
            kdf: KdfSettings::default(),
            session_id: Uuid::new_v4(),
            device_id: Uuid::new_v4(),
            trusted_device_token: None,
        }
    }

    fn unlocked_fixture(path: &Path) -> (DesktopClient, Arc<MemorySecretStore>) {
        let secrets = Arc::new(MemorySecretStore::default());
        let mut client = DesktopClient::open(path, secrets.clone()).unwrap();
        let prepared = prepare_registration(
            "alice@example.test",
            MASTER_PASSWORD.as_bytes(),
            &KdfConfig::default(),
        )
        .unwrap();
        let token = token(Uuid::new_v4(), prepared.protected_user_key);
        let profile = CachedProfile {
            scope: profile_scope("http://127.0.0.1:18080", "alice@example.test"),
            server_url: "http://127.0.0.1:18080".to_owned(),
            email: "alice@example.test".to_owned(),
            account_id: token.account_id,
            device_identifier: Uuid::new_v4(),
            kdf: token.kdf.clone(),
            protected_user_key: token.protected_user_key.clone(),
            replica: Replica::default(),
            folders: Vec::new(),
            collections: Vec::new(),
            sharing_key: None,
            organizations: Vec::new(),
            organization_collections: Vec::new(),
            pending_attachment_deletions: Vec::new(),
            last_sync_at: None,
        };
        client.document.profiles.push(profile);
        client.active = Some(0);
        client.document.active_scope = Some(client.document.profiles[0].scope.clone());
        client.vault = Some(UnlockedVault {
            user_key: prepared.user_key,
            sharing_private_key: None,
            organization_keys: BTreeMap::new(),
            items: BTreeMap::new(),
            folders: Vec::new(),
        });
        client.persist().unwrap();
        (client, secrets)
    }

    fn login_item() -> VaultItem {
        let mut item = VaultItem::new_login(
            "Private banking",
            Login {
                username: Some("alice-secret@example.test".to_owned()),
                password: Some(SecretString::new("correct horse battery staple")),
                uris: vec![LoginUri {
                    uri: "https://bank.example.test/login".to_owned(),
                    r#match: Some(UriMatchType::Host),
                    extra: serde_json::Map::new(),
                }],
                totp: Some(SecretString::new("JBSWY3DPEHPK3PXP")),
                ..Login::default()
            },
        );
        item.notes = Some("private desktop note".to_owned());
        item
    }

    #[test]
    fn durable_cache_contains_ciphertext_not_vault_plaintext() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-cache.json");
        let (mut client, _) = unlocked_fixture(&path);
        client.queue_item(login_item(), false).unwrap();

        let raw = fs::read_to_string(path).unwrap();
        for secret in [
            "Private banking",
            "alice-secret@example.test",
            "correct horse battery staple",
            "JBSWY3DPEHPK3PXP",
            "private desktop note",
        ] {
            assert!(!raw.contains(secret), "cache exposed {secret}");
        }
        assert!(raw.contains("wrappedKey"));
        assert!(raw.contains("payload"));
    }

    #[test]
    fn typed_non_login_items_use_the_same_encrypted_offline_replica() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-cache.json");
        let (mut client, _) = unlocked_fixture(&path);
        let item = client
            .save_item_local(ItemDraft {
                id: None,
                name: "Travel card".to_owned(),
                notes: Some("Use abroad".to_owned()),
                favorite: true,
                folder_id: None,
                fields: Vec::new(),
                data: ItemData::Card(Card {
                    cardholder_name: Some("Alice Example".to_owned()),
                    number: Some(SecretString::new("4111111111111111")),
                    code: Some(SecretString::new("8675309-secret-cvc")),
                    ..Card::default()
                }),
                organization_id: None,
                collection_ids: Vec::new(),
            })
            .unwrap();
        assert_eq!(item.item_type(), 3);
        assert_eq!(client.list_items("travel", "cards").unwrap().len(), 1);

        let raw = fs::read_to_string(path).unwrap();
        assert!(!raw.contains("Travel card"));
        assert!(!raw.contains("4111111111111111"));
        assert!(!raw.contains("8675309-secret-cvc"));
    }

    #[tokio::test]
    async fn folders_use_encrypted_objects_and_delete_detaches_personal_items() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-cache.json");
        let (mut client, secrets) = unlocked_fixture(&path);
        let folder = client
            .save_folder_local(&FolderDraft {
                id: None,
                name: "Private travel".to_owned(),
            })
            .unwrap();
        let item = client
            .save_login_local(LoginDraft {
                id: None,
                name: "Airline account".to_owned(),
                username: Some("alice@example.test".to_owned()),
                password: Some("seat-42-secret".to_owned()),
                uri: Some("https://airline.example.test".to_owned()),
                totp: None,
                notes: None,
                favorite: false,
                folder_id: Some(folder.id),
                fields: Vec::new(),
                organization_id: None,
                collection_ids: Vec::new(),
            })
            .unwrap();
        assert_eq!(
            client.organization_catalog().unwrap().folders[0].name,
            "Private travel"
        );
        assert_eq!(
            client
                .list_items("", &format!("folder:{}", folder.id))
                .unwrap()
                .len(),
            1
        );

        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("Private travel"));
        assert!(!raw.contains("Airline account"));
        assert!(raw.contains(&folder.id.to_string()));

        client.lock();
        drop(client);
        let mut reopened = DesktopClient::open(&path, secrets).unwrap();
        reopened
            .unlock_offline(
                Some(0),
                ApiClient::new("http://127.0.0.1:18080").unwrap(),
                MASTER_PASSWORD,
            )
            .unwrap();
        assert_eq!(
            reopened.organization_catalog().unwrap().folders[0].id,
            folder.id
        );
        assert_eq!(
            reopened.get_item(item.id).unwrap().folder_id,
            Some(folder.id)
        );

        let status = reopened.delete_folder(folder.id).await.unwrap();
        assert!(status.unlocked);
        assert!(reopened.organization_catalog().unwrap().folders.is_empty());
        assert_eq!(reopened.get_item(item.id).unwrap().folder_id, None);
    }

    #[test]
    fn android_biometric_unlock_and_uri_matched_autofill_reuse_the_encrypted_cache() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-cache.json");
        let (mut client, _) = unlocked_fixture(&path);
        let item = login_item();
        let id = item.id;
        client.queue_item(item, false).unwrap();

        let key = client.biometric_unlock_key().unwrap();
        client.lock();
        assert!(
            client
                .autofill_candidates("https://bank.example.test")
                .is_err()
        );
        client.unlock_with_biometric_key(&key).unwrap();
        let matches = client
            .autofill_candidates("https://bank.example.test")
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, id);
        assert_eq!(
            matches[0].username.as_deref(),
            Some("alice-secret@example.test")
        );
        assert_eq!(
            matches[0].password.as_deref(),
            Some("correct horse battery staple")
        );
        assert!(
            client
                .autofill_candidates("https://unrelated.example.test")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn android_autofill_never_releases_hidden_collection_passwords() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-cache.json");
        let (mut client, _) = unlocked_fixture(&path);
        let collection_id = Uuid::new_v4();
        let item = login_item();
        let item_id = item.id;
        client.queue_item(item, false).unwrap();
        client
            .require_unlocked_mut()
            .unwrap()
            .items
            .get_mut(&item_id)
            .unwrap()
            .collection_ids = vec![collection_id];
        client
            .active_profile_mut()
            .unwrap()
            .organization_collections = vec![CollectionResponse {
            id: collection_id,
            organization_id: Uuid::new_v4(),
            name: "No password fill".to_owned(),
            read_only: false,
            hide_passwords: true,
            manage: false,
            created_at: Utc::now(),
        }];

        assert!(
            client
                .autofill_candidates("https://bank.example.test")
                .unwrap()
                .is_empty()
        );
        assert!(client.credential_password_candidates().unwrap().is_empty());
    }

    #[test]
    fn attachment_private_metadata_is_ciphertext_only_in_the_offline_cache() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-cache.json");
        let (mut client, _) = unlocked_fixture(&path);
        let mut item = login_item();
        let attachment = AttachmentMetadata::generate(
            "private-tax-return.pdf",
            "application/pdf",
            70_000,
            DEFAULT_ATTACHMENT_CHUNK_SIZE,
        )
        .unwrap();
        let serialized = serde_json::to_value(&attachment).unwrap();
        let encoded_key = serialized["key"].as_str().unwrap().to_owned();
        let encoded_nonce = serialized["fileNonce"].as_str().unwrap().to_owned();
        item.attachments.push(attachment);
        client.queue_item(item, false).unwrap();

        let raw = fs::read_to_string(path).unwrap();
        assert!(!raw.contains("private-tax-return.pdf"));
        assert!(!raw.contains("application/pdf"));
        assert!(!raw.contains(&encoded_key));
        assert!(!raw.contains(&encoded_nonce));
    }

    #[tokio::test]
    async fn offline_attachment_removal_durably_queues_blob_cleanup() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-cache.json");
        let (mut client, secrets) = unlocked_fixture(&path);
        let mut item = login_item();
        let attachment = AttachmentMetadata::generate(
            "remove-me.bin",
            "application/octet-stream",
            4,
            DEFAULT_ATTACHMENT_CHUNK_SIZE,
        )
        .unwrap();
        let item_id = item.id;
        let attachment_id = attachment.id;
        item.attachments.push(attachment);
        client.queue_item(item, false).unwrap();

        let result = client
            .remove_attachment(item_id, attachment_id)
            .await
            .unwrap();
        assert!(result.cleanup_pending);
        assert!(result.item.attachments.is_empty());
        assert_eq!(
            client
                .active_profile()
                .unwrap()
                .pending_attachment_deletions
                .len(),
            1
        );

        client.lock();
        drop(client);
        let mut reopened = DesktopClient::open(&path, secrets).unwrap();
        let api = ApiClient::new("http://127.0.0.1:18080").unwrap();
        reopened
            .unlock_offline(Some(0), api, MASTER_PASSWORD)
            .unwrap();
        assert!(reopened.get_item(item_id).unwrap().attachments.is_empty());
        assert_eq!(
            reopened
                .active_profile()
                .unwrap()
                .pending_attachment_deletions[0]
                .id,
            attachment_id
        );
    }

    #[test]
    fn cached_profile_unlocks_offline_and_rejects_a_wrong_password() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-cache.json");
        let (mut client, secrets) = unlocked_fixture(&path);
        let item = login_item();
        let id = item.id;
        client.queue_item(item, false).unwrap();
        client.lock();
        drop(client);

        let mut reopened = DesktopClient::open(&path, secrets.clone()).unwrap();
        let api = ApiClient::new("http://127.0.0.1:18080").unwrap();
        let status = reopened
            .unlock_offline(Some(0), api, MASTER_PASSWORD)
            .unwrap();
        assert!(status.unlocked);
        let item = reopened.get_item(id).unwrap();
        let ItemData::Login(login) = item.data else {
            panic!("expected login");
        };
        assert_eq!(
            login.password.as_ref().map(SecretString::expose),
            Some("correct horse battery staple")
        );

        reopened.lock();
        let api = ApiClient::new("http://127.0.0.1:18080").unwrap();
        assert!(matches!(
            reopened.unlock_offline(Some(0), api, "wrong password"),
            Err(DesktopError::UnlockFailed)
        ));
    }

    #[test]
    fn refresh_token_and_device_secret_use_the_secret_store_only() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-cache.json");
        let (client, secrets) = unlocked_fixture(&path);
        let profile = &client.document.profiles[0];
        let session = token(profile.account_id, profile.protected_user_key.clone());
        client.store_session_secrets(0, &session).unwrap();

        assert_eq!(
            secrets.get(&refresh_secret_key(profile)).unwrap(),
            Some(b"keychain-only-refresh-token".to_vec())
        );
        assert_eq!(
            secrets
                .get(&device_secret_key(profile))
                .unwrap()
                .unwrap()
                .len(),
            32
        );
        let raw = fs::read_to_string(path).unwrap();
        assert!(!raw.contains("keychain-only-refresh-token"));
    }

    #[tokio::test]
    async fn offline_edits_queue_and_preserve_password_history() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-cache.json");
        let (mut client, _) = unlocked_fixture(&path);
        let created = client
            .save_login(LoginDraft {
                id: None,
                name: "Offline login".to_owned(),
                username: Some("alice".to_owned()),
                password: Some("old offline password".to_owned()),
                uri: Some("https://example.test".to_owned()),
                totp: None,
                notes: None,
                favorite: false,
                folder_id: None,
                fields: Vec::new(),
                organization_id: None,
                collection_ids: Vec::new(),
            })
            .await
            .unwrap();
        let updated = client
            .save_login(LoginDraft {
                id: Some(created.id),
                name: "Offline login updated".to_owned(),
                username: Some("alice".to_owned()),
                password: Some("new offline password".to_owned()),
                uri: Some("https://example.test/login".to_owned()),
                totp: None,
                notes: None,
                favorite: true,
                folder_id: None,
                fields: Vec::new(),
                organization_id: None,
                collection_ids: Vec::new(),
            })
            .await
            .unwrap();
        assert_eq!(updated.password_history.len(), 1);
        assert_eq!(
            updated.password_history[0].password.expose(),
            "old offline password"
        );
        assert_eq!(client.active_profile().unwrap().replica.outbox().len(), 1);
    }

    #[tokio::test]
    async fn shared_collection_item_reopens_offline_under_cached_organization_key() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-cache.json");
        let (mut client, secrets) = unlocked_fixture(&path);
        let organization_id = Uuid::new_v4();
        let collection_id = Uuid::new_v4();
        let user_key = client.require_unlocked().unwrap().user_key.clone();
        let sharing = generate_sharing_key(&user_key).unwrap();
        let private = unwrap_sharing_private_key(
            &sharing.public_key,
            &sharing.protected_private_key,
            &user_key,
        )
        .unwrap();
        let organization_key = CompositeKey::generate().unwrap();
        let wrapper =
            seal_organization_key(organization_id, &sharing.public_key, &organization_key).unwrap();
        let account_id = client.active_profile().unwrap().account_id;
        {
            let profile = client.active_profile_mut().unwrap();
            profile.sharing_key = Some(SharingKeyResponse {
                account_id,
                public_key: sharing.public_key,
                protected_private_key: Some(sharing.protected_private_key),
            });
            profile.organizations = vec![OrganizationResponse {
                id: organization_id,
                member_id: Uuid::new_v4(),
                name: "Engineering".to_owned(),
                role: OrganizationRole::User,
                status: MembershipStatus::Confirmed,
                encrypted_organization_key: Some(wrapper),
                created_at: Utc::now(),
            }];
            profile.organization_collections = vec![CollectionResponse {
                id: collection_id,
                organization_id,
                name: "Production".to_owned(),
                read_only: false,
                hide_passwords: false,
                manage: false,
                created_at: Utc::now(),
            }];
        }
        {
            let vault = client.require_unlocked_mut().unwrap();
            vault.sharing_private_key = Some(private);
            vault
                .organization_keys
                .insert(organization_id, organization_key);
        }

        let created = client
            .save_login(LoginDraft {
                id: None,
                name: "Shared production deploy".to_owned(),
                username: Some("organization-secret-user".to_owned()),
                password: Some("organization-secret-password".to_owned()),
                uri: Some("https://deploy.example.test".to_owned()),
                totp: None,
                notes: None,
                favorite: false,
                folder_id: None,
                fields: Vec::new(),
                organization_id: Some(organization_id),
                collection_ids: vec![collection_id],
            })
            .await
            .unwrap();
        let catalog = client.organization_catalog().unwrap();
        assert_eq!(catalog.organizations.len(), 1);
        assert_eq!(catalog.collections.len(), 1);
        assert!(!catalog.collections[0].read_only);
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("organization-secret-user"));
        assert!(!raw.contains("organization-secret-password"));

        client.lock();
        drop(client);
        let mut reopened = DesktopClient::open(&path, secrets).unwrap();
        let api = ApiClient::new("http://127.0.0.1:18080").unwrap();
        reopened
            .unlock_offline(Some(0), api, MASTER_PASSWORD)
            .unwrap();
        let reopened_item = reopened.get_item(created.id).unwrap();
        assert_eq!(reopened_item.organization_id, Some(organization_id));
        let ItemData::Login(login) = reopened_item.data else {
            panic!("expected login");
        };
        assert_eq!(
            login.password.as_ref().map(SecretString::expose),
            Some("organization-secret-password")
        );
    }

    #[tokio::test]
    async fn read_only_or_unknown_organization_destinations_are_rejected_locally() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-cache.json");
        let (mut client, _) = unlocked_fixture(&path);
        let organization_id = Uuid::new_v4();
        let collection_id = Uuid::new_v4();
        client.active_profile_mut().unwrap().organizations = vec![OrganizationResponse {
            id: organization_id,
            member_id: Uuid::new_v4(),
            name: "Read only".to_owned(),
            role: OrganizationRole::User,
            status: MembershipStatus::Confirmed,
            encrypted_organization_key: Some("opaque-wrapper".to_owned()),
            created_at: Utc::now(),
        }];
        client
            .active_profile_mut()
            .unwrap()
            .organization_collections = vec![CollectionResponse {
            id: collection_id,
            organization_id,
            name: "Audit".to_owned(),
            read_only: true,
            hide_passwords: true,
            manage: false,
            created_at: Utc::now(),
        }];
        let result = client
            .save_login(LoginDraft {
                id: None,
                name: "Must not queue".to_owned(),
                username: None,
                password: None,
                uri: None,
                totp: None,
                notes: None,
                favorite: false,
                folder_id: None,
                fields: Vec::new(),
                organization_id: Some(organization_id),
                collection_ids: vec![collection_id],
            })
            .await;
        assert!(matches!(result, Err(DesktopError::InvalidInput)));
        assert!(client.active_profile().unwrap().replica.outbox().is_empty());
    }

    #[test]
    fn automatic_lock_clears_decrypted_state() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vault-cache.json");
        let (mut client, _) = unlocked_fixture(&path);
        client.last_activity = Instant::now().checked_sub(Duration::from_secs(61)).unwrap();
        client.document.auto_lock_minutes = 1;
        assert!(client.lock_if_idle());
        assert!(!client.status().unlocked);
    }
}
