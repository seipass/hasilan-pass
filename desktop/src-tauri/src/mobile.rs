//! Android Tauri command boundary and secure native bridges.
//!
//! The Android activities and services call the exported JNI functions below only after an
//! Android Keystore / `BiometricPrompt` ceremony. They operate on this same
//! [`DesktopClient`] instance and encrypted cache as the Tauri UI, rather than maintaining a
//! second vault or a parallel crypto implementation.

use crate::android_deep_link::safe_android_deep_link;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex as StdMutex, OnceLock},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hasilan_desktop_core::{
    AccountSecuritySnapshot, AutofillCandidate, BitwardenFolder, ConflictSummary,
    CredentialPasskeyCandidate, DesktopClient, DesktopStatus, FolderDraft, ItemDraft, ItemSummary,
    LoginDraft, MemorySecretStore, OrganizationCatalog, SecretStore, SecretStoreError, TotpView,
};
use hasilan_protocol::{
    DeviceRequest, MfaEnableResponse, RecoveryCodesResponse, TotpSetupStartResponse,
};
use hasilan_vault::{
    PasskeyAssertionOptions, PasskeyCreationOptions, PassphraseOptions, PasswordOptions, VaultItem,
};
use jni::{
    JNIEnv,
    objects::{JByteArray, JClass, JString},
    sys::{jboolean, jstring},
};
use serde::{Deserialize, Serialize};
use tauri::{
    AppHandle, Emitter as _, Manager as _, RunEvent, State,
    plugin::{PluginApi, PluginHandle},
};
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroize;

const ANDROID_PLUGIN_IDENTIFIER: &str = "org.hasilan.pass";
const ANDROID_PLUGIN_CLASS: &str = "AndroidSecurityPlugin";

static MOBILE_CLIENT: OnceLock<Arc<Mutex<DesktopClient>>> = OnceLock::new();
/// A short-lived coordinator used only when Android starts an Autofill / Credential Manager
/// component before the Tauri Activity exists. Once the Activity has initialized, every system
/// component resolves [`MOBILE_CLIENT`] instead. That prevents a service-side offline save from
/// being hidden behind a stale, separate in-memory vault document in the foreground UI.
///
/// The pre-Activity coordinator reads the exact same ciphertext cache and has no persisted
/// secrets or network session, so Keystore biometric unwrap remains offline-only.
static SYSTEM_CLIENT: OnceLock<StdMutex<Option<Arc<Mutex<DesktopClient>>>>> = OnceLock::new();

struct MobileState {
    client: Arc<Mutex<DesktopClient>>,
}

/// Tauri's Kotlin plugin handle, used for Keystore persistence, BiometricPrompt, protected
/// clipboard operations, and Android settings intents.
#[derive(Clone)]
struct AndroidSecurity(PluginHandle<tauri::Wry>);

#[derive(Clone)]
struct AndroidSecretStore {
    security: AndroidSecurity,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SecretKeyPayload<'a> {
    key: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SecretValuePayload<'a> {
    key: &'a str,
    value: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretValueResponse {
    value: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClipboardPayload<'a> {
    value: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BiometricKeyPayload<'a> {
    key: &'a str,
    context: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountPasskeyOptionsPayload<'a> {
    options_json: &'a str,
}

#[derive(Deserialize)]
struct AccountPasskeyCredentialResponse {
    credential: String,
}

#[derive(Deserialize)]
struct AttachmentStagingResponse {
    path: String,
}

#[derive(Deserialize)]
struct AttachmentDownloadPreparation {
    handle: String,
    path: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttachmentDownloadPayload<'a> {
    file_name: &'a str,
}

#[derive(Serialize)]
struct AttachmentCommitPayload<'a> {
    handle: &'a str,
    path: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttachmentDownloadDiscardPayload<'a> {
    handle: &'a str,
    path: &'a str,
}

#[derive(Serialize)]
struct AttachmentStagingPayload<'a> {
    path: &'a str,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct BiometricStatus {
    enabled: bool,
    available: bool,
    #[serde(default)]
    storage_hardware_backed: bool,
    #[serde(default)]
    biometric_hardware_backed: bool,
    #[serde(default)]
    storage_strong_box_backed: bool,
    #[serde(default)]
    biometric_strong_box_backed: bool,
    #[serde(default)]
    strong_box_available: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClipboardPolicy {
    clear_after_seconds: u64,
}

#[derive(Deserialize, Serialize)]
struct TotpQrScan {
    value: String,
}

impl AndroidSecurity {
    fn run<T: for<'de> Deserialize<'de>>(
        &self,
        command: &str,
        payload: impl Serialize,
    ) -> Result<T, SecretStoreError> {
        self.0
            .run_mobile_plugin(command, payload)
            .map_err(|_| SecretStoreError)
    }

    async fn run_async<T: for<'de> Deserialize<'de>>(
        &self,
        command: &str,
        payload: impl Serialize,
    ) -> Result<T, String> {
        self.0
            .run_mobile_plugin_async(command, payload)
            .await
            .map_err(|_| "The Android security service is unavailable.".to_owned())
    }
}

impl SecretStore for AndroidSecretStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretStoreError> {
        let response: SecretValueResponse =
            self.security.run("getSecret", SecretKeyPayload { key })?;
        response
            .value
            .map(|value| STANDARD.decode(value).map_err(|_| SecretStoreError))
            .transpose()
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<(), SecretStoreError> {
        let encoded = STANDARD.encode(value);
        self.security.run::<()>(
            "setSecret",
            SecretValuePayload {
                key,
                value: &encoded,
            },
        )
    }

    fn delete(&self, key: &str) -> Result<(), SecretStoreError> {
        self.security
            .run::<()>("deleteSecret", SecretKeyPayload { key })
    }
}

type CommandResult<T> = Result<T, String>;

/// Initializes the Kotlin plugin before client state is created. Its synchronous Keystore calls
/// are intentionally confined to the native plugin thread, never the app WebView.
fn initialize_security_plugin(
    app: &AppHandle<tauri::Wry>,
    api: PluginApi<tauri::Wry, ()>,
) -> Result<(), Box<dyn std::error::Error>> {
    let handle = api.register_android_plugin(ANDROID_PLUGIN_IDENTIFIER, ANDROID_PLUGIN_CLASS)?;
    app.manage(AndroidSecurity(handle));
    Ok(())
}

#[tauri::command]
async fn status(state: State<'_, MobileState>) -> CommandResult<DesktopStatus> {
    Ok(state.client.lock().await.status())
}

#[tauri::command]
async fn register(
    state: State<'_, MobileState>,
    server_url: String,
    email: String,
    master_password: String,
) -> CommandResult<DesktopStatus> {
    state
        .client
        .lock()
        .await
        .register(server_url, email, master_password)
        .await
        .map_err(redacted_error)
}

#[tauri::command]
async fn login(
    state: State<'_, MobileState>,
    server_url: String,
    email: String,
    master_password: String,
    totp_code: Option<String>,
    recovery_code: Option<String>,
) -> CommandResult<DesktopStatus> {
    state
        .client
        .lock()
        .await
        .login(server_url, email, master_password, totp_code, recovery_code)
        .await
        .map_err(redacted_error)
}

#[tauri::command]
async fn unlock_with_password(
    state: State<'_, MobileState>,
    master_password: String,
) -> CommandResult<DesktopStatus> {
    state
        .client
        .lock()
        .await
        .unlock_with_password(master_password)
        .map_err(redacted_error)
}

/// Runs the Android Credential Manager account-passkey ceremony, then uses the master password
/// only inside Rust to unwrap the zero-knowledge vault key. The password itself is never sent to
/// the server in this path.
#[tauri::command]
async fn login_with_account_passkey(
    state: State<'_, MobileState>,
    security: State<'_, AndroidSecurity>,
    server_url: String,
    email: String,
    mut master_password: String,
) -> CommandResult<DesktopStatus> {
    let result = async {
        let challenge = state
            .client
            .lock()
            .await
            .begin_account_passkey_login(server_url, email, android_device(Uuid::new_v4()))
            .await
            .map_err(redacted_error)?;
        let mut options_json = serde_json::to_string(&challenge.options)
            .map_err(|_| "The account passkey challenge is malformed.".to_owned())?;
        let response: AccountPasskeyCredentialResponse = security
            .run_async(
                "getAccountPasskey",
                AccountPasskeyOptionsPayload {
                    options_json: &options_json,
                },
            )
            .await?;
        options_json.zeroize();
        let credential = parse_account_passkey_credential(response.credential)?;
        let master_password = std::mem::take(&mut master_password);
        state
            .client
            .lock()
            .await
            .finish_account_passkey_login(challenge.ceremony_id, credential, master_password)
            .await
            .map_err(redacted_error)
    }
    .await;
    // `finish_account_passkey_login` consumes and clears it on the normal path. This also
    // covers a cancelled Credential Manager prompt before it reaches the core.
    master_password.zeroize();
    result
}

#[tauri::command]
async fn account_security(state: State<'_, MobileState>) -> CommandResult<AccountSecuritySnapshot> {
    state
        .client
        .lock()
        .await
        .account_security_snapshot()
        .await
        .map_err(redacted_error)
}

#[tauri::command]
async fn start_account_totp_setup(
    state: State<'_, MobileState>,
    master_password: String,
) -> CommandResult<TotpSetupStartResponse> {
    state
        .client
        .lock()
        .await
        .start_account_totp_setup(master_password)
        .await
        .map_err(redacted_error)
}

#[tauri::command]
async fn finish_account_totp_setup(
    state: State<'_, MobileState>,
    setup_id: Uuid,
    code: String,
) -> CommandResult<MfaEnableResponse> {
    state
        .client
        .lock()
        .await
        .finish_account_totp_setup(setup_id, code)
        .await
        .map_err(redacted_error)
}

#[tauri::command]
async fn disable_account_totp(
    state: State<'_, MobileState>,
    master_password: String,
) -> CommandResult<()> {
    state
        .client
        .lock()
        .await
        .disable_account_totp(master_password)
        .await
        .map_err(redacted_error)
}

#[tauri::command]
async fn rotate_account_recovery_codes(
    state: State<'_, MobileState>,
    master_password: String,
) -> CommandResult<RecoveryCodesResponse> {
    state
        .client
        .lock()
        .await
        .rotate_account_recovery_codes(master_password)
        .await
        .map_err(redacted_error)
}

#[tauri::command]
async fn register_account_passkey(
    state: State<'_, MobileState>,
    security: State<'_, AndroidSecurity>,
    master_password: String,
    name: String,
) -> CommandResult<MfaEnableResponse> {
    let challenge = state
        .client
        .lock()
        .await
        .start_account_passkey_registration(master_password, name)
        .await
        .map_err(redacted_error)?;
    let mut options_json = serde_json::to_string(&challenge.options)
        .map_err(|_| "The account passkey challenge is malformed.".to_owned())?;
    let response: AccountPasskeyCredentialResponse = security
        .run_async(
            "createAccountPasskey",
            AccountPasskeyOptionsPayload {
                options_json: &options_json,
            },
        )
        .await?;
    options_json.zeroize();
    let credential = parse_account_passkey_credential(response.credential)?;
    state
        .client
        .lock()
        .await
        .finish_account_passkey_registration(challenge.ceremony_id, credential)
        .await
        .map_err(redacted_error)
}

#[tauri::command]
async fn remove_account_passkey(state: State<'_, MobileState>, id: Uuid) -> CommandResult<()> {
    state
        .client
        .lock()
        .await
        .remove_account_passkey(id)
        .await
        .map_err(redacted_error)
}

#[tauri::command]
async fn revoke_account_device_trust(state: State<'_, MobileState>, id: Uuid) -> CommandResult<()> {
    state
        .client
        .lock()
        .await
        .revoke_account_device_trust(id)
        .await
        .map_err(redacted_error)
}

#[tauri::command]
async fn revoke_account_session(
    state: State<'_, MobileState>,
    id: Uuid,
) -> CommandResult<DesktopStatus> {
    state
        .client
        .lock()
        .await
        .revoke_account_session(id)
        .await
        .map_err(redacted_error)
}

#[tauri::command]
async fn lock(state: State<'_, MobileState>) -> CommandResult<DesktopStatus> {
    Ok(state.client.lock().await.lock())
}

#[tauri::command]
async fn unlock_with_device_key(state: State<'_, MobileState>) -> CommandResult<DesktopStatus> {
    state
        .client
        .lock()
        .await
        .unlock_with_device_key()
        .map_err(redacted_error)
}

#[tauri::command]
async fn resume_session(state: State<'_, MobileState>) -> CommandResult<DesktopStatus> {
    state
        .client
        .lock()
        .await
        .resume_session()
        .await
        .map_err(redacted_error)
}

#[tauri::command]
async fn logout(state: State<'_, MobileState>) -> CommandResult<DesktopStatus> {
    state
        .client
        .lock()
        .await
        .logout()
        .await
        .map_err(redacted_error)
}

#[tauri::command]
async fn sync_now(state: State<'_, MobileState>) -> CommandResult<DesktopStatus> {
    state
        .client
        .lock()
        .await
        .sync_now()
        .await
        .map_err(redacted_error)
}

#[tauri::command]
async fn touch(state: State<'_, MobileState>) -> CommandResult<()> {
    state.client.lock().await.touch();
    Ok(())
}

#[tauri::command]
async fn list_items(
    state: State<'_, MobileState>,
    query: String,
    category: String,
) -> CommandResult<Vec<ItemSummary>> {
    state
        .client
        .lock()
        .await
        .list_items(&query, &category)
        .map_err(redacted_error)
}

#[tauri::command]
async fn organization_catalog(state: State<'_, MobileState>) -> CommandResult<OrganizationCatalog> {
    state
        .client
        .lock()
        .await
        .organization_catalog()
        .map_err(redacted_error)
}

#[tauri::command]
async fn get_item(state: State<'_, MobileState>, id: Uuid) -> CommandResult<VaultItem> {
    state
        .client
        .lock()
        .await
        .get_item(id)
        .map_err(redacted_error)
}

#[tauri::command]
async fn save_login(state: State<'_, MobileState>, draft: LoginDraft) -> CommandResult<VaultItem> {
    state
        .client
        .lock()
        .await
        .save_login(draft)
        .await
        .map_err(redacted_error)
}

#[tauri::command]
async fn save_item(state: State<'_, MobileState>, draft: ItemDraft) -> CommandResult<VaultItem> {
    state
        .client
        .lock()
        .await
        .save_item(draft)
        .await
        .map_err(redacted_error)
}

#[tauri::command]
async fn save_folder(
    state: State<'_, MobileState>,
    draft: FolderDraft,
) -> CommandResult<BitwardenFolder> {
    state
        .client
        .lock()
        .await
        .save_folder(draft)
        .await
        .map_err(redacted_error)
}

#[tauri::command]
async fn delete_folder(state: State<'_, MobileState>, id: Uuid) -> CommandResult<DesktopStatus> {
    state
        .client
        .lock()
        .await
        .delete_folder(id)
        .await
        .map_err(redacted_error)
}

#[tauri::command]
async fn delete_item(state: State<'_, MobileState>, id: Uuid) -> CommandResult<DesktopStatus> {
    state
        .client
        .lock()
        .await
        .delete_item(id)
        .await
        .map_err(redacted_error)
}

#[tauri::command]
async fn remove_passkey(
    state: State<'_, MobileState>,
    item_id: Uuid,
    credential_id: String,
) -> CommandResult<VaultItem> {
    state
        .client
        .lock()
        .await
        .remove_passkey(item_id, &credential_id)
        .await
        .map_err(redacted_error)
}

/// Uses Android's Storage Access Framework only to copy a user-selected plaintext file into
/// app-private cache. The shared Rust core then performs all metadata generation, encryption,
/// chunking, upload, and retry semantics; Kotlin never sees vault attachment key material.
#[tauri::command]
async fn upload_attachment(
    state: State<'_, MobileState>,
    security: State<'_, AndroidSecurity>,
    item_id: Uuid,
    attachment_id: Option<Uuid>,
) -> CommandResult<Option<VaultItem>> {
    let staged: AttachmentStagingResponse = security.run_async("pickAttachment", ()).await?;
    let mut path = staged.path;
    if !is_private_attachment_path(&path) {
        path.zeroize();
        return Err("The selected attachment is invalid.".to_owned());
    }
    let attachment_path = PathBuf::from(&path);
    let result = state
        .client
        .lock()
        .await
        .upload_attachment_from_path(item_id, attachment_id, &attachment_path)
        .await
        .map(Some)
        .map_err(redacted_error);
    let _ = security
        .run_async::<()>(
            "discardAttachmentStaging",
            AttachmentStagingPayload { path: &path },
        )
        .await;
    path.zeroize();
    result
}

/// Uses a user-chosen Storage Access Framework destination without exposing its URI to the
/// WebView. Rust writes the authenticated plaintext only to a private temporary file, and Kotlin
/// copies it to the selected destination then removes the temporary file.
#[tauri::command]
async fn download_attachment(
    state: State<'_, MobileState>,
    security: State<'_, AndroidSecurity>,
    item_id: Uuid,
    attachment_id: Uuid,
) -> CommandResult<Option<String>> {
    let mut file_name = state
        .client
        .lock()
        .await
        .attachment_file_name(item_id, attachment_id)
        .map_err(redacted_error)?;
    let prepared: AttachmentDownloadPreparation = security
        .run_async(
            "prepareAttachmentDownload",
            AttachmentDownloadPayload {
                file_name: &file_name,
            },
        )
        .await?;
    let mut path = prepared.path;
    let mut handle = prepared.handle;
    if !is_private_attachment_path(&path) || handle.is_empty() || handle.len() > 128 {
        let _ = security
            .run_async::<()>(
                "discardAttachmentDownload",
                AttachmentDownloadDiscardPayload {
                    handle: &handle,
                    path: &path,
                },
            )
            .await;
        path.zeroize();
        handle.zeroize();
        file_name.zeroize();
        return Err("The attachment destination is invalid.".to_owned());
    }
    let destination = PathBuf::from(&path);
    let downloaded = state
        .client
        .lock()
        .await
        .download_attachment_to_path(item_id, attachment_id, &destination)
        .await
        .map_err(redacted_error);
    let completed = if downloaded.is_ok() {
        security
            .run_async::<()>(
                "commitAttachmentDownload",
                AttachmentCommitPayload {
                    handle: &handle,
                    path: &path,
                },
            )
            .await
    } else {
        Ok(())
    };
    // Commit also cleans this file. Repeat the bounded private-path cleanup so failures between
    // Rust download and Android output cannot leave decrypted attachment data in cache.
    let _ = security
        .run_async::<()>(
            "discardAttachmentDownload",
            AttachmentDownloadDiscardPayload {
                handle: &handle,
                path: &path,
            },
        )
        .await;
    path.zeroize();
    handle.zeroize();
    match downloaded {
        Err(error) => {
            file_name.zeroize();
            Err(error)
        }
        Ok(()) => completed.map(|()| Some(file_name)),
    }
}

#[tauri::command]
async fn generate_password(
    state: State<'_, MobileState>,
    options: PasswordOptions,
) -> CommandResult<String> {
    state
        .client
        .lock()
        .await
        .generate_password(&options)
        .map_err(redacted_error)
}

#[tauri::command]
async fn generate_passphrase(
    state: State<'_, MobileState>,
    options: PassphraseOptions,
) -> CommandResult<String> {
    state
        .client
        .lock()
        .await
        .generate_passphrase(&options)
        .map_err(redacted_error)
}

#[tauri::command]
async fn totp_for_item(
    state: State<'_, MobileState>,
    id: Uuid,
    unix_seconds: u64,
) -> CommandResult<TotpView> {
    state
        .client
        .lock()
        .await
        .totp_for_item(id, unix_seconds)
        .map_err(redacted_error)
}

#[tauri::command]
async fn list_conflicts(state: State<'_, MobileState>) -> CommandResult<Vec<ConflictSummary>> {
    state
        .client
        .lock()
        .await
        .list_conflicts()
        .map_err(redacted_error)
}

#[tauri::command]
async fn resolve_conflict(
    state: State<'_, MobileState>,
    id: Uuid,
    keep_local: bool,
) -> CommandResult<DesktopStatus> {
    state
        .client
        .lock()
        .await
        .resolve_conflict(id, keep_local)
        .await
        .map_err(redacted_error)
}

#[tauri::command]
async fn select_profile(
    state: State<'_, MobileState>,
    scope: String,
) -> CommandResult<DesktopStatus> {
    state
        .client
        .lock()
        .await
        .select_profile(&scope)
        .map_err(redacted_error)
}

#[tauri::command]
async fn set_auto_lock_minutes(
    state: State<'_, MobileState>,
    minutes: u32,
) -> CommandResult<DesktopStatus> {
    state
        .client
        .lock()
        .await
        .set_auto_lock_minutes(minutes)
        .map_err(redacted_error)
}

#[tauri::command]
async fn set_remember_unlock(
    state: State<'_, MobileState>,
    enabled: bool,
) -> CommandResult<DesktopStatus> {
    state
        .client
        .lock()
        .await
        .set_remember_unlock(enabled)
        .map_err(redacted_error)
}

#[tauri::command]
async fn copy_secret(security: State<'_, AndroidSecurity>, mut value: String) -> CommandResult<()> {
    if value.len() > 1_000_000 {
        value.zeroize();
        return Err("The selected value is too large for the clipboard.".to_owned());
    }
    let result = security
        .run_async::<()>("copySecret", ClipboardPayload { value: &value })
        .await;
    value.zeroize();
    result
}

#[tauri::command]
async fn biometric_status(security: State<'_, AndroidSecurity>) -> CommandResult<BiometricStatus> {
    security.run_async("biometricStatus", ()).await
}

#[tauri::command]
async fn clipboard_policy(security: State<'_, AndroidSecurity>) -> CommandResult<ClipboardPolicy> {
    security.run_async("clipboardPolicy", ()).await
}

#[tauri::command]
async fn set_clipboard_policy(
    security: State<'_, AndroidSecurity>,
    clear_after_seconds: u64,
) -> CommandResult<ClipboardPolicy> {
    security
        .run_async(
            "setClipboardPolicy",
            ClipboardPolicy {
                clear_after_seconds: clear_after_seconds.min(120),
            },
        )
        .await
}

#[tauri::command]
async fn enable_biometric_unlock(
    state: State<'_, MobileState>,
    security: State<'_, AndroidSecurity>,
) -> CommandResult<BiometricStatus> {
    let (mut key, context) = {
        let mut client = state.client.lock().await;
        (
            client.biometric_unlock_key().map_err(redacted_error)?,
            client.biometric_unlock_context().map_err(redacted_error)?,
        )
    };
    let encoded = STANDARD.encode(key);
    key.zeroize();
    let result = security
        .run_async(
            "enableBiometricUnlock",
            BiometricKeyPayload {
                key: &encoded,
                context: &context,
            },
        )
        .await;
    let mut encoded = encoded;
    encoded.zeroize();
    result
}

#[tauri::command]
async fn disable_biometric_unlock(
    security: State<'_, AndroidSecurity>,
) -> CommandResult<BiometricStatus> {
    security.run_async("disableBiometricUnlock", ()).await
}

#[tauri::command]
async fn open_autofill_settings(security: State<'_, AndroidSecurity>) -> CommandResult<()> {
    security.run_async("openAutofillSettings", ()).await
}

#[tauri::command]
async fn open_credential_provider_settings(
    security: State<'_, AndroidSecurity>,
) -> CommandResult<()> {
    security
        .run_async("openCredentialProviderSettings", ())
        .await
}

#[tauri::command]
async fn scan_totp(security: State<'_, AndroidSecurity>) -> CommandResult<TotpQrScan> {
    security.run_async("scanTotp", ()).await
}

fn android_device(identifier: Uuid) -> DeviceRequest {
    DeviceRequest {
        identifier,
        name: "Hasilan Pass for Android".to_owned(),
        device_type: "mobile".to_owned(),
    }
}

fn parse_account_passkey_credential(mut response: String) -> CommandResult<serde_json::Value> {
    if response.is_empty() || response.len() > 262_144 {
        response.zeroize();
        return Err("The Credential Manager response is invalid.".to_owned());
    }
    let value = serde_json::from_str(&response)
        .map_err(|_| "The Credential Manager response is invalid.".to_owned());
    response.zeroize();
    value
}

fn is_private_attachment_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 8_192
        && PathBuf::from(path).is_absolute()
        && !path.contains('\0')
}

fn redacted_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// Starts the Android Tauri application and the shared offline-first Rust coordinator.
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(
            tauri::plugin::Builder::new("android-security")
                .setup(initialize_security_plugin)
                .build(),
        )
        .setup(|app| {
            let data_dir = app.path().app_local_data_dir()?;
            let security = app.state::<AndroidSecurity>().inner().clone();
            let client = Arc::new(Mutex::new(
                DesktopClient::open(
                    data_dir.join("encrypted-vault-cache.json"),
                    Arc::new(AndroidSecretStore { security }),
                )
                .map_err(|error| std::io::Error::other(error.to_string()))?,
            ));
            let _ = MOBILE_CLIENT.set(client.clone());
            // A system component may have unlocked the pre-Activity coordinator before the
            // Tauri window was created. Retire that coordinator now that the foreground client
            // is authoritative; otherwise its decrypted key could remain in process memory even
            // though every subsequent call resolves to `MOBILE_CLIENT`.
            retire_pre_activity_client();
            app.manage(MobileState { client });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            status,
            register,
            login,
            unlock_with_password,
            login_with_account_passkey,
            account_security,
            start_account_totp_setup,
            finish_account_totp_setup,
            disable_account_totp,
            rotate_account_recovery_codes,
            register_account_passkey,
            remove_account_passkey,
            revoke_account_device_trust,
            revoke_account_session,
            lock,
            logout,
            sync_now,
            touch,
            list_items,
            organization_catalog,
            get_item,
            save_login,
            save_item,
            save_folder,
            delete_folder,
            delete_item,
            remove_passkey,
            upload_attachment,
            download_attachment,
            generate_password,
            generate_passphrase,
            totp_for_item,
            list_conflicts,
            resolve_conflict,
            select_profile,
            set_auto_lock_minutes,
            set_remember_unlock,
            unlock_with_device_key,
            resume_session,
            copy_secret,
            clipboard_policy,
            set_clipboard_policy,
            biometric_status,
            enable_biometric_unlock,
            disable_biometric_unlock,
            open_autofill_settings,
            open_credential_provider_settings,
            scan_totp,
        ]);

    match builder.build(tauri::generate_context!()) {
        Ok(app) => app.run(|app, event| {
            if let RunEvent::Opened { urls } = event {
                for url in urls {
                    if let Some(action) = safe_android_deep_link(&url) {
                        let _ = app.emit("android-deep-link", action);
                    }
                }
            }
        }),
        Err(error) => eprintln!("Hasilan Pass Android failed to start: {error}"),
    }
}

fn android_client() -> Result<Arc<Mutex<DesktopClient>>, ()> {
    MOBILE_CLIENT.get().cloned().ok_or(())
}

fn system_client() -> Result<Arc<Mutex<DesktopClient>>, ()> {
    // Android services and the Tauri Activity normally live in the same application process.
    // Prefer the Activity coordinator once it is available, rather than allowing two clients to
    // independently hold the same encrypted-cache replica in memory.
    if let Ok(client) = android_client() {
        return Ok(client);
    }
    SYSTEM_CLIENT
        .get_or_init(|| StdMutex::new(None))
        .lock()
        .map_err(|_| ())?
        .clone()
        .ok_or(())
}

fn initialize_system_client(data_dir: String) -> bool {
    if data_dir.is_empty() || data_dir.len() > 8_192 {
        return false;
    }
    // When the Activity already exists, native system services must use its exact shared Rust
    // client. In particular, this lets an Autofill save or a passkey counter update become
    // immediately visible to the foreground vault and be included in its next normal sync.
    if android_client().is_ok() {
        return true;
    }
    let Ok(mut slot) = SYSTEM_CLIENT.get_or_init(|| StdMutex::new(None)).lock() else {
        return false;
    };
    if slot.is_some() {
        return true;
    }
    let cache_path = PathBuf::from(data_dir).join("encrypted-vault-cache.json");
    let Ok(client) = DesktopClient::open(cache_path, Arc::new(MemorySecretStore::default())) else {
        return false;
    };
    *slot = Some(Arc::new(Mutex::new(client)));
    true
}

/// Locks and drops the coordinator that can only exist before the Tauri Activity is initialized.
/// The Activity client is deliberately not touched here; it has just been installed as the
/// authoritative shared client.
fn retire_pre_activity_client() {
    let client = SYSTEM_CLIENT
        .get_or_init(|| StdMutex::new(None))
        .lock()
        .ok()
        .and_then(|mut slot| slot.take());
    if let Some(client) = client {
        tauri::async_runtime::block_on(async {
            client.lock().await.lock();
        });
    }
}

/// Locks every Android coordinator currently retained by this process. Normally the two
/// entries are the same Arc, but a service can have created a pre-Activity coordinator before
/// the foreground Activity appeared. Locking both makes background/explicit-lock transitions
/// safe in that race as well.
fn lock_all_android_clients() {
    let mut clients = Vec::with_capacity(2);
    if let Some(client) = MOBILE_CLIENT.get().cloned() {
        clients.push(client);
    }
    if let Ok(slot) = SYSTEM_CLIENT.get_or_init(|| StdMutex::new(None)).lock() {
        if let Some(client) = slot.as_ref() {
            if !clients.iter().any(|current| Arc::ptr_eq(current, client)) {
                clients.push(client.clone());
            }
        }
    }
    tauri::async_runtime::block_on(async move {
        for client in clients {
            client.lock().await.lock_for_background();
        }
    });
}

tauri::tao::platform::android::prelude::android_fn!(
    org_hasilan,
    pass,
    AutofillNative,
    initialize,
    [JString<'local>],
    jboolean
);

fn initialize(mut env: JNIEnv<'_>, _class: JClass<'_>, data_dir: JString<'_>) -> jboolean {
    let Ok(data_dir) = env
        .get_string(&data_dir)
        .map(|value| value.to_string_lossy().into_owned())
    else {
        return 0;
    };
    u8::from(initialize_system_client(data_dir)) as jboolean
}

tauri::tao::platform::android::prelude::android_fn!(
    org_hasilan,
    pass,
    AutofillNative,
    unlock,
    [JByteArray<'local>],
    jboolean
);

/// Releases a Keystore-unwrapped user key into the existing Rust coordinator. The key is copied
/// into the zeroizing `CompositeKey` and the Java byte array is never retained.
fn unlock(env: JNIEnv<'_>, _class: JClass<'_>, key: JByteArray<'_>) -> jboolean {
    let Ok(mut bytes) = env.convert_byte_array(key) else {
        return 0;
    };
    let result = system_client().is_ok_and(|client| {
        tauri::async_runtime::block_on(async {
            client
                .lock()
                .await
                .unlock_with_biometric_key(&bytes)
                .is_ok()
        })
    });
    bytes.zeroize();
    u8::from(result) as jboolean
}

tauri::tao::platform::android::prelude::android_fn!(
    org_hasilan,
    pass,
    AutofillNative,
    unlockContext,
    [],
    jstring
);

/// Returns only the active profile's non-secret biometric envelope context. Android uses this to
/// authenticate the Keystore envelope before releasing its user key to Rust.
fn unlockContext(mut env: JNIEnv<'_>, _class: JClass<'_>) -> jstring {
    let context = system_client().and_then(|client| {
        tauri::async_runtime::block_on(async {
            client
                .lock()
                .await
                .biometric_unlock_context()
                .map_err(|_| ())
        })
    });
    context
        .ok()
        .and_then(|value| env.new_string(value).ok())
        .map(JString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

tauri::tao::platform::android::prelude::android_fn!(
    org_hasilan,
    pass,
    AutofillNative,
    candidates,
    [JString<'local>],
    jstring
);

/// Returns URI-matched credentials from the shared unlocked vault as a JSON array for the Android
/// system service. This function intentionally has no Tauri webview entry point.
fn candidates(mut env: JNIEnv<'_>, _class: JClass<'_>, origin: JString<'_>) -> jstring {
    let Ok(origin) = env.get_string(&origin) else {
        return std::ptr::null_mut();
    };
    let origin = origin.to_string_lossy().into_owned();
    let candidates: Result<Vec<AutofillCandidate>, ()> = system_client().and_then(|client| {
        tauri::async_runtime::block_on(async {
            client
                .lock()
                .await
                .autofill_candidates(&origin)
                .map_err(|_| ())
        })
    });
    let Ok(candidates) = candidates else {
        return std::ptr::null_mut();
    };
    let Ok(json) = serde_json::to_string(&candidates) else {
        return std::ptr::null_mut();
    };
    env.new_string(json)
        .map(JString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

tauri::tao::platform::android::prelude::android_fn!(
    org_hasilan,
    pass,
    AutofillNative,
    lockNative,
    [],
    __VOID__
);

#[allow(
    non_snake_case,
    reason = "the Android JNI method name is part of the platform ABI"
)]
/// Immediately drops decrypted items and user keys when the Android app backgrounds.
fn lockNative(_env: JNIEnv<'_>, _class: JClass<'_>) {
    lock_all_android_clients();
}

tauri::tao::platform::android::prelude::android_fn!(
    org_hasilan,
    pass,
    AutofillNative,
    lockApp,
    [],
    __VOID__
);

#[allow(
    non_snake_case,
    reason = "the Android JNI method name is part of the platform ABI"
)]
/// Locks the Tauri UI coordinator as well as the system-service coordinator. Android invokes
/// this from `MainActivity.onStop`; keeping these independently-addressable prevents an Autofill
/// service launch from depending on a WebView being alive.
fn lockApp(_env: JNIEnv<'_>, _class: JClass<'_>) {
    lock_all_android_clients();
}

tauri::tao::platform::android::prelude::android_fn!(
    org_hasilan,
    pass,
    AutofillNative,
    saveLogin,
    [JString<'local>, JString<'local>, JString<'local>, JString<'local>],
    jboolean
);

#[allow(
    non_snake_case,
    reason = "the Android JNI method name is part of the platform ABI"
)]
fn saveLogin(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    origin: JString<'_>,
    username: JString<'_>,
    password: JString<'_>,
    name: JString<'_>,
) -> jboolean {
    let read = |env: &mut JNIEnv<'_>, value: &JString<'_>| {
        env.get_string(value)
            .map(|text| text.to_string_lossy().into_owned())
            .map_err(|_| ())
    };
    let (Ok(origin), Ok(username), Ok(mut password), Ok(name)) = (
        read(&mut env, &origin),
        read(&mut env, &username),
        read(&mut env, &password),
        read(&mut env, &name),
    ) else {
        return 0;
    };
    let result = system_client().is_ok_and(|client| {
        let draft = LoginDraft {
            id: None,
            name,
            username: (!username.trim().is_empty()).then_some(username),
            password: Some(password.clone()),
            uri: Some(origin),
            totp: None,
            notes: None,
            favorite: false,
            folder_id: None,
            fields: Vec::new(),
            organization_id: None,
            collection_ids: Vec::new(),
        };
        tauri::async_runtime::block_on(async {
            client.lock().await.save_login_local(draft).is_ok()
        })
    });
    password.zeroize();
    u8::from(result) as jboolean
}

tauri::tao::platform::android::prelude::android_fn!(
    org_hasilan,
    pass,
    AutofillNative,
    credentialPasswordCandidates,
    [],
    jstring
);

#[allow(
    non_snake_case,
    reason = "the Android JNI method name is part of the platform ABI"
)]
fn credentialPasswordCandidates(mut env: JNIEnv<'_>, _class: JClass<'_>) -> jstring {
    let candidates: Result<Vec<AutofillCandidate>, ()> = system_client().and_then(|client| {
        tauri::async_runtime::block_on(async {
            client
                .lock()
                .await
                .credential_password_candidates()
                .map_err(|_| ())
        })
    });
    json_string(&mut env, candidates)
}

tauri::tao::platform::android::prelude::android_fn!(
    org_hasilan,
    pass,
    AutofillNative,
    credentialPasskeyCandidates,
    [JString<'local>],
    jstring
);

#[allow(
    non_snake_case,
    reason = "the Android JNI method name is part of the platform ABI"
)]
fn credentialPasskeyCandidates(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    rp_id: JString<'_>,
) -> jstring {
    let Ok(rp_id) = env
        .get_string(&rp_id)
        .map(|value| value.to_string_lossy().into_owned())
    else {
        return std::ptr::null_mut();
    };
    let candidates: Result<Vec<CredentialPasskeyCandidate>, ()> =
        system_client().and_then(|client| {
            tauri::async_runtime::block_on(async {
                client
                    .lock()
                    .await
                    .credential_passkey_candidates(&rp_id)
                    .map_err(|_| ())
            })
        });
    json_string(&mut env, candidates)
}

tauri::tao::platform::android::prelude::android_fn!(
    org_hasilan,
    pass,
    AutofillNative,
    assertCredentialPasskey,
    [JString<'local>, JString<'local>, JString<'local>],
    jstring
);

#[allow(
    non_snake_case,
    reason = "the Android JNI method name is part of the platform ABI"
)]
fn assertCredentialPasskey(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    item_id: JString<'_>,
    credential_id: JString<'_>,
    options_json: JString<'_>,
) -> jstring {
    let read = |env: &mut JNIEnv<'_>, value: &JString<'_>| {
        env.get_string(value)
            .map(|text| text.to_string_lossy().into_owned())
            .map_err(|_| ())
    };
    let (Ok(item_id), Ok(credential_id), Ok(options_json)) = (
        read(&mut env, &item_id),
        read(&mut env, &credential_id),
        read(&mut env, &options_json),
    ) else {
        return std::ptr::null_mut();
    };
    let Ok(item_id) = Uuid::parse_str(&item_id) else {
        return std::ptr::null_mut();
    };
    let Ok(options) = serde_json::from_str::<PasskeyAssertionOptions>(&options_json) else {
        return std::ptr::null_mut();
    };
    let result = system_client().and_then(|client| {
        tauri::async_runtime::block_on(async {
            client
                .lock()
                .await
                .assert_credential_passkey(item_id, &credential_id, &options)
                .map_err(|_| ())
        })
    });
    json_string(&mut env, result)
}

tauri::tao::platform::android::prelude::android_fn!(
    org_hasilan,
    pass,
    AutofillNative,
    passkeyCreationTargets,
    [JString<'local>],
    jstring
);

#[allow(
    non_snake_case,
    reason = "the Android JNI method name is part of the platform ABI"
)]
fn passkeyCreationTargets(mut env: JNIEnv<'_>, _class: JClass<'_>, rp_id: JString<'_>) -> jstring {
    let Ok(rp_id) = env
        .get_string(&rp_id)
        .map(|value| value.to_string_lossy().into_owned())
    else {
        return std::ptr::null_mut();
    };
    let targets: Result<Vec<AutofillCandidate>, ()> = system_client().and_then(|client| {
        tauri::async_runtime::block_on(async {
            client
                .lock()
                .await
                .credential_passkey_creation_targets(&rp_id)
                .map_err(|_| ())
        })
    });
    json_string(&mut env, targets)
}

tauri::tao::platform::android::prelude::android_fn!(
    org_hasilan,
    pass,
    AutofillNative,
    createCredentialPasskey,
    [JString<'local>, JString<'local>],
    jstring
);

#[allow(
    non_snake_case,
    reason = "the Android JNI method name is part of the platform ABI"
)]
fn createCredentialPasskey(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    item_id: JString<'_>,
    options_json: JString<'_>,
) -> jstring {
    let read = |env: &mut JNIEnv<'_>, value: &JString<'_>| {
        env.get_string(value)
            .map(|text| text.to_string_lossy().into_owned())
            .map_err(|_| ())
    };
    let (Ok(item_id), Ok(options_json)) = (read(&mut env, &item_id), read(&mut env, &options_json))
    else {
        return std::ptr::null_mut();
    };
    let Ok(item_id) = Uuid::parse_str(&item_id) else {
        return std::ptr::null_mut();
    };
    let Ok(options) = serde_json::from_str::<PasskeyCreationOptions>(&options_json) else {
        return std::ptr::null_mut();
    };
    let created = system_client().and_then(|client| {
        tauri::async_runtime::block_on(async {
            client
                .lock()
                .await
                .create_credential_passkey(item_id, &options)
                .map_err(|_| ())
        })
    });
    let Ok(created) = created else {
        return std::ptr::null_mut();
    };
    let value = serde_json::json!({
        "credentialId": created.credential_id,
        "clientDataJson": created.client_data_json,
        "attestationObject": created.attestation_object,
        "authenticatorData": created.authenticator_data,
        "publicKey": created.public_key,
        "publicKeyAlgorithm": created.public_key_algorithm,
        "transports": created.transports,
        "discoverable": created.discoverable,
    });
    let Ok(json) = serde_json::to_string(&value) else {
        return std::ptr::null_mut();
    };
    env.new_string(json)
        .map(JString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

fn json_string<T: Serialize>(env: &mut JNIEnv<'_>, value: Result<T, ()>) -> jstring {
    let Ok(value) = value else {
        return std::ptr::null_mut();
    };
    let Ok(json) = serde_json::to_string(&value) else {
        return std::ptr::null_mut();
    };
    env.new_string(json)
        .map(JString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}
