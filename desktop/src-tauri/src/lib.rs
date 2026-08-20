//! Tauri command boundary for the native Hasilan Pass desktop client.
//!
//! The bundled webview is intentionally a presentation layer. Password derivation,
//! decryption, local search, sync, imports, and secret persistence remain in Rust.

mod android_deep_link;

#[cfg(target_os = "android")]
mod mobile;

#[cfg(not(target_os = "android"))]
mod desktop {

    use std::{fs, sync::Arc, time::Duration};

    use hasilan_desktop_core::{
        AttachmentRemoval, BitwardenFolder, ConflictSummary, DesktopClient, DesktopStatus,
        FolderDraft, ImportSummary, ItemDraft, ItemSummary, KeyringSecretStore, LoginDraft,
        OrganizationCatalog, TotpView,
    };
    use hasilan_vault::{PassphraseOptions, PasswordOptions, VaultItem};
    use tauri::{
        AppHandle, Emitter as _, Manager as _, RunEvent, State,
        menu::{Menu, MenuItem},
        tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    };
    use tokio::sync::Mutex;
    use uuid::Uuid;
    use zeroize::Zeroize;

    const CLIPBOARD_CLEAR_SECONDS: u64 = 30;
    const MAX_IMPORT_BYTES: u64 = 64 * 1024 * 1024;

    struct DesktopState {
        client: Mutex<DesktopClient>,
    }

    type CommandResult<T> = Result<T, String>;

    #[tauri::command]
    async fn status(state: State<'_, DesktopState>) -> CommandResult<DesktopStatus> {
        let client = state.client.lock().await;
        Ok(client.status())
    }

    #[tauri::command]
    async fn register(
        state: State<'_, DesktopState>,
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
        state: State<'_, DesktopState>,
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
    async fn lock(state: State<'_, DesktopState>) -> CommandResult<DesktopStatus> {
        Ok(state.client.lock().await.lock())
    }

    #[tauri::command]
    async fn logout(state: State<'_, DesktopState>) -> CommandResult<DesktopStatus> {
        state
            .client
            .lock()
            .await
            .logout()
            .await
            .map_err(redacted_error)
    }

    #[tauri::command]
    async fn sync_now(state: State<'_, DesktopState>) -> CommandResult<DesktopStatus> {
        state
            .client
            .lock()
            .await
            .sync_now()
            .await
            .map_err(redacted_error)
    }

    #[tauri::command]
    async fn touch(state: State<'_, DesktopState>) -> CommandResult<()> {
        state.client.lock().await.touch();
        Ok(())
    }

    #[tauri::command]
    async fn list_items(
        state: State<'_, DesktopState>,
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
    async fn organization_catalog(
        state: State<'_, DesktopState>,
    ) -> CommandResult<OrganizationCatalog> {
        state
            .client
            .lock()
            .await
            .organization_catalog()
            .map_err(redacted_error)
    }

    #[tauri::command]
    async fn get_item(state: State<'_, DesktopState>, id: Uuid) -> CommandResult<VaultItem> {
        state
            .client
            .lock()
            .await
            .get_item(id)
            .map_err(redacted_error)
    }

    #[tauri::command]
    async fn save_login(
        state: State<'_, DesktopState>,
        draft: LoginDraft,
    ) -> CommandResult<VaultItem> {
        state
            .client
            .lock()
            .await
            .save_login(draft)
            .await
            .map_err(redacted_error)
    }

    #[tauri::command]
    async fn save_item(
        state: State<'_, DesktopState>,
        draft: ItemDraft,
    ) -> CommandResult<VaultItem> {
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
        state: State<'_, DesktopState>,
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
    async fn delete_folder(
        state: State<'_, DesktopState>,
        id: Uuid,
    ) -> CommandResult<DesktopStatus> {
        state
            .client
            .lock()
            .await
            .delete_folder(id)
            .await
            .map_err(redacted_error)
    }

    #[tauri::command]
    async fn delete_item(state: State<'_, DesktopState>, id: Uuid) -> CommandResult<DesktopStatus> {
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
        state: State<'_, DesktopState>,
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

    #[tauri::command]
    async fn upload_attachment(
        state: State<'_, DesktopState>,
        item_id: Uuid,
        attachment_id: Option<Uuid>,
    ) -> CommandResult<Option<VaultItem>> {
        let selected = rfd::AsyncFileDialog::new()
            .set_title(if attachment_id.is_some() {
                "Resume encrypted attachment upload"
            } else {
                "Attach encrypted file"
            })
            .pick_file()
            .await;
        let Some(selected) = selected else {
            return Ok(None);
        };
        state
            .client
            .lock()
            .await
            .upload_attachment_from_path(item_id, attachment_id, selected.path())
            .await
            .map(Some)
            .map_err(redacted_error)
    }

    #[tauri::command]
    async fn download_attachment(
        state: State<'_, DesktopState>,
        item_id: Uuid,
        attachment_id: Uuid,
    ) -> CommandResult<Option<String>> {
        let file_name = state
            .client
            .lock()
            .await
            .attachment_file_name(item_id, attachment_id)
            .map_err(redacted_error)?;
        let destination = rfd::AsyncFileDialog::new()
            .set_file_name(file_name)
            .set_title("Save decrypted attachment")
            .save_file()
            .await;
        let Some(destination) = destination else {
            return Ok(None);
        };
        state
            .client
            .lock()
            .await
            .download_attachment_to_path(item_id, attachment_id, destination.path())
            .await
            .map_err(redacted_error)?;
        Ok(Some(destination.path().to_string_lossy().into_owned()))
    }

    #[tauri::command]
    async fn remove_attachment(
        state: State<'_, DesktopState>,
        item_id: Uuid,
        attachment_id: Uuid,
    ) -> CommandResult<AttachmentRemoval> {
        state
            .client
            .lock()
            .await
            .remove_attachment(item_id, attachment_id)
            .await
            .map_err(redacted_error)
    }

    #[tauri::command]
    async fn generate_password(
        state: State<'_, DesktopState>,
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
        state: State<'_, DesktopState>,
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
        state: State<'_, DesktopState>,
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
    async fn import_bitwarden_json(
        state: State<'_, DesktopState>,
    ) -> CommandResult<Option<ImportSummary>> {
        let path = rfd::AsyncFileDialog::new()
            .add_filter("Bitwarden JSON", &["json"])
            .set_title("Import Bitwarden JSON")
            .pick_file()
            .await;
        let Some(path) = path else {
            return Ok(None);
        };
        let metadata = fs::metadata(path.path())
            .map_err(|_| "The selected import could not be read.".to_owned())?;
        if metadata.len() > MAX_IMPORT_BYTES {
            return Err("The selected import exceeds the 64 MiB safety limit.".to_owned());
        }
        let bytes = fs::read(path.path())
            .map_err(|_| "The selected import could not be read.".to_owned())?;
        state
            .client
            .lock()
            .await
            .import_bitwarden_json(&bytes)
            .map(Some)
            .map_err(redacted_error)
    }

    #[tauri::command]
    async fn export_bitwarden_json(
        state: State<'_, DesktopState>,
    ) -> CommandResult<Option<String>> {
        let bytes = state
            .client
            .lock()
            .await
            .export_bitwarden_json()
            .map_err(redacted_error)?;
        let path = rfd::AsyncFileDialog::new()
            .add_filter("Bitwarden JSON", &["json"])
            .set_file_name("hasilan-bitwarden-export.json")
            .set_title("Export plaintext Bitwarden JSON")
            .save_file()
            .await;
        let Some(path) = path else {
            return Ok(None);
        };
        fs::write(path.path(), bytes)
            .map_err(|_| "The export file could not be written.".to_owned())?;
        Ok(Some(path.path().to_string_lossy().into_owned()))
    }

    #[tauri::command]
    async fn list_conflicts(state: State<'_, DesktopState>) -> CommandResult<Vec<ConflictSummary>> {
        state
            .client
            .lock()
            .await
            .list_conflicts()
            .map_err(redacted_error)
    }

    #[tauri::command]
    async fn resolve_conflict(
        state: State<'_, DesktopState>,
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
        state: State<'_, DesktopState>,
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
        state: State<'_, DesktopState>,
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
    async fn copy_secret(mut value: String) -> CommandResult<()> {
        if value.len() > 1_000_000 {
            value.zeroize();
            return Err("The selected value is too large for the clipboard.".to_owned());
        }
        let copied = value.clone();
        let result = tauri::async_runtime::spawn_blocking(move || {
            let mut clipboard = arboard::Clipboard::new().map_err(|_| ())?;
            clipboard.set_text(copied).map_err(|_| ())
        })
        .await
        .map_err(|_| "The clipboard is unavailable.".to_owned())?;
        if result.is_err() {
            value.zeroize();
            return Err("The clipboard is unavailable.".to_owned());
        }
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(Duration::from_secs(CLIPBOARD_CLEAR_SECONDS)).await;
            let expected = value;
            let _ = tauri::async_runtime::spawn_blocking(move || {
                let Ok(mut clipboard) = arboard::Clipboard::new() else {
                    return;
                };
                if clipboard
                    .get_text()
                    .is_ok_and(|current| current == expected)
                {
                    let _ = clipboard.clear();
                }
            })
            .await;
        });
        Ok(())
    }

    fn redacted_error(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    fn show_main(app: &AppHandle) {
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.unminimize();
            let _ = window.show();
            let _ = window.set_focus();
        }
    }

    fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
        let show = MenuItem::with_id(app, "show", "Open Hasilan Pass", true, None::<&str>)?;
        let lock = MenuItem::with_id(app, "lock", "Lock vault", true, None::<&str>)?;
        let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
        let menu = Menu::with_items(app, &[&show, &lock, &quit])?;
        let icon = app.default_window_icon().cloned();
        let mut builder = TrayIconBuilder::new()
            .tooltip("Hasilan Pass")
            .menu(&menu)
            .show_menu_on_left_click(false)
            .on_menu_event(|app, event| match event.id.as_ref() {
                "show" => show_main(app),
                "lock" => {
                    let app = app.clone();
                    tauri::async_runtime::spawn(async move {
                        let state = app.state::<DesktopState>();
                        state.client.lock().await.lock();
                        let _ = app.emit("vault-locked", ());
                    });
                }
                "quit" => app.exit(0),
                _ => {}
            })
            .on_tray_icon_event(|tray, event| {
                if matches!(
                    event,
                    TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    }
                ) {
                    show_main(tray.app_handle());
                }
            });
        if let Some(icon) = icon {
            builder = builder.icon(icon);
        }
        builder.build(app)?;
        Ok(())
    }

    fn start_idle_monitor(app: AppHandle) {
        tauri::async_runtime::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            loop {
                interval.tick().await;
                let locked = {
                    let state = app.state::<DesktopState>();
                    state.client.lock().await.lock_if_idle()
                };
                if locked {
                    let _ = app.emit("vault-locked", ());
                }
            }
        });
    }

    /// Starts the cross-platform desktop application.
    pub fn run() {
        let builder = tauri::Builder::default()
            .plugin(tauri_plugin_single_instance::init(|app, _, _| {
                show_main(app);
            }))
            .setup(|app| {
                let data_dir = app.path().app_local_data_dir()?;
                let client = DesktopClient::open(
                    data_dir.join("encrypted-vault-cache.json"),
                    Arc::new(KeyringSecretStore::new("org.hasilan.pass")),
                )
                .map_err(|error| std::io::Error::other(error.to_string()))?;
                app.manage(DesktopState {
                    client: Mutex::new(client),
                });
                setup_tray(app)?;
                start_idle_monitor(app.handle().clone());
                Ok(())
            })
            .on_window_event(|window, event| {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window.hide();
                }
            })
            .invoke_handler(tauri::generate_handler![
                status,
                register,
                login,
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
                remove_attachment,
                generate_password,
                generate_passphrase,
                totp_for_item,
                import_bitwarden_json,
                export_bitwarden_json,
                list_conflicts,
                resolve_conflict,
                select_profile,
                set_auto_lock_minutes,
                copy_secret,
            ]);

        let app = match builder.build(tauri::generate_context!()) {
            Ok(app) => app,
            Err(error) => {
                eprintln!("Hasilan Pass failed to start: {error}");
                return;
            }
        };
        app.run(|_, event| {
            if matches!(event, RunEvent::ExitRequested { .. }) {
                // Dropping managed state clears the in-memory user key and decrypted items.
            }
        });
    }
}

#[cfg(not(target_os = "android"))]
pub use desktop::run;

/// Android is launched by the generated `TauriActivity`; the macro exports the required native
/// entry point rather than running a desktop event loop from `main.rs`.
#[cfg(target_os = "android")]
#[tauri::mobile_entry_point]
pub fn run() {
    mobile::run();
}
