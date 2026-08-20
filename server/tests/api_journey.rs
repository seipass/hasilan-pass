//! PostgreSQL-backed zero-knowledge API journey.

use std::{error::Error, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hasilan_crypto::{
    AttachmentMetadata, CompositeKey, EncString, EncryptedEnvelope, KdfConfig, SharingKeyMaterial,
    decrypt_attachment_chunk, decrypt_json, derive_master_key, encrypt_attachment_chunk,
    encrypt_json, generate_sharing_key, open_organization_key, seal_organization_key,
    unwrap_sharing_private_key,
};
use hasilan_desktop_core::{DesktopClient, LoginDraft, MemorySecretStore};
use hasilan_protocol::{
    ApiErrorBody, AttachmentCompleteRequest, AttachmentInitiateRequest, AttachmentResponse,
    AttachmentState, CollectionAccessRequest, CollectionCreateRequest, CollectionResponse,
    DeleteObjectRequest, DeviceRequest, EncryptedObject, InvitationDeliveryKind, KdfSettings,
    LoginRequest, LogoutRequest, MembershipStatus, MfaEnableResponse, MfaStatusResponse,
    ObjectKind, OrganizationAcceptRequest, OrganizationCreateRequest, OrganizationInviteRequest,
    OrganizationInviteResponse, OrganizationMemberResponse, OrganizationResponse, OrganizationRole,
    OwnerType, PasskeyLoginStartRequest, PutObjectRequest, ReauthenticationRequest,
    RecoveryCodesResponse, RefreshRequest, RegisterRequest, RegisterResponse, SharingKeyRequest,
    SharingKeyResponse, SyncResponse, TokenResponse, TotpSetupFinishRequest,
    TotpSetupStartResponse, WebauthnChallengeResponse, WebauthnLoginFinishRequest,
    WebauthnMfaLoginStartRequest, WebauthnRegistrationFinishRequest,
    WebauthnRegistrationStartRequest,
};
use hasilan_server::{
    Config, InvitationDeliveryConfig, MfaEncryptionKey, SmtpConfig, SmtpTls, TokenPepper,
    build_router, connect_database,
};
use hasilan_vault::{ItemData, Login, LoginUri, SecretString, TotpConfig, VaultItem};
use serde::{Serialize, de::DeserializeOwned};
use sqlx::PgPool;
use tempfile::tempdir;
use tower::ServiceExt as _;
use url::Url;
use uuid::Uuid;
use webauthn_authenticator_rs::{prelude::WebauthnAuthenticator, softpasskey::SoftPasskey};
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

struct TestResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one ordered end-to-end journey keeps token and revision state explicit"
)]
async fn registration_encrypted_crud_sync_rotation_and_logout() -> Result<(), Box<dyn Error>> {
    let Some(database_url) = std::env::var("HP_TEST_DATABASE_URL").ok() else {
        eprintln!("HP_TEST_DATABASE_URL is not set; skipping PostgreSQL integration journey");
        return Ok(());
    };

    let config = Arc::new(test_config(database_url)?);
    let pool = connect_database(&config).await?;
    reset_database(&pool).await?;
    let app = build_router(Arc::clone(&config), pool.clone())?;

    let email = format!("integration-{}@example.test", Uuid::new_v4());
    let password = b"correct horse battery staple";
    let kdf = KdfConfig::default();
    let master_key = derive_master_key(password, &email, &kdf)?;
    let stretched_master_key = master_key.stretch()?;
    let user_key = CompositeKey::generate()?;
    let protected_user_key = EncString::encrypt(user_key.as_bytes(), &stretched_master_key)?;
    let auth_proof = STANDARD.encode(master_key.authentication_proof(password));
    let device = DeviceRequest {
        identifier: Uuid::new_v4(),
        name: "API integration test".to_owned(),
        device_type: "test".to_owned(),
    };

    let registered = send_json(
        &app,
        "POST",
        "/api/v1/auth/register",
        None,
        &RegisterRequest {
            email: email.clone(),
            auth_proof: auth_proof.clone(),
            protected_user_key: protected_user_key.to_string(),
            kdf: KdfSettings::default(),
            device: device.clone(),
        },
    )
    .await?;
    assert_eq!(registered.status, StatusCode::CREATED);
    let registered: RegisterResponse = decode(&registered.body)?;

    let login = send_json(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        &LoginRequest {
            email: email.clone(),
            auth_proof: auth_proof.clone(),
            device,
            totp_code: None,
            recovery_code: None,
            trusted_device_token: None,
            remember_device: false,
        },
    )
    .await?;
    assert_eq!(login.status, StatusCode::OK);
    let tokens: TokenResponse = decode(&login.body)?;
    assert_eq!(tokens.account_id, registered.account_id);

    // Web sessions move refresh authorization into HttpOnly/SameSite cookies while
    // native and extension clients retain the explicit JSON-token transport above.
    let mut web_transport = HeaderMap::new();
    web_transport.insert("x-hasilan-web-session", HeaderValue::from_static("1"));
    web_transport.insert(
        header::ORIGIN,
        HeaderValue::from_static("http://localhost:8080"),
    );
    let web_login = send_json_with_headers(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        &LoginRequest {
            email: email.clone(),
            auth_proof: auth_proof.clone(),
            device: DeviceRequest {
                identifier: Uuid::new_v4(),
                name: "Cookie transport test".to_owned(),
                device_type: "web".to_owned(),
            },
            totp_code: None,
            recovery_code: None,
            trusted_device_token: None,
            remember_device: false,
        },
        &web_transport,
    )
    .await?;
    assert_eq!(web_login.status, StatusCode::OK);
    let web_tokens: TokenResponse = decode(&web_login.body)?;
    assert!(web_tokens.refresh_token.is_empty());
    let csrf = web_login
        .headers
        .get("x-csrf-token")
        .ok_or_else(|| std::io::Error::other("missing Web CSRF response header"))?
        .to_str()?
        .to_owned();
    let refresh_cookie = response_cookie(&web_login.headers, "hp_refresh")?;
    let csrf_cookie = response_cookie(&web_login.headers, "hp_csrf")?;
    let set_cookies: Vec<_> = web_login
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(HeaderValue::to_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(set_cookies.len(), 2);
    assert!(set_cookies.iter().all(|cookie| {
        cookie.contains("Path=/api/v1/auth")
            && cookie.contains("SameSite=Strict")
            && cookie.contains("HttpOnly")
            && !cookie.contains("; Secure")
    }));

    let mut web_refresh_headers = web_transport.clone();
    web_refresh_headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!(
            "hp_refresh={refresh_cookie}; hp_csrf={csrf_cookie}"
        ))?,
    );
    let csrf_rejected = send_json_with_headers(
        &app,
        "POST",
        "/api/v1/auth/refresh",
        None,
        &RefreshRequest {
            refresh_token: String::new(),
        },
        &web_refresh_headers,
    )
    .await?;
    assert_eq!(csrf_rejected.status, StatusCode::FORBIDDEN);

    web_refresh_headers.insert("x-csrf-token", HeaderValue::from_str(&csrf)?);
    let web_refresh = send_json_with_headers(
        &app,
        "POST",
        "/api/v1/auth/refresh",
        None,
        &RefreshRequest {
            refresh_token: String::new(),
        },
        &web_refresh_headers,
    )
    .await?;
    assert_eq!(web_refresh.status, StatusCode::OK);
    let rotated_web_tokens: TokenResponse = decode(&web_refresh.body)?;
    assert!(rotated_web_tokens.refresh_token.is_empty());
    let rotated_csrf = web_refresh
        .headers
        .get("x-csrf-token")
        .ok_or_else(|| std::io::Error::other("missing rotated CSRF response header"))?
        .to_str()?
        .to_owned();
    assert_ne!(rotated_csrf, csrf);
    let rotated_refresh_cookie = response_cookie(&web_refresh.headers, "hp_refresh")?;
    let rotated_csrf_cookie = response_cookie(&web_refresh.headers, "hp_csrf")?;
    let mut web_logout_headers = web_transport.clone();
    web_logout_headers.insert("x-csrf-token", HeaderValue::from_str(&rotated_csrf)?);
    web_logout_headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!(
            "hp_refresh={rotated_refresh_cookie}; hp_csrf={rotated_csrf_cookie}"
        ))?,
    );
    let web_logout = send_json_with_headers(
        &app,
        "POST",
        "/api/v1/auth/logout",
        Some(&rotated_web_tokens.access_token),
        &LogoutRequest {
            refresh_token: None,
        },
        &web_logout_headers,
    )
    .await?;
    assert_eq!(web_logout.status, StatusCode::NO_CONTENT);
    assert!(
        web_logout
            .headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .all(|cookie| cookie.contains("Max-Age=0"))
    );

    let mut item = VaultItem::new_login(
        "Private production login",
        Login {
            username: Some("alice@example.test".to_owned()),
            password: Some(SecretString::new("do-not-store-in-plaintext")),
            uris: vec![LoginUri {
                uri: "https://login.example.test".to_owned(),
                r#match: None,
                extra: serde_json::Map::new(),
            }],
            totp: Some(SecretString::new("JBSWY3DPEHPK3PXP")),
            ..Login::default()
        },
    );
    let envelope = encrypt_json(&item, &user_key)?;
    let object_id = item.id;
    let create_request = PutObjectRequest {
        kind: ObjectKind::Cipher,
        owner_type: OwnerType::User,
        owner_id: tokens.account_id,
        collection_ids: Vec::new(),
        format: envelope.format,
        wrapped_key: envelope.wrapped_key,
        payload: envelope.payload,
        base_revision: None,
        idempotency_key: Uuid::new_v4(),
    };
    let created = send_json(
        &app,
        "PUT",
        &format!("/api/v1/vault/objects/{object_id}"),
        Some(&tokens.access_token),
        &create_request,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    let created: EncryptedObject = decode(&created.body)?;
    assert_eq!(created.object_revision, 1);

    // A retry with the same key and exact body must not allocate another revision.
    let retried = send_json(
        &app,
        "PUT",
        &format!("/api/v1/vault/objects/{object_id}"),
        Some(&tokens.access_token),
        &create_request,
    )
    .await?;
    let retried: EncryptedObject = decode(&retried.body)?;
    assert_eq!(retried.account_revision, created.account_revision);

    let stored: (String, String) = sqlx::query_as(
        "SELECT wrapped_key, payload FROM vault_objects WHERE account_id = $1 AND id = $2",
    )
    .bind(tokens.account_id)
    .bind(object_id)
    .fetch_one(&pool)
    .await?;
    for secret in [
        "Private production login",
        "alice@example.test",
        "do-not-store-in-plaintext",
        "JBSWY3DPEHPK3PXP",
    ] {
        assert!(!stored.0.contains(secret));
        assert!(!stored.1.contains(secret));
    }

    let synced = send_empty(
        &app,
        "GET",
        "/api/v1/sync?limit=200",
        Some(&tokens.access_token),
    )
    .await?;
    assert_eq!(synced.status, StatusCode::OK);
    let synced: SyncResponse = decode(&synced.body)?;
    assert_eq!(synced.changes.len(), 1);
    let synced_object = synced.changes[0]
        .object
        .as_ref()
        .ok_or("sync upsert did not include an object")?;
    let decrypted: VaultItem = decrypt_json(
        &EncryptedEnvelope {
            format: synced_object.format.clone(),
            wrapped_key: synced_object.wrapped_key.clone(),
            payload: synced_object.payload.clone(),
        },
        &user_key,
    )?;
    assert_eq!(decrypted, item);

    let mut attachment_plaintext = b"attachment plaintext must remain client-only:".to_vec();
    attachment_plaintext.extend(std::iter::repeat_n(0x5a, 70_000));
    let attachment = AttachmentMetadata::generate(
        "synthetic-evidence.bin",
        "application/octet-stream",
        u64::try_from(attachment_plaintext.len())?,
        64 * 1024,
    )?;
    item.attachments.push(attachment.clone());
    item.name = "Edited without data loss".to_owned();
    let edited_envelope = encrypt_json(&item, &user_key)?;
    let edited = send_json(
        &app,
        "PUT",
        &format!("/api/v1/vault/objects/{object_id}"),
        Some(&tokens.access_token),
        &PutObjectRequest {
            kind: ObjectKind::Cipher,
            owner_type: OwnerType::User,
            owner_id: tokens.account_id,
            collection_ids: Vec::new(),
            format: edited_envelope.format,
            wrapped_key: edited_envelope.wrapped_key,
            payload: edited_envelope.payload,
            base_revision: Some(created.object_revision),
            idempotency_key: Uuid::new_v4(),
        },
    )
    .await?;
    assert_eq!(edited.status, StatusCode::OK);
    let edited: EncryptedObject = decode(&edited.body)?;
    assert_eq!(edited.object_revision, 2);

    let initiated = send_json(
        &app,
        "POST",
        "/api/v1/attachments",
        Some(&tokens.access_token),
        &AttachmentInitiateRequest {
            id: attachment.id,
            object_id,
            object_revision: edited.object_revision,
            format: attachment.format().to_owned(),
            chunk_size: attachment.chunk_size,
            chunk_count: attachment.chunk_count,
            ciphertext_size: attachment.ciphertext_size,
        },
    )
    .await?;
    assert_eq!(initiated.status, StatusCode::CREATED);
    let initiated: AttachmentResponse = decode(&initiated.body)?;
    assert_eq!(initiated.state, AttachmentState::Uploading);
    assert!(initiated.uploaded_ranges.is_empty());

    let mut encrypted_chunks = Vec::new();
    for index in 0..attachment.chunk_count {
        let start = usize::try_from(index)? * usize::try_from(attachment.chunk_size)?;
        let end = start + attachment.plaintext_chunk_len(index)?;
        encrypted_chunks.push(encrypt_attachment_chunk(
            &attachment,
            object_id,
            index,
            &attachment_plaintext[start..end],
        )?);
    }
    let incomplete = send_json(
        &app,
        "POST",
        &format!("/api/v1/attachments/{}/complete", attachment.id),
        Some(&tokens.access_token),
        &AttachmentCompleteRequest {
            object_revision: edited.object_revision,
        },
    )
    .await?;
    assert_eq!(incomplete.status, StatusCode::CONFLICT);

    // Frames can arrive out of order and exact retries are idempotent.
    for index in (0..attachment.chunk_count).rev() {
        let uploaded = send(
            &app,
            "PUT",
            &format!("/api/v1/attachments/{}/chunks/{index}", attachment.id),
            Some(&tokens.access_token),
            Body::from(encrypted_chunks[usize::try_from(index)?].clone()),
            false,
        )
        .await?;
        assert_eq!(uploaded.status, StatusCode::NO_CONTENT);
    }
    let retried_chunk = send(
        &app,
        "PUT",
        &format!("/api/v1/attachments/{}/chunks/0", attachment.id),
        Some(&tokens.access_token),
        Body::from(encrypted_chunks[0].clone()),
        false,
    )
    .await?;
    assert_eq!(retried_chunk.status, StatusCode::NO_CONTENT);
    let mut conflicting_chunk = encrypted_chunks[0].clone();
    conflicting_chunk[0] ^= 1;
    let conflict = send(
        &app,
        "PUT",
        &format!("/api/v1/attachments/{}/chunks/0", attachment.id),
        Some(&tokens.access_token),
        Body::from(conflicting_chunk),
        false,
    )
    .await?;
    assert_eq!(conflict.status, StatusCode::CONFLICT);

    let progress = send_empty(
        &app,
        "GET",
        &format!("/api/v1/attachments/{}", attachment.id),
        Some(&tokens.access_token),
    )
    .await?;
    let progress: AttachmentResponse = decode(&progress.body)?;
    assert_eq!(progress.uploaded_ranges.len(), 1);
    assert_eq!(progress.uploaded_ranges[0].start, 0);
    assert_eq!(
        progress.uploaded_ranges[0].end_exclusive,
        attachment.chunk_count
    );
    let completed = send_json(
        &app,
        "POST",
        &format!("/api/v1/attachments/{}/complete", attachment.id),
        Some(&tokens.access_token),
        &AttachmentCompleteRequest {
            object_revision: edited.object_revision,
        },
    )
    .await?;
    assert_eq!(completed.status, StatusCode::OK);
    assert_eq!(
        decode::<AttachmentResponse>(&completed.body)?.state,
        AttachmentState::Complete
    );
    let listed = send_empty(
        &app,
        "GET",
        &format!("/api/v1/vault/objects/{object_id}/attachments"),
        Some(&tokens.access_token),
    )
    .await?;
    assert_eq!(decode::<Vec<AttachmentResponse>>(&listed.body)?.len(), 1);

    let mut downloaded = Vec::with_capacity(attachment_plaintext.len());
    for index in 0..attachment.chunk_count {
        let response = send_empty(
            &app,
            "GET",
            &format!("/api/v1/attachments/{}/chunks/{index}", attachment.id),
            Some(&tokens.access_token),
        )
        .await?;
        assert_eq!(response.status, StatusCode::OK);
        downloaded.extend_from_slice(&decrypt_attachment_chunk(
            &attachment,
            object_id,
            index,
            &response.body,
        )?);
    }
    assert_eq!(downloaded, attachment_plaintext);

    let stored_chunks = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT ciphertext FROM attachment_chunks WHERE attachment_id = $1 ORDER BY chunk_index",
    )
    .bind(attachment.id)
    .fetch_all(&pool)
    .await?;
    assert!(
        stored_chunks
            .iter()
            .all(|chunk| !contains_bytes(chunk, b"attachment plaintext"))
    );

    let deleted = send_json(
        &app,
        "DELETE",
        &format!("/api/v1/vault/objects/{object_id}"),
        Some(&tokens.access_token),
        &DeleteObjectRequest {
            base_revision: edited.object_revision,
            idempotency_key: Uuid::new_v4(),
        },
    )
    .await?;
    assert_eq!(deleted.status, StatusCode::OK);
    let deleted: EncryptedObject = decode(&deleted.body)?;
    assert!(deleted.deleted_at.is_some());
    assert_eq!(deleted.object_revision, 3);
    let hidden_attachment = send_empty(
        &app,
        "GET",
        &format!("/api/v1/attachments/{}/chunks/0", attachment.id),
        Some(&tokens.access_token),
    )
    .await?;
    assert_eq!(hidden_attachment.status, StatusCode::NOT_FOUND);

    let first_refresh = send_json(
        &app,
        "POST",
        "/api/v1/auth/refresh",
        None,
        &RefreshRequest {
            refresh_token: tokens.refresh_token.clone(),
        },
    )
    .await?;
    assert_eq!(first_refresh.status, StatusCode::OK);
    let rotated: TokenResponse = decode(&first_refresh.body)?;
    let reuse = send_json(
        &app,
        "POST",
        "/api/v1/auth/refresh",
        None,
        &RefreshRequest {
            refresh_token: tokens.refresh_token,
        },
    )
    .await?;
    assert_eq!(reuse.status, StatusCode::UNAUTHORIZED);
    let revoked_access = send_empty(
        &app,
        "GET",
        "/api/v1/account/sessions",
        Some(&rotated.access_token),
    )
    .await?;
    assert_eq!(revoked_access.status, StatusCode::UNAUTHORIZED);

    let second_login = send_json(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        &LoginRequest {
            email,
            auth_proof,
            device: DeviceRequest {
                identifier: Uuid::new_v4(),
                name: "Logout test".to_owned(),
                device_type: "test".to_owned(),
            },
            totp_code: None,
            recovery_code: None,
            trusted_device_token: None,
            remember_device: false,
        },
    )
    .await?;
    assert_eq!(second_login.status, StatusCode::OK);
    let second_tokens: TokenResponse = decode(&second_login.body)?;
    let logout = send_json(
        &app,
        "POST",
        "/api/v1/auth/logout",
        Some(&second_tokens.access_token),
        &LogoutRequest {
            refresh_token: Some(second_tokens.refresh_token),
        },
    )
    .await?;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);
    let logged_out_access = send_empty(
        &app,
        "GET",
        "/api/v1/account/sessions",
        Some(&second_tokens.access_token),
    )
    .await?;
    assert_eq!(logged_out_access.status, StatusCode::UNAUTHORIZED);

    // Exercise the same API over a real TCP socket through the native desktop runtime.
    // This proves that the Tauri core does not rely on the in-process test router or on
    // either browser client for registration, crypto, sync, and offline recovery.
    let live_app = app.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let live_address = listener.local_addr()?;
    let mut live_server = tokio::spawn(async move { axum::serve(listener, live_app).await });
    let server_url = format!("http://{live_address}");
    let desktop_email = format!("desktop-{}@example.test", Uuid::new_v4());
    let desktop_password = "correct desktop master password";
    let first_directory = tempdir()?;
    let first_cache = first_directory.path().join("encrypted-cache.json");
    let first_secrets = Arc::new(MemorySecretStore::default());
    let mut first_desktop = DesktopClient::open(&first_cache, first_secrets.clone())?;

    let status = first_desktop
        .register(
            server_url.clone(),
            desktop_email.clone(),
            desktop_password.to_owned(),
        )
        .await?;
    assert!(status.unlocked && status.online);
    let created = first_desktop
        .save_login(LoginDraft {
            id: None,
            name: "Desktop private account".to_owned(),
            username: Some("desktop-user@example.test".to_owned()),
            password: Some("desktop-only-password".to_owned()),
            uri: Some("https://desktop.example.test/login".to_owned()),
            totp: Some("JBSWY3DPEHPK3PXP".to_owned()),
            notes: Some("desktop plaintext should never escape".to_owned()),
            favorite: true,
            folder_id: None,
            fields: Vec::new(),
            organization_id: None,
            collection_ids: Vec::new(),
        })
        .await?;
    assert_eq!(first_desktop.status().pending_count, 0);

    let second_directory = tempdir()?;
    let second_cache = second_directory.path().join("encrypted-cache.json");
    let second_secrets = Arc::new(MemorySecretStore::default());
    let mut second_desktop = DesktopClient::open(&second_cache, second_secrets)?;
    let status = second_desktop
        .login(
            server_url.clone(),
            desktop_email.clone(),
            desktop_password.to_owned(),
            None,
            None,
        )
        .await?;
    assert!(status.unlocked && status.online);
    let rows = second_desktop.list_items("desktop-user", "logins")?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, created.id);
    let edited = second_desktop
        .save_login(LoginDraft {
            id: Some(created.id),
            name: "Desktop private account".to_owned(),
            username: Some("desktop-user@example.test".to_owned()),
            password: Some("synced-from-device-b".to_owned()),
            uri: Some("https://desktop.example.test/login".to_owned()),
            totp: Some("JBSWY3DPEHPK3PXP".to_owned()),
            notes: Some("updated on the second native client".to_owned()),
            favorite: true,
            folder_id: None,
            fields: Vec::new(),
            organization_id: None,
            collection_ids: Vec::new(),
        })
        .await?;
    assert_eq!(edited.password_history.len(), 1);

    first_desktop.sync_now().await?;
    let synchronized = first_desktop.get_item(created.id)?;
    let ItemData::Login(synchronized_login) = synchronized.data else {
        return Err("desktop sync returned a non-login item".into());
    };
    assert_eq!(
        synchronized_login
            .password
            .as_ref()
            .map(SecretString::expose),
        Some("synced-from-device-b")
    );

    // Native file I/O never crosses a webview boundary: Rust streams one authenticated
    // frame at a time, commits downloads atomically, and synchronizes private metadata.
    let mut native_attachment_plaintext =
        b"native attachment plaintext must remain client-only:".to_vec();
    native_attachment_plaintext.extend(std::iter::repeat_n(0x31, 1_100_000));
    let native_source = first_directory.path().join("native-private-evidence.bin");
    std::fs::write(&native_source, &native_attachment_plaintext)?;
    let attached = first_desktop
        .upload_attachment_from_path(created.id, None, &native_source)
        .await?;
    assert_eq!(attached.attachments.len(), 1);
    let native_attachment_id = attached.attachments[0].id;
    let native_cache = std::fs::read_to_string(&first_cache)?;
    assert!(!native_cache.contains("native-private-evidence.bin"));
    assert!(!native_cache.contains("native attachment plaintext"));

    second_desktop.sync_now().await?;
    let synchronized_attachment = second_desktop.get_item(created.id)?;
    assert_eq!(synchronized_attachment.attachments.len(), 1);
    assert_eq!(
        synchronized_attachment.attachments[0].id,
        native_attachment_id
    );
    let native_destination = second_directory.path().join("native-download.bin");
    second_desktop
        .download_attachment_to_path(created.id, native_attachment_id, &native_destination)
        .await?;
    assert_eq!(
        std::fs::read(&native_destination)?,
        native_attachment_plaintext
    );
    let native_stored_chunks = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT ciphertext FROM attachment_chunks WHERE attachment_id = $1 ORDER BY chunk_index",
    )
    .bind(native_attachment_id)
    .fetch_all(&pool)
    .await?;
    assert!(
        native_stored_chunks
            .iter()
            .all(|chunk| !contains_bytes(chunk, b"native attachment plaintext"))
    );
    let removed = second_desktop
        .remove_attachment(created.id, native_attachment_id)
        .await?;
    assert!(!removed.cleanup_pending);
    assert!(removed.item.attachments.is_empty());
    let remaining_chunks = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM attachment_chunks WHERE attachment_id = $1",
    )
    .bind(native_attachment_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(remaining_chunks, 0);
    first_desktop.sync_now().await?;
    assert!(first_desktop.get_item(created.id)?.attachments.is_empty());

    // Stop the listener, reopen from only the ciphertext cache, and make an edit. The
    // cache must unlock with the master password and preserve one durable outbox entry.
    live_server.abort();
    let _ = live_server.await;
    first_desktop.lock();
    drop(first_desktop);
    let mut offline_desktop = DesktopClient::open(&first_cache, first_secrets)?;
    let status = offline_desktop
        .login(
            server_url.clone(),
            desktop_email,
            desktop_password.to_owned(),
            None,
            None,
        )
        .await?;
    assert!(status.unlocked && !status.online);
    offline_desktop
        .save_login(LoginDraft {
            id: Some(created.id),
            name: "Desktop private account offline".to_owned(),
            username: Some("desktop-user@example.test".to_owned()),
            password: Some("queued-offline-password".to_owned()),
            uri: Some("https://desktop.example.test/login".to_owned()),
            totp: Some("JBSWY3DPEHPK3PXP".to_owned()),
            notes: Some("offline native edit".to_owned()),
            favorite: true,
            folder_id: None,
            fields: Vec::new(),
            organization_id: None,
            collection_ids: Vec::new(),
        })
        .await?;
    assert_eq!(offline_desktop.status().pending_count, 1);
    let cache_text = std::fs::read_to_string(&first_cache)?;
    for secret in [
        "Desktop private account",
        "desktop-user@example.test",
        "desktop-only-password",
        "synced-from-device-b",
        "queued-offline-password",
        "JBSWY3DPEHPK3PXP",
        "offline native edit",
    ] {
        assert!(
            !cache_text.contains(secret),
            "desktop cache exposed {secret}"
        );
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    let listener = tokio::net::TcpListener::bind(live_address).await?;
    let live_app = app.clone();
    live_server = tokio::spawn(async move { axum::serve(listener, live_app).await });
    let status = offline_desktop.sync_now().await?;
    assert!(status.online);
    assert_eq!(status.pending_count, 0);
    second_desktop.sync_now().await?;
    let synchronized = second_desktop.get_item(created.id)?;
    let ItemData::Login(synchronized_login) = synchronized.data else {
        return Err("desktop reconnect returned a non-login item".into());
    };
    assert_eq!(
        synchronized_login
            .password
            .as_ref()
            .map(SecretString::expose),
        Some("queued-offline-password")
    );

    let stored: (String, String) =
        sqlx::query_as("SELECT wrapped_key, payload FROM vault_objects WHERE id = $1")
            .bind(created.id)
            .fetch_one(&pool)
            .await?;
    for secret in [
        "Desktop private account offline",
        "desktop-user@example.test",
        "desktop-only-password",
        "synced-from-device-b",
        "queued-offline-password",
        "JBSWY3DPEHPK3PXP",
        "offline native edit",
    ] {
        assert!(!stored.0.contains(secret));
        assert!(!stored.1.contains(secret));
    }
    let status = offline_desktop.logout().await?;
    assert!(!status.unlocked);
    live_server.abort();
    let _ = live_server.await;

    exercise_organizations(&app, &pool, &config).await?;
    exercise_account_security(&app, &pool).await?;

    pool.close().await;
    Ok(())
}

struct OrganizationTestAccount {
    email: String,
    user_key: CompositeKey,
    sharing: SharingKeyMaterial,
    tokens: TokenResponse,
}

#[allow(
    clippy::too_many_lines,
    reason = "the ordered multi-account journey makes ACL and sync transitions auditable"
)]
async fn exercise_organizations(
    app: &Router,
    pool: &PgPool,
    base_config: &Config,
) -> Result<(), Box<dyn Error>> {
    let owner = register_organization_account(app, "owner").await?;
    let member = register_organization_account(app, "member").await?;
    let failed_delivery_member = register_organization_account(app, "failed-delivery").await?;

    for account in [&owner, &member, &failed_delivery_member] {
        let installed = send_json(
            app,
            "PUT",
            "/api/v1/account/sharing-key",
            Some(&account.tokens.access_token),
            &SharingKeyRequest {
                public_key: account.sharing.public_key.clone(),
                protected_private_key: account.sharing.protected_private_key.clone(),
            },
        )
        .await?;
        assert_eq!(installed.status, StatusCode::OK);
        let installed: SharingKeyResponse = decode(&installed.body)?;
        assert_eq!(installed.account_id, account.tokens.account_id);
        assert_eq!(installed.public_key, account.sharing.public_key);
        assert_eq!(
            installed.protected_private_key.as_deref(),
            Some(account.sharing.protected_private_key.as_str())
        );
    }

    let lookup = send_empty(
        app,
        "GET",
        &format!("/api/v1/directory/sharing-key?email={}", member.email),
        Some(&owner.tokens.access_token),
    )
    .await?;
    assert_eq!(lookup.status, StatusCode::OK);
    let lookup: SharingKeyResponse = decode(&lookup.body)?;
    assert_eq!(lookup.public_key, member.sharing.public_key);
    assert!(lookup.protected_private_key.is_none());

    let organization_id = Uuid::new_v4();
    let organization_key = CompositeKey::generate()?;
    let owner_wrapper = seal_organization_key(
        organization_id,
        &owner.sharing.public_key,
        &organization_key,
    )?;
    let created = send_json(
        app,
        "POST",
        "/api/v1/organizations",
        Some(&owner.tokens.access_token),
        &OrganizationCreateRequest {
            id: organization_id,
            name: "Ciphertext Engineering".to_owned(),
            encrypted_organization_key: owner_wrapper.clone(),
        },
    )
    .await?;
    assert_eq!(created.status, StatusCode::CREATED);
    let created: OrganizationResponse = decode(&created.body)?;
    assert_eq!(created.id, organization_id);
    assert_eq!(created.role, OrganizationRole::Owner);
    assert_eq!(created.status, MembershipStatus::Confirmed);

    let unavailable_port = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        listener.local_addr()?.port()
    };
    let mut smtp_config = base_config.clone();
    smtp_config.invitation_delivery = InvitationDeliveryConfig::Smtp(SmtpConfig {
        host: "localhost".to_owned(),
        port: unavailable_port,
        tls: SmtpTls::StartTls,
        from: "Hasilan Pass <noreply@example.test>".to_owned(),
        username: None,
        password: None,
        timeout: Duration::from_secs(1),
    });
    let smtp_app = build_router(Arc::new(smtp_config), pool.clone())?;
    let failed_wrapper = seal_organization_key(
        organization_id,
        &failed_delivery_member.sharing.public_key,
        &organization_key,
    )?;
    let failed_delivery = send_json(
        &smtp_app,
        "POST",
        &format!("/api/v1/organizations/{organization_id}/invitations"),
        Some(&owner.tokens.access_token),
        &OrganizationInviteRequest {
            email: failed_delivery_member.email.clone(),
            role: OrganizationRole::User,
            encrypted_organization_key: failed_wrapper,
        },
    )
    .await?;
    assert_eq!(failed_delivery.status, StatusCode::BAD_GATEWAY);
    let failed_membership_count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM organization_members WHERE organization_id = $1 AND email = $2",
    )
    .bind(organization_id)
    .bind(&failed_delivery_member.email)
    .fetch_one(pool)
    .await?;
    assert_eq!(failed_membership_count, 0);

    let first_collection = create_collection(
        app,
        &owner.tokens.access_token,
        organization_id,
        "Production",
    )
    .await?;
    let second_collection =
        create_collection(app, &owner.tokens.access_token, organization_id, "Finance").await?;

    let member_wrapper = seal_organization_key(
        organization_id,
        &member.sharing.public_key,
        &organization_key,
    )?;
    let invited = send_json(
        app,
        "POST",
        &format!("/api/v1/organizations/{organization_id}/invitations"),
        Some(&owner.tokens.access_token),
        &OrganizationInviteRequest {
            email: member.email.clone(),
            role: OrganizationRole::User,
            encrypted_organization_key: member_wrapper.clone(),
        },
    )
    .await?;
    assert_eq!(invited.status, StatusCode::CREATED);
    let invitation: OrganizationInviteResponse = decode(&invited.body)?;
    assert_eq!(invitation.delivery, InvitationDeliveryKind::Manual);
    let invitation_token = invitation
        .invitation_token
        .ok_or("manual invitation delivery did not return a token")?;

    let accepted = send_json(
        app,
        "POST",
        "/api/v1/organizations/invitations/accept",
        Some(&member.tokens.access_token),
        &OrganizationAcceptRequest {
            invitation_token: invitation_token.clone(),
        },
    )
    .await?;
    assert_eq!(accepted.status, StatusCode::OK);
    let accepted: OrganizationMemberResponse = decode(&accepted.body)?;
    assert_eq!(accepted.status, MembershipStatus::Accepted);
    assert_eq!(
        accepted.encrypted_organization_key.as_deref(),
        Some(member_wrapper.as_str())
    );
    let replay = send_json(
        app,
        "POST",
        "/api/v1/organizations/invitations/accept",
        Some(&member.tokens.access_token),
        &OrganizationAcceptRequest { invitation_token },
    )
    .await?;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);

    let member_private = unwrap_sharing_private_key(
        &member.sharing.public_key,
        &member.sharing.protected_private_key,
        &member.user_key,
    )?;
    let opened_key = open_organization_key(&member_private, organization_id, &member_wrapper)?;
    assert_eq!(opened_key.as_bytes(), organization_key.as_bytes());

    let confirmed = send_empty(
        app,
        "POST",
        &format!(
            "/api/v1/organizations/{organization_id}/members/{}/confirm",
            invitation.member_id
        ),
        Some(&owner.tokens.access_token),
    )
    .await?;
    assert_eq!(confirmed.status, StatusCode::OK);
    assert_eq!(
        decode::<OrganizationMemberResponse>(&confirmed.body)?.status,
        MembershipStatus::Confirmed
    );

    let granted = send_json(
        app,
        "PUT",
        &format!(
            "/api/v1/organizations/{organization_id}/collections/{}/access/{}",
            first_collection.id, invitation.member_id
        ),
        Some(&owner.tokens.access_token),
        &CollectionAccessRequest {
            member_id: invitation.member_id,
            read_only: false,
            hide_passwords: false,
            manage: false,
        },
    )
    .await?;
    assert_eq!(granted.status, StatusCode::NO_CONTENT);

    let mut first_item = VaultItem::new_login(
        "Organization production login",
        Login {
            username: Some("organization-user@example.test".to_owned()),
            password: Some(SecretString::new("organization-only-password")),
            uris: vec![LoginUri {
                uri: "https://organization.example.test".to_owned(),
                r#match: None,
                extra: serde_json::Map::new(),
            }],
            ..Login::default()
        },
    );
    first_item.organization_id = Some(organization_id);
    first_item.collection_ids = vec![first_collection.id];
    let first_envelope = encrypt_json(&first_item, &organization_key)?;
    let first_created = put_organization_item(
        app,
        &owner.tokens.access_token,
        organization_id,
        &first_item,
        &first_envelope,
        None,
    )
    .await?;

    let mut second_item = VaultItem::new_login(
        "Organization finance login",
        Login {
            username: Some("finance@example.test".to_owned()),
            password: Some(SecretString::new("finance-only-password")),
            ..Login::default()
        },
    );
    second_item.organization_id = Some(organization_id);
    second_item.collection_ids = vec![second_collection.id];
    let second_envelope = encrypt_json(&second_item, &organization_key)?;
    let second_created = put_organization_item(
        app,
        &owner.tokens.access_token,
        organization_id,
        &second_item,
        &second_envelope,
        None,
    )
    .await?;

    let synced = send_empty(
        app,
        "GET",
        "/api/v1/sync?limit=200",
        Some(&member.tokens.access_token),
    )
    .await?;
    assert_eq!(synced.status, StatusCode::OK);
    let synced: SyncResponse = decode(&synced.body)?;
    assert_eq!(synced.changes.len(), 1);
    assert_eq!(synced.changes[0].object_id, first_item.id);
    let synced_first = synced.changes[0]
        .object
        .as_ref()
        .ok_or("organization upsert omitted ciphertext")?;
    let decrypted: VaultItem = decrypt_json(
        &EncryptedEnvelope {
            format: synced_first.format.clone(),
            wrapped_key: synced_first.wrapped_key.clone(),
            payload: synced_first.payload.clone(),
        },
        &opened_key,
    )?;
    assert_eq!(decrypted, first_item);

    "Organization production login edited by member".clone_into(&mut first_item.name);
    let edited_envelope = encrypt_json(&first_item, &opened_key)?;
    let edited = put_organization_item(
        app,
        &member.tokens.access_token,
        organization_id,
        &first_item,
        &edited_envelope,
        Some(first_created.object_revision),
    )
    .await?;
    assert_eq!(edited.object_revision, 2);

    let read_only_grant = send_json(
        app,
        "PUT",
        &format!(
            "/api/v1/organizations/{organization_id}/collections/{}/access/{}",
            second_collection.id, invitation.member_id
        ),
        Some(&owner.tokens.access_token),
        &CollectionAccessRequest {
            member_id: invitation.member_id,
            read_only: true,
            hide_passwords: true,
            manage: false,
        },
    )
    .await?;
    assert_eq!(read_only_grant.status, StatusCode::NO_CONTENT);
    let denied = put_organization_item_response(
        app,
        &member.tokens.access_token,
        organization_id,
        &second_item,
        &second_envelope,
        Some(second_created.object_revision),
    )
    .await?;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);

    let after_grant = send_empty(
        app,
        "GET",
        &format!("/api/v1/sync?limit=200&cursor={}", synced.next_cursor),
        Some(&member.tokens.access_token),
    )
    .await?;
    let after_grant: SyncResponse = decode(&after_grant.body)?;
    assert_eq!(after_grant.changes.len(), 2);
    assert!(
        after_grant
            .changes
            .iter()
            .any(|change| change.object_id == first_item.id && change.object.is_some())
    );
    assert!(
        after_grant
            .changes
            .iter()
            .any(|change| change.object_id == second_item.id && change.object.is_some())
    );

    let revoked = send_empty(
        app,
        "DELETE",
        &format!(
            "/api/v1/organizations/{organization_id}/collections/{}/access/{}",
            first_collection.id, invitation.member_id
        ),
        Some(&owner.tokens.access_token),
    )
    .await?;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT);
    let after_revoke = send_empty(
        app,
        "GET",
        &format!("/api/v1/sync?limit=200&cursor={}", after_grant.next_cursor),
        Some(&member.tokens.access_token),
    )
    .await?;
    let after_revoke: SyncResponse = decode(&after_revoke.body)?;
    assert_eq!(after_revoke.changes.len(), 1);
    assert_eq!(after_revoke.changes[0].object_id, first_item.id);
    assert!(after_revoke.changes[0].object.is_none());

    let removed = send_empty(
        app,
        "DELETE",
        &format!(
            "/api/v1/organizations/{organization_id}/members/{}",
            invitation.member_id
        ),
        Some(&owner.tokens.access_token),
    )
    .await?;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let after_remove = send_empty(
        app,
        "GET",
        &format!("/api/v1/sync?limit=200&cursor={}", after_revoke.next_cursor),
        Some(&member.tokens.access_token),
    )
    .await?;
    let after_remove: SyncResponse = decode(&after_remove.body)?;
    assert_eq!(after_remove.changes.len(), 1);
    assert_eq!(after_remove.changes[0].object_id, second_item.id);
    assert!(after_remove.changes[0].object.is_none());
    let inaccessible = send_empty(
        app,
        "GET",
        &format!("/api/v1/vault/objects/{}", second_item.id),
        Some(&member.tokens.access_token),
    )
    .await?;
    assert_eq!(inaccessible.status, StatusCode::NOT_FOUND);

    let stored = sqlx::query_as::<_, (String, String, String)>(
        r"
        SELECT a.protected_sharing_private_key, o.wrapped_key, o.payload
        FROM accounts a
        JOIN vault_objects o ON o.id = $2
        WHERE a.id = $1
        ",
    )
    .bind(member.tokens.account_id)
    .bind(first_item.id)
    .fetch_one(pool)
    .await?;
    for secret in [
        "Organization production login",
        "organization-user@example.test",
        "organization-only-password",
        "Organization finance login",
        "finance-only-password",
    ] {
        assert!(!stored.0.contains(secret));
        assert!(!stored.1.contains(secret));
        assert!(!stored.2.contains(secret));
    }
    assert!(!owner_wrapper.contains(&encoded_composite_key(&organization_key)));
    Ok(())
}

fn encoded_composite_key(key: &CompositeKey) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.as_bytes())
}

async fn register_organization_account(
    app: &Router,
    label: &str,
) -> Result<OrganizationTestAccount, Box<dyn Error>> {
    let email = format!("organization-{label}-{}@example.test", Uuid::new_v4());
    let password = format!("{label} organization master password");
    let kdf = KdfConfig::default();
    let master_key = derive_master_key(password.as_bytes(), &email, &kdf)?;
    let user_key = CompositeKey::generate()?;
    let protected_user_key = EncString::encrypt(user_key.as_bytes(), &master_key.stretch()?)?;
    let auth_proof = STANDARD.encode(master_key.authentication_proof(password.as_bytes()));
    let device = DeviceRequest {
        identifier: Uuid::new_v4(),
        name: format!("Organization {label} browser"),
        device_type: "integration-test".to_owned(),
    };
    let registered = send_json(
        app,
        "POST",
        "/api/v1/auth/register",
        None,
        &RegisterRequest {
            email: email.clone(),
            auth_proof: auth_proof.clone(),
            protected_user_key: protected_user_key.to_string(),
            kdf: KdfSettings::default(),
            device: device.clone(),
        },
    )
    .await?;
    assert_eq!(registered.status, StatusCode::CREATED);
    let login = send_json(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        &LoginRequest {
            email: email.clone(),
            auth_proof,
            device,
            totp_code: None,
            recovery_code: None,
            trusted_device_token: None,
            remember_device: false,
        },
    )
    .await?;
    assert_eq!(login.status, StatusCode::OK);
    let tokens = decode(&login.body)?;
    let sharing = generate_sharing_key(&user_key)?;
    Ok(OrganizationTestAccount {
        email,
        user_key,
        sharing,
        tokens,
    })
}

async fn create_collection(
    app: &Router,
    access_token: &str,
    organization_id: Uuid,
    name: &str,
) -> Result<CollectionResponse, Box<dyn Error>> {
    let response = send_json(
        app,
        "POST",
        &format!("/api/v1/organizations/{organization_id}/collections"),
        Some(access_token),
        &CollectionCreateRequest {
            name: name.to_owned(),
        },
    )
    .await?;
    assert_eq!(response.status, StatusCode::CREATED);
    Ok(decode(&response.body)?)
}

async fn put_organization_item(
    app: &Router,
    access_token: &str,
    organization_id: Uuid,
    item: &VaultItem,
    envelope: &EncryptedEnvelope,
    base_revision: Option<i64>,
) -> Result<EncryptedObject, Box<dyn Error>> {
    let response = put_organization_item_response(
        app,
        access_token,
        organization_id,
        item,
        envelope,
        base_revision,
    )
    .await?;
    assert_eq!(response.status, StatusCode::OK);
    Ok(decode(&response.body)?)
}

async fn put_organization_item_response(
    app: &Router,
    access_token: &str,
    organization_id: Uuid,
    item: &VaultItem,
    envelope: &EncryptedEnvelope,
    base_revision: Option<i64>,
) -> Result<TestResponse, Box<dyn Error>> {
    send_json(
        app,
        "PUT",
        &format!("/api/v1/vault/objects/{}", item.id),
        Some(access_token),
        &PutObjectRequest {
            kind: ObjectKind::Cipher,
            owner_type: OwnerType::Organization,
            owner_id: organization_id,
            collection_ids: item.collection_ids.clone(),
            format: envelope.format.clone(),
            wrapped_key: envelope.wrapped_key.clone(),
            payload: envelope.payload.clone(),
            base_revision,
            idempotency_key: Uuid::new_v4(),
        },
    )
    .await
}

#[allow(
    clippy::too_many_lines,
    reason = "ordered MFA lifecycle proves one-time and replay invariants against PostgreSQL"
)]
async fn exercise_account_security(app: &Router, pool: &PgPool) -> Result<(), Box<dyn Error>> {
    let email = format!("security-{}@example.test", Uuid::new_v4());
    let password = b"security integration master password";
    let kdf = KdfConfig::default();
    let master_key = derive_master_key(password, &email, &kdf)?;
    let stretched_master_key = master_key.stretch()?;
    let user_key = CompositeKey::generate()?;
    let protected_user_key = EncString::encrypt(user_key.as_bytes(), &stretched_master_key)?;
    let auth_proof = STANDARD.encode(master_key.authentication_proof(password));
    let first_device = DeviceRequest {
        identifier: Uuid::new_v4(),
        name: "Security settings browser".to_owned(),
        device_type: "test-browser".to_owned(),
    };
    let registered = send_json(
        app,
        "POST",
        "/api/v1/auth/register",
        None,
        &RegisterRequest {
            email: email.clone(),
            auth_proof: auth_proof.clone(),
            protected_user_key: protected_user_key.to_string(),
            kdf: KdfSettings::default(),
            device: first_device.clone(),
        },
    )
    .await?;
    assert_eq!(registered.status, StatusCode::CREATED);
    let registered: RegisterResponse = decode(&registered.body)?;
    let initial_login = send_json(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        &LoginRequest {
            email: email.clone(),
            auth_proof: auth_proof.clone(),
            device: first_device,
            totp_code: None,
            recovery_code: None,
            trusted_device_token: None,
            remember_device: false,
        },
    )
    .await?;
    assert_eq!(initial_login.status, StatusCode::OK);
    let initial_tokens: TokenResponse = decode(&initial_login.body)?;

    let setup = send_json(
        app,
        "POST",
        "/api/v1/account/security/totp/start",
        Some(&initial_tokens.access_token),
        &ReauthenticationRequest {
            auth_proof: auth_proof.clone(),
        },
    )
    .await?;
    assert_eq!(setup.status, StatusCode::OK);
    let setup: TotpSetupStartResponse = decode(&setup.body)?;
    assert!(setup.otpauth_uri.starts_with("otpauth://totp/"));
    let stored_setup = sqlx::query_scalar::<_, String>(
        "SELECT encrypted_secret FROM account_totp_setups WHERE account_id = $1",
    )
    .bind(registered.account_id)
    .fetch_one(pool)
    .await?;
    assert!(stored_setup.starts_with("mfa1."));
    assert!(!stored_setup.contains(&setup.secret));

    let setup_code = TotpConfig::parse(&setup.secret)?
        .generate_at(u64::try_from(chrono::Utc::now().timestamp())?)?;
    let enabled = send_json(
        app,
        "POST",
        "/api/v1/account/security/totp/finish",
        Some(&initial_tokens.access_token),
        &TotpSetupFinishRequest {
            setup_id: setup.setup_id,
            code: setup_code.code,
        },
    )
    .await?;
    assert_eq!(enabled.status, StatusCode::OK);
    let enabled: MfaEnableResponse = decode(&enabled.body)?;
    assert_eq!(enabled.recovery_codes.len(), 10);
    let stored_seed = sqlx::query_scalar::<_, String>(
        "SELECT encrypted_secret FROM account_totp WHERE account_id = $1",
    )
    .bind(registered.account_id)
    .fetch_one(pool)
    .await?;
    assert!(!stored_seed.contains(&setup.secret));

    let status = send_empty(
        app,
        "GET",
        "/api/v1/account/security",
        Some(&initial_tokens.access_token),
    )
    .await?;
    let status: MfaStatusResponse = decode(&status.body)?;
    assert!(status.totp_enabled);
    assert_eq!(status.recovery_codes_remaining, 10);

    let trusted_device = DeviceRequest {
        identifier: Uuid::new_v4(),
        name: "Remembered browser".to_owned(),
        device_type: "test-browser".to_owned(),
    };
    let missing_factor = send_json(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        &LoginRequest {
            email: email.clone(),
            auth_proof: auth_proof.clone(),
            device: trusted_device.clone(),
            totp_code: None,
            recovery_code: None,
            trusted_device_token: None,
            remember_device: false,
        },
    )
    .await?;
    assert_eq!(missing_factor.status, StatusCode::UNAUTHORIZED);
    let missing_error: ApiErrorBody = decode(&missing_factor.body)?;
    assert_eq!(missing_error.code, "mfa_required");

    let current_totp = TotpConfig::parse(&setup.secret)?
        .generate_at(u64::try_from(chrono::Utc::now().timestamp())?)?;
    let totp_login = send_json(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        &LoginRequest {
            email: email.clone(),
            auth_proof: auth_proof.clone(),
            device: trusted_device.clone(),
            totp_code: Some(current_totp.code.clone()),
            recovery_code: None,
            trusted_device_token: None,
            remember_device: true,
        },
    )
    .await?;
    assert_eq!(totp_login.status, StatusCode::OK);
    let totp_tokens: TokenResponse = decode(&totp_login.body)?;
    let trusted_token = totp_tokens
        .trusted_device_token
        .clone()
        .ok_or("trusted-device token was not returned")?;
    let stored_trust_hash =
        sqlx::query_scalar::<_, Vec<u8>>("SELECT trusted_token_hash FROM devices WHERE id = $1")
            .bind(totp_tokens.device_id)
            .fetch_one(pool)
            .await?;
    assert_eq!(stored_trust_hash.len(), 32);
    assert_ne!(stored_trust_hash, trusted_token.as_bytes());

    let replay = send_json(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        &LoginRequest {
            email: email.clone(),
            auth_proof: auth_proof.clone(),
            device: DeviceRequest {
                identifier: Uuid::new_v4(),
                name: "TOTP replay attempt".to_owned(),
                device_type: "test".to_owned(),
            },
            totp_code: Some(current_totp.code),
            recovery_code: None,
            trusted_device_token: None,
            remember_device: false,
        },
    )
    .await?;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);

    let trusted_login = send_json(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        &LoginRequest {
            email: email.clone(),
            auth_proof: auth_proof.clone(),
            device: trusted_device.clone(),
            totp_code: None,
            recovery_code: None,
            trusted_device_token: Some(trusted_token.clone()),
            remember_device: false,
        },
    )
    .await?;
    assert_eq!(trusted_login.status, StatusCode::OK);

    let revoked_trust = send_empty(
        app,
        "DELETE",
        &format!("/api/v1/account/devices/{}/trust", totp_tokens.device_id),
        Some(&totp_tokens.access_token),
    )
    .await?;
    assert_eq!(revoked_trust.status, StatusCode::NO_CONTENT);
    let revoked_trust_login = send_json(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        &LoginRequest {
            email: email.clone(),
            auth_proof: auth_proof.clone(),
            device: trusted_device,
            totp_code: None,
            recovery_code: None,
            trusted_device_token: Some(trusted_token),
            remember_device: false,
        },
    )
    .await?;
    assert_eq!(revoked_trust_login.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        decode::<ApiErrorBody>(&revoked_trust_login.body)?.code,
        "mfa_required"
    );

    let recovery_device = DeviceRequest {
        identifier: Uuid::new_v4(),
        name: "Recovery browser".to_owned(),
        device_type: "test".to_owned(),
    };
    let recovery_login = send_json(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        &LoginRequest {
            email: email.clone(),
            auth_proof: auth_proof.clone(),
            device: recovery_device.clone(),
            totp_code: None,
            recovery_code: Some(enabled.recovery_codes[0].clone()),
            trusted_device_token: None,
            remember_device: false,
        },
    )
    .await?;
    assert_eq!(recovery_login.status, StatusCode::OK);
    let recovery_replay = send_json(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        &LoginRequest {
            email: email.clone(),
            auth_proof: auth_proof.clone(),
            device: recovery_device,
            totp_code: None,
            recovery_code: Some(enabled.recovery_codes[0].clone()),
            trusted_device_token: None,
            remember_device: false,
        },
    )
    .await?;
    assert_eq!(recovery_replay.status, StatusCode::UNAUTHORIZED);

    let rotated = send_json(
        app,
        "POST",
        "/api/v1/account/security/recovery-codes/rotate",
        Some(&initial_tokens.access_token),
        &ReauthenticationRequest {
            auth_proof: auth_proof.clone(),
        },
    )
    .await?;
    assert_eq!(rotated.status, StatusCode::OK);
    let rotated: RecoveryCodesResponse = decode(&rotated.body)?;
    assert_eq!(rotated.codes.len(), 10);
    assert_ne!(rotated.codes, enabled.recovery_codes);
    let stored_recovery_hashes = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT code_hash FROM account_recovery_codes WHERE account_id = $1",
    )
    .bind(registered.account_id)
    .fetch_all(pool)
    .await?;
    assert_eq!(stored_recovery_hashes.len(), 10);
    for hash in stored_recovery_hashes {
        assert_eq!(hash.len(), 32);
        assert!(!rotated.codes.iter().any(|code| hash == code.as_bytes()));
    }

    let registration_start = send_json(
        app,
        "POST",
        "/api/v1/account/security/webauthn/start",
        Some(&initial_tokens.access_token),
        &WebauthnRegistrationStartRequest {
            auth_proof: auth_proof.clone(),
            name: "Integration passkey".to_owned(),
        },
    )
    .await?;
    assert_eq!(registration_start.status, StatusCode::OK);
    let registration_start: WebauthnChallengeResponse = decode(&registration_start.body)?;
    let creation_options: CreationChallengeResponse =
        serde_json::from_value(registration_start.options)?;
    let origin = Url::parse("http://localhost:8080")?;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let registration_credential =
        authenticator.do_registration(origin.clone(), creation_options)?;
    let registration_finish = WebauthnRegistrationFinishRequest {
        ceremony_id: registration_start.ceremony_id,
        credential: serde_json::to_value(&registration_credential)?,
    };
    let registered_passkey = send_json(
        app,
        "POST",
        "/api/v1/account/security/webauthn/finish",
        Some(&initial_tokens.access_token),
        &registration_finish,
    )
    .await?;
    assert_eq!(registered_passkey.status, StatusCode::OK);
    let passkey_enable: MfaEnableResponse = decode(&registered_passkey.body)?;
    assert!(passkey_enable.recovery_codes.is_empty());
    let registration_replay = send_json(
        app,
        "POST",
        "/api/v1/account/security/webauthn/finish",
        Some(&initial_tokens.access_token),
        &registration_finish,
    )
    .await?;
    assert_eq!(registration_replay.status, StatusCode::UNAUTHORIZED);

    let mfa_device = DeviceRequest {
        identifier: Uuid::new_v4(),
        name: "WebAuthn second-factor browser".to_owned(),
        device_type: "test".to_owned(),
    };
    let mfa_start = send_json(
        app,
        "POST",
        "/api/v1/auth/login/webauthn/start",
        None,
        &WebauthnMfaLoginStartRequest {
            email: email.clone(),
            auth_proof: auth_proof.clone(),
            device: mfa_device,
        },
    )
    .await?;
    assert_eq!(mfa_start.status, StatusCode::OK);
    let mfa_start: WebauthnChallengeResponse = decode(&mfa_start.body)?;
    let request_options: RequestChallengeResponse = serde_json::from_value(mfa_start.options)?;
    let assertion = authenticator.do_authentication(origin.clone(), request_options)?;
    let mfa_finish = WebauthnLoginFinishRequest {
        ceremony_id: mfa_start.ceremony_id,
        credential: serde_json::to_value(&assertion)?,
        remember_device: false,
    };
    let mfa_login = send_json(
        app,
        "POST",
        "/api/v1/auth/webauthn/finish",
        None,
        &mfa_finish,
    )
    .await?;
    assert_eq!(mfa_login.status, StatusCode::OK);
    let mfa_tokens: TokenResponse = decode(&mfa_login.body)?;
    assert_eq!(mfa_tokens.account_id, registered.account_id);
    let mfa_replay = send_json(
        app,
        "POST",
        "/api/v1/auth/webauthn/finish",
        None,
        &mfa_finish,
    )
    .await?;
    assert_eq!(mfa_replay.status, StatusCode::UNAUTHORIZED);

    let passkey_start = send_json(
        app,
        "POST",
        "/api/v1/auth/passkey/start",
        None,
        &PasskeyLoginStartRequest {
            email: email.clone(),
            device: DeviceRequest {
                identifier: Uuid::new_v4(),
                name: "Passwordless browser".to_owned(),
                device_type: "test".to_owned(),
            },
        },
    )
    .await?;
    assert_eq!(passkey_start.status, StatusCode::OK);
    let passkey_start: WebauthnChallengeResponse = decode(&passkey_start.body)?;
    let request_options: RequestChallengeResponse = serde_json::from_value(passkey_start.options)?;
    let assertion = authenticator.do_authentication(origin, request_options)?;
    let passkey_login = send_json(
        app,
        "POST",
        "/api/v1/auth/webauthn/finish",
        None,
        &WebauthnLoginFinishRequest {
            ceremony_id: passkey_start.ceremony_id,
            credential: serde_json::to_value(assertion)?,
            remember_device: false,
        },
    )
    .await?;
    assert_eq!(passkey_login.status, StatusCode::OK);
    let passkey_tokens: TokenResponse = decode(&passkey_login.body)?;
    assert_eq!(
        passkey_tokens.protected_user_key,
        protected_user_key.to_string()
    );

    let status = send_empty(
        app,
        "GET",
        "/api/v1/account/security",
        Some(&initial_tokens.access_token),
    )
    .await?;
    let status: MfaStatusResponse = decode(&status.body)?;
    assert_eq!(status.webauthn_credentials.len(), 1);
    let credential_id = status.webauthn_credentials[0].id;
    let deleted = send_empty(
        app,
        "DELETE",
        &format!("/api/v1/account/security/webauthn/{credential_id}"),
        Some(&initial_tokens.access_token),
    )
    .await?;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);

    let disabled = send_json(
        app,
        "DELETE",
        "/api/v1/account/security/totp",
        Some(&initial_tokens.access_token),
        &ReauthenticationRequest {
            auth_proof: auth_proof.clone(),
        },
    )
    .await?;
    assert_eq!(disabled.status, StatusCode::NO_CONTENT);
    let status = send_empty(
        app,
        "GET",
        "/api/v1/account/security",
        Some(&initial_tokens.access_token),
    )
    .await?;
    let status: MfaStatusResponse = decode(&status.body)?;
    assert!(!status.totp_enabled);
    assert!(status.webauthn_credentials.is_empty());
    assert_eq!(status.recovery_codes_remaining, 0);

    let password_only_again = send_json(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        &LoginRequest {
            email,
            auth_proof,
            device: DeviceRequest {
                identifier: Uuid::new_v4(),
                name: "Password-only after disable".to_owned(),
                device_type: "test".to_owned(),
            },
            totp_code: None,
            recovery_code: None,
            trusted_device_token: None,
            remember_device: false,
        },
    )
    .await?;
    assert_eq!(password_only_again.status, StatusCode::OK);
    Ok(())
}

fn test_config(database_url: String) -> Result<Config, Box<dyn Error>> {
    Ok(Config {
        database_url,
        bind: "127.0.0.1:0".parse::<SocketAddr>()?,
        public_url: Url::parse("http://localhost:8080")?,
        allowed_origins: vec!["http://localhost:8080".to_owned()].into(),
        token_pepper: Arc::new(TokenPepper::from_bytes([17; 32])),
        mfa_encryption_key: Arc::new(MfaEncryptionKey::from_bytes([29; 32])),
        webauthn_rp_id: "localhost".to_owned(),
        webauthn_origin: Url::parse("http://localhost:8080")?,
        webauthn_additional_origins: Arc::from([]),
        webauthn_rp_name: "Hasilan Pass test".to_owned(),
        production: false,
        access_token_ttl: Duration::from_mins(15),
        refresh_token_ttl: Duration::from_hours(24),
        trusted_device_ttl: Duration::from_hours(720),
        attachment_max_bytes: 64 * 1024 * 1024,
        invitation_delivery: InvitationDeliveryConfig::Manual,
    })
}

async fn reset_database(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("TRUNCATE accounts CASCADE")
        .execute(pool)
        .await?;
    Ok(())
}

async fn send_json<T: Serialize + ?Sized>(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    value: &T,
) -> Result<TestResponse, Box<dyn Error>> {
    let body = serde_json::to_vec(value)?;
    send_with_headers(
        app,
        method,
        uri,
        token,
        Body::from(body),
        true,
        &HeaderMap::new(),
    )
    .await
}

async fn send_json_with_headers<T: Serialize + ?Sized>(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    value: &T,
    headers: &HeaderMap,
) -> Result<TestResponse, Box<dyn Error>> {
    let body = serde_json::to_vec(value)?;
    send_with_headers(app, method, uri, token, Body::from(body), true, headers).await
}

async fn send_empty(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
) -> Result<TestResponse, Box<dyn Error>> {
    send_with_headers(
        app,
        method,
        uri,
        token,
        Body::empty(),
        false,
        &HeaderMap::new(),
    )
    .await
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Body,
    json: bool,
) -> Result<TestResponse, Box<dyn Error>> {
    send_with_headers(app, method, uri, token, body, json, &HeaderMap::new()).await
}

async fn send_with_headers(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Body,
    json: bool,
    extra_headers: &HeaderMap,
) -> Result<TestResponse, Box<dyn Error>> {
    let mut builder = Request::builder().method(method).uri(uri);
    if json {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    for (name, value) in extra_headers {
        builder = builder.header(name, value);
    }
    let response = app.clone().oneshot(builder.body(body)?).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), 4 * 1024 * 1024).await?;
    Ok(TestResponse {
        status,
        headers,
        body: body.to_vec(),
    })
}

fn response_cookie(headers: &HeaderMap, name: &str) -> Result<String, Box<dyn Error>> {
    for value in headers.get_all(header::SET_COOKIE) {
        let value = value.to_str()?;
        if let Some(cookie) = value.strip_prefix(&format!("{name}=")) {
            return cookie
                .split(';')
                .next()
                .map(str::to_owned)
                .ok_or_else(|| std::io::Error::other("Set-Cookie value is empty").into());
        }
    }
    Err(std::io::Error::other(format!("missing {name} cookie")).into())
}

fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, serde_json::Error> {
    serde_json::from_slice(body)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
