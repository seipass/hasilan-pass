//! Typed API client used by desktop and integration tests.

use hasilan_protocol::{
    ApiErrorBody, AttachmentCompleteRequest, AttachmentInitiateRequest, AttachmentResponse,
    CollectionAccessRequest, CollectionCreateRequest, CollectionResponse, CollectionUpdateRequest,
    DeleteObjectRequest, DeviceResponse, EncryptedObject, LoginRequest, LogoutRequest,
    MfaEnableResponse, MfaStatusResponse, OrganizationAcceptRequest, OrganizationCreateRequest,
    OrganizationInviteRequest, OrganizationInviteResponse, OrganizationMemberResponse,
    OrganizationMemberRoleRequest, OrganizationResponse, PasskeyLoginStartRequest, PreloginRequest,
    PreloginResponse, PutObjectRequest, ReauthenticationRequest, RecoveryCodesResponse,
    RefreshRequest, RegisterRequest, RegisterResponse, SessionResponse, SharingKeyRequest,
    SharingKeyResponse, SyncResponse, TokenResponse, TotpSetupFinishRequest,
    TotpSetupStartResponse, WebauthnChallengeResponse, WebauthnLoginFinishRequest,
    WebauthnMfaLoginStartRequest, WebauthnRegistrationFinishRequest,
    WebauthnRegistrationStartRequest,
};
use reqwest::{Method, StatusCode};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

/// API transport or server error.
#[derive(Debug, Error)]
pub enum ClientError {
    /// Server URL was not an absolute HTTP(S) URL.
    #[error("invalid server URL")]
    InvalidUrl,
    /// Plain HTTP is limited to loopback development servers.
    #[error("server URL must use HTTPS (HTTP is allowed only on loopback)")]
    InsecureUrl,
    /// DNS, TLS, transport, or response decoding failed.
    #[error("network request failed")]
    Network(#[from] reqwest::Error),
    /// The API returned a non-success status and machine-readable code.
    #[error("server returned {status}: {code}")]
    Api {
        /// HTTP response status.
        status: StatusCode,
        /// Stable API error code.
        code: String,
    },
}

/// Stateless typed client. Token persistence remains a platform responsibility.
#[derive(Clone)]
pub struct ApiClient {
    base_url: Url,
    http: reqwest::Client,
}

impl ApiClient {
    /// Builds a rustls-backed client for a server root URL.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidUrl`] for a non-HTTP(S) URL or a transport
    /// error if the HTTP client cannot be constructed.
    pub fn new(base_url: &str) -> Result<Self, ClientError> {
        let mut base_url = Url::parse(base_url).map_err(|_| ClientError::InvalidUrl)?;
        if !matches!(base_url.scheme(), "http" | "https") {
            return Err(ClientError::InvalidUrl);
        }
        if base_url.username() != ""
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || base_url.host_str().is_none()
        {
            return Err(ClientError::InvalidUrl);
        }
        if base_url.scheme() == "http" && !is_loopback(&base_url) {
            return Err(ClientError::InsecureUrl);
        }
        base_url.set_path("/");
        Ok(Self {
            base_url,
            http: reqwest::Client::builder().build()?,
        })
    }

    /// Fetches account KDF settings.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for transport, protocol, or API failures.
    pub async fn prelogin(
        &self,
        request: &PreloginRequest,
    ) -> Result<PreloginResponse, ClientError> {
        self.public(Method::POST, "api/v1/auth/prelogin", request)
            .await
    }

    /// Registers a zero-knowledge account.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for transport, protocol, or API failures.
    pub async fn register(
        &self,
        request: &RegisterRequest,
    ) -> Result<RegisterResponse, ClientError> {
        self.public(Method::POST, "api/v1/auth/register", request)
            .await
    }

    /// Authenticates a device.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for transport, protocol, or API failures.
    pub async fn login(&self, request: &LoginRequest) -> Result<TokenResponse, ClientError> {
        self.public(Method::POST, "api/v1/auth/login", request)
            .await
    }

    /// Begins password-plus-`WebAuthn` two-step login.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, protocol, or API failures.
    pub async fn start_webauthn_mfa_login(
        &self,
        request: &WebauthnMfaLoginStartRequest,
    ) -> Result<WebauthnChallengeResponse, ClientError> {
        self.public(Method::POST, "api/v1/auth/login/webauthn/start", request)
            .await
    }

    /// Begins account authentication using a registered passkey.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, protocol, or API failures.
    pub async fn start_passkey_login(
        &self,
        request: &PasskeyLoginStartRequest,
    ) -> Result<WebauthnChallengeResponse, ClientError> {
        self.public(Method::POST, "api/v1/auth/passkey/start", request)
            .await
    }

    /// Completes a passkey or password-plus-`WebAuthn` login.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, protocol, or API failures.
    pub async fn finish_webauthn_login(
        &self,
        request: &WebauthnLoginFinishRequest,
    ) -> Result<TokenResponse, ClientError> {
        self.public(Method::POST, "api/v1/auth/webauthn/finish", request)
            .await
    }

    /// Rotates a refresh token.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for transport, protocol, or API failures.
    pub async fn refresh(&self, refresh_token: String) -> Result<TokenResponse, ClientError> {
        self.public(
            Method::POST,
            "api/v1/auth/refresh",
            &RefreshRequest { refresh_token },
        )
        .await
    }

    /// Downloads an ordered encrypted sync page.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for transport, protocol, or API failures.
    pub async fn sync(
        &self,
        access_token: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<SyncResponse, ClientError> {
        let mut url = self.endpoint("api/v1/sync")?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("limit", &limit.to_string());
            if let Some(cursor) = cursor {
                query.append_pair("cursor", cursor);
            }
        }
        self.send(self.http.get(url).bearer_auth(access_token))
            .await
    }

    /// Creates or updates an opaque encrypted object.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for transport, protocol, or API failures.
    pub async fn put_object(
        &self,
        access_token: &str,
        id: Uuid,
        request: &PutObjectRequest,
    ) -> Result<EncryptedObject, ClientError> {
        let url = self.endpoint(&format!("api/v1/vault/objects/{id}"))?;
        self.send(self.http.put(url).bearer_auth(access_token).json(request))
            .await
    }

    /// Fetches one opaque encrypted object for conflict recovery.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for transport, protocol, or API failures.
    pub async fn get_object(
        &self,
        access_token: &str,
        id: Uuid,
    ) -> Result<EncryptedObject, ClientError> {
        let url = self.endpoint(&format!("api/v1/vault/objects/{id}"))?;
        self.send(self.http.get(url).bearer_auth(access_token))
            .await
    }

    /// Creates a tombstone for an encrypted object.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for transport, protocol, or API failures.
    pub async fn delete_object(
        &self,
        access_token: &str,
        id: Uuid,
        request: &DeleteObjectRequest,
    ) -> Result<EncryptedObject, ClientError> {
        let url = self.endpoint(&format!("api/v1/vault/objects/{id}"))?;
        self.send(
            self.http
                .delete(url)
                .bearer_auth(access_token)
                .json(request),
        )
        .await
    }

    /// Installs or idempotently returns the account's client-generated sharing key pair.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, validation, or API failures.
    pub async fn put_sharing_key(
        &self,
        access_token: &str,
        request: &SharingKeyRequest,
    ) -> Result<SharingKeyResponse, ClientError> {
        let url = self.endpoint("api/v1/account/sharing-key")?;
        self.send(self.http.put(url).bearer_auth(access_token).json(request))
            .await
    }

    /// Starts or resumes a chunked ciphertext attachment upload.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, authorization, revision, or validation failures.
    pub async fn initiate_attachment(
        &self,
        access_token: &str,
        request: &AttachmentInitiateRequest,
    ) -> Result<AttachmentResponse, ClientError> {
        let url = self.endpoint("api/v1/attachments")?;
        self.send(self.http.post(url).bearer_auth(access_token).json(request))
            .await
    }

    /// Loads resumable uploaded ranges for one attachment.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport or authorization failures.
    pub async fn attachment_status(
        &self,
        access_token: &str,
        id: Uuid,
    ) -> Result<AttachmentResponse, ClientError> {
        let url = self.endpoint(&format!("api/v1/attachments/{id}"))?;
        self.send(self.http.get(url).bearer_auth(access_token))
            .await
    }

    /// Lists complete attachments and the caller's resumable uploads for an item.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport or authorization failures.
    pub async fn attachments_for_object(
        &self,
        access_token: &str,
        object_id: Uuid,
    ) -> Result<Vec<AttachmentResponse>, ClientError> {
        let url = self.endpoint(&format!("api/v1/vault/objects/{object_id}/attachments"))?;
        self.send(self.http.get(url).bearer_auth(access_token))
            .await
    }

    /// Uploads one bounded encrypted frame idempotently.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, authorization, or conflicting chunk failures.
    pub async fn put_attachment_chunk(
        &self,
        access_token: &str,
        id: Uuid,
        index: u32,
        ciphertext: Vec<u8>,
    ) -> Result<(), ClientError> {
        let url = self.endpoint(&format!("api/v1/attachments/{id}/chunks/{index}"))?;
        self.send_empty(
            self.http
                .put(url)
                .bearer_auth(access_token)
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .body(ciphertext),
        )
        .await
    }

    /// Publishes a fully uploaded attachment after revalidating the parent revision.
    ///
    /// # Errors
    /// Returns [`ClientError`] for incomplete uploads, revision changes, or transport failures.
    pub async fn complete_attachment(
        &self,
        access_token: &str,
        id: Uuid,
        request: &AttachmentCompleteRequest,
    ) -> Result<AttachmentResponse, ClientError> {
        let url = self.endpoint(&format!("api/v1/attachments/{id}/complete"))?;
        self.send(self.http.post(url).bearer_auth(access_token).json(request))
            .await
    }

    /// Downloads one opaque independently authenticated frame.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport or authorization failures.
    pub async fn attachment_chunk(
        &self,
        access_token: &str,
        id: Uuid,
        index: u32,
    ) -> Result<Vec<u8>, ClientError> {
        let url = self.endpoint(&format!("api/v1/attachments/{id}/chunks/{index}"))?;
        self.send_bytes(self.http.get(url).bearer_auth(access_token))
            .await
    }

    /// Deletes all opaque chunks for one attachment after checking parent write access.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport or authorization failures.
    pub async fn delete_attachment(&self, access_token: &str, id: Uuid) -> Result<(), ClientError> {
        let url = self.endpoint(&format!("api/v1/attachments/{id}"))?;
        self.send_empty(self.http.delete(url).bearer_auth(access_token))
            .await
    }

    /// Loads the account's public key and user-key-encrypted private sharing key.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport or API failures.
    pub async fn sharing_key(&self, access_token: &str) -> Result<SharingKeyResponse, ClientError> {
        let url = self.endpoint("api/v1/account/sharing-key")?;
        self.send(self.http.get(url).bearer_auth(access_token))
            .await
    }

    /// Resolves an existing recipient's public sharing key.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, validation, or API failures.
    pub async fn lookup_sharing_key(
        &self,
        access_token: &str,
        email: &str,
    ) -> Result<SharingKeyResponse, ClientError> {
        let mut url = self.endpoint("api/v1/directory/sharing-key")?;
        url.query_pairs_mut().append_pair("email", email);
        self.send(self.http.get(url).bearer_auth(access_token))
            .await
    }

    /// Creates an organization with a recipient-bound wrapper for the owner.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, validation, or API failures.
    pub async fn create_organization(
        &self,
        access_token: &str,
        request: &OrganizationCreateRequest,
    ) -> Result<OrganizationResponse, ClientError> {
        let url = self.endpoint("api/v1/organizations")?;
        self.send(self.http.post(url).bearer_auth(access_token).json(request))
            .await
    }

    /// Lists active and pending organizations for the account.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport or API failures.
    pub async fn organizations(
        &self,
        access_token: &str,
    ) -> Result<Vec<OrganizationResponse>, ClientError> {
        let url = self.endpoint("api/v1/organizations")?;
        self.send(self.http.get(url).bearer_auth(access_token))
            .await
    }

    /// Invites an existing recipient with a client-sealed organization key.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, authorization, or API failures.
    pub async fn invite_organization_member(
        &self,
        access_token: &str,
        organization_id: Uuid,
        request: &OrganizationInviteRequest,
    ) -> Result<OrganizationInviteResponse, ClientError> {
        let url = self.endpoint(&format!(
            "api/v1/organizations/{organization_id}/invitations"
        ))?;
        self.send(self.http.post(url).bearer_auth(access_token).json(request))
            .await
    }

    /// Accepts an organization invitation for the current account.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, token, or API failures.
    pub async fn accept_organization_invitation(
        &self,
        access_token: &str,
        request: &OrganizationAcceptRequest,
    ) -> Result<OrganizationMemberResponse, ClientError> {
        let url = self.endpoint("api/v1/organizations/invitations/accept")?;
        self.send(self.http.post(url).bearer_auth(access_token).json(request))
            .await
    }

    /// Lists non-removed organization members.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, authorization, or API failures.
    pub async fn organization_members(
        &self,
        access_token: &str,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationMemberResponse>, ClientError> {
        let url = self.endpoint(&format!("api/v1/organizations/{organization_id}/members"))?;
        self.send(self.http.get(url).bearer_auth(access_token))
            .await
    }

    /// Confirms an accepted organization member.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, authorization, or API failures.
    pub async fn confirm_organization_member(
        &self,
        access_token: &str,
        organization_id: Uuid,
        member_id: Uuid,
    ) -> Result<OrganizationMemberResponse, ClientError> {
        let url = self.endpoint(&format!(
            "api/v1/organizations/{organization_id}/members/{member_id}/confirm"
        ))?;
        self.send(self.http.post(url).bearer_auth(access_token))
            .await
    }

    /// Changes a confirmed organization member's role.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, authorization, or API failures.
    pub async fn change_organization_member_role(
        &self,
        access_token: &str,
        organization_id: Uuid,
        member_id: Uuid,
        request: &OrganizationMemberRoleRequest,
    ) -> Result<OrganizationMemberResponse, ClientError> {
        let url = self.endpoint(&format!(
            "api/v1/organizations/{organization_id}/members/{member_id}/role"
        ))?;
        self.send(self.http.put(url).bearer_auth(access_token).json(request))
            .await
    }

    /// Removes an organization member and revokes their collection feed.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, authorization, or API failures.
    pub async fn remove_organization_member(
        &self,
        access_token: &str,
        organization_id: Uuid,
        member_id: Uuid,
    ) -> Result<(), ClientError> {
        let url = self.endpoint(&format!(
            "api/v1/organizations/{organization_id}/members/{member_id}"
        ))?;
        self.send_empty(self.http.delete(url).bearer_auth(access_token))
            .await
    }

    /// Creates an organization collection.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, authorization, or API failures.
    pub async fn create_collection(
        &self,
        access_token: &str,
        organization_id: Uuid,
        request: &CollectionCreateRequest,
    ) -> Result<CollectionResponse, ClientError> {
        let url = self.endpoint(&format!(
            "api/v1/organizations/{organization_id}/collections"
        ))?;
        self.send(self.http.post(url).bearer_auth(access_token).json(request))
            .await
    }

    /// Lists collections visible to the current organization member.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, authorization, or API failures.
    pub async fn collections(
        &self,
        access_token: &str,
        organization_id: Uuid,
    ) -> Result<Vec<CollectionResponse>, ClientError> {
        let url = self.endpoint(&format!(
            "api/v1/organizations/{organization_id}/collections"
        ))?;
        self.send(self.http.get(url).bearer_auth(access_token))
            .await
    }

    /// Renames an organization collection.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, authorization, or API failures.
    pub async fn update_collection(
        &self,
        access_token: &str,
        organization_id: Uuid,
        collection_id: Uuid,
        request: &CollectionUpdateRequest,
    ) -> Result<CollectionResponse, ClientError> {
        let url = self.endpoint(&format!(
            "api/v1/organizations/{organization_id}/collections/{collection_id}"
        ))?;
        self.send(self.http.put(url).bearer_auth(access_token).json(request))
            .await
    }

    /// Grants or replaces a member's collection permissions.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, authorization, or API failures.
    pub async fn put_collection_access(
        &self,
        access_token: &str,
        organization_id: Uuid,
        collection_id: Uuid,
        request: &CollectionAccessRequest,
    ) -> Result<(), ClientError> {
        let url = self.endpoint(&format!(
            "api/v1/organizations/{organization_id}/collections/{collection_id}/access/{}",
            request.member_id
        ))?;
        self.send_empty(self.http.put(url).bearer_auth(access_token).json(request))
            .await
    }

    /// Revokes a member's collection permissions.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, authorization, or API failures.
    pub async fn delete_collection_access(
        &self,
        access_token: &str,
        organization_id: Uuid,
        collection_id: Uuid,
        member_id: Uuid,
    ) -> Result<(), ClientError> {
        let url = self.endpoint(&format!(
            "api/v1/organizations/{organization_id}/collections/{collection_id}/access/{member_id}"
        ))?;
        self.send_empty(self.http.delete(url).bearer_auth(access_token))
            .await
    }

    /// Lists sessions for account security UI.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for transport, protocol, or API failures.
    pub async fn sessions(&self, access_token: &str) -> Result<Vec<SessionResponse>, ClientError> {
        let url = self.endpoint("api/v1/account/sessions")?;
        self.send(self.http.get(url).bearer_auth(access_token))
            .await
    }

    /// Lists devices associated with the account.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for transport, protocol, or API failures.
    pub async fn devices(&self, access_token: &str) -> Result<Vec<DeviceResponse>, ClientError> {
        let url = self.endpoint("api/v1/account/devices")?;
        self.send(self.http.get(url).bearer_auth(access_token))
            .await
    }

    /// Loads non-secret MFA posture and registered credential metadata.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, protocol, or API failures.
    pub async fn account_security(
        &self,
        access_token: &str,
    ) -> Result<MfaStatusResponse, ClientError> {
        let url = self.endpoint("api/v1/account/security")?;
        self.send(self.http.get(url).bearer_auth(access_token))
            .await
    }

    /// Starts TOTP enrollment after password-proof reauthentication.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, protocol, or API failures.
    pub async fn start_totp_setup(
        &self,
        access_token: &str,
        request: &ReauthenticationRequest,
    ) -> Result<TotpSetupStartResponse, ClientError> {
        let url = self.endpoint("api/v1/account/security/totp/start")?;
        self.send(self.http.post(url).bearer_auth(access_token).json(request))
            .await
    }

    /// Confirms a pending TOTP enrollment and returns newly created recovery codes.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, protocol, or API failures.
    pub async fn finish_totp_setup(
        &self,
        access_token: &str,
        request: &TotpSetupFinishRequest,
    ) -> Result<MfaEnableResponse, ClientError> {
        let url = self.endpoint("api/v1/account/security/totp/finish")?;
        self.send(self.http.post(url).bearer_auth(access_token).json(request))
            .await
    }

    /// Disables TOTP after password-proof reauthentication.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport or API failures.
    pub async fn disable_totp(
        &self,
        access_token: &str,
        request: &ReauthenticationRequest,
    ) -> Result<(), ClientError> {
        let url = self.endpoint("api/v1/account/security/totp")?;
        self.send_empty(
            self.http
                .delete(url)
                .bearer_auth(access_token)
                .json(request),
        )
        .await
    }

    /// Invalidates all recovery codes and returns a fresh one-time set.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, protocol, or API failures.
    pub async fn rotate_recovery_codes(
        &self,
        access_token: &str,
        request: &ReauthenticationRequest,
    ) -> Result<RecoveryCodesResponse, ClientError> {
        let url = self.endpoint("api/v1/account/security/recovery-codes/rotate")?;
        self.send(self.http.post(url).bearer_auth(access_token).json(request))
            .await
    }

    /// Starts account `WebAuthn` credential registration.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, protocol, or API failures.
    pub async fn start_webauthn_registration(
        &self,
        access_token: &str,
        request: &WebauthnRegistrationStartRequest,
    ) -> Result<WebauthnChallengeResponse, ClientError> {
        let url = self.endpoint("api/v1/account/security/webauthn/start")?;
        self.send(self.http.post(url).bearer_auth(access_token).json(request))
            .await
    }

    /// Finishes account `WebAuthn` credential registration.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport, protocol, or API failures.
    pub async fn finish_webauthn_registration(
        &self,
        access_token: &str,
        request: &WebauthnRegistrationFinishRequest,
    ) -> Result<MfaEnableResponse, ClientError> {
        let url = self.endpoint("api/v1/account/security/webauthn/finish")?;
        self.send(self.http.post(url).bearer_auth(access_token).json(request))
            .await
    }

    /// Removes an account `WebAuthn` credential.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport or API failures.
    pub async fn delete_webauthn_credential(
        &self,
        access_token: &str,
        credential_id: Uuid,
    ) -> Result<(), ClientError> {
        let url = self.endpoint(&format!("api/v1/account/security/webauthn/{credential_id}"))?;
        self.send_empty(self.http.delete(url).bearer_auth(access_token))
            .await
    }

    /// Revokes a device's persistent MFA bypass grant.
    ///
    /// # Errors
    /// Returns [`ClientError`] for transport or API failures.
    pub async fn revoke_device_trust(
        &self,
        access_token: &str,
        device_id: Uuid,
    ) -> Result<(), ClientError> {
        let url = self.endpoint(&format!("api/v1/account/devices/{device_id}/trust"))?;
        self.send_empty(self.http.delete(url).bearer_auth(access_token))
            .await
    }

    /// Revokes one account session.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for transport or API failures.
    pub async fn revoke_session(
        &self,
        access_token: &str,
        session_id: Uuid,
    ) -> Result<(), ClientError> {
        let url = self.endpoint(&format!("api/v1/account/sessions/{session_id}"))?;
        self.send_empty(self.http.delete(url).bearer_auth(access_token))
            .await
    }

    /// Revokes the current session and refresh-token family.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for transport or API failures.
    pub async fn logout(
        &self,
        access_token: &str,
        refresh_token: Option<String>,
    ) -> Result<(), ClientError> {
        let url = self.endpoint("api/v1/auth/logout")?;
        self.send_empty(
            self.http
                .post(url)
                .bearer_auth(access_token)
                .json(&LogoutRequest { refresh_token }),
        )
        .await
    }

    async fn public<B, R>(&self, method: Method, path: &str, body: &B) -> Result<R, ClientError>
    where
        B: serde::Serialize + ?Sized,
        R: serde::de::DeserializeOwned,
    {
        let url = self.endpoint(path)?;
        self.send(self.http.request(method, url).json(body)).await
    }

    async fn send<R>(&self, request: reqwest::RequestBuilder) -> Result<R, ClientError>
    where
        R: serde::de::DeserializeOwned,
    {
        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let code = response
                .json::<ApiErrorBody>()
                .await
                .map_or_else(|_| "invalid_error_response".to_owned(), |error| error.code);
            return Err(ClientError::Api { status, code });
        }
        Ok(response.json().await?)
    }

    async fn send_empty(&self, request: reqwest::RequestBuilder) -> Result<(), ClientError> {
        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let code = response
                .json::<ApiErrorBody>()
                .await
                .map_or_else(|_| "invalid_error_response".to_owned(), |error| error.code);
            return Err(ClientError::Api { status, code });
        }
        Ok(())
    }

    async fn send_bytes(&self, request: reqwest::RequestBuilder) -> Result<Vec<u8>, ClientError> {
        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let code = response
                .json::<ApiErrorBody>()
                .await
                .map_or_else(|_| "invalid_error_response".to_owned(), |error| error.code);
            return Err(ClientError::Api { status, code });
        }
        Ok(response.bytes().await?.to_vec())
    }

    fn endpoint(&self, path: &str) -> Result<Url, ClientError> {
        self.base_url
            .join(path)
            .map_err(|_| ClientError::InvalidUrl)
    }
}

fn is_loopback(url: &Url) -> bool {
    matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_url_policy_accepts_https_and_loopback_only() {
        assert!(ApiClient::new("https://vault.example.test/base").is_ok());
        assert!(ApiClient::new("http://localhost:8080").is_ok());
        assert!(ApiClient::new("http://127.0.0.1:8080").is_ok());
        assert!(ApiClient::new("http://[::1]:8080").is_ok());
        assert!(matches!(
            ApiClient::new("http://vault.example.test"),
            Err(ClientError::InsecureUrl)
        ));
    }

    #[test]
    fn server_url_policy_rejects_ambiguous_or_secret_bearing_urls() {
        for input in [
            "file:///tmp/socket",
            "https://user:password@vault.example.test",
            "https://vault.example.test?token=secret",
            "https://vault.example.test/#fragment",
        ] {
            assert!(ApiClient::new(input).is_err(), "accepted {input}");
        }
    }
}
