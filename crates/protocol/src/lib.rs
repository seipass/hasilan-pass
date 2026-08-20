//! Stable request and response structures for `/api/v1`.
#![allow(
    missing_docs,
    reason = "wire DTO fields are documented by their containing type and generated OpenAPI schema"
)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// Machine-readable API error body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiErrorBody {
    pub code: String,
    pub message: String,
    pub request_id: Option<String>,
}

/// KDF selection exposed during prelogin.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum KdfType {
    Pbkdf2,
    Argon2id,
}

/// Account KDF settings. Memory is expressed in MiB.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct KdfSettings {
    pub kdf_type: KdfType,
    pub iterations: u32,
    pub memory_mib: Option<u32>,
    pub parallelism: Option<u32>,
}

impl Default for KdfSettings {
    fn default() -> Self {
        Self {
            kdf_type: KdfType::Argon2id,
            iterations: 6,
            memory_mib: Some(32),
            parallelism: Some(4),
        }
    }
}

/// Request account-specific KDF data before transmitting an authentication proof.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PreloginRequest {
    pub email: String,
}

/// Prelogin result. Unknown accounts receive policy defaults to resist enumeration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    pub kdf: KdfSettings,
}

/// Client device registration metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRequest {
    pub identifier: Uuid,
    pub name: String,
    pub device_type: String,
}

/// Zero-knowledge registration payload.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub email: String,
    /// Base64-encoded client-derived server authorization proof.
    pub auth_proof: String,
    /// User key wrapped by the password-derived master key.
    pub protected_user_key: String,
    pub kdf: KdfSettings,
    pub device: DeviceRequest,
}

/// Registration result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResponse {
    pub account_id: Uuid,
}

/// Password-proof login payload.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub email: String,
    pub auth_proof: String,
    pub device: DeviceRequest,
    pub totp_code: Option<String>,
    pub recovery_code: Option<String>,
    /// Opaque secret previously issued after a successful second-factor check.
    #[serde(default)]
    pub trusted_device_token: Option<String>,
    /// Issue or rotate a 30-day trusted-device token after full MFA succeeds.
    #[serde(default)]
    pub remember_device: bool,
}

/// Successful authentication and client-side unlock material.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TokenResponse {
    pub account_id: Uuid,
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub protected_user_key: String,
    pub kdf: KdfSettings,
    pub session_id: Uuid,
    pub device_id: Uuid,
    /// Returned only when this response creates or rotates device trust.
    pub trusted_device_token: Option<String>,
}

/// Account-level second-factor kinds. Vault-item TOTP is unrelated to this list.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum MfaMethod {
    Totp,
    RecoveryCode,
    Webauthn,
}

/// Password-proof confirmation for a security-sensitive account change.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReauthenticationRequest {
    pub auth_proof: String,
}

/// Starts authenticator-app enrollment after password reauthentication.
pub type TotpSetupStartRequest = ReauthenticationRequest;

/// One-time authenticator-app setup material. The response is never cacheable.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TotpSetupStartResponse {
    pub setup_id: Uuid,
    pub secret: String,
    pub otpauth_uri: String,
    pub expires_at: DateTime<Utc>,
}

/// Confirms possession of a pending authenticator-app seed.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TotpSetupFinishRequest {
    pub setup_id: Uuid,
    pub code: String,
}

/// Recovery codes shown exactly once when created or rotated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryCodesResponse {
    pub codes: Vec<String>,
}

/// Result of enabling a new second factor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MfaEnableResponse {
    /// Populated only when the account had no recovery codes before this operation.
    pub recovery_codes: Vec<String>,
}

/// Starts registration of an account `WebAuthn` credential.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebauthnRegistrationStartRequest {
    pub auth_proof: String,
    pub name: String,
}

/// Server-generated, expiring `WebAuthn` options and their opaque ceremony handle.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebauthnChallengeResponse {
    pub ceremony_id: Uuid,
    /// A standards-shaped `PublicKeyCredential*Options` JSON object.
    pub options: Value,
    pub expires_at: DateTime<Utc>,
}

/// Completes account `WebAuthn` credential registration.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebauthnRegistrationFinishRequest {
    pub ceremony_id: Uuid,
    /// Browser `PublicKeyCredential` encoded with base64url binary members.
    pub credential: Value,
}

/// Starts password-plus-WebAuthn two-step login.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebauthnMfaLoginStartRequest {
    pub email: String,
    pub auth_proof: String,
    pub device: DeviceRequest,
}

/// Starts account authentication with an already registered passkey.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyLoginStartRequest {
    pub email: String,
    pub device: DeviceRequest,
}

/// Completes either a passkey login or password-plus-WebAuthn login ceremony.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebauthnLoginFinishRequest {
    pub ceremony_id: Uuid,
    pub credential: Value,
    #[serde(default)]
    pub remember_device: bool,
}

/// Non-secret metadata for a registered account passkey/security key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebauthnCredentialResponse {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Current account-security posture for settings clients.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MfaStatusResponse {
    pub totp_enabled: bool,
    pub recovery_codes_remaining: u32,
    pub webauthn_credentials: Vec<WebauthnCredentialResponse>,
}

/// Refresh-token rotation request.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// Logout request (access-token authentication is also required).
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LogoutRequest {
    pub refresh_token: Option<String>,
}

/// Authenticated device metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeviceResponse {
    pub id: Uuid,
    pub identifier: Uuid,
    pub name: String,
    pub device_type: String,
    pub trusted: bool,
    pub trusted_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

/// Revocable authenticated session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    pub id: Uuid,
    pub device_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub current: bool,
}

/// Public owner-routing type. Secret ownership is repeated inside ciphertext.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum OwnerType {
    User,
    Organization,
}

/// Opaque synchronized object category.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum ObjectKind {
    Cipher,
    Folder,
    OrganizationKey,
}

/// Server-visible metadata and opaque client ciphertext.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedObject {
    pub id: Uuid,
    pub kind: ObjectKind,
    pub owner_type: OwnerType,
    pub owner_id: Uuid,
    #[serde(default)]
    pub collection_ids: Vec<Uuid>,
    pub format: String,
    pub wrapped_key: String,
    pub payload: String,
    pub object_revision: i64,
    pub account_revision: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Idempotent encrypted object create/update body.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PutObjectRequest {
    pub kind: ObjectKind,
    pub owner_type: OwnerType,
    pub owner_id: Uuid,
    #[serde(default)]
    pub collection_ids: Vec<Uuid>,
    pub format: String,
    pub wrapped_key: String,
    pub payload: String,
    /// `None` creates; `Some` requires an exact optimistic revision.
    pub base_revision: Option<i64>,
    pub idempotency_key: Uuid,
}

/// Idempotent delete body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeleteObjectRequest {
    pub base_revision: i64,
    pub idempotency_key: Uuid,
}

/// Starts or resumes an opaque chunked attachment upload for an existing vault object.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentInitiateRequest {
    pub id: Uuid,
    pub object_id: Uuid,
    /// Current parent revision used to reject stale or deleted object references.
    pub object_revision: i64,
    pub format: String,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub ciphertext_size: u64,
}

/// Revalidates the parent revision before making all uploaded chunks downloadable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentCompleteRequest {
    pub object_revision: i64,
}

/// Lifecycle state of an opaque attachment upload.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum AttachmentState {
    Uploading,
    Complete,
}

/// Half-open contiguous range of uploaded chunk indices.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentChunkRange {
    pub start: u32,
    pub end_exclusive: u32,
}

/// Server-visible dimensions and resumable progress; private file metadata stays in the item.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentResponse {
    pub id: Uuid,
    pub object_id: Uuid,
    pub object_revision: i64,
    pub format: String,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub ciphertext_size: u64,
    pub state: AttachmentState,
    pub uploaded_ranges: Vec<AttachmentChunkRange>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Change-feed operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum ChangeOperation {
    Upsert,
    Delete,
}

/// One ordered synchronization change.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SyncChange {
    pub revision: i64,
    pub operation: ChangeOperation,
    pub object_id: Uuid,
    pub object: Option<EncryptedObject>,
}

/// Cursor-based synchronization page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub changes: Vec<SyncChange>,
    pub next_cursor: String,
    pub has_more: bool,
}

/// Optimistic conflict response retains the authoritative encrypted object.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConflictResponse {
    pub code: String,
    pub current: EncryptedObject,
}

/// Health response shared by liveness/readiness routes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub database: Option<String>,
}

/// Structured security-event response; details are guaranteed secret-free.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecurityEventResponse {
    pub id: Uuid,
    pub event_type: String,
    pub occurred_at: DateTime<Utc>,
    pub device_id: Option<Uuid>,
    pub details: Value,
}

/// Organization membership role ordered from most to least privileged.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum OrganizationRole {
    Owner,
    Admin,
    Manager,
    User,
}

/// Invitation/confirmation state for an organization member.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum MembershipStatus {
    Invited,
    Accepted,
    Confirmed,
    Removed,
}

/// Installs an account public key and its user-key-encrypted private counterpart.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SharingKeyRequest {
    pub public_key: String,
    pub protected_private_key: String,
}

/// Account sharing-key material. The private key remains client encrypted.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SharingKeyResponse {
    pub account_id: Uuid,
    pub public_key: String,
    pub protected_private_key: Option<String>,
}

/// Creates an organization and the owner's encrypted organization-key wrapper.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationCreateRequest {
    /// Client-generated ID, allowing the key wrapper to bind to the organization.
    pub id: Uuid,
    pub name: String,
    pub encrypted_organization_key: String,
}

/// Organization metadata and the caller's membership/key wrapper.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationResponse {
    pub id: Uuid,
    pub member_id: Uuid,
    pub name: String,
    pub role: OrganizationRole,
    pub status: MembershipStatus,
    pub encrypted_organization_key: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Invites an existing account after encrypting the organization key to its public key.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationInviteRequest {
    pub email: String,
    pub role: OrganizationRole,
    pub encrypted_organization_key: String,
}

/// Configured adapter used to deliver an organization invitation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum InvitationDeliveryKind {
    /// The authorized administrator must deliver the returned token out of band.
    Manual,
    /// The server submitted the token to its TLS-only SMTP relay.
    Smtp,
}

/// Invitation result. SMTP mode deliberately withholds the bearer token from the caller.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationInviteResponse {
    pub member_id: Uuid,
    pub invitation_token: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub delivery: InvitationDeliveryKind,
}

/// Accepts an invitation using its high-entropy bearer token.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationAcceptRequest {
    pub invitation_token: String,
}

/// Server-visible member metadata; key wrappers remain opaque.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationMemberResponse {
    pub id: Uuid,
    pub account_id: Option<Uuid>,
    pub email: String,
    pub role: OrganizationRole,
    pub status: MembershipStatus,
    pub encrypted_organization_key: Option<String>,
    pub invited_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub confirmed_at: Option<DateTime<Utc>>,
}

/// Changes a confirmed member's organization role.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationMemberRoleRequest {
    pub role: OrganizationRole,
}

/// Creates a collection within an organization.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CollectionCreateRequest {
    pub name: String,
}

/// Renames a collection without touching its encrypted vault contents.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CollectionUpdateRequest {
    pub name: String,
}

/// Collection metadata plus the caller's effective permissions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CollectionResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
    pub created_at: DateTime<Utc>,
}

/// Grants or replaces one member's collection access.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CollectionAccessRequest {
    pub member_id: Uuid,
    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
}
