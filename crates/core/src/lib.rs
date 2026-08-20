//! Shared, non-secret primitives used throughout Hasilan Pass.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Current internal encrypted payload schema version.
pub const VAULT_SCHEMA_VERSION: u32 = 1;

/// Stable identifier for a vault object.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectId(pub Uuid);

impl ObjectId {
    /// Creates an unpredictable client-side identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ObjectId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for ObjectId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<ObjectId> for Uuid {
    fn from(value: ObjectId) -> Self {
        value.0
    }
}

/// Server-assigned optimistic-concurrency revision.
pub type Revision = i64;

/// UTC timestamp used by the domain and wire model.
pub type Timestamp = DateTime<Utc>;
