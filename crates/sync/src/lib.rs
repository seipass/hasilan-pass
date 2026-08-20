//! Deterministic client replica and conflict handling.

use std::collections::{BTreeMap, VecDeque};

use hasilan_protocol::{EncryptedObject, SyncChange, SyncResponse};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// A durable client mutation whose payload is already encrypted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingMutation {
    /// Full locally encrypted object to upload or tombstone.
    pub object: EncryptedObject,
    /// Optimistic server revision, or `None` for a create.
    pub base_revision: Option<i64>,
    /// Stable retry key persisted before network I/O.
    pub idempotency_key: Uuid,
    /// Whether this mutation creates a tombstone.
    pub delete: bool,
}

/// Both encrypted versions of an optimistic-concurrency conflict.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Conflict {
    /// Identity shared by both versions.
    pub object_id: Uuid,
    /// Unsynchronized local encrypted mutation.
    pub local: PendingMutation,
    /// Authoritative encrypted server version.
    pub server: EncryptedObject,
}

/// Persistent encrypted replica state. No decrypted vault fields belong here.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Replica {
    #[serde(default)]
    objects: BTreeMap<Uuid, EncryptedObject>,
    #[serde(default)]
    outbox: VecDeque<PendingMutation>,
    #[serde(default)]
    conflicts: BTreeMap<Uuid, Conflict>,
    cursor: Option<String>,
    last_revision: i64,
}

/// Invalid or unsafe synchronization transition.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum SyncError {
    /// A page repeated or reordered an account revision.
    #[error("sync revisions are not strictly increasing")]
    RevisionOrder,
    /// An upsert change did not carry its encrypted object snapshot.
    #[error("sync change omitted an upsert object")]
    MissingObject,
    /// Change metadata disagrees with its object snapshot.
    #[error("sync object identity/revision is inconsistent")]
    InconsistentObject,
    /// The server acknowledged a key not present in the durable outbox.
    #[error("cannot acknowledge an unknown idempotency key")]
    UnknownMutation,
}

impl Replica {
    /// Returns the opaque cursor committed with local cache state.
    #[must_use]
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    /// Returns the encrypted object cache.
    #[must_use]
    pub fn objects(&self) -> &BTreeMap<Uuid, EncryptedObject> {
        &self.objects
    }

    /// Returns durable pending work in upload order.
    #[must_use]
    pub fn outbox(&self) -> &VecDeque<PendingMutation> {
        &self.outbox
    }

    /// Returns unresolved conflicts without discarding either version.
    #[must_use]
    pub fn conflicts(&self) -> &BTreeMap<Uuid, Conflict> {
        &self.conflicts
    }

    /// Returns the highest account revision durably applied to this replica.
    #[must_use]
    pub fn last_revision(&self) -> i64 {
        self.last_revision
    }

    /// Enqueues an encrypted mutation before any network request is made.
    pub fn enqueue(&mut self, mutation: PendingMutation) {
        self.outbox
            .retain(|pending| pending.object.id != mutation.object.id);
        self.outbox.push_back(mutation);
    }

    /// Discards an object that has never reached the server and its queued work.
    pub fn discard_local(&mut self, object_id: Uuid) {
        self.outbox.retain(|pending| pending.object.id != object_id);
        self.conflicts.remove(&object_id);
    }

    /// Records an authoritative version observed during an upload race without advancing
    /// the pull cursor. The next ordered feed page will commit its revision normally.
    pub fn record_upload_conflict(&mut self, server: EncryptedObject) {
        self.mark_stale_pending_as_conflict(&server);
        self.objects.insert(server.id, server);
    }

    /// Keeps the authoritative server version and discards a conflicting local mutation.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::UnknownMutation`] if `object_id` is not conflicted.
    pub fn resolve_with_server(&mut self, object_id: Uuid) -> Result<(), SyncError> {
        let conflict = self
            .conflicts
            .remove(&object_id)
            .ok_or(SyncError::UnknownMutation)?;
        self.outbox.retain(|pending| pending.object.id != object_id);
        self.objects.insert(object_id, conflict.server);
        Ok(())
    }

    /// Rebases the encrypted local version onto the current server revision for retry.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::UnknownMutation`] if `object_id` is not conflicted.
    pub fn resolve_with_local(&mut self, object_id: Uuid) -> Result<(), SyncError> {
        let conflict = self
            .conflicts
            .remove(&object_id)
            .ok_or(SyncError::UnknownMutation)?;
        let pending = self
            .outbox
            .iter_mut()
            .find(|pending| pending.object.id == object_id)
            .ok_or(SyncError::UnknownMutation)?;
        pending.base_revision = Some(conflict.server.object_revision);
        pending.idempotency_key = Uuid::new_v4();
        Ok(())
    }

    /// Atomically validates and applies a pull page to a cloned state, then commits it.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError`] without mutating the replica if any change is invalid.
    pub fn apply_page(&mut self, page: &SyncResponse) -> Result<(), SyncError> {
        let mut next = self.clone();
        for change in &page.changes {
            next.apply_change(change)?;
        }
        next.cursor = Some(page.next_cursor.clone());
        *self = next;
        Ok(())
    }

    fn apply_change(&mut self, change: &SyncChange) -> Result<(), SyncError> {
        if change.revision <= self.last_revision {
            return Err(SyncError::RevisionOrder);
        }
        match change.operation {
            hasilan_protocol::ChangeOperation::Upsert => {
                let object = change.object.clone().ok_or(SyncError::MissingObject)?;
                if object.id != change.object_id || object.account_revision != change.revision {
                    return Err(SyncError::InconsistentObject);
                }
                self.mark_stale_pending_as_conflict(&object);
                self.objects.insert(object.id, object);
            }
            hasilan_protocol::ChangeOperation::Delete => {
                if let Some(object) = &change.object {
                    if object.id != change.object_id || object.account_revision != change.revision {
                        return Err(SyncError::InconsistentObject);
                    }
                    self.mark_stale_pending_as_conflict(object);
                    self.objects.insert(object.id, object.clone());
                } else {
                    self.objects.remove(&change.object_id);
                }
            }
        }
        self.last_revision = change.revision;
        Ok(())
    }

    fn mark_stale_pending_as_conflict(&mut self, server: &EncryptedObject) {
        if let Some(local) = self
            .outbox
            .iter()
            .find(|mutation| mutation.object.id == server.id)
            .filter(|mutation| mutation.base_revision != Some(server.object_revision))
            .cloned()
        {
            self.conflicts.insert(
                server.id,
                Conflict {
                    object_id: server.id,
                    local,
                    server: server.clone(),
                },
            );
        }
    }

    /// Removes a mutation only after the authoritative response is durably cached.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::UnknownMutation`] if the durable outbox does not
    /// contain `idempotency_key`.
    pub fn acknowledge(
        &mut self,
        idempotency_key: Uuid,
        authoritative: EncryptedObject,
    ) -> Result<(), SyncError> {
        let index = self
            .outbox
            .iter()
            .position(|entry| entry.idempotency_key == idempotency_key)
            .ok_or(SyncError::UnknownMutation)?;
        let object_id = authoritative.id;
        self.objects.insert(object_id, authoritative);
        self.outbox.remove(index);
        self.conflicts.remove(&object_id);
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test assertions intentionally fail fast"
)]
mod tests {
    use chrono::Utc;
    use hasilan_protocol::{ChangeOperation, ObjectKind, OwnerType};

    use super::*;

    fn object(id: Uuid, object_revision: i64, account_revision: i64) -> EncryptedObject {
        EncryptedObject {
            id,
            kind: ObjectKind::Cipher,
            owner_type: OwnerType::User,
            owner_id: Uuid::nil(),
            collection_ids: Vec::new(),
            format: "hp.v1".to_owned(),
            wrapped_key: "ciphertext".to_owned(),
            payload: "ciphertext".to_owned(),
            object_revision,
            account_revision,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        }
    }

    #[test]
    fn failed_page_is_atomic() {
        let id = Uuid::new_v4();
        let mut replica = Replica::default();
        let page = SyncResponse {
            changes: vec![
                SyncChange {
                    revision: 1,
                    operation: ChangeOperation::Upsert,
                    object_id: id,
                    object: Some(object(id, 1, 1)),
                },
                SyncChange {
                    revision: 1,
                    operation: ChangeOperation::Delete,
                    object_id: id,
                    object: None,
                },
            ],
            next_cursor: "cursor".to_owned(),
            has_more: false,
        };
        assert_eq!(replica.apply_page(&page), Err(SyncError::RevisionOrder));
        assert!(replica.objects().is_empty());
        assert!(replica.cursor().is_none());
    }

    #[test]
    fn concurrent_server_change_preserves_local_version_as_conflict() {
        let id = Uuid::new_v4();
        let mut replica = Replica::default();
        replica.enqueue(PendingMutation {
            object: object(id, 1, 0),
            base_revision: Some(1),
            idempotency_key: Uuid::new_v4(),
            delete: false,
        });
        replica
            .apply_page(&SyncResponse {
                changes: vec![SyncChange {
                    revision: 2,
                    operation: ChangeOperation::Upsert,
                    object_id: id,
                    object: Some(object(id, 2, 2)),
                }],
                next_cursor: "two".to_owned(),
                has_more: false,
            })
            .unwrap();
        assert!(replica.conflicts().contains_key(&id));
        assert_eq!(replica.outbox().len(), 1);
    }

    #[test]
    fn newest_local_mutation_replaces_older_work_for_the_same_object() {
        let id = Uuid::new_v4();
        let mut replica = Replica::default();
        replica.enqueue(PendingMutation {
            object: object(id, 0, 0),
            base_revision: None,
            idempotency_key: Uuid::new_v4(),
            delete: false,
        });
        let latest_key = Uuid::new_v4();
        replica.enqueue(PendingMutation {
            object: object(id, 0, 0),
            base_revision: None,
            idempotency_key: latest_key,
            delete: false,
        });
        assert_eq!(replica.outbox().len(), 1);
        assert_eq!(replica.outbox()[0].idempotency_key, latest_key);
    }

    #[test]
    fn conflict_can_be_rebased_or_discarded_without_losing_both_versions() {
        let id = Uuid::new_v4();
        let make_conflict = || {
            let mut replica = Replica::default();
            replica.enqueue(PendingMutation {
                object: object(id, 1, 0),
                base_revision: Some(1),
                idempotency_key: Uuid::new_v4(),
                delete: false,
            });
            replica
                .apply_page(&SyncResponse {
                    changes: vec![SyncChange {
                        revision: 2,
                        operation: ChangeOperation::Upsert,
                        object_id: id,
                        object: Some(object(id, 2, 2)),
                    }],
                    next_cursor: "two".to_owned(),
                    has_more: false,
                })
                .unwrap();
            replica
        };

        let mut local = make_conflict();
        local.resolve_with_local(id).unwrap();
        assert!(local.conflicts().is_empty());
        assert_eq!(local.outbox()[0].base_revision, Some(2));

        let mut server = make_conflict();
        server.resolve_with_server(id).unwrap();
        assert!(server.conflicts().is_empty());
        assert!(server.outbox().is_empty());
        assert_eq!(server.objects()[&id].object_revision, 2);
    }
}
