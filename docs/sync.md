# Synchronization protocol

Status: implemented v1 core with explicitly listed lifecycle gaps, 2026-08-13

## Goals

Synchronization transfers opaque encrypted records without exposing searchable vault
content. It must survive offline edits, retries, process termination, duplicated requests,
and concurrent devices without silently discarding a version.

The protocol is Hasilan Pass-specific. Bitwarden's current clients combine full sync,
domain APIs, cached state, and live notifications; their internal endpoint behavior is
not a stable public interoperability contract. Hasilan Pass preserves the visible vault
model and import/export compatibility while defining a small versioned API.

## Revisions and cursors

Each account has a monotonically increasing 64-bit `revision`. Every committed mutation
allocates one revision in the same PostgreSQL transaction as its object/tombstone write.
The sync cursor is an opaque, authenticated encoding of account ID, last revision, and
protocol version. Clients do not compare wall clocks.

`GET /api/v1/sync?cursor=...&limit=...` returns ordered changes plus `nextCursor` and
`hasMore`. An absent cursor replays retained history from revision zero. Pagination is
stable because account revisions are unique and the query is
`revision > last_revision ORDER BY revision` against immutable change-log rows. V1 keeps
that log indefinitely; compact snapshots and cursor-expiry recovery are future work.

The response carries only server metadata, wrapped keys, and encrypted payloads. A
response-wide revision is a convenience cursor, not an item's conflict token.

## Local state

Desktop maintains all of the following durably; the extension maintains encrypted
objects/cursor but performs mutations online rather than promising an offline outbox:

- encrypted object cache;
- last committed sync cursor;
- durable outbox of encrypted mutations;
- base object revision for each mutation;
- random idempotency key;
- explicit conflict records containing both encrypted versions.

Cursor advancement and cache application happen in one local transaction. Decrypted
views and the search index are memory-only and rebuilt after unlock.

## Upload protocol

A create uses a client-generated UUID with `baseRevision: null`. Update/delete sends the
last observed object revision in the versioned JSON request. Every mutation includes an
idempotency key; the server stores the request fingerprint and authoritative response so
a same-key retry is safe and rejects key reuse with different bytes. V1 does not encode
these preconditions as HTTP `If-Match` headers.

Success returns the authoritative object revision and account cursor. A stale base
returns `409 Conflict` with the current encrypted server object; it does not overwrite.
The native desktop client stores a conflict and offers either keep server or rebase/retry
the encrypted local version. A field-aware merge UI and “keep both as a new item” are not
currently shipped. Web and extension stop on `409`, pull the authoritative ciphertext,
and require the user to review and retry.

Automatic last-write-wins is not used for vault objects. This costs UX complexity but
avoids an unobservable password loss when two offline devices edit the same item.

## Pull/push sequence

1. Pull and transactionally apply all pages after the local cursor.
2. Detect whether queued base revisions became stale.
3. Upload non-conflicting outbox entries in creation order.
4. Record conflicts without dropping either encrypted version.
5. Pull once more through the revisions produced by uploads.
6. Commit the new cursor and compact acknowledged outbox entries.

The sequence is restartable at every boundary. Uploading first is avoided because a
client with a very old base would generate needless conflicts. Idempotency makes an
unknown result after a network interruption safe to retry.

## Deletes and tombstones

Delete marks the authoritative encrypted object with `deletedAt`, increments both object
and account revisions, and includes that ciphertext-bearing tombstone in the feed. It is
retained indefinitely in v1 and remains visible in the client Trash category. Permanent
purge, restore, configurable retention, change-log compaction, `410 cursor_expired`, and
snapshot reconciliation are not implemented; clients must not present those as working
controls. Reusing a deleted object's ID is rejected by optimistic conflict rules.

## Organizations and collections

Organization items share the same revision stream visible to each authorized member.
Access changes also emit revisions. Removal immediately causes a local encrypted-cache
purge instruction; clients delete organization keys and decrypted projections. A
malicious or offline former member may retain previously obtained data, which is a
documented limitation rather than a promise cryptography cannot enforce.

Collection membership is server-visible authorization metadata and duplicated inside
the encrypted item. A client rejects and reports mismatches. The server filters items by
current membership before returning sync rows.

## Attachments

Attachment upload uses metadata encrypted inside the parent item and independently
authenticated chunks addressed by random attachment ID plus index; the server never
receives a plaintext digest or filename. Initiation binds the opaque upload dimensions to
the exact parent object revision, chunk PUTs are idempotent, and completion rejects
missing or dimensionally inconsistent chunks. Download resumes at authenticated chunk
boundaries. Automatic expiry/garbage collection of abandoned uploads is future work;
explicit attachment deletion is implemented.

## Retry policy

Clients attempt one rotating-token refresh for an expired authenticated request and do not
blind-retry schema, authorization, integrity, or conflict failures. Idempotency makes an
application-level retry safe, and desktop preserves its outbox across transport failure.
Capped jittered retry scheduling, `Retry-After` handling, and a persistent circuit breaker
are remaining client hardening work.

## Test obligations

- concurrent update/update, update/delete, delete/restore, and ownership-change races;
- duplicated create/update/delete requests with the same idempotency key;
- disconnect before request, during body, after commit, and before response persistence;
- pagination while new writes arrive;
- future expired-cursor snapshot reconciliation with a non-empty outbox;
- organization grant/removal during sync;
- corrupt ciphertext is cached as quarantined data and never causes loss of other items;
- randomized state-machine/property tests compare client replicas to a reference model.
