#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 BACKUP_PARENT_DIRECTORY" >&2
  exit 2
fi

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
backup_parent=$1
backup_timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_directory="${backup_parent%/}/hasilan-pass-${backup_timestamp}"

umask 077
mkdir -p "$backup_parent"
if [[ -e "$backup_directory" ]]; then
  echo "backup destination already exists: $backup_directory" >&2
  exit 1
fi
mkdir "$backup_directory"

cd "$repository_root"
if ! docker compose ps --status running db --format json | grep -q '"Service":"db"'; then
  echo "the Compose database service is not running" >&2
  exit 1
fi

echo "creating a transactionally consistent PostgreSQL dump"
docker compose exec -T db sh -eu -c \
  'pg_dump --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --format=custom --no-owner' \
  > "$backup_directory/database.dump"

echo "copying the deployment secrets required to restore sessions and MFA data"
docker compose run --rm --no-deps -T --entrypoint /bin/sh secret-init \
  -eu -c 'tar -C /run/hasilan-secrets -cf - database_password token_pepper mfa_encryption_key' \
  > "$backup_directory/secrets.tar"

cat > "$backup_directory/README.txt" <<EOF
Hasilan Pass backup created at ${backup_timestamp}

database.dump is a PostgreSQL custom-format logical dump.
secrets.tar contains the database password, token pepper, and MFA encryption key.
Both files are required for a complete restore. This directory contains sensitive
account metadata and server keys even though vault item payloads remain encrypted.
EOF

(
  cd "$backup_directory"
  sha256sum database.dump secrets.tar README.txt > SHA256SUMS
)
chmod 0600 "$backup_directory"/*

echo "backup completed: $backup_directory"
echo "store the entire mode-0700 directory in an encrypted, access-controlled location"

