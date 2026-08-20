#!/usr/bin/env bash
set -euo pipefail

confirmation_phrase=restore-hasilan-pass
if [[ $# -ne 1 ]]; then
  echo "usage: HP_RESTORE_CONFIRM=$confirmation_phrase $0 BACKUP_DIRECTORY" >&2
  exit 2
fi
if [[ ${HP_RESTORE_CONFIRM:-} != "$confirmation_phrase" ]]; then
  echo "restore replaces the current database and deployment secrets" >&2
  echo "set HP_RESTORE_CONFIRM=$confirmation_phrase to continue" >&2
  exit 2
fi

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
backup_directory="$(cd "$1" && pwd)"

for required_file in database.dump secrets.tar README.txt SHA256SUMS; do
  if [[ ! -f "$backup_directory/$required_file" ]]; then
    echo "missing backup file: $required_file" >&2
    exit 1
  fi
done
(
  cd "$backup_directory"
  sha256sum --check SHA256SUMS
)

cd "$repository_root"
echo "stopping application services"
docker compose stop web server db

echo "restoring deployment secrets"
docker compose run --rm --no-deps -T --entrypoint /bin/sh secret-init -eu -c '
  find /run/hasilan-secrets -mindepth 1 -maxdepth 1 -type f -delete
  tar -C /run/hasilan-secrets -xf -
  chmod 0444 /run/hasilan-secrets/database_password /run/hasilan-secrets/token_pepper /run/hasilan-secrets/mfa_encryption_key
' < "$backup_directory/secrets.tar"

echo "starting PostgreSQL with the restored database credential"
docker compose up --detach --wait db

docker compose exec -T db sh -eu -c '
  database_password=$(tr -d "\r\n" < /run/hasilan-secrets/database_password)
  case "$database_password" in
    ""|*[!0-9a-f]*) echo "restored database password is invalid" >&2; exit 1 ;;
  esac
  case "$POSTGRES_USER" in
    ""|*[!A-Za-z0-9_]*) echo "POSTGRES_USER must contain only letters, digits, or underscores" >&2; exit 1 ;;
  esac
  psql --username "$POSTGRES_USER" --dbname postgres --set ON_ERROR_STOP=1 \
    --command "ALTER ROLE \"$POSTGRES_USER\" PASSWORD '\''$database_password'\''"
'

echo "replacing the application database from the verified dump"
docker compose exec -T db sh -eu -c '
  pg_restore --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    --clean --if-exists --no-owner --exit-on-error
' < "$backup_directory/database.dump"

echo "starting the restored application"
docker compose up --detach --wait server web
echo "restore completed and all health checks passed"
