#!/bin/sh
set -eu

read_secret() {
    secret_path=$1
    secret_label=$2
    if [ ! -r "$secret_path" ]; then
        echo "$secret_label is not readable at $secret_path" >&2
        exit 1
    fi
    secret_value=$(tr -d '\r\n' < "$secret_path")
    if [ -z "$secret_value" ]; then
        echo "$secret_label is empty" >&2
        exit 1
    fi
    printf '%s' "$secret_value"
}

database_host=${HP_DATABASE_HOST:-db}
database_port=${HP_DATABASE_PORT:-5432}
database_name=${HP_DATABASE_NAME:-hasilan}
database_user=${HP_DATABASE_USER:-hasilan}
database_password_file=${HP_DATABASE_PASSWORD_FILE:-/run/hasilan-secrets/database_password}
token_pepper_file=${HP_TOKEN_PEPPER_FILE:-/run/hasilan-secrets/token_pepper}
mfa_key_file=${HP_MFA_ENCRYPTION_KEY_FILE:-/run/hasilan-secrets/mfa_encryption_key}

case "$database_user" in
    ''|*[!A-Za-z0-9_]*) echo "HP_DATABASE_USER must contain only letters, digits, or underscores" >&2; exit 1 ;;
esac
case "$database_name" in
    ''|*[!A-Za-z0-9_]*) echo "HP_DATABASE_NAME must contain only letters, digits, or underscores" >&2; exit 1 ;;
esac
case "$database_port" in
    ''|*[!0-9]*) echo "HP_DATABASE_PORT must be numeric" >&2; exit 1 ;;
esac

database_password=$(read_secret "$database_password_file" "database password")
token_pepper=$(read_secret "$token_pepper_file" "token pepper")
mfa_encryption_key=$(read_secret "$mfa_key_file" "MFA encryption key")

export DATABASE_URL="postgresql://${database_user}:${database_password}@${database_host}:${database_port}/${database_name}"
export HP_TOKEN_PEPPER="$token_pepper"
export HP_MFA_ENCRYPTION_KEY="$mfa_encryption_key"

unset database_password token_pepper mfa_encryption_key secret_value
exec /usr/local/bin/hasilan-server

