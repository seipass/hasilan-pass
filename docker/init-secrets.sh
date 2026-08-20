#!/bin/sh
set -eu

secret_directory=/run/hasilan-secrets
umask 077

ensure_length() {
    secret_path=$1
    expected_length=$2
    secret_label=$3

    if [ ! -f "$secret_path" ]; then
        return 1
    fi
    actual_length=$(wc -c < "$secret_path" | tr -d ' ')
    if [ "$actual_length" -ne "$expected_length" ]; then
        echo "$secret_label exists but has an invalid length; refusing to overwrite it" >&2
        exit 1
    fi
    chmod 0444 "$secret_path"
    return 0
}

create_hex_secret() {
    secret_path=$1
    expected_length=$2
    secret_label=$3

    if ensure_length "$secret_path" "$expected_length" "$secret_label"; then
        return
    fi
    temporary_path="${secret_path}.tmp.$$"
    dd if=/dev/urandom bs=32 count=1 2>/dev/null \
        | od -An -tx1 \
        | tr -d ' \n' > "$temporary_path"
    chmod 0444 "$temporary_path"
    mv "$temporary_path" "$secret_path"
    echo "created $secret_label"
}

create_base64url_secret() {
    secret_path=$1
    expected_length=$2
    secret_label=$3

    if ensure_length "$secret_path" "$expected_length" "$secret_label"; then
        return
    fi
    temporary_path="${secret_path}.tmp.$$"
    dd if=/dev/urandom bs=32 count=1 2>/dev/null \
        | base64 \
        | tr '+/' '-_' \
        | tr -d '=\n' > "$temporary_path"
    chmod 0444 "$temporary_path"
    mv "$temporary_path" "$secret_path"
    echo "created $secret_label"
}

mkdir -p "$secret_directory"
create_hex_secret "$secret_directory/database_password" 64 "database password"
create_base64url_secret "$secret_directory/token_pepper" 43 "token pepper"
create_base64url_secret "$secret_directory/mfa_encryption_key" 43 "MFA encryption key"

