# Self-hosting configuration

The default `docker compose up --build --detach` stack needs only PostgreSQL. It uses
`HP_INVITATION_DELIVERY=manual`, so an organization administrator receives a one-time
invitation token and delivers it through a trusted channel.

## SMTP invitation adapter

Set `HP_INVITATION_DELIVERY=smtp` to deliver organization invitations through an SMTP
relay. Hasilan Pass supports only certificate-validated implicit TLS (`implicit`, normally
port 465) or mandatory STARTTLS (`starttls`, normally port 587). It has no plaintext or
opportunistic downgrade mode. The API does not return the invitation bearer token after
successful SMTP submission. If message construction or relay submission fails, the
database transaction is rolled back and no active invitation remains.

Required settings:

- `HP_SMTP_HOST`: ASCII DNS name covered by the relay certificate.
- `HP_SMTP_FROM`: RFC mailbox, for example `Hasilan Pass <noreply@example.com>`.
- `HP_SMTP_TLS`: `implicit` or `starttls` (default `starttls`).
- `HP_SMTP_PORT`: optional override (defaults to 465 or 587 for the selected mode).
- `HP_SMTP_TIMEOUT_SECONDS`: 1–60 seconds (default 10).

Authentication is optional. When used, configure `HP_SMTP_USERNAME` together with exactly
one of `HP_SMTP_PASSWORD` or `HP_SMTP_PASSWORD_FILE`. Prefer the file form. For Compose,
mount an operator-managed secret with a small override such as:

```yaml
services:
  server:
    environment:
      HP_SMTP_PASSWORD_FILE: /run/secrets/smtp_password
    secrets:
      - smtp_password

secrets:
  smtp_password:
    file: ./secrets/smtp_password
```

Save that override as `compose.smtp.yaml`, set the non-secret SMTP fields in `.env`, and
start both files:

```sh
docker compose -f compose.yaml -f compose.smtp.yaml up --build --detach
```

Do not commit the override's `secrets/` directory. The SMTP relay necessarily learns the
recipient address and invitation token; it never receives vault keys or decrypted vault
items. Invitation links carry the token in a URL fragment, which browsers do not send in
HTTP requests, and the Web Vault removes the fragment after successful acceptance.
