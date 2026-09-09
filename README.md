# Dynamic Encryption Digital Vault

Envelope-encrypted file storage with a PostgreSQL-backed key management layer,
authenticated (OIDC) token-based sharing, and a file lifecycle (trash /
restore / purge). This is the foundational engineering milestone described in
[`md docs/dynamic-vault-mvp-coding-prompt.md`](md%20docs/dynamic-vault-mvp-coding-prompt.md);
everything else planned for the capstone (rule-based/ML security-level
selection, survey integration) sits on top of this layer later.

**Not end-to-end encryption.** The backend can decrypt files while serving an
authorized request. Do not market or rely on this as end-to-end encrypted
storage. See "Deliberate limitations" below before treating this as
production-ready.

## Architecture

```
File
 |
 v
Generate per-file DEK (random 256-bit key)
 |
 v
Encrypt file with AES-256-GCM using the DEK (AAD binds document/key identity)
 |
 v
Wrap the DEK with the active KEK (AES-256-GCM key wrap, committed nonce)
 |
 v
Store wrapped DEK + metadata in PostgreSQL; ciphertext on local encrypted-file storage
```

```
Owner creates a read grant (recipient + expiry)
 |
 v
Random 256-bit token issued; only its SHA-256 hash is stored
 |
 v
Recipient presents token -> hash compared (constant-time), expiry/revocation checked
 |
 v
If authorized: KeyManager unwraps the DEK and decrypts -- all inside one
transaction held through the audit-log commit, so no plaintext is ever
returned before the access decision is durably recorded
```

Modules are kept independent with narrow interfaces (`encryption_service`,
`kek_provider`, `db`, `storage`, `token_service`, `key_manager`, `auth`,
`api`/`web`) so they could later be split into services without a rewrite.

## Repository layout

```
dynamic-encryption-digital-vault/
├── migrations/              # 001 schema, 002 least-privilege roles, 003 lifecycle
├── vault/                   # backend package (see below)
├── tests/                   # pytest suite (unit + real-Postgres integration)
├── frontend/                # minimal OIDC browser client
├── deploy/                  # Caddy + Docker Compose for a single-host deployment
├── Dockerfile, compose.yaml # dev/test convenience container for vault.api
└── .github/workflows/       # CI: lint, type-check, tests, dependency audit
```

`vault/api.py` is the original authenticated backend API (upload / grant /
revoke / download / audit). `vault/web.py` is the newer "product" entry point:
it reuses `api.py`'s request-body guard middleware and adds pagination, a
storage-usage endpoint, and trash/restore so it's what `deploy/` actually
runs. Both are kept because `api.py`'s narrower surface is easier to reason
about for the crypto/authorization milestone on its own.

## Local setup

Requires Python 3.11+, Docker, and a PostgreSQL client (`psql`).

```bash
python -m pip install uv
uv sync --extra test
```

### Start PostgreSQL

```bash
export POSTGRES_PASSWORD="$(python -c 'import secrets; print(secrets.token_hex(24))')"
docker compose up -d postgres
export ADMIN_DATABASE_URL="postgresql://vault_owner:${POSTGRES_PASSWORD}@127.0.0.1:5432/vault"
```

### Apply migrations

```bash
psql "$ADMIN_DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/001_schema.sql
psql "$ADMIN_DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/002_roles.sql
psql "$ADMIN_DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/003_file_lifecycle.sql
```

Set the runtime role's password once, interactively (`\password vault_runtime`
inside `psql "$ADMIN_DATABASE_URL"`), then configure `DATABASE_URL` for that
credential through your own secret-management mechanism. Never run the API
with `ADMIN_DATABASE_URL`.

### Configure the KEK

Preferred local option (OS keyring):

```bash
export VAULT_KEK_SOURCE=keyring
export VAULT_KEK_VERSIONS=v1
export VAULT_ACTIVE_KEK=v1
uv run python -m vault.admin new-key v1
uv run python -m vault.admin register-keys
uv run python -m vault.admin activate-key
```

Headless/CI environments without an unlocked OS keyring can use the
environment-variable form instead — see `.env.example` and
`vault/kek_provider.py`. Never regenerate a KEK while files encrypted under it
still need to be read.

### Configure authentication

```bash
export OIDC_ISSUER="https://your-provider.example/your-issuer"
export OIDC_JWKS_URL="https://your-provider.example/your-jwks-endpoint"
export OIDC_AUDIENCE="dynamic-vault-api"
```

The provider must issue RS256 access tokens (not ID tokens) with a `vault`
scope and a dedicated API audience — not the frontend's own OIDC client ID.

### Run the API

```bash
export VAULT_ROOT="./encrypted-files"
export VAULT_DOCS=1
uv run uvicorn vault.web:create_app --factory \
  --host 127.0.0.1 --port 8000 --workers 1 \
  --no-access-log --no-proxy-headers
```

Open `http://127.0.0.1:8000/docs` and authorize with an access token from your
identity provider.

### Run tests

Use a **separate, disposable** database — the integration suite writes real
rows and real encrypted files.

```bash
export TEST_ADMIN_DATABASE_URL="postgresql://postgres@127.0.0.1:5432/vault_test"
export TEST_DATABASE_URL="postgresql://vault_runtime@127.0.0.1:5432/vault_test"
uv run pytest -q -m "not integration"   # crypto + token-format unit tests
uv run pytest -q                        # full suite, including real PostgreSQL
uv run ruff check vault tests
uv run mypy vault
```

The integration tests spin up their own throwaway JWKS server (`tests/conftest.py`)
so no real identity provider is needed to run them.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

See [`frontend/README`](frontend/index.html) inline comments for the runtime
config it expects (`OIDC_ISSUER`, `OIDC_CLIENT_ID`, `API_BASE_URL`).

### Deploy

`deploy/compose.yaml` runs the API behind Caddy (automatic HTTPS) plus the
static frontend, as two containers on one host — see `deploy/Caddyfile` and
`deploy/Dockerfile.{api,web}`.

## Rotation and recovery

```bash
uv run python -m vault.admin new-key v2
export VAULT_KEK_VERSIONS=v1,v2
export VAULT_ACTIVE_KEK=v2
uv run python -m vault.admin register-keys
uv run python -m vault.admin activate-key
uv run python -m vault.admin rewrap   # optional: rewrap existing DEKs onto v2
```

After restoring an older database snapshot: stop all writers, restore the
historical KEKs needed to read restored documents, provision and activate a
**new, never-before-used** KEK before resuming any writes, then run
`uv run python -m vault.admin reconcile` (add `--quarantine --maintenance-ack`
only once writers are stopped) to find orphaned ciphertext.

## File lifecycle

Trash is a soft-delete: `POST /documents/{id}/trash` immediately hides the
document and revokes its existing sharing tokens; `POST
/documents/{id}/restore` brings it back (tokens are not restored — reissue
them). After 7 days, `python -m vault.lifecycle_worker` permanently deletes
the ciphertext and key material, leaving a minimal tombstone row and its audit
history. Schedule that worker (e.g. via cron) — it isn't run automatically.

## Deliberate limitations and trade-offs

- No end-to-end encryption: the backend can access plaintext during
  authorized operations.
- Revocation and trash cannot erase copies already downloaded.
- Rate limiting is process-local — keep one worker until a shared limiter is
  deliberately introduced.
- Audit logging is insert-only for the application role but not
  administrator-tamper-proof, and operations fail closed if a required audit
  write fails.
- 16 MiB file size limit; no chunked/streaming AEAD.
- Metadata (filenames, ownership, recipients, timestamps, sizes) is not
  encrypted.
- No post-quantum algorithms, ML-based policy engine, or microservice split —
  explicitly out of scope for this milestone.
- Plaintext keys exist transiently in process memory; disable core dumps and
  avoid unencrypted swap/hibernation on hosts handling them.

**Not yet verified in this environment:** dependency locking (`uv.lock`),
execution against a real OIDC provider, a backup/restore drill, and an
independent security review. Run the test suite and review checklist in the
coding prompt before treating this as a finished milestone.
