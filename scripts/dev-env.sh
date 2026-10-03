#!/usr/bin/env bash
# Development environment for the Slipstream control-plane API.
#
#   source scripts/dev-env.sh && go run ./cmd/api
#
# Generates throwaway keys on first use and caches them in .dev-secrets (git-ignore
# it). NEVER use these values outside local development; in production every secret
# comes from the secret manager.
#
# Variables:
#   LISTEN_ADDR              address to listen on (default :8080)
#   DATABASE_URL             Postgres DSN (lib/pq format)
#   REDIS_URL                redis://host:port/db
#   JWT_SIGNING_KEY          base64 of a 32-byte Ed25519 seed (access-token signing key)
#   JWT_PREVIOUS_PUBLIC_KEYS optional, comma-separated base64 Ed25519 public keys still
#                            accepted and published in the JWKS during key rotation
#   DATA_ENCRYPTION_KEY      base64 of 32 bytes: AES-256-GCM key for secrets at rest ("v1:")
#   ADMIN_TOKEN              bearer token for /admin/v1 (>= 32 chars)
#   BILLING_SERVICE_SECRET   HMAC secret shared with billing-webhooks (>= 32 chars)
#   PROBER_SERVICE_SECRET    HMAC secret shared with fleet-prober (>= 32 chars, != billing)
#   TRUSTED_PROXY_CIDRS      optional, comma-separated CIDRs whose X-Forwarded-For is honoured
#   LOG_LEVEL                debug | info | warn | error (default info)
#   SHUTDOWN_TIMEOUT         graceful shutdown budget, Go duration (default 20s)

_secrets_file="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.dev-secrets"
_rand_b64() { head -c "$1" /dev/urandom | base64 | tr -d '\n'; }
_rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

if [[ ! -f "$_secrets_file" ]]; then
  umask 077
  cat >"$_secrets_file" <<SECRETS
JWT_SIGNING_KEY=$(_rand_b64 32)
DATA_ENCRYPTION_KEY=$(_rand_b64 32)
ADMIN_TOKEN=$(_rand_hex 32)
BILLING_SERVICE_SECRET=$(_rand_hex 32)
PROBER_SERVICE_SECRET=$(_rand_hex 32)
SECRETS
fi
set -a
# shellcheck disable=SC1090
. "$_secrets_file"
LISTEN_ADDR="${LISTEN_ADDR:-:8080}"
DATABASE_URL="${DATABASE_URL:-postgres://slipstream:slipstream@127.0.0.1:5432/slipstream?sslmode=disable}"
REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}"
LOG_LEVEL="${LOG_LEVEL:-info}"
set +a
unset -f _rand_b64 _rand_hex
unset _secrets_file
echo "slipstream dev env loaded (secrets in .dev-secrets)" >&2
