#!/usr/bin/env bash
# Writes .env with fresh development secrets for docker compose. Never commit it.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] && { echo ".env already exists"; exit 0; }
r64() { head -c "$1" /dev/urandom | base64 | tr -d '\n'; }
hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
billing=$(hex 32)
umask 077
cat > .env <<ENV
JWT_SIGNING_KEY=$(r64 32)
DATA_ENCRYPTION_KEY=$(r64 32)
ADMIN_TOKEN=$(hex 32)
BILLING_SERVICE_SECRET=$billing
PROBER_SERVICE_SECRET=$(hex 32)
STRIPE_WEBHOOK_SECRET=whsec_$(hex 24)
GOOGLE_PUSH_TOKEN=$(hex 24)
ENV
echo "wrote .env"
