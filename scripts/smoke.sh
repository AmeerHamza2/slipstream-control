#!/usr/bin/env bash
# End-to-end smoke test against a running api (source scripts/dev-env.sh first).
#   ./scripts/smoke.sh [base_url]
# Requires curl, openssl, python3. Walks signup -> premium -> device -> servers ->
# heartbeats -> config issuance, signing internal calls like the real services do.
set -euo pipefail
B="${1:-http://127.0.0.1:8080}"
j() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
wgkey() { head -c32 /dev/urandom | base64; }
signed() { # service secret method path body
  local ts sig; ts=$(date +%s)
  sig=$(printf '%s' "$ts.$3.$4.$5" | openssl dgst -sha256 -hmac "$2" | awk '{print $NF}')
  curl -sf -X "$3" "$B$4" -H "X-Slipstream-Service: $1" -H "X-Slipstream-Timestamp: $ts" \
    -H "X-Slipstream-Signature: v1=$sig" -H 'Content-Type: application/json' ${5:+-d "$5"}
}

email="smoke-$RANDOM$RANDOM@example.com"; pw="correct horse battery staple"
uid=$(curl -sf -XPOST "$B/v1/auth/signup" -d "{\"email\":\"$email\",\"password\":\"$pw\"}" | j '["user_id"]')
tok=$(curl -sf -XPOST "$B/v1/auth/login" -d "{\"email\":\"$email\",\"password\":\"$pw\"}" | j '["access_token"]')
H="Authorization: Bearer $tok"
echo "user $uid"

now=$(date -u +%Y-%m-%dT%H:%M:%SZ); exp=$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%SZ)
signed billing-webhooks "$BILLING_SERVICE_SECRET" POST /internal/v1/entitlements \
  "{\"event_id\":\"evt_$RANDOM$RANDOM\",\"source\":\"stripe\",\"user_id\":\"$uid\",\"product_id\":\"premium_monthly\",\"status\":\"active\",\"expires_at\":\"$exp\",\"original_transaction_id\":\"sub_$uid\",\"occurred_at\":\"$now\"}"; echo
curl -sf "$B/v1/me" -H "$H"; echo

dev=$(curl -sf -XPOST "$B/v1/devices" -H "$H" -d "{\"name\":\"smoke\",\"platform\":\"android\",\"wg_public_key\":\"$(wgkey)\"}")
echo "device $dev"; did=$(echo "$dev" | j '["device_id"]')

ids=()
for n in fra ams; do
  sid=$(curl -sf -XPOST "$B/admin/v1/servers" -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d "{\"name\":\"$n-$RANDOM\",\"country\":\"DE\",\"city\":\"Frankfurt\",\"public_ipv4\":\"203.0.113.$((RANDOM % 200 + 1))\",\"wg_port\":51820,\"wg_public_key\":\"$(wgkey)\",\"ss_port\":8443}" | j '["id"]')
  ids+=("$sid")
done
results=$(printf '{"server_id":"%s","reachable":true,"rtt_ms_p50":30,"rtt_ms_p95":45,"loss":0,"load":0.2},' "${ids[@]}")
for _ in 1 2; do
  signed fleet-prober "$PROBER_SERVICE_SECRET" POST /internal/v1/servers/heartbeats \
    "{\"prober_id\":\"smoke\",\"observed_at\":\"$now\",\"results\":[${results%,}]}"; echo
done
echo "config:"
curl -sf -XPOST "$B/v1/devices/$did/config" -H "$H" -d '{"country":"DE"}' | python3 -m json.tool
