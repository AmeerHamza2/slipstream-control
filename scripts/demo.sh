#!/usr/bin/env bash
# End-to-end demo of the whole Slipstream VPN control plane, using the real
# services (no mocks between them):
#
#   Go api  <── signed heartbeats ──  Python fleet-prober  ──probes──►  VPN nodes
#      ▲   ──── node-scoped peer sync ────►  Go node-agent (fra node, dry-run)
#      └──── signed entitlement ────  Node billing-webhooks  ◄── Stripe-signed webhook
#
# Then it plays the phone: signup, pay, register a WireGuard public key, fetch
# the TunnelCore config, validate it with the engine's own parser and measure
# latency to each server from "the phone" (if ../tunnelcore is present). It
# ends by cancelling the subscription and watching the node agent remove the
# peer, which is what stops a lapsed user's handshakes.
#
# Prereqs: Postgres + Redis running (see README), Go, Node 22 (npm ci done in
# services/billing-webhooks), Python venv for services/fleet-prober, curl, openssl.
#
#   ./scripts/demo.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source scripts/dev-env.sh

# The demo gets its own throwaway database, recreated on every run, so it is
# deterministic and never collides with the integration tests (which use and
# truncate the main `slipstream` database).
DEMO_DB="${DEMO_DB:-slipstream_demo}"
PGURL_ADMIN="${PGURL_ADMIN:-postgres://slipstream:slipstream@127.0.0.1:5432/postgres?sslmode=disable}"
psql "$PGURL_ADMIN" -qc "DROP DATABASE IF EXISTS $DEMO_DB WITH (FORCE)" -c "CREATE DATABASE $DEMO_DB" >/dev/null
export DATABASE_URL="postgres://slipstream:slipstream@127.0.0.1:5432/$DEMO_DB?sslmode=disable"

API=http://127.0.0.1:8080
BILLING=http://127.0.0.1:8081
NODE_IP="${NODE_IP:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
NODE_IP="${NODE_IP:-$(ipconfig getifaddr en0 2>/dev/null || true)}"
[[ -n "$NODE_IP" ]] || { echo "set NODE_IP to a non-loopback IPv4 of this machine"; exit 1; }
STRIPE_WEBHOOK_SECRET=whsec_demo_$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')
GOOGLE_PUSH_TOKEN=demo-google-push-token-0123456789
PY="$ROOT/services/fleet-prober/.venv/bin/python"
LOG="$ROOT/.demo-logs"; mkdir -p "$LOG"

if [[ -t 1 ]]; then B=$'\e[1m'; G=$'\e[32m'; D=$'\e[2m'; R=$'\e[0m'; else B= G= D= R=; fi
step() { printf '\n%s── %s %s\n' "$B" "$*" "$R"; }
ok()   { printf '   %s✓%s %s\n' "$G" "$R" "$*"; }
j()    { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval('d'+sys.argv[1]))" "$1"; }

pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup EXIT
wait_http() { for _ in $(seq 1 100); do curl -sf "$1" >/dev/null 2>&1 && return 0; sleep 0.2; done; echo "timeout waiting for $1"; exit 1; }

step "1. Start the services"
go run ./cmd/api >"$LOG/api.log" 2>&1 & pids+=($!)
wait_http "$API/readyz"; ok "api (Go) on :8080: migrations applied, Postgres + Redis ready"

# Apple root: the real one is AppleRootCA-G3.cer from apple.com/certificateauthority.
# The demo only exercises Stripe, so any valid cert will do here.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=demo-root" -keyout "$LOG/root.key" -out "$LOG/root.pem" >/dev/null 2>&1
( cd services/billing-webhooks && API_URL=$API BILLING_SERVICE_SECRET=$BILLING_SERVICE_SECRET \
  STRIPE_WEBHOOK_SECRET=$STRIPE_WEBHOOK_SECRET APPLE_ROOT_CA_PATH="$LOG/root.pem" \
  GOOGLE_PUSH_TOKEN=$GOOGLE_PUSH_TOKEN REDIS_URL=$REDIS_URL PORT=8081 \
  node dist/main.js >"$LOG/billing.log" 2>&1 ) & pids+=($!)
wait_http "$BILLING/healthz"; ok "billing-webhooks (Node) on :8081"

# The ams node is simulated. The fra node gets the real node agent in step 2
# (it needs the server id the api assigns); a listener stands in for the
# Shadowsocks port, which the agent does not serve.
"$PY" services/fleet-prober/tools/fake_node.py --host "$NODE_IP" --wg-port 51830 --ss-port 8453 --load-port 9200 --delay-ms 35 --drop 0.2 >"$LOG/node2.log" 2>&1 & pids+=($!)
python3 -c "import socket,sys;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((sys.argv[1],8443));s.listen(64)
while True: s.accept()[0].close()" "$NODE_IP" >/dev/null 2>&1 & pids+=($!)
sleep 0.5; ok "simulated ams node on $NODE_IP (UDP echo health port, Shadowsocks TCP port, /load)"

step "2. Operator registers exit nodes (admin API)"
wgkey() { openssl genpkey -algorithm X25519 -outform DER 2>/dev/null | tail -c 32 | base64; }
mk() {
  curl -sf -XPOST "$API/admin/v1/servers" -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d "{\"name\":\"$1\",\"country\":\"$2\",\"city\":\"$3\",\"public_ipv4\":\"$NODE_IP\",\"wg_port\":$4,\"wg_public_key\":\"$(wgkey)\",\"ss_port\":$5}"
}
suffix=$RANDOM
fra=$(mk "fra-$suffix" DE Frankfurt 51820 8443)
s1=$(echo "$fra" | j '["id"]'); FRA_TOKEN=$(echo "$fra" | j '["agent_token"]'); ok "fra-$suffix  $s1"
s2=$(mk "ams-$suffix" NL Amsterdam 51830 8453 | j '["id"]'); ok "ams-$suffix  $s2"
ok "Shadowsocks master secrets are stored AES-256-GCM encrypted (v1:...)"

API_URL=$API SERVER_ID=$s1 AGENT_TOKEN=$FRA_TOKEN SYNC_INTERVAL=2s PEER_CAPACITY=100 \
  ECHO_ADDR="$NODE_IP:51821" HTTP_ADDR="$NODE_IP:9100" \
  go run ./cmd/node-agent -dry-run >"$LOG/node-agent.log" 2>&1 & pids+=($!)
wait_http "http://$NODE_IP:9100/healthz"
ok "node agent (Go) running on fra: pulls its peers with a node-scoped token, serves UDP echo + /load"
code=$(curl -s -o /dev/null -w '%{http_code}' "$API/admin/v1/servers/$s2/peers" -H "Authorization: Bearer $FRA_TOKEN")
ok "fra's token reading ams's peers → HTTP $code (a compromised node can't see other nodes)"

step "3. Fleet prober (Python) measures the nodes and reports signed heartbeats"
for i in 1 2; do
  API_URL=$API PROBER_ID=prober-demo PROBER_SERVICE_SECRET=$PROBER_SERVICE_SECRET \
    "$PY" -m fleet_prober --once >"$LOG/heartbeat-$i.json" 2>>"$LOG/prober.log"
done
python3 - "$LOG/heartbeat-2.json" "$s1" "$s2" <<'EOF'
import json,sys
d=json.load(open(sys.argv[1])); ids=set(sys.argv[2:])
for r in d["results"]:
    if r["server_id"] in ids:
        print(f"   {r['server_id'][:8]}  reachable={r['reachable']}  rtt_p50={r['rtt_ms_p50']}ms  loss={r['loss']}  load={r['load']}")
EOF
ok "2 consecutive reachable heartbeats → servers marked healthy"

step "4. User signs up and logs in (argon2id, EdDSA JWT)"
email="demo-$RANDOM$RANDOM@example.com"; pw="correct horse battery staple"
uid=$(curl -sf -XPOST "$API/v1/auth/signup" -d "{\"email\":\"$email\",\"password\":\"$pw\"}" | j '["user_id"]')
tok=$(curl -sf -XPOST "$API/v1/auth/login" -d "{\"email\":\"$email\",\"password\":\"$pw\"}" | j '["access_token"]')
H="Authorization: Bearer $tok"
ok "user $uid, plan=$(curl -sf "$API/v1/me" -H "$H" | j '["plan"]')"

PRIV=$(openssl genpkey -algorithm X25519 -outform DER 2>/dev/null | tail -c 32 | base64)
PUB=$(python3 - "$PRIV" <<'EOF'
import base64,subprocess,sys
raw=base64.b64decode(sys.argv[1])
der=bytes.fromhex("302e020100300506032b656e04220420")+raw
pem=b"-----BEGIN PRIVATE KEY-----\n"+base64.b64encode(der)+b"\n-----END PRIVATE KEY-----\n"
out=subprocess.run(["openssl","pkey","-pubout","-outform","DER"],input=pem,capture_output=True,check=True).stdout
print(base64.b64encode(out[-32:]).decode())
EOF
)
code=$(curl -s -o /dev/null -w '%{http_code}' -XPOST "$API/v1/devices" -H "$H" \
  -d "{\"name\":\"pixel\",\"platform\":\"android\",\"wg_public_key\":\"$PUB\"}")
ok "free plan → device registration refused with HTTP $code (payment_required)"

step "5. User pays: Stripe → billing-webhooks (Node) → api"
now=$(date +%s); exp=$((now + 30*24*3600))
evt="{\"id\":\"evt_demo_$RANDOM$RANDOM\",\"type\":\"customer.subscription.updated\",\"created\":$now,\"data\":{\"object\":{\"id\":\"sub_demo_$suffix\",\"object\":\"subscription\",\"status\":\"active\",\"current_period_end\":$exp,\"metadata\":{\"user_id\":\"$uid\",\"product_id\":\"premium_monthly\"},\"items\":{\"data\":[{\"current_period_end\":$exp}]}}}}"
sig=$(printf '%s' "$now.$evt" | openssl dgst -sha256 -hmac "$STRIPE_WEBHOOK_SECRET" | awk '{print $NF}')
resp=$(curl -s -w ' HTTP %{http_code}' -XPOST "$BILLING/billing/stripe/webhook" \
  -H "Stripe-Signature: t=$now,v1=$sig" -H 'Content-Type: application/json' --data-binary "$evt")
ok "Stripe-Signature verified, entitlement forwarded with HMAC service auth: $resp"
bad=$(curl -s -o /dev/null -w '%{http_code}' -XPOST "$BILLING/billing/stripe/webhook" \
  -H "Stripe-Signature: t=$now,v1=deadbeef" -H 'Content-Type: application/json' --data-binary "$evt")
ok "forged signature rejected with HTTP $bad"
ok "plan is now $(curl -sf "$API/v1/me" -H "$H" | j '["plan"]')"

step "6. Phone registers its WireGuard PUBLIC key (private key never leaves the device)"
dev=$(curl -sf -XPOST "$API/v1/devices" -H "$H" -d "{\"name\":\"pixel\",\"platform\":\"android\",\"wg_public_key\":\"$PUB\"}")
did=$(echo "$dev" | j '["device_id"]'); ok "device $did, tunnel address $(echo "$dev" | j '["tunnel_address"]')"

step "7. Phone fetches its TunnelCore config (ranked servers, WireGuard + Shadowsocks fallback)"
curl -sf -XPOST "$API/v1/devices/$did/config" -H "$H" -d '{}' >"$LOG/config.json"
python3 - "$LOG/config.json" <<'EOF'
import json,sys
c=json.load(open(sys.argv[1]))
for s in c["servers"]:
    print(f"   {s['protocol']:<12} {s['name']:<14} {s['endpoint']}")
print(f"   tunnel={c['tunnel_addresses']}  dns={c['dns_servers']}  mtu={c.get('mtu')}")
EOF

TC="$ROOT/../tunnelcore"
if [[ -d "$TC" ]] && command -v go >/dev/null; then
  python3 - "$LOG/config.json" "$PRIV" >"$LOG/config-with-key.json" <<'EOF'
import json,sys
c=json.load(open(sys.argv[1]))
for s in c["servers"]:
    if s["protocol"]=="wireguard": s["private_key"]=sys.argv[2]
print(json.dumps(c))
EOF
  step "8. TunnelCore engine validates the issued config with its own parser"
  ( cd "$TC" && go run ./cmd/tun-harness validate -config "$LOG/config-with-key.json" ) | sed 's/^/   /'
  step "9. Phone measures latency to each server itself (the server picker's preview)"
  ( cd "$TC" && go run ./cmd/tun-harness probe -config "$LOG/config-with-key.json" -timeout-ms 500 ) | sed 's/^/   /'
fi

step "10. Node agent puts the device on the fra node"
for _ in $(seq 1 50); do grep -q '"action":"add"' "$LOG/node-agent.log" && break; sleep 0.2; done
grep '"action":"add"' "$LOG/node-agent.log" | tail -1 | python3 -c "import json,sys; l=json.loads(sys.stdin.read()); print(f\"   peer {l['peer']} added with allowed-ips {l['allowed_ip']} (dry-run: logged, not applied)\")"
ok "only devices that were issued this node and whose owner is entitled"

step "11. Subscription cancelled: Stripe → billing → api → node agent removes the peer"
now2=$((now + 1))
del="{\"id\":\"evt_demo_$RANDOM$RANDOM\",\"type\":\"customer.subscription.deleted\",\"created\":$now2,\"data\":{\"object\":{\"id\":\"sub_demo_$suffix\",\"object\":\"subscription\",\"status\":\"canceled\",\"current_period_end\":$now2,\"metadata\":{\"user_id\":\"$uid\",\"product_id\":\"premium_monthly\"},\"items\":{\"data\":[{\"current_period_end\":$now2}]}}}}"
sig=$(printf '%s' "$now2.$del" | openssl dgst -sha256 -hmac "$STRIPE_WEBHOOK_SECRET" | awk '{print $NF}')
resp=$(curl -s -w ' HTTP %{http_code}' -XPOST "$BILLING/billing/stripe/webhook" \
  -H "Stripe-Signature: t=$now2,v1=$sig" -H 'Content-Type: application/json' --data-binary "$del")
ok "customer.subscription.deleted accepted: $resp"
t0=$(date +%s%N)
for _ in $(seq 1 50); do grep -q '"action":"remove"' "$LOG/node-agent.log" && break; sleep 0.2; done
if grep -q '"action":"remove"' "$LOG/node-agent.log"; then
  ok "node agent removed the peer within $(( ($(date +%s%N) - t0) / 1000000 )) ms: the device's next handshake will not complete"
else
  echo "   peer was not removed (see $LOG/node-agent.log)"; exit 1
fi
code=$(curl -s -o /dev/null -w '%{http_code}' -XPOST "$API/v1/devices/$did/config" -H "$H" -d '{}')
ok "config request now → HTTP $code (payment_required): the app shows the paywall"

step "Metrics (Prometheus)"
curl -sf "$API/metrics" | grep -E '^slipstream_(heartbeat_results_total|entitlement_events_total)' | sed 's/^/   /'
curl -sf "http://$NODE_IP:9100/metrics" | grep -E '^slipstream_agent_(peers|peer_changes_total|syncs_total)' | sed 's/^/   /'
printf '\n%s✓ end-to-end demo complete%s  %s(logs in .demo-logs/)%s\n' "$G" "$R" "$D" "$R"
