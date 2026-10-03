// Command seed fills a DEDICATED load-test database with a realistic, large
// dataset so query plans and the load test reflect production scale.
//
//	go run ./cmd/loadtest/seed -db 'postgres://.../slipstream_load?sslmode=disable'
//
// It TRUNCATES every table first, so it refuses to run against a database
// whose name does not contain "load" unless -force is given.
//
// Bulk rows (users, devices, subscriptions, entitlement events, refresh
// tokens) are generated server-side with generate_series. Only rows that must
// carry valid AES-256-GCM envelopes (server Shadowsocks secrets and the
// per-(device, server) preshared keys, whose AAD binds them to their ids) are
// produced in Go and streamed with COPY.
//
// Deterministic ids: user i is md5('user'||i)::uuid, device i is
// md5('dev'||i)::uuid, server j is md5('srv'||j)::uuid. Seeded users log in
// with email seed-<i>@example.com and password -password.
package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/ameerhamza2/slipstream-control/internal/auth"
	"github.com/ameerhamza2/slipstream-control/internal/crypto"
	"github.com/ameerhamza2/slipstream-control/internal/store"
)

var countries = strings.Fields("US CA MX BR AR CL CO GB IE FR DE NL BE LU CH AT IT ES PT SE NO DK FI PL CZ RO HU GR TR IL AE IN SG JP KR HK TW AU NZ ZA EG NG KE ID MY")

func main() {
	dsn := flag.String("db", os.Getenv("DATABASE_URL"), "Postgres DSN of the load-test database")
	users := flag.Int("users", 1_000_000, "users")
	devices := flag.Int("devices", 1_500_000, "devices (owned by the first -device-owners users)")
	owners := flag.Int("device-owners", 600_000, "users that own devices")
	subUsers := flag.Int("sub-users", 700_000, "users with a subscription")
	servers := flag.Int("servers", 1000, "VPN servers")
	keyDevices := flag.Int("key-devices", 600_000, "devices that were issued a config (3 servers each)")
	hotPeers := flag.Int("hot-peers", 120_000, "extra peers on the hot server (server 0)")
	password := flag.String("password", "loadtest-password-1", "password of every seeded user")
	force := flag.Bool("force", false, "allow a database whose name does not contain 'load'")
	flag.Parse()

	if u, err := url.Parse(*dsn); err != nil || (!strings.Contains(u.Path, "load") && !*force) {
		log.Fatal("refusing to TRUNCATE: database name must contain 'load' (or pass -force)")
	}
	kr, err := crypto.NewKeyringFromBase64(os.Getenv("DATA_ENCRYPTION_KEY"))
	if err != nil {
		log.Fatal("DATA_ENCRYPTION_KEY: ", err)
	}
	ctx := context.Background()
	st, err := store.Open(ctx, *dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Migrate(ctx); err != nil {
		log.Fatal("migrate: ", err)
	}
	conn, err := st.DB().Conn(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	hash, err := auth.NewHasher(auth.DefaultArgon2Params, 1).Hash(ctx, *password)
	if err != nil {
		log.Fatal(err)
	}
	step := func(name, q string, args ...any) {
		t := time.Now()
		res, err := conn.ExecContext(ctx, q, args...)
		if err != nil {
			log.Fatalf("%s: %v", name, err)
		}
		n, _ := res.RowsAffected()
		log.Printf("%-28s %10d rows  %s", name, n, time.Since(t).Round(time.Millisecond))
	}
	step("session settings", `SET maintenance_work_mem = '256MB'`)
	step("async commit", `SET synchronous_commit = off`)
	step("truncate", `TRUNCATE users, refresh_tokens, devices, servers, device_server_keys, entitlement_events, subscriptions CASCADE`)

	step("users", `INSERT INTO users (id, email, password_hash, created_at)
		SELECT md5('user'||i)::uuid, 'seed-'||i||'@example.com', $2, now() - (i % 730) * interval '1 day'
		FROM generate_series(1, $1::int) i`, *users, hash)

	step("devices", `INSERT INTO devices (id, user_id, name, platform, wg_public_key, tunnel_ip, created_at)
		SELECT md5('dev'||i)::uuid, md5('user'||(((i-1) % $2::int)+1))::uuid, 'device '||i,
		       CASE WHEN i % 3 = 0 THEN 'ios' ELSE 'android' END,
		       encode(sha256(('wg'||i)::bytea), 'base64'), '10.64.0.1'::inet + i,
		       now() - (i % 365) * interval '1 day'
		FROM generate_series(1, $1::int) i`, *devices, *owners)
	// About 2% of devices are removed again, leaving gaps in the address
	// space the way real churn does.
	step("device churn (gaps)", `DELETE FROM devices WHERE get_byte(decode(md5(id::text), 'hex'), 0) < 5`)

	// One subscription per subscribed user (85% active, the rest lapsed), and
	// a second, expired one from another store for every 10th user.
	step("subscriptions", `INSERT INTO subscriptions (source, original_transaction_id, user_id, product_id, status, expires_at, last_event_id, last_event_at, updated_at)
		SELECT (ARRAY['stripe','app_store','google_play'])[1 + i % 3], 'otid-'||i, md5('user'||i)::uuid, 'premium_monthly',
		       CASE WHEN i % 7 = 0 THEN 'expired' WHEN i % 23 = 0 THEN 'grace' ELSE 'active' END,
		       CASE WHEN i % 7 = 0 THEN now() - (i % 300) * interval '1 day' ELSE now() + (1 + i % 30) * interval '1 day' END,
		       'evt-'||i||'-'||(i % 13 + 1), now() - (i % 30) * interval '1 day', now() - (i % 30) * interval '1 day'
		FROM generate_series(1, $1::int) i`, *subUsers)
	step("subscriptions (2nd source)", `INSERT INTO subscriptions (source, original_transaction_id, user_id, product_id, status, expires_at, last_event_id, last_event_at, updated_at)
		SELECT (ARRAY['stripe','app_store','google_play'])[1 + (i + 1) % 3], 'otid2-'||i, md5('user'||i)::uuid, 'premium_yearly',
		       'expired', now() - (i % 500) * interval '1 day', 'evt2-'||i, now() - (i % 500) * interval '1 day', now() - (i % 500) * interval '1 day'
		FROM generate_series(10, $1::int, 10) i`, *subUsers)
	// ~7 events per subscription: purchase, renewals, an occasional stale or
	// duplicate delivery. About 4.9M rows for 700k subscribers.
	step("entitlement_events", `INSERT INTO entitlement_events (event_id, source, user_id, product_id, status, expires_at, original_transaction_id, occurred_at, received_at, applied, reason)
		SELECT 'evt-'||i||'-'||k, (ARRAY['stripe','app_store','google_play'])[1 + i % 3], md5('user'||i)::uuid, 'premium_monthly',
		       CASE WHEN k = i % 13 + 1 AND i % 7 = 0 THEN 'expired' ELSE 'active' END,
		       now() - ((i % 13 + 1 - k) * 30 - 30) * interval '1 day', 'otid-'||i,
		       now() - ((i % 13 + 1 - k) * 30 + (i % 30)) * interval '1 day',
		       now() - ((i % 13 + 1 - k) * 30 + (i % 30)) * interval '1 day' + interval '2 seconds',
		       k % 17 <> 0, CASE WHEN k % 17 = 0 THEN 'stale' END
		FROM generate_series(1, $1::int) i, generate_series(1, i % 13 + 1) k`, *subUsers)
	// One live token per user plus two rotated predecessors; 10% expired
	// long ago (janitor fodder).
	step("refresh_tokens", `INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, expires_at, created_at, rotated_at)
		SELECT md5('rt'||i||'-'||k)::uuid, md5('user'||i)::uuid, md5('fam'||i)::uuid, sha256(('rt'||i||'-'||k)::bytea),
		       CASE WHEN i % 10 = 0 THEN now() - interval '3 days' ELSE now() + (i % 30) * interval '1 day' END,
		       now() - (3 - k) * interval '1 day',
		       CASE WHEN k < 3 THEN now() - (2 - k) * interval '1 day' END
		FROM generate_series(1, $1::int) i, generate_series(1, 3) k`, *users)

	// Servers, with real encrypted Shadowsocks master secrets.
	t := time.Now()
	rng := rand.New(rand.NewPCG(1, 2))
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	cp, err := tx.PrepareContext(ctx, pq.CopyIn("servers", "id", "name", "country", "city", "public_ipv4", "wg_port", "wg_public_key",
		"ss_port", "ss_master_secret_enc", "healthy", "consecutive_reachable", "last_heartbeat_at", "rtt_ms_p50", "rtt_ms_p95", "loss", "load"))
	if err != nil {
		log.Fatal(err)
	}
	serverIDs := make([]string, *servers)
	for j := 0; j < *servers; j++ {
		id := md5UUID(fmt.Sprintf("srv%d", j))
		serverIDs[j] = id
		cc := countries[j%len(countries)]
		enc, err := kr.Encrypt([]byte(crypto.RandomBase64(32)), []byte("ss_master:"+id))
		if err != nil {
			log.Fatal(err)
		}
		rtt := 10 + rng.Float64()*200
		if _, err := cp.ExecContext(ctx, id, fmt.Sprintf("%s-%03d", strings.ToLower(cc), j), cc, "City "+cc,
			fmt.Sprintf("198.18.%d.%d", j/250, j%250+1), 51820, crypto.RandomBase64(32), 8443, enc,
			true, 2, time.Now(), rtt, rtt*1.5, rng.Float64()*0.02, rng.Float64()); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := cp.ExecContext(ctx); err != nil {
		log.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}
	log.Printf("%-28s %10d rows  %s", "servers", *servers, time.Since(t).Round(time.Millisecond))

	// Preshared keys: 3 servers per device for the first -key-devices devices,
	// plus -hot-peers devices on server 0 (a busy node). COPY into a staging
	// table, then insert only rows whose device survived the churn above.
	t = time.Now()
	step("psk staging", `CREATE TEMP TABLE psk_stage (device_id uuid, server_id uuid, psk_enc text)`)
	tx, err = conn.BeginTx(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	cp, err = tx.PrepareContext(ctx, pq.CopyIn("psk_stage", "device_id", "server_id", "psk_enc"))
	if err != nil {
		log.Fatal(err)
	}
	n := 0
	add := func(dev, srv string) {
		enc, err := kr.Encrypt([]byte(crypto.GeneratePresharedKey()), []byte("psk:"+dev+":"+srv))
		if err != nil {
			log.Fatal(err)
		}
		if _, err := cp.ExecContext(ctx, dev, srv, enc); err != nil {
			log.Fatal(err)
		}
		n++
	}
	for d := 1; d <= *keyDevices; d++ {
		dev := md5UUID(fmt.Sprintf("dev%d", d))
		seen := map[int]bool{}
		for _, j := range []int{1 + (d*7)%(*servers-1), 1 + (d*13+5)%(*servers-1), 1 + (d*31+11)%(*servers-1)} {
			if !seen[j] {
				seen[j] = true
				add(dev, serverIDs[j])
			}
		}
	}
	for d := 1; d <= *hotPeers && d <= *devices; d++ {
		add(md5UUID(fmt.Sprintf("dev%d", d)), serverIDs[0])
	}
	if _, err := cp.ExecContext(ctx); err != nil {
		log.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}
	log.Printf("%-28s %10d rows  %s", "psk generated", n, time.Since(t).Round(time.Millisecond))
	step("device_server_keys", `INSERT INTO device_server_keys (device_id, server_id, psk_enc, created_at)
		SELECT s.device_id, s.server_id, s.psk_enc, now() - interval '1 day' FROM psk_stage s JOIN devices d ON d.id = s.device_id
		ON CONFLICT DO NOTHING`)
	step("vacuum analyze", `VACUUM ANALYZE`)
	log.Printf("done; hot server id %s; seeded users log in as seed-<i>@example.com / %s", serverIDs[0], *password)
}

func md5UUID(s string) string {
	h := md5.Sum([]byte(s))
	x := hex.EncodeToString(h[:])
	return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}
