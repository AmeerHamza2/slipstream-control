// Package config loads service configuration from environment variables.
// Secrets are validated for shape and length but never logged.
package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the api service configuration.
type Config struct {
	ListenAddr        string
	DatabaseURL       string
	RedisURL          string
	JWTSigningSeed    []byte              // 32-byte Ed25519 seed
	JWTPreviousKeys   []ed25519.PublicKey // still accepted, still published in JWKS
	DataEncryptionKey string              // base64, 32 bytes (validated by the keyring)
	AdminToken        string
	BillingSecret     string
	ProberSecret      string
	TrustedProxies    []netip.Prefix
	LogLevel          string
	ShutdownTimeout   time.Duration
	// DrainDelay is how long /readyz reports "draining" before the listener
	// closes on SIGTERM, so a load balancer stops routing here first. Set it
	// a little above the LB's health-check interval x unhealthy threshold.
	DrainDelay time.Duration

	// Capacity and timeouts (all optional, with defaults sized for one
	// replica; see docs/SCALABILITY.md).
	DB             DBPool
	Redis          RedisPool
	RequestTimeout time.Duration // deadline for every request's DB/Redis work
	ServerCacheTTL time.Duration // in-process server list snapshot; 0 disables
	Argon2         Argon2Limits
	// DebugAddr, if set, serves net/http/pprof. It must be a loopback
	// address: profiles expose memory contents and must never be public.
	DebugAddr string
}

// DBPool sizes the database/sql pool. With N replicas the database sees up
// to N*MaxOpen connections, so put PgBouncer (transaction mode) in front at scale.
type DBPool struct {
	MaxOpen     int
	MaxIdle     int
	MaxLifetime time.Duration
	MaxIdleTime time.Duration
}

// RedisPool sizes the go-redis pool.
type RedisPool struct {
	PoolSize     int
	DialTimeout  time.Duration
	ReadTimeout  time.Duration // also used as write timeout
	PoolTimeout  time.Duration
	MinIdleConns int
}

// Argon2Limits bounds concurrent password hashing. Concurrency 0 means
// GOMAXPROCS. A request that cannot start hashing within QueueTimeout, or
// arrives when Queue requests are already waiting, gets 503 + Retry-After.
type Argon2Limits struct {
	Concurrency  int
	Queue        int
	QueueTimeout time.Duration
}

// Defaults for the optional capacity settings.
var (
	DefaultDBPool       = DBPool{MaxOpen: 20, MaxIdle: 20, MaxLifetime: 30 * time.Minute, MaxIdleTime: 5 * time.Minute}
	DefaultRedisPool    = RedisPool{PoolSize: 0, DialTimeout: 500 * time.Millisecond, ReadTimeout: 250 * time.Millisecond, PoolTimeout: 500 * time.Millisecond}
	DefaultArgon2Limits = Argon2Limits{Concurrency: 0, Queue: 0, QueueTimeout: time.Second}
)

// FromEnv reads and validates configuration.
func FromEnv() (Config, error) { return Load(os.Getenv) }

// Load reads configuration through getenv (injectable for tests).
func Load(getenv func(string) string) (Config, error) {
	c := Config{
		ListenAddr:      def(getenv("LISTEN_ADDR"), ":8080"),
		DatabaseURL:     getenv("DATABASE_URL"),
		RedisURL:        getenv("REDIS_URL"),
		AdminToken:      getenv("ADMIN_TOKEN"),
		BillingSecret:   getenv("BILLING_SERVICE_SECRET"),
		ProberSecret:    getenv("PROBER_SERVICE_SECRET"),
		LogLevel:        def(getenv("LOG_LEVEL"), "info"),
		ShutdownTimeout: 20 * time.Second,
		DB:              DefaultDBPool,
		Redis:           DefaultRedisPool,
		RequestTimeout:  10 * time.Second,
		ServerCacheTTL:  2 * time.Second,
		Argon2:          DefaultArgon2Limits,
		DebugAddr:       getenv("DEBUG_ADDR"),
	}
	var errs []error
	req := func(name, v string, minLen int) {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		} else if len(v) < minLen {
			errs = append(errs, fmt.Errorf("%s must be at least %d characters", name, minLen))
		}
	}
	req("DATABASE_URL", c.DatabaseURL, 1)
	req("REDIS_URL", c.RedisURL, 1)
	req("ADMIN_TOKEN", c.AdminToken, 32)
	req("BILLING_SERVICE_SECRET", c.BillingSecret, 32)
	req("PROBER_SERVICE_SECRET", c.ProberSecret, 32)

	if v := getenv("JWT_SIGNING_KEY"); v == "" {
		errs = append(errs, errors.New("JWT_SIGNING_KEY is required (base64 32-byte Ed25519 seed)"))
	} else if seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v)); err != nil || len(seed) != ed25519.SeedSize {
		errs = append(errs, errors.New("JWT_SIGNING_KEY must be base64 of a 32-byte Ed25519 seed"))
	} else {
		c.JWTSigningSeed = seed
	}
	for _, p := range splitList(getenv("JWT_PREVIOUS_PUBLIC_KEYS")) {
		pub, err := base64.StdEncoding.DecodeString(p)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			errs = append(errs, errors.New("JWT_PREVIOUS_PUBLIC_KEYS entries must be base64 32-byte Ed25519 public keys"))
			continue
		}
		c.JWTPreviousKeys = append(c.JWTPreviousKeys, ed25519.PublicKey(pub))
	}
	if v := getenv("DATA_ENCRYPTION_KEY"); v == "" {
		errs = append(errs, errors.New("DATA_ENCRYPTION_KEY is required (base64 32 bytes)"))
	} else if k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v)); err != nil || len(k) != 32 {
		errs = append(errs, errors.New("DATA_ENCRYPTION_KEY must be base64 of 32 bytes"))
	} else {
		c.DataEncryptionKey = v
	}
	for _, p := range splitList(getenv("TRUSTED_PROXY_CIDRS")) {
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("TRUSTED_PROXY_CIDRS: invalid prefix %q", p))
			continue
		}
		c.TrustedProxies = append(c.TrustedProxies, pfx.Masked())
	}
	if v := getenv("SHUTDOWN_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			errs = append(errs, errors.New("SHUTDOWN_TIMEOUT must be a positive duration"))
		} else {
			c.ShutdownTimeout = d
		}
	}
	num := func(name string, dst *int, lo int) {
		if v := getenv(name); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < lo {
				errs = append(errs, fmt.Errorf("%s must be an integer >= %d", name, lo))
				return
			}
			*dst = n
		}
	}
	dur := func(name string, dst *time.Duration, allowZero bool) {
		if v := getenv(name); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil || d < 0 || (d == 0 && !allowZero) {
				errs = append(errs, fmt.Errorf("%s must be a positive Go duration", name))
				return
			}
			*dst = d
		}
	}
	num("DB_MAX_OPEN_CONNS", &c.DB.MaxOpen, 1)
	c.DB.MaxIdle = c.DB.MaxOpen
	num("DB_MAX_IDLE_CONNS", &c.DB.MaxIdle, 0)
	dur("DB_CONN_MAX_LIFETIME", &c.DB.MaxLifetime, false)
	dur("DB_CONN_MAX_IDLE_TIME", &c.DB.MaxIdleTime, false)
	num("REDIS_POOL_SIZE", &c.Redis.PoolSize, 0)
	num("REDIS_MIN_IDLE_CONNS", &c.Redis.MinIdleConns, 0)
	dur("REDIS_DIAL_TIMEOUT", &c.Redis.DialTimeout, false)
	dur("REDIS_TIMEOUT", &c.Redis.ReadTimeout, false)
	dur("REDIS_POOL_TIMEOUT", &c.Redis.PoolTimeout, false)
	dur("REQUEST_TIMEOUT", &c.RequestTimeout, false)
	dur("SHUTDOWN_DRAIN_DELAY", &c.DrainDelay, true)
	dur("SERVER_CACHE_TTL", &c.ServerCacheTTL, true)
	num("ARGON2_MAX_CONCURRENCY", &c.Argon2.Concurrency, 0)
	num("ARGON2_MAX_QUEUE", &c.Argon2.Queue, 0)
	dur("ARGON2_QUEUE_TIMEOUT", &c.Argon2.QueueTimeout, false)
	if c.ServerCacheTTL > 30*time.Second {
		errs = append(errs, errors.New("SERVER_CACHE_TTL must be at most 30s (health must stay fresh)"))
	}
	if c.DB.MaxIdle > c.DB.MaxOpen {
		c.DB.MaxIdle = c.DB.MaxOpen
	}
	if c.DebugAddr != "" && !loopbackAddr(c.DebugAddr) {
		errs = append(errs, errors.New("DEBUG_ADDR must be a loopback host:port (e.g. 127.0.0.1:6060)"))
	}
	if c.BillingSecret != "" && c.BillingSecret == c.ProberSecret {
		errs = append(errs, errors.New("BILLING_SERVICE_SECRET and PROBER_SERVICE_SECRET must differ"))
	}
	return c, errors.Join(errs...)
}

func loopbackAddr(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

func def(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
