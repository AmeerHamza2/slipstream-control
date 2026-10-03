package config

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func valid() map[string]string {
	return map[string]string{
		"DATABASE_URL":           "postgres://x",
		"REDIS_URL":              "redis://x",
		"ADMIN_TOKEN":            strings.Repeat("a", 32),
		"BILLING_SERVICE_SECRET": strings.Repeat("b", 32),
		"PROBER_SERVICE_SECRET":  strings.Repeat("p", 32),
		"JWT_SIGNING_KEY":        base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"DATA_ENCRYPTION_KEY":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"TRUSTED_PROXY_CIDRS":    "10.0.0.0/8, 192.168.1.1/32",
	}
}

func TestLoad(t *testing.T) {
	c, err := Load(env(valid()))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":8080" || len(c.JWTSigningSeed) != 32 || len(c.TrustedProxies) != 2 {
		t.Fatalf("%+v", c)
	}
}

func TestLoadErrorsDoNotLeakSecrets(t *testing.T) {
	m := valid()
	m["ADMIN_TOKEN"] = "short-secret-value"
	m["JWT_SIGNING_KEY"] = "not-base64!!"
	delete(m, "REDIS_URL")
	_, err := Load(env(m))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"ADMIN_TOKEN", "JWT_SIGNING_KEY", "REDIS_URL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %s in %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "short-secret-value") || strings.Contains(err.Error(), "not-base64!!") {
		t.Fatal("error message leaks a secret")
	}
}

func TestCapacitySettings(t *testing.T) {
	c, err := Load(env(valid()))
	if err != nil {
		t.Fatal(err)
	}
	if c.DB != DefaultDBPool || c.RequestTimeout <= 0 || c.ServerCacheTTL != 2*time.Second || c.DebugAddr != "" {
		t.Fatalf("defaults: %+v", c)
	}
	m := valid()
	m["DB_MAX_OPEN_CONNS"] = "40"
	m["DB_CONN_MAX_LIFETIME"] = "10m"
	m["SERVER_CACHE_TTL"] = "0"
	m["ARGON2_MAX_CONCURRENCY"] = "3"
	m["DEBUG_ADDR"] = "127.0.0.1:6060"
	c, err = Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if c.DB.MaxOpen != 40 || c.DB.MaxIdle != 40 || c.DB.MaxLifetime != 10*time.Minute || c.ServerCacheTTL != 0 || c.Argon2.Concurrency != 3 {
		t.Fatalf("parsed: %+v", c)
	}
	for k, v := range map[string]string{
		"DB_MAX_OPEN_CONNS": "0", "REQUEST_TIMEOUT": "fast", "SERVER_CACHE_TTL": "5m",
		"DEBUG_ADDR": "0.0.0.0:6060", "ARGON2_MAX_QUEUE": "-1",
	} {
		m := valid()
		m[k] = v
		if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("%s=%q: err = %v", k, v, err)
		}
	}
}
