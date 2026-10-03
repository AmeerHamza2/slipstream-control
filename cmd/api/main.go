// Command api is the Slipstream control-plane API server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/ameerhamza2/slipstream-control/api"
	"github.com/ameerhamza2/slipstream-control/internal/auth"
	"github.com/ameerhamza2/slipstream-control/internal/config"
	"github.com/ameerhamza2/slipstream-control/internal/crypto"
	"github.com/ameerhamza2/slipstream-control/internal/httpapi"
	"github.com/ameerhamza2/slipstream-control/internal/metrics"
	"github.com/ameerhamza2/slipstream-control/internal/ratelimit"
	"github.com/ameerhamza2/slipstream-control/internal/store"
	"github.com/ameerhamza2/slipstream-control/internal/svcauth"
)

func main() {
	migrate := flag.Bool("migrate", true, "apply pending database migrations on start")
	migrateOnly := flag.Bool("migrate-only", false, "apply migrations and exit")
	flag.Parse()

	if err := run(*migrate || *migrateOnly, *migrateOnly); err != nil {
		slog.Error("fatal", "error", err.Error())
		os.Exit(1)
	}
}

func run(migrate, migrateOnly bool) error {
	cfg, err := config.FromEnv()
	log := newLogger(cfg.LogLevel)
	slog.SetDefault(log)
	if err != nil {
		return fmt.Errorf("config: %w", err) // messages name variables, never values
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := store.OpenPool(ctx, cfg.DatabaseURL, store.Pool{MaxOpen: cfg.DB.MaxOpen, MaxIdle: cfg.DB.MaxIdle,
		MaxLifetime: cfg.DB.MaxLifetime, MaxIdleTime: cfg.DB.MaxIdleTime})
	if err != nil {
		return err
	}
	defer st.Close()
	if migrate {
		applied, err := st.Migrate(ctx)
		if err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		log.Info("migrations complete", "applied", applied)
		if migrateOnly {
			return nil
		}
	}

	ropt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return errors.New("config: REDIS_URL is not a valid redis URL")
	}
	ropt.DialTimeout, ropt.ReadTimeout, ropt.WriteTimeout = cfg.Redis.DialTimeout, cfg.Redis.ReadTimeout, cfg.Redis.ReadTimeout
	// A request waits at most PoolTimeout for a free connection, and
	// per-call context deadlines are honoured, so a slow or dead Redis turns
	// into the contract's fail-open/fail-closed behaviour in bounded time.
	ropt.PoolTimeout, ropt.ContextTimeoutEnabled = cfg.Redis.PoolTimeout, true
	ropt.MinIdleConns = cfg.Redis.MinIdleConns
	if cfg.Redis.PoolSize > 0 {
		ropt.PoolSize = cfg.Redis.PoolSize
	}
	rdb := redis.NewClient(ropt)
	defer rdb.Close()
	if err := rdb.Ping(ctx).Err(); err != nil {
		// Not fatal: the rate limiter degrades per the contract.
		log.Warn("redis unreachable at startup", "error", err.Error())
	}

	keyring, err := crypto.NewKeyringFromBase64(cfg.DataEncryptionKey)
	if err != nil {
		return err
	}
	tokens, err := auth.NewTokenIssuer(cfg.JWTSigningSeed, cfg.JWTPreviousKeys)
	if err != nil {
		return err
	}
	log.Info("jwt signing key loaded", "kid", tokens.KeyID())

	srv := httpapi.New(httpapi.Deps{
		Store:   st,
		Redis:   rdb,
		Limiter: ratelimit.NewRedis(rdb, "rl:"),
		Tokens:  tokens,
		Hasher: auth.NewHasherWithLimits(auth.DefaultArgon2Params, auth.HashLimits{
			Concurrency: cfg.Argon2.Concurrency, Queue: cfg.Argon2.Queue, QueueTimeout: cfg.Argon2.QueueTimeout}),
		Keyring: keyring,
		ServiceAuth: svcauth.NewVerifier(map[string][]byte{
			svcauth.ServiceBilling: []byte(cfg.BillingSecret),
			svcauth.ServiceProber:  []byte(cfg.ProberSecret),
		}),
		AdminToken:     cfg.AdminToken,
		Metrics:        metrics.NewApp(),
		Logger:         log,
		TrustedProxies: cfg.TrustedProxies,
		Limits:         httpapi.DefaultLimits,
		OpenAPI:        api.OpenAPI,
		ServerCacheTTL: cacheTTL(cfg.ServerCacheTTL),
		RequestTimeout: cfg.RequestTimeout,
	})

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	go janitor(ctx, st, log)
	if cfg.DebugAddr != "" {
		go serveDebug(ctx, cfg.DebugAddr, log)
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.ListenAddr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	srv.Drain()
	if cfg.DrainDelay > 0 {
		log.Info("draining", "delay", cfg.DrainDelay.String())
		time.Sleep(cfg.DrainDelay)
	}
	log.Info("shutting down", "timeout", cfg.ShutdownTimeout.String())
	sctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := httpSrv.Shutdown(sctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Info("stopped")
	return nil
}

// janitor runs on every replica. Each tick (every few minutes, jittered)
// tries to take the janitor lease for an hour; the replica that gets it does
// the pass, so cleanup happens hourly across the fleet however many
// replicas there are.
func janitor(ctx context.Context, st *store.Store, log *slog.Logger) {
	const every = time.Hour
	host, _ := os.Hostname()
	holder := fmt.Sprintf("%s/%d/%x", host, os.Getpid(), rand.Uint32())
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(4*60+rand.IntN(120)) * time.Second):
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		stats, ran, err := st.Cleanup(cctx, time.Now(), holder, every)
		cancel()
		switch {
		case err != nil:
			log.Warn("cleanup failed", "error", err.Error())
		case ran:
			log.Info("cleanup done", "expired_tokens", stats.ExpiredTokens, "revoked_tokens", stats.RevokedTokens, "peer_tombstones", stats.Tombstones)
		}
	}
}

// serveDebug exposes net/http/pprof on a loopback-only listener (enforced
// by config). Never route it through the public listener.
func serveDebug(ctx context.Context, addr string, log *slog.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	log.Warn("debug listener enabled", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("debug listener", "error", err.Error())
	}
}

// cacheTTL maps the config value (0 = disabled) onto httpapi's convention
// (0 = default, negative = disabled).
func cacheTTL(d time.Duration) time.Duration {
	if d == 0 {
		return -1
	}
	return d
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}
