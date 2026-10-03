// Package httpapi is the HTTP layer of the control plane: routing,
// middleware and handlers for the public, admin and internal APIs.
package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/ameerhamza2/slipstream-control/internal/auth"
	"github.com/ameerhamza2/slipstream-control/internal/crypto"
	"github.com/ameerhamza2/slipstream-control/internal/metrics"
	"github.com/ameerhamza2/slipstream-control/internal/ratelimit"
	"github.com/ameerhamza2/slipstream-control/internal/store"
	"github.com/ameerhamza2/slipstream-control/internal/svcauth"
)

// Limits are the rate limits (defaults from the contract).
type Limits struct {
	AuthPerIP    int // signup + login, per client IP
	AuthPerEmail int // signup + login, per email hash
	RefreshPerIP int // refresh has no user yet; limited per IP instead
	PerUser      int // every other authenticated endpoint
	Window       time.Duration
}

// DefaultLimits are the contract's limits.
var DefaultLimits = Limits{AuthPerIP: 10, AuthPerEmail: 5, RefreshPerIP: 120, PerUser: 120, Window: time.Minute}

const (
	maxBodyDefault   = 64 << 10
	maxBodyHeartbeat = 1 << 20
)

// Deps are the server's collaborators.
type Deps struct {
	Store          *store.Store
	Redis          redis.UniversalClient
	Limiter        ratelimit.Limiter
	Tokens         *auth.TokenIssuer
	Hasher         *auth.Hasher
	Keyring        *crypto.Keyring
	ServiceAuth    *svcauth.Verifier
	AdminToken     string
	Metrics        *metrics.App
	Logger         *slog.Logger
	TrustedProxies []netip.Prefix
	Limits         Limits
	OpenAPI        []byte
	Now            func() time.Time
	// ServerCacheTTL is the lifetime of the in-process server list snapshot
	// (0 = default 2 s, negative = disabled).
	ServerCacheTTL time.Duration
	// RequestTimeout bounds each request's context, and with it every
	// DB and Redis call the request makes (0 = default 10 s).
	RequestTimeout time.Duration
}

// Defaults for Deps fields left zero.
const (
	DefaultServerCacheTTL = 2 * time.Second
	DefaultRequestTimeout = 10 * time.Second
)

// Server is the HTTP API.
type Server struct {
	store          *store.Store
	redis          redis.UniversalClient
	limiter        ratelimit.Limiter
	tokens         *auth.TokenIssuer
	hasher         *auth.Hasher
	keyring        *crypto.Keyring
	svc            *svcauth.Verifier
	adminToken     string
	metrics        *metrics.App
	log            *slog.Logger
	trustedProxies []netip.Prefix
	limits         Limits
	openapi        []byte
	jwks           []byte
	now            func() time.Time
	servers        *serverCache
	reqTimeout     time.Duration
	draining       atomic.Bool

	mux     *http.ServeMux
	handler http.Handler
}

// New builds the server and its routes.
func New(d Deps) *Server {
	s := &Server{
		store: d.Store, redis: d.Redis, limiter: d.Limiter, tokens: d.Tokens, hasher: d.Hasher, keyring: d.Keyring,
		svc: d.ServiceAuth, adminToken: d.AdminToken, metrics: d.Metrics, log: d.Logger, trustedProxies: d.TrustedProxies,
		limits: d.Limits, openapi: d.OpenAPI, now: d.Now, mux: http.NewServeMux(),
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.limits == (Limits{}) {
		s.limits = DefaultLimits
	}
	if s.metrics == nil {
		s.metrics = metrics.NewApp()
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	ttl := d.ServerCacheTTL
	if ttl == 0 {
		ttl = DefaultServerCacheTTL
	}
	s.servers = &serverCache{ttl: ttl, now: s.now, load: s.store.ListServers}
	s.reqTimeout = d.RequestTimeout
	if s.reqTimeout <= 0 {
		s.reqTimeout = DefaultRequestTimeout
	}
	s.jwks = s.tokens.JWKSJSON()
	s.routes()
	s.handler = s.observe(s.recoverer(http.HandlerFunc(s.dispatch)))
	return s
}

// Drain makes /readyz report 503 so load balancers stop sending new
// requests while in-flight ones finish (call it before http.Server.Shutdown).
func (s *Server) Drain() { s.draining.Store(true) }

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

type mw = func(http.Handler) http.Handler

// handle registers pattern. Middlewares run in the order given, and the
// pattern itself becomes the low-cardinality "route" metric/log label.
func (s *Server) handle(pattern string, h http.HandlerFunc, mws ...mw) {
	var next http.Handler = h
	for i := len(mws) - 1; i >= 0; i-- {
		next = mws[i](next)
	}
	inner := next
	s.mux.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		infoFrom(r.Context()).route = pattern
		ctx, cancel := context.WithTimeout(r.Context(), s.reqTimeout)
		defer cancel()
		inner.ServeHTTP(w, r.WithContext(ctx))
	}))
}

func body(n int64) mw { return func(h http.Handler) http.Handler { return limitBody(n, h) } }

func (s *Server) routes() {
	authIP := s.limitIP("auth_ip", s.limits.AuthPerIP, failClosed)
	user := []mw{s.requireUser, s.limitUser, body(maxBodyDefault)}

	// Ops.
	s.handle("GET /healthz", s.handleHealthz)
	s.handle("GET /readyz", s.handleReadyz)
	s.handle("GET /metrics", s.metrics.Registry.Handler().ServeHTTP)
	s.handle("GET /openapi.yaml", s.handleOpenAPI)
	s.handle("GET /.well-known/jwks.json", s.handleJWKS)

	// Public, app-facing.
	s.handle("POST /v1/auth/signup", s.handleSignup, authIP, body(maxBodyDefault))
	s.handle("POST /v1/auth/login", s.handleLogin, authIP, body(maxBodyDefault))
	s.handle("POST /v1/auth/refresh", s.handleRefresh, s.limitIP("refresh_ip", s.limits.RefreshPerIP, failClosed), body(maxBodyDefault))
	s.handle("POST /v1/auth/logout", s.handleLogout, user...)
	s.handle("GET /v1/me", s.handleMe, user...)
	s.handle("GET /v1/servers", s.handlePublicServers, user...)
	s.handle("POST /v1/devices", s.handleCreateDevice, user...)
	s.handle("GET /v1/devices", s.handleListDevices, user...)
	s.handle("DELETE /v1/devices/{id}", s.handleDeleteDevice, user...)
	s.handle("POST /v1/devices/{id}/config", s.handleDeviceConfig, user...)

	// Admin.
	admin := []mw{s.requireAdmin, body(maxBodyDefault)}
	s.handle("POST /admin/v1/servers", s.handleAdminCreateServer, admin...)
	s.handle("GET /admin/v1/servers/{id}/peers", s.handleAdminPeers, admin...)

	// Internal, HMAC-signed service calls.
	s.handle("GET /internal/v1/servers", s.handleInternalServers, body(maxBodyDefault), s.requireService(svcauth.ServiceProber))
	s.handle("POST /internal/v1/servers/heartbeats", s.handleHeartbeats, body(maxBodyHeartbeat), s.requireService(svcauth.ServiceProber))
	s.handle("POST /internal/v1/entitlements", s.handleEntitlementEvent, body(maxBodyDefault), s.requireService(svcauth.ServiceBilling))
}
