package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ameerhamza2/slipstream-control/internal/svcauth"
)

type authUser struct {
	ID        string
	SessionID string
}

func userFrom(ctx context.Context) (authUser, error) {
	u, ok := ctx.Value(keyUser).(authUser)
	if !ok {
		return authUser{}, errNoUser
	}
	return u, nil
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return "", false
	}
	return strings.TrimSpace(h[len(p):]), true
}

// requireUser authenticates an EdDSA access token.
func (s *Server) requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := bearer(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="slipstream"`)
			writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "missing bearer token")
			return
		}
		claims, err := s.tokens.Verify(tok)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="slipstream", error="invalid_token"`)
			writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "invalid or expired access token")
			return
		}
		infoFrom(r.Context()).userID = claims.Subject
		ctx := context.WithValue(r.Context(), keyUser, authUser{ID: claims.Subject, SessionID: claims.SessionID})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireAdmin checks the static admin bearer token. Both sides are hashed
// first so the constant-time compare does not leak the token length.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	want := sha256.Sum256([]byte(s.adminToken))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := bearer(r)
		got := sha256.Sum256([]byte(tok))
		if !ok || s.adminToken == "" || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "invalid admin token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireService verifies HMAC service signatures and that the caller is one
// of the services allowed on this route (billing cannot post heartbeats and
// the prober cannot grant entitlements). The body is read once (bounded by
// limitBody), verified, and replayed to the handler.
func (s *Server) requireService(allowed ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				var maxErr *http.MaxBytesError
				if errors.As(err, &maxErr) {
					writeError(w, r, http.StatusRequestEntityTooLarge, CodeInvalidRequest, "request body too large")
					return
				}
				writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "could not read body")
				return
			}
			svc := r.Header.Get(svcauth.HeaderService)
			if err := s.svc.Verify(svc, r.Header.Get(svcauth.HeaderTimestamp), r.Header.Get(svcauth.HeaderSignature), r.Method, r.URL.Path, body); err != nil {
				s.log.Warn("service auth failed", "request_id", requestIDFrom(r.Context()), "service", safeServiceName(svc), "reason", err.Error())
				writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "invalid service signature")
				return
			}
			if !slices.Contains(allowed, svc) {
				writeError(w, r, http.StatusForbidden, CodeForbidden, "service not allowed on this endpoint")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
		})
	}
}

func safeServiceName(s string) string {
	if s == svcauth.ServiceBilling || s == svcauth.ServiceProber {
		return s
	}
	return "unknown"
}

// limitMode is what to do when Redis is unavailable.
type limitMode int

const (
	failOpen limitMode = iota
	failClosed
)

// checkLimit applies one rate limit. It returns false if it has already
// written a response (429 or 503). The Redis call has a short deadline so a
// hung Redis degrades to the fail mode instead of stalling requests.
func (s *Server) checkLimit(w http.ResponseWriter, r *http.Request, scope, key string, limit int, mode limitMode) bool {
	ctx, cancel := context.WithTimeout(r.Context(), 250*time.Millisecond)
	defer cancel()
	d, err := s.limiter.Allow(ctx, scope+":"+key, limit, s.limits.Window)
	if err != nil {
		if mode == failClosed {
			s.metrics.RateLimitFailShut.Inc(scope)
			s.log.Error("rate limiter unavailable; failing closed", "request_id", requestIDFrom(r.Context()), "scope", scope, "error", err.Error())
			w.Header().Set("Retry-After", "1")
			writeError(w, r, http.StatusServiceUnavailable, CodeInternal, "temporarily unavailable, retry shortly")
			return false
		}
		s.metrics.RateLimitFailOpen.Inc(scope)
		s.log.Warn("rate limiter unavailable; failing open", "request_id", requestIDFrom(r.Context()), "scope", scope)
		return true
	}
	if !d.Allowed {
		s.metrics.RateLimitRejected.Inc(scope)
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(d.RetryAfter.Seconds()))))
		writeError(w, r, http.StatusTooManyRequests, CodeRateLimited, "rate limit exceeded")
		return false
	}
	return true
}

// limitIP is middleware limiting by client IP.
func (s *Server) limitIP(scope string, limit int, mode limitMode) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The IP is hashed into the key: Redis never holds raw addresses.
			sum := sha256.Sum256([]byte(s.clientIP(r)))
			if !s.checkLimit(w, r, scope, hexPrefix(sum[:]), limit, mode) {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// limitUser is middleware limiting by authenticated user (after requireUser).
func (s *Server) limitUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := userFrom(r.Context())
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "unauthenticated")
			return
		}
		if !s.checkLimit(w, r, "user", u.ID, s.limits.PerUser, failOpen) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func hexPrefix(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, 32)
	for _, c := range b[:16] {
		out = append(out, hexdigits[c>>4], hexdigits[c&15])
	}
	return string(out)
}
