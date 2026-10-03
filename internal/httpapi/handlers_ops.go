package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ameerhamza2/slipstream-control/internal/auth"
	"github.com/ameerhamza2/slipstream-control/internal/store"
)

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReadyz reports whether dependencies are reachable, so a load
// balancer stops routing to a replica that cannot reach Postgres or Redis.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	checks := map[string]string{"postgres": "ok", "redis": "ok"}
	ok := true
	if s.draining.Load() {
		checks["shutdown"], ok = "draining", false
	}
	if err := s.store.Ping(ctx); err != nil {
		checks["postgres"], ok = "unavailable", false
	}
	if s.redis == nil || s.redis.Ping(ctx).Err() != nil {
		checks["redis"], ok = "unavailable", false
	}
	status, code := "ok", http.StatusOK
	if !ok {
		status, code = "unavailable", http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{"status": status, "checks": checks})
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(s.openapi)
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(s.jwks)
}

// internalError logs the cause (never returned to the client) and writes a
// 500, or a 503 + Retry-After when the cause is transient: Postgres
// unreachable or timing out, the request deadline passing, or password
// hashing capacity saturated. A load balancer or client can retry those
// elsewhere; a 500 would say the request itself is broken.
func (s *Server) internalError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, auth.ErrBusy):
		s.unavailable(w, r, "argon2_saturated", op, err)
	case errors.Is(r.Context().Err(), context.Canceled):
		// The client went away (lib/pq reports this as "canceling statement
		// due to user request"); nobody reads this response.
		s.unavailable(w, r, "client_canceled", op, err)
	case errors.Is(r.Context().Err(), context.DeadlineExceeded):
		s.unavailable(w, r, "request_timeout", op, err)
	case store.IsUnavailable(err):
		s.unavailable(w, r, "db_unavailable", op, err)
	default:
		s.log.Error("internal error", "request_id", requestIDFrom(r.Context()), "op", op, "error", err.Error())
		writeError(w, r, http.StatusInternalServerError, CodeInternal, "internal error")
	}
}

func (s *Server) unavailable(w http.ResponseWriter, r *http.Request, reason, op string, err error) {
	s.metrics.Shed.Inc(reason)
	s.log.Warn("temporarily unavailable", "request_id", requestIDFrom(r.Context()), "op", op, "reason", reason, "error", err.Error())
	w.Header().Set("Retry-After", "1")
	writeError(w, r, http.StatusServiceUnavailable, CodeInternal, "temporarily unavailable, retry shortly")
}
