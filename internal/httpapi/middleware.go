package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

type ctxKey int

const (
	keyRequestID ctxKey = iota
	keyInfo
	keyUser
)

// reqInfo is a mutable per-request record shared by the outer access-log
// middleware and inner handlers (route pattern and user id for the log line).
type reqInfo struct {
	route  string
	userID string
}

func requestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(keyRequestID).(string)
	return id
}

func infoFrom(ctx context.Context) *reqInfo {
	if ri, ok := ctx.Value(keyInfo).(*reqInfo); ok {
		return ri
	}
	return &reqInfo{}
}

// validRequestID accepts caller-provided ids only if they are short and
// boring, so they cannot be used for log injection.
func validRequestID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == ':') {
			return false
		}
	}
	return true
}

func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// observe is the outermost middleware: request id, access log and metrics.
// The log line deliberately has no path, query, IP, user agent or headers:
// only the route pattern, status, timing and the (allowed) user id.
func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := r.Header.Get("X-Request-Id")
		if !validRequestID(id) {
			id = newRequestID()
		}
		w.Header().Set("X-Request-Id", id)
		info := &reqInfo{route: "unmatched"}
		ctx := context.WithValue(context.WithValue(r.Context(), keyRequestID, id), keyInfo, info)
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r.WithContext(ctx))
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		dur := time.Since(start)
		status := strconv.Itoa(sw.status)
		s.metrics.HTTPRequests.Inc(info.route, r.Method, status)
		s.metrics.HTTPDuration.Observe(dur.Seconds(), info.route, r.Method)
		attrs := []slog.Attr{
			slog.String("request_id", id),
			slog.String("method", r.Method),
			slog.String("route", info.route),
			slog.Int("status", sw.status),
			slog.Float64("duration_ms", float64(dur.Microseconds())/1000),
			slog.Int("bytes", sw.bytes),
		}
		if info.userID != "" {
			attrs = append(attrs, slog.String("user_id", info.userID))
		}
		level := slog.LevelInfo
		if sw.status >= 500 {
			level = slog.LevelError
		}
		s.log.LogAttrs(r.Context(), level, "http_request", attrs...)
	})
}

// recoverer turns panics into 500s with the error envelope.
func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				if p == http.ErrAbortHandler {
					panic(p)
				}
				s.log.Error("panic", "request_id", requestIDFrom(r.Context()), "panic", panicString(p), "stack", string(debug.Stack()))
				if sw, ok := w.(*statusWriter); !ok || sw.status == 0 {
					writeError(w, r, http.StatusInternalServerError, CodeInternal, "internal error")
				}
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func panicString(p any) string {
	switch v := p.(type) {
	case error:
		return v.Error()
	case string:
		return v
	}
	return "non-error panic"
}

// statusCapture swallows the ServeMux's own plain-text 404/405 responses so
// we can re-emit them as the JSON error envelope.
type statusCapture struct {
	header http.Header
	code   int
}

func (c *statusCapture) Header() http.Header         { return c.header }
func (c *statusCapture) Write(b []byte) (int, error) { return len(b), nil }
func (c *statusCapture) WriteHeader(code int)        { c.code = code }

// dispatch routes through the mux, converting its built-in 404/405/redirect
// responses into JSON envelopes.
func (s *Server) dispatch(w http.ResponseWriter, r *http.Request) {
	h, pattern := s.mux.Handler(r)
	if pattern != "" {
		s.mux.ServeHTTP(w, r)
		return
	}
	rec := &statusCapture{header: http.Header{}}
	h.ServeHTTP(rec, r)
	code := rec.code
	if code == 0 {
		code = http.StatusNotFound
	}
	if loc := rec.header.Get("Location"); loc != "" && code >= 300 && code < 400 {
		http.Redirect(w, r, loc, code)
		return
	}
	if allow := rec.header.Get("Allow"); allow != "" {
		w.Header().Set("Allow", allow)
	}
	msg := "no such endpoint"
	if code == http.StatusMethodNotAllowed {
		msg = "method not allowed"
	}
	writeError(w, r, code, codeForStatus(code), msg)
}

// limitBody caps request bodies.
func limitBody(n int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, n)
		next.ServeHTTP(w, r)
	})
}

// clientIP returns the caller's address. X-Forwarded-For is honoured only
// when the direct peer is a trusted proxy; we then walk the header right to
// left and take the first hop that is not itself a trusted proxy, which is
// the only entry a client cannot forge.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()
	if !s.trusted(peer) {
		return peer.String()
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		a = a.Unmap()
		if !s.trusted(a) {
			return a.String()
		}
	}
	return peer.String()
}

func (s *Server) trusted(a netip.Addr) bool {
	for _, p := range s.trustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

var errNoUser = errors.New("no authenticated user")
