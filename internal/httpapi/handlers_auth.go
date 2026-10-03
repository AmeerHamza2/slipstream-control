package httpapi

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"unicode/utf8"

	"github.com/ameerhamza2/slipstream-control/internal/auth"
	"github.com/ameerhamza2/slipstream-control/internal/entitlements"
	"github.com/ameerhamza2/slipstream-control/internal/ids"
	"github.com/ameerhamza2/slipstream-control/internal/store"
)

const (
	minPasswordLen = 12
	// Bound the argon2 input; long inputs are only a DoS vector.
	maxPasswordBytes = 1024
)

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func normalizeEmail(raw string) (string, bool) {
	e := strings.ToLower(strings.TrimSpace(raw))
	if e == "" || len(e) > 254 {
		return "", false
	}
	addr, err := mail.ParseAddress(e)
	if err != nil || addr.Address != e || addr.Name != "" || !strings.Contains(e[strings.LastIndexByte(e, '@')+1:], ".") {
		return "", false
	}
	return e, true
}

// readCredentials decodes and validates the body and applies the per-email
// limit (keyed by a hash of the normalised email, so Redis never stores it).
func (s *Server) readCredentials(w http.ResponseWriter, r *http.Request, checkStrength bool) (credentials, bool) {
	var c credentials
	if err := decodeJSON(r, &c, true, false); err != nil {
		writeDecodeError(w, r, err)
		return c, false
	}
	email, ok := normalizeEmail(c.Email)
	if !ok {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "email is invalid")
		return c, false
	}
	c.Email = email
	if len(c.Password) > maxPasswordBytes {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "password is too long")
		return c, false
	}
	if checkStrength && utf8.RuneCountInString(c.Password) < minPasswordLen {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "password must be at least 12 characters")
		return c, false
	}
	if c.Password == "" {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "password is required")
		return c, false
	}
	sum := sha256.Sum256([]byte(email))
	if !s.checkLimit(w, r, "auth_email", hexPrefix(sum[:]), s.limits.AuthPerEmail, failClosed) {
		return c, false
	}
	return c, true
}

func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) {
	c, ok := s.readCredentials(w, r, true)
	if !ok {
		return
	}
	hash, err := s.hasher.Hash(r.Context(), c.Password)
	if err != nil {
		s.internalError(w, r, "hash password", err)
		return
	}
	id := ids.New()
	if err := s.store.CreateUser(r.Context(), id, c.Email, hash); err != nil {
		if errors.Is(err, store.ErrEmailTaken) {
			writeError(w, r, http.StatusConflict, CodeConflict, "an account with this email already exists")
			return
		}
		s.internalError(w, r, "create user", err)
		return
	}
	infoFrom(r.Context()).userID = id
	writeJSON(w, http.StatusCreated, map[string]string{"user_id": id})
}

type tokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	c, ok := s.readCredentials(w, r, false)
	if !ok {
		return
	}
	u, err := s.store.UserByEmail(r.Context(), c.Email)
	if errors.Is(err, store.ErrNotFound) {
		// Equalise timing, and admission: when hashing is saturated an
		// unknown email gets the same 503 a known one would.
		if err := s.hasher.VerifyDummy(r.Context(), c.Password); err != nil {
			s.internalError(w, r, "verify password", err)
			return
		}
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "invalid email or password")
		return
	}
	if err != nil {
		s.internalError(w, r, "lookup user", err)
		return
	}
	match, err := s.hasher.Verify(r.Context(), c.Password, u.PasswordHash)
	if err != nil {
		s.internalError(w, r, "verify password", err)
		return
	}
	if !match {
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "invalid email or password")
		return
	}
	infoFrom(r.Context()).userID = u.ID
	if s.hasher.NeedsRehash(u.PasswordHash) {
		if h, err := s.hasher.Hash(r.Context(), c.Password); err == nil {
			_ = s.store.UpdatePasswordHash(r.Context(), u.ID, h)
		}
	}
	family := ids.New()
	refresh, hash := auth.NewRefreshToken()
	if err := s.store.CreateRefreshToken(r.Context(), ids.New(), u.ID, family, hash, s.now().Add(auth.RefreshTokenTTL)); err != nil {
		s.internalError(w, r, "create refresh token", err)
		return
	}
	s.writeTokens(w, r, u.ID, family, refresh)
}

func (s *Server) writeTokens(w http.ResponseWriter, r *http.Request, userID, family, refresh string) {
	access, exp, err := s.tokens.Issue(userID, family)
	if err != nil {
		s.internalError(w, r, "issue access token", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, tokenPair{AccessToken: access, RefreshToken: refresh, ExpiresIn: exp})
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := decodeJSON(r, &req, true, false); err != nil {
		writeDecodeError(w, r, err)
		return
	}
	if req.RefreshToken == "" || len(req.RefreshToken) > 128 {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "refresh_token is required")
		return
	}
	next, nextHash := auth.NewRefreshToken()
	userID, family, err := s.store.RotateRefreshToken(r.Context(), auth.HashRefreshToken(req.RefreshToken), nextHash, ids.New(), s.now())
	switch {
	case errors.Is(err, store.ErrTokenReused):
		infoFrom(r.Context()).userID = userID
		s.log.Warn("refresh token reuse detected; family revoked", "request_id", requestIDFrom(r.Context()), "user_id", userID, "family_id", family)
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "refresh token is no longer valid")
		return
	case errors.Is(err, store.ErrTokenInvalid):
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "refresh token is no longer valid")
		return
	case err != nil:
		s.internalError(w, r, "rotate refresh token", err)
		return
	}
	infoFrom(r.Context()).userID = userID
	s.writeTokens(w, r, userID, family, next)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	u, _ := userFrom(r.Context())
	if u.SessionID != "" && ids.Valid(u.SessionID) {
		if _, err := s.store.RevokeFamily(r.Context(), u.ID, u.SessionID, s.now()); err != nil {
			s.internalError(w, r, "revoke family", err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

type meResponse struct {
	UserID       string               `json:"user_id"`
	Email        string               `json:"email"`
	Plan         string               `json:"plan"`
	Entitlement  entitlements.Summary `json:"entitlement"`
	DevicesUsed  int                  `json:"devices_used"`
	DevicesLimit int                  `json:"devices_limit"`
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u, _ := userFrom(r.Context())
	user, err := s.store.UserByID(r.Context(), u.ID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "account no longer exists")
		return
	}
	if err != nil {
		s.internalError(w, r, "load user", err)
		return
	}
	ent, err := s.store.Entitlement(r.Context(), u.ID, s.now())
	if err != nil {
		s.internalError(w, r, "load entitlement", err)
		return
	}
	n, err := s.store.CountDevices(r.Context(), u.ID)
	if err != nil {
		s.internalError(w, r, "count devices", err)
		return
	}
	plan := ent.Plan()
	writeJSON(w, http.StatusOK, meResponse{
		UserID: user.ID, Email: user.Email, Plan: plan, Entitlement: ent,
		DevicesUsed: n, DevicesLimit: entitlements.DeviceLimit(plan),
	})
}
