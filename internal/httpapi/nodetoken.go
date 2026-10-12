package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/ameerhamza2/slipstream-control/internal/ids"
	"github.com/ameerhamza2/slipstream-control/internal/store"
)

// Node agent tokens.
//
// Every VPN node runs an agent that pulls its own peer list. Handing each node
// the admin token would mean one compromised server could register servers and
// read every other node's peers and preshared keys. A node token is scoped to
// exactly one server: it can read that server's peers and nothing else.
//
// Tokens are derived, not stored: HMAC-SHA256(NODE_AGENT_SECRET,
// "node-agent:v1:" + server_id). There is no token table to leak or migrate,
// any replica can verify, and rotating NODE_AGENT_SECRET revokes every node
// token at once. The "v1" in both the prefix and the HMAC input lets the
// derivation change without ambiguity.
const nodeTokenPrefix = "nat1."

func nodeToken(secret, serverID string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("node-agent:v1:" + strings.ToLower(serverID)))
	return nodeTokenPrefix + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// requireAdminOrNode admits the admin token, or a node token for the server
// named in the path. It guards only the peers endpoint.
func (s *Server) requireAdminOrNode(next http.Handler) http.Handler {
	admin := s.requireAdmin(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := bearer(r)
		if ok && s.nodeAgentSecret != "" && strings.HasPrefix(tok, nodeTokenPrefix) {
			want := nodeToken(s.nodeAgentSecret, r.PathValue("id"))
			if subtle.ConstantTimeCompare([]byte(tok), []byte(want)) == 1 {
				next.ServeHTTP(w, r)
				return
			}
			writeError(w, r, http.StatusUnauthorized, CodeUnauthorized, "invalid node token")
			return
		}
		admin.ServeHTTP(w, r)
	})
}

// handleAdminAgentToken returns the node token for a server, for provisioning
// (or re-provisioning) its agent. Admin only.
func (s *Server) handleAdminAgentToken(w http.ResponseWriter, r *http.Request) {
	if s.nodeAgentSecret == "" {
		writeError(w, r, http.StatusConflict, CodeConflict, "node agent tokens are not configured (set NODE_AGENT_SECRET)")
		return
	}
	id := strings.ToLower(r.PathValue("id"))
	if !ids.Valid(id) {
		writeError(w, r, http.StatusNotFound, CodeNotFound, "server not found")
		return
	}
	if _, err := s.store.GetServer(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, CodeNotFound, "server not found")
			return
		}
		s.internalError(w, r, "load server", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"server_id": id, "agent_token": nodeToken(s.nodeAgentSecret, id)})
}
