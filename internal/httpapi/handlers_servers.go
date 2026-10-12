package httpapi

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ameerhamza2/slipstream-control/internal/crypto"
	"github.com/ameerhamza2/slipstream-control/internal/entitlements"
	"github.com/ameerhamza2/slipstream-control/internal/health"
	"github.com/ameerhamza2/slipstream-control/internal/ids"
	"github.com/ameerhamza2/slipstream-control/internal/store"
)

type publicServer struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Country   string   `json:"country"`
	City      string   `json:"city"`
	Protocols []string `json:"protocols"`
	Load      *float64 `json:"load"`
	Healthy   bool     `json:"healthy"`
}

// handlePublicServers serves the cached, pre-encoded fleet list. It
// supports If-None-Match (the app polls this list) and gzip (1,000 servers
// are ~150 KB of JSON and ~25 KB compressed).
func (s *Server) handlePublicServers(w http.ResponseWriter, r *http.Request) {
	snap, err := s.servers.get(r.Context())
	if err != nil {
		s.internalError(w, r, "list servers", err)
		return
	}
	h := w.Header()
	h.Set("ETag", snap.publicETag)
	h.Set("Vary", "Accept-Encoding")
	h.Set("Cache-Control", "private, no-cache")
	if etagMatch(r.Header.Get("If-None-Match"), snap.publicETag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Type", "application/json")
	body := snap.publicJSON
	if acceptsGzip(r) {
		h.Set("Content-Encoding", "gzip")
		body = snap.publicGzip
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func etagMatch(header, etag string) bool {
	if header == "" {
		return false
	}
	for _, t := range strings.Split(header, ",") {
		t = strings.TrimSpace(t)
		if t == "*" || strings.TrimPrefix(t, "W/") == etag {
			return true
		}
	}
	return false
}

func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		enc, params, _ := strings.Cut(part, ";")
		if !strings.EqualFold(strings.TrimSpace(enc), "gzip") {
			continue
		}
		for _, p := range strings.Split(params, ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
			if q, err := strconv.ParseFloat(strings.TrimSpace(v), 64); ok && strings.EqualFold(k, "q") && err == nil && q <= 0 {
				return false
			}
		}
		return true
	}
	return false
}

var serverNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type adminServerReq struct {
	Name           string `json:"name"`
	Country        string `json:"country"`
	City           string `json:"city"`
	PublicIPv4     string `json:"public_ipv4"`
	WGPort         int    `json:"wg_port"`
	WGPublicKey    string `json:"wg_public_key"`
	SSPort         int    `json:"ss_port"`
	SSMasterSecret string `json:"ss_master_secret"`
}

type adminServerResp struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Country        string `json:"country"`
	City           string `json:"city"`
	PublicIPv4     string `json:"public_ipv4"`
	WGPort         int    `json:"wg_port"`
	WGPublicKey    string `json:"wg_public_key"`
	SSPort         int    `json:"ss_port"`
	SSMasterSecret string `json:"ss_master_secret"`
	// AgentToken is the node-scoped token for this server's agent, present
	// when NODE_AGENT_SECRET is configured.
	AgentToken string    `json:"agent_token,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

func validatePublicIPv4(s string) (string, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return "", false
	}
	return a.String(), true
}

func (s *Server) handleAdminCreateServer(w http.ResponseWriter, r *http.Request) {
	var req adminServerReq
	if err := decodeJSON(r, &req, true, false); err != nil {
		writeDecodeError(w, r, err)
		return
	}
	req.Country = strings.ToUpper(strings.TrimSpace(req.Country))
	req.City = strings.TrimSpace(req.City)
	ip, ipOK := validatePublicIPv4(req.PublicIPv4)
	switch {
	case !serverNameRe.MatchString(req.Name):
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "name must be lowercase letters, digits and dashes (max 63)")
	case !countryRe.MatchString(req.Country):
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "country must be an ISO 3166-1 alpha-2 code")
	case !validName(req.City, 64):
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "city is required (max 64 chars)")
	case !ipOK:
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "public_ipv4 must be a routable IPv4 literal")
	// wg_port+1 is the node's UDP echo health port (prober contract).
	case req.WGPort < 1 || req.WGPort > 65534:
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "wg_port must be 1-65534 (wg_port+1 is the health echo port)")
	case req.SSPort < 1 || req.SSPort > 65535:
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "ss_port must be 1-65535")
	case !crypto.ValidWireGuardKey(req.WGPublicKey):
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "wg_public_key must be base64 of 32 bytes")
	case req.SSMasterSecret != "" && (len(req.SSMasterSecret) < 16 || len(req.SSMasterSecret) > 256):
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "ss_master_secret must be 16-256 characters")
	default:
		s.createServer(w, r, req, ip)
	}
}

func (s *Server) createServer(w http.ResponseWriter, r *http.Request, req adminServerReq, ip string) {
	if req.SSMasterSecret == "" {
		req.SSMasterSecret = crypto.RandomBase64(32)
	}
	id := ids.New()
	enc, err := s.keyring.Encrypt([]byte(req.SSMasterSecret), ssAAD(id))
	if err != nil {
		s.internalError(w, r, "encrypt ss secret", err)
		return
	}
	sv, err := s.store.CreateServer(r.Context(), store.Server{ID: id, Name: req.Name, Country: req.Country, City: req.City,
		PublicIPv4: ip, WGPort: req.WGPort, WGPublicKey: req.WGPublicKey, SSPort: req.SSPort, SSMasterSecretEnc: enc})
	if errors.Is(err, store.ErrServerName) {
		writeError(w, r, http.StatusConflict, CodeConflict, "a server with this name already exists")
		return
	}
	if err != nil {
		s.internalError(w, r, "create server", err)
		return
	}
	s.servers.invalidate()
	// The master secret is returned once, here, so the operator can
	// provision the node; it is only stored encrypted.
	w.Header().Set("Cache-Control", "no-store")
	resp := adminServerResp{ID: sv.ID, Name: sv.Name, Country: sv.Country, City: sv.City,
		PublicIPv4: sv.PublicIPv4, WGPort: sv.WGPort, WGPublicKey: sv.WGPublicKey, SSPort: sv.SSPort,
		SSMasterSecret: req.SSMasterSecret, CreatedAt: sv.CreatedAt.UTC()}
	if s.nodeAgentSecret != "" {
		resp.AgentToken = nodeToken(s.nodeAgentSecret, sv.ID)
	}
	writeJSON(w, http.StatusCreated, resp)
}

type peerView struct {
	DeviceID      string `json:"device_id"`
	WGPublicKey   string `json:"wg_public_key"`
	TunnelAddress string `json:"tunnel_address"`
	PresharedKey  string `json:"preshared_key"`
}

// Peer list paging limits.
const (
	defaultPeerPage = 1000
	maxPeerPage     = 10000
)

// handleAdminPeers is what a node agent pulls to configure WireGuard. Three
// modes, all backward compatible with the original unpaginated array:
//
//   - no query parameters: every peer, as before (fine for small nodes);
//   - ?limit=N[&cursor=C]: one page of at most N (default 1000, max 10000)
//     peers, keyset-paginated; X-Next-Cursor / Link rel="next" point at the
//     next page and are absent on the last one (a page may be short when
//     many owners are lapsed; only a missing cursor means the end);
//   - ?since=T: only what changed since sync token T, as
//     {"upserts": [...], "removals": [...], "sync_token": "..."}.
//
// Every 200 carries X-Sync-Token: the token to pass as since= next time. A
// paginated walk reports the token of its first page on every page, so
// changes made while the agent was paging are picked up by the next sync.
func (s *Server) handleAdminPeers(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(r.PathValue("id"))
	if !ids.Valid(id) {
		writeError(w, r, http.StatusNotFound, CodeNotFound, "server not found")
		return
	}
	q := r.URL.Query()
	_, hasLimit := q["limit"]
	_, hasCursor := q["cursor"]
	_, hasSince := q["since"]
	limit := 0
	if hasLimit {
		n, err := strconv.Atoi(q.Get("limit"))
		if err != nil || n < 1 || n > maxPeerPage {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "limit must be an integer between 1 and "+itoa(maxPeerPage))
			return
		}
		limit = n
	}
	var cur peerCursor
	if hasCursor {
		var ok bool
		if cur, ok = decodePeerCursor(q.Get("cursor")); !ok {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "cursor is invalid")
			return
		}
		if limit == 0 {
			limit = defaultPeerPage
		}
	}
	var since time.Time
	if hasSince {
		if hasLimit || hasCursor {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "since cannot be combined with limit or cursor")
			return
		}
		var ok bool
		if since, ok = decodeSyncToken(q.Get("since")); !ok {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "since must be a sync token from X-Sync-Token")
			return
		}
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
	if hasSince {
		s.peerChanges(w, r, id, since)
		return
	}
	token := cur.sync
	if cur.pos.IsZero() {
		// Taken before reading, so anything written during the walk is
		// newer than the token and shows up in the next incremental sync.
		t, err := s.store.DBNow(r.Context())
		if err != nil {
			s.internalError(w, r, "db clock", err)
			return
		}
		token = t
	}
	peers, next, more, err := s.store.ServerPeers(r.Context(), id, s.now(), cur.pos, limit)
	if err != nil {
		s.internalError(w, r, "list peers", err)
		return
	}
	out, ok := s.peerViews(w, r, id, peers)
	if !ok {
		return
	}
	w.Header().Set("X-Sync-Token", encodeSyncToken(token))
	if limit > 0 && more {
		c := encodePeerCursor(peerCursor{pos: next, sync: token})
		w.Header().Set("X-Next-Cursor", c)
		w.Header().Set("Link", fmt.Sprintf(`</admin/v1/servers/%s/peers?limit=%d&cursor=%s>; rel="next"`, id, limit, c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) peerViews(w http.ResponseWriter, r *http.Request, serverID string, peers []store.Peer) ([]peerView, bool) {
	out := make([]peerView, 0, len(peers))
	for _, p := range peers {
		psk, err := s.keyring.Decrypt(p.PSKEnc, pskAAD(p.DeviceID, serverID))
		if err != nil {
			s.internalError(w, r, "decrypt psk", err)
			return nil, false
		}
		out = append(out, peerView{DeviceID: p.DeviceID, WGPublicKey: p.WGPublicKey, TunnelAddress: p.TunnelIP + "/32", PresharedKey: string(psk)})
	}
	return out, true
}

type peerChangesView struct {
	Upserts   []peerView `json:"upserts"`
	Removals  []string   `json:"removals"`
	SyncToken string     `json:"sync_token"`
}

func (s *Server) peerChanges(w http.ResponseWriter, r *http.Request, serverID string, since time.Time) {
	token, err := s.store.DBNow(r.Context())
	if err != nil {
		s.internalError(w, r, "db clock", err)
		return
	}
	if since.After(token.Add(5 * time.Minute)) {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "since is in the future")
		return
	}
	if token.Sub(since) > store.PeerTombstoneRetention-store.PeerSyncOverlap {
		writeError(w, r, http.StatusGone, CodeInvalidRequest, "sync token expired; do a full sync without since")
		return
	}
	ch, err := s.store.ServerPeerChanges(r.Context(), serverID, since, s.now())
	if err != nil {
		s.internalError(w, r, "peer changes", err)
		return
	}
	ups, ok := s.peerViews(w, r, serverID, ch.Upserts)
	if !ok {
		return
	}
	tok := encodeSyncToken(token)
	w.Header().Set("X-Sync-Token", tok)
	writeJSON(w, http.StatusOK, peerChangesView{Upserts: ups, Removals: ch.Removals, SyncToken: tok})
}

// Sync tokens and cursors are opaque to agents. Both are versioned so the
// encoding can change without breaking agents mid-walk.
type peerCursor struct {
	pos  store.PeerCursor
	sync time.Time
}

func encodeSyncToken(t time.Time) string {
	return "v1." + strconv.FormatInt(t.UnixMicro(), 36)
}

func decodeSyncToken(s string) (time.Time, bool) {
	v, ok := strings.CutPrefix(s, "v1.")
	if !ok || len(v) == 0 || len(v) > 16 {
		return time.Time{}, false
	}
	us, err := strconv.ParseInt(v, 36, 64)
	if err != nil || us <= 0 {
		return time.Time{}, false
	}
	return time.UnixMicro(us).UTC(), true
}

func encodePeerCursor(c peerCursor) string {
	raw := strconv.FormatInt(c.pos.IssuedAt.UnixMicro(), 36) + "." + c.pos.DeviceID + "." + strconv.FormatInt(c.sync.UnixMicro(), 36)
	return "c1." + base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodePeerCursor(s string) (peerCursor, bool) {
	v, ok := strings.CutPrefix(s, "c1.")
	if !ok || len(v) > 128 {
		return peerCursor{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return peerCursor{}, false
	}
	parts := strings.Split(string(raw), ".")
	if len(parts) != 3 || !ids.Valid(parts[1]) {
		return peerCursor{}, false
	}
	at, err1 := strconv.ParseInt(parts[0], 36, 64)
	sync, err2 := strconv.ParseInt(parts[2], 36, 64)
	if err1 != nil || err2 != nil || at <= 0 || sync <= 0 {
		return peerCursor{}, false
	}
	return peerCursor{pos: store.PeerCursor{IssuedAt: time.UnixMicro(at).UTC(), DeviceID: strings.ToLower(parts[1])}, sync: time.UnixMicro(sync).UTC()}, true
}

type internalServer struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	PublicIPv4 string `json:"public_ipv4"`
	WGPort     int    `json:"wg_port"`
	SSPort     int    `json:"ss_port"`
}

func (s *Server) handleInternalServers(w http.ResponseWriter, r *http.Request) {
	snap, err := s.servers.get(r.Context())
	if err != nil {
		s.internalError(w, r, "list servers", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(snap.internalJSON)
}

type heartbeatReq struct {
	ProberID   string    `json:"prober_id"`
	ObservedAt time.Time `json:"observed_at"`
	Results    []struct {
		ServerID  string   `json:"server_id"`
		Reachable *bool    `json:"reachable"`
		RTTp50    *float64 `json:"rtt_ms_p50"`
		RTTp95    *float64 `json:"rtt_ms_p95"`
		Loss      *float64 `json:"loss"`
		Load      *float64 `json:"load"`
	} `json:"results"`
}

const maxHeartbeatResults = 5000

func finiteIn(v *float64, lo, hi float64) bool {
	return v == nil || (!math.IsNaN(*v) && !math.IsInf(*v, 0) && *v >= lo && *v <= hi)
}

func (s *Server) handleHeartbeats(w http.ResponseWriter, r *http.Request) {
	var req heartbeatReq
	if err := decodeJSON(r, &req, false, false); err != nil {
		writeDecodeError(w, r, err)
		return
	}
	if req.ProberID == "" || len(req.ProberID) > 128 {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "prober_id is required")
		return
	}
	if req.ObservedAt.IsZero() {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "observed_at is required")
		return
	}
	if len(req.Results) > maxHeartbeatResults {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "too many results in one batch")
		return
	}
	results := make([]store.HeartbeatResult, 0, len(req.Results))
	for i, res := range req.Results {
		switch {
		case !ids.Valid(res.ServerID):
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "results["+itoa(i)+"].server_id must be a UUID")
			return
		case res.Reachable == nil:
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "results["+itoa(i)+"].reachable is required")
			return
		case !finiteIn(res.RTTp50, 0, 60000) || !finiteIn(res.RTTp95, 0, 60000):
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "results["+itoa(i)+"] rtt must be 0-60000 ms")
			return
		case !finiteIn(res.Loss, 0, 1) || !finiteIn(res.Load, 0, 1):
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "results["+itoa(i)+"] loss and load must be within 0..1")
			return
		}
		results = append(results, store.HeartbeatResult{ServerID: strings.ToLower(res.ServerID), Result: health.Result{
			Reachable: *res.Reachable, RTTp50: res.RTTp50, RTTp95: res.RTTp95, Loss: res.Loss, Load: res.Load}})
	}
	// Silence is measured on our clock (receipt time), not the prober's
	// observed_at, so prober clock skew cannot keep a dead server healthy.
	n, err := s.store.IngestHeartbeats(r.Context(), results, s.now())
	if err != nil {
		s.internalError(w, r, "ingest heartbeats", err)
		return
	}
	s.servers.invalidate()
	for _, res := range results {
		s.metrics.Heartbeats.Inc(boolLabel(res.Reachable))
	}
	writeJSON(w, http.StatusAccepted, map[string]int{"accepted": n})
}

func (s *Server) handleEntitlementEvent(w http.ResponseWriter, r *http.Request) {
	var e entitlements.Event
	if err := decodeJSON(r, &e, false, false); err != nil {
		writeDecodeError(w, r, err)
		return
	}
	e.UserID = strings.ToLower(e.UserID)
	if err := e.Validate(); err != nil {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, err.Error())
		return
	}
	applied, reason, err := s.store.ApplyEntitlementEvent(r.Context(), e)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, CodeNotFound, "user not found")
		return
	}
	if err != nil {
		s.internalError(w, r, "apply entitlement event", err)
		return
	}
	infoFrom(r.Context()).userID = e.UserID
	result := "applied"
	if !applied {
		result = reason
	}
	s.metrics.EntitlementEvents.Inc(e.Source, result)
	s.log.Info("entitlement event", "request_id", requestIDFrom(r.Context()), "user_id", e.UserID, "source", e.Source,
		"status", e.Status, "result", result)
	if applied {
		writeJSON(w, http.StatusOK, map[string]any{"applied": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"applied": false, "reason": reason})
}

func boolLabel(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func itoa(i int) string { return strconv.Itoa(i) }
