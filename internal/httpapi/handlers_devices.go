package httpapi

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ameerhamza2/slipstream-control/internal/crypto"
	"github.com/ameerhamza2/slipstream-control/internal/entitlements"
	"github.com/ameerhamza2/slipstream-control/internal/health"
	"github.com/ameerhamza2/slipstream-control/internal/ids"
	"github.com/ameerhamza2/slipstream-control/internal/ipam"
	"github.com/ameerhamza2/slipstream-control/internal/selection"
	"github.com/ameerhamza2/slipstream-control/internal/store"
)

const (
	configServerCount = 3
	wgKeepalive       = 25
	tunnelMTU         = 1420
	ssMethod          = "chacha20-ietf-poly1305"
)

var countryRe = regexp.MustCompile(`^[A-Z]{2}$`)

type deviceView struct {
	DeviceID      string    `json:"device_id"`
	Name          string    `json:"name"`
	Platform      string    `json:"platform"`
	WGPublicKey   string    `json:"wg_public_key"`
	TunnelAddress string    `json:"tunnel_address"`
	CreatedAt     time.Time `json:"created_at"`
}

func toDeviceView(d store.Device) deviceView {
	return deviceView{DeviceID: d.ID, Name: d.Name, Platform: d.Platform, WGPublicKey: d.WGPublicKey,
		TunnelAddress: ipam.Prefix(d.TunnelIP), CreatedAt: d.CreatedAt.UTC()}
}

func validName(s string, max int) bool {
	n := utf8.RuneCountInString(s)
	if n == 0 || n > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (s *Server) handleCreateDevice(w http.ResponseWriter, r *http.Request) {
	u, _ := userFrom(r.Context())
	var req struct {
		Name        string `json:"name"`
		Platform    string `json:"platform"`
		WGPublicKey string `json:"wg_public_key"`
	}
	if err := decodeJSON(r, &req, true, false); err != nil {
		writeDecodeError(w, r, err)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	switch {
	case !validName(req.Name, 64):
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "name must be 1-64 printable characters")
		return
	case req.Platform != "android" && req.Platform != "ios":
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, `platform must be "android" or "ios"`)
		return
	case !crypto.ValidWireGuardKey(req.WGPublicKey):
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "wg_public_key must be base64 of a 32-byte Curve25519 key")
		return
	}
	ent, err := s.store.Entitlement(r.Context(), u.ID, s.now())
	if err != nil {
		s.internalError(w, r, "load entitlement", err)
		return
	}
	limit := entitlements.DeviceLimit(ent.Plan())
	if limit == 0 {
		// Free plan: 0 devices. This is a paywall, not a policy denial, so
		// the app can route straight to the purchase flow.
		writeError(w, r, http.StatusPaymentRequired, CodePaymentRequired, "a premium subscription is required to add devices")
		return
	}
	d, err := s.store.CreateDevice(r.Context(), store.Device{
		ID: ids.New(), UserID: u.ID, Name: req.Name, Platform: req.Platform, WGPublicKey: req.WGPublicKey,
	}, limit)
	switch {
	case errors.Is(err, store.ErrDeviceLimit):
		writeError(w, r, http.StatusForbidden, CodeForbidden, fmt.Sprintf("device limit reached (%d); remove a device first", limit))
		return
	case errors.Is(err, store.ErrDeviceKeyTaken):
		writeError(w, r, http.StatusConflict, CodeConflict, "this WireGuard public key is already registered")
		return
	case errors.Is(err, store.ErrPoolExhausted):
		// Every tunnel address is in use. Not the client's fault and not a
		// bug; it clears when devices are removed or the pool is extended.
		s.metrics.Shed.Inc("ipam_exhausted")
		s.log.Error("tunnel address pool exhausted", "request_id", requestIDFrom(r.Context()))
		w.Header().Set("Retry-After", "300")
		writeError(w, r, http.StatusServiceUnavailable, CodeInternal, "no tunnel addresses available, retry later")
		return
	case errors.Is(err, store.ErrAllocContention):
		s.unavailable(w, r, "ipam_contention", "create device", err)
		return
	case err != nil:
		s.internalError(w, r, "create device", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"device_id": d.ID, "tunnel_address": ipam.Prefix(d.TunnelIP)})
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	u, _ := userFrom(r.Context())
	ds, err := s.store.ListDevices(r.Context(), u.ID)
	if err != nil {
		s.internalError(w, r, "list devices", err)
		return
	}
	out := make([]deviceView, 0, len(ds))
	for _, d := range ds {
		out = append(out, toDeviceView(d))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	u, _ := userFrom(r.Context())
	id := r.PathValue("id")
	if !ids.Valid(id) {
		writeError(w, r, http.StatusNotFound, CodeNotFound, "device not found")
		return
	}
	if err := s.store.DeleteDevice(r.Context(), u.ID, strings.ToLower(id)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, CodeNotFound, "device not found")
			return
		}
		s.internalError(w, r, "delete device", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// tunnelEntry is one element of the TunnelCore "servers" array. WireGuard
// and Shadowsocks entries share the type; omitempty drops the other
// protocol's fields so each entry has exactly the contract's keys.
type tunnelEntry struct {
	Name             string `json:"name"`
	Protocol         string `json:"protocol"`
	Endpoint         string `json:"endpoint"`
	PublicKey        string `json:"public_key,omitempty"`
	PresharedKey     string `json:"preshared_key,omitempty"`
	KeepaliveSeconds int    `json:"keepalive_seconds,omitempty"`
	Method           string `json:"method,omitempty"`
	Password         string `json:"password,omitempty"`
}

type tunnelConfig struct {
	Servers         []tunnelEntry `json:"servers"`
	TunnelAddresses []string      `json:"tunnel_addresses"`
	DNSServers      []string      `json:"dns_servers"`
	MTU             int           `json:"mtu"`
}

func pskAAD(deviceID, serverID string) []byte { return []byte("psk:" + deviceID + ":" + serverID) }
func ssAAD(serverID string) []byte            { return []byte("ss_master:" + serverID) }

func (s *Server) handleDeviceConfig(w http.ResponseWriter, r *http.Request) {
	u, _ := userFrom(r.Context())
	id := r.PathValue("id")
	if !ids.Valid(id) {
		writeError(w, r, http.StatusNotFound, CodeNotFound, "device not found")
		return
	}
	var req struct {
		Country string `json:"country"`
	}
	if err := decodeJSON(r, &req, true, true); err != nil {
		writeDecodeError(w, r, err)
		return
	}
	country := strings.ToUpper(strings.TrimSpace(req.Country))
	if country != "" && !countryRe.MatchString(country) {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "country must be an ISO 3166-1 alpha-2 code")
		return
	}
	dev, err := s.store.GetDevice(r.Context(), u.ID, strings.ToLower(id))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, CodeNotFound, "device not found")
		return
	}
	if err != nil {
		s.internalError(w, r, "load device", err)
		return
	}
	now := s.now()
	ent, err := s.store.Entitlement(r.Context(), u.ID, now)
	if err != nil {
		s.internalError(w, r, "load entitlement", err)
		return
	}
	if !ent.Active {
		writeError(w, r, http.StatusPaymentRequired, CodePaymentRequired, "an active subscription is required")
		return
	}
	snap, err := s.servers.get(r.Context())
	if err != nil {
		s.internalError(w, r, "list servers", err)
		return
	}
	// Same result as selection.Rank over the fleet, without re-sorting it
	// per request; the 90 s silence rule is applied here, on this request's clock.
	ranked := snap.ranking.Top(country, configServerCount, func(c selection.Candidate) bool {
		return health.Effective(snap.byID[c.ID].Health, now)
	})
	if len(ranked) == 0 {
		w.Header().Set("Retry-After", "30")
		writeError(w, r, http.StatusServiceUnavailable, CodeInternal, "no healthy servers available")
		return
	}
	serverIDs := make([]string, len(ranked))
	for i, c := range ranked {
		serverIDs[i] = c.ID
	}
	psks, err := s.store.EnsurePresharedKeys(r.Context(), dev.ID, serverIDs, func(serverID string) (string, error) {
		return s.keyring.Encrypt([]byte(crypto.GeneratePresharedKey()), pskAAD(dev.ID, serverID))
	})
	if err != nil {
		s.internalError(w, r, "ensure preshared keys", err)
		return
	}
	cfg := tunnelConfig{
		Servers:         make([]tunnelEntry, 0, 2*len(ranked)),
		TunnelAddresses: []string{ipam.Prefix(dev.TunnelIP)},
		DNSServers:      []string{ipam.DNS.String()},
		MTU:             tunnelMTU,
	}
	for _, c := range ranked {
		sv := snap.byID[c.ID]
		// A row that fails to decrypt (a server registered under a different
		// DATA_ENCRYPTION_KEY, a botched key rotation, a corrupted row) costs
		// that one server, not config issuance for every user: it is skipped,
		// logged without the ciphertext, and counted so it pages someone.
		psk, err := s.keyring.Decrypt(psks[sv.ID], pskAAD(dev.ID, sv.ID))
		if err != nil {
			s.skipUndecryptable(r, "psk", sv.ID, err)
			continue
		}
		master, err := s.keyring.Decrypt(sv.SSMasterSecretEnc, ssAAD(sv.ID))
		if err != nil {
			s.skipUndecryptable(r, "ss_master_secret", sv.ID, err)
			continue
		}
		cfg.Servers = append(cfg.Servers,
			tunnelEntry{Name: sv.Name, Protocol: "wireguard", Endpoint: net.JoinHostPort(sv.PublicIPv4, strconv.Itoa(sv.WGPort)),
				PublicKey: sv.WGPublicKey, PresharedKey: string(psk), KeepaliveSeconds: wgKeepalive},
			tunnelEntry{Name: sv.Name + "-ss", Protocol: "shadowsocks", Endpoint: net.JoinHostPort(sv.PublicIPv4, strconv.Itoa(sv.SSPort)),
				Method: ssMethod, Password: crypto.ShadowsocksPassword(master, u.ID)},
		)
	}
	if len(cfg.Servers) == 0 {
		w.Header().Set("Retry-After", "30")
		writeError(w, r, http.StatusServiceUnavailable, CodeInternal, "no usable servers available")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) skipUndecryptable(r *http.Request, kind, serverID string, err error) {
	s.metrics.SecretDecryptFail.Inc(kind)
	s.log.Error("skipping server: stored secret failed to decrypt",
		"request_id", requestIDFrom(r.Context()), "server_id", serverID, "kind", kind, "error", err.Error())
}
