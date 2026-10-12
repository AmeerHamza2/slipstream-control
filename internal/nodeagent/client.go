// Package nodeagent is the control-plane process that runs on every VPN node.
//
// It has two jobs:
//
//  1. Keep the node's WireGuard peer list equal to what the api says this node
//     should accept. The api is the gatekeeper (who is entitled, which nodes a
//     device was issued); the node enforces it. A user whose subscription ends
//     drops out of the peer list, the agent removes the peer, and the next
//     handshake from that device simply never completes.
//  2. Serve the health endpoints the fleet prober measures: a UDP echo port
//     beside the WireGuard port (WireGuard itself never answers
//     unauthenticated packets) and an HTTP /load endpoint.
//
// Sync follows docs/CONTRACT.md "Node agent peer sync": a paged full sync at
// start-up, then incremental `?since=` syncs every interval, falling back to a
// full sync on 410 and periodically to repair drift.
//
// The agent fails static: if the api is unreachable it changes nothing on the
// interface. Tearing peers down because the control plane is having a bad
// minute would turn an api incident into a VPN outage for every user.
package nodeagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Peer is one WireGuard peer this node should accept, as the api serves it.
type Peer struct {
	DeviceID      string `json:"device_id"`
	PublicKey     string `json:"wg_public_key"`
	TunnelAddress string `json:"tunnel_address"`
	PresharedKey  string `json:"preshared_key"`
}

// Changes is an incremental sync response.
type Changes struct {
	Upserts   []Peer   `json:"upserts"`
	Removals  []string `json:"removals"` // device ids
	SyncToken string   `json:"sync_token"`
}

// Client errors.
var (
	// ErrResync means the sync token is too old (410): do a full sync.
	ErrResync = errors.New("nodeagent: sync token expired, full sync required")
	// ErrUnauthorized means the agent's token was rejected. Retrying will not
	// help until an operator fixes the credential, so it is logged loudly.
	ErrUnauthorized = errors.New("nodeagent: api rejected the agent token")
	// ErrUnknownServer means the api has no server with this id.
	ErrUnknownServer = errors.New("nodeagent: api does not know this server id")
)

// Client talks to the api's peer endpoints.
type Client struct {
	BaseURL  string // e.g. https://api.slipstream.example
	ServerID string
	Token    string
	HTTP     *http.Client
	// PageSize for full syncs. Default 1000.
	PageSize int
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) peersURL(q url.Values) string {
	u := strings.TrimRight(c.BaseURL, "/") + "/admin/v1/servers/" + url.PathEscape(c.ServerID) + "/peers"
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return u
}

// maxPeerBody bounds one response. A page of 10,000 peers is ~2.2 MB; 64 MiB
// leaves room for a full unpaged list on a very large node without letting a
// misbehaving api exhaust the agent's memory.
const maxPeerBody = 64 << 20

func (c *Client) get(ctx context.Context, q url.Values) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.peersURL(q), nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPeerBody+1))
	if err != nil {
		return nil, nil, err
	}
	if len(body) > maxPeerBody {
		return nil, nil, errors.New("nodeagent: peer response too large")
	}
	switch {
	case resp.StatusCode == http.StatusOK:
		return resp, body, nil
	case resp.StatusCode == http.StatusGone:
		return nil, nil, ErrResync
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, nil, ErrUnauthorized
	case resp.StatusCode == http.StatusNotFound:
		return nil, nil, ErrUnknownServer
	default:
		return nil, nil, fmt.Errorf("nodeagent: api returned HTTP %d", resp.StatusCode)
	}
}

// FullSync walks every page and returns all peers plus the sync token to use
// for the next incremental sync.
func (c *Client) FullSync(ctx context.Context) ([]Peer, string, error) {
	size := c.PageSize
	if size <= 0 {
		size = 1000
	}
	var (
		all    []Peer
		token  string
		cursor string
	)
	for page := 0; ; page++ {
		q := url.Values{"limit": {strconv.Itoa(size)}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		resp, body, err := c.get(ctx, q)
		if err != nil {
			return nil, "", err
		}
		var peers []Peer
		if err := json.Unmarshal(body, &peers); err != nil {
			return nil, "", fmt.Errorf("nodeagent: decoding peer page %d: %w", page, err)
		}
		all = append(all, peers...)
		if page == 0 {
			// Every page of one walk carries the first page's token, so
			// changes made while paging show up in the next incremental sync.
			token = resp.Header.Get("X-Sync-Token")
		}
		cursor = resp.Header.Get("X-Next-Cursor")
		if cursor == "" {
			break
		}
	}
	if token == "" {
		return nil, "", errors.New("nodeagent: api sent no X-Sync-Token")
	}
	return all, token, nil
}

// Changes fetches what changed since token.
func (c *Client) Changes(ctx context.Context, token string) (Changes, error) {
	_, body, err := c.get(ctx, url.Values{"since": {token}})
	if err != nil {
		return Changes{}, err
	}
	var ch Changes
	if err := json.Unmarshal(body, &ch); err != nil {
		return Changes{}, fmt.Errorf("nodeagent: decoding changes: %w", err)
	}
	if ch.SyncToken == "" {
		return Changes{}, errors.New("nodeagent: changes response has no sync_token")
	}
	return ch, nil
}
