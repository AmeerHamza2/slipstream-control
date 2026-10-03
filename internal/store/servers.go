package store

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"time"

	"github.com/lib/pq"

	"github.com/ameerhamza2/slipstream-control/internal/health"
)

// Server is a VPN node with its health state.
type Server struct {
	ID                string
	Name              string
	Country           string
	City              string
	PublicIPv4        string
	WGPort            int
	WGPublicKey       string
	SSPort            int
	SSMasterSecretEnc string
	CreatedAt         time.Time
	Health            health.State
}

// CreateServer inserts a server.
func (s *Store) CreateServer(ctx context.Context, sv Server) (Server, error) {
	err := s.db.QueryRowContext(ctx, `INSERT INTO servers (id, name, country, city, public_ipv4, wg_port, wg_public_key, ss_port, ss_master_secret_enc)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING created_at`,
		sv.ID, sv.Name, sv.Country, sv.City, sv.PublicIPv4, sv.WGPort, sv.WGPublicKey, sv.SSPort, sv.SSMasterSecretEnc).Scan(&sv.CreatedAt)
	if c, ok := uniqueViolation(err); ok && c == "servers_name_key" {
		return sv, ErrServerName
	}
	return sv, err
}

const serverCols = `id, name, country, city, host(public_ipv4), wg_port, wg_public_key, ss_port, ss_master_secret_enc, created_at,
	healthy, consecutive_reachable, consecutive_unreachable, last_heartbeat_at, rtt_ms_p50, rtt_ms_p95, loss, load`

func scanServer(sc interface{ Scan(...any) error }) (Server, error) {
	var sv Server
	var last sql.NullTime
	var p50, p95, loss, load sql.NullFloat64
	err := sc.Scan(&sv.ID, &sv.Name, &sv.Country, &sv.City, &sv.PublicIPv4, &sv.WGPort, &sv.WGPublicKey, &sv.SSPort, &sv.SSMasterSecretEnc, &sv.CreatedAt,
		&sv.Health.Healthy, &sv.Health.ConsecutiveReachable, &sv.Health.ConsecutiveUnreachable, &last, &p50, &p95, &loss, &load)
	sv.Health.LastHeartbeatAt = nullTime(last)
	sv.Health.RTTp50, sv.Health.RTTp95, sv.Health.Loss, sv.Health.Load = nullFloat(p50), nullFloat(p95), nullFloat(loss), nullFloat(load)
	return sv, err
}

// ListServers returns every server ordered by name.
func (s *Store) ListServers(ctx context.Context) ([]Server, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+serverCols+` FROM servers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Server{}
	for rows.Next() {
		sv, err := scanServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sv)
	}
	return out, rows.Err()
}

// GetServer returns one server.
func (s *Store) GetServer(ctx context.Context, id string) (Server, error) {
	sv, err := scanServer(s.db.QueryRowContext(ctx, `SELECT `+serverCols+` FROM servers WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return sv, ErrNotFound
	}
	return sv, err
}

// HeartbeatResult is one prober result addressed to a server.
type HeartbeatResult struct {
	ServerID string
	health.Result
}

// IngestHeartbeats folds a batch of results into server health in one
// transaction with two round trips regardless of batch size: one
// SELECT ... WHERE id = ANY(...) ORDER BY id FOR NO KEY UPDATE (rows locked in id
// order, so concurrent batches from several probers cannot deadlock), and one
// UPDATE ... FROM unnest(...). The original per-row SELECT/UPDATE pair cost
// 2,000 statements for a 1,000-server fleet and held every row lock for
// seconds. Unknown server ids are skipped; the number of results applied is
// returned. Several results for one server in a batch apply in order.
func (s *Store) IngestHeartbeats(ctx context.Context, results []HeartbeatResult, now time.Time) (int, error) {
	if len(results) == 0 {
		return 0, nil
	}
	ids := make([]string, 0, len(results))
	seen := make(map[string]bool, len(results))
	for _, r := range results {
		if !seen[r.ServerID] {
			seen[r.ServerID] = true
			ids = append(ids, r.ServerID)
		}
	}
	sort.Strings(ids)
	accepted := 0
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		accepted = 0
		// FOR NO KEY UPDATE, not FOR UPDATE: health columns are not keys,
		// and the weaker lock does not conflict with the KEY SHARE locks that
		// foreign-key checks take. With FOR UPDATE, every config issuance
		// inserting a preshared key (FK to servers) waited behind the batch,
		// and a multi-row insert could deadlock against it.
		rows, err := tx.QueryContext(ctx, `SELECT `+serverCols+` FROM servers WHERE id = ANY($1::uuid[]) ORDER BY id FOR NO KEY UPDATE`, pq.Array(ids))
		if err != nil {
			return err
		}
		states := make(map[string]health.State, len(ids))
		for rows.Next() {
			sv, err := scanServer(rows)
			if err != nil {
				rows.Close()
				return err
			}
			states[sv.ID] = sv.Health
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range results {
			st, ok := states[r.ServerID]
			if !ok {
				continue
			}
			states[r.ServerID] = health.Apply(st, r.Result, now)
			accepted++
		}
		if len(states) == 0 {
			return nil
		}
		var (
			uid                   []string
			healthy               []bool
			reach, unreach        []int64
			p50, p95, loss, loads []sql.NullFloat64
		)
		nf := func(f *float64) sql.NullFloat64 {
			if f == nil {
				return sql.NullFloat64{}
			}
			return sql.NullFloat64{Float64: *f, Valid: true}
		}
		for id, st := range states {
			uid = append(uid, id)
			healthy = append(healthy, st.Healthy)
			reach, unreach = append(reach, int64(st.ConsecutiveReachable)), append(unreach, int64(st.ConsecutiveUnreachable))
			p50, p95 = append(p50, nf(st.RTTp50)), append(p95, nf(st.RTTp95))
			loss, loads = append(loss, nf(st.Loss)), append(loads, nf(st.Load))
		}
		_, err = tx.ExecContext(ctx, `UPDATE servers AS s SET healthy = v.healthy, consecutive_reachable = v.reach,
				consecutive_unreachable = v.unreach, last_heartbeat_at = $2, rtt_ms_p50 = v.p50, rtt_ms_p95 = v.p95,
				loss = v.loss, load = v.load
			FROM unnest($1::uuid[], $3::bool[], $4::int[], $5::int[], $6::float8[], $7::float8[], $8::float8[], $9::float8[])
				AS v(id, healthy, reach, unreach, p50, p95, loss, load)
			WHERE s.id = v.id`,
			pq.Array(uid), now, pq.Array(healthy), pq.Array(reach), pq.Array(unreach),
			pq.GenericArray{A: p50}, pq.GenericArray{A: p95}, pq.GenericArray{A: loss}, pq.GenericArray{A: loads})
		return err
	})
	return accepted, err
}

// Peer is one WireGuard peer a node must configure.
type Peer struct {
	DeviceID    string
	WGPublicKey string
	TunnelIP    string
	PSKEnc      string
	// IssuedAt is when the (device, server) key was created; with DeviceID
	// it is the keyset pagination key.
	IssuedAt time.Time
}

// PeerCursor is a keyset position in a server's peer list, which is
// ordered by (issued_at, device_id). Keys are only ever appended, so a
// cursor stays valid however long an agent takes to page through.
type PeerCursor struct {
	IssuedAt time.Time
	DeviceID string
}

// IsZero reports whether c is the start of the list.
func (c PeerCursor) IsZero() bool { return c.DeviceID == "" }

const peerCols = `d.id, d.wg_public_key, host(d.tunnel_ip), k.psk_enc, k.created_at`

// entitledPredicate is the read-time entitlement check shared by the peer
// queries: a lapsed user drops out at expires_at even if no "expired" event
// ever arrives.
const entitledPredicate = `EXISTS (SELECT 1 FROM subscriptions s
	WHERE s.user_id = d.user_id AND s.status IN ('active', 'grace') AND s.expires_at > $2)`

// ServerPeers lists devices that have been issued a config for this server
// and whose owner is currently entitled, ordered by (issued_at, device_id).
// Lapsed users drop out of the list, which is how an expired subscription is
// enforced on the data plane when the node agent next syncs.
//
// limit <= 0 returns every peer (the original, unpaginated behaviour). A
// positive limit returns at most limit peers after `after`, plus the cursor
// to continue from and whether more keys follow. A page can be shorter than
// limit when many owners are lapsed; only more == false means the end.
//
// Each round is an ordered LIMIT range scan over the key index alone, and
// only then joins devices and checks entitlement for those few rows. Written
// as one join, the planner may (and with default cost settings does) pick a
// bitmap scan plus sort over every remaining key, making a page O(n) instead
// of O(log n + limit): 0.5-0.7 s per page on a 120k-peer node.
func (s *Store) ServerPeers(ctx context.Context, serverID string, now time.Time, after PeerCursor, limit int) (peers []Peer, next PeerCursor, more bool, err error) {
	peers, next, more = []Peer{}, after, true
	if limit <= 0 {
		// Whole list: one join, which the planner can run as a parallel
		// hash join; for reading everything that beats n index lookups.
		peers, err = s.allPeers(ctx, serverID, now)
		return peers, next, false, err
	}
	for round := 0; round < maxPeerRounds && more && len(peers) < limit; round++ {
		var batch []Peer
		if batch, next, more, err = s.peerRound(ctx, serverID, now, next, limit-len(peers)); err != nil {
			return nil, next, false, err
		}
		peers = append(peers, batch...)
	}
	return peers, next, more, nil
}

const maxPeerRounds = 8

func (s *Store) allPeers(ctx context.Context, serverID string, now time.Time) ([]Peer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+peerCols+`
		FROM device_server_keys k
		JOIN devices d ON d.id = k.device_id
		WHERE k.server_id = $1 AND `+entitledPredicate+`
		ORDER BY k.created_at, k.device_id`, serverID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Peer{}
	for rows.Next() {
		var p Peer
		if err := rows.Scan(&p.DeviceID, &p.WGPublicKey, &p.TunnelIP, &p.PSKEnc, &p.IssuedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// peerRound examines the next n keys after `after` and returns the entitled
// ones, the position of the last key examined, and whether n keys were found
// (so more may follow).
func (s *Store) peerRound(ctx context.Context, serverID string, now time.Time, after PeerCursor, n int) ([]Peer, PeerCursor, bool, error) {
	q := `SELECT ` + peerCols + `, ` + entitledPredicate + `
		FROM (SELECT device_id, psk_enc, created_at FROM device_server_keys
		      WHERE server_id = $1`
	args := []any{serverID, now}
	if !after.IsZero() {
		q += ` AND (created_at, device_id) > ($4, $5)`
		args = append(args, n, after.IssuedAt, after.DeviceID)
	} else {
		args = append(args, n)
	}
	q += ` ORDER BY created_at, device_id LIMIT $3) k
		JOIN devices d ON d.id = k.device_id
		ORDER BY k.created_at, k.device_id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, after, false, err
	}
	defer rows.Close()
	var out []Peer
	examined := 0
	last := after
	for rows.Next() {
		var p Peer
		var entitled bool
		if err := rows.Scan(&p.DeviceID, &p.WGPublicKey, &p.TunnelIP, &p.PSKEnc, &p.IssuedAt, &entitled); err != nil {
			return nil, after, false, err
		}
		examined++
		last = PeerCursor{IssuedAt: p.IssuedAt, DeviceID: p.DeviceID}
		if entitled {
			out = append(out, p)
		}
	}
	// A key whose device row vanished between the two reads cannot happen
	// (FK with cascade), so examined == number of keys scanned.
	return out, last, examined == n, rows.Err()
}

// PeerSyncOverlap is subtracted from a sync token before looking for
// changes. Change timestamps come from now() inside the writing transaction,
// which can commit a little after a concurrent sync read; re-sending changes
// from a short window is harmless (upserts and removals are idempotent) and
// closes that gap. Every writing transaction involved is a single short
// statement or a few, far below this bound.
const PeerSyncOverlap = 60 * time.Second

// PeerTombstoneRetention is how long removals are remembered. A sync token
// older than this (less the overlap) cannot be served incrementally; the
// API answers 410 and the agent does a full sync.
const PeerTombstoneRetention = 24 * time.Hour

// PeerChanges is an incremental sync result.
type PeerChanges struct {
	Upserts  []Peer
	Removals []string // device ids to remove (idempotent; unknown ids are ignored by the agent)
}

// DBNow returns the database clock. Sync tokens use it so that every replica
// agrees on one clock.
func (s *Store) DBNow(ctx context.Context) (time.Time, error) {
	var t time.Time
	err := s.db.QueryRowContext(ctx, `SELECT now()`).Scan(&t)
	return t, err
}

// ServerPeerChanges returns what changed for serverID since `since` (a
// previous sync token, on the database clock), with entitlement evaluated
// as of `now`. Callers must reject tokens older than PeerTombstoneRetention
// minus PeerSyncOverlap. It reports:
//
//   - peers whose key was issued since then (new devices on this node);
//   - devices of users whose subscription row changed since then, or whose
//     subscription expired in between (renewal, refund, revocation, lapse):
//     each is an upsert if the owner is entitled now and a removal otherwise;
//   - removals recorded in peer_tombstones (device or key deleted, user
//     deleted; written by a trigger, so no code path can forget them).
//
// The candidate sets come from indexes on device_server_keys (server_id,
// created_at, device_id), subscriptions (updated_at), subscriptions
// (expires_at) and peer_tombstones (server_id, deleted_at), so the cost is
// proportional to the number of changes, not to the size of the node.
func (s *Store) ServerPeerChanges(ctx context.Context, serverID string, since, now time.Time) (PeerChanges, error) {
	var out PeerChanges
	from := since.Add(-PeerSyncOverlap)
	rows, err := s.db.QueryContext(ctx, `
		WITH changed_users AS (
			SELECT user_id FROM subscriptions WHERE updated_at > $3
			UNION
			SELECT user_id FROM subscriptions WHERE status IN ('active', 'grace') AND expires_at > $3 AND expires_at <= $2
		), cand AS (
			SELECT k.device_id FROM device_server_keys k WHERE k.server_id = $1 AND k.created_at > $3
			UNION
			SELECT k.device_id FROM changed_users cu
			JOIN devices dv ON dv.user_id = cu.user_id
			JOIN device_server_keys k ON k.device_id = dv.id AND k.server_id = $1
		)
		SELECT `+peerCols+`, `+entitledPredicate+`
		FROM cand c
		JOIN device_server_keys k ON k.server_id = $1 AND k.device_id = c.device_id
		JOIN devices d ON d.id = c.device_id
		ORDER BY k.created_at, k.device_id`, serverID, now, from)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	out.Upserts, out.Removals = []Peer{}, []string{}
	for rows.Next() {
		var p Peer
		var entitled bool
		if err := rows.Scan(&p.DeviceID, &p.WGPublicKey, &p.TunnelIP, &p.PSKEnc, &p.IssuedAt, &entitled); err != nil {
			return out, err
		}
		if entitled {
			out.Upserts = append(out.Upserts, p)
		} else {
			out.Removals = append(out.Removals, p.DeviceID)
		}
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	rows.Close()
	trows, err := s.db.QueryContext(ctx, `SELECT DISTINCT device_id FROM peer_tombstones WHERE server_id = $1 AND deleted_at > $2`, serverID, from)
	if err != nil {
		return out, err
	}
	defer trows.Close()
	for trows.Next() {
		var id string
		if err := trows.Scan(&id); err != nil {
			return out, err
		}
		out.Removals = append(out.Removals, id)
	}
	return out, trows.Err()
}
