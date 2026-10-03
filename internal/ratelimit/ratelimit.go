// Package ratelimit implements a Redis sliding-window-log rate limiter.
//
// Each key is a sorted set of request timestamps. A Lua script atomically
// trims entries older than the window, counts the rest and admits the request
// only if the count is below the limit. Using Redis' own TIME keeps every API
// replica on one clock. Unlike a fixed window there is no 2x burst at window
// boundaries; memory is O(limit) per key, which is small for our limits.
package ratelimit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Decision is the outcome of one check.
type Decision struct {
	Allowed    bool
	Remaining  int
	RetryAfter time.Duration
}

// Limiter checks and records a hit for key against limit per window.
type Limiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (Decision, error)
}

var script = redis.NewScript(`
local key    = KEYS[1]
local window = tonumber(ARGV[1])
local limit  = tonumber(ARGV[2])
local t      = redis.call('TIME')
local now    = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local count = redis.call('ZCARD', key)
if count < limit then
  redis.call('ZADD', key, now, now .. '-' .. ARGV[3])
  redis.call('PEXPIRE', key, window)
  return {1, limit - count - 1, 0}
end
local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
local retry = window
if oldest[2] then retry = tonumber(oldest[2]) + window - now end
if retry < 1 then retry = 1 end
return {0, 0, retry}
`)

// Redis is a Limiter backed by Redis.
type Redis struct {
	client redis.Scripter
	prefix string
}

// NewRedis returns a limiter; prefix namespaces keys (e.g. "rl:").
func NewRedis(client redis.Scripter, prefix string) *Redis {
	return &Redis{client: client, prefix: prefix}
}

// Allow implements Limiter. Errors mean Redis was unreachable; the caller
// decides whether to fail open or closed.
func (r *Redis) Allow(ctx context.Context, key string, limit int, window time.Duration) (Decision, error) {
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	res, err := script.Run(ctx, r.client, []string{r.prefix + key}, window.Milliseconds(), limit, hex.EncodeToString(nonce[:])).Int64Slice()
	if err != nil {
		return Decision{}, fmt.Errorf("ratelimit: %w", err)
	}
	if len(res) != 3 {
		return Decision{}, fmt.Errorf("ratelimit: unexpected script result %v", res)
	}
	return Decision{Allowed: res[0] == 1, Remaining: int(res[1]), RetryAfter: time.Duration(res[2]) * time.Millisecond}, nil
}
