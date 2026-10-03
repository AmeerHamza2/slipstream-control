package ratelimit

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/ameerhamza2/slipstream-control/internal/ids"
)

func TestRedisSlidingWindow(t *testing.T) {
	url := os.Getenv("TEST_REDIS_URL")
	if url == "" {
		t.Skip("TEST_REDIS_URL not set")
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	c := redis.NewClient(opt)
	defer c.Close()
	ctx := context.Background()
	l := NewRedis(c, "test:"+ids.New()+":")

	for i := 0; i < 3; i++ {
		d, err := l.Allow(ctx, "k", 3, 400*time.Millisecond)
		if err != nil || !d.Allowed || d.Remaining != 2-i {
			t.Fatalf("hit %d: %+v %v", i, d, err)
		}
	}
	d, err := l.Allow(ctx, "k", 3, 400*time.Millisecond)
	if err != nil || d.Allowed || d.RetryAfter <= 0 || d.RetryAfter > 400*time.Millisecond {
		t.Fatalf("4th hit: %+v %v", d, err)
	}
	// Other keys are independent.
	if d, _ := l.Allow(ctx, "other", 3, time.Second); !d.Allowed {
		t.Fatal("independent key limited")
	}
	time.Sleep(450 * time.Millisecond)
	if d, _ := l.Allow(ctx, "k", 3, 400*time.Millisecond); !d.Allowed {
		t.Fatal("window did not slide")
	}
}

func TestRedisDownReturnsError(t *testing.T) {
	c := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 100 * time.Millisecond, MaxRetries: -1})
	defer c.Close()
	if _, err := NewRedis(c, "x:").Allow(context.Background(), "k", 1, time.Second); err == nil {
		t.Fatal("expected error when redis is down")
	}
}
