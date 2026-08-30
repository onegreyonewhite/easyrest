package ratelimit

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func mustInit(t *testing.T, settings map[string]any) *RateLimitPlugin {
	t.Helper()
	p := New()
	if err := p.Init(settings); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return p
}

func assertOK(t *testing.T, ctx, got map[string]any, status *int, err error) {
	t.Helper()
	if status != nil || err != nil {
		t.Fatalf("expected success, got status=%v err=%v", status, err)
	}
	if got == nil {
		t.Fatal("expected context map")
	}
	if ctx != nil {
		ctx["__probe"] = true
		if got["__probe"] != true {
			t.Fatal("expected PreRequest to return the same context map")
		}
		delete(ctx, "__probe")
	}
}

func assertLimited(t *testing.T, status *int, err error) {
	t.Helper()
	if status == nil || *status != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %v", status)
	}
	if err == nil || err.Error() != "rate limit exceeded" {
		t.Fatalf("expected rate limit exceeded, got %v", err)
	}
}

func assertLimitedHeaders(t *testing.T, ctx map[string]any, limit int, retryAfter string) {
	t.Helper()
	if ctx[headerRetryAfter] != retryAfter {
		t.Fatalf("Retry-After: got %#v want %q", ctx[headerRetryAfter], retryAfter)
	}
	if ctx[headerLimit] != strconv.Itoa(limit) {
		t.Fatalf("X-RateLimit-Limit: got %#v want %d", ctx[headerLimit], limit)
	}
	if ctx[headerRemaining] != "0" {
		t.Fatalf("X-RateLimit-Remaining: got %#v want 0", ctx[headerRemaining])
	}
}

func TestInitDefaults(t *testing.T) {
	p := mustInit(t, nil)
	if p.limit != 100 {
		t.Errorf("limit: got %d want 100", p.limit)
	}
	if p.period != time.Minute {
		t.Errorf("period: got %v want 1m", p.period)
	}
	if p.keyMode != "global" {
		t.Errorf("key: got %q want global", p.keyMode)
	}
	if p.cache == nil {
		t.Fatal("expected cache")
	}
}

func TestInitYAMLNumbers(t *testing.T) {
	p := mustInit(t, map[string]any{
		"limit":      uint64(50),
		"cache_size": float64(8),
		"period":     int64(30),
	})
	if p.limit != 50 {
		t.Errorf("limit: got %d want 50", p.limit)
	}
	if p.period != 30*time.Second {
		t.Errorf("period: got %v want 30s", p.period)
	}
}

func TestInitPeriodFormats(t *testing.T) {
	p := mustInit(t, map[string]any{"period": "500ms"})
	if p.period != 500*time.Millisecond {
		t.Errorf("500ms: got %v", p.period)
	}
	p = mustInit(t, map[string]any{"period": 2})
	if p.period != 2*time.Second {
		t.Errorf("2 seconds: got %v", p.period)
	}
}

func TestInitErrors(t *testing.T) {
	cases := []struct {
		name     string
		settings map[string]any
	}{
		{"bad key", map[string]any{"key": "user"}},
		{"limit zero", map[string]any{"limit": 0}},
		{"limit negative", map[string]any{"limit": -1}},
		{"period zero", map[string]any{"period": 0}},
		{"period negative duration", map[string]any{"period": "-1s"}},
		{"cache_size zero", map[string]any{"cache_size": 0}},
		{"cookie missing", map[string]any{"key": "cookie"}},
		{"cookie empty", map[string]any{"key": "COOKIE", "cookie": ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := New()
			if err := p.Init(tc.settings); err == nil {
				t.Fatal("expected Init error")
			}
		})
	}
}

func TestPreRequestGlobalLimit(t *testing.T) {
	p := mustInit(t, map[string]any{"limit": 2, "period": "1m"})
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return base }
	ctx := map[string]any{"method": "GET"}
	got, status, err := p.PreRequest("db", ctx)
	assertOK(t, ctx, got, status, err)
	got, status, err = p.PreRequest("db", ctx)
	assertOK(t, ctx, got, status, err)
	got, status, err = p.PreRequest("db", ctx)
	assertLimited(t, status, err)
	assertLimitedHeaders(t, got, 2, "60")
}

func TestPreRequestWindowReset(t *testing.T) {
	p := mustInit(t, map[string]any{"limit": 1, "period": "1s"})
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base
	p.now = func() time.Time { return now }

	ctx := map[string]any{}
	_, status, err := p.PreRequest("", ctx)
	assertOK(t, ctx, ctx, status, err)
	_, status, err = p.PreRequest("", ctx)
	assertLimited(t, status, err)

	now = base.Add(500 * time.Millisecond)
	got, status, err := p.PreRequest("", ctx)
	assertLimited(t, status, err)
	assertLimitedHeaders(t, got, 1, "1")

	now = base.Add(time.Second)
	_, status, err = p.PreRequest("", ctx)
	assertOK(t, ctx, ctx, status, err)
}

func TestPreRequestIPIsolation(t *testing.T) {
	p := mustInit(t, map[string]any{"limit": 1, "period": "1m", "key": "ip"})
	a := map[string]any{"client_ip": "203.0.113.1"}
	b := map[string]any{"client_ip": "203.0.113.2"}
	empty := map[string]any{"client_ip": ""}

	_, status, err := p.PreRequest("", a)
	assertOK(t, a, a, status, err)
	_, status, err = p.PreRequest("", a)
	assertLimited(t, status, err)

	_, status, err = p.PreRequest("", b)
	assertOK(t, b, b, status, err)

	_, status, err = p.PreRequest("", empty)
	assertOK(t, empty, empty, status, err)
	_, status, err = p.PreRequest("", map[string]any{})
	assertLimited(t, status, err)
}

func TestPreRequestCookieIsolationAndAssign(t *testing.T) {
	p := mustInit(t, map[string]any{
		"limit":  1,
		"period": "1m",
		"key":    "cookie",
		"cookie": "sid",
	})
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return base }

	a := map[string]any{"cookie.sid": "aaa"}
	b := map[string]any{"cookie.sid": "bbb"}
	missing := map[string]any{}
	none := map[string]any{}

	_, status, err := p.PreRequest("", a)
	assertOK(t, a, a, status, err)
	got, status, err := p.PreRequest("", a)
	assertLimited(t, status, err)
	assertLimitedHeaders(t, got, 1, "60")

	_, status, err = p.PreRequest("", b)
	assertOK(t, b, b, status, err)

	got, status, err = p.PreRequest("", missing)
	assertOK(t, missing, missing, status, err)
	sidA, ok := missing["cookie.sid"].(string)
	if !ok || sidA == "" {
		t.Fatalf("expected assigned cookie.sid, got %#v", missing["cookie.sid"])
	}

	got, status, err = p.PreRequest("", none)
	assertOK(t, none, none, status, err)
	sidB, ok := none["cookie.sid"].(string)
	if !ok || sidB == "" {
		t.Fatalf("expected assigned cookie.sid, got %#v", none["cookie.sid"])
	}
	if sidA == sidB {
		t.Fatal("missing cookies should get distinct values")
	}

	replay := map[string]any{"cookie.sid": sidA}
	got, status, err = p.PreRequest("", replay)
	assertLimited(t, status, err)
	assertLimitedHeaders(t, got, 1, "60")
}

func TestPostRequestSetCookie(t *testing.T) {
	p := mustInit(t, map[string]any{
		"limit":  5,
		"period": "1m",
		"key":    "cookie",
		"cookie": "sid",
	})
	ctx := map[string]any{}
	got, status, err := p.PreRequest("", ctx)
	assertOK(t, ctx, got, status, err)
	sid, ok := got["cookie.sid"].(string)
	if !ok || sid == "" {
		t.Fatalf("expected assigned cookie.sid, got %#v", got["cookie.sid"])
	}

	headers, err := p.PostRequest("", got)
	if err != nil {
		t.Fatalf("PostRequest: %v", err)
	}
	raw := headers["Set-Cookie"]
	if raw == "" {
		t.Fatal("expected Set-Cookie")
	}
	if !strings.Contains(raw, "sid="+sid) {
		t.Fatalf("Set-Cookie missing value: %q", raw)
	}
	if !strings.Contains(raw, "Path=/") || !strings.Contains(strings.ToLower(raw), "httponly") {
		t.Fatalf("Set-Cookie missing attributes: %q", raw)
	}

	headers, err = p.PostRequest("", map[string]any{"cookie.sid": "keep"})
	if err != nil {
		t.Fatalf("PostRequest existing: %v", err)
	}
	if !strings.Contains(headers["Set-Cookie"], "sid=keep") {
		t.Fatalf("expected refresh Set-Cookie, got %#v", headers)
	}

	global := mustInit(t, map[string]any{"limit": 5})
	headers, err = global.PostRequest("", map[string]any{"cookie.sid": "x"})
	if err != nil || headers != nil {
		t.Fatalf("global PostRequest: headers=%v err=%v", headers, err)
	}
}

func TestPreRequestReturnsSameContext(t *testing.T) {
	p := mustInit(t, map[string]any{"limit": 5})
	ctx := map[string]any{"method": "GET"}
	got, status, err := p.PreRequest("db", ctx)
	assertOK(t, ctx, got, status, err)
	if got["method"] != "GET" {
		t.Errorf("context mutated unexpectedly: %#v", got)
	}
}

func TestPreRequestConcurrent(t *testing.T) {
	const limit = 50
	const n = 200
	p := mustInit(t, map[string]any{"limit": limit, "period": "1m", "cache_size": 16})
	ctx := map[string]any{}

	var okCount atomic.Int32
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, status, err := p.PreRequest("", ctx)
			if status == nil && err == nil {
				okCount.Add(1)
			}
		}()
	}
	wg.Wait()
	if int(okCount.Load()) != limit {
		t.Fatalf("successes: got %d want %d", okCount.Load(), limit)
	}
}

func TestLRUEvictionResetsCounter(t *testing.T) {
	p := mustInit(t, map[string]any{
		"limit":      1,
		"period":     "1m",
		"key":        "ip",
		"cache_size": 1,
	})
	a := map[string]any{"client_ip": "198.51.100.1"}
	b := map[string]any{"client_ip": "198.51.100.2"}

	_, status, err := p.PreRequest("", a)
	assertOK(t, a, a, status, err)
	_, status, err = p.PreRequest("", a)
	assertLimited(t, status, err)

	_, status, err = p.PreRequest("", b)
	assertOK(t, b, b, status, err)

	_, status, err = p.PreRequest("", a)
	assertOK(t, a, a, status, err)
}

func TestParsePeriodAndApplyLimitedHeaders(t *testing.T) {
	d, err := parsePeriod("30s")
	if err != nil || d != 30*time.Second {
		t.Fatalf("string: %v %v", d, err)
	}
	d, err = parsePeriod(12)
	if err != nil || d != 12*time.Second {
		t.Fatalf("int: %v %v", d, err)
	}
	if _, err := parsePeriod(struct{}{}); err == nil {
		t.Fatal("expected invalid period")
	}

	p := mustInit(t, map[string]any{"key": "cookie", "cookie": "rl"})
	now := time.Now()
	ctx := p.applyLimitedHeaders(map[string]any{"cookie.rl": "abc"}, now.Add(time.Second), now, true)
	if ctx[headerRetryAfter] != "1" || ctx[headerRemaining] != "0" {
		t.Fatalf("headers: %#v", ctx)
	}
	if ctx[headerSetCookie] == "" {
		t.Fatal("expected set-cookie")
	}
	if _, err := generateCookieValue(); err != nil {
		t.Fatalf("cookie: %v", err)
	}

	headers, err := p.PostRequest("db", map[string]any{"cookie.rl": "abc"})
	if err != nil || headers["Set-Cookie"] == "" {
		t.Fatalf("post cookie: %#v %v", headers, err)
	}
	if headers, err := p.PostRequest("db", map[string]any{}); err != nil || headers != nil {
		t.Fatalf("post empty: %#v %v", headers, err)
	}
	ctx, assigned, err := p.ensureCookie(nil)
	if err != nil || !assigned || cookieValue(ctx, "rl") == "" {
		t.Fatalf("ensure new cookie: %#v assigned=%v err=%v", ctx, assigned, err)
	}
	ctx, assigned, err = p.ensureCookie(map[string]any{"cookie.rl": "keep"})
	if err != nil || assigned || cookieValue(ctx, "rl") != "keep" {
		t.Fatalf("ensure existing: %#v assigned=%v", ctx, assigned)
	}
}
