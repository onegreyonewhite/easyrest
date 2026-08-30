package ratelimit

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

const (
	defaultLimit     = 100
	defaultPeriod    = time.Minute
	defaultCacheSize = 1024
	globalCacheKey   = "global"

	headerRetryAfter = "response.header.Retry-After"
	headerLimit      = "response.header.X-RateLimit-Limit"
	headerRemaining  = "response.header.X-RateLimit-Remaining"
	headerSetCookie  = "response.header.Set-Cookie"
)

var (
	errRateLimitExceeded = errors.New("rate limit exceeded")
	statusTooMany        = http.StatusTooManyRequests

	_ easyrest.MiddlewarePlugin = (*RateLimitPlugin)(nil)
)

type windowCount struct {
	count     int
	windowEnd time.Time
}

// RateLimitPlugin is a built-in middleware that enforces a fixed-window rate limit.
type RateLimitPlugin struct {
	mu         sync.Mutex
	cache      *lru.Cache[string, windowCount]
	limit      int
	period     time.Duration
	keyMode    string
	cookieName string
	now        func() time.Time
}

// New returns an uninitialized rate-limit plugin. Call Init before PreRequest.
func New() *RateLimitPlugin {
	return &RateLimitPlugin{now: time.Now}
}

// Init validates settings and creates the LRU counter cache.
func (p *RateLimitPlugin) Init(settings map[string]any) error {
	if settings == nil {
		settings = map[string]any{}
	}
	if p.now == nil {
		p.now = time.Now
	}

	limit, err := optionalInt(settings, "limit", defaultLimit)
	if err != nil {
		return err
	}
	if limit <= 0 {
		return errors.New("limit must be greater than 0")
	}

	period := defaultPeriod
	if v, ok := settings["period"]; ok {
		period, err = parsePeriod(v)
		if err != nil {
			return err
		}
	}
	if period <= 0 {
		return errors.New("period must be greater than 0")
	}

	cacheSize, err := optionalInt(settings, "cache_size", defaultCacheSize)
	if err != nil {
		return err
	}
	if cacheSize <= 0 {
		return errors.New("cache_size must be greater than 0")
	}

	keyMode := "global"
	if v, ok := settings["key"]; ok {
		s, ok := v.(string)
		if !ok {
			return errors.New("key must be a string")
		}
		keyMode = strings.ToLower(strings.TrimSpace(s))
	}
	switch keyMode {
	case "global", "ip", "cookie":
	default:
		return fmt.Errorf("key must be global, ip, or cookie")
	}

	cookieName := ""
	if v, ok := settings["cookie"]; ok {
		s, ok := v.(string)
		if !ok {
			return errors.New("cookie must be a string")
		}
		cookieName = s
	}
	if keyMode == "cookie" && cookieName == "" {
		return errors.New("cookie is required when key is cookie")
	}

	cache, err := lru.New[string, windowCount](cacheSize)
	if err != nil {
		return fmt.Errorf("create rate limit cache: %w", err)
	}

	p.limit = limit
	p.period = period
	p.keyMode = keyMode
	p.cookieName = cookieName
	p.cache = cache
	return nil
}

// PreRequest increments the counter for the request key and rejects over-limit calls with 429.
func (p *RateLimitPlugin) PreRequest(_ string, ctx map[string]any) (map[string]any, *int, error) {
	ctx, assigned, err := p.ensureCookie(ctx)
	if err != nil {
		return ctx, nil, err
	}
	key := p.cacheKey(ctx)
	now := p.now()

	p.mu.Lock()
	defer p.mu.Unlock()

	wc, ok := p.cache.Get(key)
	if !ok || !now.Before(wc.windowEnd) {
		p.cache.Add(key, windowCount{count: 1, windowEnd: now.Add(p.period)})
		return ctx, nil, nil
	}
	if wc.count >= p.limit {
		return p.applyLimitedHeaders(ctx, wc.windowEnd, now, assigned), &statusTooMany, errRateLimitExceeded
	}
	wc.count++
	p.cache.Add(key, wc)
	return ctx, nil, nil
}

// PostRequest sets Set-Cookie in cookie mode when the context has a cookie value.
func (p *RateLimitPlugin) PostRequest(_ string, ctx map[string]any) (map[string]string, error) {
	if p.keyMode != "cookie" || p.cookieName == "" {
		return nil, nil
	}
	val := cookieValue(ctx, p.cookieName)
	if val == "" {
		return nil, nil
	}
	h := setCookieHeader(p.cookieName, val)
	if h == "" {
		return nil, nil
	}
	return map[string]string{"Set-Cookie": h}, nil
}

func (p *RateLimitPlugin) ensureCookie(ctx map[string]any) (map[string]any, bool, error) {
	if p.keyMode != "cookie" || p.cookieName == "" {
		return ctx, false, nil
	}
	if cookieValue(ctx, p.cookieName) != "" {
		return ctx, false, nil
	}
	if ctx == nil {
		ctx = map[string]any{}
	}
	val, err := generateCookieValue()
	if err != nil {
		return ctx, false, fmt.Errorf("generate cookie: %w", err)
	}
	ctx["cookie."+p.cookieName] = val
	return ctx, true, nil
}

func (p *RateLimitPlugin) applyLimitedHeaders(ctx map[string]any, windowEnd, now time.Time, assigned bool) map[string]any {
	if ctx == nil {
		ctx = map[string]any{}
	}
	ctx[headerRetryAfter] = strconv.Itoa(retryAfterSeconds(windowEnd, now))
	ctx[headerLimit] = strconv.Itoa(p.limit)
	ctx[headerRemaining] = "0"
	if assigned {
		if val := cookieValue(ctx, p.cookieName); val != "" {
			if h := setCookieHeader(p.cookieName, val); h != "" {
				ctx[headerSetCookie] = h
			}
		}
	}
	return ctx
}

func (p *RateLimitPlugin) cacheKey(ctx map[string]any) string {
	switch p.keyMode {
	case "ip":
		ip, _ := easyrest.CtxString(ctx, "client_ip")
		if ip == "" {
			return globalCacheKey
		}
		return "ip:" + ip
	case "cookie":
		return "cookie:" + cookieValue(ctx, p.cookieName)
	default:
		return globalCacheKey
	}
}

func cookieValue(ctx map[string]any, name string) string {
	if ctx == nil || name == "" {
		return ""
	}
	s, ok := ctx["cookie."+name].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func generateCookieValue() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func setCookieHeader(name, value string) string {
	c := http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	return c.String()
}

func retryAfterSeconds(windowEnd, now time.Time) int {
	d := windowEnd.Sub(now)
	sec := int(d.Seconds())
	if d > time.Duration(sec)*time.Second {
		sec++
	}
	if sec < 1 {
		return 1
	}
	return sec
}

func optionalInt(settings map[string]any, key string, def int) (int, error) {
	v, ok := settings[key]
	if !ok {
		return def, nil
	}
	n, ok := easyrest.AsInt(v)
	if !ok {
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	return n, nil
}

func parsePeriod(v any) (time.Duration, error) {
	switch p := v.(type) {
	case string:
		d, err := time.ParseDuration(p)
		if err != nil {
			return 0, fmt.Errorf("invalid period: %w", err)
		}
		return d, nil
	default:
		n, ok := easyrest.AsInt(p)
		if !ok {
			return 0, errors.New("invalid period")
		}
		return time.Duration(n) * time.Second, nil
	}
}
