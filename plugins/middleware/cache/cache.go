package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

const (
	defaultTTL              = 24 * time.Hour
	headerETag              = "response.header.ETag"
	headerResourceVersion   = "response.header.Resource-Version"
	etagKeyPrefix           = "etag:"
	ctxHeaders              = "headers"
	ctxMethod               = "method"
	headerIfMatch           = "if-match"
	headerIfNoneMatch       = "if-none-match"
	headerIfResourceVersion = "if-resource-version"
	contentTypeNDJSON       = "application/x-ndjson"
)

var (
	statusNotModified                                  = http.StatusNotModified
	statusPreconditionFailed                           = http.StatusPreconditionFailed
	_                        easyrest.MiddlewarePlugin = (*Plugin)(nil)
)

// Store holds ETag version tokens for the cache middleware.
type Store interface {
	InitConnection(uri string) error
	Set(key string, value string, ttl time.Duration) error
	Get(key string) (string, error)
}

// Plugin is an ETag middleware that stores version tokens in a Store.
type Plugin struct {
	host         easyrest.HostRPC
	store        Store
	ttl          time.Duration
	invalidation map[string]map[string][]string
}

// New returns an uninitialized cache middleware that delegates storage to store.
func New(store Store) *Plugin {
	return &Plugin{store: store}
}

// Init reads uri, ttl (default 24h), and invalidation_map, then opens the store.
func (p *Plugin) Init(settings map[string]any, host easyrest.HostRPC) (easyrest.MiddlewareInfo, error) {
	p.host = host
	if err := p.initSettings(settings); err != nil {
		return easyrest.MiddlewareInfo{}, err
	}
	return easyrest.NewMiddlewareInfo(), nil
}

func (p *Plugin) initSettings(settings map[string]any) error {
	if p.store == nil {
		return errors.New("cache store is required")
	}
	if settings == nil {
		settings = map[string]any{}
	}

	uri := ""
	if v, ok := settings["uri"]; ok {
		s, ok := v.(string)
		if !ok {
			return errors.New("uri must be a string")
		}
		uri = s
	}

	ttl := defaultTTL
	if v, ok := settings["ttl"]; ok {
		parsed, err := parseTTL(v)
		if err != nil {
			return err
		}
		if parsed <= 0 {
			return errors.New("ttl must be greater than 0")
		}
		ttl = parsed
	}

	inv, err := parseInvalidationMap(settings["invalidation_map"])
	if err != nil {
		return fmt.Errorf("invalidation_map: %w", err)
	}

	if err := p.store.InitConnection(uri); err != nil {
		return fmt.Errorf("init cache store: %w", err)
	}

	p.ttl = ttl
	p.invalidation = inv
	return nil
}

// PreRequest implements If-None-Match (304) and lost-update checks for table routes.
func (p *Plugin) PreRequest(dbKey string, ctx map[string]any) (map[string]any, *int, error) {
	table, _ := easyrest.CtxString(ctx, easyrest.CtxTable)
	if table == "" {
		return ctx, nil, nil
	}
	method, _ := easyrest.CtxString(ctx, ctxMethod)
	isRead := method == http.MethodGet || method == http.MethodHead
	ifMatch := headerOf(ctx, headerIfMatch)
	ifNoneMatch := headerOf(ctx, headerIfNoneMatch)
	ifResourceVersion := headerOf(ctx, headerIfResourceVersion)
	if !isRead && ifMatch == "" && ifNoneMatch == "" && ifResourceVersion == "" {
		return ctx, nil, nil
	}

	version := p.getOrGenerate(etagKey(dbKey, table))
	ctx = ensureCtx(ctx)
	fingerprint, _ := easyrest.CtxString(ctx, easyrest.CtxCacheETagVariant)
	opaque := opaqueTag(version, fingerprint)
	etag := quoteETag(opaque, !isRead || representationWeak(fingerprint))

	if status := checkPrecondition(ifResourceVersion, ifMatch, version, opaque); status != nil {
		return ctx, status, nil
	}
	if !isRead {
		return ctx, nil, nil
	}

	ctx[headerETag] = etag
	ctx[headerResourceVersion] = version
	if ifNoneMatch != "" && noneMatch(ifNoneMatch, opaque) {
		return ctx, &statusNotModified, nil
	}
	return ctx, nil, nil
}

// PostRequest bumps table versions on successful writes and configured RPC calls.
func (p *Plugin) PostRequest(dbKey string, ctx map[string]any) (map[string]string, error) {
	status, ok := easyrest.IntFromCtx(ctx, easyrest.CtxHandlerStatus)
	if !ok || status >= 400 {
		return nil, nil
	}
	for _, name := range easyrest.CacheInvalidateNames(ctx) {
		p.bump(etagKey(dbKey, name))
	}
	if fn, _ := easyrest.CtxString(ctx, easyrest.CtxFunction); fn != "" {
		for _, tableName := range p.invalidation[dbKey][fn] {
			p.bump(etagKey(dbKey, tableName))
		}
		return nil, nil
	}
	table, _ := easyrest.CtxString(ctx, easyrest.CtxTable)
	method, _ := easyrest.CtxString(ctx, ctxMethod)
	if table == "" || !isWrite(method) {
		return nil, nil
	}
	rev := p.bump(etagKey(dbKey, table))
	fingerprint, _ := easyrest.CtxString(ctx, easyrest.CtxCacheETagVariant)
	return map[string]string{
		"ETag":             quoteETag(opaqueTag(rev, fingerprint), true),
		"Resource-Version": rev,
	}, nil
}

func (p *Plugin) getOrGenerate(key string) string {
	current, err := p.store.Get(key)
	if err == nil && current != "" {
		return current
	}
	return p.bump(key)
}

func (p *Plugin) bump(key string) string {
	newETag := uuid.NewString()
	_ = p.store.Set(key, newETag, p.ttl)
	return newETag
}

func etagKey(dbKey, table string) string {
	var b strings.Builder
	b.Grow(len(etagKeyPrefix) + len(dbKey) + 1 + len(table))
	b.WriteString(etagKeyPrefix)
	b.WriteString(dbKey)
	b.WriteByte(':')
	b.WriteString(table)
	return b.String()
}

func opaqueTag(revision, fingerprint string) string {
	var b strings.Builder
	maj := strconv.Itoa(easyrest.VersionMajor)
	min := strconv.Itoa(easyrest.VersionMinor)
	fp := fingerprintHex(fingerprint)
	b.Grow(len(revision) + 1 + len(maj) + 1 + len(min) + 1 + len(fp))
	b.WriteString(revision)
	b.WriteByte(':')
	b.WriteString(maj)
	b.WriteByte('.')
	b.WriteString(min)
	b.WriteByte(':')
	b.WriteString(fp)
	return b.String()
}

func fingerprintHex(fingerprint string) string {
	sum := sha256.Sum256([]byte(fingerprint))
	return hex.EncodeToString(sum[:8])
}

func quoteETag(opaque string, weak bool) string {
	if weak {
		return `W/"` + opaque + `"`
	}
	return `"` + opaque + `"`
}

func representationWeak(fingerprint string) bool {
	for line := range strings.SplitSeq(fingerprint, "\n") {
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if key == "Accept" && (val == contentTypeNDJSON || val == easyrest.MediaTypeCSV) {
			return true
		}
		if key == "Range" && val != "" {
			return true
		}
	}
	return false
}

type entityTag struct {
	weak   bool
	opaque string
}

func parseEntityTags(h string) (tags []entityTag, star bool) {
	s := strings.TrimSpace(h)
	if s == "*" {
		return nil, true
	}
	for i := 0; i < len(s); {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == ',') {
			i++
		}
		if i >= len(s) {
			break
		}
		if s[i] == '*' {
			return nil, true
		}
		weak := false
		if i+2 <= len(s) && s[i] == 'W' && s[i+1] == '/' {
			weak = true
			i += 2
		}
		if i >= len(s) || s[i] != '"' {
			// Skip a malformed token up to the next comma.
			if j := strings.IndexByte(s[i:], ','); j >= 0 {
				i += j + 1
				continue
			}
			break
		}
		i++
		start := i
		for i < len(s) && s[i] != '"' {
			i++
		}
		if i >= len(s) {
			break
		}
		tags = append(tags, entityTag{weak: weak, opaque: s[start:i]})
		i++
	}
	return tags, false
}

func stripQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func checkPrecondition(ifResourceVersion, ifMatch, revision, opaque string) *int {
	if ifResourceVersion != "" {
		if stripQuotes(ifResourceVersion) != revision {
			return &statusPreconditionFailed
		}
		return nil
	}
	if ifMatch == "" {
		return nil
	}
	tags, star := parseEntityTags(ifMatch)
	if star {
		return nil
	}
	hasWeak := false
	for _, t := range tags {
		if t.weak {
			hasWeak = true
			if t.opaque == revision {
				return nil
			}
		}
	}
	if hasWeak {
		return &statusPreconditionFailed
	}
	for _, t := range tags {
		if !t.weak && t.opaque == opaque {
			return nil
		}
	}
	return &statusPreconditionFailed
}

func noneMatch(ifNoneMatch, opaque string) bool {
	tags, star := parseEntityTags(ifNoneMatch)
	if star {
		return true
	}
	for _, t := range tags {
		if t.opaque == opaque {
			return true
		}
	}
	return false
}

func isWrite(method string) bool {
	return method == http.MethodPost || method == http.MethodPatch || method == http.MethodDelete
}

func ensureCtx(ctx map[string]any) map[string]any {
	if ctx == nil {
		return map[string]any{}
	}
	return ctx
}

func headerOf(ctx map[string]any, name string) string {
	if ctx == nil {
		return ""
	}
	headers, ok := ctx[ctxHeaders].(map[string]any)
	if !ok || headers == nil {
		return ""
	}
	v, ok := headers[name]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprint(v)
	}
	return s
}

func parseTTL(v any) (time.Duration, error) {
	switch p := v.(type) {
	case string:
		d, err := time.ParseDuration(p)
		if err != nil {
			return 0, fmt.Errorf("invalid ttl: %w", err)
		}
		return d, nil
	case time.Duration:
		return p, nil
	default:
		n, ok := easyrest.AsInt(v)
		if !ok {
			return 0, errors.New("invalid ttl")
		}
		return time.Duration(n) * time.Second, nil
	}
}

func parseInvalidationMap(raw any) (map[string]map[string][]string, error) {
	if raw == nil {
		return map[string]map[string][]string{}, nil
	}
	group, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("must be a map")
	}
	out := make(map[string]map[string][]string, len(group))
	for dbKey, v := range group {
		funcs, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s must be a map of function names to tables", dbKey)
		}
		fnMap := make(map[string][]string, len(funcs))
		for fn, tablesRaw := range funcs {
			tables, err := stringSlice(tablesRaw)
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", dbKey, fn, err)
			}
			fnMap[fn] = tables
		}
		out[dbKey] = fnMap
	}
	return out, nil
}

func stringSlice(v any) ([]string, error) {
	switch t := v.(type) {
	case []string:
		out := make([]string, len(t))
		copy(out, t)
		return out, nil
	case []any:
		out := make([]string, 0, len(t))
		for i, item := range t {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("item %d must be a string", i)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, errors.New("must be a list of strings")
	}
}
