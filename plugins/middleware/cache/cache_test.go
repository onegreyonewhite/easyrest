package cache

import (
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

type fakeStore struct {
	mu      sync.Mutex
	values  map[string]string
	gets    []string
	sets    []string
	lastTTL time.Duration
	initURI string
	initErr error
	setErr  error
}

func newFakeStore() *fakeStore {
	return &fakeStore{values: map[string]string{}}
}

func (s *fakeStore) InitConnection(uri string) error {
	s.initURI = uri
	return s.initErr
}

func (s *fakeStore) Set(key string, value string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sets = append(s.sets, key)
	s.lastTTL = ttl
	if s.setErr != nil {
		return s.setErr
	}
	if s.values == nil {
		s.values = map[string]string{}
	}
	s.values[key] = value
	return nil
}

func (s *fakeStore) Get(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets = append(s.gets, key)
	v, ok := s.values[key]
	if !ok {
		return "", easyrest.ErrCacheMiss
	}
	return v, nil
}

func (s *fakeStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, key)
	return nil
}

func mustInit(t *testing.T, store Store, settings map[string]any) *Plugin {
	t.Helper()
	p := New(store)
	if _, err := p.Init(settings, easyrest.HostRPC{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return p
}

func tableCtx(method, table, ifMatch, ifNoneMatch string) map[string]any {
	return tableCtxHeaders(method, table, ifMatch, ifNoneMatch, "")
}

func tableCtxHeaders(method, table, ifMatch, ifNoneMatch, ifResourceVersion string) map[string]any {
	headers := map[string]any{}
	if ifMatch != "" {
		headers["if-match"] = ifMatch
	}
	if ifNoneMatch != "" {
		headers["if-none-match"] = ifNoneMatch
	}
	if ifResourceVersion != "" {
		headers["if-resource-version"] = ifResourceVersion
	}
	return map[string]any{
		easyrest.CtxTable: table,
		"method":          method,
		"headers":         headers,
	}
}

func jsonFingerprint() string {
	return "Accept=application/json\nContent-Type=\nPrefer=\nRange=\nRange-Unit="
}

func TestInitDefaults(t *testing.T) {
	store := newFakeStore()
	p := mustInit(t, store, nil)
	if p.ttl != defaultTTL {
		t.Fatalf("ttl: got %v want %v", p.ttl, defaultTTL)
	}
	if store.initURI != "" {
		t.Fatalf("uri: got %q", store.initURI)
	}
	if p.invalidation == nil {
		t.Fatal("expected empty invalidation map")
	}
}

func TestInitSettings(t *testing.T) {
	store := newFakeStore()
	p := mustInit(t, store, map[string]any{
		"uri": "redis://localhost:6379/1",
		"ttl": "2h",
		"invalidation_map": map[string]any{
			"mydb": map[string]any{
				"refresh": []any{"users", "orders"},
			},
		},
	})
	if store.initURI != "redis://localhost:6379/1" {
		t.Fatalf("uri: %q", store.initURI)
	}
	if p.ttl != 2*time.Hour {
		t.Fatalf("ttl: %v", p.ttl)
	}
	if got := p.invalidation["mydb"]["refresh"]; len(got) != 2 || got[0] != "users" || got[1] != "orders" {
		t.Fatalf("invalidation: %#v", p.invalidation)
	}
}

func TestInitTTLSeconds(t *testing.T) {
	p := mustInit(t, newFakeStore(), map[string]any{"ttl": 30})
	if p.ttl != 30*time.Second {
		t.Fatalf("ttl: %v", p.ttl)
	}
}

func TestInitValidation(t *testing.T) {
	if _, err := New(nil).Init(nil, easyrest.HostRPC{}); err == nil {
		t.Fatal("expected store required")
	}
	if _, err := New(newFakeStore()).Init(map[string]any{"uri": 1}, easyrest.HostRPC{}); err == nil {
		t.Fatal("expected uri type error")
	}
	if _, err := New(newFakeStore()).Init(map[string]any{"ttl": "nope"}, easyrest.HostRPC{}); err == nil {
		t.Fatal("expected ttl parse error")
	}
	if _, err := New(newFakeStore()).Init(map[string]any{"ttl": 0}, easyrest.HostRPC{}); err == nil {
		t.Fatal("expected ttl > 0")
	}
	if _, err := New(newFakeStore()).Init(map[string]any{"invalidation_map": "x"}, easyrest.HostRPC{}); err == nil {
		t.Fatal("expected invalidation_map type error")
	}
	store := newFakeStore()
	store.initErr = errors.New("boom")
	if _, err := New(store).Init(map[string]any{"uri": "redis://x"}, easyrest.HostRPC{}); err == nil {
		t.Fatal("expected store init error")
	}
}

func TestPreRequest304(t *testing.T) {
	store := newFakeStore()
	store.values["etag:test:users"] = "abc"
	p := mustInit(t, store, nil)
	fp := jsonFingerprint()
	etag := quoteETag(opaqueTag("abc", fp), false)
	ctx := tableCtx(http.MethodGet, "users", "", etag)
	ctx[easyrest.CtxCacheETagVariant] = fp
	got, status, err := p.PreRequest("test", ctx)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if status == nil || *status != http.StatusNotModified {
		t.Fatalf("status: %v", status)
	}
	if got[headerETag] != etag {
		t.Fatalf("etag header: %#v", got[headerETag])
	}
	if got[headerResourceVersion] != "abc" {
		t.Fatalf("resource-version: %#v", got[headerResourceVersion])
	}
}

func TestPreRequest304WeakAndStrongSameOpaque(t *testing.T) {
	store := newFakeStore()
	store.values["etag:test:users"] = "abc"
	p := mustInit(t, store, nil)
	fp := jsonFingerprint()
	opaque := opaqueTag("abc", fp)
	ctx := tableCtx(http.MethodGet, "users", "", `W/"`+opaque+`"`)
	ctx[easyrest.CtxCacheETagVariant] = fp
	_, status, err := p.PreRequest("test", ctx)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if status == nil || *status != http.StatusNotModified {
		t.Fatalf("weak If-None-Match: %v", status)
	}

	ctx = tableCtx(http.MethodGet, "users", "", `"`+opaque+`", W/"other"`)
	ctx[easyrest.CtxCacheETagVariant] = fp
	_, status, err = p.PreRequest("test", ctx)
	if err != nil || status == nil || *status != http.StatusNotModified {
		t.Fatalf("list If-None-Match: status=%v err=%v", status, err)
	}
}

func TestPreRequest304Star(t *testing.T) {
	store := newFakeStore()
	store.values["etag:test:users"] = "abc"
	p := mustInit(t, store, nil)
	ctx := tableCtx(http.MethodGet, "users", "", "*")
	_, status, err := p.PreRequest("test", ctx)
	if err != nil || status == nil || *status != http.StatusNotModified {
		t.Fatalf("star: status=%v err=%v", status, err)
	}
}

func TestPreRequest304RequiresRepresentationETag(t *testing.T) {
	store := newFakeStore()
	store.values["etag:test:users"] = "abc"
	p := mustInit(t, store, nil)
	fp := jsonFingerprint()
	ctx := tableCtx(http.MethodGet, "users", "", "abc")
	ctx[easyrest.CtxCacheETagVariant] = fp
	got, status, err := p.PreRequest("test", ctx)
	if err != nil || status != nil {
		t.Fatalf("bare version must not 304, status=%v err=%v", status, err)
	}
	want := quoteETag(opaqueTag("abc", fp), false)
	if got[headerETag] != want {
		t.Fatalf("etag header: %#v want %s", got[headerETag], want)
	}
	if store.values["etag:test:users"] != "abc" {
		t.Fatalf("store: %#v", store.values)
	}

	other := "Accept=application/x-ndjson\nContent-Type=\nPrefer=\nRange=\nRange-Unit="
	ctx = tableCtx(http.MethodGet, "users", "", want)
	ctx[easyrest.CtxCacheETagVariant] = other
	got, status, err = p.PreRequest("test", ctx)
	if err != nil || status != nil {
		t.Fatalf("different fingerprint must not 304, status=%v err=%v", status, err)
	}
	if got[headerETag] == want {
		t.Fatalf("NDJSON ETag must differ: %q", got[headerETag])
	}

	ctx = tableCtx(http.MethodGet, "users", "", want)
	ctx[easyrest.CtxCacheETagVariant] = fp
	got, status, err = p.PreRequest("test", ctx)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if status == nil || *status != http.StatusNotModified {
		t.Fatalf("status: %v", status)
	}
	if got[headerETag] != want {
		t.Fatalf("304 etag: %#v", got[headerETag])
	}
}

func TestPreRequest412(t *testing.T) {
	store := newFakeStore()
	store.values["etag:test:users"] = "current"
	p := mustInit(t, store, nil)
	fp := jsonFingerprint()
	ctx := tableCtx(http.MethodPatch, "users", `"stale"`, "")
	ctx[easyrest.CtxCacheETagVariant] = fp
	_, status, err := p.PreRequest("test", ctx)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if status == nil || *status != http.StatusPreconditionFailed {
		t.Fatalf("status: %v", status)
	}

	opaque := opaqueTag("current", fp)
	ctx = tableCtx(http.MethodPatch, "users", `"`+opaque+`"`, "")
	ctx[easyrest.CtxCacheETagVariant] = fp
	_, status, err = p.PreRequest("test", ctx)
	if err != nil || status != nil {
		t.Fatalf("strong If-Match must not 412, status=%v err=%v", status, err)
	}
}

func TestPreRequestIfResourceVersion(t *testing.T) {
	store := newFakeStore()
	store.values["etag:test:users"] = "current"
	p := mustInit(t, store, nil)
	ctx := tableCtxHeaders(http.MethodPatch, "users", `"stale"`, "", "stale-rev")
	_, status, err := p.PreRequest("test", ctx)
	if err != nil || status == nil || *status != http.StatusPreconditionFailed {
		t.Fatalf("mismatch: status=%v err=%v", status, err)
	}

	ctx = tableCtxHeaders(http.MethodPatch, "users", `"stale"`, "", "current")
	_, status, err = p.PreRequest("test", ctx)
	if err != nil || status != nil {
		t.Fatalf("matching Resource-Version skips If-Match, status=%v err=%v", status, err)
	}

	ctx = tableCtxHeaders(http.MethodPatch, "users", `"stale"`, "", `"current"`)
	_, status, err = p.PreRequest("test", ctx)
	if err != nil || status != nil {
		t.Fatalf("quoted Resource-Version, status=%v err=%v", status, err)
	}
}

func TestPreRequestWeakIfMatchRevision(t *testing.T) {
	store := newFakeStore()
	store.values["etag:test:users"] = "current"
	p := mustInit(t, store, nil)
	ctx := tableCtx(http.MethodPatch, "users", `W/"stale"`, "")
	_, status, err := p.PreRequest("test", ctx)
	if err != nil || status == nil || *status != http.StatusPreconditionFailed {
		t.Fatalf("weak mismatch: status=%v err=%v", status, err)
	}

	ctx = tableCtx(http.MethodPatch, "users", `W/"current"`, "")
	_, status, err = p.PreRequest("test", ctx)
	if err != nil || status != nil {
		t.Fatalf("weak match revision, status=%v err=%v", status, err)
	}
}

func TestPreRequestGETIfMatch412(t *testing.T) {
	store := newFakeStore()
	store.values["etag:test:users"] = "current"
	p := mustInit(t, store, nil)
	fp := jsonFingerprint()
	ctx := tableCtx(http.MethodGet, "users", `"stale"`, "")
	ctx[easyrest.CtxCacheETagVariant] = fp
	_, status, err := p.PreRequest("test", ctx)
	if err != nil || status == nil || *status != http.StatusPreconditionFailed {
		t.Fatalf("GET If-Match: status=%v err=%v", status, err)
	}
}

func TestPreRequestNoGetOnPlainWrite(t *testing.T) {
	store := newFakeStore()
	p := mustInit(t, store, nil)
	ctx := tableCtx(http.MethodPost, "users", "", "")
	_, status, err := p.PreRequest("test", ctx)
	if err != nil || status != nil {
		t.Fatalf("expected pass-through, got status=%v err=%v", status, err)
	}
	if len(store.gets) != 0 {
		t.Fatalf("Get called: %#v", store.gets)
	}
	if len(store.sets) != 0 {
		t.Fatalf("Set called: %#v", store.sets)
	}
}

func TestPreRequestGETSetsETag(t *testing.T) {
	store := newFakeStore()
	p := mustInit(t, store, nil)
	ctx := tableCtx(http.MethodGet, "users", "", "")
	got, status, err := p.PreRequest("test", ctx)
	if err != nil || status != nil {
		t.Fatalf("expected continue, got status=%v err=%v", status, err)
	}
	etag, _ := got[headerETag].(string)
	if etag == "" {
		t.Fatal("expected ETag in ctx")
	}
	rev := store.values["etag:test:users"]
	if rev == "" || rev == etag {
		t.Fatalf("store must keep UUID, got %#v etag=%q", store.values, etag)
	}
	if got[headerResourceVersion] != rev {
		t.Fatalf("resource-version: %#v store=%q", got[headerResourceVersion], rev)
	}
	if etag != quoteETag(opaqueTag(rev, ""), false) {
		t.Fatalf("etag: %q", etag)
	}
}

func TestPreRequestSkipsNonTable(t *testing.T) {
	store := newFakeStore()
	p := mustInit(t, store, nil)
	_, status, err := p.PreRequest("test", map[string]any{"method": http.MethodGet})
	if err != nil || status != nil {
		t.Fatalf("expected skip, got status=%v err=%v", status, err)
	}
	if len(store.gets) != 0 {
		t.Fatalf("Get called: %#v", store.gets)
	}
}

func TestPostRequestBumpOnSuccessWrite(t *testing.T) {
	store := newFakeStore()
	store.values["etag:test:users"] = "old"
	p := mustInit(t, store, nil)
	headers, err := p.PostRequest("test", map[string]any{
		easyrest.CtxTable:         "users",
		easyrest.CtxHandlerStatus: http.StatusCreated,
		"method":                  http.MethodPost,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if headers["ETag"] == "" || headers["ETag"] == "old" {
		t.Fatalf("headers: %#v", headers)
	}
	rev := store.values["etag:test:users"]
	if rev == "" || rev == "old" {
		t.Fatalf("store: %#v", store.values)
	}
	if headers["Resource-Version"] != rev {
		t.Fatalf("resource-version: %#v store=%q", headers, rev)
	}
	if headers["ETag"] != quoteETag(opaqueTag(rev, ""), true) {
		t.Fatalf("etag: %#v", headers)
	}
}

func TestPostRequestNoBumpOnError(t *testing.T) {
	store := newFakeStore()
	store.values["etag:test:users"] = "old"
	p := mustInit(t, store, nil)
	headers, err := p.PostRequest("test", map[string]any{
		easyrest.CtxTable:         "users",
		easyrest.CtxHandlerStatus: http.StatusInternalServerError,
		"method":                  http.MethodPost,
	})
	if err != nil || headers != nil {
		t.Fatalf("expected no bump, got headers=%#v err=%v", headers, err)
	}
	if store.values["etag:test:users"] != "old" {
		t.Fatalf("store changed: %#v", store.values)
	}
	if len(store.sets) != 0 {
		t.Fatalf("Set called: %#v", store.sets)
	}
}

func TestPostRequestNoBumpOnGET(t *testing.T) {
	store := newFakeStore()
	p := mustInit(t, store, nil)
	headers, err := p.PostRequest("test", map[string]any{
		easyrest.CtxTable:         "users",
		easyrest.CtxHandlerStatus: http.StatusOK,
		"method":                  http.MethodGet,
	})
	if err != nil || headers != nil {
		t.Fatalf("expected no bump, got headers=%#v err=%v", headers, err)
	}
}

func TestPostRequestCacheInvalidateGET(t *testing.T) {
	store := newFakeStore()
	store.values["etag:test:users"] = "u1"
	store.values["etag:test:orders"] = "o1"
	p := mustInit(t, store, nil)
	headers, err := p.PostRequest("test", map[string]any{
		easyrest.CtxHandlerStatus:   http.StatusOK,
		easyrest.CtxCacheInvalidate: "users, orders",
		"method":                    http.MethodGet,
	})
	if err != nil || headers != nil {
		t.Fatalf("expected no ETag header, got %#v err=%v", headers, err)
	}
	if store.values["etag:test:users"] == "u1" || store.values["etag:test:orders"] == "o1" {
		t.Fatalf("expected both keys bumped: %#v", store.values)
	}
}

func TestPostRequestCacheInvalidateSkipsError(t *testing.T) {
	store := newFakeStore()
	store.values["etag:test:users"] = "old"
	p := mustInit(t, store, nil)
	headers, err := p.PostRequest("test", map[string]any{
		easyrest.CtxHandlerStatus:   http.StatusInternalServerError,
		easyrest.CtxCacheInvalidate: "users",
		"method":                    http.MethodGet,
	})
	if err != nil || headers != nil {
		t.Fatalf("expected no bump, got headers=%#v err=%v", headers, err)
	}
	if store.values["etag:test:users"] != "old" {
		t.Fatalf("store changed: %#v", store.values)
	}
	if len(store.sets) != 0 {
		t.Fatalf("Set called: %#v", store.sets)
	}
}

func TestPostRequestCacheInvalidateSkipsJunk(t *testing.T) {
	store := newFakeStore()
	p := mustInit(t, store, nil)
	_, err := p.PostRequest("test", map[string]any{
		easyrest.CtxHandlerStatus:   http.StatusOK,
		easyrest.CtxCacheInvalidate: "users, foo-bar, ,public.v_users",
		"method":                    http.MethodGet,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if store.values["etag:test:users"] == "" || store.values["etag:test:public.v_users"] == "" {
		t.Fatalf("expected valid names bumped: %#v", store.values)
	}
	if _, ok := store.values["etag:test:foo-bar"]; ok {
		t.Fatalf("junk token stored: %#v", store.values)
	}
}

func TestPostRequestCacheInvalidateWithWriteETag(t *testing.T) {
	store := newFakeStore()
	store.values["etag:test:users"] = "old-users"
	store.values["etag:test:orders"] = "old-orders"
	p := mustInit(t, store, nil)
	headers, err := p.PostRequest("test", map[string]any{
		easyrest.CtxTable:           "users",
		easyrest.CtxHandlerStatus:   http.StatusCreated,
		easyrest.CtxCacheInvalidate: "orders",
		"method":                    http.MethodPost,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if headers["ETag"] == "" || headers["ETag"] == "old-users" {
		t.Fatalf("headers: %#v", headers)
	}
	rev := store.values["etag:test:users"]
	if headers["Resource-Version"] != rev {
		t.Fatalf("users etag: %#v", store.values)
	}
	if store.values["etag:test:orders"] == "old-orders" {
		t.Fatalf("orders not bumped: %#v", store.values)
	}
}

func TestPostRequestRPCInvalidation(t *testing.T) {
	store := newFakeStore()
	store.values["etag:mydb:users"] = "u1"
	store.values["etag:mydb:orders"] = "o1"
	p := mustInit(t, store, map[string]any{
		"invalidation_map": map[string]any{
			"mydb": map[string]any{
				"refresh": []string{"users", "orders"},
			},
		},
	})
	headers, err := p.PostRequest("mydb", map[string]any{
		easyrest.CtxFunction:      "refresh",
		easyrest.CtxHandlerStatus: http.StatusOK,
		"method":                  http.MethodPost,
	})
	if err != nil || headers != nil {
		t.Fatalf("expected no ETag header, got %#v err=%v", headers, err)
	}
	if store.values["etag:mydb:users"] == "u1" || store.values["etag:mydb:orders"] == "o1" {
		t.Fatalf("expected both tables bumped: %#v", store.values)
	}
}

func TestPostRequestRPCNoBumpOnError(t *testing.T) {
	store := newFakeStore()
	store.values["etag:mydb:users"] = "u1"
	p := mustInit(t, store, map[string]any{
		"invalidation_map": map[string]any{
			"mydb": map[string]any{"refresh": []string{"users"}},
		},
	})
	_, err := p.PostRequest("mydb", map[string]any{
		easyrest.CtxFunction:      "refresh",
		easyrest.CtxHandlerStatus: http.StatusBadRequest,
		"method":                  http.MethodPost,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if store.values["etag:mydb:users"] != "u1" {
		t.Fatalf("store changed: %#v", store.values)
	}
}

func TestEnsureCtx(t *testing.T) {
	if ensureCtx(nil) == nil {
		t.Fatal("nil should allocate")
	}
	in := map[string]any{"a": 1}
	if ensureCtx(in)["a"] != 1 {
		t.Fatal("existing ctx")
	}
}

func TestHeaderOfAndParseTTL(t *testing.T) {
	if headerOf(nil, "if-match") != "" {
		t.Fatal("nil ctx")
	}
	if headerOf(map[string]any{}, "if-match") != "" {
		t.Fatal("missing headers")
	}
	if headerOf(map[string]any{ctxHeaders: map[string]any{"if-match": 12}}, "if-match") != "12" {
		t.Fatal("non-string header")
	}
	if headerOf(map[string]any{ctxHeaders: map[string]any{"if-match": "abc"}}, "if-match") != "abc" {
		t.Fatal("string header")
	}
	d, err := parseTTL("2s")
	if err != nil || d != 2*time.Second {
		t.Fatalf("duration string: %v %v", d, err)
	}
	d, err = parseTTL(5 * time.Second)
	if err != nil || d != 5*time.Second {
		t.Fatalf("duration value: %v %v", d, err)
	}
	d, err = parseTTL(7)
	if err != nil || d != 7*time.Second {
		t.Fatalf("int seconds: %v %v", d, err)
	}
	if _, err := parseTTL(struct{}{}); err == nil {
		t.Fatal("expected invalid ttl")
	}
}

func TestPlugin_KeyAccess(t *testing.T) {
	store := newFakeStore()
	p := mustInit(t, store, map[string]any{"ttl": "30s"})
	if err := p.Set("k", "v", nil); err != nil {
		t.Fatal(err)
	}
	if store.lastTTL != 30*time.Second {
		t.Fatalf("ttl = %s", store.lastTTL)
	}
	fiveSeconds := 5 * time.Second
	if err := p.Set("k", "v", &fiveSeconds); err != nil {
		t.Fatal(err)
	}
	if store.lastTTL != fiveSeconds {
		t.Fatalf("ttl = %s", store.lastTTL)
	}
	zero := time.Duration(0)
	if err := p.Set("k", "v", &zero); err == nil {
		t.Fatal("expected zero ttl error")
	}
	if store.lastTTL != fiveSeconds {
		t.Fatalf("ttl changed to %s", store.lastTTL)
	}
	got, err := p.Get("k")
	if err != nil || got != "v" {
		t.Fatalf("Get = %q, %v", got, err)
	}
	if err := p.Delete("k"); err != nil {
		t.Fatal(err)
	}
	_, err = p.Get("k")
	if !errors.Is(err, easyrest.ErrCacheMiss) {
		t.Fatalf("Get after delete: %v", err)
	}
}
