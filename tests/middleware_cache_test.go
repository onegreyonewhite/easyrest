package tests

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/onegreyonewhite/easyrest/internal/config"
	"github.com/onegreyonewhite/easyrest/internal/server"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	jwtplugin "github.com/onegreyonewhite/easyrest/plugins/auth/jwt"
	lruPlugin "github.com/onegreyonewhite/easyrest/plugins/data/lru"
	sqlitePlugin "github.com/onegreyonewhite/easyrest/plugins/data/sqlite"
	cachemw "github.com/onegreyonewhite/easyrest/plugins/middleware/cache"
	_ "modernc.org/sqlite"
)

type countingTableGetPlugin struct {
	easyrest.DBPlugin
	gets int
}

func (c *countingTableGetPlugin) TableGet(userID, table string, selectFields []string, where map[string]any, ordering, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, map[string]any, error) {
	c.gets++
	return c.DBPlugin.TableGet(userID, table, selectFields, where, ordering, groupBy, limit, offset, ctx)
}

func setupCacheMiddlewareIntegration(t *testing.T) (http.Handler, *countingTableGetPlugin, func()) {
	t.Helper()

	origPreserved := server.PreservedMiddlewarePlugins["cache-lru"]
	server.PreservedMiddlewarePlugins["cache-lru"] = func() easyrest.MiddlewarePlugin {
		return cachemw.New(lruPlugin.NewSimpleCachePlugin())
	}
	server.PreservedAuthPlugins["jwt"] = func() easyrest.AuthPlugin {
		return &jwtplugin.JWTAuthPlugin{}
	}
	db := &countingTableGetPlugin{}
	server.PreservedDbPlugins["sqlite"] = func() easyrest.DBPlugin {
		db.DBPlugin = sqlitePlugin.NewSqlitePlugin()
		return db
	}

	dbPath := setupTestDB(t)
	os.Setenv("ER_DB_TEST", "sqlite://"+dbPath)
	os.Setenv("ER_CHECK_SCOPE", "0")
	os.Setenv("ER_TOKEN_SECRET", "mytestsecret")
	os.Setenv("ER_TOKEN_USER_SEARCH", "sub")

	cfg := config.Load()
	cfg.MiddlewarePlugins = map[string]config.MiddlewareConfig{
		"cache-lru": {Settings: map[string]any{"ttl": "24h"}},
	}
	pl := cfg.PluginMap["test"]
	pl.RequestMiddlewares = []string{"cache-lru"}
	cfg.PluginMap["test"] = pl
	server.SetConfig(cfg)

	router := server.SetupRouter()
	insertUser(t, dbPath, "Alice", "")

	cleanup := func() {
		server.StopPlugins()
		os.Remove(dbPath)
		if origPreserved != nil {
			server.PreservedMiddlewarePlugins["cache-lru"] = origPreserved
		} else {
			delete(server.PreservedMiddlewarePlugins, "cache-lru")
		}
	}
	return router, db, cleanup
}

func cacheAuthGET(t *testing.T, router http.Handler, token, ifNoneMatch string) *httptest.ResponseRecorder {
	return cacheAuthGETAccept(t, router, token, "", ifNoneMatch)
}

func cacheAuthGETAccept(t *testing.T, router http.Handler, token, accept, ifNoneMatch string) *httptest.ResponseRecorder {
	return cacheAuthGETHeaders(t, router, token, http.Header{
		"Accept":        []string{accept},
		"If-None-Match": []string{ifNoneMatch},
	})
}

func cacheAuthGETHeaders(t *testing.T, router http.Handler, token string, extra http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "/api/test/users/?select=id,name", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	for k, vals := range extra {
		for _, v := range vals {
			if v == "" {
				continue
			}
			req.Header.Add(k, v)
		}
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func cacheAuthPATCH(t *testing.T, router http.Handler, token string, extra http.Header, body string) *httptest.ResponseRecorder {
	t.Helper()
	req, err := http.NewRequest(http.MethodPatch, "/api/test/users/?where.eq.id=1", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	for k, vals := range extra {
		for _, v := range vals {
			if v == "" {
				continue
			}
			req.Header.Set(k, v)
		}
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func TestCacheMiddleware_ETag304And412(t *testing.T) {
	router, db, cleanup := setupCacheMiddlewareIntegration(t)
	defer cleanup()
	token := generateToken(t)

	rr := cacheAuthGET(t, router, token, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	etag, rev := assertCacheValidators(t, rr.Header(), false)
	if db.gets != 1 {
		t.Fatalf("200 TableGet calls: %d", db.gets)
	}

	rr = cacheAuthGET(t, router, token, etag)
	if rr.Code != http.StatusNotModified {
		t.Fatalf("expected 304, got %d body=%s", rr.Code, rr.Body.String())
	}
	gotETag, gotRev := assertCacheValidators(t, rr.Header(), false)
	if gotETag != etag || gotRev != rev {
		t.Fatalf("304 validators: ETag %q Resource-Version %q", gotETag, gotRev)
	}
	if db.gets != 1 {
		t.Fatalf("304 must skip TableGet, got %d calls", db.gets)
	}

	rr = cacheAuthGETHeaders(t, router, token, http.Header{"If-Match": []string{`"stale"`}})
	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("GET If-Match stale: expected 412, got %d body=%s", rr.Code, rr.Body.String())
	}

	body := strings.NewReader(`{"name":"Updated"}`)
	req, err := http.NewRequest(http.MethodPatch, "/api/test/users/?where.eq.id=1", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", "stale-etag-value")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = cacheAuthGET(t, router, token, "")
	if rr.Header().Get("ETag") != etag {
		t.Fatalf("412 must not bump ETag: got %q want %q", rr.Header().Get("ETag"), etag)
	}
	if rr.Header().Get("Resource-Version") != rev {
		t.Fatalf("412 must not bump Resource-Version: got %q want %q", rr.Header().Get("Resource-Version"), rev)
	}
}

func TestCacheMiddleware_FormatSpecificETag(t *testing.T) {
	router, db, cleanup := setupCacheMiddlewareIntegration(t)
	defer cleanup()
	token := generateToken(t)

	rr := cacheAuthGETAccept(t, router, token, "application/json", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("JSON GET: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	jsonETag, jsonRev := assertCacheValidators(t, rr.Header(), false)
	if db.gets != 1 {
		t.Fatalf("JSON TableGet calls: %d", db.gets)
	}

	rr = cacheAuthGETAccept(t, router, token, "application/x-ndjson", jsonETag)
	if rr.Code != http.StatusOK {
		t.Fatalf("NDJSON with JSON ETag: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "application/x-ndjson") {
		t.Fatalf("NDJSON content type: %s", rr.Header().Get("Content-Type"))
	}
	ndjsonETag, ndjsonRev := assertCacheValidators(t, rr.Header(), true)
	if ndjsonETag == jsonETag {
		t.Fatalf("NDJSON ETag must differ from JSON, got %q", ndjsonETag)
	}
	if ndjsonRev != jsonRev {
		t.Fatalf("NDJSON Resource-Version %q want %q", ndjsonRev, jsonRev)
	}
	if db.gets != 2 {
		t.Fatalf("NDJSON TableGet calls: %d", db.gets)
	}

	rr = cacheAuthGETAccept(t, router, token, "text/csv", jsonETag)
	if rr.Code != http.StatusOK {
		t.Fatalf("CSV with JSON ETag: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("CSV content type: %s", rr.Header().Get("Content-Type"))
	}
	if db.gets != 3 {
		t.Fatalf("CSV TableGet calls: %d", db.gets)
	}

	rr = cacheAuthGETAccept(t, router, token, "application/json", jsonETag)
	if rr.Code != http.StatusNotModified {
		t.Fatalf("same-format If-None-Match: expected 304, got %d body=%s", rr.Code, rr.Body.String())
	}
	if db.gets != 3 {
		t.Fatalf("304 must skip TableGet, got %d calls", db.gets)
	}

	rr = cacheAuthGETHeaders(t, router, token, http.Header{
		"Accept":        []string{"application/json"},
		"Prefer":        []string{"page_size=1"},
		"If-None-Match": []string{jsonETag},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("Prefer mismatch: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	preferETag, _ := assertCacheValidators(t, rr.Header(), false)
	if preferETag == jsonETag {
		t.Fatalf("Prefer ETag must differ from default JSON, got %q", preferETag)
	}

	rr = cacheAuthGETHeaders(t, router, token, http.Header{
		"Accept":        []string{"application/json"},
		"Range":         []string{"0-0"},
		"Range-Unit":    []string{"items"},
		"If-None-Match": []string{jsonETag},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("Range mismatch: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	_, _ = assertCacheValidators(t, rr.Header(), true)

	rr = cacheAuthGETHeaders(t, router, token, http.Header{
		"Accept":       []string{"application/json"},
		"Content-Type": []string{"application/json"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("JSON GET with Content-Type: expected 200, got %d", rr.Code)
	}
	matchedETag, _ := assertCacheValidators(t, rr.Header(), false)
	rr = cacheAuthPATCH(t, router, token, http.Header{
		"Accept":   []string{"application/json"},
		"If-Match": []string{matchedETag},
	}, `{"name":"Patched"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH If-Match JSON GET ETag: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCacheMiddleware_IfResourceVersionAndWeakIfMatch(t *testing.T) {
	router, _, cleanup := setupCacheMiddlewareIntegration(t)
	defer cleanup()
	token := generateToken(t)

	rr := cacheAuthGET(t, router, token, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	_, rev := assertCacheValidators(t, rr.Header(), false)

	rr = cacheAuthPATCH(t, router, token, http.Header{
		"If-Resource-Version": []string{"not-the-revision"},
	}, `{"name":"Nope"}`)
	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("If-Resource-Version mismatch: expected 412, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = cacheAuthPATCH(t, router, token, http.Header{
		"If-Resource-Version": []string{rev},
		"If-Match":            []string{`"stale"`},
	}, `{"name":"ByVersion"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("matching If-Resource-Version: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Resource-Version"); got == "" || got == rev {
		t.Fatalf("write must bump Resource-Version, got %q previous %q", got, rev)
	}
	if !strings.HasPrefix(rr.Header().Get("ETag"), `W/"`) {
		t.Fatalf("write ETag must be weak, got %q", rr.Header().Get("ETag"))
	}

	rr = cacheAuthGET(t, router, token, "")
	_, rev = assertCacheValidators(t, rr.Header(), false)

	rr = cacheAuthPATCH(t, router, token, http.Header{
		"If-Match": []string{`W/"` + rev + `"`},
	}, `{"name":"ByWeak"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("weak If-Match revision: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = cacheAuthGET(t, router, token, "")
	_, rev = assertCacheValidators(t, rr.Header(), false)
	rr = cacheAuthPATCH(t, router, token, http.Header{
		"If-Match": []string{`W/"not-the-revision"`},
	}, `{"name":"NopeWeak"}`)
	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("weak If-Match mismatch: expected 412, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCacheMiddleware_WriteBumpsETag(t *testing.T) {
	router, _, cleanup := setupCacheMiddlewareIntegration(t)
	defer cleanup()
	token := generateToken(t)

	rr := cacheAuthGET(t, router, token, "")
	etag, rev := assertCacheValidators(t, rr.Header(), false)

	body := strings.NewReader(`[{"name":"Bob","update_field":"x"}]`)
	req, err := http.NewRequest(http.MethodPost, "/api/test/users/", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST: expected 201, got %d body=%s", rr.Code, rr.Body.String())
	}
	postETag := rr.Header().Get("ETag")
	if postETag == "" || postETag == etag {
		t.Fatalf("POST ETag should change, got %q previous %q", postETag, etag)
	}
	if !strings.HasPrefix(postETag, `W/"`) {
		t.Fatalf("POST ETag must be weak, got %q", postETag)
	}
	if got := rr.Header().Get("Resource-Version"); got == "" || got == rev {
		t.Fatalf("POST Resource-Version should change, got %q previous %q", got, rev)
	}
	rev = rr.Header().Get("Resource-Version")

	body = strings.NewReader(`{"name":"Carol"}`)
	req, err = http.NewRequest(http.MethodPatch, "/api/test/users/?where.eq.name=Bob", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	patchETag := rr.Header().Get("ETag")
	if patchETag == "" || patchETag == postETag {
		t.Fatalf("PATCH ETag should change, got %q previous %q", patchETag, postETag)
	}
	if got := rr.Header().Get("Resource-Version"); got == "" || got == rev {
		t.Fatalf("PATCH Resource-Version should change, got %q previous %q", got, rev)
	}
	rev = rr.Header().Get("Resource-Version")

	req, err = http.NewRequest(http.MethodDelete, "/api/test/users/?where.eq.name=Carol", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("DELETE: expected 204, got %d body=%s", rr.Code, rr.Body.String())
	}
	deleteETag := rr.Header().Get("ETag")
	if deleteETag == "" || deleteETag == patchETag {
		t.Fatalf("DELETE ETag should change, got %q previous %q", deleteETag, patchETag)
	}
	if got := rr.Header().Get("Resource-Version"); got == "" || got == rev {
		t.Fatalf("DELETE Resource-Version should change, got %q previous %q", got, rev)
	}
}

func TestCacheMiddleware_ErrorDoesNotBump(t *testing.T) {
	router, _, cleanup := setupCacheMiddlewareIntegration(t)
	defer cleanup()
	token := generateToken(t)

	rr := cacheAuthGET(t, router, token, "")
	etag := rr.Header().Get("ETag")
	if etag == "" {
		t.Fatal("expected ETag")
	}

	body := strings.NewReader(`not-json`)
	req, err := http.NewRequest(http.MethodPost, "/api/test/users/", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code < 400 {
		t.Fatalf("expected error status, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = cacheAuthGET(t, router, token, "")
	if got := rr.Header().Get("ETag"); got != etag {
		t.Fatalf("error must not bump ETag: got %q want %q", got, etag)
	}
}

func TestCacheMiddleware_RPCInvalidation(t *testing.T) {
	origPreserved := server.PreservedMiddlewarePlugins["cache-lru"]
	server.PreservedMiddlewarePlugins["cache-lru"] = func() easyrest.MiddlewarePlugin {
		return cachemw.New(lruPlugin.NewSimpleCachePlugin())
	}
	server.PreservedAuthPlugins["jwt"] = func() easyrest.AuthPlugin {
		return &jwtplugin.JWTAuthPlugin{}
	}
	server.PreservedDbPlugins["sqlite"] = func() easyrest.DBPlugin {
		return sqlitePlugin.NewSqlitePlugin()
	}
	defer func() {
		server.StopPlugins()
		if origPreserved != nil {
			server.PreservedMiddlewarePlugins["cache-lru"] = origPreserved
		} else {
			delete(server.PreservedMiddlewarePlugins, "cache-lru")
		}
	}()

	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	insertUser(t, dbPath, "Alice", "")

	os.Setenv("ER_DB_TEST", "sqlite://"+dbPath)
	os.Setenv("ER_CHECK_SCOPE", "0")
	os.Setenv("ER_TOKEN_SECRET", "mytestsecret")
	os.Setenv("ER_TOKEN_USER_SEARCH", "sub")

	cfg := config.Load()
	cfg.CheckScope = false
	cfg.MiddlewarePlugins = map[string]config.MiddlewareConfig{
		"cache-lru": {
			Settings: map[string]any{
				"ttl": "24h",
				"invalidation_map": map[string]any{
					"test": map[string]any{
						"refresh": []any{"users"},
					},
				},
			},
		},
	}
	pl := cfg.PluginMap["test"]
	pl.RequestMiddlewares = []string{"cache-lru"}
	cfg.PluginMap["test"] = pl
	server.SetConfig(cfg)

	router := server.SetupRouter()
	mock := &mockDBPlugin{
		tableGet: func(userID, table string, selectFields []string, where map[string]any,
			ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, map[string]any, error) {
			return []map[string]any{{"id": 1, "name": "Alice"}}, nil, nil
		},
		callFunction: func(userID, funcName string, data map[string]any, ctx map[string]any) (any, error) {
			return map[string]any{"ok": true}, nil
		},
	}
	current := *server.DbPlugins.Load()
	withMock := make(map[string]easyrest.DBPlugin, len(current)+1)
	for k, v := range current {
		withMock[k] = v
	}
	withMock["test"] = mock
	server.DbPlugins.Store(&withMock)

	token := generateToken(t)
	rr := cacheAuthGET(t, router, token, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	etag := rr.Header().Get("ETag")
	if etag == "" {
		t.Fatal("expected ETag from GET")
	}

	req, err := http.NewRequest(http.MethodPost, "/api/test/rpc/refresh/", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("RPC: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = cacheAuthGET(t, router, token, "")
	got := rr.Header().Get("ETag")
	if got == "" || got == etag {
		t.Fatalf("RPC should invalidate users ETag: got %q previous %q", got, etag)
	}
}
