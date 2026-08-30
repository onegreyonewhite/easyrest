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

func setupCacheMiddlewareIntegration(t *testing.T) (http.Handler, func()) {
	t.Helper()

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
	return router, cleanup
}

func cacheAuthGET(t *testing.T, router http.Handler, token, ifNoneMatch string) *httptest.ResponseRecorder {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "/api/test/users/?select=id,name", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func TestCacheMiddleware_ETag304And412(t *testing.T) {
	router, cleanup := setupCacheMiddlewareIntegration(t)
	defer cleanup()
	token := generateToken(t)

	rr := cacheAuthGET(t, router, token, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	etag := rr.Header().Get("ETag")
	if etag == "" {
		t.Fatalf("expected ETag on GET, headers=%v", rr.Header())
	}

	rr = cacheAuthGET(t, router, token, etag)
	if rr.Code != http.StatusNotModified {
		t.Fatalf("expected 304, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("ETag") != etag {
		t.Fatalf("304 ETag: got %q want %q", rr.Header().Get("ETag"), etag)
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
}

func TestCacheMiddleware_WriteBumpsETag(t *testing.T) {
	router, cleanup := setupCacheMiddlewareIntegration(t)
	defer cleanup()
	token := generateToken(t)

	rr := cacheAuthGET(t, router, token, "")
	etag := rr.Header().Get("ETag")
	if etag == "" {
		t.Fatal("expected ETag")
	}

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
}

func TestCacheMiddleware_ErrorDoesNotBump(t *testing.T) {
	router, cleanup := setupCacheMiddlewareIntegration(t)
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
