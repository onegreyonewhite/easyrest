package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

type countingDBPlugin struct {
	fakeDBPlugin
	gets    int
	calls   int
	schemas int
}

func (c *countingDBPlugin) TableGet(string, string, []string, map[string]any, []string, []string, int, int, map[string]any) ([]map[string]any, map[string]any, error) {
	c.gets++
	return []map[string]any{{"id": 1}}, nil, nil
}

func (c *countingDBPlugin) CallFunction(string, string, map[string]any, map[string]any) (any, map[string]any, error) {
	c.calls++
	return nil, nil, nil
}

func (c *countingDBPlugin) GetSchema(map[string]any) (any, map[string]any, error) {
	c.schemas++
	return map[string]any{
		"tables": map[string]any{},
		"views":  map[string]any{},
		"rpc":    map[string]any{},
	}, nil, nil
}

type rejectAuthPlugin struct{}

func (rejectAuthPlugin) Init(map[string]any, easyrest.HostRPC) (easyrest.AuthInfo, error) {
	return easyrest.NewAuthInfo(map[string]any{"type": "apiKey"}), nil
}

func (rejectAuthPlugin) Authenticate(map[string]string, string, string, string) (map[string]any, error) {
	return nil, errors.New("nope")
}

func setupTableRouter(t *testing.T, auth easyrest.AuthPlugin, mwName string, mw easyrest.MiddlewarePlugin) (chi.Router, *countingDBPlugin) {
	t.Helper()
	origDB := PreservedDbPlugins
	origQuery := PreservedQueryPlugins
	origAuth := PreservedAuthPlugins
	origMW := PreservedMiddlewarePlugins
	origCfg := GetConfig()
	t.Cleanup(func() {
		PreservedDbPlugins = origDB
		PreservedQueryPlugins = origQuery
		PreservedAuthPlugins = origAuth
		PreservedMiddlewarePlugins = origMW
		SetConfig(origCfg)
		StopPlugins()
	})

	db := &countingDBPlugin{}
	PreservedDbPlugins = map[string]PreservedPluginFactory[easyrest.DBPlugin]{
		"sqlite": func() easyrest.DBPlugin { return db },
	}
	PreservedQueryPlugins = map[string]PreservedPluginFactory[easyrest.DBQueryPlugin]{}
	PreservedAuthPlugins = map[string]PreservedPluginFactory[easyrest.AuthPlugin]{
		"jwt": func() easyrest.AuthPlugin { return auth },
	}
	PreservedMiddlewarePlugins = map[string]PreservedPluginFactory[easyrest.MiddlewarePlugin]{}
	pluginCfg := config.PluginConfig{Uri: "sqlite://memory"}
	mwPlugins := map[string]config.MiddlewareConfig{}
	if mwName != "" && mw != nil {
		PreservedMiddlewarePlugins[mwName] = func() easyrest.MiddlewarePlugin { return mw }
		pluginCfg.RequestMiddlewares = []string{mwName}
		mwPlugins[mwName] = config.MiddlewareConfig{}
	}

	SetConfig(config.Config{
		PluginMap: map[string]config.PluginConfig{
			"test": pluginCfg,
		},
		AuthPlugins: map[string]config.AuthConfig{
			"jwt": {Settings: map[string]any{}},
		},
		MiddlewarePlugins: mwPlugins,
	})
	return SetupRouter(), db
}

func TestTableRoutesMethodNotAllowed(t *testing.T) {
	router, db := setupTableRouter(t, &fakeAuthPlugin{}, "", nil)
	for _, method := range []string{http.MethodPut, http.MethodHead, http.MethodOptions, "QUERY"} {
		req := httptest.NewRequest(method, "/api/test/users/", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s status: %d body=%q", method, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "Method not allowed") {
			t.Fatalf("%s body: %q", method, w.Body.String())
		}
		if w.Header().Get("Allow") != "" {
			t.Fatalf("%s must not set chi Allow header, got %q", method, w.Header().Get("Allow"))
		}
	}
	if db.gets != 0 {
		t.Fatalf("TableGet called %d times on 405 paths", db.gets)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/test/users/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET status: %d body=%q", w.Code, w.Body.String())
	}
	if db.gets != 1 {
		t.Fatalf("GET TableGet calls: %d", db.gets)
	}
}

func TestTableRoutesChiDefault405Unaffected(t *testing.T) {
	router, _ := setupTableRouter(t, &fakeAuthPlugin{}, "", nil)
	for _, path := range []string{"/health", "/api/test/"} {
		req := httptest.NewRequest(http.MethodPut, path, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s status: %d body=%q", path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "Method not allowed") {
			t.Fatalf("%s leaked table 405 body: %q", path, w.Body.String())
		}
	}
}

func TestTableRoutesInternalBeforeAuth(t *testing.T) {
	router, db := setupTableRouter(t, &rejectAuthPlugin{}, "", nil)
	cfg := GetConfig()
	pluginCfg := cfg.PluginMap["test"]
	pluginCfg.Internal = true
	cfg.PluginMap["test"] = pluginCfg
	SetConfig(cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/test/users/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("internal plugin status: %d body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "DB plugin not found") {
		t.Fatalf("internal plugin body: %q", w.Body.String())
	}
	if db.gets != 0 {
		t.Fatalf("TableGet called %d times for an internal plugin", db.gets)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/test/rpc/hello/", strings.NewReader(`{}`))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("internal rpc status: %d body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "DB plugin not found") {
		t.Fatalf("internal rpc body: %q", w.Body.String())
	}
	if db.calls != 0 {
		t.Fatalf("CallFunction called %d times for an internal plugin", db.calls)
	}

	req = httptest.NewRequest(http.MethodPut, "/api/test/users/", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("internal PUT status: %d body=%q", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "Method not allowed") {
		t.Fatalf("internal PUT leaked 405 body: %q", w.Body.String())
	}
}

func TestTableRoutesInternalSchema(t *testing.T) {
	router, db := setupTableRouter(t, &fakeAuthPlugin{}, "", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/test/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("public schema status: %d body=%q", w.Code, w.Body.String())
	}
	if db.schemas != 1 {
		t.Fatalf("public schema calls: %d", db.schemas)
	}

	cfg := GetConfig()
	pluginCfg := cfg.PluginMap["test"]
	pluginCfg.Internal = true
	cfg.PluginMap["test"] = pluginCfg
	SetConfig(cfg)

	req = httptest.NewRequest(http.MethodGet, "/api/test/", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cached internal schema status: %d body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "DB plugin not found") {
		t.Fatalf("cached internal schema body: %q", w.Body.String())
	}
	if db.schemas != 1 {
		t.Fatalf("GetSchema called again after internal: %d", db.schemas)
	}
}

type countingQueryPlugin struct {
	calls int
}

func (c *countingQueryPlugin) InitConnection(string) error { return nil }

func (c *countingQueryPlugin) QueryCall(string, map[string]any) ([]map[string]any, error) {
	c.calls++
	return []map[string]any{{"n": 1}}, nil
}

func TestTableRoutesInternalQuery(t *testing.T) {
	origDB := PreservedDbPlugins
	origQuery := PreservedQueryPlugins
	origAuth := PreservedAuthPlugins
	origMW := PreservedMiddlewarePlugins
	origCfg := GetConfig()
	t.Cleanup(func() {
		PreservedDbPlugins = origDB
		PreservedQueryPlugins = origQuery
		PreservedAuthPlugins = origAuth
		PreservedMiddlewarePlugins = origMW
		SetConfig(origCfg)
		StopPlugins()
	})

	queryPlug := &countingQueryPlugin{}
	PreservedDbPlugins = map[string]PreservedPluginFactory[easyrest.DBPlugin]{
		"sqlite": func() easyrest.DBPlugin { return &fakeDBPlugin{} },
	}
	PreservedQueryPlugins = map[string]PreservedPluginFactory[easyrest.DBQueryPlugin]{
		"sqlite": func() easyrest.DBQueryPlugin { return queryPlug },
	}
	PreservedAuthPlugins = map[string]PreservedPluginFactory[easyrest.AuthPlugin]{
		"jwt": func() easyrest.AuthPlugin { return &rejectAuthPlugin{} },
	}
	PreservedMiddlewarePlugins = map[string]PreservedPluginFactory[easyrest.MiddlewarePlugin]{}
	SetConfig(config.Config{
		PluginMap: map[string]config.PluginConfig{
			"test": {Uri: "sqlite://memory", UseQuery: true, Internal: true},
		},
		AuthPlugins: map[string]config.AuthConfig{
			"jwt": {Settings: map[string]any{}},
		},
	})
	router := SetupRouter()

	req := httptest.NewRequest("QUERY", "/api/test/", strings.NewReader("select 1"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("internal query status: %d body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "DB plugin not found") {
		t.Fatalf("internal query body: %q", w.Body.String())
	}
	if queryPlug.calls != 0 {
		t.Fatalf("QueryCall called %d times for an internal plugin", queryPlug.calls)
	}
}

func TestTableRoutesMissingPluginBeforeAuth(t *testing.T) {
	router, _ := setupTableRouter(t, &rejectAuthPlugin{}, "", nil)
	req := httptest.NewRequest(http.MethodGet, "/api/missing/users/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing plugin status: %d body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "DB plugin not found") {
		t.Fatalf("missing plugin body: %q", w.Body.String())
	}
}

func TestTableRoutesFailedAuth(t *testing.T) {
	router, db := setupTableRouter(t, &rejectAuthPlugin{}, "", nil)
	req := httptest.NewRequest(http.MethodGet, "/api/test/users/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("auth status: %d body=%q", w.Code, w.Body.String())
	}
	if db.gets != 0 {
		t.Fatalf("TableGet after failed auth: %d", db.gets)
	}
}

func TestTableRoutesPreRequestShortCircuit(t *testing.T) {
	status := 418
	router, db := setupTableRouter(t, &fakeAuthPlugin{}, "block", &mockMiddlewarePlugin{
		failStatus: &status,
		failErr:    errTest("short"),
	})
	req := httptest.NewRequest(http.MethodGet, "/api/test/users/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 418 {
		t.Fatalf("PreRequest status: %d body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "short") {
		t.Fatalf("PreRequest body: %q", w.Body.String())
	}
	if db.gets != 0 {
		t.Fatalf("handler ran after PreRequest status: TableGet=%d", db.gets)
	}
}
