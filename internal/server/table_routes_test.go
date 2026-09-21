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
	gets int
}

func (c *countingDBPlugin) TableGet(string, string, []string, map[string]any, []string, []string, int, int, map[string]any) ([]map[string]any, map[string]any, error) {
	c.gets++
	return []map[string]any{{"id": 1}}, nil, nil
}

type rejectAuthPlugin struct{}

func (rejectAuthPlugin) Init(map[string]any) (map[string]any, error) {
	return map[string]any{"type": "apiKey"}, nil
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
