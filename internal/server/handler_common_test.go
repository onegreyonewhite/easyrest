package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestResolveAndLoadDBPlugin(t *testing.T) {
	origCfg := GetConfig()
	origDB := DbPlugins.Load()
	t.Cleanup(func() {
		SetConfig(origCfg)
		if origDB != nil {
			DbPlugins.Store(origDB)
		}
	})

	SetConfig(config.Config{
		PluginMap: map[string]config.PluginConfig{
			"app": {},
		},
	})
	plugins := map[string]easyrest.DBPlugin{"app": &fakeDBPlugin{}}
	DbPlugins.Store(&plugins)

	w := httptest.NewRecorder()
	if _, _, _, ok := resolveDBPlugin(w, "app", "easyrest_cache", nil, nil, []string{"easyrest_cache"}); ok {
		t.Fatal("reserved resource should 404")
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("reserved status: %d", w.Code)
	}

	w = httptest.NewRecorder()
	if _, _, _, ok := resolveDBPlugin(w, "app", "hidden", []string{"hidden"}, nil, nil); ok {
		t.Fatal("excluded resource should 404")
	}

	w = httptest.NewRecorder()
	if _, _, _, ok := resolveDBPlugin(w, "app", "orders", nil, []string{"users"}, nil); ok {
		t.Fatal("not in allowlist should 404")
	}

	w = httptest.NewRecorder()
	plug, _, _, ok := resolveDBPlugin(w, "app", "users", nil, []string{"users"}, nil)
	if !ok || plug == nil {
		t.Fatal("expected allowed plugin")
	}

	w = httptest.NewRecorder()
	if _, _, _, ok := resolveDBPlugin(w, "missing", "users", nil, nil, nil); ok {
		t.Fatal("missing db key should 404")
	}

	w = httptest.NewRecorder()
	if _, ok := loadDBPlugin(w, "app"); !ok {
		t.Fatal("load existing")
	}
	w = httptest.NewRecorder()
	if _, ok := loadDBPlugin(w, "missing"); ok {
		t.Fatal("load missing")
	}
}

func TestEnforceScopeAndPreference(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if !enforceScope(httptest.NewRecorder(), r, false, false, "users.read") {
		t.Fatal("checkScope disabled")
	}
	if !enforceScope(httptest.NewRecorder(), r, true, true, "users.read") {
		t.Fatal("public")
	}

	w := httptest.NewRecorder()
	if enforceScope(w, r, true, false, "users.read") {
		t.Fatal("missing claims should forbid")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: %d", w.Code)
	}

	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(context.WithValue(r.Context(), TokenClaimsKey, jwt.MapClaims{"scope": "users.read"}))
	if !enforceScope(httptest.NewRecorder(), r, true, false, "users.read") {
		t.Fatal("sufficient scope")
	}

	w = httptest.NewRecorder()
	setPreferenceApplied(w, map[string]any{
		"prefer":   map[string]any{"tx": "commit"},
		"timezone": "UTC",
	})
	if got := w.Header().Get("Preference-Applied"); got != "tx=commit timezone=UTC" {
		t.Fatalf("prefer: %q", got)
	}

	w = httptest.NewRecorder()
	setPreferenceApplied(w, map[string]any{"timezone": "GMT"})
	if got := w.Header().Get("Preference-Applied"); got != "timezone=GMT" {
		t.Fatalf("tz only: %q", got)
	}

	w = httptest.NewRecorder()
	setPreferenceApplied(w, map[string]any{"prefer": map[string]any{"tx": 1}})
	if got := w.Header().Get("Preference-Applied"); got != "timezone=" {
		t.Fatalf("non-string tx: %q", got)
	}

	w = httptest.NewRecorder()
	setDBServerTiming(w, 12*time.Millisecond)
	if w.Header().Get("Server-Timing") == "" {
		t.Fatal("expected server-timing")
	}

	if err := validateSelectAlias("", "x"); err != nil {
		t.Fatal(err)
	}
	if err := validateSelectAlias("ok", "x"); err != nil {
		t.Fatal(err)
	}
	if err := validateSelectAlias("bad-alias", "x"); err == nil {
		t.Fatal("expected invalid alias")
	}

	orig := GetConfig()
	t.Cleanup(func() { SetConfig(orig) })
	SetConfig(config.Config{CORS: config.CORSConfig{
		Enabled: true,
		Origins: []string{"https://ok.test", "*"},
		Methods: []string{"GET"},
		Headers: []string{"Authorization"},
		MaxAge:  10,
	}})
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	cors := corsMiddleware(okHandler)
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	cors.ServeHTTP(httptest.NewRecorder(), r)
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "https://ok.test")
	w = httptest.NewRecorder()
	cors.ServeHTTP(w, r)
	if w.Header().Get("Access-Control-Allow-Origin") != "https://ok.test" {
		t.Fatalf("cors origin: %s", w.Header().Get("Access-Control-Allow-Origin"))
	}
	r = httptest.NewRequest(http.MethodOptions, "/", nil)
	r.Header.Set("Origin", "https://ok.test")
	w = httptest.NewRecorder()
	cors.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("preflight: %d", w.Code)
	}
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", strings.Repeat("x", 1025))
	w = httptest.NewRecorder()
	cors.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("long origin: %d", w.Code)
	}

	okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for _, mw := range []func(http.Handler) http.Handler{
		clientIPMiddleware(config.ServerConfig{TrustedProxyMode: "header"}),
		clientIPMiddleware(config.ServerConfig{TrustedProxyMode: "header", TrustedProxyHeader: "X-Client"}),
		clientIPMiddleware(config.ServerConfig{TrustedProxyMode: "xff_count"}),
		clientIPMiddleware(config.ServerConfig{TrustedProxyMode: "xff_count", TrustedProxyCount: 0}),
		clientIPMiddleware(config.ServerConfig{TrustedProxyMode: "remote"}),
	} {
		mw(okHandler).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}
}
