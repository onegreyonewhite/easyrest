package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestStorageHTTP(t *testing.T) {
	orig := GetConfig()
	t.Cleanup(func() {
		SetConfig(orig)
		LoadPlugins()
	})

	dir := filepath.Join(t.TempDir(), "media")
	SetConfig(config.Config{
		StoragePlugins: map[string]config.StoragePluginConfig{
			"local":  {Settings: map[string]any{"dir": dir}},
			"memory": {},
			"dbglob": {},
		},
	})
	router := SetupRouter()

	localPlug := (*storagePlugins.Load())["local"].Plugin
	if _, _, err := localPlug.Put("note.txt", []byte("hello"), nil); err != nil {
		t.Fatal(err)
	}
	memPlug := (*storagePlugins.Load())["memory"].Plugin
	if _, _, err := memPlug.Put("note.txt", []byte("mem"), nil); err != nil {
		t.Fatal(err)
	}

	assertStorageGET(t, router, "/media/local/note.txt", http.StatusOK, "hello", "text/plain; charset=utf-8")
	assertStorageGET(t, router, "/media/memory/note.txt", http.StatusOK, "mem", "text/plain; charset=utf-8")
	assertStorageGET(t, router, "/media/local/missing.txt", http.StatusNotFound, "", "")
	assertStorageGET(t, router, "/media/dbglob/note.txt", http.StatusNotFound, "", "")
	assertStorageGET(t, router, "/media/static/swagger-ui.css", http.StatusOK, "", "text/css; charset=utf-8")
	assertStorageGET(t, router, "/media/static/swagger-ui-bundle.js", http.StatusOK, "", "text/javascript; charset=utf-8")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/media/local/note.txt", nil)
	router.ServeHTTP(rr, req)
	etag := rr.Header().Get("ETag")
	lastMod := rr.Header().Get("Last-Modified")
	if etag == "" || lastMod == "" {
		t.Fatalf("etag %q last-modified %q", etag, lastMod)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/media/local/note.txt", nil)
	req.Header.Set("If-None-Match", etag)
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotModified {
		t.Fatalf("etag status %d body %q", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/media/local/note.txt", nil)
	req.Header.Set("If-Modified-Since", lastMod)
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotModified {
		t.Fatalf("mtime status %d body %q", rr.Code, rr.Body.String())
	}
}

var storageAuthTestClaims map[string]any

type storageAuthTestPlugin struct{}

func (storageAuthTestPlugin) Init(map[string]any, easyrest.HostRPC) (easyrest.AuthInfo, error) {
	return easyrest.NewAuthInfo(map[string]any{"type": "apiKey"}), nil
}

func (storageAuthTestPlugin) Authenticate(headers map[string]string, _ string, _ string, _ string) (map[string]any, error) {
	if headers["authorization"] == "" {
		return nil, errors.New("missing credentials")
	}
	out := map[string]any{}
	for k, v := range storageAuthTestClaims {
		out[k] = v
	}
	return out, nil
}

func setupStorageAuthRouter(t *testing.T, cfg config.Config) http.Handler {
	t.Helper()
	origPreserved := PreservedAuthPlugins
	origCfg := GetConfig()
	t.Cleanup(func() {
		PreservedAuthPlugins = origPreserved
		SetConfig(origCfg)
		LoadPlugins()
	})
	PreservedAuthPlugins = map[string]PreservedPluginFactory[easyrest.AuthPlugin]{
		"jwt": func() easyrest.AuthPlugin { return storageAuthTestPlugin{} },
	}
	if cfg.AuthPlugins == nil {
		cfg.AuthPlugins = map[string]config.AuthConfig{"jwt": {}}
	}
	SetConfig(cfg)
	LoadPlugins()
	return buildRouter()
}

func TestStorageHTTPAuth(t *testing.T) {
	storageAuthTestClaims = map[string]any{"sub": "u", "scope": "read"}

	putFile := func() {
		loaded := storagePlugins.Load()
		if loaded == nil {
			t.Fatal("storage plugins not loaded")
		}
		memPlug := (*loaded)["memory"].Plugin
		if memPlug == nil {
			t.Fatal("memory storage missing")
		}
		if _, _, err := memPlug.Put("note.txt", []byte("mem"), nil); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("public ignores auth_scopes", func(t *testing.T) {
		router := setupStorageAuthRouter(t, config.Config{
			CheckScope: true,
			StoragePlugins: map[string]config.StoragePluginConfig{
				"memory": {AuthScopes: []string{"files"}},
			},
		})
		putFile()
		assertStorageGET(t, router, "/media/memory/note.txt", http.StatusOK, "mem", "text/plain; charset=utf-8")
	})

	t.Run("jwt without credentials", func(t *testing.T) {
		router := setupStorageAuthRouter(t, config.Config{
			CheckScope: true,
			StoragePlugins: map[string]config.StoragePluginConfig{
				"memory": {Auth: []string{"jwt"}},
			},
		})
		putFile()
		assertStorageGET(t, router, "/media/memory/note.txt", http.StatusUnauthorized, "", "")
	})

	t.Run("jwt with read scope", func(t *testing.T) {
		storageAuthTestClaims = map[string]any{"sub": "u", "scope": "read"}
		router := setupStorageAuthRouter(t, config.Config{
			CheckScope: true,
			StoragePlugins: map[string]config.StoragePluginConfig{
				"memory": {Auth: []string{"jwt"}},
			},
		})
		putFile()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/media/memory/note.txt", nil)
		req.Header.Set("Authorization", "Bearer tok")
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK || rr.Body.String() != "mem" {
			t.Fatalf("status %d body %q", rr.Code, rr.Body.String())
		}
	})

	t.Run("jwt without read scope", func(t *testing.T) {
		storageAuthTestClaims = map[string]any{"sub": "u", "scope": "write"}
		router := setupStorageAuthRouter(t, config.Config{
			CheckScope: true,
			StoragePlugins: map[string]config.StoragePluginConfig{
				"memory": {Auth: []string{"jwt"}},
			},
		})
		putFile()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/media/memory/note.txt", nil)
		req.Header.Set("Authorization", "Bearer tok")
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status %d body %q", rr.Code, rr.Body.String())
		}
	})

	t.Run("custom auth_scopes", func(t *testing.T) {
		storageAuthTestClaims = map[string]any{"sub": "u", "scope": "files"}
		router := setupStorageAuthRouter(t, config.Config{
			CheckScope: true,
			StoragePlugins: map[string]config.StoragePluginConfig{
				"memory": {Auth: []string{"jwt"}, AuthScopes: []string{"files"}},
			},
		})
		putFile()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/media/memory/note.txt", nil)
		req.Header.Set("Authorization", "Bearer tok")
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("files scope status %d body %q", rr.Code, rr.Body.String())
		}

		storageAuthTestClaims = map[string]any{"sub": "u", "scope": "read"}
		router = setupStorageAuthRouter(t, config.Config{
			CheckScope: true,
			StoragePlugins: map[string]config.StoragePluginConfig{
				"memory": {Auth: []string{"jwt"}, AuthScopes: []string{"files"}},
			},
		})
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/media/memory/note.txt", nil)
		req.Header.Set("Authorization", "Bearer tok")
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("read-only scope status %d body %q", rr.Code, rr.Body.String())
		}
	})
}

func assertStorageGET(t *testing.T, router http.Handler, path string, status int, body, mimeType string) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	router.ServeHTTP(rr, req)
	if rr.Code != status {
		t.Fatalf("%s status %d body %q", path, rr.Code, rr.Body.String())
	}
	if body != "" && rr.Body.String() != body {
		t.Fatalf("%s body %q", path, rr.Body.String())
	}
	if mimeType != "" && rr.Header().Get("Content-Type") != mimeType {
		t.Fatalf("%s content-type %q", path, rr.Header().Get("Content-Type"))
	}
}
