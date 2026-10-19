package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/onegreyonewhite/easyrest/internal/config"
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
