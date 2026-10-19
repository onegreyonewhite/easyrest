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
)

func TestYAMLContentPlugin(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	applyTestConfig(t, testSQLiteYAML("sqlite://"+dbPath, false, ""))
	cfg := server.GetConfig()
	if cfg.ContentPlugins == nil {
		cfg.ContentPlugins = map[string]config.ExternalPlugin{}
	}
	cfg.ContentPlugins["yaml"] = config.ExternalPlugin{}
	cfg.DefaultContentHandlers = []string{"yaml", "json", "ndjson", "xml", "csv", "form"}
	server.SetConfig(cfg)
	router := server.SetupRouter()
	tokenStr := generateToken(t)

	body := strings.NewReader("- name: Ada\n  update_field: yaml1\n")
	req, err := http.NewRequest(http.MethodPost, "/api/test/users/", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", easyrest.MediaTypeYAML)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST %d: %s", rr.Code, rr.Body.String())
	}

	req, err = http.NewRequest(http.MethodGet, "/api/test/users/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Accept", easyrest.MediaTypeYAML)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET %d: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, easyrest.MediaTypeYAML) {
		t.Fatalf("Content-Type %q", got)
	}
	if !strings.Contains(rr.Body.String(), "Ada") || !strings.Contains(rr.Body.String(), "yaml1") {
		t.Fatalf("body %s", rr.Body.String())
	}
}
