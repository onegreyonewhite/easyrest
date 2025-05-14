package tests

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/onegreyonewhite/easyrest/internal/config"
	"github.com/onegreyonewhite/easyrest/internal/server"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	sqlitePlugin "github.com/onegreyonewhite/easyrest/plugins/data/sqlite"
)

// TestSanitizeIdentifier verifies that requests containing invalid identifiers
// are rejected with HTTP 400 by the REST layer (before they reach the plugins).
// The server is expected to return StatusBadRequest if sanitizeIdentifier /
// sanitizeIdentifierList detect illegal characters.
func TestSanitizeIdentifier(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	// insert a single row so valid requests succeed later if needed
	insertUser(t, dbPath, "Alice", "")

	router := setupServerWithDB(t, dbPath)

	// ensure preserved sqlite plugin is registered so LoadPlugins succeeds
	cfg := server.GetConfig()
	cfg.PluginMap["test"] = config.PluginConfig{
		Name: "test", Uri: "sqlite://" + dbPath,
	}
	server.SetConfig(cfg)
	server.PreservedDbPlugins["sqlite"] = func() easyrest.DBPlugin {
		return sqlitePlugin.NewSqlitePlugin()
	}
	server.PreservedCachePlugins["sqlite"] = func() easyrest.CachePlugin {
		return sqlitePlugin.NewSqliteCachePlugin()
	}
	server.LoadPlugins()

	tokenStr := generateToken(t)

	tests := []struct {
		name       string
		method     string
		url        string
		expectCode int
	}{
		{
			name:       "invalid_table_name",
			method:     http.MethodGet,
			url:        "/api/test/users-table/?select=id,name",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "invalid_select_field",
			method:     http.MethodGet,
			url:        "/api/test/users/?select=id-name",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "invalid_ordering",
			method:     http.MethodGet,
			url:        "/api/test/users/?ordering=id-name",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "invalid_where_field",
			method:     http.MethodGet,
			url:        "/api/test/users/?where.eq.id-name=1",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "valid_request_control",
			method:     http.MethodGet,
			url:        "/api/test/users/?select=id,name",
			expectCode: http.StatusOK,
		},
		{
			name:       "invalid_table_semicolon",
			method:     http.MethodGet,
			url:        "/api/test/users%3Bdropusers/?select=id,name",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "invalid_select_semicolon",
			method:     http.MethodGet,
			url:        "/api/test/users/?select=id%3Bdropusers",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "invalid_ordering_semicolon",
			method:     http.MethodGet,
			url:        "/api/test/users/?ordering=id%3BDESC",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "value_with_semicolon_ok",
			method:     http.MethodGet,
			url:        "/api/test/users/?where.eq.name=id%3Bdrop",
			expectCode: http.StatusRequestedRangeNotSatisfiable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.url, nil)
			if err != nil {
				t.Fatalf("failed to build request: %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+tokenStr)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != tt.expectCode {
				t.Fatalf("%s: expected status %d, got %d. Response: %s", tt.name, tt.expectCode, rr.Code, rr.Body.String())
			}
		})
	}
}
