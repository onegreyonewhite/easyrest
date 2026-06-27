package tests

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/onegreyonewhite/easyrest/internal/config"
	"github.com/onegreyonewhite/easyrest/internal/server"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	sqlitePlugin "github.com/onegreyonewhite/easyrest/plugins/data/sqlite"
	_ "modernc.org/sqlite"
)

func setupQueryTestDB(t *testing.T) string {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "usequery-test-*.db")
	if err != nil {
		t.Fatalf("Failed to create temporary DB: %v", err)
	}
	dbPath := tmpFile.Name()
	tmpFile.Close()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open sqlite DB: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT
	)`)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}
	_, err = db.Exec(`INSERT INTO users (name) VALUES ('Alice')`)
	if err != nil {
		t.Fatalf("Failed to insert row: %v", err)
	}
	return dbPath
}

func registerSQLitePreservedPlugins() {
	server.PreservedDbPlugins["sqlite"] = func() easyrest.DBPlugin {
		return sqlitePlugin.NewSqlitePlugin()
	}
	server.PreservedCachePlugins["sqlite"] = func() easyrest.CachePlugin {
		return sqlitePlugin.NewSqliteCachePlugin()
	}
	server.PreservedQueryPlugins["sqlite"] = func() easyrest.DBQueryPlugin {
		return sqlitePlugin.NewSqliteQueryPlugin()
	}
}

func TestUseQueryEnabled(t *testing.T) {
	dbPath := setupQueryTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	os.Setenv("ER_DB_TEST", "sqlite://"+dbPath)
	os.Setenv("ER_USE_QUERY_TEST", "1")
	os.Setenv("ER_CHECK_SCOPE", "0")
	os.Setenv("ER_TOKEN_SECRET", "mytestsecret")
	os.Setenv("ER_TOKEN_USER_SEARCH", "sub")

	registerSQLitePreservedPlugins()
	server.ReloadConfig()

	cfg := server.GetConfig()
	cfg.PluginMap["test"] = config.PluginConfig{
		Name:     "test",
		Uri:      "sqlite://" + dbPath,
		UseQuery: true,
	}
	server.SetConfig(cfg)

	router := server.SetupRouter()
	tokenStr := generateToken(t)

	t.Run("QUERY returns rows", func(t *testing.T) {
		req, err := http.NewRequest("QUERY", "/api/test/", strings.NewReader("SELECT id, name FROM users"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("Expected status 200, got %d, response: %s", rr.Code, rr.Body.String())
		}

		var result []map[string]any
		if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}
		if len(result) != 1 {
			t.Fatalf("Expected 1 row, got %d", len(result))
		}
		if result[0]["name"] != "Alice" {
			t.Errorf("Expected name Alice, got %v", result[0]["name"])
		}
	})

	t.Run("DB plugin not loaded", func(t *testing.T) {
		currentDbPlugins := *server.DbPlugins.Load()
		if _, ok := currentDbPlugins["test"]; ok {
			t.Fatal("Expected DB plugin not to be loaded when use_query is true")
		}

		req, err := http.NewRequest("GET", "/api/test/users/?select=id,name", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("Expected status 404, got %d, response: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("Query plugin loaded", func(t *testing.T) {
		currentQueryPlugins := *server.QueryPlugins.Load()
		if _, ok := currentQueryPlugins["test"]; !ok {
			t.Fatal("Expected Query plugin to be loaded when use_query is true")
		}
	})
}

func TestUseQueryDisabled(t *testing.T) {
	dbPath := setupQueryTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	os.Unsetenv("ER_USE_QUERY_TEST")
	os.Setenv("ER_DB_TEST", "sqlite://"+dbPath)
	os.Setenv("ER_CHECK_SCOPE", "0")
	os.Setenv("ER_TOKEN_SECRET", "mytestsecret")
	os.Setenv("ER_TOKEN_USER_SEARCH", "sub")

	registerSQLitePreservedPlugins()
	server.ReloadConfig()

	cfg := server.GetConfig()
	cfg.PluginMap["test"] = config.PluginConfig{
		Name:     "test",
		Uri:      "sqlite://" + dbPath,
		UseQuery: false,
	}
	server.SetConfig(cfg)

	router := server.SetupRouter()
	tokenStr := generateToken(t)

	t.Run("GET table works", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/api/test/users/?select=id,name", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("Expected status 200, got %d, response: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("Query plugin not loaded", func(t *testing.T) {
		currentQueryPlugins := *server.QueryPlugins.Load()
		if _, ok := currentQueryPlugins["test"]; ok {
			t.Fatal("Expected Query plugin not to be loaded when use_query is false")
		}

		req, err := http.NewRequest("QUERY", "/api/test/", strings.NewReader("SELECT id FROM users"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("Expected status 404, got %d, response: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("DB plugin loaded", func(t *testing.T) {
		currentDbPlugins := *server.DbPlugins.Load()
		if _, ok := currentDbPlugins["test"]; !ok {
			t.Fatal("Expected DB plugin to be loaded when use_query is false")
		}
	})
}
