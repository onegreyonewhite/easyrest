package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/onegreyonewhite/easyrest/internal/server"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

type mockQueryPlugin struct {
	queryCall func(query string, ctx map[string]any) ([]map[string]any, error)
}

func (m *mockQueryPlugin) InitConnection(uri string) error { return nil }

func (m *mockQueryPlugin) QueryCall(query string, ctx map[string]any) ([]map[string]any, error) {
	return m.queryCall(query, ctx)
}

func TestQueryHandler(t *testing.T) {
	defer server.StopPlugins()

	os.Setenv("ER_TOKEN_SECRET", "mytestsecret")
	server.ReloadConfig()
	router := server.SetupRouter()

	config := server.GetConfig()
	config.CheckScope = true
	config.AnonClaims = nil
	server.SetConfig(config)

	mockPlugin := &mockQueryPlugin{
		queryCall: func(query string, ctx map[string]any) ([]map[string]any, error) {
			return []map[string]any{{"query": query, "method": ctx["method"]}}, nil
		},
	}
	newPlugins := map[string]easyrest.DBQueryPlugin{"mock": mockPlugin}
	server.QueryPlugins.Store(&newPlugins)

	t.Run("plugin not found", func(t *testing.T) {
		req, err := http.NewRequest("QUERY", "/api/unknown/", strings.NewReader("SELECT 1"))
		if err != nil {
			t.Fatal(err)
		}
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("Expected status 404, got %d, response: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("unauthorized without token", func(t *testing.T) {
		req, err := http.NewRequest("QUERY", "/api/mock/", strings.NewReader("SELECT 1"))
		if err != nil {
			t.Fatal(err)
		}
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("Expected status 401, got %d, response: %s", rr.Code, rr.Body.String())
		}
	})

	claimsNoRead := jwt.MapClaims{
		"sub":   "testuser",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": "users-write",
	}
	tokenNoRead := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsNoRead)
	tokenNoReadStr, err := tokenNoRead.SignedString([]byte("mytestsecret"))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	t.Run("forbidden insufficient scope", func(t *testing.T) {
		req, err := http.NewRequest("QUERY", "/api/mock/", strings.NewReader("SELECT 1"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tokenNoReadStr)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("Expected status 403, got %d, response: %s", rr.Code, rr.Body.String())
		}
	})

	claimsRead := jwt.MapClaims{
		"sub":   "testuser",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": "read",
	}
	tokenRead := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsRead)
	tokenReadStr, err := tokenRead.SignedString([]byte("mytestsecret"))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	t.Run("success with read scope", func(t *testing.T) {
		queryBody := "SELECT id, name FROM users WHERE id = 1"
		req, err := http.NewRequest("QUERY", "/api/mock/", strings.NewReader(queryBody))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tokenReadStr)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("Expected status 200, got %d, response: %s", rr.Code, rr.Body.String())
		}

		serverTiming := rr.Header().Get("Server-Timing")
		if serverTiming == "" || !strings.HasPrefix(serverTiming, "db;dur=") {
			t.Errorf("Expected Server-Timing header with db;dur=..., got %q", serverTiming)
		}

		var result []map[string]any
		if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}
		if len(result) != 1 {
			t.Fatalf("Expected 1 row, got %d", len(result))
		}
		if result[0]["query"] != queryBody {
			t.Errorf("Expected query %q, got %v", queryBody, result[0]["query"])
		}
		if result[0]["method"] != "QUERY" {
			t.Errorf("Expected method QUERY in context, got %v", result[0]["method"])
		}
	})

	t.Run("empty query body", func(t *testing.T) {
		req, err := http.NewRequest("QUERY", "/api/mock/", strings.NewReader("   "))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tokenReadStr)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("Expected status 400, got %d, response: %s", rr.Code, rr.Body.String())
		}
	})
}
