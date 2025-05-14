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
	"github.com/onegreyonewhite/easyrest/internal/config"
	"github.com/onegreyonewhite/easyrest/internal/server"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// TestEmptyTokenSecret checks behavior when TokenSecret is empty
func TestEmptyTokenSecret(t *testing.T) {
	// Create test database
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	// Setup server with database
	router := setupServerWithDB(t, dbPath)

	// Save original config
	originalConfig := server.GetConfig()

	// Create new config with empty TokenSecret
	newConfig := config.Config{
		Port:            originalConfig.Port,
		CheckScope:      originalConfig.CheckScope,
		TokenUserSearch: originalConfig.TokenUserSearch,
		DefaultTimezone: originalConfig.DefaultTimezone,
	}
	server.SetConfig(newConfig)

	// Restore original config after test
	defer server.SetConfig(originalConfig)

	// Create token
	claims := jwt.MapClaims{
		"sub":   "testuser",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": "users-read users-write",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte("mytestsecret"))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Test 1: POST request to table
	body := strings.NewReader(`[
		{
			"name": "test1",
			"update_field": "test1"
		}
	]`)
	req, err := http.NewRequest("POST", "/api/test/users/", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d, response: %s", rr.Code, rr.Body.String())
	}

	// Check if record was created
	rows := getAllUsers(t, dbPath)
	if len(rows) != 1 {
		t.Fatalf("Expected 1 row, got %d", len(rows))
	}

	// Test 2: RPC request
	// Create mock plugin that simply returns input data
	mockPlugin := &mockDBPlugin{
		callFunction: func(userID, funcName string, data map[string]any, ctx map[string]any) (any, error) {
			return data, nil
		},
	}
	newPluginsMap1 := map[string]easyrest.DBPlugin{"mock": mockPlugin}
	server.DbPlugins.Store(&newPluginsMap1)

	// RPC request
	body = strings.NewReader(`{"test": "value"}`)
	req, err = http.NewRequest("POST", "/api/mock/rpc/test/", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d, response: %s", rr.Code, rr.Body.String())
	}

	// Check response
	var response map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if response["test"] != "value" {
		t.Errorf("Expected test value to be 'value', got '%v'", response["test"])
	}
}

// TestEmptyTokenSecretWithoutToken checks behavior when TokenSecret is empty and no token is provided
func TestEmptyTokenSecretWithoutToken(t *testing.T) {
	// Save original config
	originalConfig := server.GetConfig()

	// Create new config with empty TokenSecret
	newConfig := config.Config{
		Port:            originalConfig.Port,
		CheckScope:      originalConfig.CheckScope,
		TokenUserSearch: originalConfig.TokenUserSearch,
		DefaultTimezone: originalConfig.DefaultTimezone,
	}
	server.SetConfig(newConfig)

	// Restore original config after test
	defer server.SetConfig(originalConfig)

	// Create test database
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	// Setup server
	server.ReloadConfig()
	router := server.SetupRouter()

	// Test 1: POST request to table without token
	body := strings.NewReader(`[
		{
			"name": "test1",
			"update_field": "test1"
		}
	]`)
	req, err := http.NewRequest("POST", "/api/test/users/", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("Expected status 401, got %d, response: %s", rr.Code, rr.Body.String())
	}

	// Test 2: RPC request without token
	// Create mock plugin
	mockPlugin := &mockDBPlugin{
		callFunction: func(userID, funcName string, data map[string]any, ctx map[string]any) (any, error) {
			return data, nil
		},
	}
	newPluginsMap2 := map[string]easyrest.DBPlugin{"mock": mockPlugin}
	server.DbPlugins.Store(&newPluginsMap2)

	body = strings.NewReader(`{"test": "value"}`)
	req, err = http.NewRequest("POST", "/api/mock/rpc/test/", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("Expected status 401, got %d, response: %s", rr.Code, rr.Body.String())
	}
}
