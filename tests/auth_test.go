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
)

// TestEmptyTokenSecret checks behavior when TokenSecret is empty
func TestEmptyTokenSecret(t *testing.T) {
	// Create test database
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)

	// Setup server with database
	router := setupServerWithDB(t, dbPath)

	// Save original config
	originalConfig := server.GetConfig()

	// Create new config with empty TokenSecret
	newConfig := config.Config{
		Port:            originalConfig.Port,
		CheckScope:      originalConfig.CheckScope,
		TokenSecret:     "",
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
	tokenStr, err := token.SignedString([]byte("any_secret")) // Use any secret since validation will be skipped
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
	server.DbPlugins["mock"] = mockPlugin

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
		TokenSecret:     "",
		TokenUserSearch: originalConfig.TokenUserSearch,
		DefaultTimezone: originalConfig.DefaultTimezone,
	}
	server.SetConfig(newConfig)

	// Restore original config after test
	defer server.SetConfig(originalConfig)

	// Create test database
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)

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
	server.DbPlugins["mock"] = mockPlugin

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

// TestTokenURL checks ER_TOKEN_URL functionality
func TestTokenURL(t *testing.T) {
	// Create test database
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)

	// Setup server with database
	router := setupServerWithDB(t, dbPath)

	// Save original config
	originalConfig := server.GetConfig()

	// Create new config with empty TokenSecret and set TokenURL
	newConfig := config.Config{
		Port:            originalConfig.Port,
		CheckScope:      originalConfig.CheckScope,
		TokenSecret:     "",
		TokenUserSearch: originalConfig.TokenUserSearch,
		DefaultTimezone: originalConfig.DefaultTimezone,
		TokenURL:        "http://auth.example.com/token",
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
	tokenStr, err := token.SignedString([]byte("any_secret"))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Test 1: Successful token verification (code 200)
	os.Setenv("ER_TOKEN_URL", "http://auth.example.com/token")
	server.SetConfig(server.GetConfig())

	// Create mock server for token verification
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("access_token") != tokenStr {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"sub":   "testuser",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"scope": "users-read users-write",
		})
	}))
	defer mockServer.Close()

	// Replace URL with mock server
	os.Setenv("ER_TOKEN_URL", mockServer.URL)
	server.SetConfig(server.GetConfig())

	// Test POST request
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

	// Test 2: Failed token verification (code 403)
	mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer mockServer.Close()

	// Replace URL with mock server
	os.Setenv("ER_TOKEN_URL", mockServer.URL)
	server.SetConfig(server.GetConfig())

	// Test POST request with invalid token
	req, err = http.NewRequest("POST", "/api/test/users/", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("Expected status 401, got %d, response: %s", rr.Code, rr.Body.String())
	}
}

// TestTokenURLWithScopeCheck checks ER_TOKEN_URL functionality with scope checking enabled
func TestTokenURLWithScopeCheck(t *testing.T) {
	// Create test database
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)

	// Setup server with database
	router := setupServerWithDB(t, dbPath)

	// Save original config
	originalConfig := server.GetConfig()

	// Create new config with empty TokenSecret, set TokenURL and enabled scope checking
	newConfig := config.Config{
		Port:            originalConfig.Port,
		CheckScope:      true,
		TokenSecret:     "",
		TokenUserSearch: originalConfig.TokenUserSearch,
		DefaultTimezone: originalConfig.DefaultTimezone,
		TokenURL:        "http://auth.example.com/token",
	}
	server.SetConfig(newConfig)

	// Restore original config after test
	defer server.SetConfig(originalConfig)

	// Create token with correct scope for POST requests
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

	// Create token with incorrect scope
	claims = jwt.MapClaims{
		"sub":   "testuser",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": "read", // Incorrect scope
	}
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	invalidTokenStr, err := token.SignedString([]byte("mytestsecret"))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Create mock server for token verification
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessToken := r.URL.Query().Get("access_token")
		if accessToken == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Decode token without signature validation
		claims, err := server.DecodeTokenWithoutValidation(accessToken)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{
				"error": err.Error(),
			})
			return
		}

		// Return the same claims as in the token
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(claims)
	}))
	defer mockServer.Close()

	// Replace URL with mock server
	os.Setenv("ER_TOKEN_URL", mockServer.URL)
	server.SetConfig(server.GetConfig())

	// Test POST request with correct scope
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

	// Test POST request with incorrect scope
	body = strings.NewReader(`[
		{
			"name": "test1",
			"update_field": "test1"
		}
	]`)
	req, err = http.NewRequest("POST", "/api/test/users/", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+invalidTokenStr)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("Expected status 403, got %d, response: %s", rr.Code, rr.Body.String())
	}

	// Test 3: Token verification with authorization server error for POST request
	mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer mockServer.Close()

	// Replace URL with mock server
	os.Setenv("ER_TOKEN_URL", mockServer.URL)
	server.SetConfig(server.GetConfig())

	body = strings.NewReader(`[
		{
			"name": "test1",
			"update_field": "test1"
		}
	]`)
	req, err = http.NewRequest("POST", "/api/test/users/", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("Expected status 401, got %d, response: %s", rr.Code, rr.Body.String())
	}

	// Create token with correct scope for RPC
	claims = jwt.MapClaims{
		"sub":   "testuser",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": "test-write", // Correct scope for RPC function test
	}
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	rpcTokenStr, err := token.SignedString([]byte("mytestsecret"))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Test 4: Successful token verification with correct scope for RPC request
	mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessToken := r.URL.Query().Get("access_token")
		if accessToken == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Decode token without signature validation
		claims, err := server.DecodeTokenWithoutValidation(accessToken)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{
				"error": err.Error(),
			})
			return
		}

		// Return the same claims as in the token
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(claims)
	}))
	defer mockServer.Close()

	os.Setenv("ER_TOKEN_URL", mockServer.URL)
	server.SetConfig(server.GetConfig())
	server.DbPlugins["mock"] = &mockDBPlugin{
		callFunction: func(userID, funcName string, data map[string]any, ctx map[string]any) (any, error) {
			return data, nil
		},
	}

	body = strings.NewReader(`{"test": "value"}`)
	req, err = http.NewRequest("POST", "/api/mock/rpc/test/", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+rpcTokenStr)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d, response: %s", rr.Code, rr.Body.String())
	}

	// Check RPC response
	var response map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if response["test"] != "value" {
		t.Errorf("Expected test value to be 'value', got '%v'", response["test"])
	}

	// Test 5: Token verification with incorrect scope for RPC request
	body = strings.NewReader(`{"test": "value"}`)
	req, err = http.NewRequest("POST", "/api/mock/rpc/test/", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+invalidTokenStr)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("Expected status 403, got %d, response: %s", rr.Code, rr.Body.String())
	}

	// Test 6: Token verification with authorization server error for RPC request
	mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer mockServer.Close()

	os.Setenv("ER_TOKEN_URL", mockServer.URL)
	server.SetConfig(server.GetConfig())

	body = strings.NewReader(`{"test": "value"}`)
	req, err = http.NewRequest("POST", "/api/mock/rpc/test/", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+rpcTokenStr)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("Expected status 401, got %d, response: %s", rr.Code, rr.Body.String())
	}
}
