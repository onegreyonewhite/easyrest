package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/onegreyonewhite/easyrest/internal/server"
)

type mockDBPlugin struct {
	callFunction func(userID, funcName string, data map[string]any, ctx map[string]any) (any, error)
}

func (m *mockDBPlugin) InitConnection(uri string) error { return nil }
func (m *mockDBPlugin) TableGet(userID, table string, selectFields []string, where map[string]any,
	ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, error) {
	return nil, nil
}
func (m *mockDBPlugin) TableCreate(userID, table string, data []map[string]any, ctx map[string]any) ([]map[string]any, error) {
	return nil, nil
}
func (m *mockDBPlugin) TableUpdate(userID, table string, data map[string]any, where map[string]any, ctx map[string]any) (int, error) {
	return 0, nil
}
func (m *mockDBPlugin) TableDelete(userID, table string, where map[string]any, ctx map[string]any) (int, error) {
	return 0, nil
}
func (m *mockDBPlugin) CallFunction(userID, funcName string, data map[string]any, ctx map[string]any) (any, error) {
	return m.callFunction(userID, funcName, data, ctx)
}
func (m *mockDBPlugin) GetSchema(ctx map[string]any) (any, error) {
	return nil, nil
}

func TestRPCWithoutClaims(t *testing.T) {
	// Create mock plugin that simply returns input data
	mockPlugin := &mockDBPlugin{
		callFunction: func(userID, funcName string, data map[string]any, ctx map[string]any) (any, error) {
			return data, nil
		},
	}
	server.DbPlugins["mock"] = mockPlugin

	// Setup server
	os.Setenv("ER_TOKEN_SECRET", "mytestsecret")
	router := server.SetupRouter()

	// Disable scope checking for test
	config := server.GetConfig()
	config.CheckScope = false
	server.SetConfig(config)

	// Test 1: Without token
	body := strings.NewReader(`{"test": "value"}`)
	req, err := http.NewRequest("POST", "/api/mock/rpc/test/", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("Expected status 401, got %d, response: %s", rr.Code, rr.Body.String())
	}

	// Test 2: With token and erctx.claims_sub
	claims := jwt.MapClaims{
		"sub":   "testuser",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": "test-write",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte("mytestsecret"))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	body = strings.NewReader(`{"test": "erctx.claims_sub"}`)
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

	var response map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if response["test"] != "testuser" {
		t.Errorf("Expected test value to be 'testuser', got '%v'", response["test"])
	}

	// Test 3: With token and request.claims.sub
	body = strings.NewReader(`{"test": "request.claims.sub"}`)
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

	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if response["test"] != "testuser" {
		t.Errorf("Expected test value to be 'testuser', got '%v'", response["test"])
	}
}
