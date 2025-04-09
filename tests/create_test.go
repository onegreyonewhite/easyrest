package tests

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/onegreyonewhite/easyrest/internal/server"
)

// TestCreateWithContextValues creates records using context values
func TestCreateWithContextValues(t *testing.T) {
	// Create test database
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()
	// Setup server with database
	router := setupServerWithDB(t, dbPath)

	// Create token with additional claims
	claims := jwt.MapClaims{
		"sub":    "testuser",
		"custom": "test_value",
		"exp":    time.Now().Add(time.Hour).Unix(),
		"scope":  "users-read users-write",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte("mytestsecret"))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// POST request with two objects using different context value variants
	body := strings.NewReader(`[
		{
			"name": "erctx.claims_sub",
			"update_field": "test1"
		},
		{
			"name": "request.claims.custom",
			"update_field": "test2"
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

	// Check that records were created with correct values
	rows := getAllUsers(t, dbPath)
	if len(rows) != 2 {
		t.Fatalf("Expected 2 rows, got %d", len(rows))
	}

	// Check first record (erctx.claims_sub)
	found := false
	for _, row := range rows {
		if row["name"] == "testuser" {
			found = true
			if row["update_field"] != "test1" {
				t.Errorf("Expected update_field to be 'test1', got '%v'", row["update_field"])
			}
			break
		}
	}
	if !found {
		t.Error("Record with name 'testuser' not found")
	}

	// Check second record (request.claims.custom)
	found = false
	for _, row := range rows {
		if row["name"] == "test_value" {
			found = true
			if row["update_field"] != "test2" {
				t.Errorf("Expected update_field to be 'test2', got '%v'", row["update_field"])
			}
			break
		}
	}
	if !found {
		t.Error("Record with name 'test_value' not found")
	}
}

// TestCreateWithInvalidJSON checks handling of invalid JSON
func TestCreateWithInvalidJSON(t *testing.T) {
	// Create test database
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	// Setup server with database
	router := setupServerWithDB(t, dbPath)

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

	// POST request with invalid JSON
	body := strings.NewReader(`[
		{
			"name": "test1",
			"update_field": "test1"
		},
		{
			"name": "test2",
			"update_field": "test2"
		}
	`)
	req, err := http.NewRequest("POST", "/api/test/users/", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Expected status 400, got %d, response: %s", rr.Code, rr.Body.String())
	}
}

// TestCreateWithoutAuth checks record creation without authorization
func TestCreateWithoutAuth(t *testing.T) {
	// Create test database
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	// Setup server with database
	router := setupServerWithDB(t, dbPath)

	// POST request without token
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
}
