package tests

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/onegreyonewhite/easyrest/internal/server"
	_ "modernc.org/sqlite"
)

// TestDeleteAll - all records are deleted when no where parameters are provided.
func TestDeleteAll(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()
	// Insert 3 records.
	insertUser(t, dbPath, "Alice", "test1")
	insertUser(t, dbPath, "Bob", "test2")
	insertUser(t, dbPath, "Charlie", "test3")
	
	os.Setenv("ER_CACHE_ENABLE_TEST", "1")
	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	// DELETE request without where parameters
	req, err := http.NewRequest("DELETE", "/api/test/users/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("TestDeleteAll: Expected status 204, got %d. Response: %s", rr.Code, rr.Body.String())
	}

	// Verify that the table is empty.
	rows := getAllUsers(t, dbPath)
	if len(rows) != 0 {
		t.Errorf("TestDeleteAll: Expected 0 rows, got %d", len(rows))
	}
}

// TestDeleteWhereLike - only records matching the LIKE condition are deleted.
func TestDeleteWhereLike(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	// Insert records.
	insertUser(t, dbPath, "Alice", "test1")
	insertUser(t, dbPath, "Alex", "test2")
	insertUser(t, dbPath, "Bob", "test3")
	insertUser(t, dbPath, "Alicia", "test4")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	// DELETE request with condition where.like.name=Al%25
	req, err := http.NewRequest("DELETE", "/api/test/users/?where.like.name=Al%25", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("TestDeleteWhereLike: Expected status 204, got %d. Response: %s", rr.Code, rr.Body.String())
	}
	// Verify that only records with names other than "Alice" remain.
	rows := getAllUsers(t, dbPath)
	for _, row := range rows {
		if name, ok := row["name"].(string); ok {
			if name == "Alice" {
				t.Errorf("TestDeleteWhereLike: Record with name 'Alice' was not deleted")
			}
		}
	}
}

// TestDeleteWhereLt - only records matching the lt condition are deleted.
func TestDeleteWhereLt(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	// Insert records.
	insertUser(t, dbPath, "Alice", "test1")
	insertUser(t, dbPath, "Bob", "test2")
	id3 := insertUser(t, dbPath, "Charlie", "test3")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	// DELETE request with condition where.lt.id=<id3>
	req, err := http.NewRequest("DELETE", "/api/test/users/?where.lt.id="+strconv.Itoa(id3), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("TestDeleteWhereLt: Expected status 204, got %d. Response: %s", rr.Code, rr.Body.String())
	}
	// Verify that only records with id less than id3 are deleted.
	rows := getAllUsers(t, dbPath)
	for _, row := range rows {
		if id, ok := row["id"].(int64); ok {
			if int(id) < id3 {
				t.Errorf("Запись с id %d должна была быть удалена", id)
			}
		}
	}
}

// TestDeleteWhereContext - records matching both conditions are deleted.
func TestDeleteWhereContext(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	// Insert records.
	insertUser(t, dbPath, "testuser", "test1")   // Name must match sub in claims
	insertUser(t, dbPath, "test_value", "test2") // Name must match custom in claims

	router := setupServerWithDB(t, dbPath)

	// Create token with additional claims
	claims := jwt.MapClaims{
		"sub":    "testuser",
		"exp":    time.Now().Add(time.Hour).Unix(),
		"scope":  "users-read users-write",
		"custom": "test_value",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte("mytestsecret"))
	if err != nil {
		t.Fatalf("Ошибка подписи токена: %v", err)
	}

	// DELETE request using context values
	req, err := http.NewRequest("DELETE", "/api/test/users/?where.eq.name=request.claims.sub", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("TestDeleteWhereContext: Expected status 204, got %d. Response: %s", rr.Code, rr.Body.String())
	}
	// Verify that only records satisfying both conditions are deleted.
	rows := getAllUsers(t, dbPath)
	for _, row := range rows {
		name := row["name"].(string)
		if name != "test_value" {
			t.Errorf("TestDeleteWhereContext: Record with name '%s' was not deleted", name)
		}
	}
}

// TestDeleteNoMatch - condition that does not match any record.
func TestDeleteNoMatch(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	// Insert 2 records.
	insertUser(t, dbPath, "Alice", "old")
	insertUser(t, dbPath, "Bob", "old")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	// Condition that matches no record, e.g., where.gt.id=9999
	req, err := http.NewRequest("DELETE", "/api/test/users/?where.gt.id=9999", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("TestDeleteNoMatch: Expected status 204, got %d, response: %s", rr.Code, rr.Body.String())
	}
	// Verify that the records are not deleted.
	rows := getAllUsers(t, dbPath)
	if len(rows) != 2 {
		t.Errorf("TestDeleteNoMatch: Expected 2 rows, got %d", len(rows))
	}
}

// TestDeleteInvalidOperator - using an unknown operator should return an error.
func TestDeleteInvalidOperator(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	insertUser(t, dbPath, "Alice", "old")
	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)
	// Use an invalid operator "unknown"
	req, err := http.NewRequest("DELETE", "/api/test/users/?where.unknown.name=Alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	// Expect status 400
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("TestDeleteInvalidOperator: Expected status 400 for invalid operator, got %d, response: %s", rr.Code, rr.Body.String())
	}
}

// TestDeleteMalformedWhere - malformed where keys should return an error.
func TestDeleteMalformedWhere(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()
	insertUser(t, dbPath, "Alice", "old")
	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)
	// Malformed format: where key without operator, e.g., "where.name"
	req, err := http.NewRequest("DELETE", "/api/test/users/?where.name=Alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	// Expect status 400
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("TestDeleteMalformedWhere: Expected status 400, got %d, response: %s", rr.Code, rr.Body.String())
	}
}
