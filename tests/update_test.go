package tests

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/onegreyonewhite/easyrest/internal/server"
	_ "modernc.org/sqlite"
)

// getAllUsers returns all rows from the 'users' table.
func getAllUsers(t *testing.T, dbPath string) []map[string]any {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Error opening DB: %v", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, name, update_field FROM users")
	if err != nil {
		t.Fatalf("Error executing query: %v", err)
	}
	defer rows.Close()

	var result []map[string]any
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("Error getting columns: %v", err)
	}
	for rows.Next() {
		columns := make([]any, len(cols))
		columnPointers := make([]any, len(cols))
		for i := range columns {
			columnPointers[i] = &columns[i]
		}
		if err := rows.Scan(columnPointers...); err != nil {
			t.Fatalf("Error scanning row: %v", err)
		}
		row := make(map[string]any)
		for i, colName := range cols {
			val := columnPointers[i].(*any)
			row[colName] = *val
		}
		result = append(result, row)
	}
	return result
}

// TestUpdateAll updates all rows without conditions.
func TestUpdateAll(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopDBPlugins()

	// Insert 3 records.
	insertUser(t, dbPath, "Alice", "old")
	insertUser(t, dbPath, "Bob", "old")
	insertUser(t, dbPath, "Charlie", "old")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	// PATCH request without conditions, update update_field to "updated-all"
	body := strings.NewReader(`{"update_field": "updated-all"}`)
	req, err := http.NewRequest("PATCH", "/api/test/users/?select=id,name,update_field", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d, response: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]int
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Error parsing response: %v", err)
	}
	if resp["updated"] != 3 {
		t.Errorf("Expected 3 rows updated, got %d", resp["updated"])
	}

	// Verify that all rows are updated.
	rows := getAllUsers(t, dbPath)
	for _, row := range rows {
		if row["update_field"] != "updated-all" {
			t.Errorf("Expected update_field = 'updated-all', got %v", row["update_field"])
		}
	}
}

// TestUpdateWhereLike updates records where name matches LIKE condition.
func TestUpdateWhereLike(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopDBPlugins()

	// Insert test data
	insertUser(t, dbPath, "Alice", "test1")
	insertUser(t, dbPath, "Alex", "test2")
	insertUser(t, dbPath, "Bob", "test3")
	insertUser(t, dbPath, "Alicia", "test4")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	// PATCH request with LIKE condition
	body := strings.NewReader(`{"update_field": "like-update"}`)
	req, err := http.NewRequest("PATCH", "/api/test/users/?where.like.name=Al%25", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Response: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]int
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Error parsing response: %v", err)
	}
	if resp["updated"] != 3 {
		t.Errorf("Expected 3 rows updated, got %d", resp["updated"])
	}

	// Check that only records starting with "Al" were updated
	rows := getAllUsers(t, dbPath)
	for _, row := range rows {
		name := row["name"].(string)
		if strings.HasPrefix(name, "Al") {
			if row["update_field"] != "like-update" {
				t.Errorf("For %s expected update_field = 'like-update', got %v", name, row["update_field"])
			}
		} else {
			if row["update_field"] == "like-update" {
				t.Errorf("For %s update_field should not have changed", name)
			}
		}
	}
}

// TestUpdateWhereLt updates records where id is less than specified value.
func TestUpdateWhereLt(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopDBPlugins()

	// Insert test data
	insertUser(t, dbPath, "Alice", "test1")
	insertUser(t, dbPath, "Bob", "test2")
	id3 := insertUser(t, dbPath, "Charlie", "test3")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	// PATCH request with lt condition
	body := strings.NewReader(`{"update_field": "lt-update"}`)
	req, err := http.NewRequest("PATCH", "/api/test/users/?where.lt.id="+strconv.Itoa(id3), body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Response: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]int
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Error parsing response: %v", err)
	}
	if resp["updated"] != 2 {
		t.Errorf("Expected 2 rows updated, got %d", resp["updated"])
	}

	// Check that only records with id < id3 were updated
	rows := getAllUsers(t, dbPath)
	for _, row := range rows {
		id := int(row["id"].(int64))
		if id < id3 {
			if row["update_field"] != "lt-update" {
				t.Errorf("For id %d expected update_field = 'lt-update', got %v", id, row["update_field"])
			}
		} else {
			if row["update_field"] == "lt-update" {
				t.Errorf("For id %d update_field should not have changed", id)
			}
		}
	}
}

// TestUpdateNoMatch updates rows with a condition that matches no records.
func TestUpdateNoMatch(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopDBPlugins()

	// Insert 2 records.
	insertUser(t, dbPath, "Alice", "old")
	insertUser(t, dbPath, "Bob", "old")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)
	// Request: condition that matches no records, e.g., id > 9999.
	url := "/api/test/users/?where.gt.id=9999"
	body := strings.NewReader(`{"update_field": "nomatch"}`)
	req, err := http.NewRequest("PATCH", url, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d, response: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]int
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Error parsing response: %v", err)
	}
	if resp["updated"] != 0 {
		t.Errorf("Expected 0 rows updated, got %d", resp["updated"])
	}
}

// TestUpdateWhereContext updates records using context values.
func TestUpdateWhereContext(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopDBPlugins()

	// Insert test data
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
		t.Fatalf("Error signing token: %v", err)
	}

	// PATCH request using context values
	body := strings.NewReader(`{"update_field": "context-update"}`)
	req, err := http.NewRequest("PATCH", "/api/test/users/?where.eq.name=request.claims.sub", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Response: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]int
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Error parsing response: %v", err)
	}
	if resp["updated"] != 1 {
		t.Errorf("Expected 1 row updated, got %d", resp["updated"])
	}

	// Check that only record with name from claims.sub was updated
	rows := getAllUsers(t, dbPath)
	for _, row := range rows {
		name := row["name"].(string)
		if name == "testuser" {
			if row["update_field"] != "context-update" {
				t.Errorf("For %s expected update_field = 'context-update', got %v", name, row["update_field"])
			}
		} else {
			if row["update_field"] == "context-update" {
				t.Errorf("For %s update_field should not have changed", name)
			}
		}
	}
}

// TestUpdateInvalidOperator checks that using unknown operator returns error.
func TestUpdateInvalidOperator(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopDBPlugins()

	insertUser(t, dbPath, "Alice", "test1")
	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	// Request with invalid operator "unknown"
	body := strings.NewReader(`{"update_field": "new"}`)
	req, err := http.NewRequest("PATCH", "/api/test/users/?where.unknown.name=Alice", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Expect 400 status for invalid operator
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Expected status 400 for invalid operator, got %d. Response: %s", rr.Code, rr.Body.String())
	}
}

// TestUpdateMalformedJSON checks that malformed JSON in request body returns error.
func TestUpdateMalformedJSON(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopDBPlugins()

	insertUser(t, dbPath, "Alice", "test1")
	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	// Request with malformed JSON
	body := strings.NewReader(`{"update_field": "new`) // malformed JSON
	req, err := http.NewRequest("PATCH", "/api/test/users/?select=id,name", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Expected status 400 for malformed JSON, got %d. Response: %s", rr.Code, rr.Body.String())
	}
}
