package tests

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// TestDeleteAll - all records are deleted when no where parameters are provided.
func TestDeleteAll(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	// Insert 3 records.
	insertUser(t, dbPath, "Alice", "old")
	insertUser(t, dbPath, "Bob", "old")
	insertUser(t, dbPath, "Charlie", "old")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	// DELETE request without where parameters
	req, err := http.NewRequest("DELETE", "/api/test/users/?select=id,name,update_field", nil)
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

// TestDeleteWhereEq - only records matching the eq condition are deleted.
func TestDeleteWhereEq(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	// Insert records.
	insertUser(t, dbPath, "Alice", "old")
	insertUser(t, dbPath, "Bob", "old")
	insertUser(t, dbPath, "Alice", "old")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	// DELETE request with condition where.eq.name=Alice
	req, err := http.NewRequest("DELETE", "/api/test/users/?where.eq.name=Alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("TestDeleteWhereEq: Expected status 204, got %d. Response: %s", rr.Code, rr.Body.String())
	}
	// Verify that only records with names other than "Alice" remain.
	rows := getAllUsers(t, dbPath)
	for _, row := range rows {
		if name, ok := row["name"].(string); ok {
			if name == "Alice" {
				t.Errorf("TestDeleteWhereEq: Record with name 'Alice' was not deleted")
			}
		}
	}
}

// TestDeleteWhereMultiple - records matching both conditions are deleted.
func TestDeleteWhereMultiple(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	// Insert records.
	insertUser(t, dbPath, "Alice", "old")
	id2 := insertUser(t, dbPath, "Alice", "old")
	_ = insertUser(t, dbPath, "Alice", "old")
	_ = insertUser(t, dbPath, "Bob", "old")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	// Condition: where.eq.name=Alice and where.lt.id=<id2+1> (i.e., delete records with id less than id2+1)
	threshold := id2 + 1
	url := "/api/test/users/?where.eq.name=Alice&where.lt.id=" + strconv.Itoa(threshold)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("TestDeleteWhereMultiple: Expected status 204, got %d. Response: %s", rr.Code, rr.Body.String())
	}
	// Verify that only records satisfying both conditions are deleted.
	rows := getAllUsers(t, dbPath)
	for _, row := range rows {
		name := row["name"].(string)
		id := int(row["id"].(int64))
		if name == "Alice" && id < threshold {
			t.Errorf("TestDeleteWhereMultiple: Record with id %d and name 'Alice' was not deleted", id)
		}
	}
}

// TestDeleteNoMatch - condition that does not match any record.
func TestDeleteNoMatch(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
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
