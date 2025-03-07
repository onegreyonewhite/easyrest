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

	_ "github.com/mattn/go-sqlite3"
)

// getAllUsers returns all rows from the 'users' table.
func getAllUsers(t *testing.T, dbPath string) []map[string]interface{} {
	t.Helper()
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Error opening DB: %v", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, name, update_field FROM users")
	if err != nil {
		t.Fatalf("Error executing query: %v", err)
	}
	defer rows.Close()

	var result []map[string]interface{}
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("Error getting columns: %v", err)
	}
	for rows.Next() {
		columns := make([]interface{}, len(cols))
		columnPointers := make([]interface{}, len(cols))
		for i := range columns {
			columnPointers[i] = &columns[i]
		}
		if err := rows.Scan(columnPointers...); err != nil {
			t.Fatalf("Error scanning row: %v", err)
		}
		row := make(map[string]interface{})
		for i, colName := range cols {
			val := columnPointers[i].(*interface{})
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

// TestUpdateWhereLike updates rows where the name matches the LIKE condition.
func TestUpdateWhereLike(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	// Insert 4 records.
	insertUser(t, dbPath, "Alice", "old")
	insertUser(t, dbPath, "Alex", "old")
	_ = insertUser(t, dbPath, "Bob", "old")
	insertUser(t, dbPath, "Alicia", "old")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)
	// Request: update update_field to "like-update" for rows where name LIKE "Al%"
	// URL encoding: "Al%" -> "Al%25"
	url := "/api/test/users/?where.like.name=Al%25"
	body := strings.NewReader(`{"update_field": "like-update"}`)
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
	// Expect 3 rows to be updated: Alice, Alex, Alicia
	if resp["updated"] != 3 {
		t.Errorf("Expected 3 rows updated, got %d", resp["updated"])
	}
	// Verify that only the intended rows are updated.
	rows := getAllUsers(t, dbPath)
	for _, row := range rows {
		name, _ := row["name"].(string)
		if strings.HasPrefix(name, "Al") {
			if row["update_field"] != "like-update" {
				t.Errorf("For %s, expected update_field = 'like-update', got %v", name, row["update_field"])
			}
		} else {
			if row["update_field"] == "like-update" {
				t.Errorf("For %s, update_field should not have changed", name)
			}
		}
	}
}

// TestUpdateWhereLt updates rows where id is less than a specified value.
func TestUpdateWhereLt(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	// Insert 3 records and store their ids.
	insertUser(t, dbPath, "Alice", "old")
	insertUser(t, dbPath, "Bob", "old")
	id3 := insertUser(t, dbPath, "Charlie", "old")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)
	// Request: update update_field to "lt-update" for rows with id < id3 (i.e., Alice and Bob).
	url := "/api/test/users/?where.lt.id=" + strconv.Itoa(id3)
	body := strings.NewReader(`{"update_field": "lt-update"}`)
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
	if resp["updated"] != 2 {
		t.Errorf("Expected 2 rows updated, got %d", resp["updated"])
	}
	// Verify that only rows with id < id3 are updated.
	rows := getAllUsers(t, dbPath)
	for _, row := range rows {
		id := int(row["id"].(int64))
		if id < id3 {
			if row["update_field"] != "lt-update" {
				t.Errorf("For id %d, expected update_field = 'lt-update', got %v", id, row["update_field"])
			}
		} else {
			if row["update_field"] == "lt-update" {
				t.Errorf("For id %d, update_field should not have changed", id)
			}
		}
	}
}

// TestUpdateNoMatch updates rows with a condition that matches no records.
func TestUpdateNoMatch(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
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

// TestUpdateInvalidOperator verifies that using an unknown operator returns an error.
func TestUpdateInvalidOperator(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	insertUser(t, dbPath, "Alice", "old")
	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)
	// Request with an invalid operator "unknown"
	req, err := http.NewRequest("PATCH", "/api/test/users/?where.unknown.name=Alice", strings.NewReader(`{"update_field": "new"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	// Expect status 400
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Expected status 400 for invalid operator, got %d, response: %s", rr.Code, rr.Body.String())
	}
}

// TestUpdateMalformedJSON verifies that malformed JSON in the request body returns an error.
func TestUpdateMalformedJSON(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	insertUser(t, dbPath, "Alice", "old")
	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)
	req, err := http.NewRequest("PATCH", "/api/test/users/?select=id,name", strings.NewReader(`{"update_field": "new`)) // malformed JSON
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Expected status 400 for malformed JSON, got %d, response: %s", rr.Code, rr.Body.String())
	}
}
