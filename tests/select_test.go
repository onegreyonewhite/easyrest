package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestSelectBasic(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	// Insert a single user.
	insertUser(t, dbPath, "Alice", "")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)
	req, err := http.NewRequest("GET", "/api/test/users/?select=id,name", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Response: %s", rr.Code, rr.Body.String())
	}
	var result []map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("Error parsing response: %v. Response: %s", err, rr.Body.String())
	}
	if len(result) != 1 {
		t.Fatalf("Expected 1 row, got %d", len(result))
	}
	if result[0]["name"] != "Alice" {
		t.Errorf("Expected name 'Alice', got %v", result[0]["name"])
	}
}

func TestSelectWhereLike(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	// Insert several users.
	insertUser(t, dbPath, "Alice", "")
	insertUser(t, dbPath, "Alex", "")
	insertUser(t, dbPath, "Bob", "")
	insertUser(t, dbPath, "Alicia", "")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)
	// Note: To correctly pass the "%" character in the URL, it must be URL-encoded.
	req, err := http.NewRequest("GET", "/api/test/users/?select=id,name&where.like.name=Al%25", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Response: %s", rr.Code, rr.Body.String())
	}
	var result []map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("Error parsing response: %v. Response: %s", err, rr.Body.String())
	}
	// Expect only users whose names start with "Al" – "Alice", "Alex", "Alicia"
	if len(result) != 3 {
		t.Fatalf("Expected 3 rows, got %d", len(result))
	}
	for _, row := range result {
		name, ok := row["name"].(string)
		if !ok || !strings.HasPrefix(name, "Al") {
			t.Errorf("Expected name starting with 'Al', got %v", row["name"])
		}
	}
}

func TestSelectWhereLt(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	// Insert two users.
	id1 := insertUser(t, dbPath, "Alice", "")
	id2 := insertUser(t, dbPath, "Bob", "")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)
	// Request: select where id < id2 (expect only the user with id1).
	req, err := http.NewRequest("GET", "/api/test/users/?select=id,name&where.lt.id="+strconv.Itoa(id2), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Response: %s", rr.Code, rr.Body.String())
	}
	var result []map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("Error parsing response: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("Expected 1 row, got %d", len(result))
	}
	if int(result[0]["id"].(float64)) != id1 {
		t.Errorf("Expected id %d, got %v", id1, result[0]["id"])
	}
}

func TestSelectMultipleWhere(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	// Insert several users.
	id1 := insertUser(t, dbPath, "Alice", "")
	id2 := insertUser(t, dbPath, "Alex", "")
	_ = insertUser(t, dbPath, "Bob", "")
	_ = insertUser(t, dbPath, "Alicia", "")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)
	// Request with two conditions: name LIKE "Al%" and id < id2
	req, err := http.NewRequest("GET", "/api/test/users/?select=id,name&where.like.name=Al%25&where.lt.id="+strconv.Itoa(id2), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Response: %s", rr.Code, rr.Body.String())
	}
	var result []map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("Error parsing response: %v", err)
	}
	// Expect that the condition id < id2 filters out "Alex" (if id1 < id2), leaving only "Alice"
	if len(result) != 1 {
		t.Fatalf("Expected 1 row, got %d", len(result))
	}
	if int(result[0]["id"].(float64)) != id1 {
		t.Errorf("Expected id %d, got %v", id1, result[0]["id"])
	}
}

func TestSelectInvalidOperator(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	insertUser(t, dbPath, "Alice", "")
	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)
	// Use an invalid operator "unknown"
	req, err := http.NewRequest("GET", "/api/test/users/?select=id,name&where.unknown.name=Alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	// Expect status 400 for invalid where key format.
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Expected status 400 for invalid operator, got %d. Response: %s", rr.Code, rr.Body.String())
	}
}
