package tests

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	_ "github.com/mattn/go-sqlite3"
	"github.com/onegreyonewhite/easyrest/internal/server"
)

// TestContextInQuery verifies that context parameters are passed from the server to the plugin query.
// In this test, the token contains the claim "sub" with value "Alice". The query uses a where clause
// comparing the user name to "erctx_claims_sub", so only a user with name "Alice" should be returned.
func TestContextInQuery(t *testing.T) {
	// Create a temporary DB with table users.
	tmpFile, err := os.CreateTemp("", "context_test_*.db")
	if err != nil {
		t.Fatalf("Failed to create temporary DB: %v", err)
	}
	dbPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(dbPath)
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open sqlite DB: %v", err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT);`)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}
	// Insert a user with name "Alice"
	_, err = db.Exec(`INSERT INTO users (name) VALUES ('Alice');`)
	if err != nil {
		t.Fatalf("Failed to insert data: %v", err)
	}

	// Set environment variables.
	os.Setenv("ER_DB_TEST", "sqlite://"+dbPath)
	os.Setenv("ER_TOKEN_USER_SEARCH", "sub")
	os.Setenv("ER_CHECK_SCOPE", "0")
	secret := "mytestsecret"
	os.Setenv("ER_TOKEN_SECRET", secret)

	// Generate a JWT token with claim "sub": "Alice"
	claims := jwt.MapClaims{
		"sub":   "Alice",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": "users-read users-write",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	router := server.SetupRouter()
	// In the query, we use where.eq.name=erctx_claims_sub. The context CTE will include a column
	// named "claims_sub" (flattened from CLAIMS.sub) if the claims map is passed.
	req, err := http.NewRequest("GET", "/api/test/users/?select=id,name&where.eq.name=erctx.claims_sub", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	// Set a timezone header (for demonstration)
	req.Header.Set("Timezone", "Asia/Vladivostok")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
	var result []map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("Error parsing response: %v", err)
	}
	// Expect one row (user "Alice") to be returned.
	if len(result) != 1 {
		t.Fatalf("Expected 1 row, got %d", len(result))
	}
	if result[0]["name"] != "Alice" {
		t.Errorf("Expected name 'Alice', got %v", result[0]["name"])
	}
}
