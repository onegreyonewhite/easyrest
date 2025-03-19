package tests

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	_ "modernc.org/sqlite"

	"github.com/onegreyonewhite/easyrest/internal/config"
	"github.com/onegreyonewhite/easyrest/internal/server"
)

// setupTestDB creates a temporary database and a 'users' table with an update_field column.
func setupTestDB(t *testing.T) string {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "testdb-update-*.db")
	if err != nil {
		t.Fatalf("Failed to create temporary DB: %v", err)
	}
	dbPath := tmpFile.Name()
	tmpFile.Close()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open sqlite DB: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		update_field TEXT
	);`)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}
	return dbPath
}

// insertUser inserts a row into the 'users' table and returns the generated id.
func insertUser(t *testing.T, dbPath, name, updateField string) int {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open sqlite DB: %v", err)
	}
	defer db.Close()

	res, err := db.Exec(`INSERT INTO users (name, update_field) VALUES (?, ?)`, name, updateField)
	if err != nil {
		t.Fatalf("Failed to insert data: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("Failed to get last insert id: %v", err)
	}
	return int(id)
}

// setupServerWithDB sets up a test server with the given database.
func setupServerWithDB(t *testing.T, dbPath string) *mux.Router {
	t.Helper()
	os.Setenv("ER_DB_TEST", "sqlite://"+dbPath)
	os.Setenv("ER_CHECK_SCOPE", "0")
	os.Setenv("ER_TOKEN_SECRET", "mytestsecret")
	os.Setenv("ER_TOKEN_USER_SEARCH", "sub")
	cfg := config.Load()
	server.SetConfig(cfg)
	return server.SetupRouter()
}

// generateToken generates a JWT token for testing.
func generateToken(t *testing.T) string {
	t.Helper()
	cfg := server.GetConfig()
	claims := jwt.MapClaims{
		"sub":   "testuser",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": "users-read users-write",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(cfg.TokenSecret))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}
	return tokenStr
}
