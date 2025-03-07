package tests

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	_ "github.com/mattn/go-sqlite3"
	"github.com/onegreyonewhite/easyrest/internal/server"
)

func BenchmarkTableGet(b *testing.B) {
	// Disable logging
	log.SetOutput(io.Discard)
	os.Setenv("ER_NO_PLUGIN_LOG", "1")

	// Create a temporary DB file
	tmpFile, err := os.CreateTemp("", "benchdb-get-*.db")
	if err != nil {
		b.Fatalf("Failed to create temporary DB: %v", err)
	}
	dbPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(dbPath)

	// Open the database and create the 'users' table
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		b.Fatalf("Failed to open sqlite DB: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT);`)
	if err != nil {
		b.Fatalf("Failed to create table: %v", err)
	}
	// Insert 1000 test records with random names
	for i := 0; i < 1000; i++ {
		_, err = db.Exec(`INSERT INTO users (name) VALUES (?)`, fmt.Sprintf("User%d", i))
		if err != nil {
			b.Fatalf("Failed to insert data: %v", err)
		}
	}

	// Set environment variables for the server
	os.Setenv("ER_DB_TEST", "sqlite://"+dbPath)
	os.Setenv("ER_TOKEN_USER_SEARCH", "sub")
	secret := "mytestsecret"
	os.Setenv("ER_TOKEN_SECRET", secret)

	// Generate a JWT token with custom claims
	claims := jwt.MapClaims{
		"sub":   "testuser",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": "read",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(secret))
	if err != nil {
		b.Fatalf("Failed to sign token: %v", err)
	}

	// Initialize the server router
	router := server.SetupRouter()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Request 10 records
		req, err := http.NewRequest("GET", "/api/test/users/?select=id&limit=10", nil)
		if err != nil {
			b.Fatalf("Error creating request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			b.Errorf("Expected status 200, got %d", rr.Code)
		}
	}
}

func BenchmarkTableCreate(b *testing.B) {
	// Disable logging
	log.SetOutput(io.Discard)
	os.Setenv("ER_NO_PLUGIN_LOG", "1")

	// Create a temporary DB file
	tmpFile, err := os.CreateTemp("", "benchdb-create-*.db")
	if err != nil {
		b.Fatalf("Failed to create temporary DB: %v", err)
	}
	dbPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(dbPath)

	// Open the database and create the 'users' table
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		b.Fatalf("Failed to open sqlite DB: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT);`)
	if err != nil {
		b.Fatalf("Failed to create table: %v", err)
	}

	// Set environment variables for the server
	os.Setenv("ER_DB_TEST", "sqlite://"+dbPath)
	os.Setenv("ER_TOKEN_USER_SEARCH", "sub")
	secret := "mytestsecret"
	os.Setenv("ER_TOKEN_SECRET", secret)

	// Generate a JWT token with custom claims
	claims := jwt.MapClaims{
		"sub":   "testuser",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": "users-read users-write",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(secret))
	if err != nil {
		b.Fatalf("Failed to sign token: %v", err)
	}

	// Initialize the server router
	router := server.SetupRouter()

	// JSON body for inserting a record
	body := `[{"name": "Benchmark User"}]`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, err := http.NewRequest("POST", "/api/test/users/", strings.NewReader(body))
		if err != nil {
			b.Fatalf("Error creating request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusCreated {
			b.Errorf("Expected status 201, got %d", rr.Code)
		}
	}
}

func BenchmarkTableUpdate(b *testing.B) {
	// Disable logging
	log.SetOutput(io.Discard)
	os.Setenv("ER_NO_PLUGIN_LOG", "1")

	// Create a temporary DB file
	tmpFile, err := os.CreateTemp("", "benchdb-update-*.db")
	if err != nil {
		b.Fatalf("Failed to create temporary DB: %v", err)
	}
	dbPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(dbPath)

	// Open the database and create the 'users' table with an additional update_field column
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		b.Fatalf("Failed to open sqlite DB: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		update_field INTEGER
	);`)
	if err != nil {
		b.Fatalf("Failed to create table: %v", err)
	}
	// Insert 1000 test records with update_field = 0
	for i := 0; i < 1000; i++ {
		_, err = db.Exec(`INSERT INTO users (name, update_field) VALUES (?, ?)`, fmt.Sprintf("User%d", i), 0)
		if err != nil {
			b.Fatalf("Failed to insert data: %v", err)
		}
	}

	// Set environment variables for the server
	os.Setenv("ER_DB_TEST", "sqlite://"+dbPath)
	os.Setenv("ER_TOKEN_USER_SEARCH", "sub")
	secret := "mytestsecret"
	os.Setenv("ER_TOKEN_SECRET", secret)

	// Generate a JWT token with custom claims
	claims := jwt.MapClaims{
		"sub":   "testuser",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": "users-read users-write",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(secret))
	if err != nil {
		b.Fatalf("Failed to sign token: %v", err)
	}

	// Initialize the server router
	router := server.SetupRouter()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Request body: update update_field to the iteration number
		body := fmt.Sprintf(`{"update_field": %d}`, i)
		// To update all records, pass an empty JSON object for where (i.e. no WHERE clause)
		req, err := http.NewRequest("PATCH", "/api/test/users/", strings.NewReader(body))
		if err != nil {
			b.Fatalf("Error creating request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			b.Errorf("Expected status 200, got %d", rr.Code)
		}
	}
}

// setupTempDBForSelect creates a temporary DB for benchmark select.
func setupTempDBForSelect() (*sql.DB, string, error) {
	tmpFile, err := os.CreateTemp("", "plain-select-*.db")
	if err != nil {
		return nil, "", err
	}
	dbPath := tmpFile.Name()
	tmpFile.Close()

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, "", err
	}

	// Create the 'users' table.
	_, err = db.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT
	);`)
	if err != nil {
		db.Close()
		return nil, "", err
	}

	// Insert 1000 records.
	for i := 0; i < 1000; i++ {
		_, err = db.Exec(`INSERT INTO users (name) VALUES (?)`, fmt.Sprintf("User%d", i))
		if err != nil {
			db.Close()
			return nil, "", err
		}
	}
	return db, dbPath, nil
}

func BenchmarkPlainSQLSelect(b *testing.B) {
	// Disable logging.
	log.SetOutput(io.Discard)

	db, dbPath, err := setupTempDBForSelect()
	if err != nil {
		b.Fatalf("Failed to setup DB: %v", err)
	}
	defer db.Close()
	defer os.Remove(dbPath)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Select the first 10 ids.
		rows, err := db.Query("SELECT id FROM users ORDER BY id ASC LIMIT 10")
		if err != nil {
			b.Fatalf("Query failed: %v", err)
		}
		count := 0
		for rows.Next() {
			var id int
			if err := rows.Scan(&id); err != nil {
				b.Fatalf("Row scan failed: %v", err)
			}
			count++
		}
		rows.Close()
		if count != 10 {
			b.Fatalf("Expected 10 rows, got %d", count)
		}
	}
}

// setupTempDBForCreate creates a temporary DB for benchmark insert.
func setupTempDBForCreate() (*sql.DB, string, error) {
	tmpFile, err := os.CreateTemp("", "plain-create-*.db")
	if err != nil {
		return nil, "", err
	}
	dbPath := tmpFile.Name()
	tmpFile.Close()

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, "", err
	}
	_, err = db.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT
	);`)
	if err != nil {
		db.Close()
		return nil, "", err
	}
	return db, dbPath, nil
}

func BenchmarkPlainSQLCreate(b *testing.B) {
	log.SetOutput(io.Discard)

	db, dbPath, err := setupTempDBForCreate()
	if err != nil {
		b.Fatalf("Failed to setup DB: %v", err)
	}
	defer db.Close()
	defer os.Remove(dbPath)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := db.Exec("INSERT INTO users (name) VALUES (?)", fmt.Sprintf("Plain Insert %d", i))
		if err != nil {
			b.Fatalf("Insert failed: %v", err)
		}
	}
}

// setupTempDBForUpdate creates a temporary DB for benchmark update.
func setupTempDBForUpdate() (*sql.DB, string, error) {
	tmpFile, err := os.CreateTemp("", "plain-update-*.db")
	if err != nil {
		return nil, "", err
	}
	dbPath := tmpFile.Name()
	tmpFile.Close()

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, "", err
	}
	_, err = db.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		update_field INTEGER
	);`)
	if err != nil {
		db.Close()
		return nil, "", err
	}
	// Insert 1000 records with update_field = 0.
	for i := 0; i < 1000; i++ {
		_, err = db.Exec("INSERT INTO users (name, update_field) VALUES (?, ?)", fmt.Sprintf("User%d", i), 0)
		if err != nil {
			db.Close()
			return nil, "", err
		}
	}
	return db, dbPath, nil
}

func BenchmarkPlainSQLUpdate(b *testing.B) {
	log.SetOutput(io.Discard)

	db, dbPath, err := setupTempDBForUpdate()
	if err != nil {
		b.Fatalf("Failed to setup DB: %v", err)
	}
	defer db.Close()
	defer os.Remove(dbPath)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Update update_field for all records.
		res, err := db.Exec("UPDATE users SET update_field = ?", i)
		if err != nil {
			b.Fatalf("Update failed: %v", err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			b.Fatalf("RowsAffected failed: %v", err)
		}
		if affected != 1000 {
			b.Fatalf("Expected 1000 rows updated, got %d", affected)
		}
	}
}

func BenchmarkAuthenticate(b *testing.B) {
	// Disable logging
	log.SetOutput(io.Discard)
	os.Setenv("ER_NO_PLUGIN_LOG", "1")

	// Set environment variables for the server
	os.Setenv("ER_TOKEN_USER_SEARCH", "sub")
	secret := "mytestsecret"
	os.Setenv("ER_TOKEN_SECRET", secret)

	// Generate a JWT token with custom claims
	claims := jwt.MapClaims{
		"sub":   "testuser",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": "read",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(secret))
	if err != nil {
		b.Fatalf("Failed to sign token: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Request 10 records
		req, err := http.NewRequest("GET", "/api/test/users/?select=id&limit=10", nil)
		if err != nil {
			b.Fatalf("Error creating request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		_, _, err = server.Authenticate(req)
		if err != nil {
			b.Fatalf("Authentication failed: %v", err)
		}
	}
}
