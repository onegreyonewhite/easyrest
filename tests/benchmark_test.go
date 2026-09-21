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

	"github.com/golang-jwt/jwt/v5"
	"github.com/onegreyonewhite/easyrest/internal/config"
	"github.com/onegreyonewhite/easyrest/internal/server"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	jwtplugin "github.com/onegreyonewhite/easyrest/plugins/auth/jwt"
	sqlitePlugin "github.com/onegreyonewhite/easyrest/plugins/data/sqlite"
	_ "modernc.org/sqlite"
)

func sqliteBenchURI(path string) string {
	return "sqlite://" + path + "?cache_size=-65536&mmap_size=268435456"
}

func enableBenchJSON() {
	cfg := server.GetConfig()
	cfg.Server.DisableHTMLEscape = true
	server.SetConfig(cfg)
}

func setupTableGet1kBench(b *testing.B) (http.Handler, string) {
	b.Helper()
	log.SetOutput(io.Discard)
	os.Setenv("ER_NO_PLUGIN_LOG", "1")

	tmpFile, err := os.CreateTemp("", "benchdb-get-1k-*.db")
	if err != nil {
		b.Fatalf("Failed to create temporary DB: %v", err)
	}
	dbPath := tmpFile.Name()
	tmpFile.Close()
	b.Cleanup(func() {
		os.Remove(dbPath)
		server.StopPlugins()
	})

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		b.Fatalf("Failed to open sqlite DB: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT);`)
	if err != nil {
		b.Fatalf("Failed to create table: %v", err)
	}
	for i := 0; i < 1000; i++ {
		_, err = db.Exec(`INSERT INTO users (name) VALUES (?)`, fmt.Sprintf("User%d", i))
		if err != nil {
			b.Fatalf("Failed to insert data: %v", err)
		}
	}

	os.Setenv("ER_DB_TEST", sqliteBenchURI(dbPath))
	os.Setenv("ER_TOKEN_USER_SEARCH", "sub")
	secret := "mytestsecret"
	os.Setenv("ER_TOKEN_SECRET", secret)

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

	server.PreservedDbPlugins["sqlite"] = func() easyrest.DBPlugin {
		return sqlitePlugin.NewSqlitePlugin()
	}
	server.PreservedAuthPlugins["jwt"] = func() easyrest.AuthPlugin {
		return &jwtplugin.JWTAuthPlugin{}
	}
	server.ReloadConfig()
	cfg := server.GetConfig()
	plugin := cfg.PluginMap["test"]
	plugin.DefaultLimit = 100
	cfg.PluginMap["test"] = plugin
	server.SetConfig(cfg)
	enableBenchJSON()
	return server.SetupRouter(), tokenStr
}

type ttfbRecorder struct {
	*httptest.ResponseRecorder
	first time.Time
}

func (r *ttfbRecorder) mark() {
	if r.first.IsZero() {
		r.first = time.Now()
	}
}

// jsonTTFBRecorder timestamps the first Write so JSON TTFB includes encoding.
type jsonTTFBRecorder struct{ *ttfbRecorder }

func newJSONTTFBRecorder() *jsonTTFBRecorder {
	return &jsonTTFBRecorder{&ttfbRecorder{ResponseRecorder: httptest.NewRecorder()}}
}

func (r *jsonTTFBRecorder) Write(p []byte) (int, error) {
	r.mark()
	return r.ResponseRecorder.Write(p)
}

// ndjsonTTFBRecorder timestamps the first Flush (headers after the first TableGet)
// and leaves Write on the embedded recorder so NDJSON total time stays comparable.
type ndjsonTTFBRecorder struct{ *ttfbRecorder }

func newNDJSONTTFBRecorder() *ndjsonTTFBRecorder {
	return &ndjsonTTFBRecorder{&ttfbRecorder{ResponseRecorder: httptest.NewRecorder()}}
}

func (r *ndjsonTTFBRecorder) Flush() {
	r.mark()
	r.ResponseRecorder.Flush()
}

func (r *ndjsonTTFBRecorder) FlushError() error {
	r.Flush()
	return nil
}

func reportTTFB(b *testing.B, sum time.Duration, n int) {
	b.Helper()
	if n == 0 {
		return
	}
	b.ReportMetric(float64(sum.Nanoseconds())/float64(n), "ttfb-ns/op")
}

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
	defer server.StopPlugins()

	// Open the database and create the 'users' table
	db, err := sql.Open("sqlite", dbPath)
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
	os.Setenv("ER_DB_TEST", sqliteBenchURI(dbPath))
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
	server.PreservedDbPlugins["sqlite"] = func() easyrest.DBPlugin {
		return sqlitePlugin.NewSqlitePlugin()
	}
	server.PreservedAuthPlugins["jwt"] = func() easyrest.AuthPlugin {
		return &jwtplugin.JWTAuthPlugin{}
	}
	server.ReloadConfig()
	enableBenchJSON()
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
			break
		}
	}
}

func BenchmarkTableGetJSON1k(b *testing.B) {
	router, tokenStr := setupTableGet1kBench(b)

	var ttfbSum time.Duration
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, err := http.NewRequest(http.MethodGet, "/api/test/users/?select=id,name&limit=1000", nil)
		if err != nil {
			b.Fatalf("Error creating request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		req.Header.Set("Accept", "application/json")
		rr := newJSONTTFBRecorder()
		start := time.Now()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			b.Errorf("Expected status 200, got %d", rr.Code)
			break
		}
		if !strings.Contains(rr.Header().Get("Content-Type"), "application/json") {
			b.Errorf("Expected JSON content type, got %s", rr.Header().Get("Content-Type"))
			break
		}
		if rr.first.IsZero() {
			b.Errorf("JSON TTFB was not observed")
			break
		}
		ttfbSum += rr.first.Sub(start)
	}
	reportTTFB(b, ttfbSum, b.N)
}

func BenchmarkTableGetNDJSON1k(b *testing.B) {
	router, tokenStr := setupTableGet1kBench(b)

	var ttfbSum time.Duration
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, err := http.NewRequest(http.MethodGet, "/api/test/users/?select=id,name", nil)
		if err != nil {
			b.Fatalf("Error creating request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		req.Header.Set("Accept", "application/x-ndjson")
		rr := newNDJSONTTFBRecorder()
		start := time.Now()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			b.Errorf("Expected status 200, got %d", rr.Code)
			break
		}
		if !strings.Contains(rr.Header().Get("Content-Type"), "application/x-ndjson") {
			b.Errorf("Expected NDJSON content type, got %s", rr.Header().Get("Content-Type"))
			break
		}
		if cr := rr.Header().Get("Content-Range"); cr != "" {
			b.Errorf("auto-stream must omit Content-Range, got %q", cr)
			break
		}
		if rr.first.IsZero() {
			b.Errorf("NDJSON TTFB was not observed")
			break
		}
		ttfbSum += rr.first.Sub(start)
	}
	reportTTFB(b, ttfbSum, b.N)
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
	defer server.StopPlugins()

	// Open the database and create the 'users' table
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		b.Fatalf("Failed to open sqlite DB: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT);`)
	if err != nil {
		b.Fatalf("Failed to create table: %v", err)
	}

	// Set environment variables for the server
	os.Setenv("ER_DB_TEST", sqliteBenchURI(dbPath))
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
	server.PreservedDbPlugins["sqlite"] = func() easyrest.DBPlugin {
		return sqlitePlugin.NewSqlitePlugin()
	}
	server.PreservedAuthPlugins["jwt"] = func() easyrest.AuthPlugin {
		return &jwtplugin.JWTAuthPlugin{}
	}
	server.ReloadConfig()
	enableBenchJSON()
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
			break
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
	defer server.StopPlugins()
	// Open the database and create the 'users' table with an additional update_field column
	db, err := sql.Open("sqlite", dbPath)
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
	for i := range 1000 {
		_, err = db.Exec(`INSERT INTO users (name, update_field) VALUES (?, ?)`, fmt.Sprintf("User%d", i), 0)
		if err != nil {
			b.Fatalf("Failed to insert data: %v", err)
		}
	}

	// Set environment variables for the server
	os.Setenv("ER_DB_TEST", sqliteBenchURI(dbPath))
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
	server.PreservedDbPlugins["sqlite"] = func() easyrest.DBPlugin {
		return sqlitePlugin.NewSqlitePlugin()
	}
	server.PreservedAuthPlugins["jwt"] = func() easyrest.AuthPlugin {
		return &jwtplugin.JWTAuthPlugin{}
	}
	server.ReloadConfig()
	enableBenchJSON()
	router := server.SetupRouter()

	for i := 0; b.Loop(); i++ {
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
			break
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

	db, err := sql.Open("sqlite", dbPath)
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

	db, err := sql.Open("sqlite", dbPath)
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

	db, err := sql.Open("sqlite", dbPath)
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

	cfg := server.GetConfig()
	cfg.AuthPlugins = map[string]config.AuthConfig{
		"jwt": {
			Settings: map[string]interface{}{
				"jwt_secret": secret,
			},
		},
	}
	server.PreservedAuthPlugins["jwt"] = func() easyrest.AuthPlugin {
		return &jwtplugin.JWTAuthPlugin{}
	}
	server.ReloadConfig()
	server.SetConfig(cfg)
	server.LoadPlugins()

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

func BenchmarkQueryCall(b *testing.B) {
	log.SetOutput(io.Discard)
	os.Setenv("ER_NO_PLUGIN_LOG", "1")

	tmpFile, err := os.CreateTemp("", "benchdb-query-*.db")
	if err != nil {
		b.Fatalf("Failed to create temporary DB: %v", err)
	}
	dbPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		b.Fatalf("Failed to open sqlite DB: %v", err)
	}

	_, err = db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT);`)
	if err != nil {
		b.Fatalf("Failed to create table: %v", err)
	}
	for i := 0; i < 1000; i++ {
		_, err = db.Exec(`INSERT INTO users (name) VALUES (?)`, fmt.Sprintf("User%d", i))
		if err != nil {
			b.Fatalf("Failed to insert data: %v", err)
		}
	}
	db.Close()

	os.Setenv("ER_DB_TEST", sqliteBenchURI(dbPath))
	os.Setenv("ER_USE_QUERY_TEST", "1")
	os.Setenv("ER_TOKEN_USER_SEARCH", "sub")
	secret := "mytestsecret"
	os.Setenv("ER_TOKEN_SECRET", secret)

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

	server.PreservedQueryPlugins["sqlite"] = func() easyrest.DBQueryPlugin {
		return sqlitePlugin.NewSqliteQueryPlugin()
	}
	server.PreservedAuthPlugins["jwt"] = func() easyrest.AuthPlugin {
		return &jwtplugin.JWTAuthPlugin{}
	}
	server.ReloadConfig()
	enableBenchJSON()
	router := server.SetupRouter()

	queryBody := "SELECT id FROM users ORDER BY id ASC LIMIT 10"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, err := http.NewRequest("QUERY", "/api/test/", strings.NewReader(queryBody))
		if err != nil {
			b.Fatalf("Error creating request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			b.Errorf("Expected status 200, got %d", rr.Code)
			break
		}
	}
}
