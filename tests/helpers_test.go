package tests

import (
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	_ "modernc.org/sqlite"

	"github.com/onegreyonewhite/easyrest/internal/config"
	"github.com/onegreyonewhite/easyrest/internal/server"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
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
func setupServerWithDB(t *testing.T, dbPath string) chi.Router {
	t.Helper()
	os.Setenv("ER_DB_TEST", "sqlite://"+dbPath)
	os.Setenv("ER_CACHE_ENABLE_TEST", "1")
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
		"role":  "admin",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtPlugin := cfg.AuthPlugins["jwt"]
	secret := jwtPlugin.Settings["jwt_secret"]
	tokenStr, err := token.SignedString([]byte(secret.(string)))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}
	return tokenStr
}

// openDB opens a sqlite DB at the given path and returns *sql.DB. Fails the test on error.
func openDB(t *testing.T, dbPath string) *sql.DB {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open sqlite DB: %v", err)
	}
	return db
}

func TestBuildWhereCondEntries(t *testing.T) {
	t.Run("empty map", func(t *testing.T) {
		clause, args, err := easyrest.BuildWhereClause(nil)
		if err != nil {
			t.Fatal(err)
		}
		if clause != "" || args != nil {
			t.Fatalf("expected empty clause for nil, got %q %v", clause, args)
		}

		clause, args, err = easyrest.BuildWhereClause(map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		if clause != "" || args != nil {
			t.Fatalf("expected empty clause for empty map, got %q %v", clause, args)
		}
	})

	t.Run("single equality via operator map", func(t *testing.T) {
		where := map[string]any{"name": map[string]any{"=": "Alice"}}
		clause, args, err := easyrest.BuildWhereClause(where)
		if err != nil {
			t.Fatal(err)
		}
		if clause != " WHERE name = ?" {
			t.Fatalf("got clause %q", clause)
		}
		if len(args) != 1 || args[0] != "Alice" {
			t.Fatalf("got args %v", args)
		}
	})

	t.Run("direct value without operator map", func(t *testing.T) {
		where := map[string]any{"status": "active"}
		clause, args, err := easyrest.BuildWhereClause(where)
		if err != nil {
			t.Fatal(err)
		}
		if clause != " WHERE status = ?" {
			t.Fatalf("got clause %q", clause)
		}
		if len(args) != 1 || args[0] != "active" {
			t.Fatalf("got args %v", args)
		}
	})

	t.Run("direct value with NOT prefix", func(t *testing.T) {
		where := map[string]any{"NOT status": "deleted"}
		clause, args, err := easyrest.BuildWhereClause(where)
		if err != nil {
			t.Fatal(err)
		}
		if clause != " WHERE NOT (status = ?)" {
			t.Fatalf("got clause %q", clause)
		}
		if len(args) != 1 || args[0] != "deleted" {
			t.Fatalf("got args %v", args)
		}
	})

	t.Run("various operators", func(t *testing.T) {
		ops := []struct {
			op   string
			sql  string
			val  string
		}{
			{"=", "age = ?", "30"},
			{"!=", "age != ?", "0"},
			{">", "score > ?", "100"},
			{">=", "score >= ?", "50"},
			{"<", "level < ?", "5"},
			{"<=", "level <= ?", "10"},
			{"LIKE", "name LIKE ?", "%test%"},
			{"ILIKE", "name ILIKE ?", "%TEST%"},
			{"IS", "active IS ?", "TRUE"},
		}
		for _, tc := range ops {
			t.Run(tc.op, func(t *testing.T) {
				where := map[string]any{"col": map[string]any{tc.op: tc.val}}
				clause, args, err := easyrest.BuildWhereClause(where)
				if err != nil {
					t.Fatal(err)
				}
				expected := " WHERE col " + tc.op + " ?"
				if clause != expected {
					t.Fatalf("op %s: expected %q, got %q", tc.op, expected, clause)
				}
				if len(args) != 1 || args[0] != tc.val {
					t.Fatalf("op %s: args %v", tc.op, args)
				}
			})
		}
	})

	t.Run("NOT with operator", func(t *testing.T) {
		where := map[string]any{"NOT age": map[string]any{">": "18"}}
		clause, args, err := easyrest.BuildWhereClause(where)
		if err != nil {
			t.Fatal(err)
		}
		if clause != " WHERE NOT (age > ?)" {
			t.Fatalf("got clause %q", clause)
		}
		if len(args) != 1 || args[0] != "18" {
			t.Fatalf("got args %v", args)
		}
	})

	t.Run("IN with multiple values", func(t *testing.T) {
		where := map[string]any{"id": map[string]any{"IN": "1,2,3"}}
		clause, args, err := easyrest.BuildWhereClause(where)
		if err != nil {
			t.Fatal(err)
		}
		if clause != " WHERE id IN (?,?,?)" {
			t.Fatalf("got clause %q", clause)
		}
		if len(args) != 3 {
			t.Fatalf("expected 3 args, got %d: %v", len(args), args)
		}
		if args[0] != "1" || args[1] != "2" || args[2] != "3" {
			t.Fatalf("got args %v", args)
		}
	})

	t.Run("IN with single value", func(t *testing.T) {
		where := map[string]any{"id": map[string]any{"IN": "42"}}
		clause, args, err := easyrest.BuildWhereClause(where)
		if err != nil {
			t.Fatal(err)
		}
		if clause != " WHERE id IN (?)" {
			t.Fatalf("got clause %q", clause)
		}
		if len(args) != 1 || args[0] != "42" {
			t.Fatalf("got args %v", args)
		}
	})

	t.Run("IN with spaces around values", func(t *testing.T) {
		where := map[string]any{"tag": map[string]any{"IN": " a , b , c "}}
		clause, args, err := easyrest.BuildWhereClause(where)
		if err != nil {
			t.Fatal(err)
		}
		if clause != " WHERE tag IN (?,?,?)" {
			t.Fatalf("got clause %q", clause)
		}
		if args[0] != "a" || args[1] != "b" || args[2] != "c" {
			t.Fatalf("values not trimmed: %v", args)
		}
	})

	t.Run("IN with empty string falls back to NULL", func(t *testing.T) {
		where := map[string]any{"id": map[string]any{"IN": ""}}
		clause, args, err := easyrest.BuildWhereClause(where)
		if err != nil {
			t.Fatal(err)
		}
		if clause != " WHERE id IN (NULL)" {
			t.Fatalf("got clause %q", clause)
		}
		if len(args) != 0 {
			t.Fatalf("expected 0 args, got %v", args)
		}
	})

	t.Run("NOT IN with values", func(t *testing.T) {
		where := map[string]any{"NOT role": map[string]any{"IN": "admin,root"}}
		clause, args, err := easyrest.BuildWhereClause(where)
		if err != nil {
			t.Fatal(err)
		}
		if clause != " WHERE NOT (role IN (?,?))" {
			t.Fatalf("got clause %q", clause)
		}
		if len(args) != 2 || args[0] != "admin" || args[1] != "root" {
			t.Fatalf("got args %v", args)
		}
	})

	t.Run("NOT IN with empty string falls back to NULL", func(t *testing.T) {
		where := map[string]any{"NOT id": map[string]any{"IN": ""}}
		clause, args, err := easyrest.BuildWhereClause(where)
		if err != nil {
			t.Fatal(err)
		}
		if clause != " WHERE NOT (id IN (NULL))" {
			t.Fatalf("got clause %q", clause)
		}
		if len(args) != 0 {
			t.Fatalf("expected 0 args, got %v", args)
		}
	})

	t.Run("multiple conditions sorted", func(t *testing.T) {
		where := map[string]any{
			"name":   map[string]any{"=": "Alice"},
			"age":    map[string]any{">": "18"},
			"status": "active",
		}
		clause, args, err := easyrest.BuildWhereClauseSorted(where)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(clause, " WHERE ") {
			t.Fatalf("clause should start with ' WHERE ', got %q", clause)
		}
		body := clause[len(" WHERE "):]
		parts := strings.Split(body, " AND ")
		if len(parts) != 3 {
			t.Fatalf("expected 3 conditions, got %d: %q", len(parts), body)
		}
		// Sorted output: age|> , name|= , status|=
		if parts[0] != "age > ?" {
			t.Errorf("parts[0]: expected 'age > ?', got %q", parts[0])
		}
		if parts[1] != "name = ?" {
			t.Errorf("parts[1]: expected 'name = ?', got %q", parts[1])
		}
		if parts[2] != "status = ?" {
			t.Errorf("parts[2]: expected 'status = ?', got %q", parts[2])
		}
		if len(args) != 3 {
			t.Fatalf("expected 3 args, got %d: %v", len(args), args)
		}
		if args[0] != "18" || args[1] != "Alice" || args[2] != "active" {
			t.Fatalf("args out of order: %v", args)
		}
	})

	t.Run("multiple operators on same field sorted", func(t *testing.T) {
		where := map[string]any{
			"age": map[string]any{">=": "18", "<=": "65"},
		}
		clause, args, err := easyrest.BuildWhereClauseSorted(where)
		if err != nil {
			t.Fatal(err)
		}
		body := clause[len(" WHERE "):]
		parts := strings.Split(body, " AND ")
		if len(parts) != 2 {
			t.Fatalf("expected 2 conditions, got %d: %q", len(parts), body)
		}
		if len(args) != 2 {
			t.Fatalf("expected 2 args, got %d: %v", len(args), args)
		}
	})

	t.Run("mixed NOT and regular sorted", func(t *testing.T) {
		where := map[string]any{
			"NOT status": map[string]any{"=": "deleted"},
			"active":     map[string]any{"IS": "TRUE"},
		}
		clause, args, err := easyrest.BuildWhereClauseSorted(where)
		if err != nil {
			t.Fatal(err)
		}
		body := clause[len(" WHERE "):]
		parts := strings.Split(body, " AND ")
		if len(parts) != 2 {
			t.Fatalf("expected 2 conditions, got %d: %q", len(parts), body)
		}
		if len(args) != 2 {
			t.Fatalf("expected 2 args, got %v", args)
		}
	})

	t.Run("numeric and boolean direct values", func(t *testing.T) {
		where := map[string]any{"count": 42, "flag": true}
		clause, args, err := easyrest.BuildWhereClauseSorted(where)
		if err != nil {
			t.Fatal(err)
		}
		body := clause[len(" WHERE "):]
		parts := strings.Split(body, " AND ")
		if len(parts) != 2 {
			t.Fatalf("expected 2 conditions, got %d: %q", len(parts), body)
		}
		if parts[0] != "count = ?" || parts[1] != "flag = ?" {
			t.Fatalf("unexpected conditions: %v", parts)
		}
		if args[0] != 42 || args[1] != true {
			t.Fatalf("args should preserve types: %v", args)
		}
	})

	t.Run("BuildWhereClause unsorted matches entry count", func(t *testing.T) {
		where := map[string]any{
			"a": map[string]any{"=": "1"},
			"b": map[string]any{"IN": "x,y"},
			"c": "direct",
		}
		clause, args, err := easyrest.BuildWhereClause(where)
		if err != nil {
			t.Fatal(err)
		}
		body := clause[len(" WHERE "):]
		parts := strings.Split(body, " AND ")
		if len(parts) != 3 {
			t.Fatalf("expected 3 conditions, got %d: %q", len(parts), body)
		}
		if len(args) != 4 { // 1 for "=", 2 for "IN", 1 for direct
			t.Fatalf("expected 4 args, got %d: %v", len(args), args)
		}
	})
}
