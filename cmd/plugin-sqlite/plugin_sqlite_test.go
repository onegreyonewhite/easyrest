package main

import (
	"database/sql"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// initTestDB creates the "users" table in the given DB.
func initTestDB(db *sql.DB) error {
	schema := `
	CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		update_field TEXT
	);`
	_, err := db.Exec(schema)
	return err
}

// openInMemoryDB opens an in-memory SQLite database.
// The DSN for in-memory is ":memory:" so we return "sqlite://:memory:".
func openInMemoryDB(uri string) (*sql.DB, error) {
	dbPath := strings.TrimPrefix(uri, "sqlite://")
	return sql.Open("sqlite3", dbPath)
}

// buildTestContext returns a sample context map for testing.
func buildTestContext() map[string]interface{} {
	return map[string]interface{}{
		"timezone": "America/Los_Angeles",
		"claims": map[string]interface{}{
			"sub": "Alice",
		},
		"headers": map[string]interface{}{
			"user-agent": "TestAgent",
		},
	}
}

// --- Test TableGet without context ---
func TestTableGet_NoContext(t *testing.T) {
	uri := "sqlite://:memory:"
	plugin := &sqlitePlugin{}
	if err := plugin.InitConnection(uri); err != nil {
		t.Fatalf("InitConnection failed: %v", err)
	}
	db, err := openInMemoryDB(uri)
	if err != nil {
		t.Fatalf("openInMemoryDB failed: %v", err)
	}
	plugin.db = db
	if err := initTestDB(plugin.db); err != nil {
		t.Fatalf("initTestDB failed: %v", err)
	}
	// Insert a test row.
	_, err = plugin.db.Exec(`INSERT INTO users (name, update_field) VALUES ('Alice', 'old')`)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}
	selectFields := []string{"id", "name"}
	where := map[string]interface{}{
		"name": map[string]interface{}{"=": "Alice"},
	}
	results, err := plugin.TableGet("testuser", "users", selectFields, where, nil, nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("TableGet failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 row, got %d", len(results))
	}
	if results[0]["name"] != "Alice" {
		t.Errorf("Expected name 'Alice', got %v", results[0]["name"])
	}
}

// --- Test TableGet with context ---
// Here, we use a where condition that compares name to a context column reference.
func TestTableGet_WithContext(t *testing.T) {
	uri := "sqlite://:memory:"
	plugin := &sqlitePlugin{}
	if err := plugin.InitConnection(uri); err != nil {
		t.Fatalf("InitConnection failed: %v", err)
	}
	db, err := openInMemoryDB(uri)
	if err != nil {
		t.Fatalf("openInMemoryDB failed: %v", err)
	}
	plugin.db = db
	if err := initTestDB(plugin.db); err != nil {
		t.Fatalf("initTestDB failed: %v", err)
	}
	// Insert a row with name 'Alice'
	_, err = plugin.db.Exec(`INSERT INTO users (name, update_field) VALUES ('Alice', 'old')`)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}
	selectFields := []string{"id", "name"}
	where := map[string]interface{}{
		"name": map[string]interface{}{"=": "erctx.claims_sub"},
	}
	ctx := buildTestContext() // flattened, claims.sub => "Alice"
	results, err := plugin.TableGet("testuser", "users", selectFields, where, nil, nil, 0, 0, ctx)
	if err != nil {
		t.Fatalf("TableGet with context failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 row, got %d", len(results))
	}
	if results[0]["name"] != "Alice" {
		t.Errorf("Expected name 'Alice', got %v", results[0]["name"])
	}
}

// --- Test TableCreate with context ---
// In this test, we pass data where update_field is set to "erctx.headers_user-agent".
// The query should use the context value from headers ("TestAgent").
func TestTableCreate_WithContext(t *testing.T) {
	uri := "sqlite://:memory:"
	plugin := &sqlitePlugin{}
	if err := plugin.InitConnection(uri); err != nil {
		t.Fatalf("InitConnection failed: %v", err)
	}
	db, err := openInMemoryDB(uri)
	if err != nil {
		t.Fatalf("openInMemoryDB failed: %v", err)
	}
	plugin.db = db
	if err := initTestDB(plugin.db); err != nil {
		t.Fatalf("initTestDB failed: %v", err)
	}
	data := []map[string]interface{}{
		{
			"name":         "Bob",
			"update_field": "erctx.headers_user_agent",
		},
	}
	ctx := buildTestContext()
	created, err := plugin.TableCreate("testuser", "users", data, ctx)
	if err != nil {
		t.Fatalf("TableCreate failed: %v", err)
	}
	if len(created) != 1 {
		t.Fatalf("Expected 1 row created, got %d", len(created))
	}
	// Verify by selecting the inserted row.
	selectFields := []string{"id", "name", "update_field"}
	where := map[string]interface{}{
		"name": map[string]interface{}{"=": "Bob"},
	}
	results, err := plugin.TableGet("testuser", "users", selectFields, where, nil, nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("TableGet failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 row, got %d", len(results))
	}
	// Expect the update_field to be replaced with the context value from headers.
	if results[0]["update_field"] != "TestAgent" {
		t.Errorf("Expected update_field 'TestAgent', got '%v'", results[0]["update_field"])
	}
}

// --- Test TableUpdate with context ---
// Here, we update the update_field column to reference a context value.
func TestTableUpdate_WithContext(t *testing.T) {
	uri := "sqlite://:memory:"
	plugin := &sqlitePlugin{}
	if err := plugin.InitConnection(uri); err != nil {
		t.Fatalf("InitConnection failed: %v", err)
	}
	db, err := openInMemoryDB(uri)
	if err != nil {
		t.Fatalf("openInMemoryDB failed: %v", err)
	}
	plugin.db = db
	if err := initTestDB(plugin.db); err != nil {
		t.Fatalf("initTestDB failed: %v", err)
	}
	// Insert a row.
	_, err = plugin.db.Exec(`INSERT INTO users (name, update_field) VALUES ('Charlie', 'old')`)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}
	// Update: set update_field to a context reference.
	data := map[string]interface{}{
		"update_field": "erctx.headers_user-agent",
	}
	where := map[string]interface{}{
		"name": map[string]interface{}{"=": "Charlie"},
	}
	ctx := buildTestContext()
	updated, err := plugin.TableUpdate("testuser", "users", data, where, ctx)
	if err != nil {
		t.Fatalf("TableUpdate failed: %v", err)
	}
	if updated != 1 {
		t.Fatalf("Expected 1 row updated, got %d", updated)
	}
	// Verify the update.
	selectFields := []string{"id", "name", "update_field"}
	results, err := plugin.TableGet("testuser", "users", selectFields, where, nil, nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("TableGet failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 row, got %d", len(results))
	}
	if results[0]["update_field"] != "TestAgent" {
		t.Errorf("Expected update_field 'TestAgent', got '%v'", results[0]["update_field"])
	}
}

// --- Test TableDelete with context ---
// Here, we delete rows using a where condition that references a context value.
func TestTableDelete_WithContext(t *testing.T) {
	uri := "sqlite://:memory:"
	plugin := &sqlitePlugin{}
	if err := plugin.InitConnection(uri); err != nil {
		t.Fatalf("InitConnection failed: %v", err)
	}
	db, err := openInMemoryDB(uri)
	if err != nil {
		t.Fatalf("openInMemoryDB failed: %v", err)
	}
	plugin.db = db
	if err := initTestDB(plugin.db); err != nil {
		t.Fatalf("initTestDB failed: %v", err)
	}
	// Insert two rows with name 'Dave'
	_, err = plugin.db.Exec(`INSERT INTO users (name, update_field) VALUES ('Dave', 'old')`)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}
	_, err = plugin.db.Exec(`INSERT INTO users (name, update_field) VALUES ('Dave', 'old')`)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}
	where := map[string]interface{}{
		"name": map[string]interface{}{"=": "erctx.claims_sub"},
	}
	// Build context where claims.sub equals "Dave"
	ctx := map[string]interface{}{
		"claims": map[string]interface{}{
			"sub": "Dave",
		},
	}
	deleted, err := plugin.TableDelete("testuser", "users", where, ctx)
	if err != nil {
		t.Fatalf("TableDelete failed: %v", err)
	}
	if deleted != 2 {
		t.Errorf("Expected 2 rows deleted, got %d", deleted)
	}
}

// --- Test CallFunction with context ---
func TestCallFunction_WithContext(t *testing.T) {
	uri := "sqlite://:memory:"
	plugin := &sqlitePlugin{}
	if err := plugin.InitConnection(uri); err != nil {
		t.Fatalf("InitConnection failed: %v", err)
	}
	ctx := buildTestContext()
	_, err := plugin.CallFunction("testuser", "myFunc", map[string]interface{}{"param": "value"}, ctx)
	if err == nil {
		t.Fatalf("CallFunction is not supported for SQLite")
	}
}
