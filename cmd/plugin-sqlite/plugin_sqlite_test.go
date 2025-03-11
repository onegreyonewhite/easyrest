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
// Now the plugin does not perform substitution so we pass already substituted values.
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
	// Instead of using a context reference, pass literal "Alice"
	where := map[string]interface{}{
		"name": map[string]interface{}{"=": "Alice"},
	}
	// Context is not used by the plugin now.
	results, err := plugin.TableGet("testuser", "users", selectFields, where, nil, nil, 0, 0, nil)
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
// Instead of using context substitution inside the plugin, we pass already substituted values.
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
	// Instead of passing "erctx.headers_user_agent", pass the substituted value "TestAgent".
	data := []map[string]interface{}{
		{
			"name":         "Bob",
			"update_field": "TestAgent",
		},
	}
	created, err := plugin.TableCreate("testuser", "users", data, nil)
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
	if results[0]["update_field"] != "TestAgent" {
		t.Errorf("Expected update_field 'TestAgent', got '%v'", results[0]["update_field"])
	}
}

// --- Test TableUpdate with context ---
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
	// Instead of passing "erctx.headers_user_agent", pass "TestAgent"
	data := map[string]interface{}{
		"update_field": "TestAgent",
	}
	where := map[string]interface{}{
		"name": map[string]interface{}{"=": "Charlie"},
	}
	updated, err := plugin.TableUpdate("testuser", "users", data, where, nil)
	if err != nil {
		t.Fatalf("TableUpdate failed: %v", err)
	}
	if updated != 1 {
		t.Fatalf("Expected 1 row updated, got %d", updated)
	}
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
	// Instead of passing "erctx.claims.sub", pass literal "Dave"
	where := map[string]interface{}{
		"name": map[string]interface{}{"=": "Dave"},
	}
	deleted, err := plugin.TableDelete("testuser", "users", where, nil)
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

// --- TestGetSchema tests the GetSchema method.
func TestGetSchema(t *testing.T) {
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

	// Create a test table with various constraints.
	schemaSQL := `
	CREATE TABLE test (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		age INTEGER,
		email TEXT DEFAULT 'unknown'
	);`
	_, err = plugin.db.Exec(schemaSQL)
	if err != nil {
		t.Fatalf("Failed to create test table: %v", err)
	}

	// Call GetSchema
	schemaRaw, err := plugin.GetSchema(nil)
	if err != nil {
		t.Fatalf("GetSchema failed: %v", err)
	}
	schemaMap, ok := schemaRaw.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected schema to be a map, got %T", schemaRaw)
	}
	tables, ok := schemaMap["tables"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected 'tables' to be a map, got %T", schemaMap["tables"])
	}
	testTable, ok := tables["test"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected table 'test' in schema")
	}
	properties, ok := testTable["properties"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected properties to be a map")
	}

	// Check column "id": primary key → readOnly true, type integer.
	idProp, ok := properties["id"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected property 'id' to be a map")
	}
	if idProp["type"] != "integer" {
		t.Errorf("Expected 'id' type 'integer', got %v", idProp["type"])
	}
	if ro, ok := idProp["readOnly"].(bool); !ok || !ro {
		t.Errorf("Expected 'id' to be readOnly")
	}

	// Check column "name": NOT NULL and no default → should be required and not x-nullable.
	nameProp, ok := properties["name"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected property 'name' to be a map")
	}
	if nameProp["type"] != "string" {
		t.Errorf("Expected 'name' type 'string', got %v", nameProp["type"])
	}
	if _, exists := nameProp["x-nullable"]; exists {
		t.Errorf("Did not expect 'name' to have x-nullable")
	}
	// Check that "name" is in required.
	required, ok := testTable["required"].([]string)
	if !ok {
		t.Fatalf("Expected required to be a slice")
	}
	foundName := false
	for _, field := range required {
		if field == "name" {
			foundName = true
			break
		}
	}
	if !foundName {
		t.Errorf("Expected 'name' to be required")
	}

	// Check column "age": allows null → should have x-nullable true and not be required.
	ageProp, ok := properties["age"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected property 'age' to be a map")
	}
	if ageProp["type"] != "integer" {
		t.Errorf("Expected 'age' type 'integer', got %v", ageProp["type"])
	}
	if xNullable, ok := ageProp["x-nullable"].(bool); !ok || !xNullable {
		t.Errorf("Expected 'age' to be x-nullable")
	}
	// Check that "age" is not in required.
	for _, field := range required {
		if field == "age" {
			t.Errorf("Did not expect 'age' to be required")
		}
	}

	// Check column "email": имеет DEFAULT → не обязателен, даже если NOT NULL не указан.
	emailProp, ok := properties["email"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected property 'email' to be a map")
	}
	if emailProp["type"] != "string" {
		t.Errorf("Expected 'email' type 'string', got %v", emailProp["type"])
	}
	// Здесь по определению, email допускает null, поэтому можно ожидать x-nullable.
	if _, exists := emailProp["x-nullable"]; !exists {
		t.Errorf("Expected 'email' to have x-nullable since it has a DEFAULT")
	}
	// Check that "email" is not in required.
	for _, field := range required {
		if field == "email" {
			t.Errorf("Did not expect 'email' to be required")
		}
	}
}
