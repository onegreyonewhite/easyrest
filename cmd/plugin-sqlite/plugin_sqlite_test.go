package main

import (
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// initTestDB creates the "users" table in the given DB.
func initTestDB(db *sql.DB) error {
	schema := `
	CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		update_field TEXT,
		created_at DATETIME
	);`
	_, err := db.Exec(schema)
	return err
}

// openInMemoryDB opens an in-memory SQLite database.
func openInMemoryDB(uri string) (*sql.DB, error) {
	dbPath := strings.TrimPrefix(uri, "sqlite://")
	return sql.Open("sqlite", dbPath)
}

// buildTestContext returns a sample context map for testing.
func buildTestContext() map[string]any {
	return map[string]any{
		"timezone": "America/Los_Angeles",
		"claims": map[string]any{
			"sub": "Alice",
		},
		"headers": map[string]any{
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
	where := map[string]any{
		"name": map[string]any{"=": "Alice"},
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
	where := map[string]any{
		"name": map[string]any{"=": "Alice"},
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
	data := []map[string]any{
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
	where := map[string]any{
		"name": map[string]any{"=": "Bob"},
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
	data := map[string]any{
		"update_field": "TestAgent",
	}
	where := map[string]any{
		"name": map[string]any{"=": "Charlie"},
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
	where := map[string]any{
		"name": map[string]any{"=": "Dave"},
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
	_, err := plugin.CallFunction("testuser", "myFunc", map[string]any{"param": "value"}, ctx)
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

	// Create a test table with various data types
	schemaSQL := `
	CREATE TABLE test (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		age INTEGER,
		email TEXT DEFAULT 'unknown',
		image BLOB,
		price REAL,
		created_at DATETIME
	);

	CREATE VIEW test_view AS 
	SELECT id, name, age, price 
	FROM test 
	WHERE age > 18;`
	_, err = plugin.db.Exec(schemaSQL)
	if err != nil {
		t.Fatalf("Failed to create test table and view: %v", err)
	}

	// Call GetSchema
	schemaRaw, err := plugin.GetSchema(nil)
	if err != nil {
		t.Fatalf("GetSchema failed: %v", err)
	}
	schemaMap, ok := schemaRaw.(map[string]any)
	if !ok {
		t.Fatalf("Expected schema to be a map, got %T", schemaRaw)
	}

	// Check tables
	tables, ok := schemaMap["tables"].(map[string]any)
	if !ok {
		t.Fatalf("Expected 'tables' to be a map, got %T", schemaMap["tables"])
	}
	testTable, ok := tables["test"].(map[string]any)
	if !ok {
		t.Fatalf("Expected table 'test' in schema")
	}
	properties, ok := testTable["properties"].(map[string]any)
	if !ok {
		t.Fatalf("Expected properties to be a map")
	}

	// Check BLOB type
	imageProp, ok := properties["image"].(map[string]any)
	if !ok {
		t.Fatalf("Expected property 'image' to be a map")
	}
	if imageProp["type"] != "string" {
		t.Errorf("Expected 'image' type 'string', got %v", imageProp["type"])
	}
	if imageProp["format"] != "byte" {
		t.Errorf("Expected 'image' format 'byte', got %v", imageProp["format"])
	}

	// Check REAL type
	priceProp, ok := properties["price"].(map[string]any)
	if !ok {
		t.Fatalf("Expected property 'price' to be a map")
	}
	if priceProp["type"] != "number" {
		t.Errorf("Expected 'price' type 'number', got %v", priceProp["type"])
	}

	// Check view
	views, ok := schemaMap["views"].(map[string]any)
	if !ok {
		t.Fatalf("Expected 'views' to be a map, got %T", schemaMap["views"])
	}
	testView, ok := views["test_view"].(map[string]any)
	if !ok {
		t.Fatalf("Expected view 'test_view' in schema")
	}
	viewProperties, ok := testView["properties"].(map[string]any)
	if !ok {
		t.Fatalf("Expected properties in view schema")
	}

	// Check view properties
	expectedViewProps := []string{"id", "name", "age", "price"}
	for _, propName := range expectedViewProps {
		if _, exists := viewProperties[propName]; !exists {
			t.Errorf("Expected property '%s' in view schema", propName)
		}
	}

	// Check that view has no required fields (views don't have NOT NULL constraints)
	if _, exists := testView["required"]; exists {
		t.Errorf("View schema should not have required fields")
	}

	// Check that view properties have correct types
	idProp := viewProperties["id"].(map[string]any)
	if idProp["type"] != "integer" {
		t.Errorf("Expected view 'id' type 'integer', got %v", idProp["type"])
	}

	nameProp := viewProperties["name"].(map[string]any)
	if nameProp["type"] != "string" {
		t.Errorf("Expected view 'name' type 'string', got %v", nameProp["type"])
	}

	ageProp := viewProperties["age"].(map[string]any)
	if ageProp["type"] != "integer" {
		t.Errorf("Expected view 'age' type 'integer', got %v", ageProp["type"])
	}

	priceProp = viewProperties["price"].(map[string]any)
	if priceProp["type"] != "number" {
		t.Errorf("Expected view 'price' type 'number', got %v", priceProp["type"])
	}
}

// TestTableGet_GroupBy tests grouping functionality
func TestTableGet_GroupBy(t *testing.T) {
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

	// Insert test data
	_, err = plugin.db.Exec(`
		INSERT INTO users (name, update_field, created_at) VALUES 
		('Alice', 'test1', '2024-03-13 10:00:00'),
		('Alice', 'test2', '2024-03-13 11:00:00'),
		('Bob', 'test3', '2024-03-13 12:00:00'),
		('Bob', 'test4', '2024-03-13 13:00:00')
	`)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	selectFields := []string{"name", "COUNT(*) as count"}
	groupBy := []string{"name"}
	results, err := plugin.TableGet("testuser", "users", selectFields, nil, nil, groupBy, 0, 0, nil)
	if err != nil {
		t.Fatalf("TableGet failed: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("Expected 2 groups, got %d", len(results))
	}

	// Verify counts
	for _, row := range results {
		name := row["name"].(string)
		count := row["count"].(int64)
		if name == "Alice" && count != 2 {
			t.Errorf("Expected count 2 for Alice, got %d", count)
		}
		if name == "Bob" && count != 2 {
			t.Errorf("Expected count 2 for Bob, got %d", count)
		}
	}
}

// TestTableGet_Ordering tests ordering functionality
func TestTableGet_Ordering(t *testing.T) {
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

	// Insert test data
	_, err = plugin.db.Exec(`
		INSERT INTO users (name, update_field, created_at) VALUES 
		('Alice', 'test1', '2024-03-13 10:00:00'),
		('Bob', 'test2', '2024-03-13 11:00:00'),
		('Charlie', 'test3', '2024-03-13 12:00:00')
	`)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	selectFields := []string{"name"}
	ordering := []string{"name DESC"}
	results, err := plugin.TableGet("testuser", "users", selectFields, nil, ordering, nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("TableGet failed: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("Expected 3 rows, got %d", len(results))
	}

	// Verify order
	expected := []string{"Charlie", "Bob", "Alice"}
	for i, row := range results {
		if row["name"] != expected[i] {
			t.Errorf("Expected name %s at position %d, got %s", expected[i], i, row["name"])
		}
	}
}

// TestTableGet_LimitOffset tests limit and offset functionality
func TestTableGet_LimitOffset(t *testing.T) {
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

	// Insert test data
	_, err = plugin.db.Exec(`
		INSERT INTO users (name, update_field, created_at) VALUES 
		('Alice', 'test1', '2024-03-13 10:00:00'),
		('Bob', 'test2', '2024-03-13 11:00:00'),
		('Charlie', 'test3', '2024-03-13 12:00:00'),
		('Dave', 'test4', '2024-03-13 13:00:00'),
		('Eve', 'test5', '2024-03-13 14:00:00')
	`)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	selectFields := []string{"name"}
	ordering := []string{"name"}

	// Test limit
	results, err := plugin.TableGet("testuser", "users", selectFields, nil, ordering, nil, 2, 0, nil)
	if err != nil {
		t.Fatalf("TableGet failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("Expected 2 rows with limit 2, got %d", len(results))
	}

	// Test offset
	results, err = plugin.TableGet("testuser", "users", selectFields, nil, ordering, nil, 0, 2, nil)
	if err != nil {
		t.Fatalf("TableGet failed: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("Expected 3 rows with offset 2, got %d", len(results))
	}

	// Test limit and offset together
	results, err = plugin.TableGet("testuser", "users", selectFields, nil, ordering, nil, 2, 1, nil)
	if err != nil {
		t.Fatalf("TableGet failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("Expected 2 rows with limit 2 and offset 1, got %d", len(results))
	}
}

// TestTableGet_TimeFormat tests time formatting for different cases
func TestTableGet_TimeFormat(t *testing.T) {
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

	// Insert test data with midnight and non-midnight times
	_, err = plugin.db.Exec(`
		INSERT INTO users (name, update_field, created_at) VALUES 
		('Alice', 'test1', '2024-03-13 00:00:00'),
		('Bob', 'test2', '2024-03-13 10:30:45')
	`)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	selectFields := []string{"name", "created_at"}
	results, err := plugin.TableGet("testuser", "users", selectFields, nil, nil, nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("TableGet failed: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("Expected 2 rows, got %d", len(results))
	}

	// Check midnight time format
	aliceTime := results[0]["created_at"].(string)
	if aliceTime != "2024-03-13" {
		t.Errorf("Expected midnight time format '2024-03-13', got '%s'", aliceTime)
	}

	// Check non-midnight time format
	bobTime := results[1]["created_at"].(string)
	if bobTime != "2024-03-13 10:30:45" {
		t.Errorf("Expected time format '2024-03-13 10:30:45', got '%s'", bobTime)
	}
}

// TestTableGet_ILIKE tests ILIKE operator conversion to LIKE COLLATE NOCASE
func TestTableGet_ILIKE(t *testing.T) {
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

	// Insert test data with different cases
	_, err = plugin.db.Exec(`
		INSERT INTO users (name, update_field, created_at) VALUES 
		('Alice', 'test1', '2024-03-13 10:00:00'),
		('ALICE', 'test2', '2024-03-13 11:00:00'),
		('alice', 'test3', '2024-03-13 12:00:00'),
		('Bob', 'test4', '2024-03-13 13:00:00')
	`)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	// Test case-insensitive search with ILIKE
	where := map[string]any{
		"name": map[string]any{
			"ILIKE": "alice",
		},
	}
	selectFields := []string{"name", "update_field"}
	results, err := plugin.TableGet("testuser", "users", selectFields, where, nil, nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("TableGet failed: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("Expected 3 rows with name ILIKE 'alice', got %d", len(results))
	}

	// Verify that all returned rows have name 'alice' (case-insensitive)
	for _, row := range results {
		name := row["name"].(string)
		if !strings.EqualFold(name, "alice") {
			t.Errorf("Expected name to be 'alice' (case-insensitive), got '%s'", name)
		}
	}

	// Test ILIKE with pattern matching
	where = map[string]any{
		"name": map[string]any{
			"ILIKE": "%li%",
		},
	}
	results, err = plugin.TableGet("testuser", "users", selectFields, where, nil, nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("TableGet failed: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("Expected 3 rows with name ILIKE '%%li%%', got %d", len(results))
	}

	// Test ILIKE with multiple conditions
	where = map[string]any{
		"name": map[string]any{
			"ILIKE": "alice",
		},
		"update_field": map[string]any{
			"ILIKE": "test%%",
		},
	}
	results, err = plugin.TableGet("testuser", "users", selectFields, where, nil, nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("TableGet failed: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("Expected 3 rows with name ILIKE 'alice' AND update_field ILIKE 'test%%', got %d", len(results))
	}

	// Test that ILIKE is properly converted to LIKE COLLATE NOCASE in the query
	// This is an internal implementation detail, but we can verify it works correctly
	where = map[string]any{
		"name": map[string]any{
			"ILIKE": "test",
		},
	}
	results, err = plugin.TableGet("testuser", "users", selectFields, where, nil, nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("TableGet failed: %v", err)
	}

	if len(results) != 0 {
		t.Fatalf("Expected 0 rows with name ILIKE 'test', got %d", len(results))
	}
}
