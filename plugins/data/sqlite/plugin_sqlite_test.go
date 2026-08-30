package sqlite

import (
	"database/sql"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"regexp"

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
	results, _, err := plugin.TableGet("testuser", "users", selectFields, where, nil, nil, 0, 0, nil)
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
	results, _, err := plugin.TableGet("testuser", "users", selectFields, where, nil, nil, 0, 0, nil)
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
	created, _, err := plugin.TableCreate("testuser", "users", data, nil)
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
	results, _, err := plugin.TableGet("testuser", "users", selectFields, where, nil, nil, 0, 0, nil)
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

func TestTableCreate_RejectsMaliciousColumn(t *testing.T) {
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
	data := []map[string]any{
		{"name) VALUES ('boom'); --": "x"},
	}
	_, _, err = plugin.TableCreate("testuser", "users", data, nil)
	if err == nil {
		t.Fatal("expected error for malicious column name")
	}
	if !strings.Contains(err.Error(), "invalid column name") {
		t.Fatalf("expected invalid column name error, got: %v", err)
	}
	var count int
	if err := plugin.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected no rows inserted, got %d", count)
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
	updated, _, err := plugin.TableUpdate("testuser", "users", data, where, nil)
	if err != nil {
		t.Fatalf("TableUpdate failed: %v", err)
	}
	if updated != 1 {
		t.Fatalf("Expected 1 row updated, got %d", updated)
	}
	selectFields := []string{"id", "name", "update_field"}
	results, _, err := plugin.TableGet("testuser", "users", selectFields, where, nil, nil, 0, 0, nil)
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

func TestTableUpdate_RejectsMaliciousColumn(t *testing.T) {
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
	_, err = plugin.db.Exec(`INSERT INTO users (name, update_field) VALUES ('Charlie', 'old')`)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}
	data := map[string]any{"name = 'pwned', update_field": "x"}
	where := map[string]any{"name": map[string]any{"=": "Charlie"}}
	_, _, err = plugin.TableUpdate("testuser", "users", data, where, nil)
	if err == nil {
		t.Fatal("expected error for malicious column name")
	}
	if !strings.Contains(err.Error(), "invalid column name") {
		t.Fatalf("expected invalid column name error, got: %v", err)
	}
	var name string
	if err := plugin.db.QueryRow(`SELECT name FROM users WHERE name = 'Charlie'`).Scan(&name); err != nil {
		t.Fatalf("select failed: %v", err)
	}
	if name != "Charlie" {
		t.Fatalf("name was modified by injection, got %q", name)
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
	deleted, _, err := plugin.TableDelete("testuser", "users", where, nil)
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
	_, _, err := plugin.CallFunction("testuser", "myFunc", map[string]any{"param": "value"}, ctx)
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
	schemaRaw, _, err := plugin.GetSchema(nil)
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
	results, _, err := plugin.TableGet("testuser", "users", selectFields, nil, nil, groupBy, 0, 0, nil)
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
	results, _, err := plugin.TableGet("testuser", "users", selectFields, nil, ordering, nil, 0, 0, nil)
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
	results, _, err := plugin.TableGet("testuser", "users", selectFields, nil, ordering, nil, 2, 0, nil)
	if err != nil {
		t.Fatalf("TableGet failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("Expected 2 rows with limit 2, got %d", len(results))
	}

	// Test offset
	results, _, err = plugin.TableGet("testuser", "users", selectFields, nil, ordering, nil, 0, 2, nil)
	if err != nil {
		t.Fatalf("TableGet failed: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("Expected 3 rows with offset 2, got %d", len(results))
	}

	// Test limit and offset together
	results, _, err = plugin.TableGet("testuser", "users", selectFields, nil, ordering, nil, 2, 1, nil)
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
	results, _, err := plugin.TableGet("testuser", "users", selectFields, nil, nil, nil, 0, 0, nil)
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
	results, _, err := plugin.TableGet("testuser", "users", selectFields, where, nil, nil, 0, 0, nil)
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
	results, _, err = plugin.TableGet("testuser", "users", selectFields, where, nil, nil, 0, 0, nil)
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
	results, _, err = plugin.TableGet("testuser", "users", selectFields, where, nil, nil, 0, 0, nil)
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
	results, _, err = plugin.TableGet("testuser", "users", selectFields, where, nil, nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("TableGet failed: %v", err)
	}

	if len(results) != 0 {
		t.Fatalf("Expected 0 rows with name ILIKE 'test', got %d", len(results))
	}
}

// --- Test TableGet with all where operators ---
func TestTableGet_AllWhereOps(t *testing.T) {
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
	// Insert one row
	_, err = plugin.db.Exec(`INSERT INTO users (name, update_field, created_at) VALUES ('Alice', 'test1', '2024-03-13 10:00:00')`)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}
	selectFields := []string{"id", "name", "update_field", "created_at"}

	// All supported where-operators
	whereCases := []struct {
		desc   string
		where  map[string]any
		expect int // how many rows expected
	}{
		{"eq match", map[string]any{"name": map[string]any{"=": "Alice"}}, 1},
		{"neq not match", map[string]any{"name": map[string]any{"!=": "Alice"}}, 0},
		{"lt not match", map[string]any{"id": map[string]any{"<": 1}}, 0},
		{"lte match", map[string]any{"id": map[string]any{"<=": 1}}, 1},
		{"gt not match", map[string]any{"id": map[string]any{">": 1}}, 0},
		{"gte match", map[string]any{"id": map[string]any{">=": 1}}, 1},
		{"like match", map[string]any{"name": map[string]any{"LIKE": "A%"}}, 1},
		{"ilike match", map[string]any{"name": map[string]any{"ILIKE": "a%"}}, 1},
		{"is match", map[string]any{"update_field": map[string]any{"IS": "test1"}}, 1},
		{"in match", map[string]any{"name": map[string]any{"IN": "Alice,Bob"}}, 1},
		{"in match null", map[string]any{"name": map[string]any{"IN": ""}}, 0},
		// NOT-versions
		{"not eq not match", map[string]any{"NOT name": map[string]any{"=": "Alice"}}, 0},
		{"not neq match", map[string]any{"NOT name": map[string]any{"!=": "Alice"}}, 1},
		{"not lt match", map[string]any{"NOT id": map[string]any{"<": 1}}, 1},
		{"not lte not match", map[string]any{"NOT id": map[string]any{"<=": 1}}, 0},
		{"not gt match", map[string]any{"NOT id": map[string]any{">": 1}}, 1},
		{"not gte not match", map[string]any{"NOT id": map[string]any{">=": 1}}, 0},
		{"not like not match", map[string]any{"NOT name": map[string]any{"LIKE": "A%"}}, 0},
		{"not ilike not match", map[string]any{"NOT name": map[string]any{"ILIKE": "a%"}}, 0},
		{"not is not match", map[string]any{"NOT update_field": map[string]any{"IS": "test1"}}, 0},
		{"not in not match", map[string]any{"NOT name": map[string]any{"IN": "Alice,Bob"}}, 0},
		{"not in not match null", map[string]any{"NOT name": map[string]any{"IN": ""}}, 0},
		// OLD syntax version
		{"eq match", map[string]any{"name": "Alice"}, 1},
		{"eq not match", map[string]any{"NOT name": "Alice"}, 0},
	}
	for _, tc := range whereCases {
		results, _, err := plugin.TableGet("testuser", "users", selectFields, tc.where, nil, nil, 0, 0, nil)
		if err != nil {
			t.Errorf("%s: TableGet failed: %v", tc.desc, err)
			continue
		}
		if len(results) != tc.expect {
			t.Errorf("%s: expected %d rows, got %d", tc.desc, tc.expect, len(results))
		}
	}
}

func TestGetSchema_SkipsUnsafeTableNames(t *testing.T) {
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
	if _, err := plugin.db.Exec(`CREATE TABLE "weird;name" (id INTEGER)`); err != nil {
		t.Fatalf("create unsafe table failed: %v", err)
	}

	schemaRaw, _, err := plugin.GetSchema(nil)
	if err != nil {
		t.Fatalf("GetSchema failed: %v", err)
	}
	schemaMap, ok := schemaRaw.(map[string]any)
	if !ok {
		t.Fatalf("unexpected schema type: %T", schemaRaw)
	}
	tables, ok := schemaMap["tables"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected tables type: %T", schemaMap["tables"])
	}
	if _, found := tables["weird;name"]; found {
		t.Fatal("unsafe table name should be omitted from schema")
	}
	if _, found := tables["users"]; !found {
		t.Fatal("expected users table in schema")
	}
}

func TestSqliteCachePluginCloseStopsCleanupGoroutine(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "sqlite-cache-close-*.db")
	if err != nil {
		t.Fatalf("failed to create temp db: %v", err)
	}
	dbPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(dbPath)

	plugin := NewSqliteCachePlugin()
	if err := plugin.InitConnection("sqlite://" + dbPath); err != nil {
		t.Fatalf("InitConnection failed: %v", err)
	}

	before := runtime.NumGoroutine()
	plugin.Close()
	time.Sleep(50 * time.Millisecond)
	after := runtime.NumGoroutine()
	if after > before+2 {
		t.Fatalf("goroutine count increased after Close: before=%d after=%d", before, after)
	}
}

func TestSqliteCacheSetGet(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "sqlite-cache-setget-*.db")
	if err != nil {
		t.Fatal(err)
	}
	dbPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(dbPath)

	plugin := NewSqliteCachePlugin()
	if err := plugin.InitConnection("sqlite://" + dbPath); err != nil {
		t.Fatalf("InitConnection: %v", err)
	}
	defer plugin.Close()

	if err := plugin.Set("k1", "v1", time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := plugin.Get("k1")
	if err != nil || got != "v1" {
		t.Fatalf("Get hit: %q %v", got, err)
	}
	if _, err := plugin.Get("missing"); err == nil {
		t.Fatal("expected miss")
	}
	if err := plugin.Set("exp", "gone", time.Millisecond); err != nil {
		t.Fatalf("Set exp: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := plugin.Get("exp"); err == nil {
		t.Fatal("expected expired miss")
	}
}

func TestTableUpdate_PreferTxRollback(t *testing.T) {
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
	_, err = plugin.db.Exec(`INSERT INTO users (name, update_field) VALUES ('Alice', 'old')`)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	ctx := map[string]any{
		"prefer": map[string]any{"tx": "rollback"},
	}
	updated, _, err := plugin.TableUpdate("u", "users", map[string]any{"update_field": "new"}, map[string]any{"name": map[string]any{"=": "Alice"}}, ctx)
	if err != nil {
		t.Fatalf("TableUpdate: %v", err)
	}
	if updated != 0 {
		t.Fatalf("expected 0 updated after rollback preference, got %d", updated)
	}
	var field string
	if err := plugin.db.QueryRow(`SELECT update_field FROM users WHERE name='Alice'`).Scan(&field); err != nil {
		t.Fatal(err)
	}
	if field != "old" {
		t.Fatalf("row should be unchanged after rollback, got %q", field)
	}
}

func TestTableUpdate_InvalidPreferTx(t *testing.T) {
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

	ctx := map[string]any{
		"prefer": map[string]any{"tx": "banana"},
	}
	_, _, err = plugin.TableUpdate("u", "users", map[string]any{"update_field": "x"}, map[string]any{"name": map[string]any{"=": "Alice"}}, ctx)
	if err == nil {
		t.Fatal("expected invalid prefer.tx error")
	}
}

func TestTableCreate_PreferTxRollbackStillReturnsRows(t *testing.T) {
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

	ctx := map[string]any{
		"prefer": map[string]any{"tx": "rollback"},
	}
	rows, _, err := plugin.TableCreate("u", "users", []map[string]any{{"name": "Bob", "update_field": "x"}}, ctx)
	if err != nil {
		t.Fatalf("TableCreate: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected created rows returned even on rollback, got %d", len(rows))
	}
	var count int
	if err := plugin.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected rollback to leave table empty, got count=%d", count)
	}
}

func TestVerifyReadOnlyConnectionErrorPaths(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec(regexp.QuoteMeta("PRAGMA query_only = ON")).WillReturnError(errors.New("pragma fail"))
	if err := verifyReadOnlyConnection(db); err == nil || !strings.Contains(err.Error(), "failed to set query_only") {
		t.Fatalf("pragma fail: %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta("PRAGMA query_only = ON")).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("PRAGMA query_only")).WillReturnError(errors.New("read fail"))
	if err := verifyReadOnlyConnection(db); err == nil || !strings.Contains(err.Error(), "failed to read query_only") {
		t.Fatalf("read fail: %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta("PRAGMA query_only = ON")).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("PRAGMA query_only")).
		WillReturnRows(sqlmock.NewRows([]string{"query_only"}).AddRow(0))
	if err := verifyReadOnlyConnection(db); err == nil || !strings.Contains(err.Error(), "not read-only") {
		t.Fatalf("not ro: %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta("PRAGMA query_only = ON")).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("PRAGMA query_only")).
		WillReturnRows(sqlmock.NewRows([]string{"query_only"}).AddRow(1))
	mock.ExpectExec(regexp.QuoteMeta("CREATE TABLE IF NOT EXISTS _easyrest_ro_check (id INTEGER)")).
		WillReturnResult(sqlmock.NewResult(0, 0))
	if err := verifyReadOnlyConnection(db); err == nil || !strings.Contains(err.Error(), "allows writes") {
		t.Fatalf("writable: %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta("PRAGMA query_only = ON")).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("PRAGMA query_only")).
		WillReturnRows(sqlmock.NewRows([]string{"query_only"}).AddRow(1))
	mock.ExpectExec(regexp.QuoteMeta("CREATE TABLE IF NOT EXISTS _easyrest_ro_check (id INTEGER)")).
		WillReturnError(errors.New("readonly"))
	if err := verifyReadOnlyConnection(db); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestTableDeleteInvalidWhere(t *testing.T) {
	plugin := &sqlitePlugin{}
	if err := plugin.InitConnection("sqlite://:memory:"); err != nil {
		t.Fatal(err)
	}
	db, err := openInMemoryDB("sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	plugin.db = db
	if err := initTestDB(plugin.db); err != nil {
		t.Fatal(err)
	}
	if _, _, err := plugin.TableDelete("u", "users", map[string]any{"id;drop": 1}, nil); err == nil {
		t.Fatal("expected invalid where")
	}
}

func TestTableGetInvalidWhereAndGroupBy(t *testing.T) {
	plugin := &sqlitePlugin{}
	if err := plugin.InitConnection("sqlite://:memory:"); err != nil {
		t.Fatal(err)
	}
	db, err := openInMemoryDB("sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	plugin.db = db
	if err := initTestDB(plugin.db); err != nil {
		t.Fatal(err)
	}
	_, err = plugin.db.Exec(`INSERT INTO users (name, update_field) VALUES ('Alice', 'old')`)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := plugin.TableGet("u", "users", []string{"name"}, map[string]any{"id;drop": 1}, nil, nil, 0, 0, nil); err == nil {
		t.Fatal("expected invalid where")
	}
	rows, _, err := plugin.TableGet("u", "users", []string{"name"}, nil, []string{"name"}, []string{"name"}, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("groupby: %d", len(rows))
	}
}

func TestHandleTransactionRollbackPreference(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	plugin := &sqlitePlugin{db: db}
	mock.ExpectBegin()
	mock.ExpectRollback()
	got, err := plugin.handleTransaction("u", map[string]any{"prefer": map[string]any{"tx": "rollback"}}, func(tx *sql.Tx) (any, error) {
		return 4, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Fatalf("expected 0 after rollback, got %v", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestHandleTransactionBeginFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	plugin := &sqlitePlugin{db: db}
	mock.ExpectBegin().WillReturnError(errors.New("begin fail"))
	_, err = plugin.handleTransaction("u", nil, func(tx *sql.Tx) (any, error) {
		return 1, nil
	})
	if err == nil || !strings.Contains(err.Error(), "failed to begin tx") {
		t.Fatalf("expected begin failure, got %v", err)
	}
}

func TestHandleTransactionCommitFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	plugin := &sqlitePlugin{db: db}
	mock.ExpectBegin()
	mock.ExpectCommit().WillReturnError(errors.New("commit fail"))

	_, err = plugin.handleTransaction("u", nil, func(tx *sql.Tx) (any, error) {
		return 1, nil
	})
	if err == nil || !strings.Contains(err.Error(), "failed to commit") {
		t.Fatalf("expected commit failure, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}
