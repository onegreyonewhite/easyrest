// pg_plugin_test.go
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	pgxmock "github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestPlugin returns a pgPlugin and pgxmock.PgxPoolIface for testing with pgxpool
func newTestPlugin(t *testing.T) (*pgPlugin, pgxmock.PgxPoolIface) {
	// Use QueryMatcherEqual for exact SQL string matching by default
	mockPool, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherEqual))
	if err != nil {
		t.Fatalf("failed to open pgxmock pool: %s", err)
	}
	// Use mockPool which implements DBPool interface
	plugin := &pgPlugin{db: mockPool}
	return plugin, mockPool
}

func expectEmptyResponseHarvest(mock pgxmock.PgxPoolIface) {
	mock.ExpectQuery(harvestResponseSettingsSQL).
		WillReturnRows(pgxmock.NewRows([]string{"name", "nullif"}))
}

func expectContextRoutine(mock pgxmock.PgxPoolIface, name string) {
	mock.ExpectQuery("SELECT " + name + "()").
		WillReturnRows(pgxmock.NewRows([]string{"?column?"}))
}

func expectMissingContextRoutine(mock pgxmock.PgxPoolIface, name string) {
	mock.ExpectQuery("SELECT " + name + "()").
		WillReturnError(&pgconn.PgError{Code: "42883", Message: "function " + name + "() does not exist"})
}

func expectResponseHarvest(mock pgxmock.PgxPoolIface, settings map[string]string) {
	rows := pgxmock.NewRows([]string{"name", "nullif"})
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		rows.AddRow(k, settings[k])
	}
	mock.ExpectQuery(harvestResponseSettingsSQL).WillReturnRows(rows)
}

func TestConvertPlaceholders(t *testing.T) {
	query := "SELECT * FROM users WHERE id = ? AND status = ?"
	converted := convertPlaceholders(query)
	expected := "SELECT * FROM users WHERE id = $1 AND status = $2"
	if converted != expected {
		t.Errorf("expected %s, got %s", expected, converted)
	}
}

func TestTableGet(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	selectFields := []string{"id", "name"}
	where := map[string]any{
		"status": map[string]any{"=": "active"},
	}
	mock.ExpectBegin()
	// Expect exact SQL string without QuoteMeta or escapes
	mock.ExpectQuery(`SELECT id, name FROM users WHERE status = $1`).
		WithArgs("active").
		WillReturnRows(pgxmock.NewRows([]string{"id", "name"}).AddRow(1, "John Doe"))
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()
	result, outCtx, err := plugin.TableGet("user1", "users", selectFields, where, nil, nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("TableGet error: %s", err)
	}
	if outCtx != nil {
		t.Fatalf("empty harvest must return nil ctx, got %#v", outCtx)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 row, got %d", len(result))
	}
	if result[0]["name"] != "John Doe" {
		t.Errorf("expected 'John Doe', got %v", result[0]["name"])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations in TestTableGet: %s", err)
	}
}

func TestTableGetSelectFieldSubstitution(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	ctx := map[string]any{"claims_sub": "sub_value"}
	selectFields := []string{"id", "erctx.claims_sub"}
	where := map[string]any{}
	mock.ExpectBegin()
	// Expect exact SQL string
	mock.ExpectExec(`SELECT set_config($1, $2, true)`).
		WithArgs("request.claims_sub", "sub_value").
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	mock.ExpectExec(`SELECT set_config($1, $2, true)`).
		WithArgs("erctx.claims_sub", "sub_value").
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	// Expect exact SQL string
	mock.ExpectQuery(`SELECT id, erctx.claims_sub FROM users`).
		WithArgs().
		WillReturnRows(pgxmock.NewRows([]string{"id", "erctx.claims_sub"}).AddRow(10, "sub_value"))
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()
	result, _, err := plugin.TableGet("user1", "users", selectFields, where, nil, nil, 0, 0, ctx)
	if err != nil {
		t.Fatalf("TableGet error: %s", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 row, got %d", len(result))
	}
	if result[0]["erctx.claims_sub"] != "sub_value" {
		t.Errorf("expected 'sub_value', got %v", result[0]["erctx.claims_sub"])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations in TestTableGetSelectFieldSubstitution: %s", err)
	}
}

func TestTableGetTimeWithTimezone(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	utcTime := time.Date(2025, 3, 7, 15, 30, 0, 0, time.UTC)
	expectedTime := "2025-03-07 10:30:00"
	selectFields := []string{"id", "created_at"}
	where := map[string]any{"dummy": "val"}
	// Expect exact SQL string
	expQ := `SELECT id, created_at FROM dummy WHERE dummy = $1`
	rows := pgxmock.NewRows([]string{"id", "created_at"}).AddRow(1, utcTime)
	mock.ExpectBegin()
	// Expect exact SQL string
	mock.ExpectExec(`SELECT set_config($1, $2, true)`).
		WithArgs("request.timezone", "America/New_York").
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	mock.ExpectExec(`SELECT set_config($1, $2, true)`).
		WithArgs("erctx.timezone", "America/New_York").
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	mock.ExpectQuery(expQ).WithArgs("val").WillReturnRows(rows)
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()
	ctxData := map[string]any{
		"timezone": "America/New_York",
	}
	results, _, err := plugin.TableGet("u", "dummy", selectFields, where, nil, nil, 0, 0, ctxData)
	if err != nil {
		t.Fatalf("TableGet error: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 row, got %d", len(results))
	}
	if results[0]["created_at"] != expectedTime {
		t.Errorf("expected time %s, got %v", expectedTime, results[0]["created_at"])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations in TestTableGetTimeWithTimezone: %v", err)
	}
}

func TestTableCreate(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	plugin.bulkThreshold = 1000
	data := []map[string]any{
		{"id": 1, "name": "Test1"},
		{"id": 2, "name": "Test2"},
		{"id": 3, "name": "Test3"},
	}
	mock.ExpectBegin()
	// Expect exact SQL string
	mock.ExpectExec("INSERT INTO users (id, name) VALUES ($1,$2),($3,$4),($5,$6)").
		WithArgs(1, "Test1", 2, "Test2", 3, "Test3").
		WillReturnResult(pgxmock.NewResult("INSERT", 3))
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()

	result, _, err := plugin.TableCreate("test_user", "users", data, nil)
	if err != nil {
		t.Errorf("TableCreate error: %v", err)
	}
	if len(result) != len(data) {
		t.Errorf("Expected %d results, got %d", len(data), len(result))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestTableCreate_RejectsMaliciousColumn(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	plugin.bulkThreshold = 1000

	data := []map[string]any{
		{"name) VALUES ('boom'); --": "x"},
	}
	_, _, err := plugin.TableCreate("test_user", "users", data, nil)
	if err == nil {
		t.Fatal("expected error for malicious column name")
	}
	if !strings.Contains(err.Error(), "invalid column name") {
		t.Fatalf("expected invalid column name error, got: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestTableUpdate(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	data := map[string]any{"name": "Bob"}
	where := map[string]any{"id": map[string]any{"=": 1}}
	mock.ExpectBegin()
	// Expect exact SQL string
	mock.ExpectExec(`UPDATE users SET name = $1 WHERE id = $2`).
		WithArgs("Bob", 1).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()
	affected, _, err := plugin.TableUpdate("user1", "users", data, where, nil)
	if err != nil {
		t.Fatalf("TableUpdate error: %s", err)
	}
	if affected != 1 {
		t.Errorf("expected 1 affected row, got %d", affected)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations in TestTableUpdate: %s", err)
	}
}

func TestTableUpdate_RejectsMaliciousColumn(t *testing.T) {
	plugin, mock := newTestPlugin(t)

	data := map[string]any{"name = 'pwned', update_field": "x"}
	where := map[string]any{"id": map[string]any{"=": 1}}
	_, _, err := plugin.TableUpdate("user1", "users", data, where, nil)
	if err == nil {
		t.Fatal("expected error for malicious column name")
	}
	if !strings.Contains(err.Error(), "invalid column name") {
		t.Fatalf("expected invalid column name error, got: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestTableDelete(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	where := map[string]any{"status": map[string]any{"=": "inactive"}}
	mock.ExpectBegin()
	// Expect exact SQL string
	mock.ExpectExec(`DELETE FROM users WHERE status = $1`).
		WithArgs("inactive").
		WillReturnResult(pgxmock.NewResult("DELETE", 1))
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()
	affected, _, err := plugin.TableDelete("user1", "users", where, nil)
	if err != nil {
		t.Fatalf("TableDelete error: %s", err)
	}
	if affected != 1 {
		t.Errorf("expected 1 affected row, got %d", affected)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations in TestTableDelete: %s", err)
	}
}

func TestCallFunction(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	data := map[string]any{"param": "value"}
	funcName := "doSomething"
	expectedResult := "Processed: value"
	mock.ExpectBegin()
	// Expect exact SQL string
	query := fmt.Sprintf(`SELECT * FROM %s($1)`, funcName)
	rows := pgxmock.NewRows([]string{"doSomething"}).AddRow(expectedResult)
	mock.ExpectQuery(query).WithArgs("value").WillReturnRows(rows)
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()
	result, _, err := plugin.CallFunction("user1", funcName, data, nil)
	if err != nil {
		t.Fatalf("CallFunction error: %s", err)
	}

	resultStr, ok := result.(string)
	if !ok {
		t.Fatalf("Expected result to be a string, got %T", result)
	}

	if resultStr != expectedResult {
		t.Errorf("expected '%s', got '%v'", expectedResult, resultStr)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations in TestCallFunction: %s", err)
	}
}

func TestGetSchema(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	plugin.searchPath = "public" // Set default search path for test
	ctxData := map[string]any{"timezone": "UTC"}
	mock.ExpectBegin()
	// Expect exact SQL string
	mock.ExpectExec(`SELECT set_config($1, $2, true)`).
		WithArgs("request.timezone", "UTC").
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	mock.ExpectExec(`SELECT set_config($1, $2, true)`).
		WithArgs("erctx.timezone", "UTC").
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	// Base tables.
	tableRows := pgxmock.NewRows([]string{"table_name"}).AddRow("users").AddRow("orders")
	// Expect exact SQL string with parameterized schema
	mock.ExpectQuery(`SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_type = 'BASE TABLE'`).
		WithArgs("public").
		WillReturnRows(tableRows)
	// Columns for "users".
	userCols := pgxmock.NewRows([]string{"column_name", "data_type", "is_nullable", "column_default"}).
		AddRow("id", "integer", "NO", nil).
		AddRow("name", "character varying", "YES", nil)
	// Expect exact SQL string with parameterized schema
	mock.ExpectQuery(`SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2`).
		WithArgs("public", "users").
		WillReturnRows(userCols)
	// Columns for "orders".
	orderCols := pgxmock.NewRows([]string{"column_name", "data_type", "is_nullable", "column_default"}).
		AddRow("id", "integer", "NO", nil).
		AddRow("amount", "numeric", "YES", nil)
	// Expect exact SQL string with parameterized schema
	mock.ExpectQuery(`SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2`).
		WithArgs("public", "orders").
		WillReturnRows(orderCols)
	// Views.
	viewRows := pgxmock.NewRows([]string{"table_name"}).AddRow("myview")
	// Expect exact SQL string with parameterized schema
	mock.ExpectQuery(`SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_type = 'VIEW'`).
		WithArgs("public").
		WillReturnRows(viewRows)
	// Columns for view "myview".
	viewCols := pgxmock.NewRows([]string{"column_name", "data_type", "is_nullable", "column_default"}).
		AddRow("vcol", "text", "YES", nil)
	// Expect exact SQL string with parameterized schema
	mock.ExpectQuery(`SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2`).
		WithArgs("public", "myview").
		WillReturnRows(viewCols)
	// RPC functions.
	rpcRows := pgxmock.NewRows([]string{"routine_name", "specific_name", "data_type"}).
		AddRow("fnTest", "fnTest", "integer")
	// Expect exact SQL string with parameterized schema
	mock.ExpectQuery(`
	SELECT r.routine_name, r.specific_name, r.data_type
	FROM information_schema.routines r
	JOIN pg_catalog.pg_proc p ON r.routine_name = p.proname
	JOIN pg_catalog.pg_namespace n ON p.pronamespace = n.oid
	LEFT JOIN pg_catalog.pg_depend dep ON dep.objid = p.oid AND dep.classid = 'pg_catalog.pg_proc'::regclass AND dep.deptype = 'e'
	WHERE r.specific_schema = $1
	  AND n.nspname = $2 -- Ensure the schema matches in both catalogs
	  AND r.routine_type = 'FUNCTION'
	  AND dep.objid IS NULL -- Only include functions NOT dependent on an extension
	`).WithArgs("public", "public").WillReturnRows(rpcRows)
	paramRows := pgxmock.NewRows([]string{"parameter_name", "data_type", "parameter_mode", "ordinal_position"}).
		AddRow("x", "integer", "IN", 1)
	// Expect exact SQL string with parameterized schema
	mock.ExpectQuery(`SELECT parameter_name, data_type, parameter_mode, ordinal_position FROM information_schema.parameters WHERE specific_schema = $1 AND specific_name = $2 ORDER BY ordinal_position`).
		WithArgs("public", "fnTest").
		WillReturnRows(paramRows)
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()
	schema, _, err := plugin.GetSchema(ctxData)
	if err != nil {
		t.Fatalf("GetSchema error: %v", err)
	}
	js, _ := json.MarshalIndent(schema, "", "  ")
	if !strings.Contains(string(js), `"tables"`) {
		t.Errorf("expected 'tables' key, got: %s", js)
	}
	if !strings.Contains(string(js), `"views"`) {
		t.Errorf("expected 'views' key, got: %s", js)
	}
	if !strings.Contains(string(js), `"rpc"`) {
		t.Errorf("expected 'rpc' key, got: %s", js)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations in TestGetSchema: %v", err)
	}
}

func TestTableCreateWithBulkOperations(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	plugin.bulkThreshold = 2
	tests := []struct {
		name        string
		data        []map[string]any
		expectBulk  bool
		expectError bool
	}{
		{
			name: "Regular insert",
			data: []map[string]any{
				{"id": 1, "name": "Test1"},
			},
			expectBulk:  false,
			expectError: false,
		},
		{
			name: "Bulk insert",
			data: []map[string]any{
				{"id": 1, "name": "Test1"},
				{"id": 2, "name": "Test2"},
				{"id": 3, "name": "Test3"},
			},
			expectBulk:  true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock.ExpectBegin()

			if tt.expectBulk {
				// Expect CopyFrom for bulk operation
				mock.ExpectCopyFrom(pgx.Identifier{"test_table"}, []string{"id", "name"}).
					WillReturnResult(int64(len(tt.data)))
			} else {
				// Expect exact SQL string for regular insert
				mock.ExpectExec("INSERT INTO test_table (id, name) VALUES ($1,$2)").
					WithArgs(tt.data[0]["id"], tt.data[0]["name"]).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			}

			expectEmptyResponseHarvest(mock)
			mock.ExpectCommit()

			result, _, err := plugin.TableCreate("test_user", "test_table", tt.data, nil)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if len(result) != len(tt.data) {
				t.Errorf("Expected %d results, got %d", len(tt.data), len(result))
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestGetSchemaComprehensive(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	plugin.searchPath = "public" // Set default search path for test
	mock.ExpectBegin()
	// Expect exact SQL string
	mock.ExpectExec(`SELECT set_config($1, $2, true)`).WithArgs("request.user", "test_user").WillReturnResult(pgxmock.NewResult("SELECT", 1))
	mock.ExpectExec(`SELECT set_config($1, $2, true)`).WithArgs("erctx.user", "test_user").WillReturnResult(pgxmock.NewResult("SELECT", 1))
	// Mock tables query
	tableRows := pgxmock.NewRows([]string{"table_name"}).AddRow("users").AddRow("products")
	// Expect exact SQL string with parameterized schema
	mock.ExpectQuery(`SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_type = 'BASE TABLE'`).WithArgs("public").WillReturnRows(tableRows)
	// Mock columns query for users table
	userColumns := pgxmock.NewRows([]string{"column_name", "data_type", "is_nullable", "column_default"}).AddRow("id", "integer", "NO", nil).AddRow("name", "character varying", "NO", nil).AddRow("created_at", "timestamp", "YES", "CURRENT_TIMESTAMP")
	// Expect exact SQL string with parameterized schema
	mock.ExpectQuery(`SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2`).WithArgs("public", "users").WillReturnRows(userColumns)
	// Mock columns query for products table
	productColumns := pgxmock.NewRows([]string{"column_name", "data_type", "is_nullable", "column_default"}).AddRow("id", "integer", "NO", nil).AddRow("name", "character varying", "NO", nil).AddRow("price", "numeric", "NO", nil)
	// Expect exact SQL string with parameterized schema
	mock.ExpectQuery(`SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2`).WithArgs("public", "products").WillReturnRows(productColumns)
	// Mock views query
	viewRows := pgxmock.NewRows([]string{"table_name"}).AddRow("user_stats")
	// Expect exact SQL string with parameterized schema - Note: Adjusted regex slightly if it was .*VIEW
	mock.ExpectQuery(`SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_type = 'VIEW'`).WithArgs("public").WillReturnRows(viewRows)
	// Mock columns query for view
	viewColumns := pgxmock.NewRows([]string{"column_name", "data_type", "is_nullable", "column_default"}).AddRow("user_id", "integer", "YES", nil).AddRow("total_orders", "bigint", "YES", nil)
	// Expect exact SQL string with parameterized schema
	mock.ExpectQuery(`SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2`).WithArgs("public", "user_stats").WillReturnRows(viewColumns)
	// Mock functions query
	functionRows := pgxmock.NewRows([]string{"routine_name", "specific_name", "data_type"}).AddRow("calculate_total", "calculate_total_123", "numeric")
	// Expect exact SQL string with parameterized schema
	mock.ExpectQuery(`
	SELECT r.routine_name, r.specific_name, r.data_type
	FROM information_schema.routines r
	JOIN pg_catalog.pg_proc p ON r.routine_name = p.proname
	JOIN pg_catalog.pg_namespace n ON p.pronamespace = n.oid
	LEFT JOIN pg_catalog.pg_depend dep ON dep.objid = p.oid AND dep.classid = 'pg_catalog.pg_proc'::regclass AND dep.deptype = 'e'
	WHERE r.specific_schema = $1
	  AND n.nspname = $2 -- Ensure the schema matches in both catalogs
	  AND r.routine_type = 'FUNCTION'
	  AND dep.objid IS NULL -- Only include functions NOT dependent on an extension
	`).WithArgs("public", "public").WillReturnRows(functionRows)
	// Mock function parameters query
	paramRows := pgxmock.NewRows([]string{"parameter_name", "data_type", "parameter_mode", "ordinal_position"}).AddRow("user_id", "integer", "IN", 1).AddRow("start_date", "date", "IN", 2)
	// Expect exact SQL string with parameterized schema
	mock.ExpectQuery(`SELECT parameter_name, data_type, parameter_mode, ordinal_position FROM information_schema.parameters WHERE specific_schema = $1 AND specific_name = $2 ORDER BY ordinal_position`).WithArgs("public", "calculate_total_123").WillReturnRows(paramRows)
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()
	schema, _, err := plugin.GetSchema(map[string]any{"user": "test_user"})
	if err != nil {
		t.Fatalf("GetSchema failed: %v", err)
	}
	schemaMap, ok := schema.(map[string]any)
	if !ok {
		t.Fatal("Schema is not a map")
	}
	// Verify tables
	tables, ok := schemaMap["tables"].(map[string]any)
	if !ok {
		t.Fatal("Tables schema is not a map")
	}
	// Check users table
	usersSchema, ok := tables["users"].(map[string]any)
	if !ok {
		t.Fatal("Users table schema is not a map")
	}
	usersProps, ok := usersSchema["properties"].(map[string]any)
	if !ok {
		t.Fatal("Users properties is not a map")
	}
	if _, ok := usersProps["id"]; !ok {
		t.Error("Users schema missing id field")
	}
	// Check views
	views, ok := schemaMap["views"].(map[string]any)
	if !ok {
		t.Fatal("Views schema is not a map")
	}
	if _, ok := views["user_stats"]; !ok {
		t.Error("Views schema missing user_stats view")
	}
	// Check RPC
	rpc, ok := schemaMap["rpc"].(map[string]any)
	if !ok {
		t.Fatal("RPC schema is not a map")
	}
	if _, ok := rpc["calculate_total"]; !ok {
		t.Error("RPC schema missing calculate_total function")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestTableDeleteComprehensive(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	tests := []struct {
		name        string
		table       string
		where       map[string]any
		ctx         map[string]any
		affected    int64
		expectError bool
	}{
		{
			name:        "Simple delete",
			table:       "users",
			where:       map[string]any{"id": 1},
			ctx:         nil,
			affected:    1,
			expectError: false,
		},
		{
			name:        "Delete with context",
			table:       "orders",
			where:       map[string]any{"status": "pending"},
			ctx:         map[string]any{"user_id": 123},
			affected:    2,
			expectError: false,
		},
		{
			name:        "Delete all",
			table:       "temp_data",
			where:       map[string]any{},
			ctx:         nil,
			affected:    5,
			expectError: false,
		},
		{
			name:        "Delete with multiple conditions",
			table:       "products",
			where:       map[string]any{"category": "electronics", "price": 100},
			ctx:         nil,
			affected:    3,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock.ExpectBegin()

			if tt.ctx != nil {
				for k, v := range tt.ctx {
					// Expect exact SQL string
					mock.ExpectExec(`SELECT set_config($1, $2, true)`).
						WithArgs("request."+k, fmt.Sprintf("%v", v)).
						WillReturnResult(pgxmock.NewResult("SELECT", 1))
					mock.ExpectExec(`SELECT set_config($1, $2, true)`).
						WithArgs("erctx."+k, fmt.Sprintf("%v", v)).
						WillReturnResult(pgxmock.NewResult("SELECT", 1))
				}
			}

			whereClause, args, _ := easyrest.BuildWhereClauseSorted(tt.where)
			// Expect the final query *after* placeholder conversion
			expectedSQL := convertPlaceholders("DELETE FROM " + tt.table + whereClause)
			mock.ExpectExec(expectedSQL).WithArgs(args...).
				WillReturnResult(pgxmock.NewResult("DELETE", tt.affected))
			expectEmptyResponseHarvest(mock)
			mock.ExpectCommit()

			affected, _, err := plugin.TableDelete("test_user", tt.table, tt.where, tt.ctx)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if int64(affected) != tt.affected {
				t.Errorf("Expected %d affected rows, got %d", tt.affected, affected)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled expectations: %v", err)
			}
		})
	}
}

// newTestPluginWithCache creates a pgPlugin, pgCachePlugin, and pgxmock.PgxPoolIface for testing.
func newTestPluginWithCache(t *testing.T) (*pgPlugin, *pgCachePlugin, pgxmock.PgxPoolIface) {
	// Use QueryMatcherEqual for exact SQL string matching by default
	mockPool, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherEqual))
	if err != nil {
		t.Fatalf("failed to open pgxmock pool: %s", err)
	}
	plugin := &pgPlugin{db: mockPool}
	cachePlugin := &pgCachePlugin{dbPluginPointer: plugin}
	return plugin, cachePlugin, mockPool
}

func TestPgCachePluginInitConnection(t *testing.T) {
	plugin, cachePlugin, mock := newTestPluginWithCache(t)
	// Expect exact single-line SQL string
	expectedSQL := `CREATE TABLE IF NOT EXISTS easyrest_cache ( key TEXT PRIMARY KEY, value TEXT, expires_at TIMESTAMPTZ );`
	mock.ExpectExec(expectedSQL).
		WillReturnResult(pgxmock.NewResult("CREATE TABLE", 1))

	err := cachePlugin.InitConnection("postgres://user:pass@localhost:5432/db")
	if err != nil {
		t.Fatalf("cachePlugin.InitConnection failed: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations in TestPgCachePluginInitConnection: %s", err)
	}
	_ = plugin // Use plugin to avoid unused variable error if cache init uses it
}

func TestResolveLocationCacheBounded(t *testing.T) {
	plugin, _ := newTestPlugin(t)
	cache, err := lru.New[string, *time.Location](maxTimezoneCacheSize)
	if err != nil {
		t.Fatalf("failed to create timezone cache: %v", err)
	}
	plugin.timezoneCache = cache

	zones := []string{
		"America/New_York", "Europe/London", "Asia/Tokyo", "Australia/Sydney",
		"America/Los_Angeles", "Europe/Berlin", "Asia/Singapore", "Pacific/Auckland",
	}
	for i := 0; i < maxTimezoneCacheSize+10; i++ {
		tz := zones[i%len(zones)]
		plugin.resolveLocation(map[string]any{"timezone": tz})
	}
	if plugin.timezoneCache.Len() > maxTimezoneCacheSize {
		t.Fatalf("timezone cache exceeded max size: got %d want <= %d", plugin.timezoneCache.Len(), maxTimezoneCacheSize)
	}
}

func TestPgCachePluginCloseStopsCleanupGoroutine(t *testing.T) {
	plugin, cachePlugin, mock := newTestPluginWithCache(t)
	expectedSQL := `CREATE TABLE IF NOT EXISTS easyrest_cache ( key TEXT PRIMARY KEY, value TEXT, expires_at TIMESTAMPTZ );`
	mock.ExpectExec(expectedSQL).WillReturnResult(pgxmock.NewResult("CREATE TABLE", 1))

	if err := cachePlugin.InitConnection("postgres://user:pass@localhost:5432/db?autoCleanup=true"); err != nil {
		t.Fatalf("InitConnection failed: %v", err)
	}

	before := runtime.NumGoroutine()
	cachePlugin.Close()
	time.Sleep(50 * time.Millisecond)
	after := runtime.NumGoroutine()
	if after > before+2 {
		t.Fatalf("goroutine count increased after Close: before=%d after=%d", before, after)
	}
	_ = plugin
}

func TestPgCachePluginSetGet(t *testing.T) {
	_, cachePlugin, mock := newTestPluginWithCache(t)
	key := "testKey"
	value := "testValue"
	ttl := 5 * time.Minute

	// --- Test Set ---
	// Expect exact SQL string, use AnyArg for expires_at - corrected syntax
	expectedSetSQL := `INSERT INTO easyrest_cache (key, value, expires_at) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at;`
	mock.ExpectExec(expectedSetSQL).
		WithArgs(key, value, pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	err := cachePlugin.Set(key, value, ttl)
	if err != nil {
		t.Fatalf("cachePlugin.Set failed: %v", err)
	}

	// --- Test Get (successful) ---
	rows := pgxmock.NewRows([]string{"value"}).AddRow(value)
	// Expect exact SQL string
	mock.ExpectQuery(`SELECT value FROM easyrest_cache WHERE key = $1 AND expires_at > NOW()`).
		WithArgs(key).
		WillReturnRows(rows)

	retrievedValue, err := cachePlugin.Get(key)
	if err != nil {
		t.Fatalf("cachePlugin.Get failed: %v", err)
	}
	if retrievedValue != value {
		t.Errorf("expected value '%s', got '%s'", value, retrievedValue)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations in TestPgCachePluginSetGet (successful get): %s", err)
	}

	// --- Test Get (key not found) ---
	mock.ExpectQuery(`SELECT value FROM easyrest_cache WHERE key = $1 AND expires_at > NOW()`).
		WithArgs("nonExistentKey").
		WillReturnError(pgx.ErrNoRows)

	_, err = cachePlugin.Get("nonExistentKey")
	// Check against sql.ErrNoRows for broader compatibility
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("expected sql.ErrNoRows for non-existent key, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations after non-existent key check: %s", err)
	}
}

func TestPgCachePluginExpiration(t *testing.T) {
	_, cachePlugin, mock := newTestPluginWithCache(t)
	key := "expiredKey"

	// --- Test Get (key expired) ---
	mock.ExpectQuery(`SELECT value FROM easyrest_cache WHERE key = $1 AND expires_at > NOW()`).
		WithArgs(key).
		WillReturnError(pgx.ErrNoRows)

	_, err := cachePlugin.Get(key)
	// Check against sql.ErrNoRows for broader compatibility
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("expected sql.ErrNoRows for expired key, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations in TestPgCachePluginExpiration: %s", err)
	}
}

func TestParseConnectionParams_Defaults(t *testing.T) {
	uri := "postgres://user:pass@host:5432/db"
	dsn, maxConns, minConns, maxLifetime, maxIdleTime, timeout, bulkThreshold, autoCleanup, searchPath, _, err := parseConnectionParams(uri)

	require.NoError(t, err)
	assert.Equal(t, uri, dsn) // DSN should be unchanged as no params were removed
	assert.Equal(t, int32(100), maxConns)
	assert.Equal(t, int32(25), minConns)
	assert.Equal(t, 5*time.Minute, maxLifetime)
	assert.Equal(t, 10*time.Minute, maxIdleTime)
	assert.Equal(t, 30*time.Second, timeout)
	assert.Equal(t, 100, bulkThreshold)
	assert.Equal(t, "", autoCleanup)
	assert.Equal(t, "public", searchPath) // Default value
}

func TestParseConnectionParams_CustomValues(t *testing.T) {
	uri := "postgres://user:pass@host:5432/db?maxOpenConns=50&maxIdleConns=10&connMaxLifetime=15&connMaxIdleTime=20&timeout=60&bulkThreshold=500&autoCleanup=true"
	expectedDSN := "postgres://user:pass@host:5432/db" // Params should be removed
	dsn, maxConns, minConns, maxLifetime, maxIdleTime, timeout, bulkThreshold, autoCleanup, searchPath, _, err := parseConnectionParams(uri)

	require.NoError(t, err)
	assert.Equal(t, expectedDSN, dsn)
	assert.Equal(t, int32(50), maxConns)
	assert.Equal(t, int32(10), minConns)
	assert.Equal(t, 15*time.Minute, maxLifetime)
	assert.Equal(t, 20*time.Minute, maxIdleTime)
	assert.Equal(t, 60*time.Second, timeout)
	assert.Equal(t, 500, bulkThreshold)
	assert.Equal(t, "true", autoCleanup)
	assert.Equal(t, "public", searchPath) // Default value
}

func TestParseConnectionParams_OnlySomeValues(t *testing.T) {
	uri := "postgres://user:pass@host:5432/db?maxOpenConns=75&timeout=45"
	expectedDSN := "postgres://user:pass@host:5432/db"
	dsn, maxConns, minConns, maxLifetime, maxIdleTime, timeout, bulkThreshold, autoCleanup, searchPath, _, err := parseConnectionParams(uri)

	require.NoError(t, err)
	assert.Equal(t, expectedDSN, dsn)
	assert.Equal(t, int32(75), maxConns)         // Custom
	assert.Equal(t, int32(25), minConns)         // Default
	assert.Equal(t, 5*time.Minute, maxLifetime)  // Default
	assert.Equal(t, 10*time.Minute, maxIdleTime) // Default
	assert.Equal(t, 45*time.Second, timeout)     // Custom
	assert.Equal(t, 100, bulkThreshold)          // Default
	assert.Equal(t, "", autoCleanup)             // Default
	assert.Equal(t, "public", searchPath)        // Default
}

func TestParseConnectionParams_InvalidValues(t *testing.T) {
	testCases := []struct {
		name    string
		uri     string
		wantErr string
	}{
		{"invalid prefix", "http://host/db", "invalid postgres URI"},
		{"invalid maxOpenConns", "postgres://host/db?maxOpenConns=abc", "invalid maxOpenConns value: abc"},
		{"invalid maxIdleConns", "postgres://host/db?maxIdleConns=xyz", "invalid maxIdleConns value: xyz"},
		{"invalid connMaxLifetime", "postgres://host/db?connMaxLifetime=def", "invalid connMaxLifetime value: def"},
		{"invalid connMaxIdleTime", "postgres://host/db?connMaxIdleTime=ghi", "invalid connMaxIdleTime value: ghi"},
		{"invalid timeout", "postgres://host/db?timeout=jkl", "invalid timeout value: jkl"},
		{"invalid bulkThreshold", "postgres://host/db?bulkThreshold=mno", "invalid bulkThreshold value: mno"},
		{"invalid URL", "postgres://user:%%@host/db", "invalid URL escape"}, // Check url.Parse error
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, _, _, _, _, _, _, _, err := parseConnectionParams(tc.uri)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestParseConnectionParams_DSNEncoding(t *testing.T) {
	uri := "postgres://user%20name:p@ssw%2Frd@host:5432/db%20name?maxOpenConns=50&other=param"
	// Correct expected DSN with @ encoded as %40
	expectedDSN := "postgres://user%20name:p%40ssw%2Frd@host:5432/db%20name?other=param"
	dsn, _, _, _, _, _, _, _, _, _, err := parseConnectionParams(uri)
	require.NoError(t, err)
	assert.Equal(t, expectedDSN, dsn)
}

func TestDeleteExpiredCacheEntries(t *testing.T) {
	_, cachePlugin, mock := newTestPluginWithCache(t)

	// Expect the DELETE query to be executed
	mock.ExpectExec(`DELETE FROM easyrest_cache WHERE expires_at <= NOW()`).
		WillReturnResult(pgxmock.NewResult("DELETE", 5)) // Example: Expect 5 rows deleted

	// Call the synchronous cleanup function
	err := cachePlugin.deleteExpiredEntries(context.Background())

	// Assertions
	require.NoError(t, err)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations in TestDeleteExpiredCacheEntries: %s", err)
	}
}

func TestParseConnectionParams_CustomSearchPath(t *testing.T) {
	uri := "postgres://user:pass@host:5432/db?search_path=custom_schema&maxOpenConns=50"
	expectedDSN := "postgres://user:pass@host:5432/db?search_path=custom_schema" // Both search_path and maxOpenConns should be removed
	dsn, maxConns, minConns, maxLifetime, maxIdleTime, timeout, bulkThreshold, autoCleanup, searchPath, _, err := parseConnectionParams(uri)

	require.NoError(t, err)
	assert.Equal(t, expectedDSN, dsn)
	assert.Equal(t, int32(50), maxConns)         // Custom
	assert.Equal(t, int32(25), minConns)         // Default
	assert.Equal(t, 5*time.Minute, maxLifetime)  // Default
	assert.Equal(t, 10*time.Minute, maxIdleTime) // Default
	assert.Equal(t, 30*time.Second, timeout)     // Default
	assert.Equal(t, 100, bulkThreshold)          // Default
	assert.Equal(t, "", autoCleanup)             // Default
	assert.Equal(t, "custom_schema", searchPath) // Custom value
}

func TestGetSchemaWithCustomSearchPath(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	plugin.searchPath = "my_schema" // Set custom search path for test
	ctxData := map[string]any{"timezone": "UTC"}
	mock.ExpectBegin()
	// Expect exact SQL string
	mock.ExpectExec(`SELECT set_config($1, $2, true)`).
		WithArgs("request.timezone", "UTC").
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	mock.ExpectExec(`SELECT set_config($1, $2, true)`).
		WithArgs("erctx.timezone", "UTC").
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	// Base tables.
	tableRows := pgxmock.NewRows([]string{"table_name"}).AddRow("users").AddRow("orders")
	// Expect exact SQL string with custom schema
	mock.ExpectQuery(`SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_type = 'BASE TABLE'`).
		WithArgs("my_schema").
		WillReturnRows(tableRows)
	// Columns for "users".
	userCols := pgxmock.NewRows([]string{"column_name", "data_type", "is_nullable", "column_default"}).
		AddRow("id", "integer", "NO", nil).
		AddRow("name", "character varying", "YES", nil)
	// Expect exact SQL string with custom schema
	mock.ExpectQuery(`SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2`).
		WithArgs("my_schema", "users").
		WillReturnRows(userCols)
	// Columns for "orders".
	orderCols := pgxmock.NewRows([]string{"column_name", "data_type", "is_nullable", "column_default"}).
		AddRow("id", "integer", "NO", nil).
		AddRow("amount", "numeric", "YES", nil)
	// Expect exact SQL string with custom schema
	mock.ExpectQuery(`SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2`).
		WithArgs("my_schema", "orders").
		WillReturnRows(orderCols)
	// Views.
	viewRows := pgxmock.NewRows([]string{"table_name"}).AddRow("myview")
	// Expect exact SQL string with custom schema
	mock.ExpectQuery(`SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_type = 'VIEW'`).
		WithArgs("my_schema").
		WillReturnRows(viewRows)
	// Columns for view "myview".
	viewCols := pgxmock.NewRows([]string{"column_name", "data_type", "is_nullable", "column_default"}).
		AddRow("vcol", "text", "YES", nil)
	// Expect exact SQL string with custom schema
	mock.ExpectQuery(`SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2`).
		WithArgs("my_schema", "myview").
		WillReturnRows(viewCols)
	// RPC functions.
	rpcRows := pgxmock.NewRows([]string{"routine_name", "specific_name", "data_type"}).
		AddRow("fnTest", "fnTest", "integer")
	// Expect exact SQL string with custom schema
	mock.ExpectQuery(`
	SELECT r.routine_name, r.specific_name, r.data_type
	FROM information_schema.routines r
	JOIN pg_catalog.pg_proc p ON r.routine_name = p.proname
	JOIN pg_catalog.pg_namespace n ON p.pronamespace = n.oid
	LEFT JOIN pg_catalog.pg_depend dep ON dep.objid = p.oid AND dep.classid = 'pg_catalog.pg_proc'::regclass AND dep.deptype = 'e'
	WHERE r.specific_schema = $1
	  AND n.nspname = $2 -- Ensure the schema matches in both catalogs
	  AND r.routine_type = 'FUNCTION'
	  AND dep.objid IS NULL -- Only include functions NOT dependent on an extension
	`).WithArgs("my_schema", "my_schema").WillReturnRows(rpcRows)
	paramRows := pgxmock.NewRows([]string{"parameter_name", "data_type", "parameter_mode", "ordinal_position"}).
		AddRow("x", "integer", "IN", 1)
	// Expect exact SQL string with custom schema
	mock.ExpectQuery(`SELECT parameter_name, data_type, parameter_mode, ordinal_position FROM information_schema.parameters WHERE specific_schema = $1 AND specific_name = $2 ORDER BY ordinal_position`).
		WithArgs("my_schema", "fnTest").
		WillReturnRows(paramRows)
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()
	schema, _, err := plugin.GetSchema(ctxData)
	if err != nil {
		t.Fatalf("GetSchema error: %v", err)
	}
	js, _ := json.MarshalIndent(schema, "", "  ")
	if !strings.Contains(string(js), `"tables"`) {
		t.Errorf("expected 'tables' key, got: %s", js)
	}
	if !strings.Contains(string(js), `"views"`) {
		t.Errorf("expected 'views' key, got: %s", js)
	}
	if !strings.Contains(string(js), `"rpc"`) {
		t.Errorf("expected 'rpc' key, got: %s", js)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations in TestGetSchemaWithCustomSearchPath: %v", err)
	}
}

func TestNewPgQueryPlugin(t *testing.T) {
	p := NewPgQueryPlugin()
	require.NotNil(t, p)
	require.NotNil(t, p.dbPluginPointer)
}

func TestPgQueryCall(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	qp := &pgQueryPlugin{dbPluginPointer: plugin}

	t.Run("select rows", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec("SET TRANSACTION READ ONLY").
			WillReturnResult(pgxmock.NewResult("SET", 0))
		mock.ExpectQuery("SELECT id, name FROM users").
			WillReturnRows(pgxmock.NewRows([]string{"id", "name"}).AddRow(1, "Alice"))
		mock.ExpectCommit()

		rows, err := qp.QueryCall("SELECT id, name FROM users", nil)
		require.NoError(t, err)
		require.Len(t, rows, 1)
		assert.Equal(t, "Alice", rows[0]["name"])
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("with context", func(t *testing.T) {
		ctx := map[string]any{"claims_sub": "sub_value"}
		mock.ExpectBegin()
		mock.ExpectExec("SET TRANSACTION READ ONLY").
			WillReturnResult(pgxmock.NewResult("SET", 0))
		mock.ExpectExec(`SELECT set_config($1, $2, true)`).
			WithArgs("request.claims_sub", "sub_value").
			WillReturnResult(pgxmock.NewResult("SELECT", 1))
		mock.ExpectExec(`SELECT set_config($1, $2, true)`).
			WithArgs("erctx.claims_sub", "sub_value").
			WillReturnResult(pgxmock.NewResult("SELECT", 1))
		mock.ExpectQuery("SELECT id FROM users").
			WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))
		mock.ExpectCommit()

		rows, err := qp.QueryCall("SELECT id FROM users", ctx)
		require.NoError(t, err)
		require.Len(t, rows, 1)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty query", func(t *testing.T) {
		_, err := qp.QueryCall("  ", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("query error rolls back", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec("SET TRANSACTION READ ONLY").
			WillReturnResult(pgxmock.NewResult("SET", 0))
		mock.ExpectQuery("SELECT bad").
			WillReturnError(errors.New("syntax error"))
		mock.ExpectRollback()

		_, err := qp.QueryCall("SELECT bad", nil)
		require.Error(t, err)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestApplyPluginContext_TypeBranches(t *testing.T) {
	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer mock.Close()

	mock.ExpectBegin()
	tx, err := mock.Begin(context.Background())
	require.NoError(t, err)

	ctx := map[string]any{
		"s":     "hello",
		"i":     42,
		"i64":   int64(99),
		"f":     3.14,
		"b":     true,
		"obj":   map[string]any{"k": "v"},
		"arr":   []any{1, 2},
		"other": time.Second,
	}
	for range ctx {
		mock.ExpectExec("SELECT set_config($1, $2, true)").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("SELECT", 1))
		mock.ExpectExec("SELECT set_config($1, $2, true)").
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("SELECT", 1))
	}

	require.NoError(t, ApplyPluginContext(context.Background(), tx, ctx))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestApplyPluginContext_EmptyAndExecError(t *testing.T) {
	require.NoError(t, ApplyPluginContext(context.Background(), nil, nil))
	require.NoError(t, ApplyPluginContext(context.Background(), nil, map[string]any{}))

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer mock.Close()
	mock.ExpectBegin()
	tx, err := mock.Begin(context.Background())
	require.NoError(t, err)
	mock.ExpectExec("SELECT set_config($1, $2, true)").
		WithArgs("request.x", "y").
		WillReturnError(fmt.Errorf("boom"))
	err = ApplyPluginContext(context.Background(), tx, map[string]any{"x": "y"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request.x")
}

func TestNewPgCachePlugin(t *testing.T) {
	p := NewPgCachePlugin()
	require.NotNil(t, p)
	require.NotNil(t, p.dbPluginPointer)
	p.Close()
}

func TestPgQueryPluginCloseNilSafe(t *testing.T) {
	p := NewPgQueryPlugin()
	p.Close()
}

func TestHarvestSQL_FiltersRequestAndErctx(t *testing.T) {
	if !strings.Contains(harvestResponseSettingsSQL, "LIKE 'response.%'") {
		t.Fatal("harvest SQL must filter response.% names")
	}
	if !strings.Contains(harvestResponseSettingsSQL, "response.headers") || !strings.Contains(harvestResponseSettingsSQL, "response.status") {
		t.Fatal("harvest SQL must union known PostgREST keys")
	}
	if !strings.Contains(harvestResponseSettingsSQL, "cache.invalidate") {
		t.Fatal("harvest SQL must union cache.invalidate")
	}
	if strings.Contains(harvestResponseSettingsSQL, "request.") || strings.Contains(harvestResponseSettingsSQL, "erctx.") {
		t.Fatal("harvest SQL must not read request./erctx. settings")
	}
}

func TestTableGet_HarvestHeadersAndStatus(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	ctx := map[string]any{"claims": map[string]any{"sub": "u1"}}
	claimsJSON, err := json.Marshal(ctx["claims"])
	require.NoError(t, err)

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config($1, $2, true)`).
		WithArgs("request.claims", string(claimsJSON)).
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	mock.ExpectExec(`SELECT set_config($1, $2, true)`).
		WithArgs("erctx.claims", string(claimsJSON)).
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	mock.ExpectQuery(`SELECT id FROM users`).
		WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))
	expectResponseHarvest(mock, map[string]string{
		"response.headers": `[{"X-From-Sql":"1"}]`,
		"response.status":  "418",
	})
	mock.ExpectCommit()

	_, outCtx, err := plugin.TableGet("user1", "users", []string{"id"}, nil, nil, nil, 0, 0, ctx)
	require.NoError(t, err)
	require.NotNil(t, outCtx)
	assert.Equal(t, `[{"X-From-Sql":"1"}]`, outCtx["response.headers"])
	assert.Equal(t, "418", outCtx["response.status"])
	assert.Equal(t, ctx["claims"], outCtx["claims"])
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTableGet_HarvestCacheInvalidate(t *testing.T) {
	plugin, mock := newTestPlugin(t)

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM users`).
		WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))
	expectResponseHarvest(mock, map[string]string{
		easyrest.CtxCacheInvalidate: "users,orders",
	})
	mock.ExpectCommit()

	_, outCtx, err := plugin.TableGet("user1", "users", []string{"id"}, nil, nil, nil, 0, 0, nil)
	require.NoError(t, err)
	require.NotNil(t, outCtx)
	assert.Equal(t, "users,orders", outCtx[easyrest.CtxCacheInvalidate])
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTableUpdate_HarvestBeforeRollbackPrefer(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	preferJSON, err := json.Marshal(map[string]any{"tx": "rollback"})
	require.NoError(t, err)
	ctx := map[string]any{"prefer": map[string]any{"tx": "rollback"}}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config($1, $2, true)`).
		WithArgs("request.prefer", string(preferJSON)).
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	mock.ExpectExec(`SELECT set_config($1, $2, true)`).
		WithArgs("erctx.prefer", string(preferJSON)).
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	mock.ExpectExec(`UPDATE users SET name = $1 WHERE id = $2`).
		WithArgs("Bob", 1).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	expectResponseHarvest(mock, map[string]string{"response.headers": `[{"X-From-Sql":"1"}]`})
	mock.ExpectRollback()

	affected, outCtx, err := plugin.TableUpdate("user1", "users", map[string]any{"name": "Bob"}, map[string]any{"id": map[string]any{"=": 1}}, ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, affected)
	require.NotNil(t, outCtx)
	assert.Equal(t, `[{"X-From-Sql":"1"}]`, outCtx["response.headers"])
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCallFunction_HarvestStatus(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT * FROM teapot()`).
		WillReturnRows(pgxmock.NewRows([]string{"teapot"}).AddRow("ok"))
	expectResponseHarvest(mock, map[string]string{"response.status": "418"})
	mock.ExpectCommit()

	result, outCtx, err := plugin.CallFunction("user1", "teapot", nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "ok", result)
	require.NotNil(t, outCtx)
	assert.Equal(t, "418", outCtx["response.status"])
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTableCreate_HarvestHeaders(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	plugin.bulkThreshold = 1000
	data := []map[string]any{{"id": 1, "name": "Test1"}}
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO users (id, name) VALUES ($1,$2)").
		WithArgs(1, "Test1").
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	expectResponseHarvest(mock, map[string]string{"response.headers": `[{"X-Inserted":"1"}]`})
	mock.ExpectCommit()

	_, outCtx, err := plugin.TableCreate("test_user", "users", data, nil)
	require.NoError(t, err)
	require.NotNil(t, outCtx)
	assert.Equal(t, `[{"X-Inserted":"1"}]`, outCtx["response.headers"])
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTableGet_HarvestQueryError(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM users`).
		WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))
	mock.ExpectQuery(harvestResponseSettingsSQL).
		WillReturnError(errors.New("harvest failed"))
	mock.ExpectRollback()

	_, _, err := plugin.TableGet("user1", "users", []string{"id"}, nil, nil, nil, 0, 0, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "harvest")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestBulkCreate_HarvestAndApplyContext(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	plugin.bulkThreshold = 2
	ctx := map[string]any{"claims": "token"}
	data := []map[string]any{
		{"id": 1, "name": "Test1"},
		{"id": 2, "name": "Test2"},
	}
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config($1, $2, true)`).
		WithArgs("request.claims", "token").
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	mock.ExpectExec(`SELECT set_config($1, $2, true)`).
		WithArgs("erctx.claims", "token").
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	mock.ExpectCopyFrom(pgx.Identifier{"test_table"}, []string{"id", "name"}).
		WillReturnResult(2)
	expectResponseHarvest(mock, map[string]string{"response.headers": `[{"X-Bulk":"1"}]`})
	mock.ExpectCommit()

	_, outCtx, err := plugin.TableCreate("test_user", "test_table", data, ctx)
	require.NoError(t, err)
	require.NotNil(t, outCtx)
	assert.Equal(t, `[{"X-Bulk":"1"}]`, outCtx["response.headers"])
	assert.Equal(t, "token", outCtx["claims"])
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestApplyPluginContext_SkipsHookKeys(t *testing.T) {
	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer mock.Close()
	mock.ExpectBegin()
	tx, err := mock.Begin(context.Background())
	require.NoError(t, err)
	mock.ExpectExec("SELECT set_config($1, $2, true)").
		WithArgs("request.timezone", "UTC").
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	mock.ExpectExec("SELECT set_config($1, $2, true)").
		WithArgs("erctx.timezone", "UTC").
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	require.NoError(t, ApplyPluginContext(context.Background(), tx, map[string]any{
		"timezone":                "UTC",
		easyrest.CtxDBPreRequest:  "custom_headers",
		easyrest.CtxDBPostRequest: "after_hook",
	}))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTableGet_ContextHooksOrder(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	ctx := map[string]any{
		easyrest.CtxDBPreRequest:  "pre_hook",
		easyrest.CtxDBPostRequest: "post_hook",
	}
	mock.ExpectBegin()
	expectContextRoutine(mock, "pre_hook")
	mock.ExpectQuery(`SELECT id FROM users`).
		WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))
	expectContextRoutine(mock, "post_hook")
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()

	_, outCtx, err := plugin.TableGet("user1", "users", []string{"id"}, nil, nil, nil, 0, 0, ctx)
	require.NoError(t, err)
	if outCtx != nil {
		t.Fatalf("empty harvest: %#v", outCtx)
	}
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTableGet_MissingPreHookSkipped(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	ctx := map[string]any{easyrest.CtxDBPreRequest: "missing_pre"}
	mock.ExpectBegin()
	expectMissingContextRoutine(mock, "missing_pre")
	mock.ExpectQuery(`SELECT id FROM users`).
		WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()

	_, _, err := plugin.TableGet("user1", "users", []string{"id"}, nil, nil, nil, 0, 0, ctx)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTableGet_MissingPostHookSkipped(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	ctx := map[string]any{easyrest.CtxDBPostRequest: "missing_post"}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM users`).
		WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))
	expectMissingContextRoutine(mock, "missing_post")
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()

	_, _, err := plugin.TableGet("user1", "users", []string{"id"}, nil, nil, nil, 0, 0, ctx)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTableGet_PreHookRaiseRollsBack(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	ctx := map[string]any{easyrest.CtxDBPreRequest: "pre_hook"}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT pre_hook()`).
		WillReturnError(&pgconn.PgError{Code: "P0001", Message: "blocked"})
	mock.ExpectRollback()

	_, _, err := plugin.TableGet("user1", "users", []string{"id"}, nil, nil, nil, 0, 0, ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db.pre-request")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTableCreate_ContextPreHook(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	plugin.bulkThreshold = 1000
	ctx := map[string]any{easyrest.CtxDBPreRequest: "pre_hook"}
	mock.ExpectBegin()
	expectContextRoutine(mock, "pre_hook")
	mock.ExpectExec("INSERT INTO users (id, name) VALUES ($1,$2)").
		WithArgs(1, "Test1").
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()

	_, _, err := plugin.TableCreate("test_user", "users", []map[string]any{{"id": 1, "name": "Test1"}}, ctx)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTableUpdate_ContextPostHook(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	ctx := map[string]any{easyrest.CtxDBPostRequest: "post_hook"}
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE users SET name = $1 WHERE id = $2`).
		WithArgs("Bob", 1).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	expectContextRoutine(mock, "post_hook")
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()

	_, _, err := plugin.TableUpdate("user1", "users", map[string]any{"name": "Bob"}, map[string]any{"id": map[string]any{"=": 1}}, ctx)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCallFunction_ContextPostHook(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	ctx := map[string]any{easyrest.CtxDBPostRequest: "post_hook"}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT * FROM teapot()`).
		WillReturnRows(pgxmock.NewRows([]string{"teapot"}).AddRow("ok"))
	expectContextRoutine(mock, "post_hook")
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()

	_, _, err := plugin.CallFunction("user1", "teapot", nil, ctx)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestBulkCreate_ContextHooks(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	plugin.bulkThreshold = 2
	ctx := map[string]any{
		"claims":                  "token",
		easyrest.CtxDBPreRequest:  "pre_hook",
		easyrest.CtxDBPostRequest: "post_hook",
	}
	data := []map[string]any{
		{"id": 1, "name": "Test1"},
		{"id": 2, "name": "Test2"},
	}
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config($1, $2, true)`).
		WithArgs("request.claims", "token").
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	mock.ExpectExec(`SELECT set_config($1, $2, true)`).
		WithArgs("erctx.claims", "token").
		WillReturnResult(pgxmock.NewResult("SELECT", 1))
	expectContextRoutine(mock, "pre_hook")
	mock.ExpectCopyFrom(pgx.Identifier{"test_table"}, []string{"id", "name"}).
		WillReturnResult(2)
	expectContextRoutine(mock, "post_hook")
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()

	_, _, err := plugin.TableCreate("test_user", "test_table", data, ctx)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTableGetGroupBy(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id, name FROM users GROUP BY name ORDER BY id LIMIT 10 OFFSET 5`).
		WillReturnRows(pgxmock.NewRows([]string{"id", "name"}).AddRow(1, "A").AddRow([]byte("2"), time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)))
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()

	result, _, err := plugin.TableGet("user1", "users", []string{"id", "name"}, nil, []string{"id"}, []string{"name"}, 10, 5, nil)
	require.NoError(t, err)
	require.Len(t, result, 2)
	require.Equal(t, "2", result[1]["id"])
	require.Equal(t, "2024-01-02", result[1]["name"])
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCallFunctionJSONBytesAndEmpty(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT * FROM fn($1)`).
		WithArgs("x").
		WillReturnRows(pgxmock.NewRows([]string{"fn"}).AddRow([]byte(`{"ok":true}`)))
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()

	result, _, err := plugin.CallFunction("u", "fn", map[string]any{"a": "x"}, nil)
	require.NoError(t, err)
	asMap, ok := result.(map[string]any)
	require.True(t, ok)
	require.Equal(t, true, asMap["ok"])
	require.NoError(t, mock.ExpectationsWereMet())

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT * FROM emptyfn()`).
		WillReturnRows(pgxmock.NewRows([]string{"emptyfn"}))
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()
	result, _, err = plugin.CallFunction("u", "emptyfn", nil, nil)
	require.NoError(t, err)
	require.Nil(t, result)
	require.NoError(t, mock.ExpectationsWereMet())

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT * FROM setof()`).
		WillReturnRows(pgxmock.NewRows([]string{"id", "name"}).AddRow(1, "a").AddRow(2, "b"))
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit()
	result, _, err = plugin.CallFunction("u", "setof", nil, nil)
	require.NoError(t, err)
	rows, ok := result.([]map[string]any)
	require.True(t, ok)
	require.Len(t, rows, 2)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetSchemaViewsFailure(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	plugin.searchPath = "public"
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_type = 'BASE TABLE'`).
		WithArgs("public").
		WillReturnRows(pgxmock.NewRows([]string{"table_name"}))
	mock.ExpectQuery(`SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_type = 'VIEW'`).
		WithArgs("public").
		WillReturnError(errors.New("views failed"))
	mock.ExpectRollback()

	_, _, err := plugin.GetSchema(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "views failed")
}

func TestResolveLocationFallback(t *testing.T) {
	plugin, _ := newTestPlugin(t)
	if plugin.resolveLocation(nil) != time.UTC {
		t.Fatal("nil ctx")
	}
	if plugin.resolveLocation(map[string]any{"timezone": "Not/AZone"}) != time.UTC {
		t.Fatal("invalid tz")
	}
	if plugin.resolveLocation(map[string]any{"timezone": ""}) != time.UTC {
		t.Fatal("empty tz")
	}
}

func TestPgPluginClose(t *testing.T) {
	plugin, _ := newTestPlugin(t)
	cache, err := lru.New[string, *time.Location](4)
	require.NoError(t, err)
	plugin.timezoneCache = cache
	plugin.Close()
	if plugin.db != nil || plugin.timezoneCache != nil {
		t.Fatal("expected close to clear pool pointer and timezone cache")
	}
	plugin.Close()
}

func TestGetSchemaErrorPaths(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	plugin.searchPath = "public"
	mock.ExpectBegin().WillReturnError(errors.New("begin fail"))
	_, _, err := plugin.GetSchema(nil)
	require.Error(t, err)

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_type = 'BASE TABLE'`).
		WithArgs("public").
		WillReturnError(errors.New("tables fail"))
	mock.ExpectRollback()
	_, _, err = plugin.GetSchema(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "tables fail")

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_type = 'BASE TABLE'`).
		WithArgs("public").
		WillReturnRows(pgxmock.NewRows([]string{"table_name"}))
	mock.ExpectQuery(`SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_type = 'VIEW'`).
		WithArgs("public").
		WillReturnRows(pgxmock.NewRows([]string{"table_name"}))
	mock.ExpectQuery(`
	SELECT r.routine_name, r.specific_name, r.data_type
	FROM information_schema.routines r
	JOIN pg_catalog.pg_proc p ON r.routine_name = p.proname
	JOIN pg_catalog.pg_namespace n ON p.pronamespace = n.oid
	LEFT JOIN pg_catalog.pg_depend dep ON dep.objid = p.oid AND dep.classid = 'pg_catalog.pg_proc'::regclass AND dep.deptype = 'e'
	WHERE r.specific_schema = $1
	  AND n.nspname = $2 -- Ensure the schema matches in both catalogs
	  AND r.routine_type = 'FUNCTION'
	  AND dep.objid IS NULL -- Only include functions NOT dependent on an extension
	`).WithArgs("public", "public").WillReturnError(errors.New("rpc fail"))
	mock.ExpectRollback()
	_, _, err = plugin.GetSchema(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rpc fail")
}

func TestCallFunctionInvalidPrefer(t *testing.T) {
	plugin, _ := newTestPlugin(t)
	_, _, err := plugin.CallFunction("u", "fn", nil, map[string]any{"prefer": map[string]any{"tx": "nope"}})
	require.Error(t, err)
}

func TestWithTxErrorPaths(t *testing.T) {
	plugin, mock := newTestPlugin(t)
	mock.ExpectBegin().WillReturnError(errors.New("begin fail"))
	_, err := plugin.withTx(context.Background(), nil, "commit", func(tx pgx.Tx, loc *time.Location) error {
		return nil
	})
	require.Error(t, err)

	mock.ExpectBegin()
	mock.ExpectRollback()
	_, err = plugin.withTx(context.Background(), nil, "commit", func(tx pgx.Tx, loc *time.Location) error {
		return errors.New("fn fail")
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "fn fail")

	mock.ExpectBegin()
	expectEmptyResponseHarvest(mock)
	mock.ExpectRollback()
	_, err = plugin.withTx(context.Background(), nil, "rollback", func(tx pgx.Tx, loc *time.Location) error {
		return nil
	})
	require.NoError(t, err)

	mock.ExpectBegin()
	expectEmptyResponseHarvest(mock)
	mock.ExpectCommit().WillReturnError(errors.New("commit fail"))
	_, err = plugin.withTx(context.Background(), nil, "commit", func(tx pgx.Tx, loc *time.Location) error {
		return nil
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to commit")

	mock.ExpectBegin()
	mock.ExpectQuery(harvestResponseSettingsSQL).WillReturnError(errors.New("harvest fail"))
	_, err = plugin.withTx(context.Background(), nil, "commit", func(tx pgx.Tx, loc *time.Location) error {
		return nil
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "harvest")
}

func TestPgCachePluginSetGetNoDB(t *testing.T) {
	cachePlugin := &pgCachePlugin{dbPluginPointer: &pgPlugin{}}
	if err := cachePlugin.Set("k", "v", time.Minute); err == nil {
		t.Fatal("expected set without db to fail")
	}
	if _, err := cachePlugin.Get("k"); err == nil {
		t.Fatal("expected get without db to fail")
	}
}

func TestDeleteExpiredCacheEntriesError(t *testing.T) {
	_, cachePlugin, mock := newTestPluginWithCache(t)
	mock.ExpectExec(`DELETE FROM easyrest_cache WHERE expires_at <= NOW()`).
		WillReturnError(errors.New("cleanup boom"))
	err := cachePlugin.deleteExpiredEntries(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "cleanup boom")
}
