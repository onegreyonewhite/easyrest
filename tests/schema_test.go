package tests

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/onegreyonewhite/easyrest/internal/config"
	"github.com/onegreyonewhite/easyrest/internal/server"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

// fakeDBPluginWithRPC is a fake implementation of DBPlugin for testing GetSchema with RPC.
type fakeDBPluginWithRPC struct{}

func (f *fakeDBPluginWithRPC) InitConnection(uri string) error { return nil }
func (f *fakeDBPluginWithRPC) TableGet(userID, table string, selectFields []string, where map[string]any,
	ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, error) {
	return nil, nil
}
func (f *fakeDBPluginWithRPC) TableCreate(userID, table string, data []map[string]any, ctx map[string]any) ([]map[string]any, error) {
	return nil, nil
}
func (f *fakeDBPluginWithRPC) TableUpdate(userID, table string, data map[string]any, where map[string]any, ctx map[string]any) (int, error) {
	return 0, nil
}
func (f *fakeDBPluginWithRPC) TableDelete(userID, table string, where map[string]any, ctx map[string]any) (int, error) {
	return 0, nil
}
func (f *fakeDBPluginWithRPC) CallFunction(userID, funcName string, data map[string]any, ctx map[string]any) (any, error) {
	return nil, nil
}
func (f *fakeDBPluginWithRPC) GetSchema(ctx map[string]any) (any, error) {
	// Return a fake schema with separate tables and views, plus an RPC.
	return map[string]any{
		"tables": map[string]any{
			"myTable": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":     "integer",
						"readOnly": true,
					},
					"name": map[string]any{
						"type": "string",
					},
				},
				"required": []any{"name"},
			},
		},
		"views": map[string]any{
			"myView": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"code": map[string]any{
						"type": "string",
					},
					"description": map[string]any{
						"type": "string",
					},
				},
				"required": []any{"code"},
			},
		},
		"rpc": map[string]any{
			"myFunc": []any{
				// Request schema
				map[string]any{
					"type": "object",
					"properties": map[string]any{
						"param": map[string]any{
							"type": "string",
						},
					},
					"required": []any{"param"},
				},
				// Response schema
				map[string]any{
					"type": "object",
					"properties": map[string]any{
						"result": map[string]any{
							"type": "string",
						},
					},
				},
			},
		},
	}, nil
}

// setupTestDBForSchema creates a test DB and a "test" table with various field types.
func setupTestDBForSchema(t *testing.T) string {
	dbPath := setupTestDB(t)

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open in-memory DB: %v", err)
	}
	// Create a table with various types:
	schemaSQL := `
	CREATE TABLE test (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		age INTEGER,
		email TEXT DEFAULT 'unknown'
	);`
	_, err = db.Exec(schemaSQL)
	if err != nil {
		t.Fatalf("Failed to create test table: %v", err)
	}
	db.Close()
	return dbPath
}

func TestSwaggerSchema(t *testing.T) {
	dbPath := setupTestDBForSchema(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	// Set environment variables for the plugin.
	os.Setenv("ER_DB_TEST", "sqlite://"+dbPath)
	os.Setenv("ER_TOKEN_SECRET", "mytestsecret")
	os.Setenv("ER_TOKEN_USER_SEARCH", "sub")
	os.Setenv("ER_TOKEN_AUTHURL", "http://auth.example.com/token")
	os.Setenv("ER_CHECK_SCOPE", "0")
	os.Setenv("ER_NO_PLUGIN_LOG", "1")

	// Use SetupRouter to obtain the router.
	server.ReloadConfig()
	router := server.SetupRouter()

	// Create a request to /api/test/
	req, err := http.NewRequest("GET", "/api/test/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	// Since swagger does not require authorization, a token is not needed.
	rr := httptest.NewRecorder()
	// Ensure that the {db} variable is properly recognized by mux.
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d, body: %s", rr.Code, rr.Body.String())
	}
	var swaggerSpec map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &swaggerSpec); err != nil {
		t.Fatalf("Failed to unmarshal swagger spec: %v", err)
	}
	// Check for the presence of the main keys.
	requiredKeys := []string{"swagger", "info", "host", "basePath", "consumes", "produces", "definitions", "paths", "securityDefinitions"}
	for _, key := range requiredKeys {
		if _, ok := swaggerSpec[key]; !ok {
			t.Errorf("Swagger spec missing key: %s", key)
		}
	}
	// Check that definitions contains the "test" model.
	definitions, ok := swaggerSpec["definitions"].(map[string]any)
	if !ok {
		t.Fatalf("definitions is not a map")
	}
	if _, ok := definitions["test"]; !ok {
		t.Errorf("Expected definitions to contain 'test'")
	}
	// Check that paths contains the "/test/" path.
	paths, ok := swaggerSpec["paths"].(map[string]any)
	if !ok {
		t.Fatalf("paths is not a map")
	}
	if _, ok := paths["/test/"]; !ok {
		t.Errorf("Expected paths to contain '/test/'")
	}
	// Check that securityDefinitions contains oauth2 with the expected tokenUrl.
	secDefs, ok := swaggerSpec["securityDefinitions"].(map[string]any)
	if !ok {
		t.Fatalf("securityDefinitions is not a map")
	}
	oauth2, ok := secDefs["jwt"].(map[string]any)
	if !ok {
		t.Fatalf("securityDefinitions missing 'oauth2'")
	}
	if tokenUrl, ok := oauth2["tokenUrl"].(string); !ok || tokenUrl != "http://auth.example.com/token" {
		t.Errorf("Expected oauth2.tokenUrl to be 'http://auth.example.com/token', got '%v'", oauth2["tokenUrl"])
	}
	// Verify that the GET operation for the /test/ path includes the required query parameters: select, limit, offset.
	getOp, ok := paths["/test/"].(map[string]any)["get"].(map[string]any)
	if !ok {
		t.Fatalf("Missing GET operation for path /test/")
	}
	params, ok := getOp["parameters"].([]any)
	if !ok {
		t.Fatalf("GET parameters is not an array")
	}
	requiredParams := []string{"select", "limit", "offset"}
	for _, rp := range requiredParams {
		found := false
		for _, p := range params {
			param, ok := p.(map[string]any)
			if ok {
				if name, ok := param["name"].(string); ok && name == rp {
					found = true
					break
				}
			}
		}
		if !found {
			t.Errorf("GET operation missing required parameter: %s", rp)
		}
	}
	// Additionally, verify that for each field in the model, only applicable 'where' parameters are created.
	// For the "test" model with fields: id (integer), name (string), age (integer), email (string).
	for _, field := range []string{"id", "name", "age", "email"} {
		for op := range server.AllowedOps {
			// Determine expected operators.
			// For string fields ("name", "email"), skip lt, lte, gt, gte.
			skip := false
			if field == "name" || field == "email" {
				if op == "lt" || op == "lte" || op == "gt" || op == "gte" {
					skip = true
				}
			}
			// For numeric fields ("id", "age"), skip like and ilike.
			if field == "id" || field == "age" {
				if op == "like" || op == "ilike" {
					skip = true
				}
			}
			paramName := "where." + op + "." + field
			found := false
			for _, p := range params {
				param, ok := p.(map[string]any)
				if ok {
					if name, ok := param["name"].(string); ok && name == paramName {
						found = true
						break
					}
				}
			}
			if skip {
				if found {
					t.Errorf("GET operation should not contain where parameter: %s", paramName)
				}
			} else {
				if !found {
					t.Errorf("GET operation missing where parameter: %s", paramName)
				}
			}
		}
	}
}

func TestSwaggerSchemaWithRPC(t *testing.T) {
	// Unset ER_DB_TEST to avoid LoadPlugins overriding our fake plugin.
	os.Unsetenv("ER_DB_TEST")
	defer server.StopPlugins()
	// Set the fake plugin for database "test".
	mockPluginInstance1 := &fakeDBPluginWithRPC{}
	newPluginsMap1 := map[string]easyrest.DBPlugin{"mock": mockPluginInstance1}
	server.DbPlugins.Store(&newPluginsMap1)

	// Create a fake HTTP request to /api/test/
	req, err := http.NewRequest("GET", "/api/mock/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	rr := httptest.NewRecorder()
	server.ReloadConfig()
	server.LoadPlugins()

	router := server.SetupRouter()

	mockPluginInstance2 := &fakeDBPluginWithRPC{}
	newPluginsMap2 := map[string]easyrest.DBPlugin{"mock": mockPluginInstance2}
	server.DbPlugins.Store(&newPluginsMap2)
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d, body: %s", rr.Code, rr.Body.String())
	}
	var swaggerSpec map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &swaggerSpec); err != nil {
		t.Fatalf("Failed to unmarshal swagger spec: %v", err)
	}

	// Check that definitions contain both "myTable" and "myView".
	definitions, ok := swaggerSpec["definitions"].(map[string]any)
	if !ok {
		t.Fatalf("definitions is not a map")
	}
	if _, ok := definitions["myTable"]; !ok {
		t.Errorf("Expected definitions to contain 'myTable'")
	}
	if _, ok := definitions["myView"]; !ok {
		t.Errorf("Expected definitions to contain 'myView'")
	}
	// Check that paths contain both "/myTable/", "/myView/" and "/rpc/myFunc/".
	paths, ok := swaggerSpec["paths"].(map[string]any)
	if !ok {
		t.Fatalf("paths is not a map")
	}
	if _, ok := paths["/myTable/"]; !ok {
		t.Errorf("Expected paths to contain '/myTable/'")
	}
	if _, ok := paths["/myView/"]; !ok {
		t.Errorf("Expected paths to contain '/myView/'")
	}
	if _, ok := paths["/rpc/myFunc/"]; !ok {
		t.Errorf("Expected paths to contain '/rpc/myFunc/'")
	}
}

// fakeDBPluginWithAllowList is a fake implementation for testing AllowList in schema.
type fakeDBPluginWithAllowList struct{}

func (f *fakeDBPluginWithAllowList) InitConnection(uri string) error { return nil }
func (f *fakeDBPluginWithAllowList) TableGet(userID, table string, selectFields []string, where map[string]any,
	ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, error) {
	return nil, nil
}
func (f *fakeDBPluginWithAllowList) TableCreate(userID, table string, data []map[string]any, ctx map[string]any) ([]map[string]any, error) {
	return nil, nil
}
func (f *fakeDBPluginWithAllowList) TableUpdate(userID, table string, data map[string]any, where map[string]any, ctx map[string]any) (int, error) {
	return 0, nil
}
func (f *fakeDBPluginWithAllowList) TableDelete(userID, table string, where map[string]any, ctx map[string]any) (int, error) {
	return 0, nil
}
func (f *fakeDBPluginWithAllowList) CallFunction(userID, funcName string, data map[string]any, ctx map[string]any) (any, error) {
	return nil, nil
}
func (f *fakeDBPluginWithAllowList) GetSchema(ctx map[string]any) (any, error) {
	// Return a fake schema with tables, views, and RPCs.
	return map[string]any{
		"tables": map[string]any{
			"allowed_table":  map[string]any{"type": "object", "properties": map[string]any{"id": map[string]any{"type": "integer"}}},  // Allowed
			"other_table":    map[string]any{"type": "object", "properties": map[string]any{"name": map[string]any{"type": "string"}}}, // Not in allow list
			"excluded_table": map[string]any{"type": "object", "properties": map[string]any{"data": map[string]any{"type": "string"}}}, // Excluded
		},
		"views": map[string]any{
			"allowed_view": map[string]any{"type": "object", "properties": map[string]any{"code": map[string]any{"type": "string"}}}, // Allowed
			"other_view":   map[string]any{"type": "object", "properties": map[string]any{"desc": map[string]any{"type": "string"}}}, // Not in allow list
		},
		"rpc": map[string]any{
			"allowed_func":  []any{map[string]any{"type": "object"}, map[string]any{"type": "object"}}, // Allowed
			"other_func":    []any{map[string]any{"type": "object"}, map[string]any{"type": "object"}}, // Not in allow list
			"excluded_func": []any{map[string]any{"type": "object"}, map[string]any{"type": "object"}}, // Excluded
		},
	}, nil
}

func TestSwaggerSchemaWithAllowList(t *testing.T) {
	os.Unsetenv("ER_DB_TEST")
	defer server.StopPlugins()

	mockPlugin := &fakeDBPluginWithAllowList{}
	newPluginsMap := map[string]easyrest.DBPlugin{"mockallow": mockPlugin}
	server.DbPlugins.Store(&newPluginsMap)

	server.ReloadConfig()
	cfg := server.GetConfig()
	cfg.PluginMap["mockallow"] = config.PluginConfig{
		Name: "mockallow",
		AllowList: config.AccessConfig{
			Table: []string{"allowed_table", "allowed_view"},
			Func:  []string{"allowed_func"},
		},
		Exclude: config.AccessConfig{
			Table: []string{"excluded_table"},
			Func:  []string{"excluded_func"},
		},
	}
	server.SetConfig(cfg)
	router := server.SetupRouter()

	newPluginsMap = map[string]easyrest.DBPlugin{"mockallow": mockPlugin}
	server.DbPlugins.Store(&newPluginsMap)

	req, err := http.NewRequest("GET", "/api/mockallow/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d, body: %s", rr.Code, rr.Body.String())
	}

	var swaggerSpec map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &swaggerSpec); err != nil {
		t.Fatalf("Failed to unmarshal swagger spec: %v", err)
	}

	definitions, ok := swaggerSpec["definitions"].(map[string]any)
	if !ok {
		t.Fatalf("definitions is not a map")
	}
	paths, ok := swaggerSpec["paths"].(map[string]any)
	if !ok {
		t.Fatalf("paths is not a map")
	}

	// Check definitions
	if _, ok := definitions["allowed_table"]; !ok {
		t.Errorf("Expected definitions to contain 'allowed_table'")
	}
	if _, ok := definitions["allowed_view"]; !ok {
		t.Errorf("Expected definitions to contain 'allowed_view'")
	}
	if _, ok := definitions["other_table"]; ok {
		t.Errorf("Expected definitions to NOT contain 'other_table'")
	}
	if _, ok := definitions["other_view"]; ok {
		t.Errorf("Expected definitions to NOT contain 'other_view'")
	}
	if _, ok := definitions["excluded_table"]; ok {
		t.Errorf("Expected definitions to NOT contain 'excluded_table'")
	}

	// Check paths
	if _, ok := paths["/allowed_table/"]; !ok {
		t.Errorf("Expected paths to contain '/allowed_table/'")
	}
	if _, ok := paths["/allowed_view/"]; !ok {
		t.Errorf("Expected paths to contain '/allowed_view/'")
	}
	if _, ok := paths["/other_table/"]; ok {
		t.Errorf("Expected paths to NOT contain '/other_table/'")
	}
	if _, ok := paths["/other_view/"]; ok {
		t.Errorf("Expected paths to NOT contain '/other_view/'")
	}
	if _, ok := paths["/excluded_table/"]; ok {
		t.Errorf("Expected paths to NOT contain '/excluded_table/'")
	}

	// Check RPC paths
	if _, ok := paths["/rpc/allowed_func/"]; !ok {
		t.Errorf("Expected paths to contain '/rpc/allowed_func/'")
	}
	if _, ok := paths["/rpc/other_func/"]; ok {
		t.Errorf("Expected paths to NOT contain '/rpc/other_func/'")
	}
	if _, ok := paths["/rpc/excluded_func/"]; ok {
		t.Errorf("Expected paths to NOT contain '/rpc/excluded_func/'")
	}
}
