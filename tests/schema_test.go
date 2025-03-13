package tests

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/onegreyonewhite/easyrest/internal/server"
)

// fakeDBPluginWithRPC is a fake implementation of DBPlugin for testing GetSchema with RPC.
type fakeDBPluginWithRPC struct{}

func (f *fakeDBPluginWithRPC) InitConnection(uri string) error { return nil }
func (f *fakeDBPluginWithRPC) TableGet(userID, table string, selectFields []string, where map[string]interface{},
	ordering []string, groupBy []string, limit, offset int, ctx map[string]interface{}) ([]map[string]interface{}, error) {
	return nil, nil
}
func (f *fakeDBPluginWithRPC) TableCreate(userID, table string, data []map[string]interface{}, ctx map[string]interface{}) ([]map[string]interface{}, error) {
	return nil, nil
}
func (f *fakeDBPluginWithRPC) TableUpdate(userID, table string, data map[string]interface{}, where map[string]interface{}, ctx map[string]interface{}) (int, error) {
	return 0, nil
}
func (f *fakeDBPluginWithRPC) TableDelete(userID, table string, where map[string]interface{}, ctx map[string]interface{}) (int, error) {
	return 0, nil
}
func (f *fakeDBPluginWithRPC) CallFunction(userID, funcName string, data map[string]interface{}, ctx map[string]interface{}) (interface{}, error) {
	return nil, nil
}
func (f *fakeDBPluginWithRPC) GetSchema(ctx map[string]interface{}) (interface{}, error) {
	// Return a fake schema with separate tables and views, plus an RPC.
	return map[string]interface{}{
		"tables": map[string]interface{}{
			"myTable": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type":     "integer",
						"readOnly": true,
					},
					"name": map[string]interface{}{
						"type": "string",
					},
				},
				"required": []interface{}{"name"},
			},
		},
		"views": map[string]interface{}{
			"myView": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"code": map[string]interface{}{
						"type": "string",
					},
					"description": map[string]interface{}{
						"type": "string",
					},
				},
				"required": []interface{}{"code"},
			},
		},
		"rpc": map[string]interface{}{
			"myFunc": []interface{}{
				// Request schema
				map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"param": map[string]interface{}{
							"type": "string",
						},
					},
					"required": []interface{}{"param"},
				},
				// Response schema
				map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"result": map[string]interface{}{
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

	db, err := sql.Open("sqlite3", dbPath)
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

	// Set environment variables for the plugin.
	os.Setenv("ER_DB_TEST", "sqlite://"+dbPath)
	os.Setenv("ER_TOKEN_SECRET", "mytestsecret")
	os.Setenv("ER_TOKEN_USER_SEARCH", "sub")
	os.Setenv("ER_TOKEN_AUTHURL", "http://auth.example.com/token")
	os.Setenv("ER_CHECK_SCOPE", "0")
	os.Setenv("ER_NO_PLUGIN_LOG", "1")

	// Use SetupRouter to obtain the router.
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
	var swaggerSpec map[string]interface{}
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
	definitions, ok := swaggerSpec["definitions"].(map[string]interface{})
	if !ok {
		t.Fatalf("definitions is not a map")
	}
	if _, ok := definitions["test"]; !ok {
		t.Errorf("Expected definitions to contain 'test'")
	}
	// Check that paths contains the "/test/" path.
	paths, ok := swaggerSpec["paths"].(map[string]interface{})
	if !ok {
		t.Fatalf("paths is not a map")
	}
	if _, ok := paths["/test/"]; !ok {
		t.Errorf("Expected paths to contain '/test/'")
	}
	// Check that securityDefinitions contains oauth2 with the expected tokenUrl.
	secDefs, ok := swaggerSpec["securityDefinitions"].(map[string]interface{})
	if !ok {
		t.Fatalf("securityDefinitions is not a map")
	}
	oauth2, ok := secDefs["jwtToken"].(map[string]interface{})
	if !ok {
		t.Fatalf("securityDefinitions missing 'oauth2'")
	}
	if tokenUrl, ok := oauth2["tokenUrl"].(string); !ok || tokenUrl != "http://auth.example.com/token" {
		t.Errorf("Expected oauth2.tokenUrl to be 'http://auth.example.com/token', got '%v'", oauth2["tokenUrl"])
	}
	// Verify that the GET operation for the /test/ path includes the required query parameters: select, limit, offset.
	getOp, ok := paths["/test/"].(map[string]interface{})["get"].(map[string]interface{})
	if !ok {
		t.Fatalf("Missing GET operation for path /test/")
	}
	params, ok := getOp["parameters"].([]interface{})
	if !ok {
		t.Fatalf("GET parameters is not an array")
	}
	requiredParams := []string{"select", "limit", "offset"}
	for _, rp := range requiredParams {
		found := false
		for _, p := range params {
			param, ok := p.(map[string]interface{})
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
				param, ok := p.(map[string]interface{})
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
	// Unset ER_DB_TEST to avoid LoadDBPlugins overriding our fake plugin.
	os.Unsetenv("ER_DB_TEST")
	// Set the fake plugin for database "test".
	server.DbPlugins["mock"] = &fakeDBPluginWithRPC{}

	// Create a fake HTTP request to /api/test/
	req, err := http.NewRequest("GET", "/api/mock/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	rr := httptest.NewRecorder()
	router := server.SetupRouter()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d, body: %s", rr.Code, rr.Body.String())
	}
	var swaggerSpec map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &swaggerSpec); err != nil {
		t.Fatalf("Failed to unmarshal swagger spec: %v", err)
	}

	// Check that definitions contain both "myTable" and "myView".
	definitions, ok := swaggerSpec["definitions"].(map[string]interface{})
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
	paths, ok := swaggerSpec["paths"].(map[string]interface{})
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
