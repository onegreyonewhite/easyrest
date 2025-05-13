package tests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/onegreyonewhite/easyrest/internal/config"
	"github.com/onegreyonewhite/easyrest/internal/server"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	sqlitePlugin "github.com/onegreyonewhite/easyrest/plugins/sqlite"
	_ "modernc.org/sqlite"
)

func TestSelectBasic(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	// Insert a single user.
	insertUser(t, dbPath, "Alice", "")
	os.Setenv("ER_CACHE_TEST", "sqlite://"+dbPath)
	os.Setenv("ER_CACHE_ENABLE_TEST", "1")
	os.Setenv("ER_CORS_ENABLED", "1")

	router := setupServerWithDB(t, dbPath)
	cfg := server.GetConfig()
	cfg.PluginMap["test"] = config.PluginConfig{
		Name:        "test",
		Uri:         "sqlite://" + dbPath,
		EnableCache: true,
		DbTxEnd:     "commit-allow-override",
	}
	cfg.CORS.Enabled = true
	server.SetConfig(cfg)
	server.PreservedDbPlugins["sqlite"] = func() easyrest.DBPlugin {
		return sqlitePlugin.NewSqlitePlugin()
	}
	server.PreservedCachePlugins["sqlite"] = func() easyrest.CachePlugin {
		return sqlitePlugin.NewSqliteCachePlugin()
	}
	server.LoadPlugins()
	tokenStr := generateToken(t)
	req, err := http.NewRequest("GET", "/api/test/users/?select=id,name", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("If-None-Match", "0000")
	req.Header.Set("Prefer", "tx=rollback")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Response: %s", rr.Code, rr.Body.String())
	}
	var result []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("Error parsing response: %v. Response: %s", err, rr.Body.String())
	}
	if len(result) != 1 {
		t.Fatalf("Expected 1 row, got %d", len(result))
	}
	if result[0]["name"] != "Alice" {
		t.Errorf("Expected name 'Alice', got %v", result[0]["name"])
	}
	// Assert that ETag header is present
	etag := rr.Header().Get("ETag")
	if etag == "" {
		t.Errorf("Expected ETag header to be set, but it was empty. Headers: %v", rr.Header())
	}
	prefer := rr.Header().Get("Preference-Applied")
	if prefer != fmt.Sprintf("tx=rollback timezone=%s", cfg.DefaultTimezone) {
		t.Errorf("Expected Preference-Applied header to be '%s', got %s", fmt.Sprintf("tx=rollback timezone=%s", cfg.DefaultTimezone), prefer)
	}

	req, err = http.NewRequest("GET", "/api/test/users/?select=id,name", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("If-None-Match", etag)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotModified {
		t.Fatalf("Expected status 304, got %d. Response: %s", rr.Code, rr.Body.String())
	}
}

func TestSelectWhereLike(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	// Insert several users.
	insertUser(t, dbPath, "Alice", "")
	insertUser(t, dbPath, "Alex", "")
	insertUser(t, dbPath, "Bob", "")
	insertUser(t, dbPath, "Alicia", "")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)
	// Note: To correctly pass the "%" character in the URL, it must be URL-encoded.
	req, err := http.NewRequest("GET", "/api/test/users/?select=id,name&where.like.name=Al%25", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Response: %s", rr.Code, rr.Body.String())
	}
	var result []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("Error parsing response: %v. Response: %s", err, rr.Body.String())
	}
	// Expect only users whose names start with "Al" – "Alice", "Alex", "Alicia"
	if len(result) != 3 {
		t.Fatalf("Expected 3 rows, got %d", len(result))
	}
	for _, row := range result {
		name, ok := row["name"].(string)
		if !ok || !strings.HasPrefix(name, "Al") {
			t.Errorf("Expected name starting with 'Al', got %v", row["name"])
		}
	}
}

func TestSelectWhereLt(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	// Insert two users.
	id1 := insertUser(t, dbPath, "Alice", "")
	id2 := insertUser(t, dbPath, "Bob", "")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)
	// Request: select where id < id2 (expect only the user with id1).
	req, err := http.NewRequest("GET", "/api/test/users/?select=id,name&where.lt.id="+strconv.Itoa(id2), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Response: %s", rr.Code, rr.Body.String())
	}
	var result []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("Error parsing response: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("Expected 1 row, got %d", len(result))
	}
	if int(result[0]["id"].(float64)) != id1 {
		t.Errorf("Expected id %d, got %v", id1, result[0]["id"])
	}
}

func TestSelectMultipleWhere(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	// Insert several users.
	id1 := insertUser(t, dbPath, "Alice", "")
	id2 := insertUser(t, dbPath, "Alex", "")
	_ = insertUser(t, dbPath, "Bob", "")
	_ = insertUser(t, dbPath, "Alicia", "")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)
	// Request with two conditions: name LIKE "Al%" and id < id2
	req, err := http.NewRequest("GET", "/api/test/users/?select=id,name&where.like.name=Al%25&where.lt.id="+strconv.Itoa(id2), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Response: %s", rr.Code, rr.Body.String())
	}
	var result []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("Error parsing response: %v", err)
	}
	// Expect that the condition id < id2 filters out "Alex" (if id1 < id2), leaving only "Alice"
	if len(result) != 1 {
		t.Fatalf("Expected 1 row, got %d", len(result))
	}
	if int(result[0]["id"].(float64)) != id1 {
		t.Errorf("Expected id %d, got %v", id1, result[0]["id"])
	}
}

func TestSelectInvalidOperator(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	insertUser(t, dbPath, "Alice", "")
	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)
	// Use an invalid operator "unknown"
	req, err := http.NewRequest("GET", "/api/test/users/?select=id,name&where.unknown.name=Alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	// Expect status 400 for invalid where key format.
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Expected status 400 for invalid operator, got %d. Response: %s", rr.Code, rr.Body.String())
	}
}

func TestSelectAllOperators(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()
	// Insert test data with different cases
	_ = insertUser(t, dbPath, "Alice", "test1")
	id2 := insertUser(t, dbPath, "ALICE2", "test2")
	_ = insertUser(t, dbPath, "Charlie", "test3")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	// Tests for each operator
	tests := []struct {
		name     string
		query    string
		expected int
	}{
		{"eq", "/api/test/users/?where.eq.name=Alice", 1},
		{"neq", "/api/test/users/?where.neq.name=Alice", 2},
		{"lt", "/api/test/users/?where.lt.id=" + strconv.Itoa(id2), 1},
		{"lte", "/api/test/users/?where.lte.id=" + strconv.Itoa(id2), 2},
		{"gt", "/api/test/users/?where.gt.id=" + strconv.Itoa(id2), 1},
		{"gte", "/api/test/users/?where.gte.id=" + strconv.Itoa(id2), 2},
		{"like", "/api/test/users/?where.like.name=Alice", 1},
		{"ilike", "/api/test/users/?where.ilike.name=alice", 1},
		{"is", "/api/test/users/?where.is.update_field=test1", 1},
		{"in", "/api/test/users/?where.in.name=Alice,ALICE2", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", tt.query, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+tokenStr)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("Expected status 200, got %d. Response: %s", rr.Code, rr.Body.String())
			}
			var result []map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
				t.Fatalf("Error parsing response: %v", err)
			}
			if len(result) != tt.expected {
				t.Errorf("Expected %d rows, got %d for query %s", tt.expected, len(result), tt.query)
			}
		})
	}
}

func TestContextSubstitution(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()
	// Insert test data
	insertUser(t, dbPath, "testuser", "test1")   // Name must match sub in claims
	insertUser(t, dbPath, "test_value", "test2") // Name must match custom in claims

	router := setupServerWithDB(t, dbPath)

	// Create token with additional claims
	claims := jwt.MapClaims{
		"sub":    "testuser",
		"exp":    time.Now().Add(time.Hour).Unix(),
		"scope":  "users-read users-write",
		"custom": "test_value",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte("mytestsecret"))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Tests for context value substitution
	tests := []struct {
		name     string
		query    string
		expected int
	}{
		{"select_context", "/api/test/users/?select=request.claims.sub", 2},
		{"where_context", "/api/test/users/?where.eq.name=request.claims.custom", 1},
		{"nested_context", "/api/test/users/?where.eq.name=request.claims.sub", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", tt.query, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+tokenStr)
			req.Header.Set("Prefer", "timezone=UTC")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("Expected status 200, got %d. Response: %s", rr.Code, rr.Body.String())
			}
			var result []map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
				t.Fatalf("Error parsing response: %v", err)
			}
			if len(result) != tt.expected {
				t.Errorf("Expected %d rows, got %d", tt.expected, len(result))
			}
		})
	}
}

func TestSelectResponseFormats(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()
	// Insert test data.
	insertUser(t, dbPath, "Alice", "")
	insertUser(t, dbPath, "Bob", "")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	// Test CSV response using Accept header.
	reqCSV, err := http.NewRequest("GET", "/api/test/users/?select=id,name", nil)
	if err != nil {
		t.Fatal(err)
	}
	reqCSV.Header.Set("Authorization", "Bearer "+tokenStr)
	reqCSV.Header.Set("Accept", "text/csv")
	rrCSV := httptest.NewRecorder()
	router.ServeHTTP(rrCSV, reqCSV)
	if rrCSV.Code != http.StatusOK {
		t.Fatalf("Expected status 200 for CSV, got %d. Response: %s", rrCSV.Code, rrCSV.Body.String())
	}
	contentTypeCSV := rrCSV.Result().Header.Get("Content-Type")
	if !strings.Contains(contentTypeCSV, "text/csv") {
		t.Errorf("Expected Content-Type to include 'text/csv', got %s", contentTypeCSV)
	}
	csvOutput := rrCSV.Body.String()
	if !strings.Contains(csvOutput, "id") || !strings.Contains(csvOutput, "name") {
		t.Errorf("CSV output does not contain expected headers. Output: %s", csvOutput)
	}

	// Test XML response using Accept header.
	reqXML, err := http.NewRequest("GET", "/api/test/users/?select=id,name", nil)
	if err != nil {
		t.Fatal(err)
	}
	reqXML.Header.Set("Authorization", "Bearer "+tokenStr)
	reqXML.Header.Set("Accept", "application/xml")
	rrXML := httptest.NewRecorder()
	router.ServeHTTP(rrXML, reqXML)
	if rrXML.Code != http.StatusOK {
		t.Fatalf("Expected status 200 for XML, got %d. Response: %s", rrXML.Code, rrXML.Body.String())
	}
	contentTypeXML := rrXML.Result().Header.Get("Content-Type")
	if !strings.Contains(contentTypeXML, "application/xml") {
		t.Errorf("Expected Content-Type to include 'application/xml', got %s", contentTypeXML)
	}
	xmlOutput := rrXML.Body.String()
	if !strings.Contains(xmlOutput, "<?xml") {
		t.Errorf("Expected XML output to contain the XML declaration. Output: %s", xmlOutput)
	}
	if !strings.Contains(xmlOutput, "<items>") && !strings.Contains(xmlOutput, "<item>") {
		t.Errorf("Expected XML output to contain <items> or <item> tags. Output: %s", xmlOutput)
	}
}

func TestAnonymousScopeAccess(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	// Create two tables: product and users
	db := openDB(t, dbPath)
	_, err := db.Exec(`CREATE TABLE product (id INTEGER PRIMARY KEY, name TEXT);`)
	if err != nil {
		t.Fatalf("Failed to create product table: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE hidden_users (id INTEGER PRIMARY KEY, name TEXT);`)
	if err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}
	_, err = db.Exec(`INSERT INTO product (name) VALUES ('Widget'), ('Gadget');`)
	if err != nil {
		t.Fatalf("Failed to insert into product: %v", err)
	}
	_, err = db.Exec(`INSERT INTO users (name) VALUES ('Alice'), ('Bob');`)
	if err != nil {
		t.Fatalf("Failed to insert into users: %v", err)
	}
	db.Close()

	os.Setenv("ER_CACHE_TEST", "sqlite://"+dbPath)
	os.Setenv("ER_CACHE_ENABLE_TEST", "1")
	os.Setenv("ER_CORS_ENABLED", "1")
	os.Setenv("ER_ANON_CLAIMS", `{"scope": "product-read"}`)

	router := setupServerWithDB(t, dbPath)
	cfg := server.GetConfig()
	cfg.PluginMap["test"] = config.PluginConfig{
		Name:        "test",
		Uri:         "sqlite://" + dbPath,
		EnableCache: true,
		DbTxEnd:     "commit-allow-override",
		Exclude: config.AccessConfig{
			Table: []string{"hidden_users"},
		},
	}
	cfg.CORS.Enabled = true
	cfg.CheckScope = true
	server.SetConfig(cfg)
	server.LoadPlugins()

	// Anonymous request to product table (should succeed)
	req, err := http.NewRequest("GET", "/api/test/product/?select=id,name", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200 for anonymous product access, got %d. Response: %s", rr.Code, rr.Body.String())
	}
	var products []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &products); err != nil {
		t.Fatalf("Error parsing product response: %v. Response: %s", err, rr.Body.String())
	}
	if len(products) != 2 {
		t.Fatalf("Expected 2 products, got %d", len(products))
	}

	// Anonymous request to users table (should fail with 403 or 401)
	req, err = http.NewRequest("GET", "/api/test/users/?select=id,name", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden && rr.Code != http.StatusUnauthorized {
		t.Fatalf("Expected status 403 or 401 for anonymous users access, got %d. Response: %s", rr.Code, rr.Body.String())
	}

	// Anonymous request to hidden_users table (should fail with 403 or 401)
	req, err = http.NewRequest("GET", "/api/test/hidden_users/?select=id,name", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("Expected status 404 for hidden users access, got %d. Response: %s", rr.Code, rr.Body.String())
	}
}

func TestSelectRangeHeaders(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	// Insert multiple users for pagination
	insertUser(t, dbPath, "Alice", "")
	insertUser(t, dbPath, "Bob", "")
	insertUser(t, dbPath, "Charlie", "")
	insertUser(t, dbPath, "Diana", "")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	tests := []struct {
		name          string
		rangeUnit     string
		rangeHeader   string
		wantStatus    int
		wantStart     int
		wantEnd       int
		wantLen       int
		wantBodyEmpty bool
	}{
		{"first_two", "items", "0-1", http.StatusOK, 0, 1, 2, false},
		{"middle", "items", "1-2", http.StatusOK, 1, 2, 2, false},
		{"last_one", "items", "3-3", http.StatusOK, 3, 3, 1, false},
		{"all", "items", "0-3", http.StatusOK, 0, 3, 4, false},
		{"out_of_range", "items", "10-15", http.StatusRequestedRangeNotSatisfiable, 15, 15, 0, true},
		{"invalid_header_fallback", "items", "bad-header", http.StatusOK, 0, 3, 4, false},
		{"no_header_fallback", "", "", http.StatusOK, 0, 3, 4, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/api/test/users/?select=id,name", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+tokenStr)
			if tt.rangeUnit != "" {
				req.Header.Set("Range-Unit", tt.rangeUnit)
			}
			if tt.rangeHeader != "" {
				req.Header.Set("Range", tt.rangeHeader)
			}
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != tt.wantStatus {
				t.Fatalf("Expected status %d, got %d. Response: %s", tt.wantStatus, rr.Code, rr.Body.String())
			}
			contentRange := rr.Header().Get("Content-Range")
			if !strings.HasPrefix(contentRange, fmt.Sprintf("%d-%d/", tt.wantStart, tt.wantEnd)) {
				t.Errorf("Content-Range header = %q, want prefix %d-%d/", contentRange, tt.wantStart, tt.wantEnd)
			}
			rangeUnit := rr.Header().Get("Range-Unit")
			if rangeUnit != "items" {
				t.Errorf("Range-Unit header = %q, want 'items'", rangeUnit)
			}
			acceptRanges := rr.Header().Get("Accept-Ranges")
			if acceptRanges != "items" {
				t.Errorf("Accept-Ranges header = %q, want 'items'", acceptRanges)
			}
			if !tt.wantBodyEmpty {
				var result []map[string]any
				if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
					t.Fatalf("Error parsing response: %v. Response: %s", err, rr.Body.String())
				}
				if len(result) != tt.wantLen {
					t.Errorf("Expected %d rows, got %d", tt.wantLen, len(result))
				}
			} else {
				if len(rr.Body.Bytes()) > 0 && strings.TrimSpace(rr.Body.String()) != "[]" {
					t.Errorf("Expected empty body, got: %q", rr.Body.String())
				}
			}
		})
	}
}

func TestSelectWhereNotEq(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	// Insert several users.
	insertUser(t, dbPath, "Alice", "")
	insertUser(t, dbPath, "Bob", "")
	insertUser(t, dbPath, "Charlie", "")

	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)
	// Query for all users except Alice
	req, err := http.NewRequest("GET", "/api/test/users/?select=id,name&where.not.eq.name=Alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Response: %s", rr.Code, rr.Body.String())
	}
	var result []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("Error parsing response: %v. Response: %s", err, rr.Body.String())
	}
	if len(result) != 2 {
		t.Fatalf("Expected 2 rows (not Alice), got %d", len(result))
	}
	for _, row := range result {
		if row["name"] == "Alice" {
			t.Errorf("Expected no row with name 'Alice', but got one: %v", row)
		}
	}
}

func TestSelectAllowList(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()

	// Create tables: users (allowed), products (not allowed), orders (excluded)
	db := openDB(t, dbPath)
	_, err := db.Exec(`CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT);`)
	if err != nil {
		t.Fatalf("Failed to create products table: %v", err)
	}
	_, err = db.Exec(`INSERT INTO products (name) VALUES ('Laptop');`)
	if err != nil {
		t.Fatalf("Failed to insert into products: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE orders (id INTEGER PRIMARY KEY, item TEXT);`)
	if err != nil {
		t.Fatalf("Failed to create orders table: %v", err)
	}
	_, err = db.Exec(`INSERT INTO orders (item) VALUES ('Keyboard');`)
	if err != nil {
		t.Fatalf("Failed to insert into orders: %v", err)
	}
	_, err = db.Exec(`INSERT INTO users (name) VALUES ('Alice');`)
	if err != nil {
		t.Fatalf("Failed to insert into users: %v", err)
	}
	db.Close()

	os.Setenv("ER_CACHE_TEST", "sqlite://"+dbPath)
	os.Setenv("ER_CACHE_ENABLE_TEST", "1")
	os.Setenv("ER_CORS_ENABLED", "1")

	router := setupServerWithDB(t, dbPath)
	cfg := server.GetConfig()
	cfg.PluginMap["test"] = config.PluginConfig{
		Name:        "test",
		Uri:         "sqlite://" + dbPath,
		EnableCache: true,
		DbTxEnd:     "commit-allow-override",
		AllowList: config.AccessConfig{
			Table: []string{"users"},
		},
		Exclude: config.AccessConfig{
			Table: []string{"orders"}, // orders is also excluded
		},
	}
	cfg.CORS.Enabled = true
	cfg.CheckScope = false // Disable scope check for simplicity
	server.SetConfig(cfg)
	server.LoadPlugins()

	tokenStr := generateToken(t)

	// 1. Access allowed table (users)
	req, err := http.NewRequest("GET", "/api/test/users/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200 for allowed table 'users', got %d. Response: %s", rr.Code, rr.Body.String())
	}

	// 2. Access disallowed table (products - not in AllowList)
	req, err = http.NewRequest("GET", "/api/test/products/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("Expected status 404 for disallowed table 'products', got %d. Response: %s", rr.Code, rr.Body.String())
	}

	// 3. Access excluded table (orders - in Exclude list)
	req, err = http.NewRequest("GET", "/api/test/orders/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("Expected status 404 for excluded table 'orders', got %d. Response: %s", rr.Code, rr.Body.String())
	}
}
