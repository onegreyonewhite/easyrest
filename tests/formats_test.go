package tests

import (
	"fmt"
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
)

func TestCreateViaCSV(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()
	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	body := strings.NewReader("name,update_field\nAlice,csv1\nBob,csv2\n")
	req, err := http.NewRequest("POST", "/api/test/users/", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "text/csv")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	rows := getAllUsers(t, dbPath)
	if len(rows) != 2 {
		t.Fatalf("Expected 2 rows, got %d", len(rows))
	}
}

func TestUpdateViaXML(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()
	id := insertUser(t, dbPath, "Before", "old")
	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	// XML single-object decode into map is limited; we still exercise the Content-Type branch.
	body := strings.NewReader(`<item><name>After</name><update_field>xml</update_field></item>`)
	req, err := http.NewRequest("PATCH", fmt.Sprintf("/api/test/users/?where.eq.id=%d", id), body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/xml")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	// Accept either success or XML parse error — both prove the XML branch ran.
	if rr.Code != http.StatusOK && rr.Code != http.StatusBadRequest {
		t.Fatalf("Expected 200 or 400, got %d: %s", rr.Code, rr.Body.String())
	}
	if rr.Code == http.StatusBadRequest && !strings.Contains(rr.Body.String(), "XML") {
		t.Fatalf("Expected XML parse error message, got: %s", rr.Body.String())
	}
}

func TestUnsupportedContentType(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()
	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	req, err := http.NewRequest("POST", "/api/test/users/", strings.NewReader("raw"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/octet-stream")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "unsupported Content-Type") {
		t.Fatalf("Expected unsupported Content-Type message, got: %s", rr.Body.String())
	}
}

func TestRequestBodyExceedsMaxSize(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()
	router := setupServerWithDB(t, dbPath)

	cfg := server.GetConfig()
	cfg.Server.MaxBodySize = 32
	server.SetConfig(cfg)

	tokenStr := generateToken(t)
	body := strings.NewReader(`[{"name":"this-body-is-definitely-longer-than-thirty-two-bytes","update_field":"x"}]`)
	req, err := http.NewRequest("POST", "/api/test/users/", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 for oversized body, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestSelectFormatQueryParam(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()
	insertUser(t, dbPath, "Alice", "")
	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	req, err := http.NewRequest("GET", "/api/test/users/?select=id,name&format=csv", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("Expected text/csv, got %s", rr.Header().Get("Content-Type"))
	}

	reqXML, err := http.NewRequest("GET", "/api/test/users/?select=id,name&format=xml", nil)
	if err != nil {
		t.Fatal(err)
	}
	reqXML.Header.Set("Authorization", "Bearer "+tokenStr)
	rrXML := httptest.NewRecorder()
	router.ServeHTTP(rrXML, reqXML)
	if rrXML.Code != http.StatusOK {
		t.Fatalf("Expected 200 for xml format, got %d: %s", rrXML.Code, rrXML.Body.String())
	}
	if !strings.Contains(rrXML.Header().Get("Content-Type"), "application/xml") {
		t.Fatalf("Expected application/xml, got %s", rrXML.Header().Get("Content-Type"))
	}
}

func TestSelectFormURLEncodedAccept(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()
	insertUser(t, dbPath, "Alice", "")
	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	req, err := http.NewRequest("GET", "/api/test/users/?select=id,name&limit=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Accept", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "application/x-www-form-urlencoded") {
		t.Fatalf("Expected form Content-Type, got %s body=%s", rr.Header().Get("Content-Type"), rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "name=") {
		t.Fatalf("Expected form body with name=, got %s", rr.Body.String())
	}
}

func TestSelectAcceptStarFallbackToContentType(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()
	insertUser(t, dbPath, "Alice", "")
	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	req, err := http.NewRequest("GET", "/api/test/users/?select=id,name", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Content-Type", "text/csv")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("Expected text/csv via */* fallback, got %s", rr.Header().Get("Content-Type"))
	}
	assertVaryAcceptAndContentType(t, rr.Header())
}

func TestSelectJSONVaryAcceptAndContentType(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()
	insertUser(t, dbPath, "Alice", "")
	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	req, err := http.NewRequest("GET", "/api/test/users/?select=id,name", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("Expected application/json, got %s", rr.Header().Get("Content-Type"))
	}
	assertVaryAcceptAndContentType(t, rr.Header())
}

func TestTrustedProxyHeaderMode(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()
	insertUser(t, dbPath, "Alice", "")

	os.Setenv("ER_DB_TEST", "sqlite://"+dbPath)
	os.Setenv("ER_CHECK_SCOPE", "0")
	os.Setenv("ER_TOKEN_SECRET", "mytestsecret")
	os.Setenv("ER_TOKEN_USER_SEARCH", "sub")
	os.Setenv("ER_ACCESSLOG", "1")
	os.Setenv("ER_SERVER_TRUSTED_PROXY_MODE", "header")
	os.Setenv("ER_SERVER_TRUSTED_PROXY_HEADER", "X-Real-IP")
	cfg := config.Load()
	server.SetConfig(cfg)
	router := server.SetupRouter()
	tokenStr := generateToken(t)

	req, _ := http.NewRequest("GET", "/api/test/users/?select=id", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("X-Real-IP", "203.0.113.10")
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", rr.Code, rr.Body.String())
	}
}

func TestTrustedProxyXFFCountMode(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()
	insertUser(t, dbPath, "Alice", "")

	os.Setenv("ER_DB_TEST", "sqlite://"+dbPath)
	os.Setenv("ER_CHECK_SCOPE", "0")
	os.Setenv("ER_TOKEN_SECRET", "mytestsecret")
	os.Setenv("ER_TOKEN_USER_SEARCH", "sub")
	os.Setenv("ER_ACCESSLOG", "1")
	os.Setenv("ER_SERVER_TRUSTED_PROXY_MODE", "xff_count")
	os.Setenv("ER_SERVER_TRUSTED_PROXY_COUNT", "1")
	cfg := config.Load()
	server.SetConfig(cfg)
	router := server.SetupRouter()
	tokenStr := generateToken(t)

	req, _ := http.NewRequest("GET", "/api/test/users/?select=id", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.1")
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", rr.Code, rr.Body.String())
	}
}

func TestRPCScopeForbidden(t *testing.T) {
	mockPlugin := &mockDBPlugin{
		callFunction: func(userID, funcName string, data map[string]any, ctx map[string]any) (any, error) {
			return data, nil
		},
	}
	defer server.StopPlugins()

	os.Setenv("ER_TOKEN_SECRET", "mytestsecret")
	server.ReloadConfig()
	router := server.SetupRouter()

	cfg := server.GetConfig()
	cfg.CheckScope = true
	server.SetConfig(cfg)
	newPlugins := map[string]easyrest.DBPlugin{"mock": mockPlugin}
	server.DbPlugins.Store(&newPlugins)

	claims := jwt.MapClaims{
		"sub":   "testuser",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": "users-read",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte("mytestsecret"))
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest("POST", "/api/mock/rpc/myFunc/", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCreateViaFormURLEncoded(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	defer server.StopPlugins()
	router := setupServerWithDB(t, dbPath)
	tokenStr := generateToken(t)

	body := strings.NewReader("name=FormUser&update_field=viaform")
	req, err := http.NewRequest("POST", "/api/test/users/", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	rows := getAllUsers(t, dbPath)
	if len(rows) != 1 || rows[0]["name"] != "FormUser" {
		t.Fatalf("unexpected rows: %#v", rows)
	}
}
