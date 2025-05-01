package tests

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/onegreyonewhite/easyrest/internal/config"
	"github.com/onegreyonewhite/easyrest/internal/server"
)

// TestConfigLoad checks coverage for config.Load().
func TestConfigLoad(t *testing.T) {
	// Set some environment variables to see if they load properly.
	os.Setenv("ER_PORT", "9999")
	os.Setenv("ER_CHECK_SCOPE", "0")
	os.Setenv("ER_TOKEN_SECRET", "mytestsecret")
	os.Setenv("ER_TOKEN_USER_SEARCH", "sub")
	os.Setenv("ER_NO_PLUGIN_LOG", "0")
	os.Setenv("ER_ACCESSLOG", "1")
	os.Setenv("ER_DEFAULT_TIMEZONE", "America/New_York")

	defer func() {
		os.Unsetenv("ER_PORT")
		os.Unsetenv("ER_CHECK_SCOPE")
		os.Unsetenv("ER_TOKEN_SECRET")
		os.Unsetenv("ER_TOKEN_USER_SEARCH")
		os.Unsetenv("ER_NO_PLUGIN_LOG")
		os.Unsetenv("ER_ACCESSLOG")
		os.Unsetenv("ER_DEFAULT_TIMEZONE")
	}()

	cfg := config.Load()
	if cfg.Port != "9999" {
		t.Errorf("Expected port 9999, got %s", cfg.Port)
	}
	if cfg.CheckScope {
		t.Errorf("Expected CheckScope = false when ER_CHECK_SCOPE=0, got true")
	}
	if cfg.TokenSecret != "mytestsecret" {
		t.Errorf("Expected TokenSecret = 'mytestsecret', got %s", cfg.TokenSecret)
	}
	if cfg.TokenUserSearch != "sub" {
		t.Errorf("Expected TokenUserSearch = 'sub', got %s", cfg.TokenUserSearch)
	}
	if cfg.NoPluginLog {
		t.Errorf("Expected NoPluginLog=false, got true")
	}
	if !cfg.AccessLogOn {
		t.Errorf("Expected AccessLogOn=true, got false")
	}
	if cfg.DefaultTimezone != "America/New_York" {
		t.Errorf("Expected DefaultTimezone=America/New_York, got %s", cfg.DefaultTimezone)
	}
}

// TestIsAllowedFunction checks coverage for isAllowedFunction.
func TestIsAllowedFunction(t *testing.T) {
	allowed := []string{"count", "sum", "avg", "min", "max"}
	for _, fn := range allowed {
		if !server.IsAllowedFunction(fn) {
			t.Errorf("Expected IsAllowedFunction(%s) = true, got false", fn)
		}
	}
	if server.IsAllowedFunction("random") {
		t.Errorf("Expected IsAllowedFunction(random) = false, got true")
	}
}

// TestParseCSV covers parseCSV with various inputs.
func TestParseCSV(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"id,name", []string{"id", "name"}},
		{"  id ,  name  , x  ", []string{"id", "name", "x"}},
	}
	for _, c := range cases {
		got := server.ParseCSV(c.input)
		if len(got) != len(c.want) {
			t.Errorf("parseCSV(%q) mismatch length: got %v, want %v", c.input, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("parseCSV(%q) mismatch at index %d: got %q, want %q", c.input, i, got[i], c.want[i])
			}
		}
	}
}

// TestCheckScope verifies checkScope coverage.
func TestCheckScope(t *testing.T) {
	claims := jwt.MapClaims{
		"scope": "users-read users-write read write",
	}
	if !server.CheckScope(claims, "users-read") {
		t.Error("Expected checkScope to allow users-read")
	}
	if !server.CheckScope(claims, "whatever-read") {
		t.Error("Expected checkScope to allow read suffix if 'read' is present")
	}
	if !server.CheckScope(claims, "whatever-write") {
		t.Error("Expected checkScope to allow write suffix if 'write' is present")
	}
	if server.CheckScope(claims, "admin") {
		t.Error("Expected checkScope to deny admin scope")
	}
}

// TestParseWhereClause checks parseWhereClause.
func TestParseWhereClause(t *testing.T) {
	values := map[string][]string{
		"where.eq.name":    {"Alice"},
		"where.neq.age":    {"30"},
		"where.lt.id":      {"100"},
		"where.lte.score":  {"50"},
		"where.gt.height":  {"180"},
		"where.gte.level":  {"2"},
		"where.like.city":  {"Moscow%"},
		"where.ilike.note": {"test%"},
		"where.is.active":  {"TRUE"},
		"where.in.group":   {"A,B,C"},
		// NOT варианты
		"where.not.eq.name":    {"Bob"},
		"where.not.neq.age":    {"40"},
		"where.not.lt.id":      {"200"},
		"where.not.lte.score":  {"60"},
		"where.not.gt.height":  {"190"},
		"where.not.gte.level":  {"3"},
		"where.not.like.city":  {"SPb%"},
		"where.not.ilike.note": {"prod%"},
		"where.not.is.active":  {"FALSE"},
		"where.not.in.group":   {"X,Y,Z"},
	}
	whereMap, err := server.ParseWhereClause(values, map[string]string{}, map[string]any{})
	if err != nil {
		t.Errorf("Unexpected error from parseWhereClause: %v", err)
	}
	checks := []struct {
		key   string
		op    string
		value string
	}{
		{"name", "=", "Alice"},
		{"age", "!=", "30"},
		{"id", "<", "100"},
		{"score", "<=", "50"},
		{"height", ">", "180"},
		{"level", ">=", "2"},
		{"city", "LIKE", "Moscow%"},
		{"note", "ILIKE", "test%"},
		{"active", "IS", "TRUE"},
		{"group", "IN", "A,B,C"},
	}
	for _, c := range checks {
		m, ok := whereMap[c.key].(map[string]any)
		if !ok {
			t.Errorf("Expected key %q in whereMap", c.key)
			continue
		}
		v, ok := m[c.op]
		if !ok {
			t.Errorf("Expected operator %q for key %q", c.op, c.key)
			continue
		}
		if v != c.value {
			t.Errorf("Expected value %q for %q %q, got %q", c.value, c.key, c.op, v)
		}
	}
	notChecks := []struct {
		key   string
		op    string
		value string
	}{
		{"NOT name", "=", "Bob"},
		{"NOT age", "!=", "40"},
		{"NOT id", "<", "200"},
		{"NOT score", "<=", "60"},
		{"NOT height", ">", "190"},
		{"NOT level", ">=", "3"},
		{"NOT city", "LIKE", "SPb%"},
		{"NOT note", "ILIKE", "prod%"},
		{"NOT active", "IS", "FALSE"},
		{"NOT group", "IN", "X,Y,Z"},
	}
	for _, c := range notChecks {
		m, ok := whereMap[c.key].(map[string]any)
		if !ok {
			t.Errorf("Expected key %q in whereMap", c.key)
			continue
		}
		v, ok := m[c.op]
		if !ok {
			t.Errorf("Expected operator %q for key %q", c.op, c.key)
			continue
		}
		if v != c.value {
			t.Errorf("Expected value %q for %q %q, got %q", c.value, c.key, c.op, v)
		}
	}
	valuesErr := map[string][]string{
		"where.unknown.x": {"foo"},
	}
	_, err2 := server.ParseWhereClause(valuesErr, map[string]string{}, map[string]any{})
	if err2 == nil {
		t.Error("Expected parseWhereClause to fail with unknown operator 'unknown'")
	}
	// Remove the unknown operator.
	values = map[string][]string{
		"where.eq.name": {"Alice"},
		"where.gt.id":   {"100"},
	}
	whereMap, err2 = server.ParseWhereClause(values, map[string]string{}, map[string]any{})
	if err2 != nil {
		t.Errorf("Unexpected error from parseWhereClause: %v", err2)
	}
	// Expect: { "name": {"=": "Alice"}, "id": {">": "100"} }
	if len(whereMap) != 2 {
		t.Errorf("Expected 2 keys in whereMap, got %d", len(whereMap))
	}
}

// TestBuildPluginContext checks coverage for buildPluginContext.
func TestBuildPluginContext(t *testing.T) {
	// Mock a request with some headers and a token claim context.
	req, _ := http.NewRequest("GET", "/api/test/users/", nil)
	req.Header.Set("Timezone", "Asia/Tokyo")
	req.Header.Set("Prefer", "timezone=America/Los_Angeles")
	req.Header.Add("X-Custom", "Value1")
	req.Header.Add("X-Custom", "Value2")

	// Attach mock claims to context.
	claims := jwt.MapClaims{"sub": "Alice", "scope": "test-scope", "exp": time.Now().Add(time.Hour).Unix()}
	ctx := context.WithValue(context.Background(), server.TokenClaimsKey, claims)
	req = req.WithContext(ctx)

	os.Setenv("ER_DEFAULT_TIMEZONE", "GMT") // fallback if not found in Prefer
	defer os.Unsetenv("ER_DEFAULT_TIMEZONE")

	got := server.BuildPluginContext(req)
	if got["timezone"] != "America/Los_Angeles" {
		t.Errorf("Expected timezone='America/Los_Angeles', got %v", got["timezone"])
	}
	headers, _ := got["headers"].(map[string]any)
	if headers["x-custom"] != "Value1 Value2" {
		t.Errorf("Expected x-custom='Value1 Value2', got %v", headers["x-custom"])
	}
	method, _ := got["method"].(string)
	if method != "GET" {
		t.Errorf("Expected method='GET', got %v", method)
	}
	path, _ := got["path"].(string)
	if path != "/api/test/users/" {
		t.Errorf("Expected path='/api/test/users/', got %v", path)
	}
	claimsMap, _ := got["claims"].(map[string]any)
	if claimsMap["sub"] != "Alice" {
		t.Errorf("Expected claims.sub = 'Alice', got %v", claimsMap["sub"])
	}
	jwtClaimsMap, _ := got["jwt.claims"].(map[string]any)
	if jwtClaimsMap["sub"] != "Alice" {
		t.Errorf("Expected jwt.claims.sub = 'Alice', got %v", jwtClaimsMap["sub"])
	}
}

// TestAccessLogMiddleware covers accessLogMiddleware (0% -> some coverage).
func TestAccessLogMiddleware(t *testing.T) {
	// We'll redirect the standard log output to a buffer to verify it logs something.
	var buf strings.Builder
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	defer server.StopPlugins()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	mw := server.AccessLogMiddleware(handler)

	req, _ := http.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusTeapot {
		t.Errorf("Expected 418 I'm a Teapot, got %d", rr.Code)
	}
	logOutput := buf.String()
	if !strings.Contains(logOutput, "ACCESS: GET") {
		t.Errorf("Expected access log to contain 'ACCESS: GET /test', got %s", logOutput)
	}
}

// TestRun is tricky to fully cover since it blocks. We'll do a minimal test to ensure it doesn't panic.
func TestRunMinimal(t *testing.T) {
	// We'll set up environment so it doesn't block.
	os.Setenv("ER_PORT", "9998")
	os.Setenv("ER_CHECK_SCOPE", "0")
	defer server.StopPlugins()
	defer func() {
		os.Unsetenv("ER_PORT")
		os.Unsetenv("ER_CHECK_SCOPE")
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// This will call ListenAndServe, which blocks. We can rely on timeouts or external interruption.
		// Typically we'd skip coverage here or you can mock net.Listen to forcibly break out.
		// We'll do a quick sleep then kill it.
		defer func() {
			// not a real approach for coverage but an example
		}()
		server.Run(config.Load())
	}()
	time.Sleep(200 * time.Millisecond)
	// We can't easily check coverage further. We kill the goroutine by exiting the test.
}

// TestLoadPlugins tries to cover LoadPlugins by messing with environment variables.
func TestLoadPlugins(t *testing.T) {
	// We'll set environment for a non-existent plugin type: e.g., "xyz"
	os.Setenv("ER_DB_NONEXIST", "xyz://somewhere")
	defer os.Unsetenv("ER_DB_NONEXIST")

	// We'll also set environment for an invalid format
	os.Setenv("ER_DB_BAD", "justbad")
	defer os.Unsetenv("ER_DB_BAD")

	// We'll set environment for a known (but not installed) plugin type "sqlite"
	os.Setenv("ER_DB_TEST", "sqlite://test.db")
	defer os.Unsetenv("ER_DB_TEST")

	// Reset dbPlugins and call LoadPlugins
	server.LoadPlugins()
	defer server.StopPlugins()
	// We expect it to attempt to look up easyrest-plugin-xyz and easyrest-plugin-sqlite
	// For coverage, we at least ensure it doesn't panic.

	currentDbPlugins := *server.DbPlugins.Load()
	if len(currentDbPlugins) > 0 {
		t.Logf("Plugins loaded: %+v", currentDbPlugins) // Log the loaded map content
		// Possibly check if "test" is in the map but not truly connected since no binary is found.
	} else {
		t.Logf("No plugins loaded (as expected if no plugin binaries are found).")
	}
}

// Helper function to call unexported function in server to retrieve dbPlugins map.
// func (server *Server) DbPlugins() map[string]easyrest.DBPlugin {
// 	// not valid code unless we do reflection or fix the code to allow us to read dbPlugins
// 	// In practice, to get coverage for LoadPlugins, we rely on not panicking.
// 	// Alternatively we can do reflection or build a getter in the main code.
// 	return nil
// }

// TestRPCHandler covers the rpcHandler function by sending a POST request with JSON data.
func TestRPCHandler(t *testing.T) {
	// We set up environment so it won't find a real plugin, but we can at least cover error paths.
	os.Setenv("ER_DB_TEST", "sqlite://:memory:")
	defer os.Unsetenv("ER_DB_TEST")

	server.ReloadConfig()
	defer server.StopPlugins()

	router := server.SetupRouter()
	tokenStr := generateTestToken(t, "mytestsecret", "funcA-write")

	reqBody := `{"param": "value"}`
	req, err := http.NewRequest("POST", "/api/test1/rpc/funcA/", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	// Expect error because plugin not actually loaded.
	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected 404 DB plugin not found, got %d, body: %s", rr.Code, rr.Body.String())
	}
}

// TestHealthHandler checks the /health endpoint returns 200 and 'OK'.
func TestHealthHandler(t *testing.T) {
	router := server.SetupRouter()
	req, _ := http.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
	if rr.Body.String() != "OK" {
		t.Errorf("Expected body 'OK', got %q", rr.Body.String())
	}
}
