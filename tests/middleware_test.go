package tests

import (
	"encoding/json"
	"errors"
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
	jwtplugin "github.com/onegreyonewhite/easyrest/plugins/auth/jwt"
	sqlitePlugin "github.com/onegreyonewhite/easyrest/plugins/data/sqlite"
	_ "modernc.org/sqlite"
)

type trackingMiddlewarePlugin struct {
	callCount     int
	postCallCount int
	lastDBKey     string
	lastCtx       map[string]any
	failErr       error
	failStatus    *int
	postHeaders   map[string]string
	ctxHeaders    map[string]any
}

func (p *trackingMiddlewarePlugin) Init(map[string]any, easyrest.HostRPC) (easyrest.MiddlewareInfo, error) {
	return easyrest.NewMiddlewareInfo(), nil
}

func (p *trackingMiddlewarePlugin) PreRequest(dbKey string, ctx map[string]any) (map[string]any, *int, error) {
	p.callCount++
	p.lastDBKey = dbKey
	p.lastCtx = ctx
	for k, v := range p.ctxHeaders {
		ctx[k] = v
	}
	if p.failStatus != nil || p.failErr != nil {
		return ctx, p.failStatus, p.failErr
	}
	return ctx, nil, nil
}

func (p *trackingMiddlewarePlugin) PostRequest(dbKey string, ctx map[string]any) (map[string]string, error) {
	p.postCallCount++
	p.lastDBKey = dbKey
	p.lastCtx = ctx
	if p.postHeaders != nil {
		return p.postHeaders, nil
	}
	return map[string]string{"X-MW-Post": "1"}, nil
}

func setupMiddlewareIntegration(t *testing.T, mw *trackingMiddlewarePlugin) (http.Handler, func()) {
	t.Helper()

	origPreserved := server.PreservedMiddlewarePlugins["testmw"]
	server.PreservedMiddlewarePlugins["testmw"] = func() easyrest.MiddlewarePlugin { return mw }
	server.PreservedAuthPlugins["jwt"] = func() easyrest.AuthPlugin {
		return &jwtplugin.JWTAuthPlugin{}
	}
	server.PreservedDbPlugins["sqlite"] = func() easyrest.DBPlugin {
		return sqlitePlugin.NewSqlitePlugin()
	}

	dbPath := setupTestDB(t)
	applyTestConfig(t, testSQLiteYAML("sqlite://"+dbPath, false, ""))
	cfg := server.GetConfig()
	cfg.MiddlewarePlugins = map[string]config.MiddlewareConfig{
		"testmw": {},
	}
	cfg.GlobalRequestMiddlewares = []string{"testmw"}
	server.SetConfig(cfg)

	router := server.SetupRouter()
	insertUser(t, dbPath, "Alice", "")

	cleanup := func() {
		server.StopPlugins()
		os.Remove(dbPath)
		if origPreserved != nil {
			server.PreservedMiddlewarePlugins["testmw"] = origPreserved
		} else {
			delete(server.PreservedMiddlewarePlugins, "testmw")
		}
	}
	return router, cleanup
}

func TestMiddlewareIntegration_TableHandler(t *testing.T) {
	mw := &trackingMiddlewarePlugin{}
	router, cleanup := setupMiddlewareIntegration(t, mw)
	defer cleanup()

	token := generateToken(t)
	req, err := http.NewRequest("GET", "/api/test/users/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if mw.callCount != 1 {
		t.Fatalf("expected middleware called once, got %d", mw.callCount)
	}
	if mw.lastDBKey != "test" {
		t.Fatalf("expected dbKey test, got %q", mw.lastDBKey)
	}
	if mw.lastCtx == nil || mw.lastCtx["method"] != "GET" {
		t.Fatalf("expected plugin context with method GET, got %#v", mw.lastCtx)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if mw.postCallCount != 1 {
		t.Fatalf("expected PostRequest once, got %d", mw.postCallCount)
	}
	if rr.Header().Get("X-MW-Post") != "1" {
		t.Fatalf("expected X-MW-Post header, got %q", rr.Header().Get("X-MW-Post"))
	}
}

func TestMiddlewareIntegration_ContextResponseHeader(t *testing.T) {
	mw := &trackingMiddlewarePlugin{
		ctxHeaders: map[string]any{"response.header.X-From-Ctx": "yes"},
	}
	router, cleanup := setupMiddlewareIntegration(t, mw)
	defer cleanup()

	token := generateToken(t)
	req, err := http.NewRequest("GET", "/api/test/users/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-From-Ctx") != "yes" {
		t.Fatalf("expected X-From-Ctx from context, got %q", rr.Header().Get("X-From-Ctx"))
	}
}

func TestMiddlewareIntegration_TableHandlerError(t *testing.T) {
	mw := &trackingMiddlewarePlugin{failErr: errors.New("middleware blocked")}
	router, cleanup := setupMiddlewareIntegration(t, mw)
	defer cleanup()

	token := generateToken(t)
	req, err := http.NewRequest("GET", "/api/test/users/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "middleware blocked" {
		t.Fatalf("unexpected body: %q", rr.Body.String())
	}
	if mw.postCallCount != 0 {
		t.Fatalf("PostRequest should not run after PreRequest error, got %d", mw.postCallCount)
	}
}

func TestMiddlewareIntegration_TableHandlerStatus(t *testing.T) {
	status := 418
	mw := &trackingMiddlewarePlugin{
		failStatus: &status,
		failErr:    errors.New("teapot"),
	}
	router, cleanup := setupMiddlewareIntegration(t, mw)
	defer cleanup()

	token := generateToken(t)
	req, err := http.NewRequest("GET", "/api/test/users/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != 418 {
		t.Fatalf("expected 418, got %d body=%s", rr.Code, rr.Body.String())
	}
	if mw.postCallCount != 0 {
		t.Fatalf("PostRequest should not run after PreRequest status, got %d", mw.postCallCount)
	}
}

func TestMiddlewareIntegration_PreRequestStatusAppliesContextHeaders(t *testing.T) {
	status := 418
	mw := &trackingMiddlewarePlugin{
		failStatus: &status,
		failErr:    errors.New("teapot"),
		ctxHeaders: map[string]any{"response.header.X-From-Ctx": "yes"},
	}
	router, cleanup := setupMiddlewareIntegration(t, mw)
	defer cleanup()

	token := generateToken(t)
	req, err := http.NewRequest("GET", "/api/test/users/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != 418 {
		t.Fatalf("expected 418, got %d body=%s", rr.Code, rr.Body.String())
	}
	if mw.postCallCount != 0 {
		t.Fatalf("PostRequest should not run after PreRequest status, got %d", mw.postCallCount)
	}
	if rr.Header().Get("X-From-Ctx") != "yes" {
		t.Fatalf("expected X-From-Ctx from PreRequest ctx, got %q", rr.Header().Get("X-From-Ctx"))
	}
}

func TestMiddlewareIntegration_PostRequestOnSelectError(t *testing.T) {
	mw := &trackingMiddlewarePlugin{}
	router, cleanup := setupMiddlewareIntegration(t, mw)
	defer cleanup()

	token := generateToken(t)
	req, err := http.NewRequest("GET", "/api/test/users/?select=id.notallowed()", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rr.Code, rr.Body.String())
	}
	if mw.postCallCount != 1 {
		t.Fatalf("expected PostRequest after handler error, got %d", mw.postCallCount)
	}
	if rr.Header().Get("X-MW-Post") != "1" {
		t.Fatalf("expected X-MW-Post on error response, got %q", rr.Header().Get("X-MW-Post"))
	}
}

func TestMiddlewareIntegration_RPCHandler(t *testing.T) {
	mw := &trackingMiddlewarePlugin{}
	router, cleanup := setupMiddlewareIntegration(t, mw)
	defer cleanup()

	mockPlugin := &mockDBPlugin{
		callFunction: func(userID, funcName string, data map[string]any, ctx map[string]any) (any, error) {
			return data, nil
		},
	}
	server.DbPlugins.Store(&map[string]easyrest.DBPlugin{"mock": mockPlugin})

	token := generateToken(t)
	body := strings.NewReader(`{"x":1}`)
	req, err := http.NewRequest("POST", "/api/mock/rpc/test/", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if mw.callCount != 1 {
		t.Fatalf("expected middleware called once, got %d", mw.callCount)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMiddlewareIntegration_QueryHandler(t *testing.T) {
	mw := &trackingMiddlewarePlugin{}
	router, cleanup := setupMiddlewareIntegration(t, mw)
	defer cleanup()

	mockPlugin := &mockQueryPlugin{
		queryCall: func(query string, ctx map[string]any) ([]map[string]any, error) {
			return []map[string]any{{"ok": true}}, nil
		},
	}
	server.QueryPlugins.Store(&map[string]easyrest.DBQueryPlugin{"mock": mockPlugin})

	token := generateToken(t)
	req, err := http.NewRequest("QUERY", "/api/mock/", strings.NewReader("SELECT 1"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if mw.callCount != 1 {
		t.Fatalf("expected middleware called once, got %d", mw.callCount)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMiddlewareIntegration_SchemaHandler(t *testing.T) {
	mw := &trackingMiddlewarePlugin{}
	router, cleanup := setupMiddlewareIntegration(t, mw)
	defer cleanup()

	mockPlugin := &schemaMockDBPlugin{
		getSchema: func(ctx map[string]any) (any, error) {
			return map[string]any{"tables": map[string]any{"users": map[string]any{}}}, nil
		},
	}
	server.DbPlugins.Store(&map[string]easyrest.DBPlugin{"mock": mockPlugin})

	req, err := http.NewRequest("GET", "/api/mock/", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if mw.callCount != 1 {
		t.Fatalf("expected middleware called once, got %d", mw.callCount)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
}

type schemaMockDBPlugin struct {
	mockDBPlugin
	getSchema func(ctx map[string]any) (any, error)
}

func (m *schemaMockDBPlugin) GetSchema(ctx map[string]any) (any, map[string]any, error) {
	schema, err := m.getSchema(ctx)
	return schema, nil, err
}

func TestMiddlewareIntegration_ChainStopsBeforeHandler(t *testing.T) {
	mw := &trackingMiddlewarePlugin{failErr: errors.New("stop early")}
	router, cleanup := setupMiddlewareIntegration(t, mw)
	defer cleanup()

	handlerCalled := false
	mockPlugin := &mockDBPlugin{
		callFunction: func(userID, funcName string, data map[string]any, ctx map[string]any) (any, error) {
			handlerCalled = true
			return data, nil
		},
	}
	server.DbPlugins.Store(&map[string]easyrest.DBPlugin{"mock": mockPlugin})

	token := generateToken(t)
	req, err := http.NewRequest("POST", "/api/mock/rpc/test/", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if handlerCalled {
		t.Fatal("RPC handler should not run when middleware fails")
	}
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestMiddlewareIntegration_UnknownPluginSkipped(t *testing.T) {
	defer server.StopPlugins()

	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	applyTestConfig(t, testSQLiteYAML("sqlite://"+dbPath, false, ""))
	server.PreservedAuthPlugins["jwt"] = func() easyrest.AuthPlugin {
		return &jwtplugin.JWTAuthPlugin{}
	}
	server.PreservedDbPlugins["sqlite"] = func() easyrest.DBPlugin {
		return sqlitePlugin.NewSqlitePlugin()
	}

	cfg := server.GetConfig()
	cfg.GlobalRequestMiddlewares = []string{"missing_mw"}
	cfg.MiddlewarePlugins = map[string]config.MiddlewareConfig{}
	server.SetConfig(cfg)
	router := server.SetupRouter()

	insertUser(t, dbPath, "Alice", "")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "testuser",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": "users-read users-write",
	})
	tokenStr, err := token.SignedString([]byte("mytestsecret"))
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("GET", "/api/test/users/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("unknown middleware should be skipped, request should succeed, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestDBPluginReturnedCtxSetsResponseHeader(t *testing.T) {
	mw := &trackingMiddlewarePlugin{}
	router, cleanup := setupMiddlewareIntegration(t, mw)
	defer cleanup()

	mockPlugin := &mockDBPlugin{
		tableGet: func(userID, table string, selectFields []string, where map[string]any,
			ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, map[string]any, error) {
			ctx["response.header.X-From-Db"] = "1"
			return []map[string]any{{"id": 1}}, ctx, nil
		},
	}
	server.DbPlugins.Store(&map[string]easyrest.DBPlugin{"test": mockPlugin})

	token := generateToken(t)
	req, err := http.NewRequest("GET", "/api/test/users/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-From-Db") != "1" {
		t.Fatalf("expected X-From-Db from returned ctx, got %q", rr.Header().Get("X-From-Db"))
	}
	if mw.lastCtx["response.header.X-From-Db"] != "1" {
		t.Fatalf("PostRequest should see DB-updated ctx, got %#v", mw.lastCtx)
	}
}

func TestDBPluginNilCtxKeepsMiddlewareHeaders(t *testing.T) {
	mw := &trackingMiddlewarePlugin{
		ctxHeaders: map[string]any{"response.header.X-From-Mw": "mw"},
	}
	router, cleanup := setupMiddlewareIntegration(t, mw)
	defer cleanup()

	mockPlugin := &mockDBPlugin{
		tableGet: func(userID, table string, selectFields []string, where map[string]any,
			ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, map[string]any, error) {
			return []map[string]any{{"id": 1}}, nil, nil
		},
	}
	server.DbPlugins.Store(&map[string]easyrest.DBPlugin{"test": mockPlugin})

	token := generateToken(t)
	req, err := http.NewRequest("GET", "/api/test/users/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-From-Mw") != "mw" {
		t.Fatalf("expected middleware header kept when DB returns nil ctx, got %q", rr.Header().Get("X-From-Mw"))
	}
	if rr.Header().Get("X-From-Db") != "" {
		t.Fatalf("did not expect X-From-Db, got %q", rr.Header().Get("X-From-Db"))
	}
}

func TestDBPluginSQLShapedResponseHeaders(t *testing.T) {
	mw := &trackingMiddlewarePlugin{}
	router, cleanup := setupMiddlewareIntegration(t, mw)
	defer cleanup()

	mockPlugin := &mockDBPlugin{
		tableGet: func(userID, table string, selectFields []string, where map[string]any,
			ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, map[string]any, error) {
			ctx["response.headers"] = `[{"X-From-Sql":"1"}]`
			return []map[string]any{{"id": 1}}, ctx, nil
		},
	}
	server.DbPlugins.Store(&map[string]easyrest.DBPlugin{"test": mockPlugin})

	token := generateToken(t)
	req, err := http.NewRequest("GET", "/api/test/users/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-From-Sql") != "1" {
		t.Fatalf("expected X-From-Sql from response.headers JSON, got %q", rr.Header().Get("X-From-Sql"))
	}
}

func TestDBPluginResponseStatusTeapot(t *testing.T) {
	mw := &trackingMiddlewarePlugin{}
	router, cleanup := setupMiddlewareIntegration(t, mw)
	defer cleanup()

	mockPlugin := &mockDBPlugin{
		tableGet: func(userID, table string, selectFields []string, where map[string]any,
			ordering []string, groupBy []string, limit, offset int, ctx map[string]any) ([]map[string]any, map[string]any, error) {
			ctx["response.status"] = "418"
			return []map[string]any{{"id": 1}}, ctx, nil
		},
		callFunction: func(userID, funcName string, data map[string]any, ctx map[string]any) (any, error) {
			return "ok", nil
		},
		callFunctionCtx: map[string]any{"response.status": "418"},
	}
	server.DbPlugins.Store(&map[string]easyrest.DBPlugin{"test": mockPlugin})

	token := generateToken(t)
	req, err := http.NewRequest("GET", "/api/test/users/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != 418 {
		t.Fatalf("GET expected 418, got %d body=%s", rr.Code, rr.Body.String())
	}

	req, err = http.NewRequest("POST", "/api/test/rpc/teapot/", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != 418 {
		t.Fatalf("RPC expected 418, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSQLiteNilHarvestKeepsStatusAndHeaders(t *testing.T) {
	mw := &trackingMiddlewarePlugin{
		ctxHeaders: map[string]any{"response.header.X-From-Mw": "mw"},
	}
	router, cleanup := setupMiddlewareIntegration(t, mw)
	defer cleanup()

	token := generateToken(t)
	req, err := http.NewRequest("GET", "/api/test/users/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("sqlite nil harvest expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-From-Mw") != "mw" {
		t.Fatalf("expected middleware header, got %q", rr.Header().Get("X-From-Mw"))
	}
}
