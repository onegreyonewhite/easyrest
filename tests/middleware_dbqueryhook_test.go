package tests

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/onegreyonewhite/easyrest/internal/config"
	"github.com/onegreyonewhite/easyrest/internal/server"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	jwtplugin "github.com/onegreyonewhite/easyrest/plugins/auth/jwt"
	sqlitePlugin "github.com/onegreyonewhite/easyrest/plugins/data/sqlite"
	dbqueryhook "github.com/onegreyonewhite/easyrest/plugins/middleware/dbqueryhook"
	_ "modernc.org/sqlite"
)

func TestMiddlewareIntegration_DBQueryHookSetsCtx(t *testing.T) {
	recorder := &trackingMiddlewarePlugin{}
	origHook := server.PreservedMiddlewarePlugins["dbqueryhook"]
	origRec := server.PreservedMiddlewarePlugins["testmw"]
	server.PreservedMiddlewarePlugins["dbqueryhook"] = func() easyrest.MiddlewarePlugin {
		return dbqueryhook.New()
	}
	server.PreservedMiddlewarePlugins["testmw"] = func() easyrest.MiddlewarePlugin { return recorder }
	server.PreservedAuthPlugins["jwt"] = func() easyrest.AuthPlugin {
		return &jwtplugin.JWTAuthPlugin{}
	}
	server.PreservedDbPlugins["sqlite"] = func() easyrest.DBPlugin {
		return sqlitePlugin.NewSqlitePlugin()
	}
	defer func() {
		server.StopPlugins()
		if origHook != nil {
			server.PreservedMiddlewarePlugins["dbqueryhook"] = origHook
		} else {
			delete(server.PreservedMiddlewarePlugins, "dbqueryhook")
		}
		if origRec != nil {
			server.PreservedMiddlewarePlugins["testmw"] = origRec
		} else {
			delete(server.PreservedMiddlewarePlugins, "testmw")
		}
	}()

	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)
	applyTestConfig(t, testSQLiteYAML("sqlite://"+dbPath, false, ""))
	cfg := server.GetConfig()
	cfg.MiddlewarePlugins = map[string]config.MiddlewareConfig{
		"dbqueryhook": {
			Settings: map[string]any{
				"by_key": map[string]any{
					"test": map[string]any{"pre_request": "custom_headers"},
				},
			},
		},
		"testmw": {},
	}
	cfg.GlobalRequestMiddlewares = []string{"dbqueryhook", "testmw"}
	server.SetConfig(cfg)

	router := server.SetupRouter()
	insertUser(t, dbPath, "Alice", "")

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
	if recorder.lastCtx == nil {
		t.Fatal("expected recorder to see context")
	}
	if recorder.lastCtx[easyrest.CtxDBType] != "sqlite" {
		t.Fatalf("db.type: %#v", recorder.lastCtx[easyrest.CtxDBType])
	}
	if recorder.lastCtx[easyrest.CtxDBPreRequest] != "custom_headers" {
		t.Fatalf("db.pre-request: %#v", recorder.lastCtx[easyrest.CtxDBPreRequest])
	}
}
