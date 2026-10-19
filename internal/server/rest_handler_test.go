package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goccy/go-json"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
)

func TestRestHandler_ListReturnsJSON(t *testing.T) {
	t.Cleanup(func() { SetRestHandlers(nil) })
	SetRestHandlers(map[string]Handler{
		"listUsers": func(Call) (any, error) {
			return map[string]any{"ok": true}, nil
		},
	})
	cfg := restUsersConfig()
	app := cfg.RestAPI["v1"]
	ep := app.Endpoints["users"]
	ep.Public = true
	ep.Actions = map[string]config.RestAction{"list": {Handler: "listUsers"}}
	app.Endpoints["users"] = ep
	cfg.RestAPI["v1"] = app

	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["ok"] != true {
		t.Fatalf("body %#v", body)
	}
}

func TestRestHandler_ClosedAuthSkipsHandler(t *testing.T) {
	t.Cleanup(func() { SetRestHandlers(nil) })
	called := false
	SetRestHandlers(map[string]Handler{
		"listUsers": func(Call) (any, error) {
			called = true
			return map[string]any{"ok": true}, nil
		},
	})
	cfg := restUsersConfig()
	cfg.CheckScope = true
	cfg.AnonClaims = map[string]any{}
	app := cfg.RestAPI["v1"]
	ep := app.Endpoints["users"]
	ep.Actions = map[string]config.RestAction{"list": {Handler: "listUsers"}}
	app.Endpoints["users"] = ep
	cfg.RestAPI["v1"] = app

	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if called {
		t.Fatal("handler ran without a token")
	}
}

func TestRestHandler_UnknownNameFailsSetup(t *testing.T) {
	orig := GetConfig()
	t.Cleanup(func() {
		SetRestHandlers(nil)
		SetConfig(orig)
	})
	err := SetupApplication(`
plugins:
  app:
    uri: sqlite://./missing.db
application:
  source: app
  api:
    v1:
      endpoints:
        users:
          actions:
            list:
              handler: missing
`, nil)
	if err == nil || !strings.Contains(err.Error(), `handler "missing" is not registered`) {
		t.Fatalf("error: %v", err)
	}
}

func TestRestHandler_HandlerErrorKeepsStatus(t *testing.T) {
	t.Cleanup(func() { SetRestHandlers(nil) })
	SetRestHandlers(map[string]Handler{
		"listUsers": func(Call) (any, error) {
			return nil, &HandlerError{Status: http.StatusTeapot, Message: "nope"}
		},
	})
	cfg := restUsersConfig()
	app := cfg.RestAPI["v1"]
	ep := app.Endpoints["users"]
	ep.Public = true
	ep.Actions = map[string]config.RestAction{"list": {Handler: "listUsers"}}
	app.Endpoints["users"] = ep
	cfg.RestAPI["v1"] = app

	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if rec.Code != http.StatusTeapot || !strings.Contains(rec.Body.String(), "nope") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestRestHandler_RetrievePassesID(t *testing.T) {
	t.Cleanup(func() { SetRestHandlers(nil) })
	SetRestHandlers(map[string]Handler{
		"getUser": func(call Call) (any, error) {
			return map[string]any{"id": call.Params["id"]}, nil
		},
	})
	cfg := restUsersConfig()
	app := cfg.RestAPI["v1"]
	ep := app.Endpoints["users"]
	ep.Public = true
	ep.Actions = map[string]config.RestAction{"retrieve": {Handler: "getUser"}}
	app.Endpoints["users"] = ep
	cfg.RestAPI["v1"] = app

	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/7/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["id"] != "7" {
		t.Fatalf("body %#v", body)
	}
}

func TestRestHandler_CustomActions(t *testing.T) {
	t.Cleanup(func() { SetRestHandlers(nil) })
	SetRestHandlers(map[string]Handler{
		"archiveUser": func(call Call) (any, error) {
			return map[string]any{"id": call.Params["id"], "op": "archive"}, nil
		},
		"exportUsers": func(Call) (any, error) {
			return map[string]any{"op": "export"}, nil
		},
		"noteState": func(call Call) (any, error) {
			return map[string]any{"method": call.Request.Method}, nil
		},
	})
	cfg := restUsersConfig()
	app := cfg.RestAPI["v1"]
	ep := app.Endpoints["users"]
	ep.Public = true
	ep.Actions = map[string]config.RestAction{}
	ep.DetailActions = map[string]config.RestCallAction{"archive": {Handler: "archiveUser"}}
	ep.ListActions = map[string]config.RestCallAction{"export": {Handler: "exportUsers"}}
	ep.StateActions = map[string]config.RestStateAction{"note": {Handler: "noteState", Post: true}}
	app.Endpoints["users"] = ep
	cfg.RestAPI["v1"] = app

	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	archive := httptest.NewRecorder()
	router.ServeHTTP(archive, httptest.NewRequest(http.MethodPost, "/restapi/v1/users/3/archive/", strings.NewReader(`{}`)))
	if archive.Code != http.StatusOK || !strings.Contains(archive.Body.String(), `"id":"3"`) {
		t.Fatalf("archive %d %s", archive.Code, archive.Body.String())
	}
	export := httptest.NewRecorder()
	router.ServeHTTP(export, httptest.NewRequest(http.MethodPost, "/restapi/v1/users/export/", strings.NewReader(`{}`)))
	if export.Code != http.StatusOK || !strings.Contains(export.Body.String(), `"op":"export"`) {
		t.Fatalf("export %d %s", export.Code, export.Body.String())
	}
	note := httptest.NewRecorder()
	router.ServeHTTP(note, httptest.NewRequest(http.MethodPost, "/restapi/v1/users/note/", strings.NewReader(`{}`)))
	if note.Code != http.StatusOK || !strings.Contains(note.Body.String(), `"method":"POST"`) {
		t.Fatalf("note %d %s", note.Code, note.Body.String())
	}
}

func TestRestHandler_ConflictingHandlerRejected(t *testing.T) {
	orig := GetConfig()
	t.Cleanup(func() {
		SetRestHandlers(nil)
		SetConfig(orig)
	})
	SetRestHandlers(map[string]Handler{
		"archiveUser": func(Call) (any, error) { return nil, nil },
		"noteState":   func(Call) (any, error) { return nil, nil },
	})
	err := SetupApplication(`
plugins:
  app:
    uri: sqlite://./missing.db
application:
  source: app
  api:
    v1:
      endpoints:
        users:
          detail_actions:
            archive:
              func: archive_user
              handler: archiveUser
`, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot set both func and handler") {
		t.Fatalf("func+handler: %v", err)
	}
	err = SetupApplication(`
plugins:
  app:
    uri: sqlite://./missing.db
application:
  source: app
  api:
    v1:
      endpoints:
        users:
          state_actions:
            note:
              source_field: note
              handler: noteState
`, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot set both") {
		t.Fatalf("field+handler: %v", err)
	}
}

func TestRestHandler_TableGetUsesInternalRPC(t *testing.T) {
	t.Cleanup(func() { SetRestHandlers(nil) })
	plug := &restRecPlugin{rows: []map[string]any{{"id": "1", "name": "ada"}}}
	SetRestHandlers(map[string]Handler{
		"listUsers": func(call Call) (any, error) {
			res, err := call.Plugins.TableGet(easyrest.HostCall{DB: "db", Name: "users"})
			if err != nil {
				return nil, err
			}
			if res.Status != http.StatusOK {
				return nil, &HandlerError{Status: res.Status, Message: string(res.Body)}
			}
			var rows []map[string]any
			if err := json.Unmarshal(res.Body, &rows); err != nil {
				return nil, err
			}
			return rows, nil
		},
	})
	cfg := restUsersConfig()
	cfg.PluginMap = map[string]config.PluginConfig{"db": {Uri: "sqlite://memory"}}
	app := cfg.RestAPI["v1"]
	ep := app.Endpoints["users"]
	ep.Public = true
	ep.Actions = map[string]config.RestAction{"list": {Handler: "listUsers"}}
	app.Endpoints["users"] = ep
	cfg.RestAPI["v1"] = app

	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plug})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ada") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if plug.getCalls != 1 || plug.getTable != "users" {
		t.Fatalf("calls %d table %q", plug.getCalls, plug.getTable)
	}
}
