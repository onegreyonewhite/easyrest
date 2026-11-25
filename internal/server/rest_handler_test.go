package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/onegreyonewhite/easyrest/internal/config"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	lrustore "github.com/onegreyonewhite/easyrest/plugins/data/lru"
	sqlitePlugin "github.com/onegreyonewhite/easyrest/plugins/data/sqlite"
	cachemw "github.com/onegreyonewhite/easyrest/plugins/middleware/cache"
	"github.com/onegreyonewhite/easyrest/plugins/storage/memory"
)

type rawQueryFake struct {
	fakeDBPlugin
	calls int
}

func (f *rawQueryFake) RawQuery(context.Context, string) ([]map[string]any, error) {
	f.calls++
	return []map[string]any{}, nil
}

func TestPluginCallerQuery(t *testing.T) {
	origCfg := GetConfig()
	origDB := DbPlugins.Load()
	t.Cleanup(func() {
		SetConfig(origCfg)
		DbPlugins.Store(origDB)
	})

	fake := &rawQueryFake{}
	SetConfig(config.Config{
		PluginMap: map[string]config.PluginConfig{
			"db": {Uri: "sqlite://memory", UseQuery: true, Internal: true},
		},
	})
	plugins := map[string]easyrest.DBPlugin{"db": fake}
	DbPlugins.Store(&plugins)

	caller := directPlugins{}
	rows, err := caller.Query(context.Background(), "db", "SELECT 1")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("rows %#v", rows)
	}
	if fake.calls != 1 {
		t.Fatalf("calls = %d", fake.calls)
	}

	SetConfig(config.Config{
		PluginMap: map[string]config.PluginConfig{
			"db": {Uri: "sqlite://memory", UseQuery: true, Internal: false},
		},
	})
	fake.calls = 0
	if _, err := caller.Query(context.Background(), "db", "SELECT 1"); err == nil {
		t.Fatal("expected error without internal flag")
	}
	if fake.calls != 0 {
		t.Fatalf("calls = %d", fake.calls)
	}
}

func TestInternalQueryRestAndHTTP(t *testing.T) {
	plug := sqlitePlugin.NewSqlitePlugin()
	if err := plug.InitConnection("sqlite://:memory:"); err != nil {
		t.Fatalf("InitConnection: %v", err)
	}
	defer plug.Close()

	ctx := context.Background()
	if _, err := plug.RawQuery(ctx, `DROP TABLE IF EXISTS users`); err != nil {
		t.Fatalf("DROP: %v", err)
	}
	if _, err := plug.RawQuery(ctx, `CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
		t.Fatalf("CREATE: %v", err)
	}
	if _, err := plug.RawQuery(ctx, `INSERT INTO users (name) VALUES ('ada')`); err != nil {
		t.Fatalf("INSERT: %v", err)
	}

	cfg := restUsersConfig()
	cfg.PluginMap = map[string]config.PluginConfig{
		"db": {Uri: "sqlite://memory", UseQuery: true, Internal: true},
	}
	app := cfg.RestAPI["v1"]
	app.Source = "db"
	app.Public = true
	cfg.RestAPI["v1"] = app

	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": plug})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/?select=id,name", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("rest list status %d body %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ada") {
		t.Fatalf("body %q", rec.Body.String())
	}

	apiGet := httptest.NewRecorder()
	if !denyInternalDB(apiGet, httptest.NewRequest(http.MethodGet, "/api/db/users/", nil), "db") {
		t.Fatal("expected internal db to be denied on /api")
	}
	if apiGet.Code != http.StatusNotFound {
		t.Fatalf("GET /api/db status %d", apiGet.Code)
	}
}

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

func TestRestHandler_HandlerErrorContentType(t *testing.T) {
	t.Cleanup(func() { SetRestHandlers(nil) })
	body := `{"error":"invalid_grant"}`
	SetRestHandlers(map[string]Handler{
		"listUsers": func(Call) (any, error) {
			return nil, &HandlerError{Status: http.StatusBadRequest, Message: body, ContentType: "application/json"}
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
	if rec.Code != http.StatusBadRequest || rec.Body.String() != body {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type %q", got)
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

func TestRestHandler_Cache(t *testing.T) {
	cachePlug := cachemw.New(lrustore.NewSimpleCachePlugin())
	if _, err := cachePlug.Init(map[string]any{"ttl": "1m"}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	orig := MiddlewarePlugins.Load()
	t.Cleanup(func() {
		SetRestHandlers(nil)
		MiddlewarePlugins.Store(orig)
	})
	MiddlewarePlugins.Store(&map[string]easyrest.MiddlewarePlugin{
		"cache-lru": cachePlug,
		"plain":     restPlainMiddleware{},
	})
	SetRestHandlers(map[string]Handler{
		"useCache": func(call Call) (any, error) {
			if err := call.Plugins.CacheSet("cache-lru", "k", "v", nil); err != nil {
				return nil, err
			}
			got, err := call.Plugins.CacheGet("cache-lru", "k")
			if err != nil || got != "v" {
				return nil, err
			}
			if err := call.Plugins.CacheDelete("cache-lru", "k"); err != nil {
				return nil, err
			}
			_, err = call.Plugins.CacheGet("cache-lru", "k")
			if !errors.Is(err, easyrest.ErrCacheMiss) {
				return nil, err
			}
			return got, nil
		},
		"shortCache": func(call Call) (any, error) {
			ttl := time.Millisecond
			if err := call.Plugins.CacheSet("cache-lru", "short", "v", &ttl); err != nil {
				return nil, err
			}
			time.Sleep(20 * time.Millisecond)
			_, err := call.Plugins.CacheGet("cache-lru", "short")
			if !errors.Is(err, easyrest.ErrCacheMiss) {
				return nil, err
			}
			return "gone", nil
		},
		"badCache": func(call Call) (any, error) {
			q := call.Request.URL.Query()
			_, err := call.Plugins.CacheGet(q.Get("plugin"), q.Get("key"))
			return nil, err
		},
	})
	cfg := restUsersConfig()
	app := cfg.RestAPI["v1"]
	ep := app.Endpoints["users"]
	ep.Public = true
	ep.Actions = map[string]config.RestAction{"list": {Handler: "useCache"}}
	app.Endpoints["users"] = ep
	app.Endpoints["notes"] = config.RestEndpoint{
		Public: true,
		Actions: map[string]config.RestAction{
			"list": {Handler: "badCache"},
		},
	}
	app.Endpoints["ticks"] = config.RestEndpoint{
		Public: true,
		Actions: map[string]config.RestAction{
			"list": {Handler: "shortCache"},
		},
	}
	cfg.RestAPI["v1"] = app

	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "v") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	short := httptest.NewRecorder()
	router.ServeHTTP(short, httptest.NewRequest(http.MethodGet, "/restapi/v1/ticks/", nil))
	if short.Code != http.StatusOK || !strings.Contains(short.Body.String(), "gone") {
		t.Fatalf("short ttl: status %d body %s", short.Code, short.Body.String())
	}

	for _, tc := range []struct {
		query string
		want  string
	}{
		{"plugin=&key=k", "cache plugin name is empty"},
		{"plugin=cache-lru&key=", "cache key is empty"},
		{"plugin=missing&key=k", `cache plugin "missing" is not loaded`},
		{"plugin=plain&key=k", `cache plugin "plain" store is unavailable`},
	} {
		got := httptest.NewRecorder()
		router.ServeHTTP(got, httptest.NewRequest(http.MethodGet, "/restapi/v1/notes/?"+tc.query, nil))
		if got.Code == http.StatusOK || !strings.Contains(got.Body.String(), tc.want) {
			t.Fatalf("%s: status %d body %s", tc.query, got.Code, got.Body.String())
		}
	}
}

func TestRestHandler_StoragePutGetDelete(t *testing.T) {
	ref := memoryStorageRef(t)
	ref.Name = "files"
	useStoragePlugins(t, map[string]storagePluginRef{"files": ref})
	t.Cleanup(func() { SetRestHandlers(nil) })
	SetRestHandlers(map[string]Handler{
		"useStorage": func(call Call) (any, error) {
			const path = "obj/data.bin"
			body := []byte("hello")
			rel, _, err := call.Plugins.StoragePut("files", path, body, nil)
			if err != nil || rel != path {
				return nil, err
			}
			got, mime, _, err := call.Plugins.StorageGetBin("files", path, nil)
			if err != nil || string(got) != "hello" || mime == "" {
				return nil, err
			}
			if err := call.Plugins.StorageDelete("files", path, nil); err != nil {
				return nil, err
			}
			_, _, _, err = call.Plugins.StorageGetBin("files", path, nil)
			if err == nil {
				return nil, errors.New("expected get after delete to fail")
			}
			return "ok", nil
		},
		"badStorage": func(call Call) (any, error) {
			q := call.Request.URL.Query()
			_, _, err := call.Plugins.StoragePut(q.Get("plugin"), "x", []byte("a"), nil)
			return nil, err
		},
	})
	cfg := restUsersConfig()
	app := cfg.RestAPI["v1"]
	ep := app.Endpoints["users"]
	ep.Public = true
	ep.Actions = map[string]config.RestAction{"list": {Handler: "useStorage"}}
	app.Endpoints["users"] = ep
	app.Endpoints["notes"] = config.RestEndpoint{
		Public:  true,
		Actions: map[string]config.RestAction{"list": {Handler: "badStorage"}},
	}
	cfg.RestAPI["v1"] = app

	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ok") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	for _, tc := range []struct {
		query string
		want  string
	}{
		{"plugin=", "storage plugin name is empty"},
		{"plugin=missing", `storage plugin "missing" is not loaded`},
	} {
		got := httptest.NewRecorder()
		router.ServeHTTP(got, httptest.NewRequest(http.MethodGet, "/restapi/v1/notes/?"+tc.query, nil))
		if got.Code == http.StatusOK || !strings.Contains(got.Body.String(), tc.want) {
			t.Fatalf("%s: status %d body %s", tc.query, got.Code, got.Body.String())
		}
	}
}

func TestRestHandler_StoragePutStream(t *testing.T) {
	ref := memoryStorageRef(t)
	ref.Name = "files"
	useStoragePlugins(t, map[string]storagePluginRef{"files": ref})
	t.Cleanup(func() { SetRestHandlers(nil) })
	SetRestHandlers(map[string]Handler{
		"useStream": func(call Call) (any, error) {
			const path = "obj/data.bin"
			rel, _, err := call.Plugins.StoragePutStream("files", path, strings.NewReader("hello"), nil)
			if err != nil || rel != path {
				return nil, err
			}
			rc, _, _, err := call.Plugins.StorageGetStream("files", path, 0, nil)
			if err != nil {
				return nil, err
			}
			body, err := io.ReadAll(rc)
			rc.Close()
			if err != nil || string(body) != "hello" {
				return nil, err
			}
			return "ok", nil
		},
	})
	cfg := restUsersConfig()
	app := cfg.RestAPI["v1"]
	ep := app.Endpoints["users"]
	ep.Public = true
	ep.Actions = map[string]config.RestAction{"list": {Handler: "useStream"}}
	app.Endpoints["users"] = ep
	cfg.RestAPI["v1"] = app

	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ok") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestRestHandler_StorageMetadataAndList(t *testing.T) {
	ref := memoryStorageRef(t)
	ref.Name = "files"
	useStoragePlugins(t, map[string]storagePluginRef{"files": ref})
	t.Cleanup(func() { SetRestHandlers(nil) })
	const path = "docs/readme.txt"
	SetRestHandlers(map[string]Handler{
		"metaList": func(call Call) (any, error) {
			body := []byte("readme")
			if _, _, err := call.Plugins.StoragePut("files", path, body, nil); err != nil {
				return nil, err
			}
			meta, err := call.Plugins.StorageGetMetadata("files", path, nil)
			if err != nil || meta.Size != int64(len(body)) || meta.Mime == "" {
				return nil, err
			}
			entries, err := call.Plugins.StorageList("files", "", nil)
			if err != nil {
				return nil, err
			}
			found := false
			for _, e := range entries {
				if e.Name == "docs" && e.Type == easyrest.StorageTypeDir {
					found = true
				}
			}
			if !found {
				return nil, errors.New("list root missing docs dir")
			}
			return map[string]any{"size": meta.Size, "mime": meta.Mime}, nil
		},
	})
	cfg := restUsersConfig()
	app := cfg.RestAPI["v1"]
	ep := app.Endpoints["users"]
	ep.Public = true
	ep.Actions = map[string]config.RestAction{"list": {Handler: "metaList"}}
	app.Endpoints["users"] = ep
	cfg.RestAPI["v1"] = app

	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"size"`) {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestRestHandler_StorageGetUrlAndInline(t *testing.T) {
	plug := memory.New()
	if _, err := plug.Init(map[string]any{"name": "files"}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	ref := storagePluginRef{Name: "files", Plugin: plug, Root: ".", Inline: false}
	inlinePlug := memory.New()
	if _, err := inlinePlug.Init(map[string]any{"name": "inline", "inline": true}, easyrest.HostRPC{}); err != nil {
		t.Fatal(err)
	}
	inlineRef := storagePluginRef{Name: "inline", Plugin: inlinePlug, Inline: true}
	useStoragePlugins(t, map[string]storagePluginRef{"files": ref, "inline": inlineRef})
	t.Cleanup(func() { SetRestHandlers(nil) })
	const path = "pub/logo.png"
	SetRestHandlers(map[string]Handler{
		"urlAndInline": func(call Call) (any, error) {
			if _, _, err := call.Plugins.StoragePut("files", path, []byte{0x89, 0x50, 0x4e, 0x47}, nil); err != nil {
				return nil, err
			}
			ctx := map[string]any{"request": requestPublic(call.Request)}
			urls, err := call.Plugins.StorageGetUrl("files", []string{path}, ctx)
			if err != nil || len(urls) != 1 || urls[0].URL == "" || urls[0].Mime == "" {
				return nil, err
			}
			if !strings.Contains(urls[0].URL, "/media/files/") {
				return nil, fmt.Errorf("url %q", urls[0].URL)
			}
			putCtx := map[string]any{easyrest.CtxStorageMIME: "text/plain"}
			dataURL, _, err := call.Plugins.StoragePut("inline", "note.txt", []byte("hi"), putCtx)
			if err != nil || !strings.HasPrefix(dataURL, "data:text/plain") {
				return nil, fmt.Errorf("inline %q err %v", dataURL, err)
			}
			return map[string]any{"url": urls[0].URL, "inline": dataURL}, nil
		},
	})
	cfg := restUsersConfig()
	app := cfg.RestAPI["v1"]
	ep := app.Endpoints["users"]
	ep.Public = true
	ep.Actions = map[string]config.RestAction{"list": {Handler: "urlAndInline"}}
	app.Endpoints["users"] = ep
	cfg.RestAPI["v1"] = app

	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/restapi/v1/users/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "/media/files/") || !strings.Contains(rec.Body.String(), "data:text/plain") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}

type restPlainMiddleware struct{}

func (restPlainMiddleware) Init(map[string]any, easyrest.HostRPC) (easyrest.MiddlewareInfo, error) {
	return easyrest.MiddlewareInfo{}, nil
}

func (restPlainMiddleware) PreRequest(string, map[string]any) (map[string]any, *int, error) {
	return nil, nil, nil
}

func (restPlainMiddleware) PostRequest(string, map[string]any) (map[string]string, error) {
	return nil, nil
}

func TestRestView_AuthSkipsView(t *testing.T) {
	t.Cleanup(func() { SetViews(nil) })
	called := false
	SetViews(map[string]View{
		"userEvents": func(http.ResponseWriter, Call) { called = true },
	})
	origAuth := AuthPlugins.Load()
	t.Cleanup(func() { AuthPlugins.Store(origAuth) })
	empty := map[string]easyrest.AuthPlugin{}
	AuthPlugins.Store(&empty)

	cfg := restUsersConfig()
	cfg.CheckScope = true
	cfg.AnonClaims = map[string]any{}
	app := cfg.RestAPI["v1"]
	ep := app.Endpoints["users"]
	ep.Actions = map[string]config.RestAction{"retrieve": {}}
	ep.Views = map[string]config.RestView{
		"sse": {Path: "{id}/sse", Methods: []string{"GET"}, Handler: "userEvents"},
	}
	app.Endpoints["users"] = ep
	cfg.RestAPI["v1"] = app

	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/7/sse/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if called {
		t.Fatal("view ran without a token")
	}
}

type restScopeAuth struct{}

func (restScopeAuth) Init(map[string]any, easyrest.HostRPC) (easyrest.AuthInfo, error) {
	return easyrest.AuthInfo{}, nil
}

func (restScopeAuth) Authenticate(headers map[string]string, _, _, _ string) (map[string]any, error) {
	switch headers["authorization"] {
	case "Bearer limited":
		return map[string]any{"sub": "ada", "scope": "other"}, nil
	case "Bearer reader":
		return map[string]any{"sub": "ada", "scope": "users-read"}, nil
	default:
		return nil, errors.New("missing token")
	}
}

func TestRestView_Scope(t *testing.T) {
	t.Cleanup(func() { SetViews(nil) })
	called := false
	SetViews(map[string]View{
		"userEvents": func(w http.ResponseWriter, _ Call) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		},
	})
	prevPlugins := AuthPlugins.Load()
	prevOrder := authPluginOrder.Load()
	t.Cleanup(func() {
		AuthPlugins.Store(prevPlugins)
		authPluginOrder.Store(prevOrder)
	})
	plugins := map[string]easyrest.AuthPlugin{"stub": restScopeAuth{}}
	AuthPlugins.Store(&plugins)
	setAuthPluginOrder(plugins)

	auth := []string{"stub"}
	cfg := restUsersConfig()
	cfg.CheckScope = true
	cfg.AnonClaims = map[string]any{}
	app := cfg.RestAPI["v1"]
	ep := app.Endpoints["users"]
	ep.Auth = &auth
	ep.Actions = map[string]config.RestAction{"retrieve": {}}
	ep.Views = map[string]config.RestView{
		"sse": {
			Path:           "{id}/sse",
			Methods:        []string{"GET"},
			Handler:        "userEvents",
			RequiredScopes: []string{"users-read"},
		},
	}
	app.Endpoints["users"] = ep
	cfg.RestAPI["v1"] = app

	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	limited := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/7/sse/", nil)
	limited.Header.Set("Authorization", "Bearer limited")
	denied := httptest.NewRecorder()
	router.ServeHTTP(denied, limited)
	if denied.Code != http.StatusForbidden || called {
		t.Fatalf("denied status %d called %v body %s", denied.Code, called, denied.Body.String())
	}
	allowed := httptest.NewRequest(http.MethodGet, "/restapi/v1/users/7/sse/", nil)
	allowed.Header.Set("Authorization", "Bearer reader")
	ok := httptest.NewRecorder()
	router.ServeHTTP(ok, allowed)
	if ok.Code != http.StatusNoContent || !called {
		t.Fatalf("allowed status %d called %v", ok.Code, called)
	}
}

func TestRestView_Methods(t *testing.T) {
	t.Cleanup(func() { SetViews(nil) })
	var got string
	calls := 0
	SetViews(map[string]View{
		"userEvents": func(w http.ResponseWriter, call Call) {
			calls++
			got = call.Request.Method
			w.WriteHeader(http.StatusNoContent)
		},
	})
	cfg := restUsersConfig()
	app := cfg.RestAPI["v1"]
	ep := app.Endpoints["users"]
	ep.Public = true
	ep.Actions = map[string]config.RestAction{"retrieve": {}}
	ep.Views = map[string]config.RestView{
		"sse": {Path: "{id}/sse", Methods: []string{"GET", "POST", "QUERY"}, Handler: "userEvents"},
	}
	app.Endpoints["users"] = ep
	cfg.RestAPI["v1"] = app

	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	for _, method := range []string{http.MethodGet, http.MethodPost, "QUERY"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(method, "/restapi/v1/users/7/sse/", nil))
		if rec.Code != http.StatusNoContent || got != method {
			t.Fatalf("%s status %d method %q", method, rec.Code, got)
		}
	}
	if calls != 3 {
		t.Fatalf("calls %d", calls)
	}
	denied := httptest.NewRecorder()
	router.ServeHTTP(denied, httptest.NewRequest(http.MethodDelete, "/restapi/v1/users/7/sse/", nil))
	if denied.Code != http.StatusMethodNotAllowed || calls != 3 {
		t.Fatalf("delete status %d calls %d body %s", denied.Code, calls, denied.Body.String())
	}
	allow := denied.Header().Values("Allow")
	joined := strings.Join(allow, ",")
	for _, method := range []string{http.MethodGet, http.MethodPost, "QUERY"} {
		if !strings.Contains(joined, method) {
			t.Fatalf("Allow %q missing %s", joined, method)
		}
	}
}

func TestRestView_PathParams(t *testing.T) {
	t.Cleanup(func() { SetViews(nil) })
	var params map[string]string
	SetViews(map[string]View{
		"userEvents": func(w http.ResponseWriter, call Call) {
			params = call.Params
			w.WriteHeader(http.StatusNoContent)
		},
	})
	cfg := restUsersConfig()
	app := cfg.RestAPI["v1"]
	ep := app.Endpoints["users"]
	ep.Public = true
	ep.URL = "orgs/{org_id}/users"
	ep.Actions = map[string]config.RestAction{"retrieve": {}}
	ep.Views = map[string]config.RestView{
		"sse": {Path: "{id}/sse", Methods: []string{"GET"}, Handler: "userEvents"},
	}
	app.Endpoints["users"] = ep
	cfg.RestAPI["v1"] = app

	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/restapi/v1/orgs/acme/users/7/sse/", nil))
	if rec.Code != http.StatusNoContent || params["org_id"] != "acme" || params["id"] != "7" {
		t.Fatalf("status %d params %#v", rec.Code, params)
	}
}

type restBlockMiddleware struct{}

func (restBlockMiddleware) Init(map[string]any, easyrest.HostRPC) (easyrest.MiddlewareInfo, error) {
	return easyrest.MiddlewareInfo{}, nil
}

func (restBlockMiddleware) PreRequest(string, map[string]any) (map[string]any, *int, error) {
	status := http.StatusTooManyRequests
	return nil, &status, nil
}

func (restBlockMiddleware) PostRequest(string, map[string]any) (map[string]string, error) {
	return nil, nil
}

func TestRestView_PreMiddleware(t *testing.T) {
	t.Cleanup(func() { SetViews(nil) })
	called := false
	SetViews(map[string]View{
		"userEvents": func(http.ResponseWriter, Call) { called = true },
	})
	orig := MiddlewarePlugins.Load()
	t.Cleanup(func() { MiddlewarePlugins.Store(orig) })
	MiddlewarePlugins.Store(&map[string]easyrest.MiddlewarePlugin{"block": restBlockMiddleware{}})

	cfg := restUsersConfig()
	cfg.MiddlewarePlugins = map[string]config.MiddlewareConfig{"block": {}}
	app := cfg.RestAPI["v1"]
	app.Middlewares = []string{"block"}
	ep := app.Endpoints["users"]
	ep.Public = true
	ep.Actions = map[string]config.RestAction{"retrieve": {}}
	ep.Views = map[string]config.RestView{
		"sse": {Path: "{id}/sse", Methods: []string{"GET"}, Handler: "userEvents"},
	}
	app.Endpoints["users"] = ep
	cfg.RestAPI["v1"] = app

	router := serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/7/sse/", nil))
	if rec.Code != http.StatusTooManyRequests || called {
		t.Fatalf("status %d called %v", rec.Code, called)
	}
}

func TestRestView_OpenAPI(t *testing.T) {
	prev := AuthSecurityDefinitions.Load()
	t.Cleanup(func() {
		AuthSecurityDefinitions.Store(prev)
		SetViews(nil)
	})
	defs := map[string]map[string]any{"oauth": {"type": "oauth2"}}
	AuthSecurityDefinitions.Store(&defs)
	SetViews(map[string]View{
		"userEvents": func(http.ResponseWriter, Call) {},
	})
	listed := []string{"oauth"}
	cfg := restUsersConfig()
	cfg.CheckScope = true
	app := cfg.RestAPI["v1"]
	app.Auth = &listed
	ep := app.Endpoints["users"]
	ep.Actions = map[string]config.RestAction{
		"retrieve": {RequiredScopes: []string{"users-read"}},
	}
	ep.Views = map[string]config.RestView{
		"sse": {
			Path:           "{id}/sse",
			Methods:        []string{"GET"},
			Handler:        "userEvents",
			Description:    "user events",
			RequiredScopes: []string{"users-read"},
		},
	}
	app.Endpoints["users"] = ep
	cfg.RestAPI["v1"] = app

	spec := restSpec(t, serveRest(t, cfg, map[string]easyrest.DBPlugin{"db": &restRecPlugin{}}), "/restapi/v1/")
	paths, _ := spec["paths"].(map[string]any)
	viewPath, _ := paths["/users/{id}/sse/"].(map[string]any)
	op, _ := viewPath["get"].(map[string]any)
	if op["description"] != "user events" {
		t.Fatalf("description %#v", op["description"])
	}
	responses, _ := op["responses"].(map[string]any)
	okResp, _ := responses["200"].(map[string]any)
	if okResp["description"] != "user events" {
		t.Fatalf("response %#v", responses["200"])
	}
	viewScopes, ok := restSecurityScopes(op["security"], "oauth")
	retrievePath, _ := paths["/users/{id}/"].(map[string]any)
	retrieve, _ := retrievePath["get"].(map[string]any)
	retrieveScopes, retrieveOK := restSecurityScopes(retrieve["security"], "oauth")
	if !ok || !retrieveOK || strings.Join(viewScopes, ",") != strings.Join(retrieveScopes, ",") || strings.Join(viewScopes, ",") != "users-read" {
		t.Fatalf("view %#v retrieve %#v", viewScopes, retrieveScopes)
	}
}
