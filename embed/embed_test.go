package embed_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onegreyonewhite/easyrest/internal/server"

	"github.com/go-chi/chi/v5"
	"github.com/goccy/go-json"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	lrustore "github.com/onegreyonewhite/easyrest/plugins/data/lru"
	sqliteplugin "github.com/onegreyonewhite/easyrest/plugins/data/sqlite"
	cachemw "github.com/onegreyonewhite/easyrest/plugins/middleware/cache"
	memstorage "github.com/onegreyonewhite/easyrest/plugins/storage/memory"

	"github.com/onegreyonewhite/easyrest/embed"
)

func TestHandler_HealthAndRoutes(t *testing.T) {
	t.Cleanup(func() {
		_, _ = embed.Handler("port: \"1\"\n", nil)
	})
	sub := chi.NewRouter()
	sub.Get("/ping", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ping"))
	})
	opts := []embed.Option{embed.WithRoutes(func(r chi.Router) {
		r.Get("/extra", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("extra"))
		})
		r.Mount("/sub", sub)
	})}

	for i := 0; i < 2; i++ {
		handler, err := embed.Handler("port: \"8080\"\n", nil, opts...)
		if err != nil {
			t.Fatal(err)
		}
		health := httptest.NewRecorder()
		handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/health", nil))
		if health.Code != http.StatusOK || health.Body.String() != "OK" {
			t.Fatalf("rebuild %d health: %d %s", i, health.Code, health.Body.String())
		}
		extra := httptest.NewRecorder()
		handler.ServeHTTP(extra, httptest.NewRequest(http.MethodGet, "/extra", nil))
		if extra.Code != http.StatusOK || extra.Body.String() != "extra" {
			t.Fatalf("rebuild %d extra: %d %s", i, extra.Code, extra.Body.String())
		}
		ping := httptest.NewRecorder()
		handler.ServeHTTP(ping, httptest.NewRequest(http.MethodGet, "/sub/ping", nil))
		if ping.Code != http.StatusOK || ping.Body.String() != "ping" {
			t.Fatalf("rebuild %d ping: %d %s", i, ping.Code, ping.Body.String())
		}
	}
}

func TestServe_ServiceReceivesPluginCaller(t *testing.T) {
	t.Cleanup(func() {
		server.StopPlugins()
		_, _ = embed.Handler("port: \"1\"\n", nil)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	checked := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = embed.Serve(ctx, fmt.Sprintf("port: \"%d\"\ncheck_scope: false\n", port), nil,
			embed.WithService(func(svcCtx context.Context, plugins embed.PluginCaller) error {
				_, err := plugins.Query(svcCtx, "missing", "select 1")
				if err == nil || !strings.Contains(err.Error(), "raw query is not allowed") {
					t.Errorf("Query: %v", err)
				}
				close(checked)
				<-svcCtx.Done()
				return nil
			}),
		)
	}()

	select {
	case <-checked:
	case <-time.After(5 * time.Second):
		t.Fatal("service did not check plugins")
	}
	cancel()
}

func TestServe_ServiceStopsWhenContextCanceled(t *testing.T) {
	t.Cleanup(func() {
		server.StopPlugins()
		_, _ = embed.Handler("port: \"1\"\n", nil)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		done <- embed.Serve(ctx, fmt.Sprintf("port: \"%d\"\ncheck_scope: false\n", port), nil,
			embed.WithService(func(ctx context.Context, _ embed.PluginCaller) error {
				close(started)
				<-ctx.Done()
				return nil
			}),
		)
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("service did not start")
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
}

func TestServe_ServiceErrorStopsServer(t *testing.T) {
	t.Cleanup(func() {
		server.StopPlugins()
		_, _ = embed.Handler("port: \"1\"\n", nil)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	want := errors.New("ping failed")
	stopped := make(chan struct{})
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		done <- embed.Serve(ctx, fmt.Sprintf("port: \"%d\"\ncheck_scope: false\n", port), nil,
			embed.WithService(func(context.Context, embed.PluginCaller) error {
				return want
			}),
			embed.WithService(func(ctx context.Context, _ embed.PluginCaller) error {
				<-ctx.Done()
				close(stopped)
				return nil
			}),
		)
	}()

	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("sibling service did not stop")
	}

	select {
	case err := <-done:
		if err == nil || err.Error() != want.Error() {
			t.Fatalf("Serve error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after service error")
	}
}

func TestRun_UnknownHandler(t *testing.T) {
	err := embed.Run(`
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

func TestHandler_UnknownView(t *testing.T) {
	_, err := embed.Handler(`
plugins:
  app:
    uri: sqlite://./missing.db
application:
  source: app
  api:
    v1:
      endpoints:
        users:
          views:
            sse:
              path: "{id}/sse"
              methods: [GET]
              handler: missing
`, nil)
	if err == nil || !strings.Contains(err.Error(), `handler "missing" is not registered`) {
		t.Fatalf("error: %v", err)
	}
}

func TestHandler_RestHandlerReadsSQLite(t *testing.T) {
	t.Cleanup(func() {
		_, _ = embed.Handler("port: \"1\"\n", nil)
	})
	dir := t.TempDir()
	path := filepath.Join(dir, "app.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users (name) VALUES ('ada')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	handler, err := embed.Handler(`
check_scope: false
plugins:
  app:
    uri: "sqlite://`+path+`"
application:
  source: app
  public: true
  api:
    v1:
      auth: []
      endpoints:
        users:
          table: users
          actions:
            list:
              handler: listUsers
`, nil,
		embed.WithDB("sqlite", func() easyrest.DBPlugin { return sqliteplugin.NewSqlitePlugin() }),
		embed.WithRestHandler("listUsers", func(call embed.Call) (any, error) {
			res, err := call.Plugins.TableGet(easyrest.HostCall{DB: "app", Name: "users"})
			if err != nil {
				return nil, err
			}
			if res.Status != http.StatusOK {
				return nil, &embed.HandlerError{Status: res.Status, Message: string(res.Body)}
			}
			var rows []map[string]any
			if err := json.Unmarshal(res.Body, &rows); err != nil {
				return nil, err
			}
			return rows, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ada") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestHandler_ViewBesideCRUD(t *testing.T) {
	t.Cleanup(func() {
		_, _ = embed.Handler("port: \"1\"\n", nil)
	})
	dir := t.TempDir()
	path := filepath.Join(dir, "app.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	handler, err := embed.Handler(`
check_scope: false
plugins:
  app:
    uri: "sqlite://`+path+`"
application:
  source: app
  public: true
  api:
    v1:
      auth: []
      endpoints:
        users:
          table: users
          actions:
            list:
              handler: listUsers
          views:
            sse:
              path: "{id}/sse"
              methods: [GET]
              handler: userEvents
`, nil,
		embed.WithDB("sqlite", func() easyrest.DBPlugin { return sqliteplugin.NewSqlitePlugin() }),
		embed.WithRestHandler("listUsers", func(embed.Call) (any, error) {
			return map[string]any{"ok": true}, nil
		}),
		embed.WithView("userEvents", func(w http.ResponseWriter, call embed.Call) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("data: " + call.Params["id"] + "\n\n"))
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	sse := httptest.NewRecorder()
	handler.ServeHTTP(sse, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/7/sse/", nil))
	if sse.Code != http.StatusOK || sse.Header().Get("Content-Type") != "text/event-stream" || sse.Body.String() != "data: 7\n\n" {
		t.Fatalf("sse status %d type %q body %q", sse.Code, sse.Header().Get("Content-Type"), sse.Body.String())
	}
	list := httptest.NewRecorder()
	handler.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "ok") {
		t.Fatalf("list status %d body %s", list.Code, list.Body.String())
	}
}

func TestHandler_ViewReadsBodyAndTable(t *testing.T) {
	t.Cleanup(func() {
		_, _ = embed.Handler("port: \"1\"\n", nil)
	})
	dir := t.TempDir()
	path := filepath.Join(dir, "app.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users (name) VALUES ('ada')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	handler, err := embed.Handler(`
check_scope: false
plugins:
  app:
    uri: "sqlite://`+path+`"
application:
  source: app
  public: true
  api:
    v1:
      auth: []
      endpoints:
        users:
          table: users
          actions:
            list:
              handler: listUsers
          views:
            note:
              path: "{id}/note"
              methods: [POST]
              handler: noteUser
`, nil,
		embed.WithDB("sqlite", func() easyrest.DBPlugin { return sqliteplugin.NewSqlitePlugin() }),
		embed.WithRestHandler("listUsers", func(embed.Call) (any, error) {
			return map[string]any{"ok": true}, nil
		}),
		embed.WithView("noteUser", func(w http.ResponseWriter, call embed.Call) {
			raw, err := io.ReadAll(call.Request.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			res, err := call.Plugins.TableGet(easyrest.HostCall{DB: "app", Name: "users"})
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			_, _ = w.Write(raw)
			_, _ = w.Write(res.Body)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	note := httptest.NewRecorder()
	handler.ServeHTTP(note, httptest.NewRequest(http.MethodPost, "/restapi/v1/users/7/note/", strings.NewReader("Z")))
	if note.Code != http.StatusOK || !strings.Contains(note.Body.String(), "Z") || !strings.Contains(note.Body.String(), "ada") {
		t.Fatalf("note status %d body %s", note.Code, note.Body.String())
	}
	list := httptest.NewRecorder()
	handler.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "ok") {
		t.Fatalf("list status %d body %s", list.Code, list.Body.String())
	}
}

func TestHandler_ViewHead(t *testing.T) {
	t.Cleanup(func() {
		_, _ = embed.Handler("port: \"1\"\n", nil)
	})
	dir := t.TempDir()
	path := filepath.Join(dir, "app.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	var feedMethod string
	var feedCalls, headCalls int
	handler, err := embed.Handler(`
check_scope: false
plugins:
  app:
    uri: "sqlite://`+path+`"
application:
  source: app
  public: true
  api:
    v1:
      auth: []
      endpoints:
        users:
          actions:
            list: {}
          views:
            feed:
              path: "{id}/sse"
              methods: [GET]
              handler: feedUser
            probe:
              path: "{id}/peek"
              methods: [HEAD]
              handler: headUser
`, nil,
		embed.WithDB("sqlite", func() easyrest.DBPlugin { return sqliteplugin.NewSqlitePlugin() }),
		embed.WithView("feedUser", func(w http.ResponseWriter, call embed.Call) {
			feedCalls++
			feedMethod = call.Request.Method
			w.WriteHeader(http.StatusOK)
		}),
		embed.WithView("headUser", func(w http.ResponseWriter, call embed.Call) {
			headCalls++
			if call.Request.Method != http.MethodHead {
				http.Error(w, call.Request.Method, http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	headFeed := httptest.NewRecorder()
	handler.ServeHTTP(headFeed, httptest.NewRequest(http.MethodHead, "/restapi/v1/users/7/sse/", nil))
	if headFeed.Code != http.StatusOK || feedCalls != 1 || feedMethod != http.MethodHead || headCalls != 0 {
		t.Fatalf("feed head status %d method %q feed %d head %d", headFeed.Code, feedMethod, feedCalls, headCalls)
	}
	headProbe := httptest.NewRecorder()
	handler.ServeHTTP(headProbe, httptest.NewRequest(http.MethodHead, "/restapi/v1/users/7/peek/", nil))
	if headProbe.Code != http.StatusNoContent || headCalls != 1 || feedCalls != 1 {
		t.Fatalf("probe head status %d feed %d head %d body %s", headProbe.Code, feedCalls, headCalls, headProbe.Body.String())
	}
}

func TestHandler_CacheKey(t *testing.T) {
	t.Cleanup(func() {
		_, _ = embed.Handler("port: \"1\"\n", nil)
	})
	dir := t.TempDir()
	path := filepath.Join(dir, "app.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	handler, err := embed.Handler(`
check_scope: false
plugins:
  app:
    uri: "sqlite://`+path+`"
middleware_plugins:
  cache-lru:
    settings:
      ttl: 1m
application:
  source: app
  public: true
  api:
    v1:
      auth: []
      endpoints:
        users:
          table: users
          actions:
            list:
              handler: readCache
`, nil,
		embed.WithDB("sqlite", func() easyrest.DBPlugin { return sqliteplugin.NewSqlitePlugin() }),
		embed.WithMiddleware("cache-lru", func() easyrest.MiddlewarePlugin {
			return cachemw.New(lrustore.NewSimpleCachePlugin())
		}),
		embed.WithRestHandler("readCache", func(call embed.Call) (any, error) {
			if err := call.Plugins.CacheSet("cache-lru", "k", "cached", nil); err != nil {
				return nil, err
			}
			got, err := call.Plugins.CacheGet("cache-lru", "k")
			if err != nil {
				return nil, err
			}
			if err := call.Plugins.CacheDelete("cache-lru", "k"); err != nil {
				return nil, err
			}
			_, err = call.Plugins.CacheGet("cache-lru", "k")
			if !errors.Is(err, embed.ErrCacheMiss) {
				return nil, err
			}
			return got, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "cached") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestHandler_Storage(t *testing.T) {
	t.Cleanup(func() {
		_, _ = embed.Handler("port: \"1\"\n", nil)
	})
	dir := t.TempDir()
	path := filepath.Join(dir, "app.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	handler, err := embed.Handler(`
check_scope: false
plugins:
  app:
    uri: "sqlite://`+path+`"
storage_plugins:
  files:
    plugin: memory
application:
  source: app
  public: true
  api:
    v1:
      auth: []
      endpoints:
        users:
          table: users
          actions:
            list:
              handler: useStorage
`, nil,
		embed.WithDB("sqlite", func() easyrest.DBPlugin { return sqliteplugin.NewSqlitePlugin() }),
		embed.WithStorage("memory", func() easyrest.StoragePlugin { return memstorage.New() }),
		embed.WithRestHandler("useStorage", func(call embed.Call) (any, error) {
			const relPath = "embed/obj.bin"
			if _, _, err := call.Plugins.StoragePut("files", relPath, []byte("stored"), nil); err != nil {
				return nil, err
			}
			body, _, _, err := call.Plugins.StorageGetBin("files", relPath, nil)
			if err != nil || string(body) != "stored" {
				return nil, err
			}
			if err := call.Plugins.StorageDelete("files", relPath, nil); err != nil {
				return nil, err
			}
			return "done", nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/restapi/v1/users/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "done") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestHandler_RestSpec(t *testing.T) {
	t.Cleanup(func() {
		server.SetRestSpecHooks(nil)
		_, _ = embed.Handler("port: \"1\"\n", nil)
	})
	overlay := `
port: "1"
application:
  api:
    b:
      source: db
    a:
      source: db
`
	var seen []string
	handler, err := embed.Handler(overlay, nil,
		embed.WithRestSpec(func(name string, doc map[string]any) error {
			seen = append(seen, "1:"+name)
			doc["x-first"] = name
			return nil
		}),
		embed.WithRestSpec(func(name string, doc map[string]any) error {
			if doc["x-first"] != name {
				return fmt.Errorf("first hook missing for %s", name)
			}
			seen = append(seen, "2:"+name)
			return nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(seen, ",") != "1:a,2:a,1:b,2:b" {
		t.Fatalf("order %v", seen)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/restapi/a/?format=json", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"x-first":"a"`) {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}

	handler, err = embed.Handler(overlay, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/restapi/a/?format=json", nil))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "x-first") {
		t.Fatalf("cleared status %d body %s", rec.Code, rec.Body.String())
	}

	_, err = embed.Handler(overlay, nil, embed.WithRestSpec(func(name string, doc map[string]any) error {
		doc["x-bad"] = true
		return errors.New("boom")
	}))
	if err == nil || !strings.Contains(err.Error(), "spec hook") {
		t.Fatalf("err %v", err)
	}
	handler, err = embed.Handler(overlay, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/restapi/a/?format=json", nil))
	if strings.Contains(rec.Body.String(), "x-bad") {
		t.Fatalf("mutated %s", rec.Body.String())
	}
}
