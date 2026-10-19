package embed_test

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/goccy/go-json"
	easyrest "github.com/onegreyonewhite/easyrest/plugin"
	sqliteplugin "github.com/onegreyonewhite/easyrest/plugins/data/sqlite"

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
